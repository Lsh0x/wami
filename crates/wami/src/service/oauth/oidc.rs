//! OpenID Connect — the flows where a human is present.
//!
//! Authorization code with PKCE, refresh rotation, ID tokens, consent and
//! discovery, layered onto the same [`OAuthService`] that issues
//! `client_credentials` tokens. One keyset signs everything, so a relying party
//! that already verifies wami's access tokens verifies its ID tokens too.
//!
//! # The shape of the flow
//!
//! The host authenticates the user — wami does not; that is
//! [`crate::service::auth`]'s job or an upstream IdP's — and then:
//!
//! 1. [`OAuthService::authorize`] with the user it just authenticated. It
//!    returns either a code, or [`Authorization::ConsentRequired`] naming the
//!    scopes the user has not yet approved.
//! 2. On approval, [`OAuthService::grant_consent`], then `authorize` again.
//! 3. The host redirects to the client with the code.
//! 4. The client posts it back with its verifier, and
//!    [`OAuthService::exchange_code`] returns the tokens.
//!
//! # What is deliberately absent
//!
//! No `plain` PKCE, no implicit flow, and PKCE is not optional — the challenge
//! is a required field of [`AuthorizationRequest`] rather than an `Option`, so
//! a caller cannot forget it. Each of those has been the root of enough real
//! incidents that offering them, even behind a flag, would be offering a way to
//! get this wrong.

use async_trait::async_trait;
use chrono::Utc;
use std::sync::Arc;
use wami_core::error::{AmiError, Result};

use super::{OAuthService, OAuthStore};
use crate::store::traits::oauth::{OAuthAuthorizationStore, OAuthConsentStore, OAuthRefreshStore};
use crate::wami::oauth::{
    builder, oidc, AuthorizationCode, CodeChallenge, DiscoveryDocument, GrantType, OAuthClaims,
    OAuthClient, RefreshToken, UserConsent, UserInfo, UserProfile, AUTHORIZATION_CODE_LIFETIME,
    REFRESH_TOKEN_LIFETIME,
};

/// Combined bound for a store that can serve the user-facing flows.
pub trait OidcStore:
    OAuthStore + OAuthAuthorizationStore + OAuthRefreshStore + OAuthConsentStore
{
}
impl<T: OAuthStore + OAuthAuthorizationStore + OAuthRefreshStore + OAuthConsentStore> OidcStore
    for T
{
}

/// Where the profile claims in an ID token come from.
///
/// wami does not own your user directory, and pretending otherwise would mean
/// either duplicating it or restricting who can use this. The host answers
/// instead, for whatever a user is in its world.
///
/// A service without one still issues ID tokens; they carry `sub` and nothing
/// else, which is all `openid` on its own entitles a client to.
#[async_trait]
pub trait UserClaimsSource: Send + Sync {
    /// The profile of `user_name`, or `None` if there is nothing to release.
    async fn claims_for(&self, user_name: &str) -> Result<Option<UserProfile>>;
}

/// What the host asks for once it has authenticated a user.
#[derive(Debug, Clone)]
pub struct AuthorizationRequest {
    /// The client the user is signing in to.
    pub client_id: String,
    /// The user the host has just authenticated.
    pub user_name: String,
    /// Where the code will be delivered. Matched exactly against the client's
    /// registered set.
    pub redirect_uri: String,
    /// Scopes the client asked for.
    pub scopes: Vec<String>,
    /// The client's PKCE commitment. Not optional, by construction.
    pub challenge: CodeChallenge,
    /// The client's nonce, echoed into the ID token.
    pub nonce: Option<String>,
    /// The client's opaque state, handed back untouched.
    pub state: Option<String>,
}

/// The outcome of an authorization request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Authorization {
    /// A code to deliver to `redirect_uri`.
    Code {
        /// The code.
        code: String,
        /// Where to deliver it — the one that was validated, not the one to
        /// re-read from the request.
        redirect_uri: String,
        /// The client's state, unchanged.
        state: Option<String>,
    },
    /// The user has not approved these scopes yet.
    ///
    /// The host shows them, and calls [`OAuthService::grant_consent`] if the
    /// user agrees. Returning this rather than granting silently is the whole
    /// point of consent.
    ConsentRequired {
        /// Which client is asking.
        client_id: String,
        /// The scopes still needing approval — the full set to display, not
        /// only the new ones, so the user sees what they are agreeing to.
        scopes: Vec<String>,
    },
}

/// A client redeeming an authorization code.
#[derive(Debug, Clone)]
pub struct CodeExchange {
    /// The client's identifier.
    pub client_id: String,
    /// The client's secret.
    pub client_secret: String,
    /// The code it received.
    pub code: String,
    /// The redirect URI the code was issued against.
    pub redirect_uri: String,
    /// The PKCE verifier behind the challenge it committed to.
    pub code_verifier: String,
}

/// The tokens returned by the user-facing grants.
///
/// Separate from [`TokenResponse`] because those grants return a refresh token
/// and, when `openid` was granted, an ID token — and because a client parsing
/// this must not silently accept a response missing them.
///
/// [`TokenResponse`]: crate::wami::oauth::TokenResponse
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OidcTokens {
    /// The signed access token.
    pub access_token: String,
    /// Always `Bearer`.
    pub token_type: String,
    /// Access token lifetime in seconds.
    pub expires_in: i64,
    /// Granted scopes, space-delimited.
    pub scope: String,
    /// The refresh token. Single-use: the next refresh replaces it.
    pub refresh_token: String,
    /// The ID token, present when `openid` was granted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
}

impl<S: OidcStore> OAuthService<S> {
    /// Attach a source of profile claims for ID tokens and `/userinfo`.
    pub fn with_user_claims(mut self, claims: Arc<dyn UserClaimsSource>) -> Self {
        self.user_claims = Some(claims);
        self
    }

    /// Issue an authorization code for an authenticated user, or ask for
    /// consent.
    ///
    /// # Errors
    ///
    /// [`AmiError::AccessDenied`] if the client is unknown, disabled, or not
    /// registered for the `authorization_code` grant.
    /// [`AmiError::InvalidParameter`] if the redirect URI is not registered or
    /// a requested scope is outside the client's set.
    ///
    /// Both are returned *to the caller of this library* and must never be
    /// redirected to the client: sending an error to an unverified redirect URI
    /// is the vulnerability the check exists to prevent.
    pub async fn authorize(&self, request: AuthorizationRequest) -> Result<Authorization> {
        let client = self.enabled_client(&request.client_id).await?;

        if !client.allows_grant(GrantType::AuthorizationCode) {
            return Err(AmiError::AccessDenied {
                message: format!(
                    "client {} may not use the authorization_code grant",
                    request.client_id
                ),
            });
        }

        // Before anything else. Every later step assumes the code has somewhere
        // safe to go.
        oidc::validate_redirect_uri(&client, &request.redirect_uri)?;

        let granted = client.narrow_scopes(&request.scopes).map_err(|refused| {
            AmiError::InvalidParameter {
                message: format!(
                    "client {} is not entitled to scope {refused}",
                    request.client_id
                ),
            }
        })?;

        let approved = self
            .store
            .read()
            .await
            .get_consent(&request.client_id, &request.user_name)
            .await?
            .is_some_and(|c| c.covers(&granted));

        if !approved {
            return Ok(Authorization::ConsentRequired {
                client_id: request.client_id,
                scopes: granted,
            });
        }

        let code = AuthorizationCode {
            code: oidc::generate_opaque_value(),
            client_id: request.client_id,
            user_name: request.user_name,
            scopes: granted,
            redirect_uri: request.redirect_uri.clone(),
            challenge: Some(request.challenge),
            nonce: request.nonce,
            expires_at: Utc::now() + AUTHORIZATION_CODE_LIFETIME,
        };
        let issued = code.code.clone();
        self.store
            .write()
            .await
            .store_authorization_code(code)
            .await?;

        Ok(Authorization::Code {
            code: issued,
            redirect_uri: request.redirect_uri,
            state: request.state,
        })
    }

    /// Record a user's approval of a client's scopes.
    ///
    /// Widening an existing consent replaces it; the record is what the user
    /// last agreed to, not a log of every time they agreed.
    pub async fn grant_consent(
        &self,
        client_id: &str,
        user_name: &str,
        scopes: Vec<String>,
    ) -> Result<UserConsent> {
        let client = self.enabled_client(client_id).await?;
        let scopes =
            client
                .narrow_scopes(&scopes)
                .map_err(|refused| AmiError::InvalidParameter {
                    message: format!("client {client_id} is not entitled to scope {refused}"),
                })?;

        self.store
            .write()
            .await
            .record_consent(UserConsent {
                user_name: user_name.to_string(),
                client_id: client_id.to_string(),
                scopes,
                granted_at: Utc::now(),
            })
            .await
    }

    /// Withdraw a user's approval, and with it every refresh token it backed.
    ///
    /// Revoking the consent alone would leave the client holding a refresh
    /// token that keeps minting access tokens for a month — the user would have
    /// said no and nothing would have stopped.
    pub async fn withdraw_consent(&self, client_id: &str, user_name: &str) -> Result<bool> {
        let mut store = self.store.write().await;
        let withdrawn = store.revoke_consent(client_id, user_name).await?;
        store.revoke_refresh_chain(client_id, user_name).await?;
        Ok(withdrawn)
    }

    /// Redeem an authorization code.
    ///
    /// # Errors
    ///
    /// [`AmiError::AccessDenied`] for bad client credentials, and for an
    /// unknown, expired, replayed or mismatched code — all reported
    /// identically, because telling them apart tells an attacker which of their
    /// guesses was closest.
    pub async fn exchange_code(&self, exchange: CodeExchange) -> Result<OidcTokens> {
        let client = self
            .validate_client(&exchange.client_id, &exchange.client_secret)
            .await?;

        // Consumed before it is checked, and unconditionally. A code that fails
        // any check below is spent regardless — leaving it redeemable would let
        // an attacker who holds a stolen code keep trying verifiers.
        let code = self
            .store
            .write()
            .await
            .consume_authorization_code(&exchange.code)
            .await?
            .ok_or_else(refused_code)?;

        if code.client_id != exchange.client_id
            || code.redirect_uri != exchange.redirect_uri
            || code.expires_at <= Utc::now()
        {
            return Err(refused_code());
        }

        // PKCE. A code with no challenge cannot be redeemed at all: the only
        // way to store one is through `authorize`, which requires a challenge,
        // so its absence means the record was written by something else.
        match &code.challenge {
            Some(challenge) if challenge.verify(&exchange.code_verifier) => {}
            _ => return Err(refused_code()),
        }

        self.mint(&client, &code.user_name, &code.scopes, code.nonce)
            .await
    }

    /// Exchange a refresh token for a fresh set.
    ///
    /// The presented token is spent and a new one issued in its place. A token
    /// presented twice is treated as leaked: the whole chain for that user and
    /// client is revoked, so both the attacker and the legitimate client are
    /// forced back through sign-in. That is the point — a silent second use is
    /// indistinguishable from theft, and letting it pass makes rotation
    /// decorative.
    ///
    /// # Errors
    ///
    /// [`AmiError::AccessDenied`] for bad credentials, an unknown or expired
    /// token, or a reuse.
    pub async fn refresh_tokens(
        &self,
        client_id: &str,
        client_secret: &str,
        refresh_token: &str,
    ) -> Result<OidcTokens> {
        let client = self.validate_client(client_id, client_secret).await?;

        let existing = self
            .store
            .read()
            .await
            .get_refresh_token(refresh_token)
            .await?
            .ok_or_else(refused_refresh)?;

        if existing.client_id != client_id {
            return Err(refused_refresh());
        }

        let replacement = RefreshToken {
            token: oidc::generate_opaque_value(),
            client_id: client_id.to_string(),
            user_name: existing.user_name.clone(),
            scopes: existing.scopes.clone(),
            expires_at: Utc::now() + REFRESH_TOKEN_LIFETIME,
            used_at: None,
            replaced_by: None,
        };
        let minted = replacement.token.clone();

        let spent = self
            .store
            .write()
            .await
            .rotate_refresh_token(refresh_token, replacement)
            .await?
            .ok_or_else(refused_refresh)?;

        // The store hands back the token it took. If it does not name our
        // replacement, we did not win the rotation, and nothing was minted.
        if spent.replaced_by.as_deref() != Some(minted.as_str()) {
            if spent.used_at.is_none() {
                // Merely expired. The user signs in again; nothing is wrong.
                return Err(refused_refresh());
            }
            self.store
                .write()
                .await
                .revoke_refresh_chain(client_id, &spent.user_name)
                .await?;
            return Err(AmiError::AccessDenied {
                message: "refresh token reuse detected; the chain has been revoked".to_string(),
            });
        }

        // No nonce on refresh: the client's nonce belonged to one sign-in, and
        // replaying it into a later ID token would defeat what it is for.
        self.mint(&client, &spent.user_name, &spent.scopes, None)
            .await
    }

    /// Answer `/userinfo` for a bearer access token.
    ///
    /// # Errors
    ///
    /// [`AmiError::AccessDenied`] if the token is invalid, revoked, expired, or
    /// was not granted `openid` — a `client_credentials` token has no user
    /// behind it, and answering with the client as `sub` would be a lie.
    pub async fn user_info(&self, access_token: &str, audience: &str) -> Result<UserInfo> {
        let refused = || AmiError::AccessDenied {
            message: "invalid access token".to_string(),
        };

        let claims = self
            .keys
            .verify_claims::<OAuthClaims>(access_token, audience)
            .map_err(|_| refused())?;

        let scopes: Vec<String> = claims
            .scope
            .split_whitespace()
            .map(str::to_string)
            .collect();
        if !scopes.iter().any(|s| s == "openid") {
            return Err(refused());
        }

        let record = self
            .store
            .read()
            .await
            .get_oauth_token(&claims.jti)
            .await?
            .ok_or_else(refused)?;
        if !record.is_active_at(Utc::now()) {
            return Err(refused());
        }

        let profile = self.profile_of(&claims.sub).await?;
        Ok(oidc::build_user_info(&claims.sub, &scopes, &profile))
    }

    /// The provider metadata for this service, served from `base_url`.
    pub fn discovery(&self, base_url: &str) -> DiscoveryDocument {
        oidc::build_discovery_document(&self.issuer, base_url)
    }

    /// A registered, enabled client, or [`AmiError::AccessDenied`].
    async fn enabled_client(&self, client_id: &str) -> Result<OAuthClient> {
        let refused = || AmiError::AccessDenied {
            message: "unknown or disabled client".to_string(),
        };
        let client = self
            .store
            .read()
            .await
            .get_oauth_client(client_id)
            .await?
            .ok_or_else(refused)?;
        if !client.enabled {
            return Err(refused());
        }
        Ok(client)
    }

    /// What the host will release about a user, or nothing if it was not asked.
    async fn profile_of(&self, user_name: &str) -> Result<UserProfile> {
        match &self.user_claims {
            Some(source) => Ok(source.claims_for(user_name).await?.unwrap_or_default()),
            None => Ok(UserProfile::default()),
        }
    }

    /// Mint the access, refresh and (when `openid` is granted) ID tokens.
    ///
    /// One place, so the code and refresh paths cannot drift into issuing
    /// differently-shaped tokens.
    async fn mint(
        &self,
        client: &OAuthClient,
        user_name: &str,
        scopes: &[String],
        nonce: Option<String>,
    ) -> Result<OidcTokens> {
        let now = Utc::now();
        let signing_failed = |e: crate::wami::sts::jwt::JwtError| {
            AmiError::StoreError(format!("failed to sign: {e}"))
        };

        let claims =
            builder::build_user_claims(client, user_name, scopes, &self.issuer, now, self.lifetime);
        let access_token = self.keys.sign_claims(&claims).map_err(signing_failed)?;

        let id_token = if scopes.iter().any(|s| s == "openid") {
            let profile = self.profile_of(user_name).await?;
            let id_claims = oidc::build_id_token_claims(
                oidc::IdTokenRequest {
                    user_name,
                    client_id: &client.client_id,
                    issuer: &self.issuer,
                    scopes,
                    profile: &profile,
                    nonce,
                },
                now,
                self.lifetime,
            );
            Some(self.keys.sign_claims(&id_claims).map_err(signing_failed)?)
        } else {
            None
        };

        let refresh = RefreshToken {
            token: oidc::generate_opaque_value(),
            client_id: client.client_id.clone(),
            user_name: user_name.to_string(),
            scopes: scopes.to_vec(),
            expires_at: now + REFRESH_TOKEN_LIFETIME,
            used_at: None,
            replaced_by: None,
        };
        let refresh_token = refresh.token.clone();

        // Both recorded before either is handed out. A token the caller holds
        // but the store never saw could not be revoked.
        let mut store = self.store.write().await;
        store
            .record_oauth_token(builder::build_token_record(&claims, now))
            .await?;
        store.store_refresh_token(refresh).await?;

        Ok(OidcTokens {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: self.lifetime.num_seconds(),
            scope: scopes.join(" "),
            refresh_token,
            id_token,
        })
    }
}

/// One answer for every way a code exchange can fail.
fn refused_code() -> AmiError {
    AmiError::AccessDenied {
        message: "invalid authorization code".to_string(),
    }
}

/// One answer for every way a refresh can fail, reuse aside.
fn refused_refresh() -> AmiError {
    AmiError::AccessDenied {
        message: "invalid refresh token".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::memory::InMemoryOAuthStore;
    use crate::wami::oauth::{build_client, derive_s256_challenge, GrantRequest, IdTokenClaims};
    use crate::wami::sts::jwt::KeyManager;
    use tokio::sync::RwLock;

    const AUD: &str = "the-api";
    const REDIRECT: &str = "https://app.test/cb";
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    struct Directory;

    #[async_trait]
    impl UserClaimsSource for Directory {
        async fn claims_for(&self, user_name: &str) -> Result<Option<UserProfile>> {
            Ok((user_name == "alice").then(|| UserProfile {
                name: Some("Alice Example".into()),
                email: Some("alice@example.test".into()),
            }))
        }
    }

    async fn service_with(
        grants: Vec<GrantType>,
        redirects: Vec<String>,
    ) -> OAuthService<InMemoryOAuthStore> {
        let service = OAuthService::new(
            Arc::new(RwLock::new(InMemoryOAuthStore::new())),
            Arc::new(KeyManager::generate()),
            "https://id.test".to_string(),
        )
        .with_user_claims(Arc::new(Directory));

        let client = build_client(
            "app".into(),
            "s3cret",
            "The App".into(),
            grants,
            vec![
                "openid".into(),
                "profile".into(),
                "email".into(),
                "reports:read".into(),
            ],
            AUD.to_string(),
            redirects,
        )
        .unwrap();
        service.register_client(client).await.unwrap();
        service
    }

    async fn service() -> OAuthService<InMemoryOAuthStore> {
        service_with(
            vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
            vec![REDIRECT.to_string()],
        )
        .await
    }

    fn request(scopes: &[&str]) -> AuthorizationRequest {
        AuthorizationRequest {
            client_id: "app".into(),
            user_name: "alice".into(),
            redirect_uri: REDIRECT.into(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            challenge: CodeChallenge::s256(derive_s256_challenge(VERIFIER)),
            nonce: Some("n-0S6".into()),
            state: Some("xyz".into()),
        }
    }

    fn exchange(code: &str, verifier: &str) -> CodeExchange {
        CodeExchange {
            client_id: "app".into(),
            client_secret: "s3cret".into(),
            code: code.into(),
            redirect_uri: REDIRECT.into(),
            code_verifier: verifier.into(),
        }
    }

    /// Consent, then a code. The two steps every other test starts from.
    async fn a_code(service: &OAuthService<InMemoryOAuthStore>, scopes: &[&str]) -> String {
        service
            .grant_consent(
                "app",
                "alice",
                scopes.iter().map(|s| s.to_string()).collect(),
            )
            .await
            .unwrap();
        match service.authorize(request(scopes)).await.unwrap() {
            Authorization::Code { code, .. } => code,
            other => panic!("expected a code, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_user_who_has_not_consented_is_asked_before_any_code_exists() {
        let service = service().await;

        let outcome = service
            .authorize(request(&["openid", "email"]))
            .await
            .unwrap();
        assert_eq!(
            outcome,
            Authorization::ConsentRequired {
                client_id: "app".into(),
                scopes: vec!["openid".into(), "email".into()],
            }
        );

        // And nothing was stored — an unapproved request must not leave a code
        // lying around that something else could redeem.
        assert!(service
            .store
            .write()
            .await
            .consume_authorization_code("anything")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn consent_that_does_not_cover_the_request_is_asked_for_again() {
        let service = service().await;
        service
            .grant_consent("app", "alice", vec!["openid".into()])
            .await
            .unwrap();

        let outcome = service
            .authorize(request(&["openid", "email"]))
            .await
            .unwrap();
        assert!(matches!(outcome, Authorization::ConsentRequired { .. }));

        // Widening it lets the same request through.
        service
            .grant_consent("app", "alice", vec!["openid".into(), "email".into()])
            .await
            .unwrap();
        let outcome = service
            .authorize(request(&["openid", "email"]))
            .await
            .unwrap();
        assert!(matches!(outcome, Authorization::Code { .. }));
    }

    #[tokio::test]
    async fn the_whole_flow_yields_an_id_token_addressed_to_the_client() {
        let service = service().await;
        let code = a_code(&service, &["openid", "profile", "email"]).await;

        let tokens = service
            .exchange_code(exchange(&code, VERIFIER))
            .await
            .unwrap();
        assert_eq!(tokens.token_type, "Bearer");
        assert_eq!(tokens.scope, "openid profile email");
        assert!(!tokens.refresh_token.is_empty());

        // The access token names the user, and is verified against the API's
        // audience.
        let access: OAuthClaims = service
            .keys
            .verify_claims(&tokens.access_token, AUD)
            .unwrap();
        assert_eq!(access.sub, "alice", "the user, not the client");
        assert_eq!(access.client_id, "app");

        // The ID token is verified against the *client's* audience, not the
        // API's — a resource server cannot accept it by accident.
        let id: IdTokenClaims = service
            .keys
            .verify_claims(tokens.id_token.as_ref().unwrap(), "app")
            .unwrap();
        assert_eq!(id.sub, "alice");
        assert_eq!(id.iss, "https://id.test");
        assert_eq!(id.nonce.as_deref(), Some("n-0S6"));
        assert_eq!(id.name.as_deref(), Some("Alice Example"));
        assert_eq!(id.email.as_deref(), Some("alice@example.test"));

        assert!(
            service
                .keys
                .verify_claims::<IdTokenClaims>(tokens.id_token.as_ref().unwrap(), AUD)
                .is_err(),
            "an ID token must not verify as an access token"
        );
    }

    #[tokio::test]
    async fn without_openid_there_is_no_id_token() {
        let service = service().await;
        let code = a_code(&service, &["reports:read"]).await;

        let tokens = service
            .exchange_code(exchange(&code, VERIFIER))
            .await
            .unwrap();
        assert_eq!(tokens.id_token, None);
        assert_eq!(tokens.scope, "reports:read");
    }

    #[tokio::test]
    async fn a_code_cannot_be_redeemed_twice() {
        let service = service().await;
        let code = a_code(&service, &["openid"]).await;

        assert!(service
            .exchange_code(exchange(&code, VERIFIER))
            .await
            .is_ok());
        let replay = service.exchange_code(exchange(&code, VERIFIER)).await;
        assert!(matches!(replay, Err(AmiError::AccessDenied { .. })));
    }

    #[tokio::test]
    async fn a_wrong_verifier_is_refused_and_burns_the_code() {
        // PKCE only helps if a failed attempt costs the attacker the code. If
        // the code survived, an intercepted one could be brute-forced.
        let service = service().await;
        let code = a_code(&service, &["openid"]).await;

        assert!(service
            .exchange_code(exchange(&code, "not-the-verifier"))
            .await
            .is_err());
        assert!(
            service
                .exchange_code(exchange(&code, VERIFIER))
                .await
                .is_err(),
            "the real client should no longer be able to redeem it either"
        );
    }

    #[tokio::test]
    async fn a_code_is_bound_to_the_redirect_uri_it_was_issued_against() {
        let service = service().await;
        let code = a_code(&service, &["openid"]).await;

        let mut elsewhere = exchange(&code, VERIFIER);
        elsewhere.redirect_uri = "https://app.test/other".into();
        assert!(matches!(
            service.exchange_code(elsewhere).await,
            Err(AmiError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn an_unregistered_redirect_uri_never_produces_a_code() {
        let service = service().await;
        service
            .grant_consent("app", "alice", vec!["openid".into()])
            .await
            .unwrap();

        for hostile in [
            "https://app.test/cb.attacker.test",
            "https://app.test.attacker.test/cb",
            "http://app.test/cb",
        ] {
            let mut req = request(&["openid"]);
            req.redirect_uri = hostile.into();
            assert!(
                matches!(
                    service.authorize(req).await,
                    Err(AmiError::InvalidParameter { .. })
                ),
                "{hostile} was accepted"
            );
        }
    }

    #[tokio::test]
    async fn a_client_not_registered_for_the_grant_cannot_start_the_flow() {
        let service = service_with(
            vec![GrantType::ClientCredentials],
            vec![REDIRECT.to_string()],
        )
        .await;
        service
            .grant_consent("app", "alice", vec!["openid".into()])
            .await
            .unwrap();

        assert!(matches!(
            service.authorize(request(&["openid"])).await,
            Err(AmiError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn a_scope_outside_the_client_set_is_refused_at_authorization() {
        let service = service().await;
        let mut req = request(&["openid"]);
        req.scopes = vec!["billing:write".into()];

        assert!(matches!(
            service.authorize(req).await,
            Err(AmiError::InvalidParameter { .. })
        ));
    }

    #[tokio::test]
    async fn an_expired_code_is_refused() {
        let service = service().await;
        let code = AuthorizationCode {
            code: "stale".into(),
            client_id: "app".into(),
            user_name: "alice".into(),
            scopes: vec!["openid".into()],
            redirect_uri: REDIRECT.into(),
            challenge: Some(CodeChallenge::s256(derive_s256_challenge(VERIFIER))),
            nonce: None,
            expires_at: Utc::now() - chrono::Duration::seconds(1),
        };
        service
            .store
            .write()
            .await
            .store_authorization_code(code)
            .await
            .unwrap();

        assert!(matches!(
            service.exchange_code(exchange("stale", VERIFIER)).await,
            Err(AmiError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn a_code_belonging_to_another_client_cannot_be_redeemed() {
        let service = service().await;
        let other = build_client(
            "other".into(),
            "other-secret",
            "Other".into(),
            vec![GrantType::AuthorizationCode],
            vec!["openid".into()],
            AUD.to_string(),
            vec![REDIRECT.to_string()],
        )
        .unwrap();
        service.register_client(other).await.unwrap();

        let code = a_code(&service, &["openid"]).await;
        let mut stolen = exchange(&code, VERIFIER);
        stolen.client_id = "other".into();
        stolen.client_secret = "other-secret".into();

        assert!(matches!(
            service.exchange_code(stolen).await,
            Err(AmiError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn wrong_client_credentials_never_reach_the_code() {
        let service = service().await;
        let code = a_code(&service, &["openid"]).await;

        let mut wrong = exchange(&code, VERIFIER);
        wrong.client_secret = "guessed".into();
        assert!(service.exchange_code(wrong).await.is_err());

        // The code survived: a failed *authentication* must not spend it, or
        // anyone could burn a code by guessing at the secret.
        assert!(service
            .exchange_code(exchange(&code, VERIFIER))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn a_refresh_token_works_once_and_yields_a_new_one() {
        let service = service().await;
        let code = a_code(&service, &["openid", "email"]).await;
        let first = service
            .exchange_code(exchange(&code, VERIFIER))
            .await
            .unwrap();

        let second = service
            .refresh_tokens("app", "s3cret", &first.refresh_token)
            .await
            .unwrap();
        assert_ne!(second.refresh_token, first.refresh_token, "it rotated");
        assert_eq!(second.scope, first.scope, "scopes carry over");

        let claims: OAuthClaims = service
            .keys
            .verify_claims(&second.access_token, AUD)
            .unwrap();
        assert_eq!(claims.sub, "alice");

        // A refreshed ID token carries no nonce: the original belonged to one
        // sign-in.
        let id: IdTokenClaims = service
            .keys
            .verify_claims(second.id_token.as_ref().unwrap(), "app")
            .unwrap();
        assert_eq!(id.nonce, None);
    }

    #[tokio::test]
    async fn reusing_a_refresh_token_revokes_the_whole_chain() {
        let service = service().await;
        let code = a_code(&service, &["openid"]).await;
        let first = service
            .exchange_code(exchange(&code, VERIFIER))
            .await
            .unwrap();
        let second = service
            .refresh_tokens("app", "s3cret", &first.refresh_token)
            .await
            .unwrap();

        // The attacker replays the token the legitimate client already spent.
        let err = service
            .refresh_tokens("app", "s3cret", &first.refresh_token)
            .await
            .unwrap_err();
        assert!(matches!(err, AmiError::AccessDenied { .. }));

        // And the legitimate client is locked out too. That is intended: we
        // cannot tell which of the two is the thief, so both sign in again.
        assert!(
            service
                .refresh_tokens("app", "s3cret", &second.refresh_token)
                .await
                .is_err(),
            "the chain should have been revoked"
        );
    }

    #[tokio::test]
    async fn an_unknown_or_foreign_refresh_token_is_refused() {
        let service = service().await;
        assert!(service
            .refresh_tokens("app", "s3cret", "never-issued")
            .await
            .is_err());

        let other = build_client(
            "other".into(),
            "other-secret",
            "Other".into(),
            vec![GrantType::RefreshToken],
            vec!["openid".into()],
            AUD.to_string(),
            vec![REDIRECT.to_string()],
        )
        .unwrap();
        service.register_client(other).await.unwrap();

        let code = a_code(&service, &["openid"]).await;
        let tokens = service
            .exchange_code(exchange(&code, VERIFIER))
            .await
            .unwrap();

        assert!(
            service
                .refresh_tokens("other", "other-secret", &tokens.refresh_token)
                .await
                .is_err(),
            "a refresh token is bound to the client it was issued to"
        );
    }

    #[tokio::test]
    async fn withdrawing_consent_stops_the_refresh_tokens_it_backed() {
        // Otherwise the user says no and the client keeps minting access tokens
        // for a month.
        let service = service().await;
        let code = a_code(&service, &["openid"]).await;
        let tokens = service
            .exchange_code(exchange(&code, VERIFIER))
            .await
            .unwrap();

        assert!(service.withdraw_consent("app", "alice").await.unwrap());
        assert!(service
            .refresh_tokens("app", "s3cret", &tokens.refresh_token)
            .await
            .is_err());

        // And the next authorization asks again.
        assert!(matches!(
            service.authorize(request(&["openid"])).await.unwrap(),
            Authorization::ConsentRequired { .. }
        ));
    }

    #[tokio::test]
    async fn userinfo_releases_only_what_the_scopes_granted() {
        let service = service().await;
        let code = a_code(&service, &["openid", "email"]).await;
        let tokens = service
            .exchange_code(exchange(&code, VERIFIER))
            .await
            .unwrap();

        let info = service.user_info(&tokens.access_token, AUD).await.unwrap();
        assert_eq!(info.sub, "alice");
        assert_eq!(info.email.as_deref(), Some("alice@example.test"));
        assert_eq!(info.name, None, "profile was not granted");
    }

    #[tokio::test]
    async fn userinfo_refuses_a_token_with_no_user_behind_it() {
        // A client_credentials token's subject is the client. Answering with it
        // as `sub` would tell the caller a person signed in when none did.
        let service = service_with(vec![GrantType::ClientCredentials], vec![]).await;
        let token = service
            .issue_token(GrantRequest::ClientCredentials {
                client_id: "app".into(),
                client_secret: "s3cret".into(),
                scope: vec!["reports:read".into()],
            })
            .await
            .unwrap();

        assert!(matches!(
            service.user_info(&token.access_token, AUD).await,
            Err(AmiError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn userinfo_refuses_a_revoked_token() {
        let service = service().await;
        let code = a_code(&service, &["openid"]).await;
        let tokens = service
            .exchange_code(exchange(&code, VERIFIER))
            .await
            .unwrap();

        service.revoke_all_for_client("app").await.unwrap();
        assert!(service.user_info(&tokens.access_token, AUD).await.is_err());
        assert!(service.user_info("not-a-jwt", AUD).await.is_err());
    }

    #[tokio::test]
    async fn a_service_without_a_claims_source_releases_only_the_subject() {
        let service = OAuthService::new(
            Arc::new(RwLock::new(InMemoryOAuthStore::new())),
            Arc::new(KeyManager::generate()),
            "https://id.test".to_string(),
        );
        let client = build_client(
            "app".into(),
            "s3cret",
            "The App".into(),
            vec![GrantType::AuthorizationCode],
            vec!["openid".into(), "email".into()],
            AUD.to_string(),
            vec![REDIRECT.to_string()],
        )
        .unwrap();
        service.register_client(client).await.unwrap();

        let code = a_code(&service, &["openid", "email"]).await;
        let tokens = service
            .exchange_code(exchange(&code, VERIFIER))
            .await
            .unwrap();

        let info = service.user_info(&tokens.access_token, AUD).await.unwrap();
        assert_eq!(info.sub, "alice");
        assert_eq!(info.email, None, "there was nothing to ask");
    }

    #[tokio::test]
    async fn a_disabled_client_can_neither_authorize_nor_consent() {
        let service = service().await;
        service.disable_client("app").await.unwrap();

        assert!(matches!(
            service.authorize(request(&["openid"])).await,
            Err(AmiError::AccessDenied { .. })
        ));
        assert!(service
            .grant_consent("app", "alice", vec!["openid".into()])
            .await
            .is_err());
    }

    #[tokio::test]
    async fn a_user_cannot_consent_to_a_scope_the_client_never_had() {
        // Otherwise a host with a buggy consent screen could record approval
        // for something the client was never registered to ask for, and the
        // narrowing at authorization time would be the only thing left.
        let service = service().await;
        let err = service
            .grant_consent("app", "alice", vec!["billing:write".into()])
            .await
            .unwrap_err();
        assert!(matches!(err, AmiError::InvalidParameter { .. }));
    }

    #[tokio::test]
    async fn an_expired_refresh_token_is_refused_without_revoking_the_chain() {
        // Expiry is not a leak. Punishing it like one would sign every idle
        // user out of every other client they use.
        let service = service().await;
        let code = a_code(&service, &["openid"]).await;
        let live = service
            .exchange_code(exchange(&code, VERIFIER))
            .await
            .unwrap();

        let stale = RefreshToken {
            token: "stale".into(),
            client_id: "app".into(),
            user_name: "alice".into(),
            scopes: vec!["openid".into()],
            expires_at: Utc::now() - chrono::Duration::seconds(1),
            used_at: None,
            replaced_by: None,
        };
        service
            .store
            .write()
            .await
            .store_refresh_token(stale)
            .await
            .unwrap();

        let err = service
            .refresh_tokens("app", "s3cret", "stale")
            .await
            .unwrap_err();
        assert!(matches!(err, AmiError::AccessDenied { .. }));
        assert!(
            !err.to_string().contains("reuse"),
            "an expiry must not be reported as a leak: {err}"
        );

        assert!(
            service
                .refresh_tokens("app", "s3cret", &live.refresh_token)
                .await
                .is_ok(),
            "the user's live token should have survived"
        );
    }

    #[tokio::test]
    async fn discovery_reports_this_services_issuer() {
        let service = service().await;
        let doc = service.discovery("https://id.test");
        assert_eq!(doc.issuer, "https://id.test");
        assert_eq!(doc.authorization_endpoint, "https://id.test/authorize");
        assert_eq!(doc.code_challenge_methods_supported, vec!["S256"]);
    }
}
