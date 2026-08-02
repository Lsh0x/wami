//! OAuth 2.0 authorization server — machine-to-machine grants.
//!
//! Issues short-lived signed JWTs to services that authenticate as themselves,
//! and answers introspection and revocation for them.
//!
//! # Why a store is involved at all
//!
//! A signed token is verifiable offline: any holder of the public key can check
//! it without asking wami anything. That is the point, and it is also why
//! revocation needs a record — a signed token stays valid until its `exp` no
//! matter what the issuer later decides. Everything else here could be
//! stateless; revocation cannot.
//!
//! # Example
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use tokio::sync::RwLock;
//! use wami::store::memory::InMemoryOAuthStore;
//! use wami::wami::oauth::{build_client, GrantRequest, GrantType};
//! use wami::wami::sts::jwt::KeyManager;
//! use wami::service::oauth::OAuthService;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let store = Arc::new(RwLock::new(InMemoryOAuthStore::new()));
//! let keys = Arc::new(KeyManager::generate());
//! let service = OAuthService::new(store, keys, "wami".to_string());
//!
//! let client = build_client(
//!     "reporting".into(),
//!     "s3cret",
//!     "Reporting job".into(),
//!     vec![GrantType::ClientCredentials],
//!     vec!["reports:read".into()],
//!     "wami".into(),
//! )?;
//! service.register_client(client).await?;
//!
//! let token = service
//!     .issue_token(GrantRequest::ClientCredentials {
//!         client_id: "reporting".into(),
//!         client_secret: "s3cret".into(),
//!         scope: vec!["reports:read".into()],
//!     })
//!     .await?;
//! println!("{} expires in {}s", token.token_type, token.expires_in);
//! # Ok(())
//! # }
//! ```

use chrono::{Duration, Utc};
use std::sync::Arc;
use tokio::sync::RwLock;
use wami_core::error::{AmiError, Result};

use crate::service::auth::verify_secret;
use crate::store::traits::oauth::{OAuthClientStore, OAuthTokenStore};
use crate::wami::oauth::{
    builder, GrantRequest, GrantType, OAuthClaims, OAuthClient, TokenIntrospection, TokenResponse,
    DEFAULT_TOKEN_LIFETIME,
};
use crate::wami::sts::jwt::KeyManager;

/// Combined bound for a store that can hold clients and tokens.
pub trait OAuthStore: OAuthClientStore + OAuthTokenStore {}
impl<T: OAuthClientStore + OAuthTokenStore> OAuthStore for T {}

/// Issues, introspects and revokes OAuth access tokens.
pub struct OAuthService<S> {
    store: Arc<RwLock<S>>,
    keys: Arc<KeyManager>,
    issuer: String,
    lifetime: Duration,
}

impl<S: OAuthStore> OAuthService<S> {
    /// Build a service signing with `keys` and claiming `issuer`.
    pub fn new(store: Arc<RwLock<S>>, keys: Arc<KeyManager>, issuer: String) -> Self {
        Self {
            store,
            keys,
            issuer,
            lifetime: DEFAULT_TOKEN_LIFETIME,
        }
    }

    /// Override how long issued tokens live.
    ///
    /// Shorter narrows the window in which a revoked token is still accepted by
    /// an offline verifier; longer reduces how often clients come back.
    pub fn with_token_lifetime(mut self, lifetime: Duration) -> Self {
        self.lifetime = lifetime;
        self
    }

    /// The public keys a verifier needs, as a JWKS.
    ///
    /// Serving this over HTTP is transport, and belongs to whatever hosts the
    /// library.
    pub fn jwks(&self) -> crate::wami::sts::jwt::Jwks {
        self.keys.jwks()
    }

    /// Register a client.
    pub async fn register_client(&self, client: OAuthClient) -> Result<OAuthClient> {
        self.store.write().await.create_oauth_client(client).await
    }

    /// Authenticate a client by id and secret.
    ///
    /// Every failure — unknown id, wrong secret, disabled client — is reported
    /// the same way. Distinguishing them would turn this into an oracle for
    /// which client ids exist.
    pub async fn validate_client(&self, client_id: &str, secret: &str) -> Result<OAuthClient> {
        let refused = || AmiError::AccessDenied {
            message: "invalid client credentials".to_string(),
        };

        let client = self
            .store
            .read()
            .await
            .get_oauth_client(client_id)
            .await?
            .ok_or_else(refused)?;

        if !client.enabled || !verify_secret(secret, &client.secret_hash)? {
            return Err(refused());
        }

        Ok(client)
    }

    /// Issue an access token.
    ///
    /// # Errors
    ///
    /// [`AmiError::AccessDenied`] if the credentials are wrong, the client is
    /// disabled, or it is not registered for this grant.
    /// [`AmiError::InvalidParameter`] if it asked for a scope it does not hold.
    pub async fn issue_token(&self, request: GrantRequest) -> Result<TokenResponse> {
        let GrantRequest::ClientCredentials {
            client_id,
            client_secret,
            scope,
        } = request;

        let client = self.validate_client(&client_id, &client_secret).await?;

        if !client.allows_grant(GrantType::ClientCredentials) {
            return Err(AmiError::AccessDenied {
                message: format!("client {client_id} may not use the client_credentials grant"),
            });
        }

        let granted =
            client
                .narrow_scopes(&scope)
                .map_err(|refused| AmiError::InvalidParameter {
                    message: format!("client {client_id} is not entitled to scope {refused}"),
                })?;

        let issued_at = Utc::now();
        let claims =
            builder::build_claims(&client, &granted, &self.issuer, issued_at, self.lifetime);
        let signed = self
            .keys
            .sign_claims(&claims)
            .map_err(|e| AmiError::StoreError(format!("failed to sign token: {e}")))?;

        // Recorded before it is handed out: a token the caller holds but the
        // store never saw could not be revoked.
        self.store
            .write()
            .await
            .record_oauth_token(builder::build_token_record(&claims, issued_at))
            .await?;

        Ok(builder::build_response(signed, &granted, self.lifetime))
    }

    /// Answer an introspection request — RFC 7662.
    ///
    /// Never fails on a bad token: an expired, revoked, forged or unknown token
    /// all return `active: false` with nothing else. Returning an error instead
    /// would let a caller tell those apart.
    pub async fn introspect_token(
        &self,
        token: &str,
        audience: &str,
    ) -> Result<TokenIntrospection> {
        let Ok(claims) = self.keys.verify_claims::<OAuthClaims>(token, audience) else {
            return Ok(TokenIntrospection::inactive());
        };

        // The signature holds, but the issuer may have revoked it since.
        let Some(record) = self.store.read().await.get_oauth_token(&claims.jti).await? else {
            return Ok(TokenIntrospection::inactive());
        };
        if !record.is_active_at(Utc::now()) {
            return Ok(TokenIntrospection::inactive());
        }

        Ok(TokenIntrospection {
            active: true,
            scope: (!claims.scope.is_empty()).then(|| claims.scope.clone()),
            client_id: Some(claims.client_id),
            sub: Some(claims.sub),
            exp: Some(claims.exp),
            iat: Some(claims.iat),
            jti: Some(claims.jti),
        })
    }

    /// Revoke a token — RFC 7009.
    ///
    /// Succeeds whether or not the token existed, as the RFC requires: the
    /// caller learns only that the token is not usable, never whether it ever
    /// was. The `jti` is read from the signature, so a forged token revokes
    /// nothing.
    ///
    /// Note the limit this cannot escape: a verifier checking the signature
    /// offline will keep accepting the token until it expires. Revocation binds
    /// on anyone who introspects, which is why token lifetimes are short.
    pub async fn revoke_token(&self, token: &str, audience: &str) -> Result<()> {
        if let Ok(claims) = self.keys.verify_claims::<OAuthClaims>(token, audience) {
            self.store
                .write()
                .await
                .revoke_oauth_token(&claims.jti)
                .await?;
        }
        Ok(())
    }

    /// Revoke every token a client holds, and return how many.
    ///
    /// What to reach for when a client is compromised. Disabling the client
    /// stops new tokens; this stops the ones already issued.
    pub async fn revoke_all_for_client(&self, client_id: &str) -> Result<u64> {
        self.store
            .write()
            .await
            .revoke_oauth_tokens_for_client(client_id)
            .await
    }

    /// Stop a client obtaining new tokens, leaving existing ones alone.
    pub async fn disable_client(&self, client_id: &str) -> Result<OAuthClient> {
        let mut store = self.store.write().await;
        let mut client =
            store
                .get_oauth_client(client_id)
                .await?
                .ok_or_else(|| AmiError::ResourceNotFound {
                    resource: format!("OAuth client {client_id}"),
                })?;
        client.enabled = false;
        store.update_oauth_client(client).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::memory::InMemoryOAuthStore;
    use crate::wami::oauth::build_client;

    const AUD: &str = "wami";

    fn service() -> OAuthService<InMemoryOAuthStore> {
        OAuthService::new(
            Arc::new(RwLock::new(InMemoryOAuthStore::new())),
            Arc::new(KeyManager::generate()),
            "wami-oauth".to_string(),
        )
    }

    async fn with_client(scopes: &[&str]) -> OAuthService<InMemoryOAuthStore> {
        let service = service();
        let client = build_client(
            "svc".into(),
            "s3cret",
            "Service".into(),
            vec![GrantType::ClientCredentials],
            scopes.iter().map(|s| s.to_string()).collect(),
            AUD.to_string(),
        )
        .unwrap();
        service.register_client(client).await.unwrap();
        service
    }

    fn grant(scope: &[&str]) -> GrantRequest {
        GrantRequest::ClientCredentials {
            client_id: "svc".into(),
            client_secret: "s3cret".into(),
            scope: scope.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[tokio::test]
    async fn a_token_is_signed_by_the_shared_keyset_and_verifies_offline() {
        let service = with_client(&["read"]).await;
        let response = service.issue_token(grant(&["read"])).await.unwrap();

        assert_eq!(response.token_type, "Bearer");
        assert_eq!(response.expires_in, 900);
        assert_eq!(response.scope, "read");

        // The point of signing with the STS keyset: the same JWKS verifies it,
        // with no call back to wami.
        let claims = service
            .jwks()
            .keys
            .first()
            .map(|_| {
                service
                    .keys
                    .verify_claims::<OAuthClaims>(&response.access_token, AUD)
                    .unwrap()
            })
            .unwrap();
        assert_eq!(claims.client_id, "svc");
        assert_eq!(claims.iss, "wami-oauth");
    }

    #[tokio::test]
    async fn every_authentication_failure_looks_the_same() {
        // Otherwise the endpoint becomes an oracle for which client ids exist.
        let service = with_client(&["read"]).await;
        service.disable_client("svc").await.unwrap();

        let disabled = service.validate_client("svc", "s3cret").await.unwrap_err();
        let unknown = service
            .validate_client("ghost", "s3cret")
            .await
            .unwrap_err();
        let wrong = service.validate_client("svc", "nope").await.unwrap_err();

        for err in [&disabled, &unknown, &wrong] {
            assert!(matches!(err, AmiError::AccessDenied { .. }), "{err:?}");
        }
        assert_eq!(disabled.to_string(), unknown.to_string());
        assert_eq!(unknown.to_string(), wrong.to_string());
    }

    #[tokio::test]
    async fn a_scope_the_client_does_not_hold_is_refused() {
        let service = with_client(&["read"]).await;
        let err = service
            .issue_token(grant(&["read", "write"]))
            .await
            .unwrap_err();

        assert!(matches!(err, AmiError::InvalidParameter { .. }));
        assert!(err.to_string().contains("write"));
    }

    #[tokio::test]
    async fn an_empty_scope_request_yields_everything_the_client_holds() {
        let service = with_client(&["read", "write"]).await;
        let response = service.issue_token(grant(&[])).await.unwrap();
        assert_eq!(response.scope, "read write");
    }

    #[tokio::test]
    async fn introspection_reports_an_issued_token_as_active() {
        let service = with_client(&["read"]).await;
        let response = service.issue_token(grant(&["read"])).await.unwrap();

        let info = service
            .introspect_token(&response.access_token, AUD)
            .await
            .unwrap();
        assert!(info.active);
        assert_eq!(info.client_id.as_deref(), Some("svc"));
        assert_eq!(info.scope.as_deref(), Some("read"));
    }

    #[tokio::test]
    async fn a_revoked_token_introspects_as_inactive_and_reveals_nothing() {
        let service = with_client(&["read"]).await;
        let response = service.issue_token(grant(&["read"])).await.unwrap();

        service
            .revoke_token(&response.access_token, AUD)
            .await
            .unwrap();

        let info = service
            .introspect_token(&response.access_token, AUD)
            .await
            .unwrap();
        assert_eq!(info, TokenIntrospection::inactive());
    }

    #[tokio::test]
    async fn a_forged_or_unknown_token_is_inactive_rather_than_an_error() {
        let service = with_client(&["read"]).await;

        // Signed by somebody else entirely.
        let stranger = OAuthService::new(
            Arc::new(RwLock::new(InMemoryOAuthStore::new())),
            Arc::new(KeyManager::generate()),
            "elsewhere".to_string(),
        );
        let other_client = build_client(
            "svc".into(),
            "s3cret",
            "Service".into(),
            vec![GrantType::ClientCredentials],
            vec!["read".into()],
            AUD.to_string(),
        )
        .unwrap();
        stranger.register_client(other_client).await.unwrap();
        let foreign = stranger.issue_token(grant(&["read"])).await.unwrap();

        for token in [foreign.access_token.as_str(), "not-a-jwt", ""] {
            assert!(!service.introspect_token(token, AUD).await.unwrap().active);
        }
    }

    #[tokio::test]
    async fn revoking_an_unknown_token_still_succeeds() {
        // RFC 7009: the caller must not learn whether the token ever existed.
        let service = with_client(&["read"]).await;
        service.revoke_token("not-a-jwt", AUD).await.unwrap();
    }

    #[tokio::test]
    async fn a_token_for_another_audience_does_not_introspect_here() {
        // The audience split #114 made possible: a token minted for one
        // consumer must not read as active at another.
        let service = with_client(&["read"]).await;
        let response = service.issue_token(grant(&["read"])).await.unwrap();

        assert!(
            !service
                .introspect_token(&response.access_token, "somewhere-else")
                .await
                .unwrap()
                .active
        );
    }

    #[tokio::test]
    async fn compromising_a_client_can_be_contained_in_two_moves() {
        let service = with_client(&["read"]).await;
        let first = service.issue_token(grant(&["read"])).await.unwrap();
        let second = service.issue_token(grant(&["read"])).await.unwrap();

        // Stop the bleeding: no new tokens...
        service.disable_client("svc").await.unwrap();
        assert!(service.issue_token(grant(&["read"])).await.is_err());

        // ...and kill the ones already out.
        assert_eq!(service.revoke_all_for_client("svc").await.unwrap(), 2);
        for token in [&first, &second] {
            assert!(
                !service
                    .introspect_token(&token.access_token, AUD)
                    .await
                    .unwrap()
                    .active
            );
        }
    }

    #[tokio::test]
    async fn a_shorter_lifetime_narrows_the_revocation_window() {
        let service = with_client(&["read"])
            .await
            .with_token_lifetime(Duration::seconds(30));
        let response = service.issue_token(grant(&["read"])).await.unwrap();
        assert_eq!(response.expires_in, 30);
    }

    #[tokio::test]
    async fn a_client_registered_without_this_grant_cannot_use_it() {
        let service = service();
        let mut client = build_client(
            "svc".into(),
            "s3cret",
            "Service".into(),
            vec![GrantType::ClientCredentials],
            vec!["read".into()],
            AUD.to_string(),
        )
        .unwrap();
        // Registered for no grant at all — as a store row written elsewhere
        // could be, since the builder refuses to create one.
        client.grant_types.clear();
        service.register_client(client).await.unwrap();

        let err = service.issue_token(grant(&["read"])).await.unwrap_err();
        assert!(matches!(err, AmiError::AccessDenied { .. }));
        assert!(err.to_string().contains("client_credentials"));
    }
}
