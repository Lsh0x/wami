//! OpenID Connect — the flows where a human is present.
//!
//! Authorization code with PKCE, refresh rotation, ID tokens and consent. What
//! separates these from `client_credentials` is not the cryptography but the
//! browser: a value travels through a user agent the server does not control,
//! so every step here exists to survive that trip.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use wami_core::error::{AmiError, Result};

/// How a PKCE verifier is bound to its challenge — RFC 7636 §4.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum CodeChallengeMethod {
    /// SHA-256 of the verifier, base64url without padding.
    S256,
}

/// The PKCE challenge a client commits to when it asks for a code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeChallenge {
    /// The challenge value.
    pub challenge: String,
    /// How it was derived.
    pub method: CodeChallengeMethod,
}

impl CodeChallenge {
    /// An S256 challenge.
    pub fn s256(challenge: impl Into<String>) -> Self {
        Self {
            challenge: challenge.into(),
            method: CodeChallengeMethod::S256,
        }
    }

    /// Whether `verifier` is the secret behind this challenge.
    ///
    /// `plain` is deliberately not supported. It offers no protection at all
    /// against the attack PKCE exists to stop — an attacker who intercepts the
    /// authorization request sees the challenge, and under `plain` the
    /// challenge *is* the verifier.
    pub fn verify(&self, verifier: &str) -> bool {
        match self.method {
            CodeChallengeMethod::S256 => {
                let digest = Sha256::digest(verifier.as_bytes());
                // Constant-time is not required here: the challenge is public,
                // and a mismatch reveals nothing an attacker cannot compute.
                URL_SAFE_NO_PAD.encode(digest) == self.challenge
            }
        }
    }
}

/// Derive the S256 challenge for a verifier. Useful to clients and to tests.
pub fn derive_s256_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// An authorization code, issued once a user has approved a client.
///
/// Short-lived and single-use. The store contract is that consuming it is one
/// operation — see [`OAuthAuthorizationStore::consume_authorization_code`].
///
/// [`OAuthAuthorizationStore::consume_authorization_code`]: crate::store::traits::oauth::OAuthAuthorizationStore::consume_authorization_code
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationCode {
    /// The opaque code handed to the user agent.
    pub code: String,
    /// Which client it was issued to.
    pub client_id: String,
    /// Which user approved.
    pub user_name: String,
    /// Scopes approved.
    pub scopes: Vec<String>,
    /// The redirect URI it was issued against.
    ///
    /// Replayed at exchange time and compared exactly: a code obtained for one
    /// redirect must not be redeemable against another.
    pub redirect_uri: String,
    /// The PKCE challenge the client committed to.
    pub challenge: Option<CodeChallenge>,
    /// The client's nonce, carried into the ID token.
    pub nonce: Option<String>,
    /// When it stops being redeemable.
    pub expires_at: DateTime<Utc>,
}

/// How long an authorization code stays redeemable.
///
/// Seconds, not minutes: it only has to survive one redirect. RFC 6749 §4.1.2
/// recommends a maximum of ten minutes; this is deliberately far below.
pub const AUTHORIZATION_CODE_LIFETIME: Duration = Duration::seconds(60);

/// How long a refresh token lives before the user must sign in again.
pub const REFRESH_TOKEN_LIFETIME: Duration = Duration::days(30);

/// A refresh token, exchangeable for a fresh access token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefreshToken {
    /// The opaque token value.
    pub token: String,
    /// Which client holds it.
    pub client_id: String,
    /// Which user it acts for.
    pub user_name: String,
    /// Scopes it can mint.
    pub scopes: Vec<String>,
    /// When it expires.
    pub expires_at: DateTime<Utc>,
    /// When it was used, if it was.
    ///
    /// Rotation means a refresh token is single-use. A second use is not an
    /// error to shrug at — it means the token leaked, because the legitimate
    /// client has already moved on to its replacement.
    pub used_at: Option<DateTime<Utc>>,
    /// The token issued in its place, if any. Lets a reuse be traced to the
    /// chain it came from.
    pub replaced_by: Option<String>,
}

impl RefreshToken {
    /// Whether the token can still be exchanged at `now`.
    pub fn is_usable_at(&self, now: DateTime<Utc>) -> bool {
        self.used_at.is_none() && self.expires_at > now
    }
}

/// A user's standing approval of a client's scopes.
///
/// Recorded so a returning user is not asked again for what they already
/// granted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserConsent {
    /// Which user approved.
    pub user_name: String,
    /// Which client they approved.
    pub client_id: String,
    /// What they approved.
    pub scopes: Vec<String>,
    /// When.
    pub granted_at: DateTime<Utc>,
}

impl UserConsent {
    /// Whether this consent already covers everything in `requested`.
    pub fn covers(&self, requested: &[String]) -> bool {
        requested.iter().all(|s| self.scopes.contains(s))
    }
}

/// The claims of an OpenID Connect ID token.
///
/// An ID token says *who signed in*; an access token says *what may be done*.
/// Keeping them separate is why this is not merely an access token with extra
/// fields — a resource server must never accept an ID token as authorisation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdTokenClaims {
    /// The user.
    pub sub: String,
    /// Who issued it.
    pub iss: String,
    /// The client it was minted for.
    pub aud: String,
    /// Expiry.
    pub exp: i64,
    /// Issue time.
    pub iat: i64,
    /// Echo of the client's nonce.
    ///
    /// The client generated it, and checks it comes back unchanged. That is
    /// what stops an ID token captured from one sign-in being replayed into
    /// another.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Present when the `profile` scope was granted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Present when the `email` scope was granted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

// Two claims a reviewer will look for here and not find.
//
// `at_hash` is OPTIONAL for an ID token returned from the token endpoint in the
// authorization code flow (OIDC Core §3.1.3.6 — it is only REQUIRED where a
// token arrives through the front channel, which this library never does).
// Emitting one would also mean choosing a hash for `alg: EdDSA`, which no
// specification defines: implementations disagree between SHA-256 and Ed25519's
// internal SHA-512. An `at_hash` a relying party computes differently is a hard
// validation failure, where its absence is a no-op. Absent is the safer answer
// until EdDSA has a settled convention.
//
// `auth_time`, `acr` and `amr` describe the authentication event, and wami does
// not perform it — the host does, before it ever calls `authorize`. Supporting
// them means the host passing the event in, which is additive and not yet done.

/// The profile claims wami puts in an ID token when the scopes allow it.
///
/// wami does not own your user directory. This is what the host hands over when
/// asked, and nothing here is stored by the library.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserProfile {
    /// Display name, released under the `profile` scope.
    pub name: Option<String>,
    /// Email address, released under the `email` scope.
    pub email: Option<String>,
}

/// What `/userinfo` answers — the same claims, without the token envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserInfo {
    /// The user.
    pub sub: String,
    /// Present when the `profile` scope was granted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Present when the `email` scope was granted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

/// The OpenID Provider metadata document — RFC 8414.
///
/// A value, not an endpoint: serving it is transport, and belongs to whatever
/// hosts the library.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryDocument {
    /// The issuer identifier.
    pub issuer: String,
    /// Where clients send users to authorise.
    pub authorization_endpoint: String,
    /// Where codes and refresh tokens are exchanged.
    pub token_endpoint: String,
    /// Where the signing keys are published.
    pub jwks_uri: String,
    /// Where user claims are served.
    pub userinfo_endpoint: String,
    /// Response types supported — `code` only; the implicit flow is not
    /// offered, having been deprecated for delivering tokens through the URL.
    pub response_types_supported: Vec<String>,
    /// Grants supported.
    pub grant_types_supported: Vec<String>,
    /// Subject identifier types.
    pub subject_types_supported: Vec<String>,
    /// Signing algorithms — Ed25519, matching the STS keyset.
    pub id_token_signing_alg_values_supported: Vec<String>,
    /// Scopes recognised.
    pub scopes_supported: Vec<String>,
    /// PKCE methods. `plain` is absent deliberately.
    pub code_challenge_methods_supported: Vec<String>,
}

/// Generate an opaque, unguessable value for a code or refresh token.
pub fn generate_opaque_value() -> String {
    Uuid::new_v4().simple().to_string() + &Uuid::new_v4().simple().to_string()
}

/// Release only the profile claims the granted scopes cover.
///
/// A single place decides this, so the ID token and `/userinfo` cannot drift
/// into disagreeing about what `profile` releases.
fn released<'a>(
    profile: &'a UserProfile,
    scopes: &[String],
) -> (Option<&'a String>, Option<&'a String>) {
    let has = |s: &str| scopes.iter().any(|g| g == s);
    (
        has("profile").then_some(profile.name.as_ref()).flatten(),
        has("email").then_some(profile.email.as_ref()).flatten(),
    )
}

/// Who an ID token is about, and for whom.
///
/// A struct rather than six positional arguments: `user_name`, `client_id` and
/// `issuer` are all `&str`, and swapping two of them would compile and mint a
/// token asserting the wrong thing.
#[derive(Debug, Clone)]
pub struct IdTokenRequest<'a> {
    /// The user who signed in — becomes `sub`.
    pub user_name: &'a str,
    /// The client that asked — becomes `aud`.
    pub client_id: &'a str,
    /// The provider — becomes `iss`.
    pub issuer: &'a str,
    /// The granted scopes, deciding which profile claims are released.
    pub scopes: &'a [String],
    /// What the host is willing to say about the user.
    pub profile: &'a UserProfile,
    /// The client's nonce, echoed back.
    pub nonce: Option<String>,
}

/// Build the claims of an ID token.
///
/// `aud` is the client, not the resource server: an ID token is addressed to
/// whoever asked who signed in, and a resource server that accepts one as
/// authorisation has confused the two.
pub fn build_id_token_claims(
    request: IdTokenRequest<'_>,
    issued_at: DateTime<Utc>,
    lifetime: Duration,
) -> IdTokenClaims {
    let (name, email) = released(request.profile, request.scopes);
    IdTokenClaims {
        sub: request.user_name.to_string(),
        iss: request.issuer.to_string(),
        aud: request.client_id.to_string(),
        exp: (issued_at + lifetime).timestamp(),
        iat: issued_at.timestamp(),
        nonce: request.nonce,
        name: name.cloned(),
        email: email.cloned(),
    }
}

/// The `/userinfo` answer for a user, narrowed to the granted scopes.
pub fn build_user_info(user_name: &str, scopes: &[String], profile: &UserProfile) -> UserInfo {
    let (name, email) = released(profile, scopes);
    UserInfo {
        sub: user_name.to_string(),
        name: name.cloned(),
        email: email.cloned(),
    }
}

/// The provider metadata for an issuer served at `base_url`.
///
/// Paths follow the conventional OIDC layout. A host that mounts them elsewhere
/// should build the document itself rather than move the endpoints and leave
/// this lying.
pub fn build_discovery_document(issuer: &str, base_url: &str) -> DiscoveryDocument {
    let base = base_url.trim_end_matches('/');
    DiscoveryDocument {
        issuer: issuer.to_string(),
        authorization_endpoint: format!("{base}/authorize"),
        token_endpoint: format!("{base}/token"),
        jwks_uri: format!("{base}/.well-known/jwks.json"),
        userinfo_endpoint: format!("{base}/userinfo"),
        response_types_supported: vec!["code".to_string()],
        grant_types_supported: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
            "client_credentials".to_string(),
        ],
        subject_types_supported: vec!["public".to_string()],
        id_token_signing_alg_values_supported: vec!["EdDSA".to_string()],
        scopes_supported: vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
        ],
        // `plain` is absent because it is not implemented, and it is not
        // implemented because it protects against nothing.
        code_challenge_methods_supported: vec!["S256".to_string()],
    }
}

/// Validate a redirect URI against a client's registered set.
///
/// # Errors
///
/// [`AmiError::InvalidParameter`] when it is not registered. Note this is
/// reported to the *caller of the library*, never redirected to: sending an
/// error to an unverified redirect URI is itself the vulnerability.
pub fn validate_redirect_uri(client: &super::model::OAuthClient, uri: &str) -> Result<()> {
    if client.allows_redirect(uri) {
        return Ok(());
    }
    Err(AmiError::InvalidParameter {
        message: format!(
            "redirect_uri {uri} is not registered for client {}",
            client.client_id
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_verifier_matches_only_its_own_challenge() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = CodeChallenge::s256(derive_s256_challenge(verifier));

        assert!(challenge.verify(verifier));
        assert!(!challenge.verify("something-else"));
        assert!(!challenge.verify(""));
    }

    #[test]
    fn s256_matches_the_rfc_7636_test_vector() {
        // RFC 7636 Appendix B publishes this pair. Pinning it here is what
        // stops the derivation from quietly becoming something no other
        // implementation agrees with.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            derive_s256_challenge(verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn a_refresh_token_is_usable_once() {
        let now = Utc::now();
        let mut token = RefreshToken {
            token: "t".into(),
            client_id: "c".into(),
            user_name: "alice".into(),
            scopes: vec![],
            expires_at: now + Duration::days(30),
            used_at: None,
            replaced_by: None,
        };
        assert!(token.is_usable_at(now));

        token.used_at = Some(now);
        assert!(
            !token.is_usable_at(now),
            "a second use means the token leaked"
        );
    }

    #[test]
    fn an_expired_refresh_token_is_not_usable() {
        let now = Utc::now();
        let token = RefreshToken {
            token: "t".into(),
            client_id: "c".into(),
            user_name: "alice".into(),
            scopes: vec![],
            expires_at: now - Duration::seconds(1),
            used_at: None,
            replaced_by: None,
        };
        assert!(!token.is_usable_at(now));
    }

    #[test]
    fn consent_covers_a_subset_but_not_a_superset() {
        let consent = UserConsent {
            user_name: "alice".into(),
            client_id: "c".into(),
            scopes: vec!["openid".into(), "profile".into()],
            granted_at: Utc::now(),
        };

        assert!(consent.covers(&["openid".to_string()]));
        assert!(consent.covers(&["openid".to_string(), "profile".to_string()]));
        assert!(!consent.covers(&["openid".to_string(), "email".to_string()]));
    }

    #[test]
    fn a_redirect_uri_is_matched_exactly_never_by_prefix() {
        use super::super::model::{GrantType, OAuthClient};

        let client = OAuthClient {
            client_id: "c".into(),
            secret_hash: "h".into(),
            name: "n".into(),
            grant_types: vec![GrantType::AuthorizationCode],
            scopes: vec![],
            audience: "wami".into(),
            redirect_uris: vec!["https://app.example.com/cb".into()],
            created_at: Utc::now(),
            enabled: true,
        };

        assert!(validate_redirect_uri(&client, "https://app.example.com/cb").is_ok());

        // Each of these would be accepted by a prefix match, and each delivers
        // the authorization code somewhere else.
        for hostile in [
            "https://app.example.com/cb.attacker.test",
            "https://app.example.com/cb/../evil",
            "https://app.example.com/cb?next=https://evil.test",
            "https://app.example.com.attacker.test/cb",
            "http://app.example.com/cb",
        ] {
            assert!(
                validate_redirect_uri(&client, hostile).is_err(),
                "{hostile} was accepted"
            );
        }
    }

    fn a_profile() -> UserProfile {
        UserProfile {
            name: Some("Alice".into()),
            email: Some("alice@example.test".into()),
        }
    }

    #[test]
    fn a_scope_that_was_not_granted_releases_nothing() {
        let scopes = vec!["openid".to_string()];
        let info = build_user_info("alice", &scopes, &a_profile());
        assert_eq!(info.sub, "alice");
        assert_eq!(info.name, None, "profile was not granted");
        assert_eq!(info.email, None, "email was not granted");

        let claims = build_id_token_claims(
            IdTokenRequest {
                user_name: "alice",
                client_id: "c",
                issuer: "wami",
                scopes: &scopes,
                profile: &a_profile(),
                nonce: None,
            },
            Utc::now(),
            Duration::minutes(5),
        );
        assert_eq!(claims.name, None);
        assert_eq!(claims.email, None);
    }

    #[test]
    fn each_profile_scope_releases_only_its_own_claim() {
        let profile = a_profile();
        let only_profile = build_user_info("alice", &["profile".to_string()], &profile);
        assert_eq!(only_profile.name.as_deref(), Some("Alice"));
        assert_eq!(only_profile.email, None);

        let only_email = build_user_info("alice", &["email".to_string()], &profile);
        assert_eq!(only_email.name, None);
        assert_eq!(only_email.email.as_deref(), Some("alice@example.test"));
    }

    #[test]
    fn the_id_token_and_userinfo_agree_on_what_a_scope_releases() {
        // They are two views of the same decision. Letting them diverge means
        // a claim withheld from one leaks through the other.
        let scopes = vec!["openid".to_string(), "email".to_string()];
        let profile = a_profile();
        let claims = build_id_token_claims(
            IdTokenRequest {
                user_name: "alice",
                client_id: "c",
                issuer: "wami",
                scopes: &scopes,
                profile: &profile,
                nonce: None,
            },
            Utc::now(),
            Duration::minutes(5),
        );
        let info = build_user_info("alice", &scopes, &profile);

        assert_eq!(claims.sub, info.sub);
        assert_eq!(claims.name, info.name);
        assert_eq!(claims.email, info.email);
    }

    #[test]
    fn an_id_token_is_addressed_to_the_client_and_echoes_its_nonce() {
        let now = Utc::now();
        let claims = build_id_token_claims(
            IdTokenRequest {
                user_name: "alice",
                client_id: "the-client",
                issuer: "wami",
                scopes: &["openid".to_string()],
                profile: &UserProfile::default(),
                nonce: Some("n-0S6_WzA2Mj".into()),
            },
            now,
            Duration::minutes(5),
        );

        assert_eq!(claims.sub, "alice", "the subject is who signed in");
        assert_eq!(claims.aud, "the-client", "not the resource server");
        assert_eq!(claims.iss, "wami");
        assert_eq!(claims.nonce.as_deref(), Some("n-0S6_WzA2Mj"));
        assert_eq!(claims.exp - claims.iat, 300);
    }

    #[test]
    fn discovery_never_advertises_plain_pkce_or_the_implicit_flow() {
        let doc = build_discovery_document("https://id.example.test", "https://id.example.test/");

        assert_eq!(doc.code_challenge_methods_supported, vec!["S256"]);
        assert_eq!(doc.response_types_supported, vec!["code"]);
        assert!(!doc.grant_types_supported.contains(&"implicit".to_string()));
        // A trailing slash on the base must not produce a doubled one.
        assert_eq!(doc.token_endpoint, "https://id.example.test/token");
        assert_eq!(
            doc.jwks_uri,
            "https://id.example.test/.well-known/jwks.json"
        );
    }

    #[test]
    fn opaque_values_do_not_repeat() {
        assert_ne!(generate_opaque_value(), generate_opaque_value());
        assert_eq!(generate_opaque_value().len(), 64);
    }
}
