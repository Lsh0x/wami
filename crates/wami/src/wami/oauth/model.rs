//! OAuth 2.0 domain types.
//!
//! Machine-to-machine only: a service presents credentials and gets a token.
//! The flows that involve a human — authorization code, PKCE, consent — need
//! redirects and replay protection, and live elsewhere.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// How a client is allowed to obtain a token.
///
/// Only `client_credentials` is honoured today. The variant is an enum rather
/// than a bare string so that registering a client for a grant the library
/// cannot yet perform is a type error, not a runtime surprise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantType {
    /// The client authenticates as itself. No user is involved.
    ClientCredentials,
    /// A user authorises the client, which then exchanges a code for a token.
    AuthorizationCode,
    /// The client trades a refresh token for a fresh access token.
    RefreshToken,
}

/// A registered OAuth client.
///
/// The secret is stored hashed, like every other credential in this library —
/// see [`OAuthClient::secret_hash`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthClient {
    /// Public identifier, safe to log.
    pub client_id: String,
    /// bcrypt hash of the secret. Never the secret itself.
    pub secret_hash: String,
    /// Human-readable name, for operators reading a client list.
    pub name: String,
    /// Grants this client may use.
    pub grant_types: Vec<GrantType>,
    /// Scopes this client may ask for. A request for anything outside this set
    /// is refused rather than silently narrowed — a client that believes it
    /// holds a scope it does not is worse than one told it cannot have it.
    pub scopes: Vec<String>,
    /// The audience tokens for this client are minted with.
    pub audience: String,
    /// Where the authorization server may redirect back to.
    ///
    /// Matched exactly — never by prefix. A prefix match on
    /// `https://app.example.com/cb` would accept
    /// `https://app.example.com/cb.attacker.test`, which is how authorization
    /// codes get delivered to the wrong party.
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    /// When the client was registered.
    pub created_at: DateTime<Utc>,
    /// Whether the client may still obtain tokens.
    pub enabled: bool,
}

impl OAuthClient {
    /// Whether this client is allowed to use `grant`.
    pub fn allows_grant(&self, grant: GrantType) -> bool {
        self.grant_types.contains(&grant)
    }

    /// Whether `uri` is one this client registered, compared exactly.
    pub fn allows_redirect(&self, uri: &str) -> bool {
        self.redirect_uris
            .iter()
            .any(|registered| registered == uri)
    }

    /// The subset of `requested` this client may have, or the first scope it
    /// may not.
    ///
    /// An empty request means "everything you are entitled to", matching
    /// RFC 6749 §3.3, where an omitted scope leaves the choice to the server.
    pub fn narrow_scopes<'a>(&self, requested: &'a [String]) -> Result<Vec<String>, &'a str> {
        if requested.is_empty() {
            return Ok(self.scopes.clone());
        }
        if let Some(refused) = requested.iter().find(|s| !self.scopes.contains(s)) {
            return Err(refused);
        }
        Ok(requested.to_vec())
    }
}

/// What a caller asks for when it wants a token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GrantRequest {
    /// RFC 6749 §4.4 — the client authenticates as itself.
    ClientCredentials {
        /// The client's public identifier.
        client_id: String,
        /// The client's secret, in the clear, checked against the stored hash.
        client_secret: String,
        /// Scopes asked for. Empty means every scope the client holds.
        scope: Vec<String>,
    },
}

/// The claims carried by an OAuth access token.
///
/// Deliberately separate from `StsClaims`: the two are signed by the same keys
/// but answer to different specifications, and merging them would mean every
/// STS change had to be checked against RFC 7662.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthClaims {
    /// Subject — the client, since no user is involved in this grant.
    pub sub: String,
    /// Issuer.
    pub iss: String,
    /// Audience.
    pub aud: String,
    /// Expiry, as a Unix timestamp.
    pub exp: i64,
    /// Issue time, as a Unix timestamp.
    pub iat: i64,
    /// Token id. This is what revocation records, so it must be unique per
    /// token rather than per client.
    pub jti: String,
    /// Granted scopes, space-delimited as RFC 6749 §3.3 requires.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub scope: String,
    /// The client that obtained the token. Redundant with `sub` for this grant,
    /// and not for the ones that will follow — a token obtained on behalf of a
    /// user has a user as `sub` and still needs to name the client.
    pub client_id: String,
}

/// A token as it was issued, for the store to keep.
///
/// The signed JWT is verifiable offline, so this record exists for exactly one
/// reason: revocation. A signed token stays valid until it expires unless
/// something is asked, and this is the thing that gets asked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessToken {
    /// The `jti` of the token, and the key it is revoked by.
    pub jti: String,
    /// Which client holds it.
    pub client_id: String,
    /// What it grants.
    pub scopes: Vec<String>,
    /// When it was issued.
    pub issued_at: DateTime<Utc>,
    /// When it stops being valid on its own.
    pub expires_at: DateTime<Utc>,
    /// When it was revoked, if it was.
    pub revoked_at: Option<DateTime<Utc>>,
}

impl AccessToken {
    /// Whether the token is still usable at `now`.
    pub fn is_active_at(&self, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_none() && self.expires_at > now
    }
}

/// The response to a successful token request — RFC 6749 §5.1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenResponse {
    /// The signed JWT.
    pub access_token: String,
    /// Always `Bearer` here.
    pub token_type: String,
    /// Lifetime in seconds, as the RFC specifies — not an absolute time.
    pub expires_in: i64,
    /// Granted scopes, space-delimited. May be narrower than requested.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub scope: String,
}

/// The answer to an introspection request — RFC 7662 §2.2.
///
/// Every field but `active` is absent when the token is not active. The RFC is
/// explicit about this: an inactive token must not leak who it belonged to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenIntrospection {
    /// Whether the token is currently valid.
    pub active: bool,
    /// Granted scopes, space-delimited.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// The client the token was issued to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Subject.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// Expiry, as a Unix timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    /// Issue time, as a Unix timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    /// Token id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}

impl TokenIntrospection {
    /// The answer for a token that is expired, revoked, forged, or unknown.
    ///
    /// One shape for all four on purpose: telling them apart would let an
    /// attacker probe for which token ids exist.
    pub fn inactive() -> Self {
        Self {
            active: false,
            scope: None,
            client_id: None,
            sub: None,
            exp: None,
            iat: None,
            jti: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(scopes: &[&str]) -> OAuthClient {
        OAuthClient {
            client_id: "c".into(),
            secret_hash: "h".into(),
            name: "n".into(),
            grant_types: vec![GrantType::ClientCredentials],
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            audience: "wami".into(),
            redirect_uris: vec![],
            created_at: Utc::now(),
            enabled: true,
        }
    }

    #[test]
    fn an_empty_scope_request_means_everything_the_client_holds() {
        let c = client(&["read", "write"]);
        assert_eq!(c.narrow_scopes(&[]).unwrap(), vec!["read", "write"]);
    }

    #[test]
    fn a_scope_the_client_does_not_hold_is_refused_not_dropped() {
        // Silently narrowing would hand back a token the caller believes is
        // broader than it is — the failure would surface later, elsewhere.
        let c = client(&["read"]);
        let asked = vec!["read".to_string(), "write".to_string()];
        assert_eq!(c.narrow_scopes(&asked), Err("write"));
    }

    #[test]
    fn a_subset_is_granted_as_asked() {
        let c = client(&["read", "write"]);
        let asked = vec!["read".to_string()];
        assert_eq!(c.narrow_scopes(&asked).unwrap(), vec!["read"]);
    }

    #[test]
    fn a_revoked_token_is_inactive_even_before_it_expires() {
        let now = Utc::now();
        let mut token = AccessToken {
            jti: "j".into(),
            client_id: "c".into(),
            scopes: vec![],
            issued_at: now,
            expires_at: now + chrono::Duration::hours(1),
            revoked_at: None,
        };
        assert!(token.is_active_at(now));

        token.revoked_at = Some(now);
        assert!(!token.is_active_at(now));
    }

    #[test]
    fn an_expired_token_is_inactive_even_though_it_was_never_revoked() {
        let now = Utc::now();
        let token = AccessToken {
            jti: "j".into(),
            client_id: "c".into(),
            scopes: vec![],
            issued_at: now - chrono::Duration::hours(2),
            expires_at: now - chrono::Duration::hours(1),
            revoked_at: None,
        };
        assert!(!token.is_active_at(now));
    }

    #[test]
    fn an_inactive_introspection_reveals_nothing_else() {
        // RFC 7662: an inactive token must not disclose who held it.
        let json = serde_json::to_value(TokenIntrospection::inactive()).unwrap();
        assert_eq!(json, serde_json::json!({ "active": false }));
    }
}
