//! Pure constructors for OAuth domain objects.
//!
//! No store, no clock injection beyond what is passed in — the service layer
//! owns persistence, these build the values it persists.

use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;
use wami_core::error::{AmiError, Result};

use super::model::{AccessToken, GrantType, OAuthClaims, OAuthClient, TokenResponse};

/// How long an issued token lives.
///
/// Short by intent. A signed token cannot be recalled once handed out, so the
/// window between revoking a client and its last token dying is exactly this
/// value — see [`crate::service::oauth::OAuthService::revoke_token`].
pub const DEFAULT_TOKEN_LIFETIME: Duration = Duration::minutes(15);

/// Register a client, hashing the supplied secret.
///
/// The caller keeps the plaintext secret: this is the only moment it exists
/// outside the client's own configuration, exactly as with access keys.
pub fn build_client(
    client_id: String,
    plaintext_secret: &str,
    name: String,
    grant_types: Vec<GrantType>,
    scopes: Vec<String>,
    audience: String,
) -> Result<OAuthClient> {
    if client_id.trim().is_empty() {
        return Err(AmiError::InvalidParameter {
            message: "client_id cannot be empty".to_string(),
        });
    }
    if plaintext_secret.is_empty() {
        return Err(AmiError::InvalidParameter {
            message: "client secret cannot be empty".to_string(),
        });
    }
    if grant_types.is_empty() {
        return Err(AmiError::InvalidParameter {
            message: "a client with no grant types can never obtain a token".to_string(),
        });
    }

    Ok(OAuthClient {
        client_id,
        secret_hash: crate::service::auth::hash_secret(plaintext_secret)?,
        name,
        grant_types,
        scopes,
        audience,
        created_at: Utc::now(),
        enabled: true,
    })
}

/// Generate a client secret with 256 bits of entropy.
pub fn generate_client_secret() -> String {
    Uuid::new_v4().simple().to_string() + &Uuid::new_v4().simple().to_string()
}

/// Build the claims for an access token.
pub fn build_claims(
    client: &OAuthClient,
    scopes: &[String],
    issuer: &str,
    issued_at: DateTime<Utc>,
    lifetime: Duration,
) -> OAuthClaims {
    OAuthClaims {
        sub: client.client_id.clone(),
        iss: issuer.to_string(),
        aud: client.audience.clone(),
        exp: (issued_at + lifetime).timestamp(),
        iat: issued_at.timestamp(),
        jti: Uuid::new_v4().to_string(),
        scope: scopes.join(" "),
        client_id: client.client_id.clone(),
    }
}

/// The record kept so the token can later be revoked.
pub fn build_token_record(claims: &OAuthClaims, issued_at: DateTime<Utc>) -> AccessToken {
    AccessToken {
        jti: claims.jti.clone(),
        client_id: claims.client_id.clone(),
        scopes: if claims.scope.is_empty() {
            vec![]
        } else {
            claims.scope.split(' ').map(str::to_string).collect()
        },
        issued_at,
        expires_at: DateTime::from_timestamp(claims.exp, 0).unwrap_or(issued_at),
        revoked_at: None,
    }
}

/// Wrap a signed token in the RFC 6749 §5.1 response shape.
pub fn build_response(
    access_token: String,
    scopes: &[String],
    lifetime: Duration,
) -> TokenResponse {
    TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: lifetime.num_seconds(),
        scope: scopes.join(" "),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_client_secret_is_never_stored_in_the_clear() {
        let client = build_client(
            "svc".into(),
            "hunter2",
            "Service".into(),
            vec![GrantType::ClientCredentials],
            vec!["read".into()],
            "wami".into(),
        )
        .unwrap();

        assert_ne!(client.secret_hash, "hunter2");
        assert!(crate::service::auth::verify_secret("hunter2", &client.secret_hash).unwrap());
        assert!(!crate::service::auth::verify_secret("wrong", &client.secret_hash).unwrap());
    }

    #[test]
    fn a_client_that_could_never_get_a_token_is_refused_at_registration() {
        let err = build_client(
            "svc".into(),
            "s",
            "Service".into(),
            vec![],
            vec![],
            "wami".into(),
        )
        .unwrap_err();
        assert!(matches!(err, AmiError::InvalidParameter { .. }));
    }

    #[test]
    fn an_empty_id_or_secret_is_refused() {
        for (id, secret) in [("", "s"), ("  ", "s"), ("svc", "")] {
            assert!(build_client(
                id.into(),
                secret,
                "n".into(),
                vec![GrantType::ClientCredentials],
                vec![],
                "wami".into(),
            )
            .is_err());
        }
    }

    #[test]
    fn secrets_do_not_repeat() {
        let a = generate_client_secret();
        let b = generate_client_secret();
        assert_ne!(a, b);
        assert_eq!(a.len(), 64, "256 bits of hex");
    }

    #[test]
    fn every_token_gets_its_own_id_so_revocation_is_per_token() {
        let client = build_client(
            "svc".into(),
            "s",
            "Service".into(),
            vec![GrantType::ClientCredentials],
            vec!["read".into()],
            "wami".into(),
        )
        .unwrap();
        let now = Utc::now();
        let first = build_claims(
            &client,
            &["read".into()],
            "wami",
            now,
            Duration::minutes(15),
        );
        let second = build_claims(
            &client,
            &["read".into()],
            "wami",
            now,
            Duration::minutes(15),
        );

        assert_ne!(
            first.jti, second.jti,
            "a shared jti would revoke both at once"
        );
        assert_eq!(first.exp - first.iat, 900);
        assert_eq!(first.scope, "read");
    }

    #[test]
    fn a_token_record_round_trips_its_scopes() {
        let client = build_client(
            "svc".into(),
            "s",
            "Service".into(),
            vec![GrantType::ClientCredentials],
            vec!["read".into(), "write".into()],
            "wami".into(),
        )
        .unwrap();
        let now = Utc::now();
        let claims = build_claims(
            &client,
            &["read".into(), "write".into()],
            "wami",
            now,
            Duration::minutes(15),
        );
        let record = build_token_record(&claims, now);

        assert_eq!(record.scopes, vec!["read", "write"]);
        assert_eq!(record.jti, claims.jti);
        assert!(record.revoked_at.is_none());

        // A scopeless token must not produce a single empty-string scope.
        let bare = build_claims(&client, &[], "wami", now, Duration::minutes(15));
        assert!(build_token_record(&bare, now).scopes.is_empty());
    }
}
