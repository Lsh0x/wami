//! JWT Ed25519 token signing for STS credentials.
//!
//! When a signing keypair is configured, STS services produce a signed JWT
//! alongside the opaque session token. The JWT contains structured claims
//! (StsClaims) verifiable offline by any party holding the public key.
//!
//! This module requires the `sts-jwt` feature (enabled by default).

use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::pkcs8::spki::EncodePublicKey;
use ed25519_dalek::{SigningKey, VerifyingKey};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use super::credentials::Credentials;

/// Structured claims embedded in a signed JWT for STS credentials.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StsClaims {
    /// Subject: the principal ARN
    pub sub: String,
    /// Issuer
    pub iss: String,
    /// Audience
    pub aud: String,
    /// Expiration time (Unix timestamp)
    pub exp: i64,
    /// Issued at (Unix timestamp)
    pub iat: i64,
    /// Unique token ID (credential access_key_id)
    pub jti: String,
    /// Optional tenant ID for multi-tenant isolation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Optional Space ID — set when the JWT is scoped to a specific Space.
    /// Determines which Space's resources the bearer can access.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space_id: Option<String>,
    /// The bearer's role within the Space (e.g. "owner", "admin", "member", "viewer").
    /// Only meaningful when `space_id` is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space_role: Option<String>,
    /// Actions the credential is scoped to
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scoped_actions: Vec<String>,
    /// Resources the credential is scoped to
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scoped_resources: Vec<String>,
}

/// Context for building STS claims from credentials.
pub struct StsClaimsContext {
    /// The principal ARN (subject)
    pub principal_arn: String,
    /// Issuer string
    pub issuer: String,
    /// Audience string
    pub audience: String,
    /// Actions the credential is scoped to
    pub scoped_actions: Vec<String>,
    /// Resources the credential is scoped to
    pub scoped_resources: Vec<String>,
}

/// Build STS claims from credentials and context.
pub fn build_sts_claims(credentials: &Credentials, context: &StsClaimsContext) -> StsClaims {
    StsClaims {
        sub: context.principal_arn.clone(),
        iss: context.issuer.clone(),
        aud: context.audience.clone(),
        exp: credentials.expiration.timestamp(),
        iat: chrono::Utc::now().timestamp(),
        jti: credentials.access_key_id.clone(),
        tenant_id: credentials.tenant_id.as_ref().map(|t| t.to_string()),
        space_id: None,
        space_role: None,
        scoped_actions: context.scoped_actions.clone(),
        scoped_resources: context.scoped_resources.clone(),
    }
}

/// Manages Ed25519 keypair for JWT signing and verification.
pub struct KeyManager {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl KeyManager {
    /// Generate a new random Ed25519 keypair.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Create a KeyManager from an existing 32-byte secret.
    pub fn from_bytes(secret: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(secret);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Sign claims and produce a JWT string.
    ///
    /// Uses standard PKCS#8 DER encoding for the Ed25519 signing key.
    pub fn sign_claims(&self, claims: &StsClaims) -> Result<String, JwtError> {
        let header = Header::new(Algorithm::EdDSA);
        let pkcs8_der = self
            .signing_key
            .to_pkcs8_der()
            .map_err(|e| JwtError::KeyEncoding(e.to_string()))?;
        let encoding_key = EncodingKey::from_ed_der(pkcs8_der.as_bytes());
        encode(&header, claims, &encoding_key).map_err(JwtError::Encode)
    }

    /// Verify a JWT token and return the claims.
    ///
    /// Note: `jsonwebtoken` with the `ring` backend expects raw 32-byte Ed25519
    /// public keys via `from_ed_der` (despite the function name suggesting DER).
    /// The audience claim is validated against `["wami"]`.
    pub fn verify_token(&self, token: &str) -> Result<StsClaims, JwtError> {
        // jsonwebtoken + ring expects raw 32-byte Ed25519 public key, not SPKI DER.
        // This is a known quirk of the `from_ed_der` API naming.
        let decoding_key = DecodingKey::from_ed_der(&self.verifying_key.to_bytes());
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_required_spec_claims(&["exp", "iat", "sub", "iss", "aud"]);
        validation.set_audience(&["wami"]);
        // validate_aud defaults to true and set_audience configures the expected
        // values — audience IS validated.
        let token_data =
            decode::<StsClaims>(token, &decoding_key, &validation).map_err(JwtError::Decode)?;
        Ok(token_data.claims)
    }

    /// Return the public key as standard SPKI PEM (SubjectPublicKeyInfo).
    ///
    /// The returned PEM can be consumed by standard tools (openssl, external JWT
    /// libraries) to verify tokens produced by this KeyManager.
    pub fn public_key_pem(&self) -> Result<String, JwtError> {
        let spki_der = self
            .verifying_key
            .to_public_key_der()
            .map_err(|e| JwtError::KeyEncoding(e.to_string()))?;
        let b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            spki_der.as_ref(),
        );
        // PEM wraps base64 at 64 characters per line
        let lines: Vec<&str> = b64
            .as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        Ok(format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
            lines.join("\n")
        ))
    }

    /// Return the public key as SPKI DER bytes (SubjectPublicKeyInfo).
    ///
    /// This is the standard DER encoding suitable for interoperability with
    /// external verification libraries.
    pub fn public_key_spki_der(&self) -> Result<Vec<u8>, JwtError> {
        let spki_der = self
            .verifying_key
            .to_public_key_der()
            .map_err(|e| JwtError::KeyEncoding(e.to_string()))?;
        Ok(spki_der.as_ref().to_vec())
    }

    /// Return the raw 32-byte public key.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Return the raw 32-byte secret key (for persistence).
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }
}

/// Errors that can occur during JWT operations.
#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    #[error("JWT encoding error: {0}")]
    Encode(jsonwebtoken::errors::Error),
    #[error("JWT decoding error: {0}")]
    Decode(jsonwebtoken::errors::Error),
    #[error("Key encoding error: {0}")]
    KeyEncoding(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_credentials() -> Credentials {
        use crate::arn::{TenantPath, WamiArn};

        let wami_arn = WamiArn::builder()
            .service(crate::arn::Service::Sts)
            .tenant_path(TenantPath::single(0))
            .wami_instance("123456789012")
            .resource("credentials", "test")
            .build()
            .unwrap();

        Credentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_access_key: "secret".to_string(),
            session_token: "token".to_string(),
            expiration: chrono::Utc::now() + chrono::Duration::hours(1),
            arn: "arn:aws:sts::123456789012:assumed-role/TestRole/session".to_string(),
            wami_arn,
            providers: vec![],
            tenant_id: None,
            signed_token: None,
        }
    }

    fn test_claims_context() -> StsClaimsContext {
        StsClaimsContext {
            principal_arn: "arn:aws:iam::123456789012:user/alice".to_string(),
            issuer: "wami-sts".to_string(),
            audience: "wami".to_string(),
            scoped_actions: vec!["s3:GetObject".to_string()],
            scoped_resources: vec!["arn:aws:s3:::my-bucket/*".to_string()],
        }
    }

    #[test]
    fn test_keypair_generation() {
        let km1 = KeyManager::generate();
        let km2 = KeyManager::generate();

        // Two generated keypairs should have different public keys
        assert_ne!(km1.public_key_bytes(), km2.public_key_bytes());
        // Public key should be 32 bytes
        assert_eq!(km1.public_key_bytes().len(), 32);
    }

    #[test]
    fn test_keypair_from_bytes() {
        let km1 = KeyManager::generate();
        let secret = km1.signing_key.to_bytes();
        let km2 = KeyManager::from_bytes(&secret);

        assert_eq!(km1.public_key_bytes(), km2.public_key_bytes());
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let km = KeyManager::generate();
        let creds = test_credentials();
        let ctx = test_claims_context();
        let claims = build_sts_claims(&creds, &ctx);

        let token = km.sign_claims(&claims).expect("signing should succeed");
        assert!(!token.is_empty());

        let verified = km.verify_token(&token).expect("verification should succeed");
        assert_eq!(verified.sub, claims.sub);
        assert_eq!(verified.iss, claims.iss);
        assert_eq!(verified.jti, claims.jti);
        assert_eq!(verified.scoped_actions, claims.scoped_actions);
        assert_eq!(verified.scoped_resources, claims.scoped_resources);
    }

    #[test]
    fn test_claims_serialization() {
        let creds = test_credentials();
        let ctx = test_claims_context();
        let claims = build_sts_claims(&creds, &ctx);

        let json = serde_json::to_string(&claims).expect("serialization should succeed");
        let deserialized: StsClaims =
            serde_json::from_str(&json).expect("deserialization should succeed");

        assert_eq!(claims.sub, deserialized.sub);
        assert_eq!(claims.iss, deserialized.iss);
        assert_eq!(claims.aud, deserialized.aud);
        assert_eq!(claims.jti, deserialized.jti);
        assert_eq!(claims.tenant_id, deserialized.tenant_id);
        assert_eq!(claims.scoped_actions, deserialized.scoped_actions);
    }

    #[test]
    fn test_expired_token_rejection() {
        let km = KeyManager::generate();

        // Create claims that are already expired
        let claims = StsClaims {
            sub: "arn:aws:iam::123456789012:user/alice".to_string(),
            iss: "wami-sts".to_string(),
            aud: "wami".to_string(),
            exp: (chrono::Utc::now() - chrono::Duration::hours(1)).timestamp(),
            iat: (chrono::Utc::now() - chrono::Duration::hours(2)).timestamp(),
            jti: "AKIAEXPIRED".to_string(),
            tenant_id: None,
            space_id: None,
            space_role: None,
            scoped_actions: vec![],
            scoped_resources: vec![],
        };

        let token = km.sign_claims(&claims).expect("signing should succeed");
        let result = km.verify_token(&token);
        assert!(result.is_err(), "expired token should be rejected");
    }

    #[test]
    fn test_tampered_token_rejection() {
        let km = KeyManager::generate();
        let creds = test_credentials();
        let ctx = test_claims_context();
        let claims = build_sts_claims(&creds, &ctx);

        let token = km.sign_claims(&claims).expect("signing should succeed");

        // Tamper with the token by modifying a character in the signature part
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let mut tampered_sig = parts[2].to_string();
        // Flip a character
        if tampered_sig.ends_with('A') {
            tampered_sig.pop();
            tampered_sig.push('B');
        } else {
            tampered_sig.pop();
            tampered_sig.push('A');
        }
        let tampered_token = format!("{}.{}.{}", parts[0], parts[1], tampered_sig);

        let result = km.verify_token(&tampered_token);
        assert!(result.is_err(), "tampered token should be rejected");
    }

    #[test]
    fn test_different_key_rejection() {
        let km1 = KeyManager::generate();
        let km2 = KeyManager::generate();
        let creds = test_credentials();
        let ctx = test_claims_context();
        let claims = build_sts_claims(&creds, &ctx);

        let token = km1.sign_claims(&claims).expect("signing should succeed");
        let result = km2.verify_token(&token);
        assert!(
            result.is_err(),
            "token signed by different key should be rejected"
        );
    }

    #[test]
    fn test_public_key_pem_is_standard_spki() {
        let km = KeyManager::generate();
        let pem = km.public_key_pem().expect("PEM generation should succeed");

        // Standard SPKI PEM format
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        assert!(pem.ends_with("-----END PUBLIC KEY-----"));

        // Extract base64 content and verify it decodes to valid SPKI DER
        let b64_content: String = pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        let der_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &b64_content,
        )
        .expect("PEM content should be valid base64");

        // SPKI DER for Ed25519 is 44 bytes (12-byte header + 32-byte key)
        assert_eq!(der_bytes.len(), 44, "SPKI DER should be 44 bytes for Ed25519");

        // Verify the SPKI DER matches what public_key_spki_der returns
        let spki_der = km
            .public_key_spki_der()
            .expect("SPKI DER generation should succeed");
        assert_eq!(der_bytes, spki_der);
    }

    #[test]
    fn test_public_key_spki_der() {
        let km = KeyManager::generate();
        let spki_der = km
            .public_key_spki_der()
            .expect("SPKI DER generation should succeed");

        // Ed25519 SPKI DER: 44 bytes total
        // SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING { raw 32 bytes } }
        assert_eq!(spki_der.len(), 44);

        // Verify the raw public key bytes are embedded at the end
        let raw_bytes = km.public_key_bytes();
        assert_eq!(&spki_der[12..], &raw_bytes);
    }
}
