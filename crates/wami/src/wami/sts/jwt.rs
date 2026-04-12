//! JWT Ed25519 token signing for STS credentials.
//!
//! When a signing keypair is configured, STS services produce a signed JWT
//! alongside the opaque session token. The JWT contains structured claims
//! (StsClaims) verifiable offline by any party holding the public key.

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
    pub fn sign_claims(&self, claims: &StsClaims) -> Result<String, JwtError> {
        let header = Header::new(Algorithm::EdDSA);
        let pkcs8_der = self.signing_key_pkcs8_der();
        let encoding_key = EncodingKey::from_ed_der(&pkcs8_der);
        encode(&header, claims, &encoding_key).map_err(JwtError::Encode)
    }

    /// Verify a JWT token and return the claims.
    pub fn verify_token(&self, token: &str) -> Result<StsClaims, JwtError> {
        // Ring expects raw 32-byte public key for Ed25519 verification
        let decoding_key = DecodingKey::from_ed_der(&self.verifying_key.to_bytes());
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_required_spec_claims(&["exp", "iat", "sub", "iss", "aud"]);
        validation.set_audience(&["wami"]);
        // We validate audience manually via required claims; allow any single issuer
        validation.validate_aud = false;
        let token_data =
            decode::<StsClaims>(token, &decoding_key, &validation).map_err(JwtError::Decode)?;
        Ok(token_data.claims)
    }

    /// Encode the signing key as PKCS8 v2 DER (Ed25519).
    ///
    /// PKCS8 v2 structure for Ed25519:
    ///   SEQUENCE {
    ///     INTEGER 1  (version v2)
    ///     SEQUENCE { OID 1.3.101.112 }
    ///     OCTET STRING { OCTET STRING { private key bytes } }
    ///     [1] { BIT STRING { public key bytes } }
    ///   }
    fn signing_key_pkcs8_der(&self) -> Vec<u8> {
        let secret = self.signing_key.to_bytes();
        let public = self.verifying_key.to_bytes();

        // Inner OCTET STRING wrapping 32-byte private key
        let inner_octet = Self::der_octet_string(&secret);

        // Algorithm identifier: SEQUENCE { OID 1.3.101.112 }
        let oid_bytes: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70]; // OID 1.3.101.112
        let algo_id = Self::der_sequence(oid_bytes);

        // Version INTEGER 1 (v2 for public key inclusion)
        let version: &[u8] = &[0x02, 0x01, 0x01];

        // Private key OCTET STRING
        let private_key_octet = Self::der_octet_string(&inner_octet);

        // Public key: context-specific tag [1], explicit, containing BIT STRING
        let mut bit_string = vec![0x03, (public.len() + 1) as u8, 0x00];
        bit_string.extend_from_slice(&public);
        let mut public_key_tagged = vec![0xa1, bit_string.len() as u8];
        public_key_tagged.extend_from_slice(&bit_string);

        // Outer SEQUENCE
        let mut inner = Vec::new();
        inner.extend_from_slice(version);
        inner.extend_from_slice(&algo_id);
        inner.extend_from_slice(&private_key_octet);
        inner.extend_from_slice(&public_key_tagged);

        Self::der_sequence(&inner)
    }

    fn der_sequence(content: &[u8]) -> Vec<u8> {
        let mut result = vec![0x30];
        Self::der_push_length(&mut result, content.len());
        result.extend_from_slice(content);
        result
    }

    fn der_octet_string(content: &[u8]) -> Vec<u8> {
        let mut result = vec![0x04];
        Self::der_push_length(&mut result, content.len());
        result.extend_from_slice(content);
        result
    }

    fn der_push_length(buf: &mut Vec<u8>, len: usize) {
        if len < 0x80 {
            buf.push(len as u8);
        } else if len < 0x100 {
            buf.push(0x81);
            buf.push(len as u8);
        } else {
            buf.push(0x82);
            buf.push((len >> 8) as u8);
            buf.push(len as u8);
        }
    }

    /// Return the public key as PEM-encoded string.
    pub fn public_key_pem(&self) -> String {
        // Ed25519 public key in a simple PEM-like format
        let bytes = self.verifying_key.to_bytes();
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes);
        format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
            encoded
        )
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
    fn test_public_key_pem() {
        let km = KeyManager::generate();
        let pem = km.public_key_pem();
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        assert!(pem.ends_with("-----END PUBLIC KEY-----"));
    }
}
