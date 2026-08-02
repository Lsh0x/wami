//! JWT Ed25519 token signing for STS credentials.
//!
//! When a signing keypair is configured, STS services produce a signed JWT
//! alongside the opaque session token. The JWT contains structured claims
//! (StsClaims) verifiable offline by any party holding the public key.
//!
//! This module requires the `sts-jwt` feature (enabled by default).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::pkcs8::spki::EncodePublicKey;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::{SigningKey, VerifyingKey};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand::rngs::OsRng;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::credentials::Credentials;

/// A JWK Set: the public keys a verifier may use, as a value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Jwks {
    /// The keys, active first.
    pub keys: Vec<Jwk>,
}

/// One public key in JWK form (RFC 8037 OKP, Ed25519).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Jwk {
    /// Key type — always `OKP` for Ed25519.
    pub kty: String,
    /// Curve — always `Ed25519`.
    pub crv: String,
    /// Algorithm — always `EdDSA`.
    pub alg: String,
    /// Intended use — always `sig`.
    #[serde(rename = "use")]
    pub use_: String,
    /// The key id tokens signed by this key carry.
    pub kid: String,
    /// The public key, base64url without padding.
    pub x: String,
}

/// What a signed token declares itself to be, in the JOSE `typ` header.
///
/// # Why this exists
///
/// wami signs access tokens and ID tokens with one keyset. They are told apart
/// by `aud` — an access token names the resource server, an ID token names the
/// client — and that holds, as long as the verifier checks the audience.
/// RFC 9068 adds a structural label so it does not have to:
///
/// > The explicit typing required in this profile [...] helps the resource
/// > server to distinguish between JWT access tokens and OpenID Connect ID
/// > Tokens.
///
/// # Why it is not the default
///
/// Every token wami has issued so far carries `typ: JWT`. Switching that to
/// `at+jwt` unannounced would break a resource server that pins the old value.
/// Issuance is opt-in — see
/// [`OAuthService::with_explicit_typ`][crate::service::oauth::OAuthService::with_explicit_typ]
/// — and [`KeyManager::verify_claims`] never looks at the label at all, so a
/// verifier written before any of this existed keeps working unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TokenType {
    /// `JWT` — the unlabelled default. What every token carried before RFC 9068
    /// typing was an option, and what ID tokens still carry: OIDC registers no
    /// `typ` of its own for them.
    Jwt,
    /// `at+jwt` — an OAuth 2.0 access token, RFC 9068.
    AccessToken,
}

impl TokenType {
    /// The header value.
    pub fn as_str(self) -> &'static str {
        match self {
            TokenType::Jwt => "JWT",
            TokenType::AccessToken => "at+jwt",
        }
    }

    /// Parse a `typ` header value.
    ///
    /// RFC 9068 §4: a resource server accepts `at+jwt` or `application/at+jwt`.
    /// The media-type prefix is optional in JOSE headers and both forms are on
    /// the wire, so both are read.
    pub fn parse(typ: &str) -> Option<Self> {
        match typ {
            "JWT" | "jwt" => Some(TokenType::Jwt),
            "at+jwt" | "application/at+jwt" => Some(TokenType::AccessToken),
            _ => None,
        }
    }
}

/// How strictly a verifier holds a token to its declared [`TokenType`].
///
/// The distinction exists because RFC 9068 conformance and a live migration
/// want opposite things, and only the deployment knows which it is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TypePolicy {
    /// An unlabelled token, or one labelled `JWT`, passes anywhere. Only a
    /// label that is *more* specific and *wrong* is refused.
    Lenient,
    /// The label must be exactly what was asked for. An unlabelled token is
    /// refused. This is RFC 9068 §4 as written.
    Strict,
}

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
    active: KeyPair,
    /// Keys that no longer sign but must still verify: a token outlives the
    /// rotation that replaced the key which signed it.
    retired: Vec<KeyPair>,
}

/// One Ed25519 keypair and the `kid` that names it.
pub struct KeyPair {
    kid: String,
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl KeyPair {
    fn new(signing_key: SigningKey) -> Self {
        let verifying_key = signing_key.verifying_key();
        Self {
            kid: thumbprint(&verifying_key),
            signing_key,
            verifying_key,
        }
    }

    /// The key id: an RFC 7638 JWK thumbprint of the public key.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The public key, as the `x` parameter of an OKP JWK.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }
}

/// RFC 7638 JWK thumbprint of an Ed25519 public key.
///
/// The digest is taken over the canonical JWK — required members only, in
/// lexicographic order, no whitespace — as RFC 8037 §2 defines them for OKP.
///
/// Hashing the raw 32 public key bytes would have been simpler and would have
/// produced a *different* id for the same key than any standards-conforming
/// party computes from the published JWKS. Two ids for one key, with nothing to
/// say which is wrong.
fn thumbprint(verifying_key: &VerifyingKey) -> String {
    let x = URL_SAFE_NO_PAD.encode(verifying_key.to_bytes());
    let canonical = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#);
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

impl KeyManager {
    /// Generate a new random Ed25519 keypair.
    pub fn generate() -> Self {
        Self {
            active: KeyPair::new(SigningKey::generate(&mut OsRng)),
            retired: Vec::new(),
        }
    }

    /// Create a KeyManager from an existing 32-byte secret.
    ///
    /// The `kid` is derived from the key, so two instances loading the same
    /// secret agree on it. Were it random, each instance would name the same
    /// key differently and reject the other's tokens — a failure that only
    /// appears on the day a second instance is started.
    pub fn from_bytes(secret: &[u8; 32]) -> Self {
        Self {
            active: KeyPair::new(SigningKey::from_bytes(secret)),
            retired: Vec::new(),
        }
    }

    /// The key currently signing.
    pub fn active(&self) -> &KeyPair {
        &self.active
    }

    /// Keys that still verify but no longer sign.
    pub fn retired(&self) -> &[KeyPair] {
        &self.retired
    }

    /// Promote `signing_key` to active and retire the current one.
    ///
    /// Takes `&mut self`, so two concurrent rotations — which would leave two
    /// keys believing they are active — are rejected at compile time rather
    /// than guarded at runtime.
    pub fn rotate(&mut self, signing_key: SigningKey) {
        let previous = std::mem::replace(&mut self.active, KeyPair::new(signing_key));
        self.retired.push(previous);
    }

    /// Forget a retired key, so it stops verifying and leaves the JWKS.
    ///
    /// Deliberately manual: this library holds no clock and does not know how
    /// long your tokens live. A retired key must stay as long as a token it
    /// signed can still be valid, and only the caller knows that span. Returns
    /// whether a key was removed.
    pub fn remove_retired(&mut self, kid: &str) -> bool {
        let before = self.retired.len();
        self.retired.retain(|k| k.kid != kid);
        self.retired.len() != before
    }

    /// The JWKS as a value: every key that currently verifies, active first.
    ///
    /// Serving this over HTTP, and deciding its cache headers, is transport and
    /// belongs to whatever hosts the library.
    pub fn jwks(&self) -> Jwks {
        Jwks {
            keys: std::iter::once(&self.active)
                .chain(self.retired.iter())
                .map(|pair| Jwk {
                    kty: "OKP".to_string(),
                    crv: "Ed25519".to_string(),
                    alg: "EdDSA".to_string(),
                    use_: "sig".to_string(),
                    kid: pair.kid.clone(),
                    x: URL_SAFE_NO_PAD.encode(pair.verifying_key.to_bytes()),
                })
                .collect(),
        }
    }

    /// Sign claims and produce a JWT string.
    ///
    /// The header carries the `kid` of the signing key. Without it a verifier
    /// holding several keys cannot tell which one to try, so rotation would
    /// invalidate every token still in flight.
    ///
    /// Uses standard PKCS#8 DER encoding for the Ed25519 signing key.
    /// Generic over the claim set so other issuers — OAuth, for one — can sign
    /// with the same keys and the same rotation, instead of each growing its own
    /// signer. Existing callers infer `StsClaims` from the argument.
    pub fn sign_claims<C: Serialize>(&self, claims: &C) -> Result<String, JwtError> {
        self.sign_claims_as(claims, TokenType::Jwt)
    }

    /// Sign claims, declaring in the header what kind of token this is.
    ///
    /// See [`TokenType`] for what the label buys and why it is not the default.
    pub fn sign_claims_as<C: Serialize>(
        &self,
        claims: &C,
        typ: TokenType,
    ) -> Result<String, JwtError> {
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(self.active.kid.clone());
        header.typ = Some(typ.as_str().to_string());
        let pkcs8_der = self
            .active
            .signing_key
            .to_pkcs8_der()
            .map_err(|e| JwtError::KeyEncoding(e.to_string()))?;
        let encoding_key = EncodingKey::from_ed_der(pkcs8_der.as_bytes());
        encode(&header, claims, &encoding_key).map_err(JwtError::Encode)
    }

    /// Verify a JWT token against an expected audience and return the claims.
    ///
    /// The audience is a parameter, mirroring [`StsClaimsContext::audience`] on
    /// the issuing side. A verifier that accepted one compiled-in audience
    /// could not tell two classes of token apart — say one that only buys
    /// another token from one that grants access — which is what `aud` is for.
    ///
    /// Note: `jsonwebtoken` with the `ring` backend expects raw 32-byte Ed25519
    /// public keys via `from_ed_der` (despite the function name suggesting DER).
    pub fn verify_token(&self, token: &str, audience: &str) -> Result<StsClaims, JwtError> {
        self.verify_claims(token, audience)
    }

    /// Verify a token and deserialise it into any claim set.
    ///
    /// [`KeyManager::verify_token`] is this with `StsClaims` filled in; the two
    /// share every check, so key rotation and audience validation cannot drift
    /// apart between issuers.
    ///
    /// The `typ` header is **not** examined. This is the historical door and
    /// its contract predates RFC 9068 typing: a verifier that has been calling
    /// it since before [`TokenType`] existed must not start failing because
    /// some issuer, elsewhere, turned labelling on. Callers who want the label
    /// enforced ask for it — see [`verify_claims_as`].
    ///
    /// [`verify_claims_as`]: Self::verify_claims_as
    pub fn verify_claims<C: DeserializeOwned>(
        &self,
        token: &str,
        audience: &str,
    ) -> Result<C, JwtError> {
        self.verify_signed_claims(token, audience)
    }

    /// Verify a token that must be of a given kind, and deserialise it.
    ///
    /// The signature and the audience are checked first, always. The label is
    /// examined only once the token has proven genuine, so no decision here
    /// rests on bytes an attacker chose.
    ///
    /// # Which labels pass
    ///
    /// | policy | expecting | header says | |
    /// |---|---|---|---|
    /// | [`Lenient`] | [`AccessToken`] | absent, `JWT`, or `at+jwt` | accepted |
    /// | [`Lenient`] | [`Jwt`] | absent or `JWT` | accepted |
    /// | [`Lenient`] | [`Jwt`] | `at+jwt` | refused |
    /// | [`Strict`] | either | exactly the expected label | accepted |
    /// | either | either | anything unrecognised | refused |
    ///
    /// # Choosing a policy
    ///
    /// [`Lenient`] is for a deployment mid-migration: a token issued before
    /// labelling was enabled carries no useful `typ`, and refusing it would
    /// mean an outage every time an issuer flips
    /// [`with_explicit_typ`][crate::service::oauth::OAuthService::with_explicit_typ].
    /// It still closes the direction that matters — a token labelled `at+jwt`
    /// will not pass as an ID token.
    ///
    /// [`Strict`] is what RFC 9068 §4 actually asks of a resource server:
    ///
    /// > The resource server MUST verify that the `typ` header value is
    /// > `at+jwt` or `application/at+jwt` and reject tokens carrying any other
    /// > value.
    ///
    /// Reach for it once every issuer you accept is labelling. Until then it
    /// refuses your own legacy tokens, which is the point of it being a
    /// choice rather than a default.
    ///
    /// # Errors
    ///
    /// [`JwtError::TokenTypeMismatch`] when the token is genuine but labelled
    /// something this call cannot accept.
    ///
    /// [`Lenient`]: TypePolicy::Lenient
    /// [`Strict`]: TypePolicy::Strict
    /// [`AccessToken`]: TokenType::AccessToken
    /// [`Jwt`]: TokenType::Jwt
    pub fn verify_claims_as<C: DeserializeOwned>(
        &self,
        token: &str,
        audience: &str,
        expected: TokenType,
        policy: TypePolicy,
    ) -> Result<C, JwtError> {
        // Signature and audience first. Everything below reads a header that
        // has already been proven to be the one the issuer signed.
        let claims = self.verify_signed_claims(token, audience)?;

        let declared = jsonwebtoken::decode_header(token)
            .map_err(JwtError::Decode)?
            .typ;

        let acceptable = match (declared.as_deref().map(TokenType::parse), policy) {
            // No label. Genuine, and says nothing about what it is.
            (None, TypePolicy::Lenient) => true,
            (None, TypePolicy::Strict) => false,
            // A label nobody recognises — `dpop+jwt`, say. Never ours.
            (Some(None), _) => false,
            (Some(Some(found)), TypePolicy::Strict) => found == expected,
            // Lenient: `JWT` is the unlabelled shape spelled out, so it passes
            // wherever no label would. Anything more specific must match.
            (Some(Some(TokenType::Jwt)), TypePolicy::Lenient) => true,
            (Some(Some(found)), TypePolicy::Lenient) => found == expected,
        };

        if !acceptable {
            return Err(JwtError::TokenTypeMismatch {
                expected: expected.as_str(),
                found: declared.unwrap_or_else(|| "<absent>".to_string()),
            });
        }
        Ok(claims)
    }

    /// Everything after the `typ` check: key lookup, signature, audience.
    fn verify_signed_claims<C: DeserializeOwned>(
        &self,
        token: &str,
        audience: &str,
    ) -> Result<C, JwtError> {
        // Which key signed this is read from the header before anything is
        // verified. An unknown or absent kid is refused as such, and not as a
        // bad signature: the two are diagnosed differently — one is a key
        // distribution problem, the other is a forgery.
        let kid = jsonwebtoken::decode_header(token)
            .map_err(JwtError::Decode)?
            .kid
            .ok_or(JwtError::MissingKeyId)?;

        let pair = self
            .key_for(&kid)
            .ok_or_else(|| JwtError::UnknownKeyId(kid.clone()))?;

        // jsonwebtoken + ring expects raw 32-byte Ed25519 public key, not SPKI DER.
        // This is a known quirk of the `from_ed_der` API naming.
        let decoding_key = DecodingKey::from_ed_der(&pair.verifying_key.to_bytes());
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_required_spec_claims(&["exp", "iat", "sub", "iss", "aud"]);
        validation.set_audience(&[audience]);
        // validate_aud defaults to true and set_audience configures the expected
        // values — audience IS validated.
        let token_data = decode::<C>(token, &decoding_key, &validation).map_err(|e| {
            // A well-signed token addressed elsewhere is not a forgery: it is a
            // token of the wrong class, and the caller has to distinguish the
            // two to route or refuse it. Collapsing it into `Decode` would make
            // that require reading `jsonwebtoken`'s own error kinds.
            if matches!(e.kind(), jsonwebtoken::errors::ErrorKind::InvalidAudience) {
                JwtError::AudienceMismatch {
                    expected: audience.to_string(),
                }
            } else {
                JwtError::Decode(e)
            }
        })?;
        Ok(token_data.claims)
    }

    /// Return the public key as standard SPKI PEM (SubjectPublicKeyInfo).
    ///
    /// The returned PEM can be consumed by standard tools (openssl, external JWT
    /// libraries) to verify tokens produced by this KeyManager.
    pub fn public_key_pem(&self) -> Result<String, JwtError> {
        let spki_der = self
            .active
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
            .active
            .verifying_key
            .to_public_key_der()
            .map_err(|e| JwtError::KeyEncoding(e.to_string()))?;
        Ok(spki_der.as_ref().to_vec())
    }

    /// Return the raw 32-byte public key of the active key.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.active.verifying_key.to_bytes()
    }

    /// Return the raw 32-byte secret key of the active key (for persistence).
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.active.signing_key.to_bytes()
    }

    /// Find a key by id, active or retired.
    fn key_for(&self, kid: &str) -> Option<&KeyPair> {
        std::iter::once(&self.active)
            .chain(self.retired.iter())
            .find(|k| k.kid == kid)
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
    /// Refused before any signature check: nothing says which key to try.
    #[error("token carries no key id")]
    MissingKeyId,
    /// The key id is well-formed but names no key this manager holds. Distinct
    /// from a bad signature — this one is fixed by distributing a key, not by
    /// rejecting a forgery.
    #[error("unknown key id: {0}")]
    UnknownKeyId(String),
    /// The signature holds, but the token was issued for another audience.
    /// Reported apart from [`JwtError::Decode`] so a caller verifying several
    /// classes of token can tell "not for me" from "not genuine".
    #[error("token is not addressed to audience `{expected}`")]
    AudienceMismatch {
        /// The audience the verifier was asked to accept.
        expected: String,
    },
    /// The token declares a `typ` that cannot be what the verifier asked for.
    /// The case that matters: an RFC 9068 access token presented where an ID
    /// token belongs.
    #[error("token declares typ `{found}`, which cannot serve as `{expected}`")]
    TokenTypeMismatch {
        /// What the verifier wanted.
        expected: &'static str,
        /// What the header said.
        found: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The audience the fixtures issue for, and the one to verify against
    /// unless a test is specifically about a mismatch.
    const AUD: &str = "wami";

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
            audience: AUD.to_string(),
            scoped_actions: vec!["s3:GetObject".to_string()],
            scoped_resources: vec!["arn:aws:s3:::my-bucket/*".to_string()],
        }
    }

    fn test_claims() -> StsClaims {
        build_sts_claims(&test_credentials(), &test_claims_context())
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
        let secret = km1.secret_bytes();
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

        let verified = km
            .verify_token(&token, AUD)
            .expect("verification should succeed");
        assert_eq!(verified.sub, claims.sub);
        assert_eq!(verified.iss, claims.iss);
        assert_eq!(verified.jti, claims.jti);
        assert_eq!(verified.scoped_actions, claims.scoped_actions);
        assert_eq!(verified.scoped_resources, claims.scoped_resources);
    }

    #[test]
    fn the_historical_door_never_looks_at_the_label() {
        // `verify_claims` predates typing. A verifier calling it must not start
        // failing because some issuer, elsewhere, turned labelling on — it did
        // not ask for the label and never agreed to be bound by it.
        let km = KeyManager::generate();
        let claims = build_sts_claims(&test_credentials(), &test_claims_context());

        for typ in [TokenType::Jwt, TokenType::AccessToken] {
            let token = km.sign_claims_as(&claims, typ).unwrap();
            assert!(
                km.verify_claims::<StsClaims>(&token, AUD).is_ok(),
                "{typ:?} was refused by the untyped door"
            );
            assert!(km.verify_token(&token, AUD).is_ok());
        }
    }

    #[test]
    fn leniently_an_unlabelled_token_passes_as_either_kind() {
        // The reason typing can be switched on mid-flight: tokens issued
        // before it carry no useful label, and still verify.
        let km = KeyManager::generate();
        let claims = build_sts_claims(&test_credentials(), &test_claims_context());
        let token = km.sign_claims(&claims).unwrap();

        for expected in [TokenType::Jwt, TokenType::AccessToken] {
            assert!(km
                .verify_claims_as::<StsClaims>(&token, AUD, expected, TypePolicy::Lenient)
                .is_ok());
        }
    }

    #[test]
    fn leniently_an_access_token_still_cannot_be_read_as_an_id_token() {
        // The one direction lenience does not forgive, and the confusion
        // RFC 9068 exists to end.
        let km = KeyManager::generate();
        let claims = build_sts_claims(&test_credentials(), &test_claims_context());
        let token = km.sign_claims_as(&claims, TokenType::AccessToken).unwrap();

        assert!(km
            .verify_claims_as::<StsClaims>(&token, AUD, TokenType::AccessToken, TypePolicy::Lenient)
            .is_ok());

        match km
            .verify_claims_as::<StsClaims>(&token, AUD, TokenType::Jwt, TypePolicy::Lenient)
            .unwrap_err()
        {
            JwtError::TokenTypeMismatch { found, expected } => {
                assert_eq!(found, "at+jwt");
                assert_eq!(expected, "JWT");
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn strictly_only_the_exact_label_passes() {
        // RFC 9068 §4 as written: a resource server rejects anything that is
        // not `at+jwt`, an unlabelled legacy token included. That is why it is
        // a choice — turning it on before every issuer labels locks them out.
        let km = KeyManager::generate();
        let claims = build_sts_claims(&test_credentials(), &test_claims_context());

        let labelled = km.sign_claims_as(&claims, TokenType::AccessToken).unwrap();
        assert!(km
            .verify_claims_as::<StsClaims>(
                &labelled,
                AUD,
                TokenType::AccessToken,
                TypePolicy::Strict
            )
            .is_ok());

        let legacy = km.sign_claims(&claims).unwrap();
        let err = km
            .verify_claims_as::<StsClaims>(&legacy, AUD, TokenType::AccessToken, TypePolicy::Strict)
            .unwrap_err();
        assert!(
            matches!(&err, JwtError::TokenTypeMismatch { found, .. } if found == "JWT"),
            "got {err:?}"
        );
    }

    #[test]
    fn a_bad_signature_is_reported_as_such_even_when_the_label_is_also_wrong() {
        // The label is examined only after the token has proven genuine, so no
        // answer here is decided by bytes an attacker chose.
        let km = KeyManager::generate();
        let other = KeyManager::generate();
        let claims = build_sts_claims(&test_credentials(), &test_claims_context());
        let foreign = other
            .sign_claims_as(&claims, TokenType::AccessToken)
            .unwrap();

        let err = km
            .verify_claims_as::<StsClaims>(&foreign, AUD, TokenType::Jwt, TypePolicy::Lenient)
            .unwrap_err();
        assert!(
            !matches!(err, JwtError::TokenTypeMismatch { .. }),
            "the label must not be judged before the signature: {err:?}"
        );
    }

    #[test]
    fn the_typ_header_says_what_was_asked_for() {
        let km = KeyManager::generate();
        let claims = build_sts_claims(&test_credentials(), &test_claims_context());

        for (typ, expected) in [(TokenType::Jwt, "JWT"), (TokenType::AccessToken, "at+jwt")] {
            let token = km.sign_claims_as(&claims, typ).unwrap();
            let header = jsonwebtoken::decode_header(&token).unwrap();
            assert_eq!(header.typ.as_deref(), Some(expected));
            assert!(header.kid.is_some(), "rotation still needs the kid");
        }
    }

    #[test]
    fn both_spellings_of_the_access_token_type_are_read() {
        // RFC 9068 §4 allows the media-type prefix; both are on the wire.
        assert_eq!(TokenType::parse("at+jwt"), Some(TokenType::AccessToken));
        assert_eq!(
            TokenType::parse("application/at+jwt"),
            Some(TokenType::AccessToken)
        );
        assert_eq!(TokenType::parse("JWT"), Some(TokenType::Jwt));
        assert_eq!(TokenType::parse("dpop+jwt"), None);
    }

    #[test]
    fn a_typ_nobody_recognises_is_refused_under_either_policy() {
        let km = KeyManager::generate();
        let claims = build_sts_claims(&test_credentials(), &test_claims_context());
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(km.active.kid.clone());
        header.typ = Some("dpop+jwt".to_string());
        let pkcs8 = km.active.signing_key.to_pkcs8_der().unwrap();
        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_ed_der(pkcs8.as_bytes()),
        )
        .unwrap();

        for expected in [TokenType::Jwt, TokenType::AccessToken] {
            for policy in [TypePolicy::Lenient, TypePolicy::Strict] {
                assert!(
                    km.verify_claims_as::<StsClaims>(&token, AUD, expected, policy)
                        .is_err(),
                    "{expected:?}/{policy:?} accepted dpop+jwt"
                );
            }
        }

        // But the untyped door does not care, by design.
        assert!(km.verify_claims::<StsClaims>(&token, AUD).is_ok());
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
        let result = km.verify_token(&token, AUD);
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

        let result = km.verify_token(&tampered_token, AUD);
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
        let result = km2.verify_token(&token, AUD);
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
        let b64_content: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        let der_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &b64_content)
                .expect("PEM content should be valid base64");

        // SPKI DER for Ed25519 is 44 bytes (12-byte header + 32-byte key)
        assert_eq!(
            der_bytes.len(),
            44,
            "SPKI DER should be 44 bytes for Ed25519"
        );

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

    /// RFC 8037 §3.1 publishes this key and RFC 7638 §3.1 the thumbprint
    /// method. Pinning the pair here is what stops the id from silently
    /// becoming "SHA-256 of the raw bytes", which no other implementation
    /// would agree with.
    #[test]
    fn thumbprint_follows_rfc_7638() {
        // The public key from RFC 8037 §3.1, base64url-decoded.
        let x = URL_SAFE_NO_PAD
            .decode("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")
            .unwrap();
        let verifying_key = VerifyingKey::from_bytes(&x.try_into().unwrap()).unwrap();

        // The digest must be taken over {"crv":..,"kty":..,"x":..} exactly:
        // required members, lexicographic order, no whitespace.
        let expected = {
            let canonical = r#"{"crv":"Ed25519","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;
            URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
        };

        assert_eq!(thumbprint(&verifying_key), expected);
    }

    #[test]
    fn same_secret_yields_same_kid() {
        // Two instances loading one secret must name the key identically, or
        // each rejects the other's tokens the day a second one is started.
        let secret = [7u8; 32];
        assert_eq!(
            KeyManager::from_bytes(&secret).active().kid(),
            KeyManager::from_bytes(&secret).active().kid()
        );
    }

    #[test]
    fn signed_tokens_carry_the_active_kid() {
        let km = KeyManager::generate();
        let token = km.sign_claims(&test_claims()).unwrap();

        let header = jsonwebtoken::decode_header(&token).unwrap();
        assert_eq!(header.kid.as_deref(), Some(km.active().kid()));
    }

    #[test]
    fn a_retired_key_still_verifies_its_own_tokens() {
        // The whole point: a token outlives the rotation that replaced its key.
        let mut km = KeyManager::generate();
        let before = km.sign_claims(&test_claims()).unwrap();
        let old_kid = km.active().kid().to_string();

        km.rotate(SigningKey::generate(&mut OsRng));
        let after = km.sign_claims(&test_claims()).unwrap();

        assert!(
            km.verify_token(&before, AUD).is_ok(),
            "in-flight token died"
        );
        assert!(km.verify_token(&after, AUD).is_ok());
        assert_ne!(km.active().kid(), old_kid);
        assert_eq!(km.retired().len(), 1);
    }

    #[test]
    fn removing_a_retired_key_stops_it_verifying() {
        let mut km = KeyManager::generate();
        let token = km.sign_claims(&test_claims()).unwrap();
        let old_kid = km.active().kid().to_string();

        km.rotate(SigningKey::generate(&mut OsRng));
        assert!(km.verify_token(&token, AUD).is_ok());

        assert!(km.remove_retired(&old_kid));
        assert!(matches!(
            km.verify_token(&token, AUD),
            Err(JwtError::UnknownKeyId(_))
        ));
        assert!(
            !km.remove_retired(&old_kid),
            "removing twice reported a hit"
        );
    }

    #[test]
    fn an_unknown_kid_is_not_reported_as_a_bad_signature() {
        // One is a key distribution problem, the other is a forgery. Collapsing
        // them into one error sends whoever debugs it down the wrong path.
        let signer = KeyManager::generate();
        let token = signer.sign_claims(&test_claims()).unwrap();

        let stranger = KeyManager::generate();
        assert!(matches!(
            stranger.verify_token(&token, AUD),
            Err(JwtError::UnknownKeyId(_))
        ));
    }

    #[test]
    fn a_token_without_kid_is_refused() {
        // Forged by signing with a bare header, as a pre-kid issuer would.
        let km = KeyManager::generate();
        let pkcs8 = km.active().signing_key.to_pkcs8_der().unwrap();
        let token = encode(
            &Header::new(Algorithm::EdDSA),
            &test_claims(),
            &EncodingKey::from_ed_der(pkcs8.as_bytes()),
        )
        .unwrap();

        assert!(matches!(
            km.verify_token(&token, AUD),
            Err(JwtError::MissingKeyId)
        ));
    }

    #[test]
    fn jwks_lists_every_verifying_key_active_first() {
        let mut km = KeyManager::generate();
        let first = km.active().kid().to_string();
        km.rotate(SigningKey::generate(&mut OsRng));

        let jwks = km.jwks();
        assert_eq!(jwks.keys.len(), 2);
        assert_eq!(jwks.keys[0].kid, km.active().kid());
        assert_eq!(jwks.keys[1].kid, first);
        assert!(jwks
            .keys
            .iter()
            .all(|k| k.kty == "OKP" && k.crv == "Ed25519" && k.alg == "EdDSA" && k.use_ == "sig"));

        // `use` is a Rust keyword; the wire name must survive the rename.
        let json = serde_json::to_string(&jwks).unwrap();
        assert!(json.contains(r#""use":"sig""#), "{json}");
    }

    fn claims_for(audience: &str) -> StsClaims {
        build_sts_claims(
            &test_credentials(),
            &StsClaimsContext {
                audience: audience.to_string(),
                ..test_claims_context()
            },
        )
    }

    #[test]
    fn the_verifier_accepts_whichever_audience_it_is_given() {
        // One issuer, two classes of token. Neither is the verifier's built-in
        // audience, because there is no longer one.
        let km = KeyManager::generate();
        let exchange = km.sign_claims(&claims_for("wami-sts")).unwrap();
        let access = km.sign_claims(&claims_for("mermaid-live")).unwrap();

        assert_eq!(
            km.verify_token(&exchange, "wami-sts").unwrap().aud,
            "wami-sts"
        );
        assert_eq!(
            km.verify_token(&access, "mermaid-live").unwrap().aud,
            "mermaid-live"
        );
    }

    #[test]
    fn a_token_addressed_elsewhere_is_refused_as_such() {
        // The point of `aud`: a token that only buys another token must not
        // pass where one granting access is expected — and the refusal must
        // say so, rather than looking like a forgery.
        let km = KeyManager::generate();
        let token = km.sign_claims(&claims_for("wami-sts")).unwrap();

        let err = km.verify_token(&token, "mermaid-live").unwrap_err();
        assert!(
            matches!(&err, JwtError::AudienceMismatch { expected } if expected == "mermaid-live"),
            "got {err:?}"
        );
    }
}
