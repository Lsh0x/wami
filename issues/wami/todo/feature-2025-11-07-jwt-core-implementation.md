# Issue #003: Core JWT Implementation (Native Rust)

**Status**: 🔴 Open  
**Priority**: High  
**Type**: Feature Enhancement  
**Assignee**: TBD  
**Created**: 2025-11-07  
**Labels**: `enhancement`, `jwt`, `security`, `crypto`, `native-implementation`

## Summary

Implement a native Rust JWT library (`wami-jwt` crate) supporting JWS (JSON Web Signature) and JWE (JSON Web Encryption) with all standard algorithms. This is the foundation for JWT integration across WAMI.

## Current State

- ❌ No JWT support in WAMI
- ❌ No cryptographic token generation/validation
- ✅ Basic authentication with access keys exists
- ✅ STS session tokens use simple string format
- ✅ Cryptographic libraries available (ring, rsa, aes-gcm via dependencies)

## Problem Statement

WAMI currently lacks:
- Standard JWT token format (RFC 7519)
- Cryptographic signature/encryption for tokens
- JWT parsing and validation capabilities
- Support for JWS (signing) and JWE (encryption)

Without JWT support, WAMI cannot:
- Generate cryptographically signed tokens
- Support stateless authentication
- Integrate with OIDC/OAuth2 providers
- Provide secure API tokens for external clients

## Proposed Solution

Create a new `wami-jwt` crate with native Rust implementation:

1. **JWS Support** (JSON Web Signature)
   - HS256 (HMAC-SHA256) - Symmetric signing
   - RS256 (RSA-SHA256) - Asymmetric signing with RSA
   - ES256 (ECDSA-P256-SHA256) - Asymmetric signing with ECDSA

2. **JWE Support** (JSON Web Encryption)
   - RSA-OAEP-256 key encryption
   - A256GCM content encryption (AES-256-GCM)

3. **Core Components**
   - JWT structure (header, payload, signature/encrypted data)
   - Base64URL encoding/decoding
   - Claims parsing and validation
   - Key management (HMAC, RSA, ECDSA)
   - Error handling

## Implementation Plan

### Phase 1: Core Structure (Week 1)

**Tasks**:
- [ ] Create `crates/wami-jwt/` crate structure
- [ ] Define `Jwt`, `JwtHeader`, `JwtPayload` structures
- [ ] Implement Base64URL encoding/decoding (`encoder.rs`)
- [ ] Create error types (`JwtError` enum)
- [ ] Basic JWT parsing (three-part structure: header.payload.signature)
- [ ] JWT serialization (compact format)

**Files to Create**:
- `crates/wami-jwt/Cargo.toml`
- `crates/wami-jwt/src/lib.rs`
- `crates/wami-jwt/src/jwt.rs`
- `crates/wami-jwt/src/error.rs`
- `crates/wami-jwt/src/encoder.rs`

### Phase 2: JWS Implementation (Week 2)

**Tasks**:
- [ ] Implement HMAC-SHA256 signing/verification (`jws.rs`)
- [ ] Implement RSA-SHA256 signing/verification
- [ ] Implement ECDSA-P256-SHA256 signing/verification
- [ ] Key management for each algorithm type (`keys.rs`)
- [ ] Signature validation logic
- [ ] Support for "none" algorithm (disabled for security)

**Files to Create**:
- `crates/wami-jwt/src/jws.rs`
- `crates/wami-jwt/src/keys.rs`

### Phase 3: JWE Implementation (Week 3)

**Tasks**:
- [ ] Implement RSA-OAEP-256 key encryption
- [ ] Implement AES-256-GCM content encryption
- [ ] Combined JWE encryption/decryption (`jwe.rs`)
- [ ] Key management for encryption keys
- [ ] Content Encryption Key (CEK) generation
- [ ] Initialization Vector (IV) generation

**Files to Create**:
- `crates/wami-jwt/src/jwe.rs`

### Phase 4: Claims and Validation (Week 3)

**Tasks**:
- [ ] Standard claims structure (`claims.rs`)
  - `iss` (Issuer)
  - `sub` (Subject)
  - `aud` (Audience)
  - `exp` (Expiration)
  - `iat` (Issued At)
  - `nbf` (Not Before)
  - `jti` (JWT ID)
- [ ] WAMI-specific claims structure
- [ ] Expiration validation
- [ ] Not-before validation
- [ ] Audience validation
- [ ] Issuer validation

**Files to Create**:
- `crates/wami-jwt/src/claims.rs`
- `crates/wami-jwt/src/decoder.rs`

### Phase 5: Testing (Week 4)

**Tasks**:
- [ ] Unit tests for each algorithm (HS256, RS256, ES256)
- [ ] Unit tests for JWE encryption/decryption
- [ ] Integration tests for JWS/JWE
- [ ] Security tests (invalid tokens, timing attacks, algorithm confusion)
- [ ] Performance benchmarks
- [ ] Test vectors from RFC 7519

**Files to Create**:
- `crates/wami-jwt/src/tests.rs`

## Files to Create

```
crates/wami-jwt/
├── Cargo.toml
└── src/
    ├── lib.rs
    ├── jwt.rs          # Core JWT structures
    ├── jws.rs          # JWS implementation
    ├── jwe.rs          # JWE implementation
    ├── claims.rs       # Claims structures
    ├── keys.rs         # Key management
    ├── encoder.rs      # Base64URL encoding
    ├── decoder.rs      # JWT decoding and validation
    ├── error.rs        # Error types
    └── tests.rs        # Comprehensive tests
```

## Dependencies

```toml
[package]
name = "wami-jwt"
version = "0.1.0"
edition = "2021"
license = "MIT"
description = "Native Rust JWT implementation for WAMI"

[dependencies]
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
chrono = { version = "0.4", features = ["serde"] }
base64 = "0.22"
ring = "0.17"  # HMAC, RSA, ECDSA
rsa = { version = "0.9", features = ["sha2"] }  # RSA-OAEP
aes-gcm = "0.10"  # AES-GCM
wami-core = { path = "../wami-core" }

[dev-dependencies]
hex = "0.4"
```

## Examples

### Example 1: Generate JWS Token

```rust
use wami_jwt::{JwtHeader, WamiClaims, sign_jws, Algorithm};
use wami_jwt::keys::HmacKey;

// Create claims
let claims = WamiClaims {
    standard: StandardClaims {
        iss: Some("wami-instance-123".to_string()),
        sub: "arn:wami:iam:0:wami:123:user/alice".to_string(),
        aud: Some("wami-api".to_string()),
        exp: chrono::Utc::now().timestamp() + 3600,
        iat: chrono::Utc::now().timestamp(),
        nbf: None,
        jti: Some(uuid::Uuid::new_v4().to_string()),
    },
    wami_arn: "arn:wami:iam:0:wami:123:user/alice".to_string(),
    wami_tenant: "0".to_string(),
    wami_instance: "123".to_string(),
    wami_is_root: false,
    custom: HashMap::new(),
};

// Create header
let header = JwtHeader {
    alg: Algorithm::HS256,
    typ: "JWT".to_string(),
    enc: None,
    kid: Some("key-1".to_string()),
};

// Sign with HMAC key
let key = HmacKey::from_secret(b"my-secret-key");
let token = sign_jws(&header, &claims, &key)?;

println!("JWT: {}", token);
```

### Example 2: Verify JWS Token

```rust
use wami_jwt::{verify_jws, keys::HmacKey};

let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";
let key = HmacKey::from_secret(b"my-secret-key");

let (header, claims) = verify_jws(token, &key)?;

// Validate claims
if claims.standard.exp < chrono::Utc::now().timestamp() {
    return Err(JwtError::TokenExpired);
}

println!("Subject: {}", claims.standard.sub);
```

## Testing Strategy

1. **Unit Tests**: Each algorithm (HS256, RS256, ES256) sign/verify
2. **Integration Tests**: Full JWT generation and validation flow
3. **Security Tests**: Invalid signatures rejected, expired tokens rejected, algorithm confusion attacks prevented
4. **Performance Tests**: Token generation < 5ms, token validation < 5ms
5. **RFC Compliance Tests**: Test vectors from RFC 7519, 7515, 7516

## Success Criteria

- [ ] All JWS algorithms implemented (HS256, RS256, ES256)
- [ ] JWE encryption/decryption working (RSA-OAEP-256 + A256GCM)
- [ ] Claims validation complete (exp, nbf, aud, iss)
- [ ] 100% test coverage for core functionality
- [ ] Performance < 5ms for token generation/validation
- [ ] No external JWT library dependencies (pure Rust)
- [ ] RFC 7519, 7515, 7516 compliant
- [ ] Security best practices followed (no "none" algorithm, constant-time comparisons)

## Dependencies

### External Dependencies
- `ring` - Cryptographic primitives (HMAC, RSA, ECDSA)
- `rsa` - RSA operations for JWE
- `aes-gcm` - AES-GCM for content encryption
- `base64` - Base64URL encoding
- `serde` + `serde_json` - JSON serialization
- `chrono` - Timestamp handling

### Internal Dependencies
- `wami-core` - Error types, context structures

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Cryptographic implementation bugs | High | Use well-tested libraries (ring, rsa), comprehensive tests, security audit |
| Performance issues | Medium | Benchmark early, optimize hot paths, consider caching |
| Algorithm confusion attacks | High | Strict algorithm validation, no "none" algorithm support |
| Timing attacks | Medium | Constant-time comparisons, use library functions |
| Key management complexity | Medium | Clear key management API, documentation, examples |

## Related Issues

- Issue #004: JWT Integration in STS Session Tokens (depends on this)
- Issue #005: JWT Authentication (depends on this)
- Issue #006: OIDC JWT Parsing and Validation (depends on this)
- Issue #007: JWT API Tokens for External Clients (depends on this)

## Related Documentation

- [RFC 7519 - JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
- [RFC 7515 - JSON Web Signature (JWS)](https://tools.ietf.org/html/rfc7515)
- [RFC 7516 - JSON Web Encryption (JWE)](https://tools.ietf.org/html/rfc7516)

---

**Estimated Effort**: 4 weeks (1 developer)  
**Estimated LOC**: ~2,000-3,000 lines of new code  
**Dependencies**: None (foundation issue)

