# Issue #006: OIDC JWT Parsing and Validation

**Status**: 🔴 Open  
**Priority**: Medium  
**Type**: Feature Enhancement  
**Assignee**: TBD  
**Created**: 2025-11-07  
**Labels**: `enhancement`, `jwt`, `oidc`, `federation`, `identity-provider`

## Summary

Add support for parsing and validating OIDC (OpenID Connect) JWT tokens from external identity providers, enabling federated authentication with OIDC providers.

## Current State

- ✅ OIDC provider model exists (`OidcProvider`)
- ✅ OIDC providers can be created/configured
- ✅ `IdentityProviderService` manages OIDC providers
- ❌ No JWT parsing from OIDC providers
- ❌ No validation of OIDC-issued JWTs
- ❌ No mapping from OIDC claims to WamiContext

## Problem Statement

WAMI supports OIDC provider configuration but cannot:
- Parse JWT tokens from OIDC providers (Google, Auth0, etc.)
- Validate OIDC JWT signatures
- Extract claims from OIDC tokens
- Create WAMI sessions from OIDC tokens
- Support federated authentication flows

## Proposed Solution

Add OIDC JWT support to `IdentityProviderService`:

1. **OIDC JWT Validation**
   - Parse JWT from OIDC provider
   - Validate signature with provider's public keys
   - Extract standard OIDC claims (sub, email, groups, etc.)

2. **Federation Integration**
   - Map OIDC claims to WamiContext
   - Create federated sessions from OIDC tokens
   - Support OIDC token refresh

3. **Public Key Management**
   - Fetch OIDC provider public keys (JWKS)
   - Cache public keys
   - Handle key rotation

## Implementation Plan

### Phase 1: OIDC JWT Parsing (Week 1)

**Tasks**:
- [ ] Add JWT parsing to `IdentityProviderService`
- [ ] Extract OIDC claims (sub, email, name, groups, etc.)
- [ ] Validate JWT structure
- [ ] Parse OIDC-specific claims (iss, aud, azp, etc.)

**Files to Modify**:
- `crates/wami/src/service/identity/identity_provider.rs`

**New Structures**:
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcClaims {
    // Standard OIDC claims
    pub sub: String,              // Subject (user ID)
    pub iss: String,              // Issuer (provider URL)
    pub aud: String,              // Audience (client ID)
    pub exp: i64,                 // Expiration
    pub iat: i64,                 // Issued at
    pub email: Option<String>,    // Email address
    pub name: Option<String>,     // Full name
    pub given_name: Option<String>, // First name
    pub family_name: Option<String>, // Last name
    pub groups: Option<Vec<String>>, // Group memberships
    pub picture: Option<String>,  // Profile picture URL
    // Custom claims
    #[serde(flatten)]
    pub custom: HashMap<String, Value>,
}
```

### Phase 2: Signature Validation (Week 2)

**Tasks**:
- [ ] Implement JWKS (JSON Web Key Set) fetching
- [ ] Parse JWKS from OIDC provider
- [ ] Validate JWT signature with provider's public keys
- [ ] Cache public keys (with expiration)
- [ ] Handle key rotation (multiple keys in JWKS)

**Files to Create**:
- `crates/wami/src/service/identity/oidc_jwt.rs` (optional, if large)

**Key Functions**:
```rust
pub async fn fetch_jwks(
    provider_url: &str,
) -> Result<Jwks>;

pub async fn validate_oidc_jwt(
    jwt: &str,
    provider: &OidcProvider,
) -> Result<OidcClaims>;
```

### Phase 3: Federation Integration (Week 2)

**Tasks**:
- [ ] Map OIDC claims to WamiContext
- [ ] Create federated user sessions
- [ ] Integration with `FederationService`
- [ ] Support token refresh
- [ ] Handle federated user creation (if needed)

**Files to Modify**:
- `crates/wami/src/service/sts/federation.rs`
- `crates/wami/src/service/identity/identity_provider.rs`

**Mapping Logic**:
```rust
fn map_oidc_claims_to_context(
    claims: &OidcClaims,
    provider: &OidcProvider,
) -> Result<WamiContext> {
    // Extract user info from OIDC claims
    // Create or find federated user
    // Build WamiContext
}
```

### Phase 4: Testing (Week 3)

**Tasks**:
- [ ] Unit tests for OIDC JWT parsing
- [ ] Integration tests with mock OIDC providers
- [ ] Tests with real providers (Google, Auth0)
- [ ] Security tests (invalid signatures, expired tokens)
- [ ] JWKS caching tests

## Files to Modify

- `crates/wami/src/service/identity/identity_provider.rs`
- `crates/wami/src/service/sts/federation.rs`
- `crates/wami/src/wami/identity/identity_provider/model.rs`

## Files to Create

- `crates/wami/src/service/identity/oidc_jwt.rs` (optional, if large)

## Dependencies

- **Issue #003** (wami-jwt crate) must be completed first

## Examples

### Example 1: Validate OIDC JWT

```rust
use wami::service::identity::IdentityProviderService;

let service = IdentityProviderService::new(store);

// Validate JWT from Google OIDC provider
let oidc_provider = store.get_oidc_provider("arn:...").await?;
let claims = service
    .validate_oidc_jwt(&jwt_token, &oidc_provider)
    .await?;

println!("User: {}", claims.sub);
println!("Email: {:?}", claims.email);
```

### Example 2: Create Federated Session

```rust
use wami::service::sts::FederationService;

let federation_service = FederationService::new(store);

// Create session from OIDC token
let session = federation_service
    .create_session_from_oidc_token(
        &jwt_token,
        &oidc_provider,
    )
    .await?;

println!("Federated session: {}", session.session_token);
```

### Example 3: JWKS Caching

```rust
// JWKS are automatically fetched and cached
// Cache expires based on Cache-Control header from provider
// Keys are automatically rotated when provider updates JWKS

let claims = service
    .validate_oidc_jwt(&jwt_token, &oidc_provider)
    .await?;
// JWKS fetched and cached automatically
```

## Testing Strategy

1. **Unit Tests**: OIDC JWT parsing, claim extraction
2. **Integration Tests**: Full OIDC flow with mock providers
3. **Real Provider Tests**: Google, Auth0, Okta
4. **Security Tests**: Invalid signatures, expired tokens, wrong issuer
5. **JWKS Tests**: Key rotation, caching, expiration

## Success Criteria

- [ ] OIDC JWT tokens parsed correctly
- [ ] Signatures validated with provider keys
- [ ] Federated sessions created from OIDC tokens
- [ ] JWKS fetched and cached
- [ ] Key rotation handled
- [ ] Tests passing
- [ ] Documentation with examples

## Dependencies

- Issue #003 (wami-jwt crate) must be completed first

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Provider key rotation | Medium | Cache JWKS, support multiple keys |
| Network failures fetching JWKS | Medium | Cache with expiration, retry logic |
| Claim mapping complexity | Medium | Clear mapping rules, documentation |

---

**Estimated Effort**: 3 weeks (1 developer)  
**Dependencies**: Issue #003

