# Issue #005: JWT Authentication

**Status**: 🔴 Open  
**Priority**: High  
**Type**: Feature Enhancement  
**Assignee**: TBD  
**Created**: 2025-11-07  
**Labels**: `enhancement`, `jwt`, `authentication`, `security`

## Summary

Add JWT-based authentication to WAMI, allowing users to authenticate using JWT tokens instead of access keys.

## Current State

- ✅ `AuthenticationService` supports access key authentication
- ✅ Access keys validated with bcrypt hashing
- ✅ `WamiContext` created from authenticated user
- ❌ No JWT authentication method
- ❌ No JWT token validation in authentication flow

## Problem Statement

WAMI only supports access key authentication. Need alternative:
- JWT tokens for stateless authentication
- API clients using JWT
- Integration with external JWT issuers
- Self-contained authentication (no database lookup for validation)

## Proposed Solution

Add JWT authentication to `AuthenticationService`:

1. **New Authentication Method**
   - `authenticate_jwt(jwt_token: &str) -> Result<WamiContext>`
   - Validate JWT signature
   - Extract claims and create context
   - Support both WAMI-issued and external JWTs

2. **JWT Service**
   - `JwtService` for JWT generation/validation
   - Key management (signing keys per instance/tenant)
   - Key rotation support

3. **Store Integration**
   - `JwtKeyStore` trait for key storage
   - Memory implementation
   - Key rotation tracking

## Implementation Plan

### Phase 1: JWT Service (Week 1)

**Tasks**:
- [ ] Create `JwtService` in `crates/wami/src/service/jwt/mod.rs`
- [ ] Implement JWT generation with WAMI claims
- [ ] Implement JWT validation
- [ ] Key management (get, rotate, list keys)
- [ ] Support for multiple signing keys (key rotation)

**Files to Create**:
- `crates/wami/src/service/jwt/mod.rs`
- `crates/wami/src/service/jwt/key_management.rs`

**Key Structures**:
```rust
pub struct JwtService<S> {
    store: Arc<RwLock<S>>,
    key_store: Arc<RwLock<dyn JwtKeyStore>>,
}

impl<S> JwtService<S> {
    pub fn generate_token(
        &self,
        context: &WamiContext,
        expiration: Duration,
    ) -> Result<String>;
    
    pub fn validate_token(
        &self,
        token: &str,
    ) -> Result<WamiContext>;
}
```

### Phase 2: Authentication Integration (Week 2)

**Tasks**:
- [ ] Add `authenticate_jwt()` to `AuthenticationService`
- [ ] Extract `WamiContext` from JWT claims
- [ ] Validate JWT signature and expiration
- [ ] Handle external JWT issuers (optional)
- [ ] Support for key rotation (multiple valid keys)

**Files to Modify**:
- `crates/wami/src/service/auth/authentication.rs`

**New Method**:
```rust
impl<S> AuthenticationService<S> {
    /// Authenticate using JWT token
    pub async fn authenticate_jwt(
        &self,
        jwt_token: &str,
    ) -> Result<WamiContext> {
        // Validate JWT signature
        // Extract claims
        // Create WamiContext from claims
    }
}
```

### Phase 3: Key Store (Week 2)

**Tasks**:
- [ ] Create `JwtKeyStore` trait
- [ ] Implement memory store
- [ ] Key rotation logic
- [ ] Per-tenant key support
- [ ] Key expiration and rotation tracking

**Files to Create**:
- `crates/wami/src/store/traits/jwt.rs`
- `crates/wami/src/store/memory/jwt.rs`

**Trait Definition**:
```rust
#[async_trait]
pub trait JwtKeyStore: Send + Sync {
    async fn get_signing_key(
        &self,
        instance_id: &str,
        key_id: Option<&str>,
    ) -> Result<SigningKey>;
    
    async fn rotate_key(
        &mut self,
        instance_id: &str,
    ) -> Result<String>;  // Returns new key ID
    
    async fn list_keys(
        &self,
        instance_id: &str,
    ) -> Result<Vec<KeyMetadata>>;
}
```

### Phase 4: Testing (Week 3)

**Tasks**:
- [ ] Unit tests for JWT authentication
- [ ] Integration tests with AuthenticationService
- [ ] Security tests (invalid tokens, expired tokens, wrong keys)
- [ ] Performance tests
- [ ] Key rotation tests

## Files to Create

- `crates/wami/src/service/jwt/mod.rs`
- `crates/wami/src/service/jwt/key_management.rs`
- `crates/wami/src/store/traits/jwt.rs`
- `crates/wami/src/store/memory/jwt.rs`

## Files to Modify

- `crates/wami/src/service/auth/authentication.rs`
- `crates/wami/src/lib.rs` (exports)

## Dependencies

- **Issue #003** (wami-jwt crate) must be completed first

## Examples

### Example 1: Authenticate with JWT

```rust
use wami::service::auth::AuthenticationService;

let auth_service = AuthenticationService::new(store);

// Authenticate using JWT token
let context = auth_service
    .authenticate_jwt(&jwt_token)
    .await?;

println!("Authenticated as: {}", context.caller_arn());
println!("Instance: {}", context.instance_id());
```

### Example 2: Generate JWT for User

```rust
use wami::service::jwt::JwtService;

let jwt_service = JwtService::new(store, key_store);

// Generate JWT token for authenticated user
let token = jwt_service
    .generate_token(
        &context,
        Duration::hours(24),
    )
    .await?;

println!("JWT Token: {}", token);
```

### Example 3: Key Rotation

```rust
use wami::service::jwt::JwtService;

let jwt_service = JwtService::new(store, key_store);

// Rotate signing key for instance
let new_key_id = jwt_service
    .rotate_key("instance-123")
    .await?;

println!("New key ID: {}", new_key_id);
// Old keys still valid for grace period
```

## Testing Strategy

1. **Unit Tests**: JWT generation and validation
2. **Integration Tests**: Full authentication flow with JWT
3. **Security Tests**: Invalid tokens, expired tokens, wrong signatures
4. **Performance Tests**: JWT authentication vs access key authentication
5. **Key Rotation Tests**: Multiple keys valid during rotation

## Success Criteria

- [ ] JWT authentication working
- [ ] Context extracted from JWT correctly
- [ ] Key management functional
- [ ] Key rotation supported
- [ ] Tests passing
- [ ] Documentation complete
- [ ] Performance acceptable (< 10ms overhead)

## Dependencies

- Issue #003 (wami-jwt crate) must be completed first

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Key compromise | High | Key rotation support, short key lifetimes |
| Performance overhead | Medium | Benchmark, optimize validation |
| Token replay attacks | Medium | JTI (JWT ID) tracking, short expiration |

---

**Estimated Effort**: 3 weeks (1 developer)  
**Dependencies**: Issue #003

