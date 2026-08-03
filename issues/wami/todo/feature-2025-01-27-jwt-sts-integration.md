# Issue #004: JWT Integration in STS Session Tokens

**Status**: 🔴 Open  
**Priority**: High  
**Type**: Feature Enhancement  
**Assignee**: TBD  
**Created**: 2025-01-27  
**Labels**: `enhancement`, `jwt`, `sts`, `session-tokens`

## Summary

Integrate JWT tokens into STS session token generation, allowing STS to optionally generate JWT tokens instead of (or alongside) legacy string tokens.

## Current State

- ✅ STS session tokens use simple string format: `"TOKEN{uuid}"`
- ✅ Session tokens stored in `StsSession` model
- ✅ `SessionTokenService::get_session_token()` generates tokens
- ❌ No JWT format for session tokens
- ❌ No cryptographic validation of session tokens

## Problem Statement

Current session tokens are:
- Not cryptographically signed (can be forged)
- Not self-contained (require database lookup)
- Not standard format (not compatible with JWT-based systems)
- Cannot be validated without database access

## Proposed Solution

Add JWT option to STS session token generation:

1. **Token Format Option**
   - Legacy format (backward compatible)
   - JWT format (new, optional)

2. **JWT Claims for Sessions**
   - `sub`: User ARN
   - `iss`: WAMI instance ID
   - `exp`: Expiration timestamp
   - `iat`: Issued at timestamp
   - `wami_arn`: Principal ARN
   - `wami_tenant`: Tenant path
   - `wami_instance`: Instance ID
   - `wami_session_id`: Session identifier

3. **Integration Points**
   - `SessionTokenService::get_session_token()` - Add JWT option
   - `StsSession` model - Add `jwt_token` field
   - Store JWT alongside legacy token for compatibility

## Implementation Plan

### Phase 1: Model Updates (Week 1)

**Tasks**:
- [ ] Add `jwt_token: Option<String>` to `StsSession` model
- [ ] Add `TokenFormat` enum (Legacy | Jwt | Both)
- [ ] Update `GetSessionTokenRequest` with format option
- [ ] Update `GetSessionTokenResponse` to include JWT

**Files to Modify**:
- `crates/wami/src/wami/sts/session/model.rs`
- `crates/wami/src/wami/sts/session_token/requests.rs`

### Phase 2: JWT Generation (Week 1)

**Tasks**:
- [ ] Create JWT generation in `SessionTokenService`
- [ ] Populate WAMI claims in JWT payload
- [ ] Sign JWT with instance signing key
- [ ] Store JWT in session model
- [ ] Return JWT in response

**Files to Modify**:
- `crates/wami/src/service/sts/session_token.rs`

**Key Functions**:
```rust
impl<S: SessionStore> SessionTokenService<S> {
    /// Generate JWT session token
    async fn generate_jwt_session_token(
        &self,
        context: &WamiContext,
        principal_arn: &str,
        expiration: DateTime<Utc>,
    ) -> Result<String>;
}
```

### Phase 3: JWT Validation (Week 2)

**Tasks**:
- [ ] Add JWT validation for session tokens
- [ ] Extract context from JWT claims
- [ ] Validate expiration and signature
- [ ] Integration with existing session validation
- [ ] Support JWT-only authentication (no database lookup)

**Files to Modify**:
- `crates/wami/src/service/sts/session.rs`
- `crates/wami/src/service/sts/session_token.rs`

### Phase 4: Testing (Week 2)

**Tasks**:
- [ ] Unit tests for JWT generation
- [ ] Integration tests with STS service
- [ ] Backward compatibility tests (legacy tokens still work)
- [ ] Performance tests (JWT vs legacy)
- [ ] Security tests (invalid JWT, expired JWT)

## Files to Modify

- `crates/wami/src/service/sts/session_token.rs` - Add JWT generation
- `crates/wami/src/wami/sts/session/model.rs` - Add `jwt_token` field
- `crates/wami/src/wami/sts/session_token/requests.rs` - Add format option
- `crates/wami/src/service/sts/session.rs` - Add JWT validation

## Dependencies

- **Issue #003** (wami-jwt crate) must be completed first

## Examples

### Example 1: Generate JWT Session Token

```rust
use wami::service::sts::SessionTokenService;
use wami::wami::sts::session_token::GetSessionTokenRequest;

let request = GetSessionTokenRequest {
    duration_seconds: Some(3600),
    serial_number: None,
    token_code: None,
    format: Some(TokenFormat::Jwt),  // Request JWT format
};

let response = session_service
    .get_session_token(&context, request, &user_arn)
    .await?;

// JWT available in response
println!("JWT Token: {}", response.jwt_token.unwrap());
// Output: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Example 2: Validate JWT Session Token

```rust
use wami::service::sts::SessionService;

// Validate JWT without database lookup
let session = session_service
    .validate_jwt_session_token(&jwt_token)
    .await?;

println!("Session valid until: {}", session.expiration);
println!("Principal: {}", session.principal_arn.unwrap());
```

### Example 3: Both Formats

```rust
let request = GetSessionTokenRequest {
    duration_seconds: Some(3600),
    format: Some(TokenFormat::Both),  // Generate both
    // ...
};

let response = session_service
    .get_session_token(&context, request, &user_arn)
    .await?;

// Both tokens available
println!("Legacy: {}", response.session_token);
println!("JWT: {}", response.jwt_token.unwrap());
```

## Testing Strategy

1. **Unit Tests**: JWT generation with different claims
2. **Integration Tests**: Full STS flow with JWT tokens
3. **Backward Compatibility**: Legacy tokens still work
4. **Performance Tests**: JWT generation overhead
5. **Security Tests**: Invalid JWT, expired JWT, signature validation

## Success Criteria

- [ ] JWT tokens generated for STS sessions
- [ ] JWT tokens validated correctly
- [ ] Backward compatibility maintained (legacy tokens work)
- [ ] Performance acceptable (< 10ms overhead)
- [ ] Tests passing
- [ ] Documentation updated

## Dependencies

- Issue #003 (wami-jwt crate) must be completed first

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Breaking changes | High | Keep legacy format as default, JWT optional |
| Performance overhead | Medium | Benchmark, optimize JWT generation |
| Key management | Medium | Use existing key management from Issue #003 |

---

**Estimated Effort**: 2 weeks (1 developer)  
**Dependencies**: Issue #003

