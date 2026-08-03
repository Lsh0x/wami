# Issue #007: JWT API Tokens for External Clients

**Status**: 🔴 Open  
**Priority**: Medium  
**Type**: Feature Enhancement  
**Assignee**: TBD  
**Created**: 2025-01-27  
**Labels**: `enhancement`, `jwt`, `api-tokens`, `external-clients`

## Summary

Create a service for generating and managing JWT API tokens for external clients, enabling programmatic access to WAMI APIs with scoped permissions.

## Current State

- ✅ Access keys for programmatic access
- ✅ STS session tokens for temporary access
- ✅ `AuthenticationService` for credential validation
- ❌ No dedicated API token system
- ❌ No scoped permissions for API tokens
- ❌ No token revocation mechanism

## Problem Statement

External clients need:
- Long-lived API tokens (unlike STS sessions)
- Scoped permissions (specific actions/resources)
- Token revocation capability
- Token rotation support
- Audit trail for API token usage

Current access keys don't support:
- Scoped permissions (all-or-nothing)
- Easy revocation (requires key deletion)
- Usage tracking
- Token metadata (client identification, purpose)

## Proposed Solution

Create `ApiTokenService` for JWT API tokens:

1. **API Token Generation**
   - Generate JWT with scoped permissions
   - Custom expiration (longer than sessions)
   - Client identification (client_id claim)
   - Token metadata (name, description, tags)

2. **Scoped Permissions**
   - Actions allowed in token
   - Resources accessible
   - Conditions (IP restrictions, etc.)

3. **Token Management**
   - Token revocation (blacklist)
   - Token rotation
   - Usage tracking
   - Expiration management

4. **Store Integration**
   - `ApiTokenStore` trait
   - Store issued tokens
   - Track usage and revocation

## Implementation Plan

### Phase 1: API Token Service (Week 1)

**Tasks**:
- [ ] Create `ApiTokenService` in `crates/wami/src/service/jwt/api_token.rs`
- [ ] Implement token generation with scopes
- [ ] Implement token validation
- [ ] Scoped permission checking
- [ ] Client identification

**Files to Create**:
- `crates/wami/src/service/jwt/api_token.rs`
- `crates/wami/src/wami/jwt/api_token/model.rs`
- `crates/wami/src/wami/jwt/api_token/requests.rs`

**Key Structures**:
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiToken {
    pub token_id: String,
    pub client_id: String,
    pub name: String,
    pub description: Option<String>,
    pub scopes: Vec<Scope>,
    pub expiration: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
    pub revoked: bool,
    pub metadata: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scope {
    pub actions: Vec<String>,      // e.g., ["iam:GetUser", "iam:ListUsers"]
    pub resources: Vec<String>,    // e.g., ["arn:wami:iam:*:user/*"]
    pub conditions: Option<Value>,  // Optional conditions
}
```

### Phase 2: Token Management (Week 2)

**Tasks**:
- [ ] Token revocation (blacklist)
- [ ] Token rotation
- [ ] Usage tracking
- [ ] Expiration handling
- [ ] Token listing and querying

**Files to Modify**:
- `crates/wami/src/service/jwt/api_token.rs`

**Key Methods**:
```rust
impl<S> ApiTokenService<S> {
    pub async fn revoke_token(
        &mut self,
        token_id: &str,
    ) -> Result<()>;
    
    pub async fn rotate_token(
        &mut self,
        token_id: &str,
    ) -> Result<String>;  // Returns new token
    
    pub async fn track_usage(
        &mut self,
        token_id: &str,
    ) -> Result<()>;
}
```

### Phase 3: Store Implementation (Week 2)

**Tasks**:
- [ ] Create `ApiTokenStore` trait
- [ ] Implement memory store
- [ ] Store issued tokens
- [ ] Track revocations
- [ ] Track usage statistics

**Files to Create**:
- `crates/wami/src/store/traits/jwt/api_token.rs`
- `crates/wami/src/store/memory/jwt/api_token.rs`

**Trait Definition**:
```rust
#[async_trait]
pub trait ApiTokenStore: Send + Sync {
    async fn create_token(
        &mut self,
        token: ApiToken,
    ) -> Result<ApiToken>;
    
    async fn get_token(
        &self,
        token_id: &str,
    ) -> Result<Option<ApiToken>>;
    
    async fn revoke_token(
        &mut self,
        token_id: &str,
    ) -> Result<()>;
    
    async fn list_tokens(
        &self,
        client_id: Option<&str>,
    ) -> Result<Vec<ApiToken>>;
}
```

### Phase 4: Integration with Authentication (Week 3)

**Tasks**:
- [ ] Integrate API tokens with `AuthenticationService`
- [ ] Validate scoped permissions
- [ ] Check token revocation
- [ ] Track usage on authentication
- [ ] Support token in Authorization header

**Files to Modify**:
- `crates/wami/src/service/auth/authentication.rs`

### Phase 5: Testing (Week 3)

**Tasks**:
- [ ] Unit tests for token generation
- [ ] Integration tests
- [ ] Security tests (token reuse, expired tokens)
- [ ] Performance tests
- [ ] Revocation tests

## Files to Create

- `crates/wami/src/service/jwt/api_token.rs`
- `crates/wami/src/store/traits/jwt/api_token.rs`
- `crates/wami/src/store/memory/jwt/api_token.rs`
- `crates/wami/src/wami/jwt/api_token/model.rs`
- `crates/wami/src/wami/jwt/api_token/requests.rs`

## Dependencies

- **Issue #003** (wami-jwt crate) must be completed first
- **Issue #005** (JWT Authentication) recommended

## Examples

### Example 1: Generate API Token

```rust
use wami::service::jwt::ApiTokenService;
use wami::wami::jwt::api_token::{CreateApiTokenRequest, Scope};

let service = ApiTokenService::new(store);

let request = CreateApiTokenRequest {
    client_id: "my-app-123".to_string(),
    name: "Production API Token".to_string(),
    description: Some("Token for production API access".to_string()),
    scopes: vec![
        Scope {
            actions: vec!["iam:GetUser".to_string(), "iam:ListUsers".to_string()],
            resources: vec!["arn:wami:iam:*:user/*".to_string()],
            conditions: None,
        },
    ],
    expiration_days: Some(365),  // 1 year
    metadata: HashMap::new(),
};

let token = service.create_token(&context, request).await?;
println!("API Token: {}", token.jwt_token);
```

### Example 2: Authenticate with API Token

```rust
use wami::service::auth::AuthenticationService;

let auth_service = AuthenticationService::new(store);

// Authenticate using API token
let context = auth_service
    .authenticate_api_token(&api_token)
    .await?;

// Context has scoped permissions
println!("Authenticated as: {}", context.caller_arn());
```

### Example 3: Revoke Token

```rust
use wami::service::jwt::ApiTokenService;

let service = ApiTokenService::new(store);

// Revoke token
service.revoke_token(&context, "token-123").await?;

// Token is now invalid, authentication will fail
```

### Example 4: Rotate Token

```rust
use wami::service::jwt::ApiTokenService;

let service = ApiTokenService::new(store);

// Rotate token (creates new token, marks old as rotated)
let new_token = service.rotate_token(&context, "token-123").await?;

println!("New token: {}", new_token);
// Old token still valid for grace period (configurable)
```

## Testing Strategy

1. **Unit Tests**: Token generation, scoped permissions
2. **Integration Tests**: Full API token flow
3. **Security Tests**: Token reuse, expired tokens, revoked tokens
4. **Performance Tests**: Token validation overhead
5. **Revocation Tests**: Immediate revocation, grace period

## Success Criteria

- [ ] API tokens generated with scopes
- [ ] Token validation working
- [ ] Scoped permissions enforced
- [ ] Revocation functional
- [ ] Usage tracking implemented
- [ ] Token rotation supported
- [ ] Tests passing
- [ ] Documentation with examples

## Dependencies

- Issue #003 (wami-jwt crate) must be completed first
- Issue #005 (JWT Authentication) recommended

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Token compromise | High | Short expiration, easy revocation, rotation |
| Scope bypass | High | Strict permission checking, audit logging |
| Token reuse | Medium | JTI tracking, one-time use option |

---

**Estimated Effort**: 3 weeks (1 developer)  
**Dependencies**: Issue #003 (required), Issue #005 (recommended)

