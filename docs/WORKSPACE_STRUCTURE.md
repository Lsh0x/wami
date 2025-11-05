# WAMI Workspace Structure

This document describes the modular workspace architecture of WAMI, which has been refactored from a monolithic crate into a composable workspace of specialized crates.

## Overview

WAMI is organized as a **Cargo workspace** containing multiple crates, each with a specific responsibility. This modular design provides:

- **Faster compilation** - Only compile what you need
- **Clear dependencies** - Explicit boundaries between modules
- **Better organization** - Logical separation of concerns
- **Feature isolation** - Optional features via feature flags

## Workspace Crates

### Core Crates

#### `wami-core`
**Purpose**: Foundation primitives shared across the entire workspace

**Contains**:
- `arn` - ARN parsing, building, and transformation
- `context` - `WamiContext` and session information
- `error` - `AmiError` and `Result` types
- `types` - Common types (`PolicyDocument`, `Tag`, etc.)

**Usage**:
```rust
use wami_core::arn::{WamiArn, Service, TenantPath};
use wami_core::context::WamiContext;
use wami_core::error::{AmiError, Result};
use wami_core::types::PolicyDocument;
```

**Dependencies**: AWS SDKs, `chrono`, `serde`, `thiserror`

---

#### `wami-traits`
**Purpose**: Domain-agnostic trait definitions for stores and services

**Contains**:
- `Store<T>` - Generic CRUD trait for backing stores
- `Service` - Abstraction over high-level services
- `ServiceRegistry` - Dependency injection mechanism

**Usage**:
```rust
use wami_traits::Store;
use wami_traits::Service;
use wami_traits::ServiceRegistry;
```

**Dependencies**: `wami-core`

---

#### `wami-provider`
**Purpose**: Cloud provider integrations (AWS, GCP, Azure)

**Contains**:
- Provider-specific ARN builders and transformers
- Cloud provider configuration
- Provider-specific implementations

**Usage**:
```rust
use wami_provider::{AwsProvider, CloudProvider, ProviderConfig};
```

**Dependencies**: `wami-core`

---

### Domain Crates

#### `wami-identity`
**Purpose**: Identity domain models and builders

**Contains**:
- `User`, `Group`, `Role`
- `IdentityProvider`, `ServiceLinkedRole`
- Builders and operations for identity management

**Usage**:
```rust
use wami_identity::{User, Group, Role, UserBuilder};
```

**Dependencies**: `wami-core`

---

#### `wami-credentials`
**Purpose**: Credential management domain

**Contains**:
- `AccessKey`, `LoginProfile`, `MfaDevice`
- `ServerCertificate`, `SigningCertificate`
- Service-specific credentials

**Usage**:
```rust
use wami_credentials::{AccessKey, LoginProfile, MfaDevice};
```

**Dependencies**: `wami-core`

---

### Infrastructure Crates

#### `wami-macros`
**Purpose**: Procedural macros for reducing boilerplate

**Contains**:
- `#[derive(Service)]` - Auto-generate `Service` trait implementations
- `#[service]` - Generate service struct boilerplate
- `register_services!` - Register multiple services in a registry

**Usage**:
```rust
use wami_macros::service;

#[service(store_trait = "crate::store::traits::UserStore")]
pub struct UserService<S> {
    store: Arc<RwLock<S>>,
}
```

**Dependencies**: `syn`, `quote`, `proc-macro2`

**Note**: This is a procedural macro crate (`proc-macro = true`)

---

#### `wami-service`
**Purpose**: Service registry and orchestration utilities

**Contains**:
- `Registry` - Dynamic service registration and retrieval
- Service discovery utilities

**Usage**:
```rust
use wami_service::Registry;
use wami_traits::ServiceRegistry;

let mut registry = Registry::new();
registry.register("user_service", Arc::new(user_service));
```

**Dependencies**: `wami-traits`

---

### Main Crate

#### `wami`
**Purpose**: Main façade crate that re-exports everything

**Contains**:
- Re-exports from all workspace crates
- Service layer implementations
- Store implementations (memory, traits)
- Backward compatibility layer

**Usage**:
```rust
// All public APIs are available through the main crate
use wami::{
    // Core types
    WamiContext, WamiArn, AmiError, Result,
    // Domain types
    User, Group, Role, AccessKey,
    // Stores
    InMemoryStore, UserStore,
    // Services
    UserService, GroupService,
};
```

**Dependencies**: All workspace crates

---

## Import Patterns

### Before (Monolithic)
```rust
use crate::error::Result;
use crate::context::WamiContext;
use crate::credentials::AccessKey;
```

### After (Workspace)
```rust
// In workspace crates (wami-core, wami-credentials, etc.)
use wami_core::error::Result;
use wami_core::context::WamiContext;
use wami_credentials::access_key::AccessKey;

// In your application (using the main crate)
use wami::error::Result;
use wami::context::WamiContext;
use wami::AccessKey;
```

## Service Macro (`#[service]`)

To remove boilerplate from service implementations we use the `#[service]` attribute macro.
It generates the following helpers by default:

- `new(store: Arc<RwLock<S>>) -> Self`
- `store(&self) -> &Arc<RwLock<S>>`
- `read_store(&self)` / `write_store(&self)` guard helpers

### Basic Usage
```rust
#[wami_macros::service(store_trait = "crate::store::traits::UserStore")]
pub struct UserService<S> {
    store: Arc<RwLock<S>>,
}
```

### Services with Additional Fields
For services that need custom constructors (e.g., to inject a provider),
use `generate_new = false` and keep your own `new` implementation.

```rust
#[wami_macros::service(
    store_trait = "crate::store::traits::SessionStore",
    generate_new = false,
)]
pub struct SessionService<S> {
    store: Arc<RwLock<S>>,
    provider: Arc<dyn CloudProvider>,
    account_id: String,
}
```

### Composite Store Bounds
Some services depend on multiple store traits. Define a local alias and use it in the macro:

```rust
pub trait AttachmentServiceStore: UserStore + GroupStore + RoleStore + PolicyStore {}
impl<T> AttachmentServiceStore for T where T: UserStore + GroupStore + RoleStore + PolicyStore {}

#[wami_macros::service(
    store_trait = "crate::service::policies::attachment::AttachmentServiceStore"
)]
pub struct AttachmentService<S> {
    store: Arc<RwLock<S>>,
}
```

This pattern keeps the macro flexible while avoiding repeated trait bounds in each method.

## Feature Flags

The main `wami` crate supports feature flags for optional compilation:

```toml
[dependencies]
wami = { path = "../wami", features = ["identity", "sts"] }
```

Available features (planned):
- `identity` - Identity management (users, groups, roles)
- `credentials` - Credential management
- `sts` - Security Token Service
- `sso-admin` - SSO Administration
- `default` - Includes all features

## Building

### Build entire workspace
```bash
cargo build --workspace
```

### Build specific crate
```bash
cargo build -p wami-core
cargo build -p wami-identity
```

### Build with tests
```bash
cargo test --workspace
```

## Development Workflow

1. **Core changes** → Edit `wami-core`
2. **Domain changes** → Edit `wami-identity`, `wami-credentials`, etc.
3. **Service changes** → Edit `wami` crate's service layer
4. **Macro changes** → Edit `wami-macros` (requires full rebuild)

## Migration Guide

If you're migrating code from the monolithic structure:

1. **Update imports**:
   - `crate::error` → `wami_core::error` (in workspace crates) or `wami::error` (in apps)
   - `crate::context` → `wami_core::context` or `wami::context`
   - `crate::credentials` → `wami_credentials` or `wami::AccessKey`

2. **Service layer**: Services now use the `#[service]` macro or manual implementations with `read_store()`/`write_store()` helpers

3. **Store layer**: Store traits remain in `wami` crate for backward compatibility

## Benefits

✅ **Faster builds** - Compile only what changed  
✅ **Clear boundaries** - Explicit dependencies  
✅ **Better organization** - Logical module separation  
✅ **Type safety** - Shared types via `wami-core`  
✅ **Extensibility** - Easy to add new domain crates  

## Future Enhancements

- [ ] Feature-gated compilation for optional domains
- [ ] Plugin system for external service providers
- [ ] Versioned service APIs
- [ ] Async trait support improvements
- [ ] Telemetry hooks for service calls

