# WAMI Workspace Structure

This document describes the modular workspace architecture of WAMI, which has been refactored from a monolithic crate into a composable workspace of specialized crates.

## Overview

WAMI is organized as a **Cargo workspace** containing multiple crates, each with a specific responsibility. This modular design provides:

- **Faster compilation** - Only compile what you need
- **Clear dependencies** - Explicit boundaries between modules
- **Better organization** - Logical separation of concerns
- **Feature isolation** - Optional features via feature flags

## Workspace Crates

Five members. Four are published to crates.io; the fifth is internal.

| crate | published | what it is |
|-------|-----------|------------|
| [`wami`](../crates/wami) | ✅ | the library — identity, policies, STS, OAuth/OIDC, stores, services, and the provider and credential modules |
| [`wami-core`](../crates/wami-core) | ✅ | ARNs, `WamiContext`, `AmiError`, shared types, and the `traits` module (`Store`, `Service`, `ServiceRegistry`) |
| [`wami-condition`](../crates/wami-condition) | ✅ | IAM condition-key evaluation — self-contained enough to use on its own |
| [`wami-macros`](../crates/wami-macros) | ✅ | procedural macros. Separate because Rust requires it: a `proc-macro = true` crate cannot hold ordinary library code |
| [`wami-service`](../crates/wami-service) | ❌ | a service registry, not in `wami`'s dependency graph. `publish = false` |

```
wami-core ──┬── wami-condition ──┐
            ├── wami-service     ├── wami
wami-macros ────────────────────-┘
```

### Why so few

There were ten. Publishing `wami` requires every crate in its graph to be on
crates.io — cargo strips `path` at publish time, so a consumer resolves
`wami-core = "0.16.0"` from the registry and nothing else. Six of the ten had no
public identity to justify that: `wami-provider` and the four cloud
implementations existed only behind a re-export façade, `wami-credentials`
behind `pub use wami_credentials as credentials`, and `wami-traits` was 37 lines
that `wami` never referenced.

They are now modules — `wami::provider`, `wami::provider::aws`,
`wami::credentials`, `wami_core::traits` — at exactly the paths they were
reachable from before. See [#129](https://github.com/Lsh0x/wami/issues/129) for
the reasoning and what it cost.

`wami-condition` stayed separate on purpose: 10k lines that rarely change, whose
separate compilation is worth keeping, and a problem someone might genuinely
want to solve without adopting an identity model.

### Versioning

`wami`, `wami-core`, `wami-condition` and `wami-macros` move in lockstep at one
version. They are released together and tested together; separate version lines
would imply an independence that does not exist.

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
cargo build -p wami-condition
```

### Build with tests
```bash
cargo test --workspace
```

## Development Workflow

1. **Core changes** → Edit `wami-core` (ARNs, context, errors, shared traits)
2. **Condition evaluation** → Edit `wami-condition`
3. **Everything else** → Edit `wami`: domain, services, stores, providers,
   credentials. They are modules there, not crates.
4. **Macro changes** → Edit `wami-macros` (requires a full rebuild, since every
   expansion downstream is invalidated)

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

