# WAMI - Who Am I

**Multi-cloud Identity and Access Management Library for Rust**

[![GitHub last commit](https://img.shields.io/github/last-commit/lsh0x/wami)](https://github.com/lsh0x/wami/commits/main)
[![CI](https://github.com/lsh0x/wami/workflows/CI/badge.svg)](https://github.com/lsh0x/wami/actions)
[![Codecov](https://codecov.io/gh/lsh0x/wami/branch/main/graph/badge.svg)](https://codecov.io/gh/lsh0x/wami)
[![Docs](https://docs.rs/wami/badge.svg)](https://docs.rs/wami)
[![Crates.io](https://img.shields.io/crates/v/wami.svg)](https://crates.io/crates/wami)

## Overview

**WAMI** (Who Am I) is a pure Rust library for Identity and Access Management (IAM), Security Token Service (STS), and Single Sign-On (SSO) operations across multiple cloud providers. Built with a **domain-driven design**, WAMI separates business logic from storage, making it flexible, testable, and cloud-agnostic.

**Key Features:**
- 🌐 **Multi-cloud Support** - AWS, GCP, Azure, and custom identity providers
- 🏗️ **Pure Domain Logic** - Business logic without storage dependencies
- 💾 **Pluggable Storage** - In-memory, SQL, NoSQL, or custom backends
- 🏢 **Multi-tenant Architecture** - Built-in hierarchical tenant isolation with opaque numeric IDs
- 🔐 **Complete IAM Suite** - Users, groups, roles, policies, credentials
- 🔑 **Temporary Credentials** - STS sessions and role assumption
- 📊 **SSO Administration** - Permission sets, assignments, and federation
- 🏷️ **ARN System** - Unified resource naming with multi-tenant and multi-cloud support
- 🔢 **Opaque Tenant IDs** - Numeric tenant IDs (u64) for security and scalability
- 🦀 **100% Rust** - Type-safe, async-first, zero-cost abstractions
- ✅ **Well-tested** - 539 unit tests with 89.43% code coverage (all passing)

---

## 📚 Documentation

### Getting Started
- **[Getting Started Guide](docs/GETTING_STARTED.md)** - Step-by-step tutorial for your first WAMI app
- **[Workspace Structure](docs/WORKSPACE_STRUCTURE.md)** - Understanding the modular crate architecture
- **[Examples](examples/README.md)** - 24 working examples demonstrating all major features

### Core Concepts
- **[Architecture](docs/ARCHITECTURE.md)** - Design principles, components, and data flow
- **[API Reference](docs/API_REFERENCE.md)** - Detailed API documentation for all modules

### Feature Guides
- **[IAM Guide](docs/IAM_GUIDE.md)** - Users, groups, roles, and policies
- **[STS Guide](docs/STS_GUIDE.md)** - Temporary credentials and sessions
- **[SSO Admin Guide](docs/SSO_ADMIN_GUIDE.md)** - Permission sets and account assignments
- **[Multi-tenant Guide](docs/MULTI_TENANT_GUIDE.md)** - Tenant isolation and hierarchy

### Advanced Topics
- **[Store Implementation](docs/STORE_IMPLEMENTATION.md)** - Create custom storage backends
- **[Multi-cloud Providers](docs/MULTICLOUD_PROVIDERS.md)** - AWS, GCP, Azure provider details
- **[Permission Checking](docs/PERMISSION_CHECKING.md)** - Policy evaluation and authorization
- **[ARN Specification](docs/ARN_SPECIFICATION.md)** - Complete ARN format documentation and usage guide
- **[ARN Architecture](docs/ARN_ARCHITECTURE_COMPLETE.md)** - Resource naming across providers with multi-tenant and multi-cloud support

### Project Information
- **[Changelog](docs/CHANGELOG.md)** - Version history and release notes
- **[Multi-cloud Status](docs/MULTICLOUD_STATUS.md)** - Provider implementation status
- **[Security](docs/SECURITY.md)** - Security policies and vulnerability reporting

---

## Quick Start

### Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
wami = "0.16"
tokio = { version = "1.0", features = ["full"] }
```

**Note**: WAMI is organized as a **workspace of crates** for better modularity. The main `wami` crate re-exports everything, so you can use it exactly as before. For details, see [Workspace Structure](docs/WORKSPACE_STRUCTURE.md).

### Your First Example

```rust
use wami::arn::{TenantPath, WamiArn};
use wami::context::WamiContext;
use wami::store::memory::InMemoryWamiStore;
use wami::store::traits::UserStore;
use wami::wami::identity::user::builder::build_user;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize storage
    let mut store = InMemoryWamiStore::default();
    
    // Create WAMI context with ARN (using numeric tenant IDs)
    let context = WamiContext::builder()
        .instance_id("123456789012")
        .tenant_path(TenantPath::single(0)) // Root tenant uses ID 0
        .caller_arn(
            WamiArn::builder()
                .service(wami::arn::Service::Iam)
                .tenant_path(TenantPath::single(0))
                .wami_instance("123456789012")
                .resource("user", "admin")
                .build()?,
        )
        .is_root(false)
        .build()?;
    
    // Build a user (pure function with ARN support)
    let user = build_user(
        "alice".to_string(),
        Some("/engineering/".to_string()),
        &context,
    )?;
    
    // Store it
    let created = store.create_user(user).await?;
    println!("✅ Created user: {}", created.user_name);
    println!("✅ WAMI ARN: {}", created.wami_arn);
    
    // Retrieve it
    let retrieved = store.get_user("alice").await?;
    println!("✅ Retrieved: {:?}", retrieved.unwrap().user_name);
    
    Ok(())
}
```

**Output:**
```
✅ Created user: alice
✅ WAMI ARN: arn:wami:iam:0:wami:123456789012:user/...
✅ Retrieved: "alice"
```

See **[Getting Started Guide](docs/GETTING_STARTED.md)** for more examples.

## 🎯 Example Programs

WAMI includes **24 runnable examples** demonstrating all major features:

| Category | Examples | Status |
|----------|----------|--------|
| **Getting Started** | 01-03: Hello World, CRUD, Service Layer | ✅ All Working |
| **Multi-Tenancy** | 04-08: Tenants, Hierarchy, Quotas, Cross-Tenant Access, Migration | ✅ All Working |
| **Multi-Cloud** | 09-13: User Sync, Provider Switching, Hybrid Cloud, DR | ✅ All Working |
| **Policies & RBAC** | 14-17, 23: Policy Basics, Evaluation, RBAC, ABAC, Boundaries | ✅ All Working |
| **STS & Federation** | 18-20: Session Tokens, Role Assumption, Federation | ✅ All Working |
| **SSO & Federation** | 21-22: SSO Setup, Identity Providers | ✅ All Working |
| **ARN System** | 25: ARN Usage (Building, Parsing, Transforming) | ✅ All Working |

Run any example with:
```bash
cargo run --example 01_hello_wami
```

**See [examples/README.md](examples/README.md) for complete documentation.**

---

## Architecture Overview

WAMI follows a clean 3-layer architecture:

```
┌─────────────────────────────────────────────────┐
│         Application Layer (Your Code)           │
└────────────────────┬────────────────────────────┘
                     │
┌────────────────────┼────────────────────────────┐
│    Domain Layer    │  Pure Functions            │
│                    │  (wami::*)                 │
│  • Identity        │  No storage dependencies   │
│  • Credentials     │  Pure business logic       │
│  • Policies        │  Builders & validators     │
│  • STS Sessions    │                            │
│  • Tenants         │                            │
│  • ARN System      │                            │
└────────────────────┬────────────────────────────┘
                     │
┌────────────────────┼────────────────────────────┐
│    Storage Layer   │  Traits & Implementations  │
│  WamiStore         │  In-memory, SQL, custom    │
│  StsStore          │  Pluggable backends        │
│  TenantStore       │                            │
└─────────────────────────────────────────────────┘
```

**Key Benefits:**
- ✅ **Separation of Concerns** - Domain logic independent from storage
- ✅ **Testability** - Pure functions are easy to test
- ✅ **Flexibility** - Use any storage backend (memory, SQL, NoSQL)
- ✅ **Type Safety** - Rust's type system prevents common errors

Read more in **[Architecture Guide](docs/ARCHITECTURE.md)**.

---

## Core Features

### 🔐 Identity Management

```rust
use wami::arn::{TenantPath, WamiArn};
use wami::context::WamiContext;
use wami::wami::identity::{user, group, role};

// Create WAMI context
let context = WamiContext::builder()
    .instance_id("123456789012")
    .tenant_path(TenantPath::single(0)) // Root tenant uses ID 0
    .caller_arn(
        WamiArn::builder()
            .service(wami::arn::Service::Iam)
            .tenant_path(TenantPath::single(0))
            .wami_instance("123456789012")
            .resource("user", "admin")
            .build()?,
    )
    .is_root(false)
    .build()?;

// Create user
let user = user::builder::build_user("alice".into(), None, &context)?;
store.create_user(user).await?;

// Create group and add user
let group = group::builder::build_group("admins".into(), None, &context)?;
store.create_group(group).await?;
store.add_user_to_group("admins", "alice").await?;

// Create role with trust policy
let trust_policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}"#;
let role = role::builder::build_role(
    "AdminRole".into(),
    trust_policy.to_string(),
    None,
    None,
    None,
    &context,
)?;
store.create_role(role).await?;
```

### 🔑 Credentials & STS

```rust
use wami::arn::{TenantPath, WamiArn};
use wami::context::WamiContext;
use wami::wami::credentials::access_key::builder::build_access_key;
use wami::service::{SessionTokenService, AssumeRoleService};
use wami::wami::sts::session_token::requests::GetSessionTokenRequest;

// Create WAMI context (using numeric tenant IDs)
let context = WamiContext::builder()
    .instance_id("123456789012")
    .tenant_path(TenantPath::single(0)) // Root tenant uses ID 0
    .caller_arn(
        WamiArn::builder()
            .service(wami::arn::Service::Iam)
            .tenant_path(TenantPath::single(0))
            .wami_instance("123456789012")
            .resource("user", "alice")
            .build()?,
    )
    .is_root(false)
    .build()?;

// Create access keys (uses context)
let key = build_access_key("alice".to_string(), &context)?;
store.create_access_key(key).await?;

// Create temporary session (via service layer)
let sts_service = SessionTokenService::new(store.clone());
let token_req = GetSessionTokenRequest {
    duration_seconds: Some(3600),
    serial_number: None,
    token_code: None,
};
let session = sts_service
    .get_session_token(&context, token_req, &user_arn)
    .await?;
```

### 🏷️ ARN System

```rust
use wami::arn::{WamiArn, Service, TenantPath};

// Build a WAMI native ARN (using numeric tenant IDs)
let arn = WamiArn::builder()
    .service(Service::Iam)
    .tenant_hierarchy(vec![12345678, 87654321, 99999999]) // Opaque numeric IDs
    .wami_instance("999888777")
    .resource("user", "77557755")
    .build()?;

println!("{}", arn);
// Output: arn:wami:iam:12345678/87654321/99999999:wami:999888777:user/77557755

// Build a cloud-synced ARN
let cloud_arn = WamiArn::builder()
    .service(Service::Iam)
    .tenant(12345678) // Numeric tenant ID
    .wami_instance("999888777")
    .cloud_provider("aws", "223344556677")
    .resource("user", "77557755")
    .build()?;

println!("{}", cloud_arn);
// Output: arn:wami:iam:12345678:wami:999888777:aws:223344556677:global:user/77557755

// Parse an ARN
let parsed = WamiArn::from_str("arn:wami:iam:12345678:wami:999888777:user/77557755")?;
println!("Resource type: {}", parsed.resource_type());
```

### 🏢 Multi-tenant Support

```rust
use wami::wami::tenant::{Tenant, TenantId};

// Create parent tenant (service generates unique numeric ID)
let parent = tenant_service
    .create_tenant(
        &context,
        "acme-corp".to_string(),
        Some("ACME Corp".to_string()),
        None, // No parent, this is a root tenant
    )
    .await?;
let parent_id = parent.id.clone();

// Create child tenant
let child = tenant_service
    .create_tenant(
        &context,
        "engineering".to_string(),
        Some("Engineering Dept".to_string()),
        Some(parent_id.clone()),
    )
    .await?;
let child_id = child.id.clone();

// Query hierarchy
let descendants = store.get_descendants(&parent_id).await?;
```

---

## Project Structure

```
wami/
├── src/
│   ├── wami/              # Domain layer (pure functions)
│   │   ├── identity/      # Users, groups, roles
│   │   ├── credentials/   # Access keys, MFA, certificates
│   │   ├── policies/      # IAM policies
│   │   ├── sts/          # Sessions, temporary credentials
│   │   ├── sso_admin/    # SSO configuration
│   │   └── tenant/       # Multi-tenant models
│   │
│   ├── arn/              # ARN system (WAMI resource naming)
│   │   ├── types.rs      # Core ARN types
│   │   ├── builder.rs     # Fluent ARN builder
│   │   ├── parser.rs      # ARN parsing
│   │   └── transformer.rs # Provider-specific transformations
│   │
│   ├── store/            # Storage layer
│   │   ├── traits/       # Storage trait definitions
│   │   └── memory/       # In-memory implementations
│   │
│   ├── provider/         # Cloud provider abstractions
│   │   ├── aws.rs
│   │   ├── gcp.rs
│   │   └── azure.rs
│   │
│   └── error.rs          # Error types
│
├── docs/                 # 📚 All documentation
├── examples/             # Working code examples
└── tests/                # Integration tests
```

---

## Testing

Run the full test suite:

```bash
cargo test
```

WAMI has **539 tests** (all passing ✅) covering:
- ✅ Domain logic (pure functions)
- ✅ Store implementations (CRUD, queries, concurrency)
- ✅ Multi-tenant isolation
- ✅ Resource enumeration and downcasting
- ✅ ARN building, parsing, and transformation

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Add tests for your changes
4. Ensure all tests pass (`cargo test`)
5. Run `cargo clippy` and `cargo fmt`
6. Submit a pull request

See **[Contributing Guide](CONTRIBUTING.md)** for more details.

---

## Roadmap

### In Planning
- [ ] **[Policy Condition Keys](docs/issues/ISSUE_001_CONDITION_KEYS.md)** - 140+ condition keys and 91 operators for fine-grained access control ([Summary](docs/CONDITION_KEYS_SUMMARY.md))

### Future Enhancements
- [ ] SQL store implementations (PostgreSQL, MySQL)
- [ ] Advanced policy evaluation engine
- [x] **Identity Provider Support** - SAML and OIDC federation (✅ Completed in v0.8.0)
- [x] **ARN System** - Unified resource naming with multi-tenant and multi-cloud support (✅ Completed in v0.11.0)
- [x] **Opaque Numeric Tenant IDs** - Secure tenant identification with u64-based IDs (✅ Completed in v0.11.0)
- [ ] Audit logging and compliance
- [ ] Service/orchestration layer

See **[Issues Tracker](docs/issues/README.md)** for details.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Security

Found a security issue? Please see **[Security Policy](docs/SECURITY.md)** for reporting guidelines.

---

## Links

- **[Documentation](docs/)** - Complete documentation index
- **[Crates.io](https://crates.io/crates/wami)** - Published crate
- **[Docs.rs](https://docs.rs/wami)** - API documentation
- **[GitHub](https://github.com/lsh0x/wami)** - Source code
- **[Issues](https://github.com/lsh0x/wami/issues)** - Bug reports and feature requests

---

<div align="center">
  <strong>Built with ❤️ in Rust</strong>
  <br>
  <sub>Multi-cloud IAM made simple</sub>
</div>
