# wami-identity

Identity domain models for the WAMI workspace. This crate encapsulates the
structures, builders, and operations for users, groups, roles, service-linked
roles, identity providers, and root users.

## Features

- **Models** – Strongly typed definitions for IAM identities used across
  services and stores.
- **Builder APIs** – Context-driven builders that generate WAMI ARNs, enforce
  validation rules, and populate metadata.
- **Operations** – Business logic for identity lifecycle tasks (e.g., service
  linked role utilities).
- **Serde Support** – All models derive serialization traits for persistence and
  transport.

## Usage

```toml
[dependencies]
wami-identity = { path = "../wami-identity" }
```

```rust
use wami_core::context::WamiContext;
use wami_identity::user::builder::build_user;

let context = WamiContext::builder()
    .instance_id("123456789012")
    .tenant_path(wami_core::arn::TenantPath::single(0))
    .caller_arn(
        wami_core::arn::WamiArn::builder()
            .service(wami_core::arn::Service::Iam)
            .tenant(0)
            .wami_instance("123456789012")
            .resource("user", "admin")
            .build()
            .unwrap(),
    )
    .is_root(false)
    .build()
    .unwrap();

let user = build_user("alice".into(), Some("/engineering/".into()), &context).unwrap();
assert!(user.wami_arn.to_string().contains("user/alice"));
```

## Modules

- `user`, `group`, `role`, `service_linked_role`, `identity_provider`, `root_user`
  – Domain-specific namespaces with builders, models, and helpers.

## License

Licensed under MIT. See [`../LICENSE`](../../LICENSE) for details.


