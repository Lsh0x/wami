# wami-credentials

Credential domain models and builders for WAMI. This crate provides strongly
typed representations and helper functions for access keys, login profiles, MFA
devices, server/signing certificates, and service-specific credentials.

## Features

- **Model Structs** – Typed representations of all credential resources used by
  services and stores.
- **Builder Utilities** – Context-aware builders that generate consistent WAMI
  ARNs, IDs, and metadata.
- **Request Types** – DTOs for service APIs (create/update/list operations).
- **Serde Support** – All models derive `Serialize`/`Deserialize` where
  appropriate.

## Usage

```toml
[dependencies]
wami-credentials = { path = "../wami-credentials" }
```

```rust
use wami_core::context::WamiContext;
use wami_credentials::access_key::builder::build_access_key;

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

let access_key = build_access_key("alice".into(), &context).unwrap();
assert!(access_key.wami_arn.to_string().contains("access-key"));
```

## Modules

- `access_key`, `login_profile`, `mfa_device`, `server_certificate`,
  `signing_certificate`, `service_credential` – Domain-specific namespaces with
  builders, models, and request/response types.

## License

Licensed under MIT. See [`../LICENSE`](../../LICENSE) for details.


