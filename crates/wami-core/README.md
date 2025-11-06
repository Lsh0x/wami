# wami-core

Core primitives shared across the WAMI workspace. This crate contains the
fundamental building blocks that other crates depend on, such as ARN parsing,
execution context, error handling, and shared types.

## Features

- **ARN System** – Builders, parsers, and transformers for multi-cloud WAMI
  ARNs (AWS, GCP, Azure, Scaleway, custom).
- **Execution Context** – `WamiContext` and session metadata used to scope
  operations.
- **Error Handling** – `AmiError`, helper utilities, and the `Result` alias used
  across the workspace.
- **Shared Types** – Strongly typed structures for policies, pagination,
  provider metadata, and more.

## Modules

- `arn` – Builders, parsers, and transformers for WAMI ARNs.
- `context` – Authentication/authorization context and session info.
- `error` – Core error types and helper utilities.
- `types` – Shared data structures (policy documents, pagination, etc.).

## Usage

Add the dependency in your `Cargo.toml`:

```toml
[dependencies]
wami-core = { path = "../wami-core" }
```

Example:

```rust
use wami_core::arn::{TenantPath, WamiArn};
use wami_core::context::WamiContext;

let context = WamiContext::builder()
    .instance_id("123456789012")
    .tenant_path(TenantPath::single(0))
    .caller_arn(
        WamiArn::builder()
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
```

## License

Licensed under MIT. See [`../LICENSE`](../../LICENSE) for details.


