# wami-provider

Cloud provider integrations for the WAMI workspace. This crate encapsulates the
logic required to generate resource identifiers, map ARNs, and enforce provider
limits for AWS, GCP, Azure, and custom environments.

## Features

- **Provider Abstractions** – Common `CloudProvider` trait with concrete
  implementations for AWS, GCP, Azure, and customizable providers.
- **ARN Builder** – Utilities to parse and generate provider-specific ARNs and
  map them to WAMI ARNs.
- **Resource Limits** – Provider-specific quotas and validation helpers.
- **Utility Functions** – Helpers for provider-aware ID and path generation.

## Usage

```toml
[dependencies]
wami-provider = { path = "../wami-provider" }
```

```rust
use wami_provider::{AwsProvider, CloudProvider};

let provider = AwsProvider::new();
let user_arn = provider.generate_resource_identifier(
    wami_provider::ResourceType::User,
    "123456789012",
    "/",
    "alice",
);
assert_eq!(user_arn, "arn:aws:iam::123456789012:user/alice");
```

## Modules

- `aws`, `gcp`, `azure` – Provider-specific implementations.
- `arn_builder` – Parse and match provider ARNs.
- `custom` – Build-your-own provider implementation with configurable limits.
- `provider_info` – Metadata structures shared by services and stores.

## License

Licensed under MIT. See [`../LICENSE`](../../LICENSE) for details.

