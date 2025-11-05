# Access Key Module

IAM access key resource management for WAMI. This module provides strongly typed
representations, builders, and request types for managing IAM access keys.

## Overview

Access keys are long-term credentials used for programmatic access to AWS services.
This module provides:

- **Model Types** – `AccessKey` and `AccessKeyLastUsed` for representing access key
  resources
- **Builder Functions** – Context-aware builders that generate consistent WAMI ARNs
  and IDs
- **Request Types** – DTOs for service API operations (create, list, update)

## Models

### `AccessKey`

Represents an IAM access key with the following fields:

- `user_name` – The IAM user associated with the key
- `access_key_id` – Unique identifier (format: `AKIA` + 16 alphanumeric chars)
- `status` – Access key status (`Active` or `Inactive`)
- `create_date` – Timestamp when the key was created
- `secret_access_key` – Secret key (only provided during creation)
- `wami_arn` – WAMI ARN for cross-provider identification
- `providers` – List of cloud provider configurations

### `AccessKeyLastUsed`

Tracks usage information for access keys:

- `last_used_date` – When the key was last used
- `region` – AWS region where it was last used
- `service_name` – Service that was accessed

## Builder Functions

### `build_access_key`

Creates a new `AccessKey` with context-based identifiers:

```rust
use wami_core::context::WamiContext;
use wami_credentials::access_key::builder::build_access_key;

let context = WamiContext::builder()
    .instance_id("123456789012")
    .tenant_path(wami_core::arn::TenantPath::single(0))
    .caller_arn(/* ... */)
    .build()
    .unwrap();

let access_key = build_access_key("alice".into(), &context)?;
```

### `update_access_key_status`

Updates the status of an access key:

```rust
use wami_credentials::access_key::builder::update_access_key_status;

let access_key = update_access_key_status(access_key, "Inactive".to_string());
```

### `add_provider_to_access_key`

Adds a provider configuration to an access key:

```rust
use wami_credentials::access_key::builder::add_provider_to_access_key;
use wami_provider::ProviderConfig;

let config = ProviderConfig::aws(/* ... */);
let access_key = add_provider_to_access_key(access_key, config);
```

## Request Types

- `CreateAccessKeyRequest` – Request to create a new access key
- `ListAccessKeysRequest` – Request to list access keys for a user
- `ListAccessKeysResponse` – Response containing a list of access keys
- `UpdateAccessKeyRequest` – Request to update an access key's status

## Usage Example

```rust
use wami_core::context::WamiContext;
use wami_credentials::access_key::builder::build_access_key;
use wami_credentials::access_key::AccessKey;

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

// Create a new access key
let access_key = build_access_key("alice".into(), &context)?;

// Access key ID follows AWS format (AKIA prefix)
assert!(access_key.access_key_id.starts_with("AKIA"));
assert_eq!(access_key.status, "Active");
assert!(access_key.wami_arn.to_string().contains("access-key"));
```

