# Login Profile Module

IAM login profile resource management for WAMI. This module provides strongly
typed representations, builders, and request types for managing IAM user login
profiles (console passwords).

## Overview

Login profiles enable IAM users to sign in to the AWS Management Console with
a password. This module provides:

- **Model Types** – `LoginProfile` for representing login profile resources
- **Builder Functions** – Context-aware builders that generate consistent WAMI ARNs
- **Request Types** – DTOs for service API operations (create, get, update)

## Models

### `LoginProfile`

Represents a login profile (console password) for an IAM user:

- `user_name` – The IAM user associated with the login profile
- `create_date` – Timestamp when the profile was created
- `password_reset_required` – Whether the user must reset their password on next sign-in
- `wami_arn` – WAMI ARN for cross-provider identification
- `providers` – List of cloud provider configurations

## Builder Functions

### `build_login_profile`

Creates a new `LoginProfile` with context-based identifiers:

```rust
use wami_core::context::WamiContext;
use wami_credentials::login_profile::builder::build_login_profile;

let context = WamiContext::builder()
    .instance_id("123456789012")
    .tenant_path(wami_core::arn::TenantPath::single(0))
    .caller_arn(/* ... */)
    .build()
    .unwrap();

let login_profile = build_login_profile(
    "alice".into(),
    true, // password_reset_required
    &context,
)?;
```

### `update_login_profile`

Updates a login profile's properties:

```rust
use wami_credentials::login_profile::builder::update_login_profile;

// Update password reset requirement
let login_profile = update_login_profile(
    login_profile,
    Some(false), // password_reset_required
);
```

### `add_provider_to_login_profile`

Adds a provider configuration to a login profile:

```rust
use wami_credentials::login_profile::builder::add_provider_to_login_profile;
use wami_provider::ProviderConfig;

let config = ProviderConfig::aws(/* ... */);
let login_profile = add_provider_to_login_profile(login_profile, config);
```

## Request Types

- `CreateLoginProfileRequest` – Request to create a new login profile
- `GetLoginProfileRequest` – Request to retrieve a login profile
- `UpdateLoginProfileRequest` – Request to update a login profile

## Usage Example

```rust
use wami_core::context::WamiContext;
use wami_credentials::login_profile::builder::build_login_profile;
use wami_credentials::login_profile::LoginProfile;

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

// Create a new login profile with password reset required
let login_profile = build_login_profile(
    "alice".into(),
    true,
    &context,
)?;

assert_eq!(login_profile.user_name, "alice");
assert!(login_profile.password_reset_required);
assert!(login_profile.wami_arn.to_string().contains("user"));
```

