# MFA Device Module

IAM MFA (Multi-Factor Authentication) device resource management for WAMI. This
module provides strongly typed representations, builders, and request types for
managing MFA devices.

## Overview

MFA devices add an extra layer of security by requiring users to provide a
second authentication factor. This module provides:

- **Model Types** – `MfaDevice` for representing MFA device resources
- **Builder Functions** – Context-aware builders that generate consistent WAMI ARNs
- **Request Types** – DTOs for service API operations (enable, list)

## Models

### `MfaDevice`

Represents an MFA device associated with an IAM user:

- `user_name` – The IAM user associated with the MFA device
- `serial_number` – Unique serial number that identifies the MFA device
- `enable_date` – Timestamp when the device was enabled
- `wami_arn` – WAMI ARN for cross-provider identification
- `providers` – List of cloud provider configurations

## Builder Functions

### `build_mfa_device`

Creates a new `MfaDevice` with context-based identifiers:

```rust
use wami_core::context::WamiContext;
use wami_credentials::build_mfa_device;

let context = WamiContext::builder()
    .instance_id("123456789012")
    .tenant_path(wami_core::arn::TenantPath::single(0))
    .caller_arn(/* ... */)
    .build()
    .unwrap();

let mfa_device = build_mfa_device(
    "alice".into(),
    "arn:aws:iam::123456789012:mfa/alice".into(),
    &context,
)?;
```

### `add_provider_to_mfa_device`

Adds a provider configuration to an MFA device:

```rust
use wami_credentials::add_provider_to_mfa_device;
use wami_provider::ProviderConfig;

let config = ProviderConfig::aws(/* ... */);
let mfa_device = add_provider_to_mfa_device(mfa_device, config);
```

## Request Types

The module provides request types for MFA device operations:
- `EnableMfaDeviceRequest` – Request to enable an MFA device for a user (requires authentication codes)
- `ListMfaDevicesRequest` – Request to list MFA devices for a user

## Usage Example

```rust
use wami_core::context::WamiContext;
use wami_credentials::{build_mfa_device, MfaDevice};

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

// Create a new MFA device
let serial_number = "arn:aws:iam::123456789012:mfa/alice";
let mfa_device = build_mfa_device(
    "alice".into(),
    serial_number.into(),
    &context,
)?;

assert_eq!(mfa_device.user_name, "alice");
assert_eq!(mfa_device.serial_number, serial_number);
assert!(mfa_device.wami_arn.to_string().contains("mfa"));
```

