# Service Credential Module

IAM service-specific credential resource management for WAMI. This module provides
strongly typed representations, builders, and request types for managing
service-specific credentials used by AWS services like CodeCommit and IoT.

## Overview

Service-specific credentials are long-term credentials generated for specific AWS
services that don't support regular access keys. This module provides:

- **Model Types** – `ServiceSpecificCredential` and `ServiceSpecificCredentialMetadata`
  for representing service credential resources
- **Builder Functions** – Context-aware builders that generate consistent WAMI ARNs
- **Request Types** – DTOs for service API operations

## Models

### `ServiceSpecificCredential`

Represents a service-specific credential with the following fields:

- `user_name` – The IAM user associated with the credential
- `service_specific_credential_id` – Unique identifier for the credential
- `service_user_name` – Generated username for the service
- `service_password` – Generated password (only provided during creation)
- `service_name` – Name of the service (e.g., "codecommit.amazonaws.com")
- `create_date` – Timestamp when the credential was created
- `status` – Status of the credential (`Active` or `Inactive`)
- `wami_arn` – WAMI ARN for cross-provider identification
- `providers` – List of cloud provider configurations

### `ServiceSpecificCredentialMetadata`

Metadata about a service-specific credential (without the password):

- `user_name` – The IAM user associated with the credential
- `service_specific_credential_id` – Unique identifier for the credential
- `service_user_name` – Generated username for the service
- `service_name` – Name of the service
- `create_date` – Timestamp when the credential was created
- `status` – Status of the credential

## Builder Functions

### `build_service_credential`

Creates a new `ServiceSpecificCredential` with context-based identifiers:

```rust
use wami_core::context::WamiContext;
use wami_credentials::service_credential::builder::build_service_credential;

let context = WamiContext::builder()
    .instance_id("123456789012")
    .tenant_path(wami_core::arn::TenantPath::single(0))
    .caller_arn(/* ... */)
    .build()
    .unwrap();

let credential = build_service_credential(
    "alice".into(),
    "codecommit.amazonaws.com".into(),
    &context,
)?;
```

## Request Types

The module provides request types for service credential operations:
- `CreateServiceSpecificCredentialRequest` – Request to create a service credential
- `ListServiceSpecificCredentialsRequest` – Request to list service credentials for a user
- `UpdateServiceSpecificCredentialRequest` – Request to update credential status
- `DeleteServiceSpecificCredentialRequest` – Request to delete a service credential

## Usage Example

```rust
use wami_core::context::WamiContext;
use wami_credentials::service_credential::builder::build_service_credential;
use wami_credentials::service_credential::ServiceSpecificCredential;

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

// Create a new service-specific credential for CodeCommit
let credential = build_service_credential(
    "alice".into(),
    "codecommit.amazonaws.com".into(),
    &context,
)?;

assert_eq!(credential.user_name, "alice");
assert_eq!(credential.service_name, "codecommit.amazonaws.com");
assert_eq!(credential.status, "Active");
assert!(credential.service_password.is_some()); // Only available on creation
assert!(credential.wami_arn.to_string().contains("service-credential"));
```

