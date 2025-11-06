# Signing Certificate Module

IAM signing certificate resource management for WAMI. This module provides strongly
typed representations, builders, and request types for managing IAM signing
certificates used for API request signing.

## Overview

Signing certificates are X.509 certificates used to sign API requests instead of
using access keys. This module provides:

- **Model Types** – `SigningCertificate` and `CertificateStatus` for representing
  signing certificate resources
- **Builder Functions** – Context-aware builders that generate consistent WAMI ARNs
- **Request Types** – DTOs for service API operations

## Models

### `SigningCertificate`

Represents a signing certificate associated with an IAM user:

- `user_name` – The IAM user associated with the certificate
- `certificate_id` – Unique identifier for the certificate
- `certificate_body` – PEM-encoded certificate contents
- `status` – Status of the certificate (`Active` or `Inactive`)
- `upload_date` – Timestamp when the certificate was uploaded
- `wami_arn` – WAMI ARN for cross-provider identification
- `providers` – List of cloud provider configurations

### `CertificateStatus`

Enum representing the status of a signing certificate:

- `Active` – Certificate is active and can be used
- `Inactive` – Certificate is inactive and cannot be used

## Builder Functions

### `build_signing_certificate`

Creates a new `SigningCertificate` with context-based identifiers:

```rust
use wami_core::context::WamiContext;
use wami_credentials::signing_certificate::builder::build_signing_certificate;

let context = WamiContext::builder()
    .instance_id("123456789012")
    .tenant_path(wami_core::arn::TenantPath::single(0))
    .caller_arn(/* ... */)
    .build()
    .unwrap();

let certificate = build_signing_certificate(
    "alice".into(),
    "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----".to_string(),
    &context,
)?;
```

## Request Types

The module provides request types for signing certificate operations:
- `UploadSigningCertificateRequest` – Request to upload a signing certificate
- `ListSigningCertificatesRequest` – Request to list signing certificates for a user
- `UpdateSigningCertificateRequest` – Request to update certificate status
- `DeleteSigningCertificateRequest` – Request to delete a signing certificate

## Usage Example

```rust
use wami_core::context::WamiContext;
use wami_credentials::signing_certificate::builder::build_signing_certificate;
use wami_credentials::signing_certificate::{SigningCertificate, CertificateStatus};

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

// Create a new signing certificate
let certificate_body = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----";
let certificate = build_signing_certificate(
    "alice".into(),
    certificate_body.to_string(),
    &context,
)?;

assert_eq!(certificate.user_name, "alice");
assert_eq!(certificate.status, CertificateStatus::Active);
assert!(certificate.wami_arn.to_string().contains("signing-certificate"));
```

