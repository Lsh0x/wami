# Server Certificate Module

IAM server certificate resource management for WAMI. This module provides strongly
typed representations, builders, and request types for managing IAM server
certificates used for HTTPS connections.

## Overview

Server certificates are used to secure HTTPS connections in AWS services. This
module provides:

- **Model Types** – `ServerCertificate` and `ServerCertificateMetadata` for
  representing server certificate resources
- **Builder Functions** – Context-aware builders that generate consistent WAMI ARNs
- **Request Types** – DTOs for service API operations

## Models

### `ServerCertificate`

Represents a server certificate with the following fields:

- `server_certificate_metadata` – Metadata about the certificate
- `certificate_body` – PEM-encoded public key certificate
- `certificate_chain` – Optional PEM-encoded certificate chain
- `tags` – Tags associated with the certificate
- `wami_arn` – WAMI ARN for cross-provider identification
- `providers` – List of cloud provider configurations

### `ServerCertificateMetadata`

Contains metadata about the server certificate:

- `path` – Path to the server certificate
- `server_certificate_name` – Name of the certificate
- `arn` – AWS ARN of the certificate
- `server_certificate_id` – Unique identifier for the certificate
- `upload_date` – Timestamp when the certificate was uploaded
- `expiration` – Optional expiration date

## Builder Functions

### `build_server_certificate`

Creates a new `ServerCertificate` with context-based identifiers:

```rust
use wami_core::context::WamiContext;
use wami_credentials::build_server_certificate;

let context = WamiContext::builder()
    .instance_id("123456789012")
    .tenant_path(wami_core::arn::TenantPath::single(0))
    .caller_arn(/* ... */)
    .build()
    .unwrap();

let certificate = build_server_certificate(
    "my-cert".to_string(),
    "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----".to_string(),
    None, // certificate_chain
    "/".to_string(), // path
    Vec::new(), // tags
    &context,
)?;
```

## Request Types

The module provides request and response types for server certificate operations:
- `UploadServerCertificateRequest` – Request to upload a server certificate
- `UploadServerCertificateResponse` – Response containing the uploaded certificate metadata
- `GetServerCertificateRequest` – Request to retrieve a server certificate
- `GetServerCertificateResponse` – Response containing the server certificate
- `ListServerCertificatesRequest` – Request to list server certificates
- `ListServerCertificatesResponse` – Response containing a list of certificate metadata
- `DeleteServerCertificateRequest` – Request to delete a server certificate
- `UpdateServerCertificateRequest` – Request to update certificate metadata (name or path)

## Usage Example

```rust
use wami_core::context::WamiContext;
use wami_credentials::{build_server_certificate, ServerCertificate};

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

// Create a new server certificate
let certificate_body = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----";
let certificate = build_server_certificate(
    "my-cert".to_string(),
    certificate_body.to_string(),
    None,
    "/".to_string(),
    Vec::new(),
    &context,
)?;

assert_eq!(certificate.server_certificate_metadata.server_certificate_name, "my-cert");
assert!(certificate.wami_arn.to_string().contains("server-certificate"));
```

