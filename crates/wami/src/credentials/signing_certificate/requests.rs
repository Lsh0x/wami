//! Signing Certificate Request and Response Types

use crate::arn::ScopedName;
use crate::arn::TenantPath;
use serde::{Deserialize, Serialize};

use super::model::*;

/// Request to upload a signing certificate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadSigningCertificateRequest {
    /// The user — its tenant and its name
    #[serde(rename = "User")]
    pub user: ScopedName,

    /// The contents of the signing certificate (PEM-encoded X.509 certificate)
    #[serde(rename = "CertificateBody")]
    pub certificate_body: String,
}

/// Response from uploading a signing certificate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadSigningCertificateResponse {
    /// Information about the uploaded signing certificate
    #[serde(rename = "Certificate")]
    pub certificate: SigningCertificate,
}

/// Request to delete a signing certificate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteSigningCertificateRequest {
    /// The user — its tenant and its name
    #[serde(rename = "User")]
    pub user: ScopedName,

    /// The ID of the signing certificate to delete
    #[serde(rename = "CertificateId")]
    pub certificate_id: String,
}

/// Request to list signing certificates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListSigningCertificatesRequest {
    /// The tenant to list — exactly this one: never its children, never the
    /// whole store (wami 005).
    pub tenant: TenantPath,

    /// Only this user's certificates; its tenant must be `tenant`. All of the
    /// tenant's when absent.
    #[serde(rename = "User", skip_serializing_if = "Option::is_none")]
    pub user: Option<ScopedName>,
}

/// Response from listing signing certificates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListSigningCertificatesResponse {
    /// List of signing certificates
    #[serde(rename = "Certificates")]
    pub certificates: Vec<SigningCertificate>,

    /// Whether the results are truncated
    #[serde(rename = "IsTruncated")]
    pub is_truncated: bool,

    /// Marker for pagination
    #[serde(rename = "Marker", skip_serializing_if = "Option::is_none")]
    pub marker: Option<String>,
}

/// Request to update a signing certificate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSigningCertificateRequest {
    /// The user — its tenant and its name
    #[serde(rename = "User")]
    pub user: ScopedName,

    /// The ID of the signing certificate to update
    #[serde(rename = "CertificateId")]
    pub certificate_id: String,

    /// The new status for the signing certificate
    #[serde(rename = "Status")]
    pub status: CertificateStatus,
}
