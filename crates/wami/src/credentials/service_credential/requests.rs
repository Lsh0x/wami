//! Service Credential Request and Response Types

use crate::arn::ScopedName;
use crate::arn::TenantPath;
use serde::{Deserialize, Serialize};

use super::model::*;

/// Request to create a service-specific credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateServiceSpecificCredentialRequest {
    /// The user — its tenant and its name
    #[serde(rename = "User")]
    pub user: ScopedName,

    /// The name of the AWS service (e.g., "codecommit.amazonaws.com")
    #[serde(rename = "ServiceName")]
    pub service_name: String,
}

/// Response from creating a service-specific credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateServiceSpecificCredentialResponse {
    /// The created credential with password
    #[serde(rename = "ServiceSpecificCredential")]
    pub service_specific_credential: ServiceSpecificCredential,
}

/// Request to delete a service-specific credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteServiceSpecificCredentialRequest {
    /// The user — its tenant and its name
    #[serde(rename = "User")]
    pub user: ScopedName,

    /// The unique identifier of the credential
    #[serde(rename = "ServiceSpecificCredentialId")]
    pub service_specific_credential_id: String,
}

/// Request to list service-specific credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListServiceSpecificCredentialsRequest {
    /// The tenant to list — exactly this one: never its children, never the
    /// whole store (wami 005).
    pub tenant: TenantPath,

    /// Only this user's credentials; its tenant must be `tenant`. All of the
    /// tenant's when absent.
    #[serde(rename = "User", skip_serializing_if = "Option::is_none")]
    pub user: Option<ScopedName>,

    /// Filter by service name (optional)
    #[serde(rename = "ServiceName", skip_serializing_if = "Option::is_none")]
    pub service_name: Option<String>,
}

/// Response from listing service-specific credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListServiceSpecificCredentialsResponse {
    /// List of credential metadata
    #[serde(rename = "ServiceSpecificCredentials")]
    pub service_specific_credentials: Vec<ServiceSpecificCredentialMetadata>,
}

/// Request to reset a service-specific credential password
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResetServiceSpecificCredentialRequest {
    /// The user — its tenant and its name
    #[serde(rename = "User")]
    pub user: ScopedName,

    /// The unique identifier of the credential
    #[serde(rename = "ServiceSpecificCredentialId")]
    pub service_specific_credential_id: String,
}

/// Response from resetting a service-specific credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResetServiceSpecificCredentialResponse {
    /// The credential with new password
    #[serde(rename = "ServiceSpecificCredential")]
    pub service_specific_credential: ServiceSpecificCredential,
}

/// Request to update a service-specific credential status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateServiceSpecificCredentialRequest {
    /// The user — its tenant and its name
    #[serde(rename = "User")]
    pub user: ScopedName,

    /// The unique identifier of the credential
    #[serde(rename = "ServiceSpecificCredentialId")]
    pub service_specific_credential_id: String,

    /// The new status (Active or Inactive)
    #[serde(rename = "Status")]
    pub status: String,
}
