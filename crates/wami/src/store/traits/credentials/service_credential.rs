//! Service-Specific Credential Store Trait

use crate::credentials::service_credential::ServiceSpecificCredential;
use async_trait::async_trait;
use wami_core::arn::{ScopedName, TenantPath};
use wami_core::error::Result;

/// Trait for service-specific credential storage operations
#[async_trait]
pub trait ServiceCredentialStore: Send + Sync {
    async fn create_service_specific_credential(
        &mut self,
        credential: ServiceSpecificCredential,
    ) -> Result<ServiceSpecificCredential>;

    async fn get_service_specific_credential(
        &self,
        credential_id: &str,
    ) -> Result<Option<ServiceSpecificCredential>>;

    async fn update_service_specific_credential(
        &mut self,
        credential: ServiceSpecificCredential,
    ) -> Result<ServiceSpecificCredential>;

    async fn delete_service_specific_credential(
        &mut self,
        service_specific_credential_id: &str,
    ) -> Result<()>;

    /// List the service-specific credentials of exactly `tenant`, or only
    /// those of `owner` when given — never the whole store.
    async fn list_service_specific_credentials(
        &self,
        tenant: &TenantPath,
        owner: Option<&ScopedName>,
    ) -> Result<Vec<ServiceSpecificCredential>>;
}
