//! Service-Specific Credential Store Implementation for InMemoryWamiStore

use crate::credentials::service_credential::ServiceSpecificCredential;
use crate::store::memory::InMemoryWamiStore;
use crate::store::traits::ServiceCredentialStore;
use async_trait::async_trait;
use wami_core::arn::{ScopedName, TenantPath};
use wami_core::error::Result;

#[async_trait]
impl ServiceCredentialStore for InMemoryWamiStore {
    async fn create_service_specific_credential(
        &mut self,
        credential: ServiceSpecificCredential,
    ) -> Result<ServiceSpecificCredential> {
        self.service_specific_credentials.insert(
            credential.service_specific_credential_id.clone(),
            credential.clone(),
        );
        Ok(credential)
    }

    async fn get_service_specific_credential(
        &self,
        credential_id: &str,
    ) -> Result<Option<ServiceSpecificCredential>> {
        Ok(self
            .service_specific_credentials
            .get(credential_id)
            .cloned())
    }

    async fn update_service_specific_credential(
        &mut self,
        credential: ServiceSpecificCredential,
    ) -> Result<ServiceSpecificCredential> {
        self.service_specific_credentials.insert(
            credential.service_specific_credential_id.clone(),
            credential.clone(),
        );
        Ok(credential)
    }

    async fn delete_service_specific_credential(
        &mut self,
        service_specific_credential_id: &str,
    ) -> Result<()> {
        self.service_specific_credentials
            .remove(service_specific_credential_id);
        Ok(())
    }

    async fn list_service_specific_credentials(
        &self,
        tenant: &TenantPath,
        owner: Option<&ScopedName>,
    ) -> Result<Vec<ServiceSpecificCredential>> {
        let creds: Vec<ServiceSpecificCredential> = self
            .service_specific_credentials
            .values()
            .filter(|cred| cred.owner.tenant() == tenant)
            .filter(|cred| owner.is_none_or(|owner| &cred.owner == owner))
            .cloned()
            .collect();
        Ok(creds)
    }
}
