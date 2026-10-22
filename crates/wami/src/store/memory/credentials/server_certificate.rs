//! Server Certificate Store Implementation for InMemoryWamiStore

use crate::credentials::server_certificate::ServerCertificateMetadata;
use crate::credentials::ServerCertificate;
use crate::store::memory::InMemoryWamiStore;
use crate::store::traits::ServerCertificateStore;
use async_trait::async_trait;
use wami_core::arn::{ScopedName, TenantPath};
use wami_core::error::{AmiError, Result};
use wami_core::types::PaginationParams;

#[async_trait]
impl ServerCertificateStore for InMemoryWamiStore {
    async fn create_server_certificate(
        &mut self,
        certificate: ServerCertificate,
    ) -> Result<ServerCertificateMetadata> {
        let key = certificate.key();
        // Keyed by tenant and name: two tenants may each hold a `web`, and a
        // second upload under a held key is refused rather than replacing it.
        if self.server_certificates.contains_key(&key) {
            return Err(AmiError::ResourceExists {
                resource: format!("server certificate {key}"),
            });
        }
        let metadata = certificate.server_certificate_metadata.clone();
        self.server_certificates.insert(key, certificate);
        Ok(metadata)
    }

    async fn get_server_certificate(
        &self,
        key: &ScopedName,
    ) -> Result<Option<ServerCertificateMetadata>> {
        Ok(self
            .server_certificates
            .get(key)
            .map(|cert| cert.server_certificate_metadata.clone()))
    }

    /// Found by `server_certificate_id`, the one stable identifier the
    /// metadata carries; a rename moves it to its new key in its own tenant.
    async fn update_server_certificate(
        &mut self,
        certificate: ServerCertificateMetadata,
    ) -> Result<ServerCertificateMetadata> {
        let old = self
            .server_certificates
            .iter()
            .find(|(_, held)| {
                held.server_certificate_metadata.server_certificate_id
                    == certificate.server_certificate_id
            })
            .map(|(key, _)| key.clone())
            .ok_or_else(|| AmiError::ResourceNotFound {
                resource: format!(
                    "server certificate with id {}",
                    certificate.server_certificate_id
                ),
            })?;
        let key = old.renamed(&certificate.server_certificate_name);
        if key != old && self.server_certificates.contains_key(&key) {
            return Err(AmiError::ResourceExists {
                resource: format!("server certificate {key}"),
            });
        }
        let mut held = self
            .server_certificates
            .remove(&old)
            .expect("found just above under the same lock");
        held.server_certificate_metadata = certificate.clone();
        self.server_certificates.insert(key, held);
        Ok(certificate)
    }

    async fn delete_server_certificate(&mut self, key: &ScopedName) -> Result<()> {
        self.server_certificates.remove(key);
        Ok(())
    }

    async fn list_server_certificates(
        &self,
        tenant: &TenantPath,
        path_prefix: Option<&str>,
        _pagination: Option<&PaginationParams>,
    ) -> Result<(Vec<ServerCertificateMetadata>, bool, Option<String>)> {
        let certs: Vec<ServerCertificateMetadata> = self
            .server_certificates
            .iter()
            .filter(|(key, _)| key.tenant() == tenant)
            .filter(|(_, cert)| {
                path_prefix
                    .is_none_or(|prefix| cert.server_certificate_metadata.path.starts_with(prefix))
            })
            .map(|(_, cert)| cert.server_certificate_metadata.clone())
            .collect();
        Ok((certs, false, None))
    }
}
