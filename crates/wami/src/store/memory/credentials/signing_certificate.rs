//! Signing Certificate Store Implementation for InMemoryWamiStore

use crate::credentials::signing_certificate::SigningCertificate;
use crate::store::memory::InMemoryWamiStore;
use crate::store::traits::SigningCertificateStore;
use async_trait::async_trait;
use wami_core::arn::{ScopedName, TenantPath};
use wami_core::error::Result;

#[async_trait]
impl SigningCertificateStore for InMemoryWamiStore {
    async fn create_signing_certificate(
        &mut self,
        certificate: SigningCertificate,
    ) -> Result<SigningCertificate> {
        self.signing_certificates
            .insert(certificate.certificate_id.clone(), certificate.clone());
        Ok(certificate)
    }

    async fn get_signing_certificate(
        &self,
        certificate_id: &str,
    ) -> Result<Option<SigningCertificate>> {
        Ok(self.signing_certificates.get(certificate_id).cloned())
    }

    async fn update_signing_certificate(
        &mut self,
        certificate: SigningCertificate,
    ) -> Result<SigningCertificate> {
        self.signing_certificates
            .insert(certificate.certificate_id.clone(), certificate.clone());
        Ok(certificate)
    }

    async fn delete_signing_certificate(&mut self, certificate_id: &str) -> Result<()> {
        self.signing_certificates.remove(certificate_id);
        Ok(())
    }

    async fn list_signing_certificates(
        &self,
        tenant: &TenantPath,
        owner: Option<&ScopedName>,
    ) -> Result<Vec<SigningCertificate>> {
        let certs: Vec<SigningCertificate> = self
            .signing_certificates
            .values()
            .filter(|cert| cert.owner.tenant() == tenant)
            .filter(|cert| owner.is_none_or(|owner| &cert.owner == owner))
            .cloned()
            .collect();
        Ok(certs)
    }
}
