//! Signing Certificate Store Trait

use async_trait::async_trait;
use wami_core::error::Result;
use wami_credentials::signing_certificate::SigningCertificate;

/// Trait for signing certificate storage operations
#[async_trait]
pub trait SigningCertificateStore: Send + Sync {
    async fn create_signing_certificate(
        &mut self,
        certificate: SigningCertificate,
    ) -> Result<SigningCertificate>;

    async fn get_signing_certificate(
        &self,
        certificate_id: &str,
    ) -> Result<Option<SigningCertificate>>;

    async fn update_signing_certificate(
        &mut self,
        certificate: SigningCertificate,
    ) -> Result<SigningCertificate>;

    async fn delete_signing_certificate(&mut self, certificate_id: &str) -> Result<()>;

    async fn list_signing_certificates(
        &self,
        user_name: Option<&str>,
    ) -> Result<Vec<SigningCertificate>>;
}
