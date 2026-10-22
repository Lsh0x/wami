//! Signing Certificate Store Trait

use crate::credentials::signing_certificate::SigningCertificate;
use async_trait::async_trait;
use wami_core::arn::{ScopedName, TenantPath};
use wami_core::error::Result;

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

    /// List the signing certificates of exactly `tenant`, or only those of
    /// `owner` when given — never the whole store.
    async fn list_signing_certificates(
        &self,
        tenant: &TenantPath,
        owner: Option<&ScopedName>,
    ) -> Result<Vec<SigningCertificate>>;
}
