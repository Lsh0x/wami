//! Server Certificate Store Trait

use crate::credentials::server_certificate::ServerCertificateMetadata;
use crate::credentials::ServerCertificate;
use async_trait::async_trait;
use wami_core::arn::{ScopedName, TenantPath};
use wami_core::error::Result;
use wami_core::types::PaginationParams;

/// Trait for server certificate storage operations
#[async_trait]
pub trait ServerCertificateStore: Send + Sync {
    async fn create_server_certificate(
        &mut self,
        certificate: ServerCertificate,
    ) -> Result<ServerCertificateMetadata>;

    /// The certificate stored under `key` — its tenant and its name.
    async fn get_server_certificate(
        &self,
        key: &ScopedName,
    ) -> Result<Option<ServerCertificateMetadata>>;

    async fn update_server_certificate(
        &mut self,
        certificate: ServerCertificateMetadata,
    ) -> Result<ServerCertificateMetadata>;

    /// Delete the certificate stored under `key`.
    async fn delete_server_certificate(&mut self, key: &ScopedName) -> Result<()>;

    /// List the certificates of exactly `tenant`.
    async fn list_server_certificates(
        &self,
        tenant: &TenantPath,
        path_prefix: Option<&str>,
        pagination: Option<&PaginationParams>,
    ) -> Result<(Vec<ServerCertificateMetadata>, bool, Option<String>)>;
}
