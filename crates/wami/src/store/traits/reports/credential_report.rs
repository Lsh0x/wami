//! Credential Report Store Trait

use crate::wami::reports::credential_report::CredentialReport;
use async_trait::async_trait;
use wami_core::error::Result;

/// Trait for credential report storage operations
#[async_trait]
pub trait CredentialReportStore: Send + Sync {
    async fn store_credential_report(&mut self, report: CredentialReport) -> Result<()>;

    async fn get_credential_report(&self) -> Result<Option<CredentialReport>>;
}
