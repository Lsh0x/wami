//! Consent Store Trait
//!
//! Storage operations for GDPR consent records, erasure certificates,
//! data export, and retention policies.

use crate::wami::gdpr::{
    ConsentRecord, DataCategory, ErasureCertificate, RetentionPolicy, UserDataExport,
};
use async_trait::async_trait;
use wami_core::error::Result;

/// Store trait for GDPR consent and data rights operations.
#[async_trait]
pub trait ConsentStore: Send + Sync {
    // ─── Consent CRUD ───────────────────────────────────────────

    /// Record a new consent decision.
    async fn create_consent(&mut self, record: ConsentRecord) -> Result<ConsentRecord>;

    /// Get a specific consent record by ID.
    async fn get_consent(&self, consent_id: &str) -> Result<Option<ConsentRecord>>;

    /// Get the active consent for a user + category (latest non-expired).
    async fn get_active_consent(
        &self,
        tenant_id: &str,
        user_name: &str,
        category: DataCategory,
    ) -> Result<Option<ConsentRecord>>;

    /// List all consent records for a user within a tenant.
    async fn list_user_consents(
        &self,
        tenant_id: &str,
        user_name: &str,
    ) -> Result<Vec<ConsentRecord>>;

    /// Revoke (deactivate) a consent record.
    async fn revoke_consent(&mut self, consent_id: &str) -> Result<()>;

    /// Revoke all consents for a user within a tenant.
    async fn revoke_all_user_consents(&mut self, tenant_id: &str, user_name: &str) -> Result<u64>;

    // ─── Erasure ────────────────────────────────────────────────

    /// Store an erasure certificate after data deletion.
    async fn create_erasure_certificate(
        &mut self,
        certificate: ErasureCertificate,
    ) -> Result<ErasureCertificate>;

    /// Get an erasure certificate by ID.
    async fn get_erasure_certificate(
        &self,
        certificate_id: &str,
    ) -> Result<Option<ErasureCertificate>>;

    /// List erasure certificates for a user.
    async fn list_user_erasure_certificates(
        &self,
        tenant_id: &str,
        user_name: &str,
    ) -> Result<Vec<ErasureCertificate>>;

    // ─── Data Export ────────────────────────────────────────────

    /// Generate a data export for a user (right of access).
    /// The implementation should gather data from all relevant sources.
    async fn export_user_data(
        &self,
        tenant_id: &str,
        user_name: &str,
        categories: &[DataCategory],
    ) -> Result<UserDataExport>;

    // ─── Retention Policies ─────────────────────────────────────

    /// Create or update a retention policy for a category.
    async fn upsert_retention_policy(&mut self, policy: RetentionPolicy)
        -> Result<RetentionPolicy>;

    /// Get the retention policy for a specific category in a tenant.
    async fn get_retention_policy(
        &self,
        tenant_id: &str,
        category: DataCategory,
    ) -> Result<Option<RetentionPolicy>>;

    /// List all retention policies for a tenant.
    async fn list_retention_policies(&self, tenant_id: &str) -> Result<Vec<RetentionPolicy>>;

    /// Delete a retention policy.
    async fn delete_retention_policy(&mut self, policy_id: &str) -> Result<()>;

    /// Enforce retention: purge data older than the policy allows.
    /// Returns the number of records purged.
    async fn enforce_retention(&mut self, tenant_id: &str) -> Result<u64>;
}
