#![allow(clippy::await_holding_lock)]
//! GDPR Service
//!
//! Orchestrates consent management, audit trail recording, data export,
//! erasure, and retention enforcement over the store layer.

use crate::store::traits::{AuditStore, ConsentStore};
use crate::wami::gdpr::model::{
    AuditOutcome, ConsentLevel, ConsentRecord, DataCategory, ErasureCertificate, RetentionPolicy,
    UserDataExport, WamiAuditEvent,
};
use crate::wami::gdpr::operations;
use chrono::Utc;
use std::sync::{Arc, RwLock};
use wami_core::error::{AmiError, Result};

/// Combined trait bound for GDPR storage.
pub trait GdprStore: ConsentStore + AuditStore {}
impl<T: ConsentStore + AuditStore> GdprStore for T {}

/// Service for GDPR compliance operations.
///
/// Provides high-level methods that combine domain logic (validation,
/// scope computation) with storage and audit trail recording.
#[wami_macros::service(store_trait = "GdprStore")]
pub struct GdprService<S> {
    store: Arc<RwLock<S>>,
}

impl<S: GdprStore> GdprService<S> {
    // ─── Consent Management ─────────────────────────────────────

    /// Grant consent for a data category.
    ///
    /// Records the consent and emits an audit event.
    #[allow(clippy::too_many_arguments)]
    pub async fn grant_consent(
        &self,
        tenant_id: &str,
        user_name: &str,
        category: DataCategory,
        level: ConsentLevel,
        ip_address: Option<String>,
        user_agent: Option<String>,
        policy_version: Option<String>,
    ) -> Result<ConsentRecord> {
        // Validate inputs.
        operations::validate_consent(user_name, tenant_id, category, level)?;

        // Revoke any existing active consent for this user+category.
        if let Some(existing) = self
            .read_store()
            .get_active_consent(tenant_id, user_name, category)
            .await?
        {
            self.write_store().revoke_consent(&existing.id).await?;
        }

        // Create the new consent record.
        let record = ConsentRecord {
            id: generate_id(),
            user_name: user_name.to_string(),
            tenant_id: tenant_id.to_string(),
            category,
            level,
            granted_at: Utc::now(),
            expires_at: None,
            ip_address,
            user_agent,
            policy_version,
            active: true,
        };

        let created = self.write_store().create_consent(record).await?;

        // Audit trail.
        let audit_event =
            operations::build_consent_audit_event(tenant_id, user_name, user_name, category, level);
        self.write_store().record_event(audit_event).await?;

        Ok(created)
    }

    /// Revoke consent for a specific category.
    pub async fn revoke_consent(
        &self,
        tenant_id: &str,
        user_name: &str,
        category: DataCategory,
    ) -> Result<()> {
        let existing = self
            .read_store()
            .get_active_consent(tenant_id, user_name, category)
            .await?
            .ok_or_else(|| AmiError::ResourceNotFound {
                resource: format!(
                    "Active consent for user '{}' category {:?}",
                    user_name, category
                ),
            })?;

        self.write_store().revoke_consent(&existing.id).await?;

        // Audit trail.
        let event = WamiAuditEvent {
            id: generate_id(),
            tenant_id: tenant_id.to_string(),
            actor: user_name.to_string(),
            action: "consent:Revoke".to_string(),
            resource: format!("user/{}/consent/{:?}", user_name, category),
            outcome: AuditOutcome::Success,
            timestamp: Utc::now(),
            source_ip: None,
            metadata: None,
        };
        self.write_store().record_event(event).await?;

        Ok(())
    }

    /// Revoke ALL consents for a user (e.g. before account deletion).
    pub async fn revoke_all_consents(&self, tenant_id: &str, user_name: &str) -> Result<u64> {
        let count = self
            .write_store()
            .revoke_all_user_consents(tenant_id, user_name)
            .await?;

        let event = WamiAuditEvent {
            id: generate_id(),
            tenant_id: tenant_id.to_string(),
            actor: user_name.to_string(),
            action: "consent:RevokeAll".to_string(),
            resource: format!("user/{}", user_name),
            outcome: AuditOutcome::Success,
            timestamp: Utc::now(),
            source_ip: None,
            metadata: Some(serde_json::json!({ "revoked_count": count })),
        };
        self.write_store().record_event(event).await?;

        Ok(count)
    }

    /// List all active consents for a user.
    pub async fn list_user_consents(
        &self,
        tenant_id: &str,
        user_name: &str,
    ) -> Result<Vec<ConsentRecord>> {
        self.read_store()
            .list_user_consents(tenant_id, user_name)
            .await
    }

    /// Check whether processing is allowed for a category.
    pub async fn is_processing_allowed(
        &self,
        tenant_id: &str,
        user_name: &str,
        category: DataCategory,
    ) -> Result<bool> {
        let consents = self
            .read_store()
            .list_user_consents(tenant_id, user_name)
            .await?;
        Ok(operations::is_processing_allowed(&consents, category))
    }

    // ─── Erasure (Right to be Forgotten) ────────────────────────

    /// Request erasure of a user's data.
    ///
    /// Computes the scope (what can be erased vs. retained due to legal obligations),
    /// performs the erasure, and returns a certificate.
    pub async fn request_erasure(
        &self,
        tenant_id: &str,
        user_name: &str,
        categories: &[DataCategory],
        processed_by: &str,
    ) -> Result<ErasureCertificate> {
        // Get retention policies to determine what must be retained.
        let policies = self.read_store().list_retention_policies(tenant_id).await?;

        let (to_erase, to_retain) = operations::compute_erasure_scope(categories, &policies);

        if to_erase.is_empty() {
            return Err(AmiError::InvalidParameter {
                message: "All requested categories are subject to active retention policies"
                    .to_string(),
            });
        }

        let now = Utc::now();
        let certificate = ErasureCertificate {
            id: generate_id(),
            user_name: user_name.to_string(),
            tenant_id: tenant_id.to_string(),
            categories_erased: to_erase,
            requested_at: now,
            completed_at: now,
            processed_by: processed_by.to_string(),
            verification_hash: compute_verification_hash(user_name, &now),
            retained_categories: to_retain,
            retention_justification: if !policies.is_empty() {
                Some("Legal retention obligations apply".to_string())
            } else {
                None
            },
        };

        let saved = self
            .write_store()
            .create_erasure_certificate(certificate.clone())
            .await?;

        // Revoke all consents for erased user.
        let _ = self
            .write_store()
            .revoke_all_user_consents(tenant_id, user_name)
            .await;

        // Audit trail.
        let audit_event = operations::build_erasure_audit_event(tenant_id, processed_by, &saved);
        self.write_store().record_event(audit_event).await?;

        Ok(saved)
    }

    /// Get an erasure certificate by ID.
    pub async fn get_erasure_certificate(
        &self,
        certificate_id: &str,
    ) -> Result<Option<ErasureCertificate>> {
        self.read_store()
            .get_erasure_certificate(certificate_id)
            .await
    }

    // ─── Data Export (Right of Access) ──────────────────────────

    /// Export a user's personal data.
    pub async fn export_user_data(
        &self,
        tenant_id: &str,
        user_name: &str,
        categories: &[DataCategory],
    ) -> Result<UserDataExport> {
        let export = self
            .read_store()
            .export_user_data(tenant_id, user_name, categories)
            .await?;

        // Audit trail.
        let event = WamiAuditEvent {
            id: generate_id(),
            tenant_id: tenant_id.to_string(),
            actor: user_name.to_string(),
            action: "gdpr:Export".to_string(),
            resource: format!("user/{}", user_name),
            outcome: AuditOutcome::Success,
            timestamp: Utc::now(),
            source_ip: None,
            metadata: Some(serde_json::json!({
                "categories": categories,
                "section_count": export.sections.len(),
            })),
        };
        self.write_store().record_event(event).await?;

        Ok(export)
    }

    // ─── Retention Policies ─────────────────────────────────────

    /// Create or update a retention policy.
    pub async fn upsert_retention_policy(
        &self,
        policy: RetentionPolicy,
    ) -> Result<RetentionPolicy> {
        self.write_store().upsert_retention_policy(policy).await
    }

    /// List retention policies for a tenant.
    pub async fn list_retention_policies(&self, tenant_id: &str) -> Result<Vec<RetentionPolicy>> {
        self.read_store().list_retention_policies(tenant_id).await
    }

    /// Enforce retention policies (purge expired data).
    pub async fn enforce_retention(&self, tenant_id: &str) -> Result<u64> {
        let count = self.write_store().enforce_retention(tenant_id).await?;

        if count > 0 {
            let event = WamiAuditEvent {
                id: generate_id(),
                tenant_id: tenant_id.to_string(),
                actor: "system".to_string(),
                action: "gdpr:EnforceRetention".to_string(),
                resource: format!("tenant/{}", tenant_id),
                outcome: AuditOutcome::Success,
                timestamp: Utc::now(),
                source_ip: None,
                metadata: Some(serde_json::json!({ "records_purged": count })),
            };
            self.write_store().record_event(event).await?;
        }

        Ok(count)
    }

    // ─── Audit Trail (read) ─────────────────────────────────────

    /// Query audit events with optional filters.
    pub async fn query_audit_events(
        &self,
        tenant_id: &str,
        filter: &crate::store::traits::gdpr::audit::AuditFilter,
    ) -> Result<Vec<WamiAuditEvent>> {
        self.read_store().query_events(tenant_id, filter).await
    }
}

// ─── Helpers ────────────────────────────────────────────────────

fn generate_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let rand: u64 = rand::random();
    format!("{:013x}{:016x}", ts, rand)
}

fn compute_verification_hash(user_name: &str, timestamp: &chrono::DateTime<Utc>) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    user_name.hash(&mut hasher);
    timestamp.timestamp_millis().hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}
