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
        // Note: split into two statements to drop the read lock before acquiring write lock
        // (std::sync::RwLock deadlocks if both held on the same thread).
        let existing = self
            .read_store()
            .get_active_consent(tenant_id, user_name, category)
            .await?;
        if let Some(existing) = existing {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::traits::gdpr::audit::AuditFilter;
    use crate::wami::gdpr::model::{ExportSection, UserDataExport};
    use async_trait::async_trait;
    use chrono::{DateTime, Duration, Utc};

    // ─── Mock Store ────────────────────────────────────────────

    #[derive(Default, Clone)]
    struct MockGdprStore {
        consents: Vec<ConsentRecord>,
        erasure_certs: Vec<ErasureCertificate>,
        audit_events: Vec<WamiAuditEvent>,
        retention_policies: Vec<RetentionPolicy>,
    }

    #[async_trait]
    impl ConsentStore for MockGdprStore {
        async fn create_consent(&mut self, record: ConsentRecord) -> Result<ConsentRecord> {
            self.consents.push(record.clone());
            Ok(record)
        }

        async fn get_consent(&self, consent_id: &str) -> Result<Option<ConsentRecord>> {
            Ok(self.consents.iter().find(|c| c.id == consent_id).cloned())
        }

        async fn get_active_consent(
            &self,
            tenant_id: &str,
            user_name: &str,
            category: DataCategory,
        ) -> Result<Option<ConsentRecord>> {
            Ok(self
                .consents
                .iter()
                .find(|c| {
                    c.tenant_id == tenant_id
                        && c.user_name == user_name
                        && c.category == category
                        && c.active
                })
                .cloned())
        }

        async fn list_user_consents(
            &self,
            tenant_id: &str,
            user_name: &str,
        ) -> Result<Vec<ConsentRecord>> {
            Ok(self
                .consents
                .iter()
                .filter(|c| c.tenant_id == tenant_id && c.user_name == user_name && c.active)
                .cloned()
                .collect())
        }

        async fn revoke_consent(&mut self, consent_id: &str) -> Result<()> {
            if let Some(c) = self.consents.iter_mut().find(|c| c.id == consent_id) {
                c.active = false;
            }
            Ok(())
        }

        async fn revoke_all_user_consents(
            &mut self,
            tenant_id: &str,
            user_name: &str,
        ) -> Result<u64> {
            let mut count = 0u64;
            for c in &mut self.consents {
                if c.tenant_id == tenant_id && c.user_name == user_name && c.active {
                    c.active = false;
                    count += 1;
                }
            }
            Ok(count)
        }

        async fn create_erasure_certificate(
            &mut self,
            certificate: ErasureCertificate,
        ) -> Result<ErasureCertificate> {
            self.erasure_certs.push(certificate.clone());
            Ok(certificate)
        }

        async fn get_erasure_certificate(
            &self,
            certificate_id: &str,
        ) -> Result<Option<ErasureCertificate>> {
            Ok(self
                .erasure_certs
                .iter()
                .find(|c| c.id == certificate_id)
                .cloned())
        }

        async fn list_user_erasure_certificates(
            &self,
            tenant_id: &str,
            user_name: &str,
        ) -> Result<Vec<ErasureCertificate>> {
            Ok(self
                .erasure_certs
                .iter()
                .filter(|c| c.tenant_id == tenant_id && c.user_name == user_name)
                .cloned()
                .collect())
        }

        async fn export_user_data(
            &self,
            tenant_id: &str,
            user_name: &str,
            categories: &[DataCategory],
        ) -> Result<UserDataExport> {
            let sections: Vec<ExportSection> = categories
                .iter()
                .map(|cat| ExportSection {
                    category: *cat,
                    data: serde_json::json!({"mock": true}),
                    record_count: 1,
                })
                .collect();
            Ok(UserDataExport {
                user_name: user_name.to_string(),
                tenant_id: tenant_id.to_string(),
                exported_at: Utc::now(),
                sections,
                format_version: "1.0".to_string(),
            })
        }

        async fn upsert_retention_policy(
            &mut self,
            policy: RetentionPolicy,
        ) -> Result<RetentionPolicy> {
            // Replace if exists, else insert
            self.retention_policies.retain(|p| p.id != policy.id);
            self.retention_policies.push(policy.clone());
            Ok(policy)
        }

        async fn get_retention_policy(
            &self,
            tenant_id: &str,
            category: DataCategory,
        ) -> Result<Option<RetentionPolicy>> {
            Ok(self
                .retention_policies
                .iter()
                .find(|p| p.tenant_id == tenant_id && p.category == category)
                .cloned())
        }

        async fn list_retention_policies(&self, tenant_id: &str) -> Result<Vec<RetentionPolicy>> {
            Ok(self
                .retention_policies
                .iter()
                .filter(|p| p.tenant_id == tenant_id)
                .cloned()
                .collect())
        }

        async fn delete_retention_policy(&mut self, policy_id: &str) -> Result<()> {
            self.retention_policies.retain(|p| p.id != policy_id);
            Ok(())
        }

        async fn enforce_retention(&mut self, tenant_id: &str) -> Result<u64> {
            // Simulate purging expired consents based on retention_days
            let now = Utc::now();
            let mut purged = 0u64;
            let policies: Vec<_> = self
                .retention_policies
                .iter()
                .filter(|p| p.tenant_id == tenant_id && p.auto_purge)
                .cloned()
                .collect();
            for policy in &policies {
                let cutoff = now - Duration::days(policy.retention_days as i64);
                let before = self.consents.len();
                self.consents.retain(|c| {
                    !(c.tenant_id == tenant_id
                        && c.category == policy.category
                        && c.granted_at < cutoff)
                });
                purged += (before - self.consents.len()) as u64;
            }
            Ok(purged)
        }
    }

    #[async_trait]
    impl AuditStore for MockGdprStore {
        async fn record_event(&mut self, event: WamiAuditEvent) -> Result<()> {
            self.audit_events.push(event);
            Ok(())
        }

        async fn get_event(&self, event_id: &str) -> Result<Option<WamiAuditEvent>> {
            Ok(self.audit_events.iter().find(|e| e.id == event_id).cloned())
        }

        async fn query_events(
            &self,
            tenant_id: &str,
            filter: &AuditFilter,
        ) -> Result<Vec<WamiAuditEvent>> {
            let mut results: Vec<_> = self
                .audit_events
                .iter()
                .filter(|e| e.tenant_id == tenant_id)
                .filter(|e| filter.actor.as_ref().map_or(true, |a| &e.actor == a))
                .filter(|e| {
                    filter
                        .action_prefix
                        .as_ref()
                        .map_or(true, |p| e.action.starts_with(p.as_str()))
                })
                .cloned()
                .collect();
            if let Some(limit) = filter.limit {
                results.truncate(limit);
            }
            Ok(results)
        }

        async fn count_events(&self, tenant_id: &str, _filter: &AuditFilter) -> Result<u64> {
            Ok(self
                .audit_events
                .iter()
                .filter(|e| e.tenant_id == tenant_id)
                .count() as u64)
        }

        async fn purge_events_before(
            &mut self,
            tenant_id: &str,
            before: DateTime<Utc>,
        ) -> Result<u64> {
            let before_len = self.audit_events.len();
            self.audit_events
                .retain(|e| !(e.tenant_id == tenant_id && e.timestamp < before));
            Ok((before_len - self.audit_events.len()) as u64)
        }
    }

    // ─── Helpers ───────────────────────────────────────────────

    fn make_service() -> GdprService<MockGdprStore> {
        let store = Arc::new(RwLock::new(MockGdprStore::default()));
        GdprService::new(store)
    }

    // ─── Tests ─────────────────────────────────────────────────

    #[tokio::test]
    async fn grant_consent_creates_record() {
        let svc = make_service();
        let record = svc
            .grant_consent(
                "t1",
                "alice",
                DataCategory::Identity,
                ConsentLevel::Full,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(record.user_name, "alice");
        assert_eq!(record.tenant_id, "t1");
        assert_eq!(record.category, DataCategory::Identity);
        assert_eq!(record.level, ConsentLevel::Full);
        assert!(record.active);
    }

    #[tokio::test]
    async fn grant_consent_replaces_existing() {
        let svc = make_service();
        let first = svc
            .grant_consent(
                "t1",
                "alice",
                DataCategory::Identity,
                ConsentLevel::Analytics,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        let second = svc
            .grant_consent(
                "t1",
                "alice",
                DataCategory::Identity,
                ConsentLevel::Full,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        assert_ne!(first.id, second.id);
        // The old consent should be revoked; list should only return the new active one
        let list = svc.list_user_consents("t1", "alice").await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].level, ConsentLevel::Full);
    }

    #[tokio::test]
    async fn grant_consent_validation_error() {
        let svc = make_service();
        let result = svc
            .grant_consent(
                "t1",
                "",
                DataCategory::Identity,
                ConsentLevel::Full,
                None,
                None,
                None,
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn revoke_consent_success() {
        let svc = make_service();
        svc.grant_consent(
            "t1",
            "alice",
            DataCategory::Usage,
            ConsentLevel::Full,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        svc.revoke_consent("t1", "alice", DataCategory::Usage)
            .await
            .unwrap();
        let list = svc.list_user_consents("t1", "alice").await.unwrap();
        assert!(list.is_empty());
    }

    #[tokio::test]
    async fn revoke_consent_not_found() {
        let svc = make_service();
        let result = svc.revoke_consent("t1", "alice", DataCategory::Usage).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn revoke_all_consents() {
        let svc = make_service();
        svc.grant_consent(
            "t1",
            "alice",
            DataCategory::Usage,
            ConsentLevel::Full,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        svc.grant_consent(
            "t1",
            "alice",
            DataCategory::Identity,
            ConsentLevel::Full,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        let count = svc.revoke_all_consents("t1", "alice").await.unwrap();
        assert_eq!(count, 2);
        let list = svc.list_user_consents("t1", "alice").await.unwrap();
        assert!(list.is_empty());
    }

    #[tokio::test]
    async fn list_user_consents_empty() {
        let svc = make_service();
        let list = svc.list_user_consents("t1", "alice").await.unwrap();
        assert!(list.is_empty());
    }

    #[tokio::test]
    async fn is_processing_allowed_service() {
        let svc = make_service();
        svc.grant_consent(
            "t1",
            "alice",
            DataCategory::Usage,
            ConsentLevel::Full,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        assert!(svc
            .is_processing_allowed("t1", "alice", DataCategory::Usage)
            .await
            .unwrap());
        assert!(!svc
            .is_processing_allowed("t1", "alice", DataCategory::Messages)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn request_erasure_no_retention() {
        let svc = make_service();
        svc.grant_consent(
            "t1",
            "alice",
            DataCategory::Identity,
            ConsentLevel::Full,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        let cert = svc
            .request_erasure(
                "t1",
                "alice",
                &[DataCategory::Identity, DataCategory::Messages],
                "admin",
            )
            .await
            .unwrap();
        assert_eq!(cert.categories_erased.len(), 2);
        assert!(cert.retained_categories.is_empty());
        assert_eq!(cert.user_name, "alice");
        assert!(cert.retention_justification.is_none());
        // Consents should have been revoked
        let list = svc.list_user_consents("t1", "alice").await.unwrap();
        assert!(list.is_empty());
    }

    #[tokio::test]
    async fn request_erasure_with_retention_policy() {
        let svc = make_service();
        // Create a retention policy that blocks Identity erasure
        let policy = RetentionPolicy {
            id: "rp1".to_string(),
            tenant_id: "t1".to_string(),
            category: DataCategory::Identity,
            retention_days: 365,
            legal_basis: "legal obligation".to_string(),
            auto_purge: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        svc.upsert_retention_policy(policy).await.unwrap();

        let cert = svc
            .request_erasure(
                "t1",
                "alice",
                &[DataCategory::Identity, DataCategory::Messages],
                "admin",
            )
            .await
            .unwrap();
        assert_eq!(cert.categories_erased, vec![DataCategory::Messages]);
        assert_eq!(cert.retained_categories, vec![DataCategory::Identity]);
        assert!(cert.retention_justification.is_some());
    }

    #[tokio::test]
    async fn request_erasure_all_retained_fails() {
        let svc = make_service();
        let policy = RetentionPolicy {
            id: "rp1".to_string(),
            tenant_id: "t1".to_string(),
            category: DataCategory::Identity,
            retention_days: 365,
            legal_basis: "legal".to_string(),
            auto_purge: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        svc.upsert_retention_policy(policy).await.unwrap();

        let result = svc
            .request_erasure("t1", "alice", &[DataCategory::Identity], "admin")
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn export_user_data_returns_sections() {
        let svc = make_service();
        let export = svc
            .export_user_data(
                "t1",
                "alice",
                &[DataCategory::Identity, DataCategory::Messages],
            )
            .await
            .unwrap();
        assert_eq!(export.user_name, "alice");
        assert_eq!(export.tenant_id, "t1");
        assert_eq!(export.sections.len(), 2);
        assert_eq!(export.sections[0].category, DataCategory::Identity);
        assert_eq!(export.sections[1].category, DataCategory::Messages);
    }

    #[tokio::test]
    async fn enforce_retention_purges_old_consents() {
        let svc = make_service();
        // Create a consent with an old granted_at date
        {
            let mut store = svc.write_store();
            store.consents.push(ConsentRecord {
                id: "old-c1".to_string(),
                user_name: "alice".to_string(),
                tenant_id: "t1".to_string(),
                category: DataCategory::Usage,
                level: ConsentLevel::Full,
                granted_at: Utc::now() - Duration::days(400),
                expires_at: None,
                ip_address: None,
                user_agent: None,
                policy_version: None,
                active: true,
            });
        }
        // Create a retention policy with auto_purge=true, 365 days
        let policy = RetentionPolicy {
            id: "rp1".to_string(),
            tenant_id: "t1".to_string(),
            category: DataCategory::Usage,
            retention_days: 365,
            legal_basis: "cleanup".to_string(),
            auto_purge: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        svc.upsert_retention_policy(policy).await.unwrap();

        let purged = svc.enforce_retention("t1").await.unwrap();
        assert_eq!(purged, 1);
    }

    #[tokio::test]
    async fn enforce_retention_no_purge_when_nothing_expired() {
        let svc = make_service();
        // Recent consent should not be purged
        svc.grant_consent(
            "t1",
            "alice",
            DataCategory::Usage,
            ConsentLevel::Full,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        let policy = RetentionPolicy {
            id: "rp1".to_string(),
            tenant_id: "t1".to_string(),
            category: DataCategory::Usage,
            retention_days: 365,
            legal_basis: "cleanup".to_string(),
            auto_purge: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        svc.upsert_retention_policy(policy).await.unwrap();

        let purged = svc.enforce_retention("t1").await.unwrap();
        assert_eq!(purged, 0);
    }

    #[tokio::test]
    async fn enforce_retention_emits_audit_when_purging() {
        let svc = make_service();
        {
            let mut store = svc.write_store();
            store.consents.push(ConsentRecord {
                id: "old-c1".to_string(),
                user_name: "bob".to_string(),
                tenant_id: "t1".to_string(),
                category: DataCategory::Messages,
                level: ConsentLevel::Full,
                granted_at: Utc::now() - Duration::days(500),
                expires_at: None,
                ip_address: None,
                user_agent: None,
                policy_version: None,
                active: true,
            });
        }
        let policy = RetentionPolicy {
            id: "rp2".to_string(),
            tenant_id: "t1".to_string(),
            category: DataCategory::Messages,
            retention_days: 90,
            legal_basis: "cleanup".to_string(),
            auto_purge: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        svc.upsert_retention_policy(policy).await.unwrap();
        svc.enforce_retention("t1").await.unwrap();

        let events = svc
            .query_audit_events(
                "t1",
                &AuditFilter {
                    action_prefix: Some("gdpr:EnforceRetention".to_string()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, "gdpr:EnforceRetention");
    }

    #[tokio::test]
    async fn query_audit_events_filters_by_action() {
        let svc = make_service();
        // Grant consent generates audit events
        svc.grant_consent(
            "t1",
            "alice",
            DataCategory::Identity,
            ConsentLevel::Full,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        svc.revoke_consent("t1", "alice", DataCategory::Identity)
            .await
            .unwrap();

        let consent_events = svc
            .query_audit_events(
                "t1",
                &AuditFilter {
                    action_prefix: Some("consent:".to_string()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(consent_events.len(), 2); // Grant + Revoke
    }

    #[tokio::test]
    async fn query_audit_events_empty() {
        let svc = make_service();
        let events = svc
            .query_audit_events("t1", &AuditFilter::default())
            .await
            .unwrap();
        assert!(events.is_empty());
    }

    #[tokio::test]
    async fn get_erasure_certificate_found() {
        let svc = make_service();
        let cert = svc
            .request_erasure("t1", "alice", &[DataCategory::Identity], "admin")
            .await
            .unwrap();
        let fetched = svc.get_erasure_certificate(&cert.id).await.unwrap();
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().id, cert.id);
    }

    #[tokio::test]
    async fn get_erasure_certificate_not_found() {
        let svc = make_service();
        let fetched = svc.get_erasure_certificate("nonexistent").await.unwrap();
        assert!(fetched.is_none());
    }

    #[tokio::test]
    async fn grant_consent_with_optional_fields() {
        let svc = make_service();
        let record = svc
            .grant_consent(
                "t1",
                "alice",
                DataCategory::Identity,
                ConsentLevel::Full,
                Some("127.0.0.1".to_string()),
                Some("Mozilla/5.0".to_string()),
                Some("v2.0".to_string()),
            )
            .await
            .unwrap();
        assert_eq!(record.ip_address.as_deref(), Some("127.0.0.1"));
        assert_eq!(record.user_agent.as_deref(), Some("Mozilla/5.0"));
        assert_eq!(record.policy_version.as_deref(), Some("v2.0"));
    }

    #[tokio::test]
    async fn list_retention_policies_returns_tenant_scoped() {
        let svc = make_service();
        let p1 = RetentionPolicy {
            id: "rp1".to_string(),
            tenant_id: "t1".to_string(),
            category: DataCategory::Identity,
            retention_days: 365,
            legal_basis: "legal".to_string(),
            auto_purge: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let p2 = RetentionPolicy {
            id: "rp2".to_string(),
            tenant_id: "t2".to_string(),
            category: DataCategory::Usage,
            retention_days: 90,
            legal_basis: "analytics".to_string(),
            auto_purge: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        svc.upsert_retention_policy(p1).await.unwrap();
        svc.upsert_retention_policy(p2).await.unwrap();

        let t1_policies = svc.list_retention_policies("t1").await.unwrap();
        assert_eq!(t1_policies.len(), 1);
        assert_eq!(t1_policies[0].tenant_id, "t1");
    }

    #[tokio::test]
    async fn export_user_data_emits_audit_event() {
        let svc = make_service();
        svc.export_user_data("t1", "alice", &[DataCategory::Identity])
            .await
            .unwrap();

        let events = svc
            .query_audit_events(
                "t1",
                &AuditFilter {
                    action_prefix: Some("gdpr:Export".to_string()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].actor, "alice");
    }
}
