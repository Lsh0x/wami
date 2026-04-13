//! GDPR Pure Functions (Operations)
//!
//! Stateless helper functions for GDPR domain logic.
//! These are used by the GdprService layer for validation and construction.

use super::model::{
    ConsentLevel, ConsentRecord, DataCategory, ErasureCertificate, RetentionPolicy, WamiAuditEvent,
};
use chrono::Utc;
use wami_core::error::{AmiError, Result};

/// Validate that a consent grant is well-formed.
#[allow(clippy::result_large_err)]
pub fn validate_consent(
    user_name: &str,
    tenant_id: &str,
    category: DataCategory,
    level: ConsentLevel,
) -> Result<()> {
    if user_name.is_empty() {
        return Err(AmiError::InvalidParameter {
            message: "user_name cannot be empty".to_string(),
        });
    }
    if tenant_id.is_empty() {
        return Err(AmiError::InvalidParameter {
            message: "tenant_id cannot be empty".to_string(),
        });
    }
    // Denied level can be applied to any category.
    // Full level requires explicit grant per category.
    let _ = (category, level);
    Ok(())
}

/// Check if a consent record is currently valid (not expired, still active).
pub fn is_consent_active(record: &ConsentRecord) -> bool {
    if !record.active {
        return false;
    }
    if let Some(expires_at) = record.expires_at {
        if expires_at < Utc::now() {
            return false;
        }
    }
    true
}

/// Check whether processing is allowed for a given category based on consent records.
///
/// Returns `true` if at least one active consent record permits the category.
pub fn is_processing_allowed(consents: &[ConsentRecord], category: DataCategory) -> bool {
    consents
        .iter()
        .filter(|c| c.category == category && is_consent_active(c))
        .any(|c| {
            matches!(
                c.level,
                ConsentLevel::Full | ConsentLevel::Analytics | ConsentLevel::Marketing
            )
        })
}

/// Determine which categories should be erased vs. retained given retention policies.
pub fn compute_erasure_scope(
    categories_requested: &[DataCategory],
    retention_policies: &[RetentionPolicy],
) -> (Vec<DataCategory>, Vec<DataCategory>) {
    let mut to_erase = Vec::new();
    let mut to_retain = Vec::new();

    for &cat in categories_requested {
        let has_active_retention = retention_policies
            .iter()
            .any(|p| p.category == cat && !p.auto_purge);

        if has_active_retention {
            to_retain.push(cat);
        } else {
            to_erase.push(cat);
        }
    }

    (to_erase, to_retain)
}

/// Build an audit event for a consent change.
pub fn build_consent_audit_event(
    tenant_id: &str,
    actor: &str,
    user_name: &str,
    category: DataCategory,
    level: ConsentLevel,
) -> WamiAuditEvent {
    WamiAuditEvent {
        id: generate_id(),
        tenant_id: tenant_id.to_string(),
        actor: actor.to_string(),
        action: "consent:Grant".to_string(),
        resource: format!("user/{}/consent/{:?}", user_name, category),
        outcome: super::model::AuditOutcome::Success,
        timestamp: Utc::now(),
        source_ip: None,
        metadata: Some(serde_json::json!({
            "category": category,
            "level": level,
        })),
    }
}

/// Build an audit event for an erasure request.
pub fn build_erasure_audit_event(
    tenant_id: &str,
    actor: &str,
    certificate: &ErasureCertificate,
) -> WamiAuditEvent {
    WamiAuditEvent {
        id: generate_id(),
        tenant_id: tenant_id.to_string(),
        actor: actor.to_string(),
        action: "gdpr:Erase".to_string(),
        resource: format!("user/{}/erasure/{}", certificate.user_name, certificate.id),
        outcome: super::model::AuditOutcome::Success,
        timestamp: Utc::now(),
        source_ip: None,
        metadata: Some(serde_json::json!({
            "categories_erased": certificate.categories_erased,
            "retained_categories": certificate.retained_categories,
        })),
    }
}

/// Generate a unique ID (ULID-like).
fn generate_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let rand: u64 = rand::random();
    format!("{:013x}{:016x}", ts, rand)
}

// Suppress unused imports for types used only in serde_json::json! macro
#[allow(unused_imports)]
use super::model::AuditOutcome;

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    fn make_consent(
        category: DataCategory,
        level: ConsentLevel,
        active: bool,
        expires_at: Option<chrono::DateTime<Utc>>,
    ) -> ConsentRecord {
        ConsentRecord {
            id: "c1".to_string(),
            user_name: "alice".to_string(),
            tenant_id: "t1".to_string(),
            category,
            level,
            granted_at: Utc::now(),
            expires_at,
            ip_address: None,
            user_agent: None,
            policy_version: None,
            active,
        }
    }

    // ─── validate_consent ──────────────────────────────────────

    #[test]
    fn validate_consent_ok() {
        let result = validate_consent(
            "alice",
            "tenant1",
            DataCategory::Identity,
            ConsentLevel::Full,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn validate_consent_empty_user() {
        let result = validate_consent("", "tenant1", DataCategory::Identity, ConsentLevel::Full);
        assert!(result.is_err());
        let msg = format!("{:?}", result.unwrap_err());
        assert!(msg.contains("user_name"));
    }

    #[test]
    fn validate_consent_empty_tenant() {
        let result = validate_consent("alice", "", DataCategory::Identity, ConsentLevel::Full);
        assert!(result.is_err());
        let msg = format!("{:?}", result.unwrap_err());
        assert!(msg.contains("tenant_id"));
    }

    // ─── is_consent_active ─────────────────────────────────────

    #[test]
    fn is_consent_active_when_active_no_expiry() {
        let r = make_consent(DataCategory::Identity, ConsentLevel::Full, true, None);
        assert!(is_consent_active(&r));
    }

    #[test]
    fn is_consent_active_when_inactive() {
        let r = make_consent(DataCategory::Identity, ConsentLevel::Full, false, None);
        assert!(!is_consent_active(&r));
    }

    #[test]
    fn is_consent_active_when_expired() {
        let past = Utc::now() - Duration::hours(1);
        let r = make_consent(DataCategory::Identity, ConsentLevel::Full, true, Some(past));
        assert!(!is_consent_active(&r));
    }

    #[test]
    fn is_consent_active_when_future_expiry() {
        let future = Utc::now() + Duration::hours(1);
        let r = make_consent(
            DataCategory::Identity,
            ConsentLevel::Full,
            true,
            Some(future),
        );
        assert!(is_consent_active(&r));
    }

    // ─── is_processing_allowed ─────────────────────────────────

    #[test]
    fn processing_allowed_with_full() {
        let consents = vec![make_consent(
            DataCategory::Usage,
            ConsentLevel::Full,
            true,
            None,
        )];
        assert!(is_processing_allowed(&consents, DataCategory::Usage));
    }

    #[test]
    fn processing_allowed_with_analytics() {
        let consents = vec![make_consent(
            DataCategory::Usage,
            ConsentLevel::Analytics,
            true,
            None,
        )];
        assert!(is_processing_allowed(&consents, DataCategory::Usage));
    }

    #[test]
    fn processing_allowed_with_marketing() {
        let consents = vec![make_consent(
            DataCategory::Usage,
            ConsentLevel::Marketing,
            true,
            None,
        )];
        assert!(is_processing_allowed(&consents, DataCategory::Usage));
    }

    #[test]
    fn processing_denied_with_denied_level() {
        let consents = vec![make_consent(
            DataCategory::Usage,
            ConsentLevel::Denied,
            true,
            None,
        )];
        assert!(!is_processing_allowed(&consents, DataCategory::Usage));
    }

    #[test]
    fn processing_denied_with_essential_level() {
        let consents = vec![make_consent(
            DataCategory::Usage,
            ConsentLevel::Essential,
            true,
            None,
        )];
        assert!(!is_processing_allowed(&consents, DataCategory::Usage));
    }

    #[test]
    fn processing_denied_wrong_category() {
        let consents = vec![make_consent(
            DataCategory::Messages,
            ConsentLevel::Full,
            true,
            None,
        )];
        assert!(!is_processing_allowed(&consents, DataCategory::Usage));
    }

    #[test]
    fn processing_denied_inactive_consent() {
        let consents = vec![make_consent(
            DataCategory::Usage,
            ConsentLevel::Full,
            false,
            None,
        )];
        assert!(!is_processing_allowed(&consents, DataCategory::Usage));
    }

    // ─── compute_erasure_scope ─────────────────────────────────

    fn make_policy(category: DataCategory, auto_purge: bool) -> RetentionPolicy {
        RetentionPolicy {
            id: "p1".to_string(),
            tenant_id: "t1".to_string(),
            category,
            retention_days: 365,
            legal_basis: "legal".to_string(),
            auto_purge,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn erasure_scope_no_policies() {
        let cats = vec![DataCategory::Identity, DataCategory::Messages];
        let (erase, retain) = compute_erasure_scope(&cats, &[]);
        assert_eq!(erase.len(), 2);
        assert!(retain.is_empty());
    }

    #[test]
    fn erasure_scope_with_active_retention() {
        let cats = vec![DataCategory::Identity, DataCategory::Messages];
        // auto_purge=false means active retention (do NOT erase)
        let policies = vec![make_policy(DataCategory::Identity, false)];
        let (erase, retain) = compute_erasure_scope(&cats, &policies);
        assert_eq!(erase, vec![DataCategory::Messages]);
        assert_eq!(retain, vec![DataCategory::Identity]);
    }

    #[test]
    fn erasure_scope_auto_purge_policy_allows_erasure() {
        let cats = vec![DataCategory::Identity];
        // auto_purge=true means the policy allows erasure
        let policies = vec![make_policy(DataCategory::Identity, true)];
        let (erase, retain) = compute_erasure_scope(&cats, &policies);
        assert_eq!(erase, vec![DataCategory::Identity]);
        assert!(retain.is_empty());
    }

    #[test]
    fn erasure_scope_mixed() {
        let cats = vec![
            DataCategory::Identity,
            DataCategory::Messages,
            DataCategory::Usage,
        ];
        let policies = vec![
            make_policy(DataCategory::Identity, false), // retained
            make_policy(DataCategory::Usage, true),     // auto-purge, so erasable
        ];
        let (erase, retain) = compute_erasure_scope(&cats, &policies);
        assert_eq!(erase, vec![DataCategory::Messages, DataCategory::Usage]);
        assert_eq!(retain, vec![DataCategory::Identity]);
    }

    // ─── build_consent_audit_event ─────────────────────────────

    #[test]
    fn build_consent_audit_event_fields() {
        let evt = build_consent_audit_event(
            "t1",
            "admin",
            "alice",
            DataCategory::Usage,
            ConsentLevel::Full,
        );
        assert_eq!(evt.tenant_id, "t1");
        assert_eq!(evt.actor, "admin");
        assert_eq!(evt.action, "consent:Grant");
        assert!(evt.resource.contains("alice"));
        assert!(evt.resource.contains("Usage"));
        assert_eq!(evt.outcome, super::AuditOutcome::Success);
        assert!(evt.metadata.is_some());
        assert!(!evt.id.is_empty());
    }

    // ─── build_erasure_audit_event ─────────────────────────────

    #[test]
    fn build_erasure_audit_event_fields() {
        let cert = ErasureCertificate {
            id: "cert-1".to_string(),
            user_name: "alice".to_string(),
            tenant_id: "t1".to_string(),
            categories_erased: vec![DataCategory::Identity],
            requested_at: Utc::now(),
            completed_at: Utc::now(),
            processed_by: "admin".to_string(),
            verification_hash: "abc123".to_string(),
            retained_categories: vec![DataCategory::Messages],
            retention_justification: Some("legal".to_string()),
        };
        let evt = build_erasure_audit_event("t1", "admin", &cert);
        assert_eq!(evt.tenant_id, "t1");
        assert_eq!(evt.actor, "admin");
        assert_eq!(evt.action, "gdpr:Erase");
        assert!(evt.resource.contains("alice"));
        assert!(evt.resource.contains("cert-1"));
        assert_eq!(evt.outcome, super::AuditOutcome::Success);
        assert!(evt.metadata.is_some());
    }
}
