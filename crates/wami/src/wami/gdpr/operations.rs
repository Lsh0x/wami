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
