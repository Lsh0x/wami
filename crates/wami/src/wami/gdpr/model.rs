//! GDPR Domain Models
//!
//! Types for consent tracking, audit events, erasure certificates, and data export.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ─── Consent ────────────────────────────────────────────────────

/// Granularity of user consent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentLevel {
    /// All processing allowed.
    Full,
    /// Only essential processing (service delivery).
    Essential,
    /// Analytics and improvement allowed, no marketing.
    Analytics,
    /// Marketing/profiling allowed.
    Marketing,
    /// Explicit denial of all non-essential processing.
    Denied,
}

/// Category of personal data subject to consent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataCategory {
    /// Account identity (name, email, phone).
    Identity,
    /// Chat messages and conversations.
    Messages,
    /// Model usage and analytics.
    Usage,
    /// Preferences and settings.
    Preferences,
    /// Files and documents uploaded.
    Documents,
    /// Location and IP-based data.
    Location,
    /// Behavioral profiling data.
    Profiling,
}

/// A recorded consent decision by a user for a specific data category.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentRecord {
    /// Unique consent record ID.
    pub id: String,
    /// User who granted/revoked consent.
    pub user_name: String,
    /// Tenant scope (Space ID).
    pub tenant_id: String,
    /// Data category this consent applies to.
    pub category: DataCategory,
    /// Level of consent granted.
    pub level: ConsentLevel,
    /// When consent was granted/updated.
    pub granted_at: DateTime<Utc>,
    /// When consent expires (if applicable).
    pub expires_at: Option<DateTime<Utc>>,
    /// IP address at time of consent (for legal proof).
    pub ip_address: Option<String>,
    /// User-agent at time of consent (for legal proof).
    pub user_agent: Option<String>,
    /// Version of the privacy policy the user agreed to.
    pub policy_version: Option<String>,
    /// Whether this consent is currently active.
    pub active: bool,
}

// ─── Audit Trail ────────────────────────────────────────────────

/// An audit event recording a significant action in the system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WamiAuditEvent {
    /// Unique event ID.
    pub id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Who performed the action (user ARN or system).
    pub actor: String,
    /// Action performed (e.g. "user:Create", "consent:Grant").
    pub action: String,
    /// Resource affected (ARN or path).
    pub resource: String,
    /// Result of the action.
    pub outcome: AuditOutcome,
    /// When the event occurred.
    pub timestamp: DateTime<Utc>,
    /// Source IP address.
    pub source_ip: Option<String>,
    /// Additional context (JSON-encoded metadata).
    pub metadata: Option<serde_json::Value>,
}

/// Outcome of an audited action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Success,
    Denied,
    Failed,
}

// ─── Erasure ────────────────────────────────────────────────────

/// Certificate proving data erasure was performed (right to be forgotten).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErasureCertificate {
    /// Unique certificate ID.
    pub id: String,
    /// User whose data was erased.
    pub user_name: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Categories of data that were erased.
    pub categories_erased: Vec<DataCategory>,
    /// When erasure was requested.
    pub requested_at: DateTime<Utc>,
    /// When erasure was completed.
    pub completed_at: DateTime<Utc>,
    /// Who processed the erasure (system or admin ARN).
    pub processed_by: String,
    /// Hash of the erased data for non-repudiation.
    pub verification_hash: String,
    /// Categories retained due to legal obligation.
    pub retained_categories: Vec<DataCategory>,
    /// Legal basis for any retained data.
    pub retention_justification: Option<String>,
}

// ─── Data Export ────────────────────────────────────────────────

/// A user's exported personal data (right of access / portability).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserDataExport {
    /// User whose data is exported.
    pub user_name: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// When the export was generated.
    pub exported_at: DateTime<Utc>,
    /// Data sections keyed by category.
    pub sections: Vec<ExportSection>,
    /// Format version.
    pub format_version: String,
}

/// A section of exported data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportSection {
    pub category: DataCategory,
    pub data: serde_json::Value,
    pub record_count: usize,
}

// ─── Retention ──────────────────────────────────────────────────

/// Retention policy for a data category within a tenant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    /// Unique policy ID.
    pub id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Data category this policy applies to.
    pub category: DataCategory,
    /// Maximum retention duration in days.
    pub retention_days: u32,
    /// Legal basis for the retention period.
    pub legal_basis: String,
    /// Whether automatic purge is enabled after retention expires.
    pub auto_purge: bool,
    /// When this policy was created.
    pub created_at: DateTime<Utc>,
    /// When this policy was last updated.
    pub updated_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    // ─── ConsentLevel serde ───────────────────────────────────

    #[test]
    fn consent_level_serde_roundtrip() {
        for (variant, expected) in [
            (ConsentLevel::Full, "\"full\""),
            (ConsentLevel::Essential, "\"essential\""),
            (ConsentLevel::Analytics, "\"analytics\""),
            (ConsentLevel::Marketing, "\"marketing\""),
            (ConsentLevel::Denied, "\"denied\""),
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            assert_eq!(json, expected);
            let back: ConsentLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(back, variant);
        }
    }

    // ─── DataCategory serde ───────────────────────────────────

    #[test]
    fn data_category_serde_roundtrip() {
        for (variant, expected) in [
            (DataCategory::Identity, "\"identity\""),
            (DataCategory::Messages, "\"messages\""),
            (DataCategory::Usage, "\"usage\""),
            (DataCategory::Preferences, "\"preferences\""),
            (DataCategory::Documents, "\"documents\""),
            (DataCategory::Location, "\"location\""),
            (DataCategory::Profiling, "\"profiling\""),
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            assert_eq!(json, expected);
            let back: DataCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(back, variant);
        }
    }

    // ─── AuditOutcome serde ───────────────────────────────────

    #[test]
    fn audit_outcome_serde_roundtrip() {
        for (variant, expected) in [
            (AuditOutcome::Success, "\"success\""),
            (AuditOutcome::Denied, "\"denied\""),
            (AuditOutcome::Failed, "\"failed\""),
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            assert_eq!(json, expected);
            let back: AuditOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(back, variant);
        }
    }

    // ─── ConsentRecord serde ──────────────────────────────────

    #[test]
    fn consent_record_serde_roundtrip() {
        let now = Utc::now();
        let record = ConsentRecord {
            id: "c1".to_string(),
            user_name: "alice".to_string(),
            tenant_id: "t1".to_string(),
            category: DataCategory::Identity,
            level: ConsentLevel::Full,
            granted_at: now,
            expires_at: Some(now),
            ip_address: Some("10.0.0.1".to_string()),
            user_agent: Some("Mozilla/5.0".to_string()),
            policy_version: Some("v2".to_string()),
            active: true,
        };
        let json = serde_json::to_string(&record).unwrap();
        let back: ConsentRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "c1");
        assert_eq!(back.user_name, "alice");
        assert_eq!(back.category, DataCategory::Identity);
        assert_eq!(back.level, ConsentLevel::Full);
        assert!(back.active);
        assert_eq!(back.ip_address.as_deref(), Some("10.0.0.1"));
    }

    #[test]
    fn consent_record_optional_fields_none() {
        let record = ConsentRecord {
            id: "c2".to_string(),
            user_name: "bob".to_string(),
            tenant_id: "t1".to_string(),
            category: DataCategory::Usage,
            level: ConsentLevel::Essential,
            granted_at: Utc::now(),
            expires_at: None,
            ip_address: None,
            user_agent: None,
            policy_version: None,
            active: false,
        };
        let json = serde_json::to_string(&record).unwrap();
        let back: ConsentRecord = serde_json::from_str(&json).unwrap();
        assert!(back.expires_at.is_none());
        assert!(back.ip_address.is_none());
        assert!(!back.active);
    }

    // ─── WamiAuditEvent serde ─────────────────────────────────

    #[test]
    fn audit_event_serde_roundtrip() {
        let event = WamiAuditEvent {
            id: "e1".to_string(),
            tenant_id: "t1".to_string(),
            actor: "admin".to_string(),
            action: "user:Create".to_string(),
            resource: "user/alice".to_string(),
            outcome: AuditOutcome::Success,
            timestamp: Utc::now(),
            source_ip: Some("192.168.1.1".to_string()),
            metadata: Some(serde_json::json!({"key": "value"})),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: WamiAuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "e1");
        assert_eq!(back.action, "user:Create");
        assert_eq!(back.outcome, AuditOutcome::Success);
        assert!(back.metadata.is_some());
    }

    #[test]
    fn audit_event_no_metadata() {
        let event = WamiAuditEvent {
            id: "e2".to_string(),
            tenant_id: "t1".to_string(),
            actor: "system".to_string(),
            action: "gdpr:Erase".to_string(),
            resource: "user/bob".to_string(),
            outcome: AuditOutcome::Denied,
            timestamp: Utc::now(),
            source_ip: None,
            metadata: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: WamiAuditEvent = serde_json::from_str(&json).unwrap();
        assert!(back.source_ip.is_none());
        assert!(back.metadata.is_none());
        assert_eq!(back.outcome, AuditOutcome::Denied);
    }

    // ─── ErasureCertificate serde ─────────────────────────────

    #[test]
    fn erasure_certificate_serde_roundtrip() {
        let cert = ErasureCertificate {
            id: "ec1".to_string(),
            user_name: "alice".to_string(),
            tenant_id: "t1".to_string(),
            categories_erased: vec![DataCategory::Messages, DataCategory::Usage],
            requested_at: Utc::now(),
            completed_at: Utc::now(),
            processed_by: "admin".to_string(),
            verification_hash: "abc123".to_string(),
            retained_categories: vec![DataCategory::Identity],
            retention_justification: Some("legal obligation".to_string()),
        };
        let json = serde_json::to_string(&cert).unwrap();
        let back: ErasureCertificate = serde_json::from_str(&json).unwrap();
        assert_eq!(back.categories_erased.len(), 2);
        assert_eq!(back.retained_categories, vec![DataCategory::Identity]);
        assert_eq!(
            back.retention_justification.as_deref(),
            Some("legal obligation")
        );
    }

    // ─── UserDataExport serde ─────────────────────────────────

    #[test]
    fn user_data_export_serde_roundtrip() {
        let export = UserDataExport {
            user_name: "alice".to_string(),
            tenant_id: "t1".to_string(),
            exported_at: Utc::now(),
            sections: vec![
                ExportSection {
                    category: DataCategory::Identity,
                    data: serde_json::json!({"name": "Alice"}),
                    record_count: 1,
                },
                ExportSection {
                    category: DataCategory::Messages,
                    data: serde_json::json!([]),
                    record_count: 0,
                },
            ],
            format_version: "1.0".to_string(),
        };
        let json = serde_json::to_string(&export).unwrap();
        let back: UserDataExport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.sections.len(), 2);
        assert_eq!(back.sections[0].category, DataCategory::Identity);
        assert_eq!(back.sections[0].record_count, 1);
        assert_eq!(back.format_version, "1.0");
    }

    // ─── RetentionPolicy serde ────────────────────────────────

    #[test]
    fn retention_policy_serde_roundtrip() {
        let policy = RetentionPolicy {
            id: "rp1".to_string(),
            tenant_id: "t1".to_string(),
            category: DataCategory::Identity,
            retention_days: 365,
            legal_basis: "GDPR Art. 6(1)(c)".to_string(),
            auto_purge: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let json = serde_json::to_string(&policy).unwrap();
        let back: RetentionPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(back.retention_days, 365);
        assert_eq!(back.category, DataCategory::Identity);
        assert!(back.auto_purge);
        assert_eq!(back.legal_basis, "GDPR Art. 6(1)(c)");
    }
}
