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
