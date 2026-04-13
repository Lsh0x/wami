//! Audit Store Trait
//!
//! Storage operations for WAMI audit trail events.

use crate::wami::gdpr::WamiAuditEvent;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use wami_core::error::Result;

/// Filtering options for audit event queries.
#[derive(Debug, Clone, Default)]
pub struct AuditFilter {
    /// Filter by actor (who performed the action).
    pub actor: Option<String>,
    /// Filter by action prefix (e.g. "consent:" or "user:").
    pub action_prefix: Option<String>,
    /// Filter by resource (affected entity).
    pub resource: Option<String>,
    /// Events after this timestamp.
    pub from: Option<DateTime<Utc>>,
    /// Events before this timestamp.
    pub to: Option<DateTime<Utc>>,
    /// Maximum number of events to return.
    pub limit: Option<usize>,
    /// Offset for pagination.
    pub offset: Option<usize>,
}

/// Store trait for audit trail operations.
#[async_trait]
pub trait AuditStore: Send + Sync {
    /// Record an audit event.
    async fn record_event(&mut self, event: WamiAuditEvent) -> Result<()>;

    /// Get a specific audit event by ID.
    async fn get_event(&self, event_id: &str) -> Result<Option<WamiAuditEvent>>;

    /// Query audit events for a tenant with optional filters.
    async fn query_events(
        &self,
        tenant_id: &str,
        filter: &AuditFilter,
    ) -> Result<Vec<WamiAuditEvent>>;

    /// Count audit events matching a filter (for pagination).
    async fn count_events(&self, tenant_id: &str, filter: &AuditFilter) -> Result<u64>;

    /// Purge audit events older than a given date (for retention compliance).
    /// Returns the number of events purged.
    async fn purge_events_before(&mut self, tenant_id: &str, before: DateTime<Utc>) -> Result<u64>;
}
