//! GDPR Compliance & Audit Trail
//!
//! Provides consent management, data export, erasure, and retention enforcement.
//! Designed for multi-tenant environments — each consent/audit record is scoped
//! to a tenant.

pub mod model;
pub mod operations;

// Re-export main types
pub use model::{
    ConsentLevel, ConsentRecord, DataCategory, ErasureCertificate, RetentionPolicy, UserDataExport,
    WamiAuditEvent,
};
