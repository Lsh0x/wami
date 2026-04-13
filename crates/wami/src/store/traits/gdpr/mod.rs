//! GDPR Store Traits
//!
//! Focused traits for consent, audit, and erasure storage operations.
//! Following the Interface Segregation Principle — consumers can depend
//! on only the sub-trait they need.

pub mod audit;
pub mod consent;

pub use audit::AuditStore;
pub use consent::ConsentStore;
