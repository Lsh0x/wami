//! Identity Store Trait
//!
//! Defines the interface for caller identity storage operations.

use crate::wami::sts::CallerIdentity;
use async_trait::async_trait;
use wami_core::arn::{ScopedName, TenantPath};
use wami_core::error::Result;

/// Trait for caller identity storage operations
#[async_trait]
pub trait IdentityStore: Send + Sync {
    /// Create (or replace) the identity of the principal `key` names.
    ///
    /// Keyed by the principal's key — tenant and name — never by its
    /// AWS-format `arn`, which names no tenant: two tenants' users of one
    /// name shared one entry, the last overwriting the first (wami 005,
    /// review round 2 F4).
    async fn create_identity(
        &mut self,
        key: &ScopedName,
        identity: CallerIdentity,
    ) -> Result<CallerIdentity>;

    /// Retrieve the identity of the principal `key` names
    async fn get_identity(&self, key: &ScopedName) -> Result<Option<CallerIdentity>>;

    /// List the identities of `tenant`'s principals — that tenant only, its
    /// children included in nothing.
    async fn list_identities(&self, tenant: &TenantPath) -> Result<Vec<CallerIdentity>>;
}
