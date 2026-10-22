//! Policy Store Trait
//!
//! Focused trait for policy-related storage operations

use crate::wami::policies::Policy;
use async_trait::async_trait;
use wami_core::arn::TenantPath;
use wami_core::error::Result;
use wami_core::types::PaginationParams;

/// Store trait for IAM policy operations
#[async_trait]
pub trait PolicyStore: Send + Sync {
    /// Create a new policy.
    ///
    /// # Errors
    ///
    /// [`AmiError::ResourceExists`](wami_core::error::AmiError::ResourceExists)
    /// when a policy is already stored under its `arn`. Nothing is
    /// overwritten: that ARN names no tenant, so a create that replaced the
    /// stored policy let one tenant rewrite the document another tenant's
    /// attachments evaluate.
    async fn create_policy(&mut self, policy: Policy) -> Result<Policy>;

    /// Get a policy by ARN
    async fn get_policy(&self, policy_arn: &str) -> Result<Option<Policy>>;

    /// Update an existing policy
    async fn update_policy(&mut self, policy: Policy) -> Result<Policy>;

    /// Delete a policy
    async fn delete_policy(&mut self, policy_arn: &str) -> Result<()>;

    /// List the policies of exactly `tenant` (the tenant path their
    /// `wami_arn` carries), with optional filtering and pagination
    async fn list_policies(
        &self,
        tenant: &TenantPath,
        scope: Option<&str>,
        pagination: Option<&PaginationParams>,
    ) -> Result<(Vec<Policy>, bool, Option<String>)>;
}
