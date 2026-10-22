//! Role Store Trait
//!
//! Focused trait for role-related storage operations

use crate::wami::identity::Role;
use async_trait::async_trait;
use wami_core::arn::{ScopedName, TenantPath};
use wami_core::error::Result;
use wami_core::types::PaginationParams;

/// Store trait for IAM role operations
///
/// A role is stored under its [`ScopedName`] ([`Role::key`]): tenant `5/7`'s
/// `admin` and tenant `6/7`'s are two roles, with two sets of policies. There
/// is no by-name method, deliberately.
#[async_trait]
pub trait RoleStore: Send + Sync {
    /// Create a new role.
    ///
    /// # Errors
    ///
    /// [`AmiError::ResourceExists`](wami_core::error::AmiError::ResourceExists)
    /// when a role already holds the record's key or its `role_id`; nothing is
    /// overwritten.
    async fn create_role(&mut self, role: Role) -> Result<Role>;

    /// Get the role stored under `key`.
    async fn get_role(&self, key: &ScopedName) -> Result<Option<Role>>;

    /// Replace the stored role whose `role_id` is the record's.
    ///
    /// # Errors
    ///
    /// [`AmiError::ResourceNotFound`](wami_core::error::AmiError::ResourceNotFound)
    /// when no role has that id, and
    /// [`AmiError::ResourceExists`](wami_core::error::AmiError::ResourceExists)
    /// when its key is held by another role.
    async fn update_role(&mut self, role: Role) -> Result<Role>;

    /// Delete the role stored under `key`.
    async fn delete_role(&mut self, key: &ScopedName) -> Result<()>;

    /// List the roles of exactly `tenant`, with optional path filtering and
    /// pagination.
    async fn list_roles(
        &self,
        tenant: &TenantPath,
        path_prefix: Option<&str>,
        pagination: Option<&PaginationParams>,
    ) -> Result<(Vec<Role>, bool, Option<String>)>;

    // Managed policy attachment methods

    /// Attach a managed policy to a role
    async fn attach_role_policy(&mut self, key: &ScopedName, policy_arn: &str) -> Result<()>;

    /// Detach a managed policy from a role
    async fn detach_role_policy(&mut self, key: &ScopedName, policy_arn: &str) -> Result<()>;

    /// List all managed policies attached to a role
    async fn list_attached_role_policies(&self, key: &ScopedName) -> Result<Vec<String>>;

    // Inline policy methods

    /// Put an inline policy on a role
    async fn put_role_policy(
        &mut self,
        key: &ScopedName,
        policy_name: &str,
        policy_document: String,
    ) -> Result<()>;

    /// Get an inline policy from a role
    async fn get_role_policy(&self, key: &ScopedName, policy_name: &str) -> Result<Option<String>>;

    /// Delete an inline policy from a role
    async fn delete_role_policy(&mut self, key: &ScopedName, policy_name: &str) -> Result<()>;

    /// List all inline policy names for a role
    async fn list_role_policies(&self, key: &ScopedName) -> Result<Vec<String>>;
}
