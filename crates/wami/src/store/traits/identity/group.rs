//! Group Store Trait
//!
//! Focused trait for group-related storage operations

use crate::wami::identity::Group;
use async_trait::async_trait;
use wami_core::arn::{ScopedName, TenantPath};
use wami_core::error::Result;
use wami_core::types::PaginationParams;

/// Store trait for IAM group operations
///
/// A group is stored under its [`ScopedName`] ([`Group::key`]), and a member
/// is named by the user's key: a group of tenant `5/7` called `admins` and one
/// of `6/7` are two groups, and `alice` of one tenant is not `alice` of the
/// other. There is no by-name method, deliberately.
#[async_trait]
pub trait GroupStore: Send + Sync {
    /// Create a new group.
    ///
    /// # Errors
    ///
    /// [`AmiError::ResourceExists`](wami_core::error::AmiError::ResourceExists)
    /// when a group already holds the record's key or its `group_id`; nothing
    /// is overwritten.
    async fn create_group(&mut self, group: Group) -> Result<Group>;

    /// Get the group stored under `key`.
    async fn get_group(&self, key: &ScopedName) -> Result<Option<Group>>;

    /// Replace the stored group whose `group_id` is the record's; a rename
    /// moves it to its new key.
    ///
    /// # Errors
    ///
    /// [`AmiError::ResourceNotFound`](wami_core::error::AmiError::ResourceNotFound)
    /// when no group has that id, and
    /// [`AmiError::ResourceExists`](wami_core::error::AmiError::ResourceExists)
    /// when the new key is held by another group.
    async fn update_group(&mut self, group: Group) -> Result<Group>;

    /// Delete the group stored under `key`.
    async fn delete_group(&mut self, key: &ScopedName) -> Result<()>;

    /// List the groups of exactly `tenant`, with optional path filtering and
    /// pagination.
    async fn list_groups(
        &self,
        tenant: &TenantPath,
        path_prefix: Option<&str>,
        pagination: Option<&PaginationParams>,
    ) -> Result<(Vec<Group>, bool, Option<String>)>;

    /// List the groups the user stored under `user` belongs to
    async fn list_groups_for_user(&self, user: &ScopedName) -> Result<Vec<Group>>;

    /// Add the user stored under `user` to the group stored under `group`.
    ///
    /// # Errors
    ///
    /// [`AmiError::ResourceNotFound`](wami_core::error::AmiError::ResourceNotFound)
    /// when either is not stored — a row for an absent party would come alive
    /// at its create — and
    /// [`AmiError::InvalidParameter`](wami_core::error::AmiError::InvalidParameter)
    /// when they are of different tenants: a group's policies decide only its
    /// own tenant's principals (wami 005, Δ4).
    async fn add_user_to_group(&mut self, group: &ScopedName, user: &ScopedName) -> Result<()>;

    /// Remove a user from a group
    async fn remove_user_from_group(&mut self, group: &ScopedName, user: &ScopedName)
        -> Result<()>;

    // Managed policy attachment methods

    /// Attach a managed policy to a group
    async fn attach_group_policy(&mut self, key: &ScopedName, policy_arn: &str) -> Result<()>;

    /// Detach a managed policy from a group
    async fn detach_group_policy(&mut self, key: &ScopedName, policy_arn: &str) -> Result<()>;

    /// List all managed policies attached to a group
    async fn list_attached_group_policies(&self, key: &ScopedName) -> Result<Vec<String>>;

    // Inline policy methods

    /// Put an inline policy on a group
    async fn put_group_policy(
        &mut self,
        key: &ScopedName,
        policy_name: &str,
        policy_document: String,
    ) -> Result<()>;

    /// Get an inline policy from a group
    async fn get_group_policy(&self, key: &ScopedName, policy_name: &str)
        -> Result<Option<String>>;

    /// Delete an inline policy from a group
    async fn delete_group_policy(&mut self, key: &ScopedName, policy_name: &str) -> Result<()>;

    /// List all inline policy names for a group
    async fn list_group_policies(&self, key: &ScopedName) -> Result<Vec<String>>;
}
