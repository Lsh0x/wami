//! User Store Trait
//!
//! Focused trait for user-related storage operations

use crate::wami::identity::User;
use async_trait::async_trait;
use wami_core::arn::{ScopedName, TenantPath};
use wami_core::error::Result;
use wami_core::types::{PaginationParams, Tag};

/// Store trait for IAM user operations
///
/// A user is stored under its [`ScopedName`] — the tenant path its `wami_arn`
/// carries and its `user_name` ([`User::key`]) — never under the bare name:
/// two tenants may each hold an `alice`, and a store keyed by the name hands
/// one tenant's record to the other. Every method that addresses a user takes
/// that key; there is no by-name method, deliberately.
#[async_trait]
pub trait UserStore: Send + Sync {
    /// Create a new user.
    ///
    /// # Errors
    ///
    /// [`AmiError::ResourceExists`](wami_core::error::AmiError::ResourceExists)
    /// when a user already holds the record's key or its `user_id`. Nothing is
    /// overwritten: a create that replaced the existing record would let anyone
    /// able to create a user rewrite whoever held that name.
    async fn create_user(&mut self, user: User) -> Result<User>;

    /// Get the user stored under `key`.
    async fn get_user(&self, key: &ScopedName) -> Result<Option<User>>;

    /// Replace the stored user whose `user_id` is the record's.
    ///
    /// The record is found by its stable id, so a rename moves it to its new
    /// key.
    ///
    /// # Errors
    ///
    /// [`AmiError::ResourceNotFound`](wami_core::error::AmiError::ResourceNotFound)
    /// when no user has that id, and
    /// [`AmiError::ResourceExists`](wami_core::error::AmiError::ResourceExists)
    /// when the new key is held by another user.
    async fn update_user(&mut self, user: User) -> Result<User>;

    /// Delete the user stored under `key`.
    async fn delete_user(&mut self, key: &ScopedName) -> Result<()>;

    /// List the users of exactly `tenant` — never its children, never the
    /// whole store — with optional path filtering and pagination.
    async fn list_users(
        &self,
        tenant: &TenantPath,
        path_prefix: Option<&str>,
        pagination: Option<&PaginationParams>,
    ) -> Result<(Vec<User>, bool, Option<String>)>;

    /// Tag a user
    async fn tag_user(&mut self, key: &ScopedName, tags: Vec<Tag>) -> Result<()>;

    /// List tags for a user
    async fn list_user_tags(&self, key: &ScopedName) -> Result<Vec<Tag>>;

    /// Untag a user
    async fn untag_user(&mut self, key: &ScopedName, tag_keys: Vec<String>) -> Result<()>;

    // Managed policy attachment methods

    /// Attach a managed policy to a user
    async fn attach_user_policy(&mut self, key: &ScopedName, policy_arn: &str) -> Result<()>;

    /// Detach a managed policy from a user
    async fn detach_user_policy(&mut self, key: &ScopedName, policy_arn: &str) -> Result<()>;

    /// List all managed policies attached to a user
    async fn list_attached_user_policies(&self, key: &ScopedName) -> Result<Vec<String>>;

    // Inline policy methods

    /// Put an inline policy on a user
    async fn put_user_policy(
        &mut self,
        key: &ScopedName,
        policy_name: &str,
        policy_document: String,
    ) -> Result<()>;

    /// Get an inline policy from a user
    async fn get_user_policy(&self, key: &ScopedName, policy_name: &str) -> Result<Option<String>>;

    /// Delete an inline policy from a user
    async fn delete_user_policy(&mut self, key: &ScopedName, policy_name: &str) -> Result<()>;

    /// List all inline policy names for a user
    async fn list_user_policies(&self, key: &ScopedName) -> Result<Vec<String>>;
}
