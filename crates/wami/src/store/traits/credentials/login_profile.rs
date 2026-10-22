//! Login Profile Store Trait
//!
//! Focused trait for login profile storage operations

use crate::credentials::LoginProfile;
use async_trait::async_trait;
use wami_core::arn::ScopedName;
use wami_core::error::Result;

/// Store trait for IAM login profile operations
#[async_trait]
pub trait LoginProfileStore: Send + Sync {
    /// Create the login profile of its owner.
    ///
    /// # Errors
    ///
    /// [`AmiError::ResourceExists`](wami_core::error::AmiError::ResourceExists)
    /// when the owner already has one: a create that replaced it would be a
    /// password reset nobody asked for.
    async fn create_login_profile(&mut self, profile: LoginProfile) -> Result<LoginProfile>;

    /// Get the login profile of the user stored under `owner`
    async fn get_login_profile(&self, owner: &ScopedName) -> Result<Option<LoginProfile>>;

    /// Update a login profile
    async fn update_login_profile(&mut self, profile: LoginProfile) -> Result<LoginProfile>;

    /// Delete the login profile of the user stored under `owner`
    async fn delete_login_profile(&mut self, owner: &ScopedName) -> Result<()>;
}
