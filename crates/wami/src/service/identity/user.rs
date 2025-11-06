//! User Service
//!
//! Orchestrates user management operations by combining wami builders with store persistence.

use crate::store::traits::UserStore;
use crate::wami::identity::user::{
    builder as user_builder, CreateUserRequest, ListUsersRequest, UpdateUserRequest, User,
};
use std::sync::{Arc, RwLock};
use wami_core::context::WamiContext;
use wami_core::error::Result;
use wami_core::types::Tag;

/// Service for managing IAM users
///
/// Provides high-level operations that combine wami pure functions with store persistence.
#[wami_macros::service(store_trait = "crate::store::traits::UserStore")]
pub struct UserService<S> {
    store: Arc<RwLock<S>>,
}

impl<S: UserStore> UserService<S> {
    /// Create a new user
    pub async fn create_user(
        &self,
        context: &WamiContext,
        request: CreateUserRequest,
    ) -> Result<User> {
        // Use wami builder to create user with context
        let mut user = user_builder::build_user(request.user_name, request.path, context)?;

        // Apply permissions boundary if specified
        if let Some(boundary_arn) = request.permissions_boundary {
            user = user_builder::set_permissions_boundary(user, boundary_arn);
        }

        // Apply tags if specified
        let user = if let Some(tags) = request.tags {
            user_builder::add_tags(user, tags)
        } else {
            user
        };

        // Store it
        self.write_store().create_user(user).await
    }

    /// Get a user by name
    pub async fn get_user(&self, user_name: &str) -> Result<Option<User>> {
        self.read_store().get_user(user_name).await
    }

    /// Update a user
    pub async fn update_user(&self, request: UpdateUserRequest) -> Result<User> {
        // Get existing user
        let mut user = self
            .store
            .read()
            .unwrap()
            .get_user(&request.user_name)
            .await?
            .ok_or_else(|| crate::error::AmiError::ResourceNotFound {
                resource: format!("User: {}", request.user_name),
            })?;

        // Apply updates using builder functions
        if let Some(new_user_name) = request.new_user_name {
            user = user_builder::update_user_name(user, new_user_name);
        }

        if let Some(new_path) = request.new_path {
            user = user_builder::update_user_path(user, new_path);
        }

        // Store updated user
        self.write_store().update_user(user).await
    }

    /// Delete a user
    pub async fn delete_user(&self, user_name: &str) -> Result<()> {
        self.write_store().delete_user(user_name).await
    }

    /// List users with optional filtering
    pub async fn list_users(
        &self,
        request: ListUsersRequest,
    ) -> Result<(Vec<User>, bool, Option<String>)> {
        self.read_store()
            .list_users(request.path_prefix.as_deref(), request.pagination.as_ref())
            .await
    }

    /// Tag a user
    pub async fn tag_user(&self, user_name: &str, tags: Vec<Tag>) -> Result<()> {
        self.write_store().tag_user(user_name, tags).await
    }

    /// List tags for a user
    pub async fn list_user_tags(&self, user_name: &str) -> Result<Vec<Tag>> {
        self.read_store().list_user_tags(user_name).await
    }

    /// Untag a user
    pub async fn untag_user(&self, user_name: &str, tag_keys: Vec<String>) -> Result<()> {
        self.write_store().untag_user(user_name, tag_keys).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::memory::InMemoryWamiStore;
    use wami_core::arn::{TenantPath, WamiArn};
    use wami_core::context::WamiContext;

    fn setup_service() -> UserService<InMemoryWamiStore> {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        UserService::new(store)
    }

    fn test_context() -> WamiContext {
        let arn: WamiArn = "arn:wami:.*:12345678:wami:123456789012:user/test"
            .parse()
            .unwrap();
        WamiContext::builder()
            .instance_id("123456789012")
            .tenant_path(TenantPath::single(12345678))
            .caller_arn(arn)
            .is_root(false)
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn test_create_and_get_user() {
        let service = setup_service();
        let context = test_context();

        let request = CreateUserRequest {
            user_name: "alice".to_string(),
            path: Some("/engineering/".to_string()),
            permissions_boundary: None,
            tags: None,
        };

        let user = service.create_user(&context, request).await.unwrap();
        assert_eq!(user.user_name, "alice");
        assert_eq!(user.path, "/engineering/");

        let retrieved = service.get_user("alice").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().user_name, "alice");
    }

    #[tokio::test]
    async fn test_update_user() {
        let service = setup_service();
        let context = test_context();

        // Create user
        let create_request = CreateUserRequest {
            user_name: "bob".to_string(),
            path: Some("/".to_string()),
            permissions_boundary: None,
            tags: None,
        };
        service.create_user(&context, create_request).await.unwrap();

        // Update user
        let update_request = UpdateUserRequest {
            user_name: "bob".to_string(),
            new_user_name: Some("robert".to_string()),
            new_path: Some("/admin/".to_string()),
        };
        let updated = service.update_user(update_request).await.unwrap();
        assert_eq!(updated.user_name, "robert");
        assert_eq!(updated.path, "/admin/");
    }

    #[tokio::test]
    async fn test_delete_user() {
        let service = setup_service();

        let request = CreateUserRequest {
            user_name: "charlie".to_string(),
            path: None,
            permissions_boundary: None,
            tags: None,
        };
        let context = test_context();
        service.create_user(&context, request).await.unwrap();

        service.delete_user("charlie").await.unwrap();

        let retrieved = service.get_user("charlie").await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_list_users() {
        let service = setup_service();

        // Create multiple users
        for name in ["user1", "user2", "user3"] {
            let request = CreateUserRequest {
                user_name: name.to_string(),
                path: Some("/test/".to_string()),
                permissions_boundary: None,
                tags: None,
            };
            let context = test_context();
            service.create_user(&context, request).await.unwrap();
        }

        let list_request = ListUsersRequest {
            path_prefix: Some("/test/".to_string()),
            pagination: None,
        };
        let (users, _, _) = service.list_users(list_request).await.unwrap();
        assert_eq!(users.len(), 3);
    }

    #[tokio::test]
    async fn test_tag_operations() {
        let service = setup_service();

        let request = CreateUserRequest {
            user_name: "tagged_user".to_string(),
            path: None,
            permissions_boundary: None,
            tags: None,
        };
        let context = test_context();
        service.create_user(&context, request).await.unwrap();

        // Tag user
        let tags = vec![Tag {
            key: "Environment".to_string(),
            value: "Production".to_string(),
        }];
        service.tag_user("tagged_user", tags).await.unwrap();

        // List tags
        let retrieved_tags = service.list_user_tags("tagged_user").await.unwrap();
        assert_eq!(retrieved_tags.len(), 1);
        assert_eq!(retrieved_tags[0].key, "Environment");

        // Untag
        service
            .untag_user("tagged_user", vec!["Environment".to_string()])
            .await
            .unwrap();

        let tags_after = service.list_user_tags("tagged_user").await.unwrap();
        assert_eq!(tags_after.len(), 0);
    }

    // ========== Error Path Tests ==========

    #[tokio::test]
    async fn test_update_user_nonexistent() {
        let service = setup_service();

        let request = UpdateUserRequest {
            user_name: "nonexistent".to_string(),
            new_path: Some("/new/".to_string()),
            new_user_name: None,
        };

        let result = service.update_user(request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_tag_user_nonexistent() {
        let service = setup_service();

        let tags = vec![Tag {
            key: "Key".to_string(),
            value: "Value".to_string(),
        }];

        // Tag is idempotent - succeeds even if user doesn't exist (tags are silently ignored)
        let result = service.tag_user("nonexistent", tags).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_list_user_tags_nonexistent() {
        let service = setup_service();

        // List tags returns empty list for non-existent user
        let result = service.list_user_tags("nonexistent").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_untag_user_nonexistent() {
        let service = setup_service();

        // Untag is idempotent - succeeds even if user doesn't exist
        let result = service
            .untag_user("nonexistent", vec!["Key".to_string()])
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_list_users_empty_result() {
        let service = setup_service();

        let request = ListUsersRequest {
            path_prefix: Some("/nonexistent/".to_string()),
            pagination: None,
        };

        let (users, _, _) = service.list_users(request).await.unwrap();
        assert_eq!(users.len(), 0);
    }

    #[tokio::test]
    async fn test_list_users_with_path_prefix_filtering() {
        let service = setup_service();
        let context = test_context();

        // Create users with different paths
        for (name, path) in [
            ("user1", "/admin/"),
            ("user2", "/user/"),
            ("user3", "/admin/"),
        ] {
            let request = CreateUserRequest {
                user_name: name.to_string(),
                path: Some(path.to_string()),
                permissions_boundary: None,
                tags: None,
            };
            service.create_user(&context, request).await.unwrap();
        }

        let request = ListUsersRequest {
            path_prefix: Some("/admin/".to_string()),
            pagination: None,
        };

        let (users, _, _) = service.list_users(request).await.unwrap();
        assert_eq!(users.len(), 2);
        assert!(users.iter().all(|u| u.path == "/admin/"));
    }

    #[tokio::test]
    async fn test_delete_user_nonexistent() {
        let service = setup_service();

        // Delete is idempotent - succeeds even if user doesn't exist
        let result = service.delete_user("nonexistent").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_get_user_nonexistent() {
        let service = setup_service();

        let result = service.get_user("nonexistent").await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    // Note: test_with_provider removed as with_provider() method no longer exists
    // Provider selection is now handled through WamiContext and CloudMapping
}
