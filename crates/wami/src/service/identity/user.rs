//! User Service
//!
//! Orchestrates user management operations by combining wami builders with store persistence.

use crate::service::auth::authorizer::{iam_resource_arn, Authorizer};
use crate::store::traits::UserStore;
use crate::wami::identity::root_user::ROOT_USER_NAME;
use crate::wami::identity::user::{
    builder as user_builder, CreateUserRequest, ListUsersRequest, UpdateUserRequest, User,
};
use std::sync::Arc;
use tokio::sync::RwLock;
use wami_core::actions::WamiAction;
use wami_core::arn::ScopedName;
use wami_core::context::WamiContext;
use wami_core::error::{AmiError, Result};
use wami_core::types::Tag;

/// Service for managing IAM users
///
/// Every verb names its target by [`ScopedName`] — the tenant explicitly, never
/// the caller's by default (wami 005).
/// Optionally holds an [`Authorizer`] for authorization guards on every method.
#[wami_macros::service(store_trait = "crate::store::traits::UserStore", generate_new = false)]
pub struct UserService<S> {
    store: Arc<RwLock<S>>,
    authz: Option<Arc<dyn Authorizer>>,
}

impl<S: UserStore> UserService<S> {
    /// Create a new UserService without authorization guards (backward compatible).
    pub fn new(store: Arc<RwLock<S>>) -> Self {
        Self { store, authz: None }
    }

    /// Create a new UserService with an authorization guard.
    pub fn with_authorizer(store: Arc<RwLock<S>>, authz: Arc<dyn Authorizer>) -> Self {
        Self {
            store,
            authz: Some(authz),
        }
    }

    /// Internal: check authorization if an authorizer is set.
    async fn guard(
        &self,
        context: &WamiContext,
        action: WamiAction,
        resource_type: &str,
        resource_id: &str,
    ) -> Result<()> {
        if let Some(authz) = &self.authz {
            let arn = iam_resource_arn(context, resource_type, resource_id)?;
            authz.check_or_deny(context, action.as_str(), &arn).await?;
        }
        Ok(())
    }

    /// Create a new user under `request.user`.
    ///
    /// # Errors
    ///
    /// [`AmiError::ResourceExists`] when the key is held: nothing is overwritten.
    pub async fn create_user(
        &self,
        context: &WamiContext,
        request: CreateUserRequest,
    ) -> Result<User> {
        self.guard(
            context,
            WamiAction::IamCreateUser,
            "user",
            request.user.name(),
        )
        .await?;

        let mut user = user_builder::build_user(&request.user, request.path, context)?;
        if let Some(boundary_arn) = request.permissions_boundary {
            user = user_builder::set_permissions_boundary(user, boundary_arn);
        }
        let user = if let Some(tags) = request.tags {
            user_builder::add_tags(user, tags)
        } else {
            user
        };

        self.write_store().await.create_user(user).await
    }

    /// Get the user stored under `user`
    pub async fn get_user(&self, context: &WamiContext, user: &ScopedName) -> Result<Option<User>> {
        self.guard(context, WamiAction::IamReadUser, "user", user.name())
            .await?;
        self.read_store().await.get_user(user).await
    }

    /// Update a user
    ///
    /// The root user cannot be renamed (but path and other attributes can be updated).
    pub async fn update_user(
        &self,
        context: &WamiContext,
        request: UpdateUserRequest,
    ) -> Result<User> {
        self.guard(
            context,
            WamiAction::IamUpdateUser,
            "user",
            request.user.name(),
        )
        .await?;

        // Protect root user from being renamed
        if request.user.name() == ROOT_USER_NAME {
            if let Some(ref new_name) = request.new_user_name {
                if new_name != ROOT_USER_NAME {
                    return Err(AmiError::InvalidParameter {
                        message: "Cannot rename the root user".to_string(),
                    });
                }
            }
        }

        let mut user = self
            .read_store()
            .await
            .get_user(&request.user)
            .await?
            .ok_or_else(|| AmiError::ResourceNotFound {
                resource: format!("User: {}", request.user),
            })?;

        if let Some(new_user_name) = request.new_user_name {
            user = user_builder::update_user_name(user, new_user_name);
        }
        if let Some(new_path) = request.new_path {
            user = user_builder::update_user_path(user, new_path);
        }

        // The store finds the record by its id, so a rename moves it — with its
        // policies, memberships and credentials — to the new key.
        self.write_store().await.update_user(user).await
    }

    /// Delete a user
    ///
    /// The root user cannot be deleted.
    pub async fn delete_user(&self, context: &WamiContext, user: &ScopedName) -> Result<()> {
        if user.name() == ROOT_USER_NAME {
            return Err(AmiError::InvalidParameter {
                message: "Cannot delete the root user".to_string(),
            });
        }

        self.guard(context, WamiAction::IamDeleteUser, "user", user.name())
            .await?;
        self.write_store().await.delete_user(user).await
    }

    /// List the users of `request.tenant` — that tenant only
    pub async fn list_users(
        &self,
        context: &WamiContext,
        request: ListUsersRequest,
    ) -> Result<(Vec<User>, bool, Option<String>)> {
        self.guard(context, WamiAction::IamListUsers, "user", "*")
            .await?;
        self.read_store()
            .await
            .list_users(
                &request.tenant,
                request.path_prefix.as_deref(),
                request.pagination.as_ref(),
            )
            .await
    }

    /// Tag a user
    pub async fn tag_user(
        &self,
        context: &WamiContext,
        user: &ScopedName,
        tags: Vec<Tag>,
    ) -> Result<()> {
        self.guard(context, WamiAction::IamUpdateUser, "user", user.name())
            .await?;
        self.write_store().await.tag_user(user, tags).await
    }

    /// List tags for a user
    pub async fn list_user_tags(
        &self,
        context: &WamiContext,
        user: &ScopedName,
    ) -> Result<Vec<Tag>> {
        self.guard(context, WamiAction::IamReadUser, "user", user.name())
            .await?;
        self.read_store().await.list_user_tags(user).await
    }

    /// Untag a user
    pub async fn untag_user(
        &self,
        context: &WamiContext,
        user: &ScopedName,
        tag_keys: Vec<String>,
    ) -> Result<()> {
        self.guard(context, WamiAction::IamUpdateUser, "user", user.name())
            .await?;
        self.write_store().await.untag_user(user, tag_keys).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::auth::decision::{Decision, DenyReason};
    use crate::store::memory::InMemoryWamiStore;
    use wami_core::arn::{TenantPath, WamiArn};
    use wami_core::context::WamiContext;

    /// The tenant every test of this module works in.
    fn tenant() -> wami_core::arn::TenantPath {
        wami_core::arn::TenantPath::single(12345678)
    }

    /// `name`'s key in that tenant.
    fn key(name: impl AsRef<str>) -> wami_core::arn::ScopedName {
        wami_core::arn::ScopedName::new(tenant(), name.as_ref())
    }

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
            user: key("alice"),
            path: Some("/engineering/".to_string()),
            permissions_boundary: None,
            tags: None,
        };

        let user = service.create_user(&context, request).await.unwrap();
        assert_eq!(user.user_name, "alice");
        assert_eq!(user.path, "/engineering/");

        let retrieved = service.get_user(&context, &key("alice")).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().user_name, "alice");
    }

    #[tokio::test]
    async fn test_update_user() {
        let service = setup_service();
        let context = test_context();

        // Create user
        let create_request = CreateUserRequest {
            user: key("bob"),
            path: Some("/".to_string()),
            permissions_boundary: None,
            tags: None,
        };
        service.create_user(&context, create_request).await.unwrap();

        // Update user
        let update_request = UpdateUserRequest {
            user: key("bob"),
            new_user_name: Some("robert".to_string()),
            new_path: Some("/admin/".to_string()),
        };
        let updated = service.update_user(&context, update_request).await.unwrap();
        assert_eq!(updated.user_name, "robert");
        assert_eq!(updated.path, "/admin/");
    }

    #[tokio::test]
    async fn test_delete_user() {
        let service = setup_service();
        let context = test_context();

        let request = CreateUserRequest {
            user: key("charlie"),
            path: None,
            permissions_boundary: None,
            tags: None,
        };
        service.create_user(&context, request).await.unwrap();

        service
            .delete_user(&context, &key("charlie"))
            .await
            .unwrap();

        let retrieved = service.get_user(&context, &key("charlie")).await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_list_users() {
        let service = setup_service();
        let context = test_context();

        // Create multiple users
        for name in ["user1", "user2", "user3"] {
            let request = CreateUserRequest {
                user: key(name),
                path: Some("/test/".to_string()),
                permissions_boundary: None,
                tags: None,
            };
            service.create_user(&context, request).await.unwrap();
        }

        let list_request = ListUsersRequest {
            tenant: tenant(),
            path_prefix: Some("/test/".to_string()),
            pagination: None,
        };
        let (users, _, _) = service.list_users(&context, list_request).await.unwrap();
        assert_eq!(users.len(), 3);
    }

    #[tokio::test]
    async fn test_tag_operations() {
        let service = setup_service();
        let context = test_context();

        let request = CreateUserRequest {
            user: key("tagged_user"),
            path: None,
            permissions_boundary: None,
            tags: None,
        };
        service.create_user(&context, request).await.unwrap();

        // Tag user
        let tags = vec![Tag {
            key: "Environment".to_string(),
            value: "Production".to_string(),
        }];
        service
            .tag_user(&context, &key("tagged_user"), tags)
            .await
            .unwrap();

        // List tags
        let retrieved_tags = service
            .list_user_tags(&context, &key("tagged_user"))
            .await
            .unwrap();
        assert_eq!(retrieved_tags.len(), 1);
        assert_eq!(retrieved_tags[0].key, "Environment");

        // Untag
        service
            .untag_user(
                &context,
                &key("tagged_user"),
                vec!["Environment".to_string()],
            )
            .await
            .unwrap();

        let tags_after = service
            .list_user_tags(&context, &key("tagged_user"))
            .await
            .unwrap();
        assert_eq!(tags_after.len(), 0);
    }

    // ========== Error Path Tests ==========

    #[tokio::test]
    async fn test_update_user_nonexistent() {
        let service = setup_service();
        let context = test_context();

        let request = UpdateUserRequest {
            user: key("nonexistent"),
            new_path: Some("/new/".to_string()),
            new_user_name: None,
        };

        let result = service.update_user(&context, request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_tag_user_nonexistent() {
        let service = setup_service();
        let context = test_context();

        let tags = vec![Tag {
            key: "Key".to_string(),
            value: "Value".to_string(),
        }];

        // Tag is idempotent - succeeds even if user doesn't exist (tags are silently ignored)
        let result = service.tag_user(&context, &key("nonexistent"), tags).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_list_user_tags_nonexistent() {
        let service = setup_service();
        let context = test_context();

        // List tags returns empty list for non-existent user
        let result = service.list_user_tags(&context, &key("nonexistent")).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_untag_user_nonexistent() {
        let service = setup_service();
        let context = test_context();

        // Untag is idempotent - succeeds even if user doesn't exist
        let result = service
            .untag_user(&context, &key("nonexistent"), vec!["Key".to_string()])
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_list_users_empty_result() {
        let service = setup_service();
        let context = test_context();

        let request = ListUsersRequest {
            tenant: tenant(),
            path_prefix: Some("/nonexistent/".to_string()),
            pagination: None,
        };

        let (users, _, _) = service.list_users(&context, request).await.unwrap();
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
                user: key(name),
                path: Some(path.to_string()),
                permissions_boundary: None,
                tags: None,
            };
            service.create_user(&context, request).await.unwrap();
        }

        let request = ListUsersRequest {
            tenant: tenant(),
            path_prefix: Some("/admin/".to_string()),
            pagination: None,
        };

        let (users, _, _) = service.list_users(&context, request).await.unwrap();
        assert_eq!(users.len(), 2);
        assert!(users.iter().all(|u| u.path == "/admin/"));
    }

    #[tokio::test]
    async fn test_delete_user_nonexistent() {
        let service = setup_service();
        let context = test_context();

        // Delete is idempotent - succeeds even if user doesn't exist
        let result = service.delete_user(&context, &key("nonexistent")).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_get_user_nonexistent() {
        let service = setup_service();
        let context = test_context();

        let result = service.get_user(&context, &key("nonexistent")).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    // ========== Root User Protection Tests ==========

    #[tokio::test]
    async fn test_delete_root_user_is_denied() {
        let service = setup_service();
        let context = test_context();

        let result = service.delete_user(&context, &key("root")).await;
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("Cannot delete the root user"));
    }

    #[tokio::test]
    async fn test_rename_root_user_is_denied() {
        let service = setup_service();
        let context = test_context();

        // First create a root user in the store
        let request = CreateUserRequest {
            user: key("root"),
            path: Some("/".to_string()),
            permissions_boundary: None,
            tags: None,
        };
        service.create_user(&context, request).await.unwrap();

        // Try to rename root
        let update_request = UpdateUserRequest {
            user: key("root"),
            new_user_name: Some("not-root".to_string()),
            new_path: None,
        };
        let result = service.update_user(&context, update_request).await;
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("Cannot rename the root user"));
    }

    #[tokio::test]
    async fn test_update_root_user_path_is_allowed() {
        let service = setup_service();
        let context = test_context();

        // Create a root user
        let request = CreateUserRequest {
            user: key("root"),
            path: Some("/".to_string()),
            permissions_boundary: None,
            tags: None,
        };
        service.create_user(&context, request).await.unwrap();

        // Changing path (not name) should be allowed
        let update_request = UpdateUserRequest {
            user: key("root"),
            new_user_name: None,
            new_path: Some("/admin/".to_string()),
        };
        let result = service.update_user(&context, update_request).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().path, "/admin/");
    }

    // ─── Authorization guard tests ────────────────────────────

    use crate::service::auth::authorizer::Authorizer;
    use async_trait::async_trait;

    struct DenyAllAuthorizer;

    #[async_trait]
    impl Authorizer for DenyAllAuthorizer {
        async fn authorize(
            &self,
            _ctx: &WamiContext,
            _action: &str,
            _arn: &WamiArn,
        ) -> wami_core::error::Result<Decision> {
            Ok(Decision::Deny(DenyReason::NoMatch))
        }
    }

    fn setup_guarded_service() -> UserService<InMemoryWamiStore> {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::new()));
        UserService::with_authorizer(store, Arc::new(DenyAllAuthorizer))
    }

    #[tokio::test]
    async fn test_guard_create_user_denied() {
        let service = setup_guarded_service();
        let context = test_context();
        let request = CreateUserRequest {
            user: key("alice"),
            path: None,
            permissions_boundary: None,
            tags: None,
        };
        let result = service.create_user(&context, request).await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn test_guard_get_user_denied() {
        let service = setup_guarded_service();
        let context = test_context();
        let result = service.get_user(&context, &key("alice")).await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn test_guard_delete_user_denied() {
        let service = setup_guarded_service();
        let context = test_context();
        let result = service.delete_user(&context, &key("alice")).await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn test_guard_list_users_denied() {
        let service = setup_guarded_service();
        let context = test_context();
        let request = ListUsersRequest {
            tenant: tenant(),
            path_prefix: None,
            pagination: None,
        };
        let result = service.list_users(&context, request).await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn test_guard_update_user_denied() {
        let service = setup_guarded_service();
        let context = test_context();
        let request = UpdateUserRequest {
            user: key("alice"),
            new_user_name: Some("bob".to_string()),
            new_path: None,
        };
        let result = service.update_user(&context, request).await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn test_guard_tag_user_denied() {
        let service = setup_guarded_service();
        let context = test_context();
        let result = service
            .tag_user(
                &context,
                &key("alice"),
                vec![wami_core::types::Tag {
                    key: "Key".to_string(),
                    value: "Val".to_string(),
                }],
            )
            .await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn test_guard_untag_user_denied() {
        let service = setup_guarded_service();
        let context = test_context();
        let result = service
            .untag_user(&context, &key("alice"), vec!["Key".to_string()])
            .await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn test_guard_list_user_tags_denied() {
        let service = setup_guarded_service();
        let context = test_context();
        let result = service.list_user_tags(&context, &key("alice")).await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }
}
