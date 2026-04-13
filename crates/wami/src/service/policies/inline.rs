//! Inline Policy Service
//!
//! Service for managing inline policies on users, groups, and roles.

use crate::service::auth::authorizer::{iam_resource_arn, Authorizer};
use crate::store::traits::{GroupStore, RoleStore, UserStore};
use crate::wami::policies::inline::*;
use std::sync::{Arc, RwLock};
use wami_core::actions::WamiAction;
use wami_core::context::WamiContext;
use wami_core::error::{AmiError, Result};

pub trait InlinePolicyServiceStore: UserStore + GroupStore + RoleStore {}
impl<T> InlinePolicyServiceStore for T where T: UserStore + GroupStore + RoleStore {}

/// Service for managing inline policies
///
/// Optionally holds an [`Authorizer`] for authorization guards on every method.
#[wami_macros::service(
    store_trait = "crate::service::policies::inline::InlinePolicyServiceStore",
    generate_new = false
)]
pub struct InlinePolicyService<S> {
    store: Arc<RwLock<S>>,
    authz: Option<Arc<dyn Authorizer>>,
}

impl<S> InlinePolicyService<S>
where
    S: InlinePolicyServiceStore,
{
    /// Create a new InlinePolicyService without authorization guards (backward compatible).
    pub fn new(store: Arc<RwLock<S>>) -> Self {
        Self { store, authz: None }
    }

    /// Create a new InlinePolicyService with an authorization guard.
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

    // User inline policy methods

    /// Put an inline policy on a user
    pub async fn put_user_policy(
        &self,
        context: &WamiContext,
        request: PutUserPolicyRequest,
    ) -> Result<PutUserPolicyResponse> {
        self.guard(
            context,
            WamiAction::IamCreatePolicy,
            "user",
            &request.user_name,
        )
        .await?;

        let mut store = self.write_store();

        // Verify user exists
        store
            .get_user(&request.user_name)
            .await?
            .ok_or_else(|| AmiError::ResourceNotFound {
                resource: format!("User: {}", request.user_name),
            })?;

        // Validate policy document is valid JSON
        serde_json::from_str::<serde_json::Value>(&request.policy_document).map_err(|e| {
            AmiError::InvalidParameter {
                message: format!("Invalid policy document JSON: {}", e),
            }
        })?;

        // Put the inline policy
        store
            .put_user_policy(
                &request.user_name,
                &request.policy_name,
                request.policy_document,
            )
            .await?;

        Ok(PutUserPolicyResponse {
            message: format!(
                "Inline policy {} added to user {}",
                request.policy_name, request.user_name
            ),
        })
    }

    /// Get an inline policy from a user
    pub async fn get_user_policy(
        &self,
        context: &WamiContext,
        request: GetUserPolicyRequest,
    ) -> Result<GetUserPolicyResponse> {
        self.guard(
            context,
            WamiAction::IamReadPolicy,
            "user",
            &request.user_name,
        )
        .await?;

        let store = self.read_store();

        // Verify user exists
        store
            .get_user(&request.user_name)
            .await?
            .ok_or_else(|| AmiError::ResourceNotFound {
                resource: format!("User: {}", request.user_name),
            })?;

        // Get the inline policy
        let policy_document = store
            .get_user_policy(&request.user_name, &request.policy_name)
            .await?
            .ok_or_else(|| AmiError::ResourceNotFound {
                resource: format!(
                    "Policy {} for user {}",
                    request.policy_name, request.user_name
                ),
            })?;

        Ok(GetUserPolicyResponse {
            user_name: request.user_name,
            policy_name: request.policy_name,
            policy_document,
        })
    }

    /// Delete an inline policy from a user
    pub async fn delete_user_policy(
        &self,
        context: &WamiContext,
        request: DeleteUserPolicyRequest,
    ) -> Result<DeleteUserPolicyResponse> {
        self.guard(
            context,
            WamiAction::IamDeletePolicy,
            "user",
            &request.user_name,
        )
        .await?;

        let mut store = self.write_store();

        // Verify user exists
        store
            .get_user(&request.user_name)
            .await?
            .ok_or_else(|| AmiError::ResourceNotFound {
                resource: format!("User: {}", request.user_name),
            })?;

        // Delete the inline policy
        store
            .delete_user_policy(&request.user_name, &request.policy_name)
            .await?;

        Ok(DeleteUserPolicyResponse {
            message: format!(
                "Inline policy {} deleted from user {}",
                request.policy_name, request.user_name
            ),
        })
    }

    /// List inline policies for a user
    pub async fn list_user_policies(
        &self,
        context: &WamiContext,
        request: ListUserPoliciesRequest,
    ) -> Result<ListUserPoliciesResponse> {
        self.guard(
            context,
            WamiAction::IamReadPolicy,
            "user",
            &request.user_name,
        )
        .await?;

        let store = self.read_store();

        // Verify user exists
        store
            .get_user(&request.user_name)
            .await?
            .ok_or_else(|| AmiError::ResourceNotFound {
                resource: format!("User: {}", request.user_name),
            })?;

        // List the inline policies
        let policy_names = store.list_user_policies(&request.user_name).await?;

        Ok(ListUserPoliciesResponse { policy_names })
    }

    // Group inline policy methods

    /// Put an inline policy on a group
    pub async fn put_group_policy(
        &self,
        context: &WamiContext,
        request: PutGroupPolicyRequest,
    ) -> Result<PutGroupPolicyResponse> {
        self.guard(
            context,
            WamiAction::IamCreatePolicy,
            "group",
            &request.group_name,
        )
        .await?;

        let mut store = self.write_store();

        // Verify group exists
        store
            .get_group(&request.group_name)
            .await?
            .ok_or_else(|| AmiError::ResourceNotFound {
                resource: format!("Group: {}", request.group_name),
            })?;

        // Validate policy document is valid JSON
        serde_json::from_str::<serde_json::Value>(&request.policy_document).map_err(|e| {
            AmiError::InvalidParameter {
                message: format!("Invalid policy document JSON: {}", e),
            }
        })?;

        // Put the inline policy
        store
            .put_group_policy(
                &request.group_name,
                &request.policy_name,
                request.policy_document,
            )
            .await?;

        Ok(PutGroupPolicyResponse {
            message: format!(
                "Inline policy {} added to group {}",
                request.policy_name, request.group_name
            ),
        })
    }

    /// Get an inline policy from a group
    pub async fn get_group_policy(
        &self,
        context: &WamiContext,
        request: GetGroupPolicyRequest,
    ) -> Result<GetGroupPolicyResponse> {
        self.guard(
            context,
            WamiAction::IamReadPolicy,
            "group",
            &request.group_name,
        )
        .await?;

        let store = self.read_store();

        // Verify group exists
        store
            .get_group(&request.group_name)
            .await?
            .ok_or_else(|| AmiError::ResourceNotFound {
                resource: format!("Group: {}", request.group_name),
            })?;

        // Get the inline policy
        let policy_document = store
            .get_group_policy(&request.group_name, &request.policy_name)
            .await?
            .ok_or_else(|| AmiError::ResourceNotFound {
                resource: format!(
                    "Policy {} for group {}",
                    request.policy_name, request.group_name
                ),
            })?;

        Ok(GetGroupPolicyResponse {
            group_name: request.group_name,
            policy_name: request.policy_name,
            policy_document,
        })
    }

    /// Delete an inline policy from a group
    pub async fn delete_group_policy(
        &self,
        context: &WamiContext,
        request: DeleteGroupPolicyRequest,
    ) -> Result<DeleteGroupPolicyResponse> {
        self.guard(
            context,
            WamiAction::IamDeletePolicy,
            "group",
            &request.group_name,
        )
        .await?;

        let mut store = self.write_store();

        // Verify group exists
        store
            .get_group(&request.group_name)
            .await?
            .ok_or_else(|| AmiError::ResourceNotFound {
                resource: format!("Group: {}", request.group_name),
            })?;

        // Delete the inline policy
        store
            .delete_group_policy(&request.group_name, &request.policy_name)
            .await?;

        Ok(DeleteGroupPolicyResponse {
            message: format!(
                "Inline policy {} deleted from group {}",
                request.policy_name, request.group_name
            ),
        })
    }

    /// List inline policies for a group
    pub async fn list_group_policies(
        &self,
        context: &WamiContext,
        request: ListGroupPoliciesRequest,
    ) -> Result<ListGroupPoliciesResponse> {
        self.guard(
            context,
            WamiAction::IamReadPolicy,
            "group",
            &request.group_name,
        )
        .await?;

        let store = self.read_store();

        // Verify group exists
        store
            .get_group(&request.group_name)
            .await?
            .ok_or_else(|| AmiError::ResourceNotFound {
                resource: format!("Group: {}", request.group_name),
            })?;

        // List the inline policies
        let policy_names = store.list_group_policies(&request.group_name).await?;

        Ok(ListGroupPoliciesResponse { policy_names })
    }

    // Role inline policy methods

    /// Put an inline policy on a role
    pub async fn put_role_policy(
        &self,
        context: &WamiContext,
        request: PutRolePolicyRequest,
    ) -> Result<PutRolePolicyResponse> {
        self.guard(
            context,
            WamiAction::IamCreatePolicy,
            "role",
            &request.role_name,
        )
        .await?;

        let mut store = self.write_store();

        // Verify role exists
        store
            .get_role(&request.role_name)
            .await?
            .ok_or_else(|| AmiError::ResourceNotFound {
                resource: format!("Role: {}", request.role_name),
            })?;

        // Validate policy document is valid JSON
        serde_json::from_str::<serde_json::Value>(&request.policy_document).map_err(|e| {
            AmiError::InvalidParameter {
                message: format!("Invalid policy document JSON: {}", e),
            }
        })?;

        // Put the inline policy
        store
            .put_role_policy(
                &request.role_name,
                &request.policy_name,
                request.policy_document,
            )
            .await?;

        Ok(PutRolePolicyResponse {
            message: format!(
                "Inline policy {} added to role {}",
                request.policy_name, request.role_name
            ),
        })
    }

    /// Get an inline policy from a role
    pub async fn get_role_policy(
        &self,
        context: &WamiContext,
        request: GetRolePolicyRequest,
    ) -> Result<GetRolePolicyResponse> {
        self.guard(
            context,
            WamiAction::IamReadPolicy,
            "role",
            &request.role_name,
        )
        .await?;

        let store = self.read_store();

        // Verify role exists
        store
            .get_role(&request.role_name)
            .await?
            .ok_or_else(|| AmiError::ResourceNotFound {
                resource: format!("Role: {}", request.role_name),
            })?;

        // Get the inline policy
        let policy_document = store
            .get_role_policy(&request.role_name, &request.policy_name)
            .await?
            .ok_or_else(|| AmiError::ResourceNotFound {
                resource: format!(
                    "Policy {} for role {}",
                    request.policy_name, request.role_name
                ),
            })?;

        Ok(GetRolePolicyResponse {
            role_name: request.role_name,
            policy_name: request.policy_name,
            policy_document,
        })
    }

    /// Delete an inline policy from a role
    pub async fn delete_role_policy(
        &self,
        context: &WamiContext,
        request: DeleteRolePolicyRequest,
    ) -> Result<DeleteRolePolicyResponse> {
        self.guard(
            context,
            WamiAction::IamDeletePolicy,
            "role",
            &request.role_name,
        )
        .await?;

        let mut store = self.write_store();

        // Verify role exists
        store
            .get_role(&request.role_name)
            .await?
            .ok_or_else(|| AmiError::ResourceNotFound {
                resource: format!("Role: {}", request.role_name),
            })?;

        // Delete the inline policy
        store
            .delete_role_policy(&request.role_name, &request.policy_name)
            .await?;

        Ok(DeleteRolePolicyResponse {
            message: format!(
                "Inline policy {} deleted from role {}",
                request.policy_name, request.role_name
            ),
        })
    }

    /// List inline policies for a role
    pub async fn list_role_policies(
        &self,
        context: &WamiContext,
        request: ListRolePoliciesRequest,
    ) -> Result<ListRolePoliciesResponse> {
        self.guard(
            context,
            WamiAction::IamReadPolicy,
            "role",
            &request.role_name,
        )
        .await?;

        let store = self.read_store();

        // Verify role exists
        store
            .get_role(&request.role_name)
            .await?
            .ok_or_else(|| AmiError::ResourceNotFound {
                resource: format!("Role: {}", request.role_name),
            })?;

        // List the inline policies
        let policy_names = store.list_role_policies(&request.role_name).await?;

        Ok(ListRolePoliciesResponse { policy_names })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::memory::InMemoryWamiStore;
    use crate::wami::identity::group::builder::build_group;
    use crate::wami::identity::role::builder::build_role;
    use crate::wami::identity::user::builder::build_user;
    use std::sync::Arc;
    use wami_core::arn::{TenantPath, WamiArn};
    use wami_core::context::WamiContext;

    async fn create_test_context() -> WamiContext {
        WamiContext::builder()
            .instance_id("123456789012")
            .tenant_path(TenantPath::single(0))
            .caller_arn(
                WamiArn::builder()
                    .service(crate::arn::Service::Iam)
                    .tenant_path(TenantPath::single(0))
                    .wami_instance("123456789012")
                    .resource("user", "admin")
                    .build()
                    .unwrap(),
            )
            .is_root(false)
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn test_put_user_policy() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::new()));
        let service = InlinePolicyService::new(store.clone());
        let context = create_test_context().await;

        let user = build_user("alice".to_string(), Some("/".to_string()), &context).unwrap();
        let _created_user = store.write().unwrap().create_user(user).await.unwrap();

        let request = PutUserPolicyRequest {
            user_name: "alice".to_string(),
            policy_name: "MyInlinePolicy".to_string(),
            policy_document: r#"{"Version":"2012-10-17","Statement":[]}"#.to_string(),
        };
        let response = service.put_user_policy(&context, request).await.unwrap();
        assert!(response.message.contains("added"));
    }

    #[tokio::test]
    async fn test_get_user_policy() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::new()));
        let service = InlinePolicyService::new(store.clone());
        let context = create_test_context().await;

        let user = build_user("alice".to_string(), Some("/".to_string()), &context).unwrap();
        let _created_user = store.write().unwrap().create_user(user).await.unwrap();

        let put_request = PutUserPolicyRequest {
            user_name: "alice".to_string(),
            policy_name: "MyInlinePolicy".to_string(),
            policy_document: r#"{"Version":"2012-10-17","Statement":[]}"#.to_string(),
        };
        service
            .put_user_policy(&context, put_request)
            .await
            .unwrap();

        let get_request = GetUserPolicyRequest {
            user_name: "alice".to_string(),
            policy_name: "MyInlinePolicy".to_string(),
        };
        let response = service
            .get_user_policy(&context, get_request)
            .await
            .unwrap();
        assert_eq!(response.policy_name, "MyInlinePolicy");
        assert!(response.policy_document.contains("Version"));
    }

    #[tokio::test]
    async fn test_delete_user_policy() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::new()));
        let service = InlinePolicyService::new(store.clone());
        let context = create_test_context().await;

        let user = build_user("alice".to_string(), Some("/".to_string()), &context).unwrap();
        let _created_user = store.write().unwrap().create_user(user).await.unwrap();

        let put_request = PutUserPolicyRequest {
            user_name: "alice".to_string(),
            policy_name: "MyInlinePolicy".to_string(),
            policy_document: r#"{"Version":"2012-10-17","Statement":[]}"#.to_string(),
        };
        service
            .put_user_policy(&context, put_request)
            .await
            .unwrap();

        let delete_request = DeleteUserPolicyRequest {
            user_name: "alice".to_string(),
            policy_name: "MyInlinePolicy".to_string(),
        };
        let response = service
            .delete_user_policy(&context, delete_request)
            .await
            .unwrap();
        assert!(response.message.contains("deleted"));
    }

    #[tokio::test]
    async fn test_list_user_policies() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::new()));
        let service = InlinePolicyService::new(store.clone());
        let context = create_test_context().await;

        let user = build_user("alice".to_string(), Some("/".to_string()), &context).unwrap();
        let _created_user = store.write().unwrap().create_user(user).await.unwrap();

        let put_request1 = PutUserPolicyRequest {
            user_name: "alice".to_string(),
            policy_name: "Policy1".to_string(),
            policy_document: r#"{"Version":"2012-10-17","Statement":[]}"#.to_string(),
        };
        service
            .put_user_policy(&context, put_request1)
            .await
            .unwrap();

        let put_request2 = PutUserPolicyRequest {
            user_name: "alice".to_string(),
            policy_name: "Policy2".to_string(),
            policy_document: r#"{"Version":"2012-10-17","Statement":[]}"#.to_string(),
        };
        service
            .put_user_policy(&context, put_request2)
            .await
            .unwrap();

        let list_request = ListUserPoliciesRequest {
            user_name: "alice".to_string(),
        };
        let response = service
            .list_user_policies(&context, list_request)
            .await
            .unwrap();
        assert_eq!(response.policy_names.len(), 2);
    }

    #[tokio::test]
    async fn test_put_group_policy() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::new()));
        let service = InlinePolicyService::new(store.clone());
        let context = create_test_context().await;

        let group = build_group("developers".to_string(), Some("/".to_string()), &context).unwrap();
        let _created_group = store.write().unwrap().create_group(group).await.unwrap();

        let request = PutGroupPolicyRequest {
            group_name: "developers".to_string(),
            policy_name: "MyInlinePolicy".to_string(),
            policy_document: r#"{"Version":"2012-10-17","Statement":[]}"#.to_string(),
        };
        let response = service.put_group_policy(&context, request).await.unwrap();
        assert!(response.message.contains("added"));
    }

    #[tokio::test]
    async fn test_put_role_policy() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::new()));
        let service = InlinePolicyService::new(store.clone());
        let context = create_test_context().await;

        let role = build_role(
            "AdminRole".to_string(),
            r#"{"Version":"2012-10-17","Statement":[]}"#.to_string(),
            Some("/".to_string()),
            None,
            None,
            &context,
        )
        .unwrap();
        let _created_role = store.write().unwrap().create_role(role).await.unwrap();

        let request = PutRolePolicyRequest {
            role_name: "AdminRole".to_string(),
            policy_name: "MyInlinePolicy".to_string(),
            policy_document: r#"{"Version":"2012-10-17","Statement":[]}"#.to_string(),
        };
        let response = service.put_role_policy(&context, request).await.unwrap();
        assert!(response.message.contains("added"));
    }

    #[tokio::test]
    async fn test_invalid_json_policy() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::new()));
        let service = InlinePolicyService::new(store.clone());
        let context = create_test_context().await;

        let user = build_user("alice".to_string(), Some("/".to_string()), &context).unwrap();
        let _created_user = store.write().unwrap().create_user(user).await.unwrap();

        let request = PutUserPolicyRequest {
            user_name: "alice".to_string(),
            policy_name: "MyInlinePolicy".to_string(),
            policy_document: "invalid json".to_string(),
        };
        let result = service.put_user_policy(&context, request).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AmiError::InvalidParameter { .. }
        ));
    }

    // ========== Error Path Tests ==========

    #[tokio::test]
    async fn test_put_user_policy_nonexistent_user() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::new()));
        let service = InlinePolicyService::new(store);
        let context = create_test_context().await;

        let request = PutUserPolicyRequest {
            user_name: "nonexistent".to_string(),
            policy_name: "Policy".to_string(),
            policy_document: r#"{"Version":"2012-10-17"}"#.to_string(),
        };

        let result = service.put_user_policy(&context, request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_user_policy_nonexistent_user() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::new()));
        let service = InlinePolicyService::new(store);
        let context = create_test_context().await;

        let request = GetUserPolicyRequest {
            user_name: "nonexistent".to_string(),
            policy_name: "Policy".to_string(),
        };

        let result = service.get_user_policy(&context, request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_user_policy_nonexistent_policy() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::new()));
        let service = InlinePolicyService::new(store.clone());
        let context = create_test_context().await;

        let user = build_user("alice".to_string(), Some("/".to_string()), &context).unwrap();
        let _created_user = store.write().unwrap().create_user(user).await.unwrap();

        let request = GetUserPolicyRequest {
            user_name: "alice".to_string(),
            policy_name: "NonexistentPolicy".to_string(),
        };

        let result = service.get_user_policy(&context, request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_delete_user_policy_nonexistent_user() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::new()));
        let service = InlinePolicyService::new(store);
        let context = create_test_context().await;

        let request = DeleteUserPolicyRequest {
            user_name: "nonexistent".to_string(),
            policy_name: "Policy".to_string(),
        };

        let result = service.delete_user_policy(&context, request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_list_user_policies_nonexistent_user() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::new()));
        let service = InlinePolicyService::new(store);
        let context = create_test_context().await;

        let request = ListUserPoliciesRequest {
            user_name: "nonexistent".to_string(),
        };

        let result = service.list_user_policies(&context, request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_put_group_policy_nonexistent_group() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::new()));
        let service = InlinePolicyService::new(store);
        let context = create_test_context().await;

        let request = PutGroupPolicyRequest {
            group_name: "nonexistent".to_string(),
            policy_name: "Policy".to_string(),
            policy_document: r#"{"Version":"2012-10-17"}"#.to_string(),
        };

        let result = service.put_group_policy(&context, request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_put_role_policy_nonexistent_role() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::new()));
        let service = InlinePolicyService::new(store);
        let context = create_test_context().await;

        let request = PutRolePolicyRequest {
            role_name: "nonexistent".to_string(),
            policy_name: "Policy".to_string(),
            policy_document: r#"{"Version":"2012-10-17"}"#.to_string(),
        };

        let result = service.put_role_policy(&context, request).await;
        assert!(result.is_err());
    }

    // ─── Authorization guard tests ────────────────────────────

    use crate::service::auth::authorizer::Authorizer;
    use async_trait::async_trait;

    /// Mock authorizer that always allows.
    struct AllowAllAuthorizer;

    #[async_trait]
    impl Authorizer for AllowAllAuthorizer {
        async fn authorize(
            &self,
            _context: &WamiContext,
            _action: &str,
            _resource_arn: &WamiArn,
        ) -> wami_core::error::Result<bool> {
            Ok(true)
        }
        async fn check_or_deny(
            &self,
            _context: &WamiContext,
            _action: &str,
            _resource_arn: &WamiArn,
        ) -> wami_core::error::Result<()> {
            Ok(())
        }
    }

    /// Mock authorizer that always denies.
    struct DenyAllAuthorizer;

    #[async_trait]
    impl Authorizer for DenyAllAuthorizer {
        async fn authorize(
            &self,
            _context: &WamiContext,
            _action: &str,
            _resource_arn: &WamiArn,
        ) -> wami_core::error::Result<bool> {
            Ok(false)
        }
        async fn check_or_deny(
            &self,
            _context: &WamiContext,
            _action: &str,
            _resource_arn: &WamiArn,
        ) -> wami_core::error::Result<()> {
            Err(wami_core::error::AmiError::AccessDenied {
                message: "denied by mock".to_string(),
            })
        }
    }

    #[tokio::test]
    async fn test_guard_allows_with_authorizer() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::new()));
        let service =
            InlinePolicyService::with_authorizer(store.clone(), Arc::new(AllowAllAuthorizer));
        let context = create_test_context().await;

        // Create user so the store operation can succeed
        let user = build_user("alice".to_string(), Some("/".to_string()), &context).unwrap();
        store.write().unwrap().create_user(user).await.unwrap();

        let request = PutUserPolicyRequest {
            user_name: "alice".to_string(),
            policy_name: "TestPolicy".to_string(),
            policy_document: r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["*"],"Resource":["*"]}]}"#.to_string(),
        };

        let result = service.put_user_policy(&context, request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_guard_denies_with_authorizer() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::new()));
        let service =
            InlinePolicyService::with_authorizer(store.clone(), Arc::new(DenyAllAuthorizer));
        let context = create_test_context().await;

        let request = PutUserPolicyRequest {
            user_name: "alice".to_string(),
            policy_name: "TestPolicy".to_string(),
            policy_document: r#"{"Version":"2012-10-17"}"#.to_string(),
        };

        let result = service.put_user_policy(&context, request).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, wami_core::error::AmiError::AccessDenied { .. }),
            "Expected AccessDenied, got: {:?}",
            err
        );
    }

    #[tokio::test]
    async fn test_guard_get_user_policy_denied() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::new()));
        let service =
            InlinePolicyService::with_authorizer(store.clone(), Arc::new(DenyAllAuthorizer));
        let context = create_test_context().await;

        let request = GetUserPolicyRequest {
            user_name: "alice".to_string(),
            policy_name: "TestPolicy".to_string(),
        };

        let result = service.get_user_policy(&context, request).await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn test_guard_list_user_policies_denied() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::new()));
        let service =
            InlinePolicyService::with_authorizer(store.clone(), Arc::new(DenyAllAuthorizer));
        let context = create_test_context().await;

        let request = ListUserPoliciesRequest {
            user_name: "alice".to_string(),
        };

        let result = service.list_user_policies(&context, request).await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn test_guard_delete_user_policy_denied() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::new()));
        let service =
            InlinePolicyService::with_authorizer(store.clone(), Arc::new(DenyAllAuthorizer));
        let context = create_test_context().await;

        let request = DeleteUserPolicyRequest {
            user_name: "alice".to_string(),
            policy_name: "TestPolicy".to_string(),
        };

        let result = service.delete_user_policy(&context, request).await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn test_guard_put_group_policy_denied() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::new()));
        let service =
            InlinePolicyService::with_authorizer(store.clone(), Arc::new(DenyAllAuthorizer));
        let context = create_test_context().await;

        let request = PutGroupPolicyRequest {
            group_name: "admins".to_string(),
            policy_name: "TestPolicy".to_string(),
            policy_document: r#"{"Version":"2012-10-17"}"#.to_string(),
        };

        let result = service.put_group_policy(&context, request).await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn test_guard_put_role_policy_denied() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::new()));
        let service =
            InlinePolicyService::with_authorizer(store.clone(), Arc::new(DenyAllAuthorizer));
        let context = create_test_context().await;

        let request = PutRolePolicyRequest {
            role_name: "admin-role".to_string(),
            policy_name: "TestPolicy".to_string(),
            policy_document: r#"{"Version":"2012-10-17"}"#.to_string(),
        };

        let result = service.put_role_policy(&context, request).await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }
}
