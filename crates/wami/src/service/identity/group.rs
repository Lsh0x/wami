//! Group Service
//!
//! Orchestrates group management operations including membership management.

use crate::service::auth::authorizer::{iam_resource_arn, Authorizer};
use crate::store::traits::GroupStore;
use crate::wami::identity::group::{
    builder as group_builder, CreateGroupRequest, Group, ListGroupsRequest, UpdateGroupRequest,
};
use std::sync::{Arc, RwLock};
use wami_core::actions::WamiAction;
use wami_core::context::WamiContext;
use wami_core::error::Result;

/// Service for managing IAM groups
///
/// Provides high-level operations for group management and membership.
#[wami_macros::service(store_trait = "crate::store::traits::GroupStore", generate_new = false)]
pub struct GroupService<S> {
    store: Arc<RwLock<S>>,
    authz: Option<Arc<dyn Authorizer>>,
}

impl<S: GroupStore> GroupService<S> {
    /// Create without authorization guards (backward compatible).
    pub fn new(store: Arc<RwLock<S>>) -> Self {
        Self { store, authz: None }
    }

    /// Create with an authorization guard.
    pub fn with_authorizer(store: Arc<RwLock<S>>, authz: Arc<dyn Authorizer>) -> Self {
        Self {
            store,
            authz: Some(authz),
        }
    }

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

    /// Create a new group
    pub async fn create_group(
        &self,
        context: &WamiContext,
        request: CreateGroupRequest,
    ) -> Result<Group> {
        self.guard(
            context,
            WamiAction::IamCreateGroup,
            "group",
            &request.group_name,
        )
        .await?;

        let group = group_builder::build_group(request.group_name, request.path, context)?;
        self.write_store().create_group(group).await
    }

    /// Get a group by name
    pub async fn get_group(
        &self,
        context: &WamiContext,
        group_name: &str,
    ) -> Result<Option<Group>> {
        self.guard(context, WamiAction::IamReadRole, "group", group_name)
            .await?;
        self.read_store().get_group(group_name).await
    }

    /// Update a group
    pub async fn update_group(
        &self,
        context: &WamiContext,
        request: UpdateGroupRequest,
    ) -> Result<Group> {
        self.guard(
            context,
            WamiAction::IamUpdateUser,
            "group",
            &request.group_name,
        )
        .await?;

        let mut group = self
            .read_store()
            .get_group(&request.group_name)
            .await?
            .ok_or_else(|| crate::error::AmiError::ResourceNotFound {
                resource: format!("Group: {}", request.group_name),
            })?;

        if let Some(new_group_name) = request.new_group_name {
            group = group_builder::update_group_name(group, new_group_name);
        }

        if let Some(new_path) = request.new_path {
            group = group_builder::update_group_path(group, new_path);
        }

        self.write_store().update_group(group).await
    }

    /// Delete a group
    pub async fn delete_group(&self, context: &WamiContext, group_name: &str) -> Result<()> {
        self.guard(context, WamiAction::IamDeleteGroup, "group", group_name)
            .await?;
        self.write_store().delete_group(group_name).await
    }

    /// List groups with optional filtering
    pub async fn list_groups(
        &self,
        context: &WamiContext,
        request: ListGroupsRequest,
    ) -> Result<(Vec<Group>, bool, Option<String>)> {
        self.guard(context, WamiAction::IamListUsers, "group", "*")
            .await?;
        self.read_store()
            .list_groups(request.path_prefix.as_deref(), request.pagination.as_ref())
            .await
    }

    /// Add a user to a group
    pub async fn add_user_to_group(
        &self,
        context: &WamiContext,
        group_name: &str,
        user_name: &str,
    ) -> Result<()> {
        self.guard(
            context,
            WamiAction::IamManageGroupMembers,
            "group",
            group_name,
        )
        .await?;
        self.write_store()
            .add_user_to_group(group_name, user_name)
            .await
    }

    /// Remove a user from a group
    pub async fn remove_user_from_group(
        &self,
        context: &WamiContext,
        group_name: &str,
        user_name: &str,
    ) -> Result<()> {
        self.guard(
            context,
            WamiAction::IamManageGroupMembers,
            "group",
            group_name,
        )
        .await?;
        self.write_store()
            .remove_user_from_group(group_name, user_name)
            .await
    }

    /// List all groups for a user
    pub async fn list_groups_for_user(
        &self,
        context: &WamiContext,
        user_name: &str,
    ) -> Result<Vec<Group>> {
        self.guard(context, WamiAction::IamReadUser, "user", user_name)
            .await?;
        self.read_store().list_groups_for_user(user_name).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::memory::InMemoryWamiStore;
    use crate::store::traits::UserStore;
    use crate::wami::identity::user::builder as user_builder;
    use wami_core::arn::{TenantPath, WamiArn};
    use wami_core::context::WamiContext;

    fn setup_service() -> GroupService<InMemoryWamiStore> {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        GroupService::new(store)
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
    async fn test_create_and_get_group() {
        let service = setup_service();
        let context = test_context();

        let request = CreateGroupRequest {
            group_name: "admins".to_string(),
            path: Some("/it/".to_string()),
            tags: None,
        };

        let group = service.create_group(&context, request).await.unwrap();
        assert_eq!(group.group_name, "admins");
        assert_eq!(group.path, "/it/");

        let retrieved = service.get_group(&context, "admins").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().group_name, "admins");
    }

    #[tokio::test]
    async fn test_update_group() {
        let service = setup_service();
        let context = test_context();

        let create_request = CreateGroupRequest {
            group_name: "developers".to_string(),
            path: Some("/".to_string()),
            tags: None,
        };
        service
            .create_group(&context, create_request)
            .await
            .unwrap();

        let update_request = UpdateGroupRequest {
            group_name: "developers".to_string(),
            new_group_name: Some("engineers".to_string()),
            new_path: Some("/tech/".to_string()),
        };
        let updated = service
            .update_group(&context, update_request)
            .await
            .unwrap();
        assert_eq!(updated.group_name, "engineers");
        assert_eq!(updated.path, "/tech/");
    }

    #[tokio::test]
    async fn test_delete_group() {
        let service = setup_service();
        let context = test_context();

        let request = CreateGroupRequest {
            group_name: "temp_group".to_string(),
            path: None,
            tags: None,
        };
        service.create_group(&context, request).await.unwrap();

        service.delete_group(&context, "temp_group").await.unwrap();

        let retrieved = service.get_group(&context, "temp_group").await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_list_groups() {
        let service = setup_service();
        let context = test_context();

        for name in ["group1", "group2", "group3"] {
            let request = CreateGroupRequest {
                group_name: name.to_string(),
                path: Some("/test/".to_string()),
                tags: None,
            };
            service.create_group(&context, request).await.unwrap();
        }

        let list_request = ListGroupsRequest {
            path_prefix: Some("/test/".to_string()),
            pagination: None,
        };
        let (groups, _, _) = service.list_groups(&context, list_request).await.unwrap();
        assert_eq!(groups.len(), 3);
    }

    #[tokio::test]
    async fn test_group_membership() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let service = GroupService::new(store.clone());
        let context = test_context();

        let user =
            user_builder::build_user("alice".to_string(), Some("/".to_string()), &context).unwrap();
        store.write().unwrap().create_user(user).await.unwrap();

        let request = CreateGroupRequest {
            group_name: "admins".to_string(),
            path: None,
            tags: None,
        };
        service.create_group(&context, request).await.unwrap();

        service
            .add_user_to_group(&context, "admins", "alice")
            .await
            .unwrap();

        let groups = service
            .list_groups_for_user(&context, "alice")
            .await
            .unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].group_name, "admins");

        service
            .remove_user_from_group(&context, "admins", "alice")
            .await
            .unwrap();

        let groups_after = service
            .list_groups_for_user(&context, "alice")
            .await
            .unwrap();
        assert_eq!(groups_after.len(), 0);
    }
}
