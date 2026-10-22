//! Role Service
//!
//! Orchestrates role management operations.

use crate::service::auth::authorizer::{confirm, guard, guard_tenant, Authorizer};
use crate::store::traits::{PolicyStore, RoleStore};

/// What the role service reads: the roles, and the policies a boundary
/// given at create names (review round 1, Δ5).
pub trait RoleServiceStore: RoleStore + PolicyStore {}
impl<T> RoleServiceStore for T where T: RoleStore + PolicyStore {}
use crate::wami::identity::role::{
    builder as role_builder, CreateRoleRequest, ListRolesRequest, Role, UpdateRoleRequest,
};
use std::sync::Arc;
use tokio::sync::RwLock;
use wami_core::actions::WamiAction;
use wami_core::arn::ScopedName;
use wami_core::context::WamiContext;
use wami_core::error::Result;

/// Service for managing IAM roles
///
/// Provides high-level operations for role management.
#[wami_macros::service(
    store_trait = "crate::service::identity::role::RoleServiceStore",
    generate_new = false
)]
pub struct RoleService<S> {
    store: Arc<RwLock<S>>,
    authz: Option<Arc<dyn Authorizer>>,
}

impl<S: RoleServiceStore> RoleService<S> {
    pub fn new(store: Arc<RwLock<S>>) -> Self {
        Self { store, authz: None }
    }

    pub fn with_authorizer(store: Arc<RwLock<S>>, authz: Arc<dyn Authorizer>) -> Self {
        Self {
            store,
            authz: Some(authz),
        }
    }

    /// Create a new role
    pub async fn create_role(
        &self,
        context: &WamiContext,
        request: CreateRoleRequest,
    ) -> Result<Role> {
        guard(
            self.authz.as_ref(),
            context,
            WamiAction::IamCreateRole,
            "role",
            &request.role,
        )
        .await?;

        let mut role = role_builder::build_role(
            &request.role,
            request.assume_role_policy_document,
            request.path,
            request.description,
            request.max_session_duration,
            context,
        )?;

        if let Some(boundary_arn) = request.permissions_boundary {
            // The checks every door setting a boundary runs: a stored policy
            // of the role's tenant, suitable as a boundary (Δ5); a foreign one
            // and an absent one answer alike (Δ6).
            crate::service::policies::permissions_boundary::boundary_policy(
                &*self.read_store().await,
                context,
                &boundary_arn,
                &request.role,
            )
            .await?;
            role = role_builder::set_permissions_boundary(role, boundary_arn);
        }

        let role = if let Some(tags) = request.tags {
            role_builder::add_tags(role, tags)
        } else {
            role
        };

        self.write_store().await.create_role(role).await
    }

    /// Get a role by name
    pub async fn get_role(&self, context: &WamiContext, role: &ScopedName) -> Result<Option<Role>> {
        guard(
            self.authz.as_ref(),
            context,
            WamiAction::IamReadRole,
            "role",
            role,
        )
        .await?;
        let found = self.read_store().await.get_role(role).await?;
        if let Some(found) = &found {
            confirm(
                context,
                "role",
                role,
                &found.key(),
                &found.wami_arn.wami_instance_id,
            )?;
        }
        Ok(found)
    }

    /// Update a role
    pub async fn update_role(
        &self,
        context: &WamiContext,
        request: UpdateRoleRequest,
    ) -> Result<Role> {
        guard(
            self.authz.as_ref(),
            context,
            WamiAction::IamCreateRole,
            "role",
            &request.role,
        )
        .await?;

        let mut role = self
            .store
            .read()
            .await
            .get_role(&request.role)
            .await?
            .ok_or_else(|| crate::error::AmiError::ResourceNotFound {
                resource: format!("Role: {}", request.role),
            })?;
        confirm(
            context,
            "role",
            &request.role,
            &role.key(),
            &role.wami_arn.wami_instance_id,
        )?;

        if let Some(description) = request.description {
            role = role_builder::update_description(role, Some(description));
        }

        if let Some(max_session_duration) = request.max_session_duration {
            role = role_builder::update_max_session_duration(role, max_session_duration);
        }

        self.write_store().await.update_role(role).await
    }

    /// Delete a role
    pub async fn delete_role(&self, context: &WamiContext, role: &ScopedName) -> Result<()> {
        guard(
            self.authz.as_ref(),
            context,
            WamiAction::IamDeleteRole,
            "role",
            role,
        )
        .await?;
        self.write_store().await.delete_role(role).await
    }

    /// List roles with optional filtering
    pub async fn list_roles(
        &self,
        context: &WamiContext,
        request: ListRolesRequest,
    ) -> Result<(Vec<Role>, bool, Option<String>)> {
        guard_tenant(
            self.authz.as_ref(),
            context,
            WamiAction::IamReadRole,
            "role",
            &request.tenant,
        )
        .await?;
        self.store
            .read()
            .await
            .list_roles(
                &request.tenant,
                request.path_prefix.as_deref(),
                request.pagination.as_ref(),
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::auth::decision::{Decision, DenyReason};
    use crate::store::memory::InMemoryWamiStore;
    use wami_core::arn::{TenantPath, WamiArn};
    use wami_core::context::WamiContext;
    use wami_core::types::Tag;

    /// The tenant every test of this module works in.
    fn tenant() -> wami_core::arn::TenantPath {
        wami_core::arn::TenantPath::single(12345678)
    }

    /// `name`'s key in that tenant.
    fn key(name: impl AsRef<str>) -> wami_core::arn::ScopedName {
        wami_core::arn::ScopedName::new(tenant(), name.as_ref())
    }

    fn setup_service() -> RoleService<InMemoryWamiStore> {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        RoleService::new(store)
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
    async fn test_create_and_get_role() {
        let service = setup_service();
        let context = test_context();

        let request = CreateRoleRequest {
            role: key("admin-role"),
            assume_role_policy_document: r#"{"Version":"2012-10-17","Statement":[]}"#.to_string(),
            path: Some("/admin/".to_string()),
            description: Some("Admin role".to_string()),
            max_session_duration: Some(3600),
            permissions_boundary: None,
            tags: None,
        };

        let role = service.create_role(&context, request).await.unwrap();
        assert_eq!(role.role_name, "admin-role");
        assert_eq!(role.path, "/admin/");
        assert_eq!(role.max_session_duration, Some(3600));

        let retrieved = service
            .get_role(&context, &key("admin-role"))
            .await
            .unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().role_name, "admin-role");
    }

    #[tokio::test]
    async fn test_update_role() {
        let service = setup_service();
        let context = test_context();

        let create_request = CreateRoleRequest {
            role: key("test-role"),
            assume_role_policy_document: r#"{"Version":"2012-10-17","Statement":[]}"#.to_string(),
            path: None,
            description: Some("Test role".to_string()),
            max_session_duration: Some(3600),
            permissions_boundary: None,
            tags: None,
        };
        service.create_role(&context, create_request).await.unwrap();

        let update_request = UpdateRoleRequest {
            role: key("test-role"),
            description: Some("Updated description".to_string()),
            max_session_duration: Some(7200),
        };
        let updated = service.update_role(&context, update_request).await.unwrap();
        assert_eq!(updated.description, Some("Updated description".to_string()));
        assert_eq!(updated.max_session_duration, Some(7200));
    }

    #[tokio::test]
    async fn test_delete_role() {
        let service = setup_service();
        let context = test_context();

        let request = CreateRoleRequest {
            role: key("temp-role"),
            assume_role_policy_document: r#"{"Version":"2012-10-17","Statement":[]}"#.to_string(),
            path: None,
            description: None,
            max_session_duration: None,
            permissions_boundary: None,
            tags: None,
        };
        service.create_role(&context, request).await.unwrap();

        service
            .delete_role(&context, &key("temp-role"))
            .await
            .unwrap();

        let retrieved = service.get_role(&context, &key("temp-role")).await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_list_roles() {
        let service = setup_service();
        let context = test_context();

        for name in ["role1", "role2", "role3"] {
            let request = CreateRoleRequest {
                role: key(name),
                assume_role_policy_document: r#"{"Version":"2012-10-17","Statement":[]}"#
                    .to_string(),
                path: Some("/test/".to_string()),
                description: None,
                max_session_duration: None,
                permissions_boundary: None,
                tags: None,
            };
            service.create_role(&context, request).await.unwrap();
        }

        let list_request = ListRolesRequest {
            tenant: tenant(),
            path_prefix: Some("/test/".to_string()),
            pagination: None,
        };
        let (roles, _, _) = service.list_roles(&context, list_request).await.unwrap();
        assert_eq!(roles.len(), 3);
    }

    #[tokio::test]
    async fn test_create_role_with_tags() {
        let service = setup_service();
        let context = test_context();

        let tags = vec![Tag {
            key: "Environment".to_string(),
            value: "Production".to_string(),
        }];

        let request = CreateRoleRequest {
            role: key("tagged-role"),
            assume_role_policy_document: r#"{"Version":"2012-10-17","Statement":[]}"#.to_string(),
            path: None,
            description: None,
            max_session_duration: None,
            permissions_boundary: None,
            tags: Some(tags.clone()),
        };

        let role = service.create_role(&context, request).await.unwrap();
        assert_eq!(role.tags.len(), 1);
        assert_eq!(role.tags[0].key, "Environment");
    }

    // ========== Authorization Guard Tests ==========

    use crate::service::auth::authorizer::Authorizer;
    use async_trait::async_trait;

    struct DenyAllAuthorizer;

    #[async_trait]
    impl Authorizer for DenyAllAuthorizer {
        async fn authorize(
            &self,
            _context: &WamiContext,
            _action: &str,
            _resource_arn: &WamiArn,
        ) -> wami_core::error::Result<Decision> {
            Ok(Decision::Deny(DenyReason::NoMatch))
        }
    }

    #[tokio::test]
    async fn test_guard_create_role_denied() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let service = RoleService::with_authorizer(store, Arc::new(DenyAllAuthorizer));
        let context = test_context();

        let request = CreateRoleRequest {
            role: key("admin-role"),
            assume_role_policy_document: r#"{"Version":"2012-10-17","Statement":[]}"#.to_string(),
            path: None,
            description: None,
            max_session_duration: None,
            permissions_boundary: None,
            tags: None,
        };

        let result = service.create_role(&context, request).await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn test_guard_get_role_denied() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let service = RoleService::with_authorizer(store, Arc::new(DenyAllAuthorizer));
        let context = test_context();

        let result = service.get_role(&context, &key("admin-role")).await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn test_guard_update_role_denied() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let service = RoleService::with_authorizer(store, Arc::new(DenyAllAuthorizer));
        let context = test_context();

        let request = UpdateRoleRequest {
            role: key("admin-role"),
            description: Some("Updated".to_string()),
            max_session_duration: None,
        };

        let result = service.update_role(&context, request).await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn test_guard_delete_role_denied() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let service = RoleService::with_authorizer(store, Arc::new(DenyAllAuthorizer));
        let context = test_context();

        let result = service.delete_role(&context, &key("admin-role")).await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn test_guard_list_roles_denied() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let service = RoleService::with_authorizer(store, Arc::new(DenyAllAuthorizer));
        let context = test_context();

        let request = ListRolesRequest {
            tenant: tenant(),
            path_prefix: None,
            pagination: None,
        };

        let result = service.list_roles(&context, request).await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }
}
