//! Service-Linked Role Service
//!
//! Orchestrates service-linked role management operations.

use crate::service::auth::authorizer::{iam_resource_arn, Authorizer};
use crate::store::traits::{RoleStore, ServiceLinkedRoleStore};
use crate::wami::identity::role::builder as role_builder;
use crate::wami::identity::service_linked_role::{
    operations as slr_ops, CreateServiceLinkedRoleRequest, DeletionTaskInfo,
};
use crate::wami::identity::Role;
use std::sync::{Arc, RwLock};
use wami_core::actions::WamiAction;
use wami_core::context::WamiContext;
use wami_core::error::Result;

pub trait ServiceLinkedRoleServiceStore: RoleStore + ServiceLinkedRoleStore {}
impl<T> ServiceLinkedRoleServiceStore for T where T: RoleStore + ServiceLinkedRoleStore {}

/// Service for managing service-linked roles
///
/// Service-linked roles are predefined AWS roles that are linked to specific AWS services.
#[wami_macros::service(
    store_trait = "crate::service::identity::service_linked_role::ServiceLinkedRoleServiceStore",
    generate_new = false
)]
pub struct ServiceLinkedRoleService<S> {
    store: Arc<RwLock<S>>,
    authz: Option<Arc<dyn Authorizer>>,
}

impl<S: ServiceLinkedRoleServiceStore> ServiceLinkedRoleService<S> {
    pub fn new(store: Arc<RwLock<S>>) -> Self {
        Self { store, authz: None }
    }

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

    /// Create a service-linked role
    pub async fn create_service_linked_role(
        &self,
        context: &WamiContext,
        request: CreateServiceLinkedRoleRequest,
    ) -> Result<Role> {
        self.guard(
            context,
            WamiAction::IamCreateRole,
            "role",
            &request.aws_service_name,
        )
        .await?;

        slr_ops::service_linked_role_operations::validate_service_name(&request.aws_service_name)?;

        if let Some(ref suffix) = request.custom_suffix {
            slr_ops::service_linked_role_operations::validate_custom_suffix(suffix)?;
        }

        let role_name = slr_ops::service_linked_role_operations::generate_role_name(
            &request.aws_service_name,
            request.custom_suffix.as_deref(),
        );

        let path = "/aws-service-role/".to_string() + &request.aws_service_name + "/";

        let assume_role_policy = format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"Service":"{}"}},"Action":"sts:AssumeRole"}}]}}"#,
            request.aws_service_name
        );

        let role = role_builder::build_role(
            role_name,
            assume_role_policy,
            Some(path),
            request.description,
            None,
            context,
        )?;

        self.write_store().create_role(role).await
    }

    /// Get the status of a service-linked role deletion task
    pub async fn get_service_linked_role_deletion_task(
        &self,
        context: &WamiContext,
        deletion_task_id: &str,
    ) -> Result<Option<DeletionTaskInfo>> {
        self.guard(context, WamiAction::IamReadRole, "role", deletion_task_id)
            .await?;
        self.store
            .read()
            .unwrap()
            .get_service_linked_role_deletion_task(deletion_task_id)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::memory::InMemoryWamiStore;
    use wami_core::arn::{TenantPath, WamiArn};
    use wami_core::context::WamiContext;

    fn setup_service() -> ServiceLinkedRoleService<InMemoryWamiStore> {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        ServiceLinkedRoleService::new(store)
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
    async fn test_create_service_linked_role() {
        let service = setup_service();
        let context = test_context();

        let request = CreateServiceLinkedRoleRequest {
            aws_service_name: "elasticbeanstalk.amazonaws.com".to_string(),
            description: Some("Service-linked role for Elastic Beanstalk".to_string()),
            custom_suffix: None,
        };

        let role = service
            .create_service_linked_role(&context, request)
            .await
            .unwrap();
        assert!(role.role_name.contains("AWSServiceRoleForElasticbeanstalk"));
        assert_eq!(
            role.path,
            "/aws-service-role/elasticbeanstalk.amazonaws.com/"
        );
    }

    #[tokio::test]
    async fn test_create_service_linked_role_with_custom_suffix() {
        let service = setup_service();
        let context = test_context();

        let request = CreateServiceLinkedRoleRequest {
            aws_service_name: "autoscaling.amazonaws.com".to_string(),
            description: None,
            custom_suffix: Some("MyApp".to_string()),
        };

        let role = service
            .create_service_linked_role(&context, request)
            .await
            .unwrap();
        assert!(role.role_name.contains("MyApp"));
    }

    #[tokio::test]
    async fn test_create_service_linked_role_invalid_service() {
        let service = setup_service();
        let context = test_context();

        let request = CreateServiceLinkedRoleRequest {
            aws_service_name: "invalid-service".to_string(),
            description: None,
            custom_suffix: None,
        };

        let result = service.create_service_linked_role(&context, request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_deletion_task() {
        let service = setup_service();
        let context = test_context();

        let request = CreateServiceLinkedRoleRequest {
            aws_service_name: "elasticbeanstalk.amazonaws.com".to_string(),
            description: None,
            custom_suffix: None,
        };
        service
            .create_service_linked_role(&context, request)
            .await
            .unwrap();

        let task = service
            .get_service_linked_role_deletion_task(&context, "task-123")
            .await
            .unwrap();
        assert!(task.is_none());
    }
}
