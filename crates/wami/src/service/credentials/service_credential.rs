//! Service Credential Service
//!
//! Orchestrates service-specific credential management operations.

use crate::credentials::service_credential::{
    builder as cred_builder, CreateServiceSpecificCredentialRequest,
    DeleteServiceSpecificCredentialRequest, ListServiceSpecificCredentialsRequest,
    ServiceSpecificCredential, UpdateServiceSpecificCredentialRequest,
};
use crate::service::auth::authorizer::{iam_resource_arn, Authorizer};
use crate::store::traits::ServiceCredentialStore;
use std::sync::Arc;
use tokio::sync::RwLock;
use wami_core::actions::WamiAction;
use wami_core::context::WamiContext;
use wami_core::error::Result;

/// Service for managing IAM service-specific credentials
///
/// Provides high-level operations for AWS service credentials (e.g., CodeCommit).
/// Optionally holds an [`Authorizer`] for authorization guards on every method.
#[wami_macros::service(
    store_trait = "crate::store::traits::ServiceCredentialStore",
    generate_new = false
)]
pub struct ServiceCredentialService<S> {
    store: Arc<RwLock<S>>,
    authz: Option<Arc<dyn Authorizer>>,
}

impl<S: ServiceCredentialStore> ServiceCredentialService<S> {
    /// Create a new ServiceCredentialService without authorization guards (backward compatible).
    pub fn new(store: Arc<RwLock<S>>) -> Self {
        Self { store, authz: None }
    }

    /// Create a new ServiceCredentialService with an authorization guard.
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

    /// Create a new service-specific credential
    pub async fn create_service_specific_credential(
        &self,
        context: &WamiContext,
        request: CreateServiceSpecificCredentialRequest,
    ) -> Result<ServiceSpecificCredential> {
        // Authorization guard
        self.guard(
            context,
            WamiAction::IamManageCredentials,
            "user",
            &request.user_name,
        )
        .await?;

        // Use wami builder to create credential
        let credential = cred_builder::build_service_credential(
            request.user_name,
            request.service_name,
            context,
        )?;

        // Store it
        self.write_store()
            .await
            .create_service_specific_credential(credential)
            .await
    }

    /// Get a service-specific credential by ID
    pub async fn get_service_specific_credential(
        &self,
        context: &WamiContext,
        credential_id: &str,
    ) -> Result<Option<ServiceSpecificCredential>> {
        self.guard(
            context,
            WamiAction::IamManageCredentials,
            "credential",
            credential_id,
        )
        .await?;
        self.read_store()
            .await
            .get_service_specific_credential(credential_id)
            .await
    }

    /// Update a service-specific credential status
    pub async fn update_service_specific_credential(
        &self,
        context: &WamiContext,
        request: UpdateServiceSpecificCredentialRequest,
    ) -> Result<ServiceSpecificCredential> {
        self.guard(
            context,
            WamiAction::IamManageCredentials,
            "user",
            &request.user_name,
        )
        .await?;

        // Get existing credential
        let mut credential = self
            .read_store()
            .await
            .get_service_specific_credential(&request.service_specific_credential_id)
            .await?
            .ok_or_else(|| crate::error::AmiError::ResourceNotFound {
                resource: format!(
                    "ServiceSpecificCredential: {}",
                    request.service_specific_credential_id
                ),
            })?;

        // Apply updates
        credential.status = request.status;

        // Store updated credential
        self.write_store()
            .await
            .update_service_specific_credential(credential)
            .await
    }

    /// Delete a service-specific credential
    pub async fn delete_service_specific_credential(
        &self,
        context: &WamiContext,
        request: DeleteServiceSpecificCredentialRequest,
    ) -> Result<()> {
        self.guard(
            context,
            WamiAction::IamManageCredentials,
            "user",
            &request.user_name,
        )
        .await?;
        self.write_store()
            .await
            .delete_service_specific_credential(&request.service_specific_credential_id)
            .await
    }

    /// List service-specific credentials for a user
    pub async fn list_service_specific_credentials(
        &self,
        context: &WamiContext,
        request: ListServiceSpecificCredentialsRequest,
    ) -> Result<Vec<ServiceSpecificCredential>> {
        let user_name = request.user_name.as_deref().unwrap_or("");
        self.guard(
            context,
            WamiAction::IamManageCredentials,
            "user",
            if user_name.is_empty() { "*" } else { user_name },
        )
        .await?;
        self.read_store()
            .await
            .list_service_specific_credentials(user_name)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::auth::decision::{Decision, DenyReason};
    use crate::store::memory::InMemoryWamiStore;
    use wami_core::arn::{TenantPath, WamiArn};

    fn setup_service() -> ServiceCredentialService<InMemoryWamiStore> {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        ServiceCredentialService::new(store)
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
    async fn test_create_and_get_service_credential() {
        let service = setup_service();
        let context = test_context();

        let request = CreateServiceSpecificCredentialRequest {
            user_name: "alice".to_string(),
            service_name: "codecommit.amazonaws.com".to_string(),
        };

        let credential = service
            .create_service_specific_credential(&context, request)
            .await
            .unwrap();
        assert_eq!(credential.user_name, "alice");
        assert_eq!(credential.service_name, "codecommit.amazonaws.com");

        let retrieved = service
            .get_service_specific_credential(&context, &credential.service_specific_credential_id)
            .await
            .unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().user_name, "alice");
    }

    #[tokio::test]
    async fn test_update_service_credential_status() {
        let service = setup_service();
        let context = test_context();

        let create_req = CreateServiceSpecificCredentialRequest {
            user_name: "bob".to_string(),
            service_name: "codecommit.amazonaws.com".to_string(),
        };
        let credential = service
            .create_service_specific_credential(&context, create_req)
            .await
            .unwrap();

        let update_req = UpdateServiceSpecificCredentialRequest {
            user_name: "bob".to_string(),
            service_specific_credential_id: credential.service_specific_credential_id.clone(),
            status: "Inactive".to_string(),
        };
        let updated = service
            .update_service_specific_credential(&context, update_req)
            .await
            .unwrap();
        assert_eq!(updated.status, "Inactive");
    }

    #[tokio::test]
    async fn test_delete_service_credential() {
        let service = setup_service();
        let context = test_context();

        let create_req = CreateServiceSpecificCredentialRequest {
            user_name: "charlie".to_string(),
            service_name: "codecommit.amazonaws.com".to_string(),
        };
        let credential = service
            .create_service_specific_credential(&context, create_req)
            .await
            .unwrap();

        let delete_req = DeleteServiceSpecificCredentialRequest {
            user_name: "charlie".to_string(),
            service_specific_credential_id: credential.service_specific_credential_id.clone(),
        };
        service
            .delete_service_specific_credential(&context, delete_req)
            .await
            .unwrap();

        let retrieved = service
            .get_service_specific_credential(&context, &credential.service_specific_credential_id)
            .await
            .unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_list_service_credentials() {
        let service = setup_service();
        let context = test_context();

        // Create multiple credentials for same user
        for _ in 0..3 {
            let request = CreateServiceSpecificCredentialRequest {
                user_name: "david".to_string(),
                service_name: "codecommit.amazonaws.com".to_string(),
            };
            service
                .create_service_specific_credential(&context, request)
                .await
                .unwrap();
        }

        let list_request = ListServiceSpecificCredentialsRequest {
            user_name: Some("david".to_string()),
            service_name: None,
        };
        let credentials = service
            .list_service_specific_credentials(&context, list_request)
            .await
            .unwrap();
        assert_eq!(credentials.len(), 3);
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
    async fn test_guard_create_service_specific_credential_denied() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let service = ServiceCredentialService::with_authorizer(store, Arc::new(DenyAllAuthorizer));
        let context = test_context();

        let request = CreateServiceSpecificCredentialRequest {
            user_name: "alice".to_string(),
            service_name: "codecommit.amazonaws.com".to_string(),
        };

        let result = service
            .create_service_specific_credential(&context, request)
            .await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn test_guard_get_service_specific_credential_denied() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let service = ServiceCredentialService::with_authorizer(store, Arc::new(DenyAllAuthorizer));
        let context = test_context();

        let result = service
            .get_service_specific_credential(&context, "some-id")
            .await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn test_guard_update_service_specific_credential_denied() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let service = ServiceCredentialService::with_authorizer(store, Arc::new(DenyAllAuthorizer));
        let context = test_context();

        let request = UpdateServiceSpecificCredentialRequest {
            user_name: "alice".to_string(),
            service_specific_credential_id: "some-id".to_string(),
            status: "Inactive".to_string(),
        };

        let result = service
            .update_service_specific_credential(&context, request)
            .await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn test_guard_delete_service_specific_credential_denied() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let service = ServiceCredentialService::with_authorizer(store, Arc::new(DenyAllAuthorizer));
        let context = test_context();

        let request = DeleteServiceSpecificCredentialRequest {
            user_name: "alice".to_string(),
            service_specific_credential_id: "some-id".to_string(),
        };

        let result = service
            .delete_service_specific_credential(&context, request)
            .await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn test_guard_list_service_specific_credentials_denied() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let service = ServiceCredentialService::with_authorizer(store, Arc::new(DenyAllAuthorizer));
        let context = test_context();

        let request = ListServiceSpecificCredentialsRequest {
            user_name: Some("alice".to_string()),
            service_name: None,
        };

        let result = service
            .list_service_specific_credentials(&context, request)
            .await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }
}
