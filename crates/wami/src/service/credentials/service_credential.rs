//! Service Credential Service
//!
//! Orchestrates service-specific credential management operations.

use crate::credentials::service_credential::{
    builder as cred_builder, CreateServiceSpecificCredentialRequest,
    DeleteServiceSpecificCredentialRequest, ListServiceSpecificCredentialsRequest,
    ServiceSpecificCredential, UpdateServiceSpecificCredentialRequest,
};
use crate::service::auth::authorizer::{
    credential_found, guard, guard_by_id, guard_tenant, Authorizer,
};
use crate::store::traits::{ServiceCredentialStore, UserStore};
use std::sync::Arc;
use tokio::sync::RwLock;
use wami_core::actions::WamiAction;
use wami_core::context::WamiContext;
use wami_core::error::{AmiError, Result};

/// What the service credential service reads: the credentials, and their
/// owners.
pub trait ServiceCredentialServiceStore: ServiceCredentialStore + UserStore {}
impl<T> ServiceCredentialServiceStore for T where T: ServiceCredentialStore + UserStore {}

/// Service for managing IAM service-specific credentials
///
/// Provides high-level operations for AWS service credentials (e.g., CodeCommit).
/// Optionally holds an [`Authorizer`] for authorization guards on every method.
#[wami_macros::service(
    store_trait = "crate::service::credentials::service_credential::ServiceCredentialServiceStore",
    generate_new = false
)]
pub struct ServiceCredentialService<S> {
    store: Arc<RwLock<S>>,
    authz: Option<Arc<dyn Authorizer>>,
}

impl<S: ServiceCredentialServiceStore> ServiceCredentialService<S> {
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

    /// Create a new service-specific credential
    pub async fn create_service_specific_credential(
        &self,
        context: &WamiContext,
        request: CreateServiceSpecificCredentialRequest,
    ) -> Result<ServiceSpecificCredential> {
        guard(
            self.authz.as_ref(),
            context,
            WamiAction::IamManageCredentials,
            "user",
            &request.user,
        )
        .await?;
        let owner = super::read_owner(&*self.read_store().await, context, &request.user).await?;
        let credential =
            cred_builder::build_service_credential(&owner, request.service_name, context)?;

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
        self.read_judged(context, credential_id, None).await
    }

    /// Read the credential stored under `credential_id`, then judge its
    /// OWNER; an absent id and a denied owner are one refusal (A1). When the
    /// request names a user, the stored owner must be that user.
    async fn read_judged(
        &self,
        context: &WamiContext,
        credential_id: &str,
        named: Option<&wami_core::arn::ScopedName>,
    ) -> Result<Option<ServiceSpecificCredential>> {
        let credential = self
            .read_store()
            .await
            .get_service_specific_credential(credential_id)
            .await?;
        let owner = credential.as_ref().map(|c| {
            credential_found(
                context,
                &c.owner,
                credential_id,
                &c.wami_arn.wami_instance_id,
            )
        });
        guard_by_id(
            self.authz.as_ref(),
            context,
            WamiAction::IamManageCredentials,
            "service credential",
            credential_id,
            owner,
        )
        .await?;
        if let (Some(credential), Some(named)) = (&credential, named) {
            if &credential.owner != named {
                return Err(AmiError::InvalidParameter {
                    message: format!(
                        "service credential {credential_id} does not belong to {named}"
                    ),
                });
            }
        }
        Ok(credential)
    }

    /// Update a service-specific credential status
    pub async fn update_service_specific_credential(
        &self,
        context: &WamiContext,
        request: UpdateServiceSpecificCredentialRequest,
    ) -> Result<ServiceSpecificCredential> {
        let mut credential = self
            .read_judged(
                context,
                &request.service_specific_credential_id,
                Some(&request.user),
            )
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
        self.read_judged(
            context,
            &request.service_specific_credential_id,
            Some(&request.user),
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
        match &request.user {
            Some(user) => {
                if user.tenant() != &request.tenant {
                    return Err(AmiError::InvalidParameter {
                        message: format!("{user} is not of tenant {}", request.tenant),
                    });
                }
                guard(
                    self.authz.as_ref(),
                    context,
                    WamiAction::IamManageCredentials,
                    "user",
                    user,
                )
                .await?;
            }
            None => {
                guard_tenant(
                    self.authz.as_ref(),
                    context,
                    WamiAction::IamManageCredentials,
                    "user",
                    &request.tenant,
                )
                .await?;
            }
        }
        self.read_store()
            .await
            .list_service_specific_credentials(&request.tenant, request.user.as_ref())
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::auth::decision::{Decision, DenyReason};
    use crate::store::memory::InMemoryWamiStore;
    use wami_core::arn::{TenantPath, WamiArn};

    /// The tenant every test here works in.
    fn tenant() -> wami_core::arn::TenantPath {
        wami_core::arn::TenantPath::single(12345678)
    }

    /// `name`'s key in that tenant.
    fn key(name: impl AsRef<str>) -> wami_core::arn::ScopedName {
        wami_core::arn::ScopedName::new(tenant(), name.as_ref())
    }

    /// A service over a store holding the users the tests mint credentials
    /// for: a credential is only ever minted for a user that is there.
    async fn setup_service() -> ServiceCredentialService<InMemoryWamiStore> {
        use crate::store::traits::UserStore;
        let mut seeded = InMemoryWamiStore::default();
        for name in ["alice", "bob", "charlie", "david"] {
            let user =
                crate::wami::identity::user::builder::build_user(&key(name), None, &test_context())
                    .unwrap();
            seeded.create_user(user).await.unwrap();
        }
        ServiceCredentialService::new(Arc::new(RwLock::new(seeded)))
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
        let service = setup_service().await;
        let context = test_context();

        let request = CreateServiceSpecificCredentialRequest {
            user: key("alice"),
            service_name: "codecommit.amazonaws.com".to_string(),
        };

        let credential = service
            .create_service_specific_credential(&context, request)
            .await
            .unwrap();
        assert_eq!(credential.owner.name(), "alice");
        assert_eq!(credential.service_name, "codecommit.amazonaws.com");

        let retrieved = service
            .get_service_specific_credential(&context, &credential.service_specific_credential_id)
            .await
            .unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().owner.name(), "alice");
    }

    #[tokio::test]
    async fn test_update_service_credential_status() {
        let service = setup_service().await;
        let context = test_context();

        let create_req = CreateServiceSpecificCredentialRequest {
            user: key("bob"),
            service_name: "codecommit.amazonaws.com".to_string(),
        };
        let credential = service
            .create_service_specific_credential(&context, create_req)
            .await
            .unwrap();

        let update_req = UpdateServiceSpecificCredentialRequest {
            user: key("bob"),
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
        let service = setup_service().await;
        let context = test_context();

        let create_req = CreateServiceSpecificCredentialRequest {
            user: key("charlie"),
            service_name: "codecommit.amazonaws.com".to_string(),
        };
        let credential = service
            .create_service_specific_credential(&context, create_req)
            .await
            .unwrap();

        let delete_req = DeleteServiceSpecificCredentialRequest {
            user: key("charlie"),
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
        let service = setup_service().await;
        let context = test_context();

        // Create multiple credentials for same user
        for _ in 0..3 {
            let request = CreateServiceSpecificCredentialRequest {
                user: key("david"),
                service_name: "codecommit.amazonaws.com".to_string(),
            };
            service
                .create_service_specific_credential(&context, request)
                .await
                .unwrap();
        }

        let list_request = ListServiceSpecificCredentialsRequest {
            tenant: tenant(),
            user: Some(key("david")),
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
            user: key("alice"),
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
            user: key("alice"),
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
            user: key("alice"),
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
            tenant: tenant(),
            user: Some(key("alice")),
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
