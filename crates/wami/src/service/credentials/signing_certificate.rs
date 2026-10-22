//! Signing Certificate Service
//!
//! Orchestrates signing certificate management operations.

use crate::credentials::signing_certificate::{
    builder as cert_builder, DeleteSigningCertificateRequest, ListSigningCertificatesRequest,
    SigningCertificate, UpdateSigningCertificateRequest, UploadSigningCertificateRequest,
};
use crate::service::auth::authorizer::{
    credential_found, guard, guard_by_id, guard_tenant, Authorizer,
};
use crate::store::traits::{SigningCertificateStore, UserStore};
use std::sync::Arc;
use tokio::sync::RwLock;
use wami_core::actions::WamiAction;
use wami_core::context::WamiContext;
use wami_core::error::{AmiError, Result};

/// What the signing certificate service reads: the certificates, and their
/// owners.
pub trait SigningCertificateServiceStore: SigningCertificateStore + UserStore {}
impl<T> SigningCertificateServiceStore for T where T: SigningCertificateStore + UserStore {}

/// Service for managing IAM signing certificates
///
/// Provides high-level operations for X.509 certificate management.
/// Optionally holds an [`Authorizer`] for authorization guards on every method.
#[wami_macros::service(
    store_trait = "crate::service::credentials::signing_certificate::SigningCertificateServiceStore",
    generate_new = false
)]
pub struct SigningCertificateService<S> {
    store: Arc<RwLock<S>>,
    authz: Option<Arc<dyn Authorizer>>,
}

impl<S: SigningCertificateServiceStore> SigningCertificateService<S> {
    /// Create a new SigningCertificateService without authorization guards (backward compatible).
    pub fn new(store: Arc<RwLock<S>>) -> Self {
        Self { store, authz: None }
    }

    /// Create a new SigningCertificateService with an authorization guard.
    pub fn with_authorizer(store: Arc<RwLock<S>>, authz: Arc<dyn Authorizer>) -> Self {
        Self {
            store,
            authz: Some(authz),
        }
    }

    /// Upload a new signing certificate
    pub async fn upload_signing_certificate(
        &self,
        context: &WamiContext,
        request: UploadSigningCertificateRequest,
    ) -> Result<SigningCertificate> {
        guard(
            self.authz.as_ref(),
            context,
            WamiAction::IamManageCredentials,
            "user",
            &request.user,
        )
        .await?;
        let owner = super::read_owner(&*self.read_store().await, context, &request.user).await?;
        let certificate =
            cert_builder::build_signing_certificate(&owner, request.certificate_body, context)?;

        // Store it
        self.write_store()
            .await
            .create_signing_certificate(certificate)
            .await
    }

    /// Get a signing certificate by ID
    pub async fn get_signing_certificate(
        &self,
        context: &WamiContext,
        certificate_id: &str,
    ) -> Result<Option<SigningCertificate>> {
        self.read_judged(context, certificate_id, None).await
    }

    /// Read the certificate stored under `certificate_id`, then judge its
    /// OWNER; an absent id and a denied owner are one refusal (A1). When the
    /// request names a user, the stored owner must be that user.
    async fn read_judged(
        &self,
        context: &WamiContext,
        certificate_id: &str,
        named: Option<&wami_core::arn::ScopedName>,
    ) -> Result<Option<SigningCertificate>> {
        let certificate = self
            .read_store()
            .await
            .get_signing_certificate(certificate_id)
            .await?;
        let owner = certificate.as_ref().map(|c| {
            credential_found(
                context,
                &c.owner,
                certificate_id,
                &c.wami_arn.wami_instance_id,
            )
        });
        guard_by_id(
            self.authz.as_ref(),
            context,
            WamiAction::IamManageCredentials,
            "signing certificate",
            certificate_id,
            owner,
        )
        .await?;
        if let (Some(certificate), Some(named)) = (&certificate, named) {
            if &certificate.owner != named {
                return Err(AmiError::InvalidParameter {
                    message: format!(
                        "signing certificate {certificate_id} does not belong to {named}"
                    ),
                });
            }
        }
        Ok(certificate)
    }

    /// Update a signing certificate (change status)
    pub async fn update_signing_certificate(
        &self,
        context: &WamiContext,
        request: UpdateSigningCertificateRequest,
    ) -> Result<SigningCertificate> {
        let mut certificate = self
            .read_judged(context, &request.certificate_id, Some(&request.user))
            .await?
            .ok_or_else(|| crate::error::AmiError::ResourceNotFound {
                resource: format!("SigningCertificate: {}", request.certificate_id),
            })?;

        // Apply updates
        certificate.status = request.status;

        // Store updated certificate
        self.write_store()
            .await
            .update_signing_certificate(certificate)
            .await
    }

    /// Delete a signing certificate
    pub async fn delete_signing_certificate(
        &self,
        context: &WamiContext,
        request: DeleteSigningCertificateRequest,
    ) -> Result<()> {
        self.read_judged(context, &request.certificate_id, Some(&request.user))
            .await?;
        self.write_store()
            .await
            .delete_signing_certificate(&request.certificate_id)
            .await
    }

    /// List signing certificates for a user
    pub async fn list_signing_certificates(
        &self,
        context: &WamiContext,
        request: ListSigningCertificatesRequest,
    ) -> Result<Vec<SigningCertificate>> {
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
            .list_signing_certificates(&request.tenant, request.user.as_ref())
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::signing_certificate::CertificateStatus;
    use crate::service::auth::decision::{Decision, DenyReason};
    use crate::store::memory::InMemoryWamiStore;

    /// The tenant every test here works in.
    fn tenant() -> wami_core::arn::TenantPath {
        wami_core::arn::TenantPath::single(0)
    }

    /// `name`'s key in that tenant.
    fn key(name: impl AsRef<str>) -> wami_core::arn::ScopedName {
        wami_core::arn::ScopedName::new(tenant(), name.as_ref())
    }

    /// A service over a store holding the users the tests mint credentials
    /// for: a credential is only ever minted for a user that is there.
    async fn setup_service() -> SigningCertificateService<InMemoryWamiStore> {
        use crate::store::traits::UserStore;
        let mut seeded = InMemoryWamiStore::default();
        for name in ["alice", "bob", "charlie", "david"] {
            let user =
                crate::wami::identity::user::builder::build_user(&key(name), None, &test_context())
                    .unwrap();
            seeded.create_user(user).await.unwrap();
        }
        SigningCertificateService::new(Arc::new(RwLock::new(seeded)))
    }

    fn test_context() -> WamiContext {
        use wami_core::arn::{TenantPath, WamiArn};
        WamiContext::builder()
            .instance_id("123456789012")
            .tenant_path(TenantPath::single(0))
            .caller_arn(
                WamiArn::builder()
                    .service(crate::arn::Service::Iam)
                    .tenant_path(TenantPath::single(0))
                    .wami_instance("123456789012")
                    .resource("user", "test-user")
                    .build()
                    .unwrap(),
            )
            .is_root(false)
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn test_upload_and_get_signing_certificate() {
        let service = setup_service().await;
        let context = test_context();

        let request = UploadSigningCertificateRequest {
            user: key("alice"),
            certificate_body: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
                .to_string(),
        };

        let certificate = service
            .upload_signing_certificate(&context, request)
            .await
            .unwrap();
        assert_eq!(certificate.owner.name(), "alice");
        assert!(!certificate.certificate_id.is_empty());

        let retrieved = service
            .get_signing_certificate(&context, &certificate.certificate_id)
            .await
            .unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().owner.name(), "alice");
    }

    #[tokio::test]
    async fn test_update_signing_certificate_status() {
        let service = setup_service().await;
        let context = test_context();

        let upload_req = UploadSigningCertificateRequest {
            user: key("bob"),
            certificate_body: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
                .to_string(),
        };
        let certificate = service
            .upload_signing_certificate(&context, upload_req)
            .await
            .unwrap();

        let update_req = UpdateSigningCertificateRequest {
            user: key("bob"),
            certificate_id: certificate.certificate_id.clone(),
            status: CertificateStatus::Inactive,
        };
        let updated = service
            .update_signing_certificate(&context, update_req)
            .await
            .unwrap();
        assert_eq!(updated.status, CertificateStatus::Inactive);
    }

    #[tokio::test]
    async fn test_delete_signing_certificate() {
        let service = setup_service().await;
        let context = test_context();

        let upload_req = UploadSigningCertificateRequest {
            user: key("charlie"),
            certificate_body: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
                .to_string(),
        };
        let certificate = service
            .upload_signing_certificate(&context, upload_req)
            .await
            .unwrap();

        let delete_req = DeleteSigningCertificateRequest {
            user: key("charlie"),
            certificate_id: certificate.certificate_id.clone(),
        };
        service
            .delete_signing_certificate(&context, delete_req)
            .await
            .unwrap();

        let retrieved = service
            .get_signing_certificate(&context, &certificate.certificate_id)
            .await
            .unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_list_signing_certificates() {
        let service = setup_service().await;
        let context = test_context();

        // Upload multiple certificates for same user
        for _ in 0..3 {
            let request = UploadSigningCertificateRequest {
                user: key("david"),
                certificate_body: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
                    .to_string(),
            };
            service
                .upload_signing_certificate(&context, request)
                .await
                .unwrap();
        }

        let list_request = ListSigningCertificatesRequest {
            tenant: tenant(),
            user: Some(key("david")),
        };
        let certificates = service
            .list_signing_certificates(&context, list_request)
            .await
            .unwrap();
        assert_eq!(certificates.len(), 3);
    }

    // ========== Authorization Guard Tests ==========

    use crate::service::auth::authorizer::Authorizer;
    use async_trait::async_trait;
    use wami_core::arn::WamiArn;

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
    async fn test_guard_upload_signing_certificate_denied() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let service =
            SigningCertificateService::with_authorizer(store, Arc::new(DenyAllAuthorizer));
        let context = test_context();

        let request = UploadSigningCertificateRequest {
            user: key("alice"),
            certificate_body: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
                .to_string(),
        };

        let result = service.upload_signing_certificate(&context, request).await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn test_guard_get_signing_certificate_denied() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let service =
            SigningCertificateService::with_authorizer(store, Arc::new(DenyAllAuthorizer));
        let context = test_context();

        let result = service.get_signing_certificate(&context, "some-id").await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn test_guard_update_signing_certificate_denied() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let service =
            SigningCertificateService::with_authorizer(store, Arc::new(DenyAllAuthorizer));
        let context = test_context();

        let request = UpdateSigningCertificateRequest {
            user: key("alice"),
            certificate_id: "some-id".to_string(),
            status: CertificateStatus::Inactive,
        };

        let result = service.update_signing_certificate(&context, request).await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn test_guard_delete_signing_certificate_denied() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let service =
            SigningCertificateService::with_authorizer(store, Arc::new(DenyAllAuthorizer));
        let context = test_context();

        let request = DeleteSigningCertificateRequest {
            user: key("alice"),
            certificate_id: "some-id".to_string(),
        };

        let result = service.delete_signing_certificate(&context, request).await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn test_guard_list_signing_certificates_denied() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let service =
            SigningCertificateService::with_authorizer(store, Arc::new(DenyAllAuthorizer));
        let context = test_context();

        let request = ListSigningCertificatesRequest {
            tenant: tenant(),
            user: Some(key("alice")),
        };

        let result = service.list_signing_certificates(&context, request).await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }
}
