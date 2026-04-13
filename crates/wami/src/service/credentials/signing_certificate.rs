//! Signing Certificate Service
//!
//! Orchestrates signing certificate management operations.

use crate::service::auth::authorizer::{iam_resource_arn, Authorizer};
use crate::store::traits::SigningCertificateStore;
use std::sync::{Arc, RwLock};
use wami_core::actions::WamiAction;
use wami_core::context::WamiContext;
use wami_core::error::Result;
use wami_credentials::signing_certificate::{
    builder as cert_builder, DeleteSigningCertificateRequest, ListSigningCertificatesRequest,
    SigningCertificate, UpdateSigningCertificateRequest, UploadSigningCertificateRequest,
};

/// Service for managing IAM signing certificates
///
/// Provides high-level operations for X.509 certificate management.
/// Optionally holds an [`Authorizer`] for authorization guards on every method.
#[wami_macros::service(
    store_trait = "crate::store::traits::SigningCertificateStore",
    generate_new = false
)]
pub struct SigningCertificateService<S> {
    store: Arc<RwLock<S>>,
    authz: Option<Arc<dyn Authorizer>>,
}

impl<S: SigningCertificateStore> SigningCertificateService<S> {
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

    /// Upload a new signing certificate
    pub async fn upload_signing_certificate(
        &self,
        context: &WamiContext,
        request: UploadSigningCertificateRequest,
    ) -> Result<SigningCertificate> {
        // Authorization guard
        self.guard(
            context,
            WamiAction::IamManageCredentials,
            "user",
            &request.user_name,
        )
        .await?;

        // Use wami builder to create certificate
        let certificate = cert_builder::build_signing_certificate(
            request.user_name,
            request.certificate_body,
            context,
        )?;

        // Store it
        self.write_store()
            .create_signing_certificate(certificate)
            .await
    }

    /// Get a signing certificate by ID
    pub async fn get_signing_certificate(
        &self,
        context: &WamiContext,
        certificate_id: &str,
    ) -> Result<Option<SigningCertificate>> {
        self.guard(
            context,
            WamiAction::IamManageCredentials,
            "credential",
            certificate_id,
        )
        .await?;
        self.read_store()
            .get_signing_certificate(certificate_id)
            .await
    }

    /// Update a signing certificate (change status)
    pub async fn update_signing_certificate(
        &self,
        context: &WamiContext,
        request: UpdateSigningCertificateRequest,
    ) -> Result<SigningCertificate> {
        self.guard(
            context,
            WamiAction::IamManageCredentials,
            "user",
            &request.user_name,
        )
        .await?;

        // Get existing certificate
        let mut certificate = self
            .read_store()
            .get_signing_certificate(&request.certificate_id)
            .await?
            .ok_or_else(|| crate::error::AmiError::ResourceNotFound {
                resource: format!("SigningCertificate: {}", request.certificate_id),
            })?;

        // Apply updates
        certificate.status = request.status;

        // Store updated certificate
        self.write_store()
            .update_signing_certificate(certificate)
            .await
    }

    /// Delete a signing certificate
    pub async fn delete_signing_certificate(
        &self,
        context: &WamiContext,
        request: DeleteSigningCertificateRequest,
    ) -> Result<()> {
        self.guard(
            context,
            WamiAction::IamManageCredentials,
            "user",
            &request.user_name,
        )
        .await?;
        self.write_store()
            .delete_signing_certificate(&request.certificate_id)
            .await
    }

    /// List signing certificates for a user
    pub async fn list_signing_certificates(
        &self,
        context: &WamiContext,
        request: ListSigningCertificatesRequest,
    ) -> Result<Vec<SigningCertificate>> {
        let user_name = request.user_name.as_deref().unwrap_or("*");
        self.guard(context, WamiAction::IamManageCredentials, "user", user_name)
            .await?;
        self.read_store()
            .list_signing_certificates(request.user_name.as_deref())
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::memory::InMemoryWamiStore;
    use wami_credentials::signing_certificate::CertificateStatus;

    fn setup_service() -> SigningCertificateService<InMemoryWamiStore> {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        SigningCertificateService::new(store)
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
        let service = setup_service();
        let context = test_context();

        let request = UploadSigningCertificateRequest {
            user_name: "alice".to_string(),
            certificate_body: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
                .to_string(),
        };

        let certificate = service
            .upload_signing_certificate(&context, request)
            .await
            .unwrap();
        assert_eq!(certificate.user_name, "alice");
        assert!(!certificate.certificate_id.is_empty());

        let retrieved = service
            .get_signing_certificate(&context, &certificate.certificate_id)
            .await
            .unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().user_name, "alice");
    }

    #[tokio::test]
    async fn test_update_signing_certificate_status() {
        let service = setup_service();
        let context = test_context();

        let upload_req = UploadSigningCertificateRequest {
            user_name: "bob".to_string(),
            certificate_body: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
                .to_string(),
        };
        let certificate = service
            .upload_signing_certificate(&context, upload_req)
            .await
            .unwrap();

        let update_req = UpdateSigningCertificateRequest {
            user_name: "bob".to_string(),
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
        let service = setup_service();
        let context = test_context();

        let upload_req = UploadSigningCertificateRequest {
            user_name: "charlie".to_string(),
            certificate_body: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
                .to_string(),
        };
        let certificate = service
            .upload_signing_certificate(&context, upload_req)
            .await
            .unwrap();

        let delete_req = DeleteSigningCertificateRequest {
            user_name: "charlie".to_string(),
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
        let service = setup_service();
        let context = test_context();

        // Upload multiple certificates for same user
        for _ in 0..3 {
            let request = UploadSigningCertificateRequest {
                user_name: "david".to_string(),
                certificate_body: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
                    .to_string(),
            };
            service
                .upload_signing_certificate(&context, request)
                .await
                .unwrap();
        }

        let list_request = ListSigningCertificatesRequest {
            user_name: Some("david".to_string()),
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
    async fn test_guard_upload_signing_certificate_denied() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let service =
            SigningCertificateService::with_authorizer(store, Arc::new(DenyAllAuthorizer));
        let context = test_context();

        let request = UploadSigningCertificateRequest {
            user_name: "alice".to_string(),
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
            user_name: "alice".to_string(),
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
            user_name: "alice".to_string(),
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
            user_name: Some("alice".to_string()),
        };

        let result = service.list_signing_certificates(&context, request).await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }
}
