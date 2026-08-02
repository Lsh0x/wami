//! Server Certificate Service
//!
//! Orchestrates server certificate management operations.

use crate::service::auth::authorizer::{iam_resource_arn, Authorizer};
use crate::store::traits::ServerCertificateStore;
use std::sync::Arc;
use tokio::sync::RwLock;
use wami_core::actions::WamiAction;
use wami_core::context::WamiContext;
use wami_core::error::Result;
use wami_core::types::PaginationParams;
use wami_credentials::server_certificate::{
    builder as cert_builder, ListServerCertificatesRequest, ServerCertificateMetadata,
    UpdateServerCertificateRequest, UploadServerCertificateRequest,
};

/// Service for managing IAM server certificates
///
/// Provides high-level operations for server certificate management.
/// Optionally holds an [`Authorizer`] for authorization guards on every method.
#[wami_macros::service(
    store_trait = "crate::store::traits::ServerCertificateStore",
    generate_new = false
)]
pub struct ServerCertificateService<S> {
    store: Arc<RwLock<S>>,
    authz: Option<Arc<dyn Authorizer>>,
}

impl<S: ServerCertificateStore> ServerCertificateService<S> {
    /// Create a new ServerCertificateService without authorization guards (backward compatible).
    pub fn new(store: Arc<RwLock<S>>) -> Self {
        Self { store, authz: None }
    }

    /// Create a new ServerCertificateService with an authorization guard.
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

    /// Upload a new server certificate
    pub async fn upload_server_certificate(
        &self,
        context: &WamiContext,
        request: UploadServerCertificateRequest,
    ) -> Result<ServerCertificateMetadata> {
        // Authorization guard
        self.guard(
            context,
            WamiAction::IamManageCredentials,
            "credential",
            &request.server_certificate_name,
        )
        .await?;

        // Use wami builder to create certificate
        let certificate = cert_builder::build_server_certificate(
            request.server_certificate_name,
            request.certificate_body,
            request.certificate_chain,
            request.path.unwrap_or_else(|| "/".to_string()),
            request.tags.unwrap_or_default(),
            context,
        )?;

        // Store it (note: private_key is part of ServerCertificate, not passed separately)
        self.write_store()
            .await
            .create_server_certificate(certificate)
            .await
    }

    /// Get a server certificate by name
    pub async fn get_server_certificate(
        &self,
        context: &WamiContext,
        certificate_name: &str,
    ) -> Result<Option<ServerCertificateMetadata>> {
        self.guard(
            context,
            WamiAction::IamManageCredentials,
            "credential",
            certificate_name,
        )
        .await?;
        self.read_store()
            .await
            .get_server_certificate(certificate_name)
            .await
    }

    /// Update a server certificate
    pub async fn update_server_certificate(
        &self,
        context: &WamiContext,
        request: UpdateServerCertificateRequest,
    ) -> Result<ServerCertificateMetadata> {
        self.guard(
            context,
            WamiAction::IamManageCredentials,
            "credential",
            &request.server_certificate_name,
        )
        .await?;

        // Get existing certificate
        let mut certificate = self
            .read_store()
            .await
            .get_server_certificate(&request.server_certificate_name)
            .await?
            .ok_or_else(|| crate::error::AmiError::ResourceNotFound {
                resource: format!("ServerCertificate: {}", request.server_certificate_name),
            })?;

        // Apply updates
        if let Some(new_name) = request.new_server_certificate_name {
            certificate.server_certificate_name = new_name;
        }

        if let Some(new_path) = request.new_path {
            certificate.path = new_path;
        }

        // Store updated certificate
        self.write_store()
            .await
            .update_server_certificate(certificate)
            .await
    }

    /// Delete a server certificate
    pub async fn delete_server_certificate(
        &self,
        context: &WamiContext,
        certificate_name: &str,
    ) -> Result<()> {
        self.guard(
            context,
            WamiAction::IamManageCredentials,
            "credential",
            certificate_name,
        )
        .await?;
        self.write_store()
            .await
            .delete_server_certificate(certificate_name)
            .await
    }

    /// List server certificates with optional filtering
    pub async fn list_server_certificates(
        &self,
        context: &WamiContext,
        request: ListServerCertificatesRequest,
    ) -> Result<(Vec<ServerCertificateMetadata>, bool, Option<String>)> {
        self.guard(context, WamiAction::IamManageCredentials, "credential", "*")
            .await?;

        let pagination = if request.marker.is_some() || request.max_items.is_some() {
            Some(PaginationParams {
                marker: request.marker,
                max_items: request.max_items,
            })
        } else {
            None
        };

        self.read_store()
            .await
            .list_server_certificates(request.path_prefix.as_deref(), pagination.as_ref())
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::memory::InMemoryWamiStore;

    fn setup_service() -> ServerCertificateService<InMemoryWamiStore> {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        ServerCertificateService::new(store)
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
    async fn test_upload_and_get_server_certificate() {
        let service = setup_service();
        let context = test_context();

        let request = UploadServerCertificateRequest {
            server_certificate_name: "test-cert".to_string(),
            certificate_body: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
                .to_string(),
            private_key: "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----"
                .to_string(),
            certificate_chain: None,
            path: Some("/certs/".to_string()),
            tags: None,
        };

        let metadata = service
            .upload_server_certificate(&context, request)
            .await
            .unwrap();
        assert_eq!(metadata.server_certificate_name, "test-cert");
        assert_eq!(metadata.path, "/certs/");

        let retrieved = service
            .get_server_certificate(&context, "test-cert")
            .await
            .unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().server_certificate_name, "test-cert");
    }

    #[tokio::test]
    async fn test_delete_server_certificate() {
        let service = setup_service();
        let context = test_context();

        let request = UploadServerCertificateRequest {
            server_certificate_name: "delete-me".to_string(),
            certificate_body: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
                .to_string(),
            private_key: "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----"
                .to_string(),
            certificate_chain: None,
            path: None,
            tags: None,
        };
        service
            .upload_server_certificate(&context, request)
            .await
            .unwrap();

        service
            .delete_server_certificate(&context, "delete-me")
            .await
            .unwrap();

        let retrieved = service
            .get_server_certificate(&context, "delete-me")
            .await
            .unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_list_server_certificates() {
        let service = setup_service();
        let context = test_context();

        // Upload multiple certificates
        for i in 0..3 {
            let request = UploadServerCertificateRequest {
                server_certificate_name: format!("cert{}", i),
                certificate_body: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
                    .to_string(),
                private_key: "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----"
                    .to_string(),
                certificate_chain: None,
                path: Some("/test/".to_string()),
                tags: None,
            };
            service
                .upload_server_certificate(&context, request)
                .await
                .unwrap();
        }

        let list_request = ListServerCertificatesRequest {
            path_prefix: Some("/test/".to_string()),
            marker: None,
            max_items: None,
        };
        let (certs, _, _) = service
            .list_server_certificates(&context, list_request)
            .await
            .unwrap();
        assert_eq!(certs.len(), 3);
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
    async fn test_guard_upload_server_certificate_denied() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let service = ServerCertificateService::with_authorizer(store, Arc::new(DenyAllAuthorizer));
        let context = test_context();

        let request = UploadServerCertificateRequest {
            server_certificate_name: "test-cert".to_string(),
            certificate_body: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
                .to_string(),
            private_key: "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----"
                .to_string(),
            certificate_chain: None,
            path: None,
            tags: None,
        };

        let result = service.upload_server_certificate(&context, request).await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn test_guard_get_server_certificate_denied() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let service = ServerCertificateService::with_authorizer(store, Arc::new(DenyAllAuthorizer));
        let context = test_context();

        let result = service.get_server_certificate(&context, "test-cert").await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn test_guard_update_server_certificate_denied() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let service = ServerCertificateService::with_authorizer(store, Arc::new(DenyAllAuthorizer));
        let context = test_context();

        let request = UpdateServerCertificateRequest {
            server_certificate_name: "test-cert".to_string(),
            new_server_certificate_name: None,
            new_path: None,
        };

        let result = service.update_server_certificate(&context, request).await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn test_guard_delete_server_certificate_denied() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let service = ServerCertificateService::with_authorizer(store, Arc::new(DenyAllAuthorizer));
        let context = test_context();

        let result = service
            .delete_server_certificate(&context, "test-cert")
            .await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn test_guard_list_server_certificates_denied() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let service = ServerCertificateService::with_authorizer(store, Arc::new(DenyAllAuthorizer));
        let context = test_context();

        let request = ListServerCertificatesRequest {
            path_prefix: None,
            marker: None,
            max_items: None,
        };

        let result = service.list_server_certificates(&context, request).await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }
}
