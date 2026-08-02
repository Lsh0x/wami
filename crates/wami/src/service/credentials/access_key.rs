//! Access Key Service
//!
//! Orchestrates access key management operations.

use crate::service::auth::authorizer::{iam_resource_arn, Authorizer};
use crate::store::traits::AccessKeyStore;
use std::sync::Arc;
use tokio::sync::RwLock;
use wami_core::actions::WamiAction;
use wami_core::context::WamiContext;
use wami_core::error::Result;
use wami_credentials::access_key::{
    builder as access_key_builder, AccessKey, CreateAccessKeyRequest, ListAccessKeysRequest,
};

/// Service for managing IAM access keys
///
/// Provides high-level operations for access key management.
/// Optionally holds an [`Authorizer`] for authorization guards on every method.
#[wami_macros::service(
    store_trait = "crate::store::traits::AccessKeyStore",
    generate_new = false
)]
pub struct AccessKeyService<S> {
    store: Arc<RwLock<S>>,
    authz: Option<Arc<dyn Authorizer>>,
}

impl<S: AccessKeyStore> AccessKeyService<S> {
    /// Create a new AccessKeyService without authorization guards (backward compatible).
    pub fn new(store: Arc<RwLock<S>>) -> Self {
        Self { store, authz: None }
    }

    /// Create a new AccessKeyService with an authorization guard.
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

    /// Create a new access key
    pub async fn create_access_key(
        &self,
        context: &WamiContext,
        request: CreateAccessKeyRequest,
    ) -> Result<AccessKey> {
        // Authorization guard
        self.guard(
            context,
            WamiAction::IamManageCredentials,
            "user",
            &request.user_name,
        )
        .await?;

        // Use wami builder to create access key
        let access_key = access_key_builder::build_access_key(request.user_name, context)?;

        // Store it
        self.write_store().await.create_access_key(access_key).await
    }

    /// Get an access key by ID
    pub async fn get_access_key(
        &self,
        context: &WamiContext,
        access_key_id: &str,
    ) -> Result<Option<AccessKey>> {
        self.guard(
            context,
            WamiAction::IamManageCredentials,
            "credential",
            access_key_id,
        )
        .await?;
        self.read_store().await.get_access_key(access_key_id).await
    }

    /// Update an access key (e.g., change status)
    pub async fn update_access_key(
        &self,
        context: &WamiContext,
        access_key: AccessKey,
    ) -> Result<AccessKey> {
        self.guard(
            context,
            WamiAction::IamManageCredentials,
            "user",
            &access_key.user_name,
        )
        .await?;
        self.write_store().await.update_access_key(access_key).await
    }

    /// Delete an access key
    pub async fn delete_access_key(
        &self,
        context: &WamiContext,
        access_key_id: &str,
    ) -> Result<()> {
        self.guard(
            context,
            WamiAction::IamManageCredentials,
            "credential",
            access_key_id,
        )
        .await?;
        self.write_store()
            .await
            .delete_access_key(access_key_id)
            .await
    }

    /// List access keys for a user
    pub async fn list_access_keys(
        &self,
        context: &WamiContext,
        request: ListAccessKeysRequest,
    ) -> Result<(Vec<AccessKey>, bool, Option<String>)> {
        self.guard(
            context,
            WamiAction::IamManageCredentials,
            "user",
            &request.user_name,
        )
        .await?;
        self.read_store()
            .await
            .list_access_keys(&request.user_name, request.pagination.as_ref())
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::auth::decision::{Decision, DenyReason};
    use crate::store::memory::InMemoryWamiStore;
    use wami_core::arn::{TenantPath, WamiArn};

    fn setup_service() -> AccessKeyService<InMemoryWamiStore> {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        AccessKeyService::new(store)
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
    async fn test_create_and_get_access_key() {
        let service = setup_service();
        let context = test_context();

        let request = CreateAccessKeyRequest {
            user_name: "alice".to_string(),
        };

        let access_key = service.create_access_key(&context, request).await.unwrap();
        assert_eq!(access_key.user_name, "alice");
        assert!(!access_key.access_key_id.is_empty());
        assert!(access_key.secret_access_key.is_some());

        let retrieved = service
            .get_access_key(&context, &access_key.access_key_id)
            .await
            .unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().user_name, "alice");
    }

    #[tokio::test]
    async fn test_delete_access_key() {
        let service = setup_service();
        let context = test_context();

        let request = CreateAccessKeyRequest {
            user_name: "bob".to_string(),
        };
        let access_key = service.create_access_key(&context, request).await.unwrap();

        service
            .delete_access_key(&context, &access_key.access_key_id)
            .await
            .unwrap();

        let retrieved = service
            .get_access_key(&context, &access_key.access_key_id)
            .await
            .unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_list_access_keys() {
        let service = setup_service();
        let context = test_context();

        // Create multiple access keys for same user
        for _ in 0..3 {
            let request = CreateAccessKeyRequest {
                user_name: "charlie".to_string(),
            };
            service.create_access_key(&context, request).await.unwrap();
        }

        let list_request = ListAccessKeysRequest {
            user_name: "charlie".to_string(),
            pagination: None,
        };
        let (keys, _, _) = service
            .list_access_keys(&context, list_request)
            .await
            .unwrap();
        assert_eq!(keys.len(), 3);
    }

    // ========== Error Path Tests ==========

    #[tokio::test]
    async fn test_get_access_key_nonexistent() {
        let service = setup_service();
        let context = test_context();

        let result = service.get_access_key(&context, "nonexistent-key-id").await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_delete_access_key_nonexistent() {
        let service = setup_service();
        let context = test_context();

        // Delete is idempotent - succeeds even if access key doesn't exist
        let result = service
            .delete_access_key(&context, "nonexistent-key-id")
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_list_access_keys_empty_result() {
        let service = setup_service();
        let context = test_context();

        let request = ListAccessKeysRequest {
            user_name: "nonexistent".to_string(),
            pagination: None,
        };

        let (keys, _, _) = service.list_access_keys(&context, request).await.unwrap();
        assert_eq!(keys.len(), 0);
    }

    #[tokio::test]
    async fn test_update_access_key_nonexistent() {
        let service = setup_service();
        let context = test_context();

        // Update is idempotent - creates/updates even if access key doesn't exist
        use wami_credentials::build_access_key;
        let access_key = build_access_key("alice".to_string(), &context).unwrap();
        let mut nonexistent_key = access_key;
        nonexistent_key.access_key_id = "nonexistent-key-id".to_string();

        let result = service.update_access_key(&context, nonexistent_key).await;
        assert!(result.is_ok());
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
    async fn test_guard_create_access_key_denied() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let service = AccessKeyService::with_authorizer(store, Arc::new(DenyAllAuthorizer));
        let context = test_context();

        let request = CreateAccessKeyRequest {
            user_name: "alice".to_string(),
        };

        let result = service.create_access_key(&context, request).await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn test_guard_get_access_key_denied() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let service = AccessKeyService::with_authorizer(store, Arc::new(DenyAllAuthorizer));
        let context = test_context();

        let result = service.get_access_key(&context, "some-key-id").await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn test_guard_update_access_key_denied() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let service = AccessKeyService::with_authorizer(store, Arc::new(DenyAllAuthorizer));
        let context = test_context();

        let access_key = wami_credentials::build_access_key("alice".to_string(), &context).unwrap();

        let result = service.update_access_key(&context, access_key).await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn test_guard_delete_access_key_denied() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let service = AccessKeyService::with_authorizer(store, Arc::new(DenyAllAuthorizer));
        let context = test_context();

        let result = service.delete_access_key(&context, "some-key-id").await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn test_guard_list_access_keys_denied() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let service = AccessKeyService::with_authorizer(store, Arc::new(DenyAllAuthorizer));
        let context = test_context();

        let request = ListAccessKeysRequest {
            user_name: "alice".to_string(),
            pagination: None,
        };

        let result = service.list_access_keys(&context, request).await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }
}
