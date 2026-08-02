//! MFA Device Service
//!
//! Orchestrates MFA device management operations.

use crate::service::auth::authorizer::{iam_resource_arn, Authorizer};
use crate::store::traits::MfaDeviceStore;
use std::sync::Arc;
use tokio::sync::RwLock;
use wami_core::actions::WamiAction;
use wami_core::context::WamiContext;
use wami_core::error::Result;
use wami_credentials::mfa_device::{
    builder as mfa_builder, EnableMfaDeviceRequest, ListMfaDevicesRequest, MfaDevice,
};

/// Service for managing IAM MFA devices
///
/// Provides high-level operations for MFA device management.
/// Optionally holds an [`Authorizer`] for authorization guards on every method.
#[wami_macros::service(
    store_trait = "crate::store::traits::MfaDeviceStore",
    generate_new = false
)]
pub struct MfaDeviceService<S> {
    store: Arc<RwLock<S>>,
    authz: Option<Arc<dyn Authorizer>>,
}

impl<S: MfaDeviceStore> MfaDeviceService<S> {
    /// Create a new MfaDeviceService without authorization guards (backward compatible).
    pub fn new(store: Arc<RwLock<S>>) -> Self {
        Self { store, authz: None }
    }

    /// Create a new MfaDeviceService with an authorization guard.
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

    /// Create and enable a new MFA device
    pub async fn create_mfa_device(
        &self,
        context: &WamiContext,
        request: EnableMfaDeviceRequest,
    ) -> Result<MfaDevice> {
        // Authorization guard
        self.guard(
            context,
            WamiAction::IamManageCredentials,
            "user",
            &request.user_name,
        )
        .await?;

        // Use wami builder to create MFA device
        let mfa_device =
            mfa_builder::build_mfa_device(request.user_name, request.serial_number, context)?;

        // Store it
        self.write_store().await.create_mfa_device(mfa_device).await
    }

    /// Get an MFA device by serial number
    pub async fn get_mfa_device(
        &self,
        context: &WamiContext,
        serial_number: &str,
    ) -> Result<Option<MfaDevice>> {
        self.guard(
            context,
            WamiAction::IamManageCredentials,
            "credential",
            serial_number,
        )
        .await?;
        self.read_store().await.get_mfa_device(serial_number).await
    }

    /// Delete an MFA device
    pub async fn delete_mfa_device(
        &self,
        context: &WamiContext,
        serial_number: &str,
    ) -> Result<()> {
        self.guard(
            context,
            WamiAction::IamManageCredentials,
            "credential",
            serial_number,
        )
        .await?;
        self.write_store()
            .await
            .delete_mfa_device(serial_number)
            .await
    }

    /// List MFA devices for a user
    pub async fn list_mfa_devices(
        &self,
        context: &WamiContext,
        request: ListMfaDevicesRequest,
    ) -> Result<Vec<MfaDevice>> {
        self.guard(
            context,
            WamiAction::IamManageCredentials,
            "user",
            &request.user_name,
        )
        .await?;
        self.read_store()
            .await
            .list_mfa_devices(&request.user_name)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::auth::decision::{Decision, DenyReason};
    use crate::store::memory::InMemoryWamiStore;
    use wami_core::arn::{TenantPath, WamiArn};

    fn setup_service() -> MfaDeviceService<InMemoryWamiStore> {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        MfaDeviceService::new(store)
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
    async fn test_create_and_get_mfa_device() {
        let service = setup_service();
        let context = test_context();

        let request = EnableMfaDeviceRequest {
            user_name: "alice".to_string(),
            serial_number: "arn:aws:iam::123456789012:mfa/alice-device".to_string(),
            authentication_code_1: "123456".to_string(),
            authentication_code_2: "789012".to_string(),
        };

        let mfa_device = service.create_mfa_device(&context, request).await.unwrap();
        assert_eq!(mfa_device.user_name, "alice");

        let retrieved = service
            .get_mfa_device(&context, &mfa_device.serial_number)
            .await
            .unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().user_name, "alice");
    }

    #[tokio::test]
    async fn test_delete_mfa_device() {
        let service = setup_service();
        let context = test_context();

        let request = EnableMfaDeviceRequest {
            user_name: "bob".to_string(),
            serial_number: "arn:aws:iam::123456789012:mfa/bob-device".to_string(),
            authentication_code_1: "123456".to_string(),
            authentication_code_2: "789012".to_string(),
        };
        let mfa_device = service.create_mfa_device(&context, request).await.unwrap();

        service
            .delete_mfa_device(&context, &mfa_device.serial_number)
            .await
            .unwrap();

        let retrieved = service
            .get_mfa_device(&context, &mfa_device.serial_number)
            .await
            .unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_list_mfa_devices() {
        let service = setup_service();
        let context = test_context();

        // Create multiple MFA devices for same user
        for i in 0..3 {
            let request = EnableMfaDeviceRequest {
                user_name: "charlie".to_string(),
                serial_number: format!("arn:aws:iam::123456789012:mfa/charlie-device-{}", i),
                authentication_code_1: "123456".to_string(),
                authentication_code_2: "789012".to_string(),
            };
            service.create_mfa_device(&context, request).await.unwrap();
        }

        let list_request = ListMfaDevicesRequest {
            user_name: "charlie".to_string(),
        };
        let devices = service
            .list_mfa_devices(&context, list_request)
            .await
            .unwrap();
        assert_eq!(devices.len(), 3);
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
    async fn test_guard_create_mfa_device_denied() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let service = MfaDeviceService::with_authorizer(store, Arc::new(DenyAllAuthorizer));
        let context = test_context();

        let request = EnableMfaDeviceRequest {
            user_name: "alice".to_string(),
            serial_number: "arn:aws:iam::123456789012:mfa/alice-device".to_string(),
            authentication_code_1: "123456".to_string(),
            authentication_code_2: "789012".to_string(),
        };

        let result = service.create_mfa_device(&context, request).await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn test_guard_get_mfa_device_denied() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let service = MfaDeviceService::with_authorizer(store, Arc::new(DenyAllAuthorizer));
        let context = test_context();

        let result = service.get_mfa_device(&context, "some-serial").await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn test_guard_delete_mfa_device_denied() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let service = MfaDeviceService::with_authorizer(store, Arc::new(DenyAllAuthorizer));
        let context = test_context();

        let result = service.delete_mfa_device(&context, "some-serial").await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn test_guard_list_mfa_devices_denied() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let service = MfaDeviceService::with_authorizer(store, Arc::new(DenyAllAuthorizer));
        let context = test_context();

        let request = ListMfaDevicesRequest {
            user_name: "alice".to_string(),
        };

        let result = service.list_mfa_devices(&context, request).await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }
}
