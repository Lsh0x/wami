//! MFA Device Service
//!
//! Orchestrates MFA device management operations.

use crate::credentials::mfa_device::{
    builder as mfa_builder, EnableMfaDeviceRequest, ListMfaDevicesRequest, MfaDevice,
};
use crate::service::auth::authorizer::{guard, guard_by_id, target_arn, Authorizer};
use crate::store::traits::{MfaDeviceStore, UserStore};
use std::sync::Arc;
use tokio::sync::RwLock;
use wami_core::actions::WamiAction;
use wami_core::context::WamiContext;
use wami_core::error::Result;

/// What the MFA device service reads: the devices, and their owners.
pub trait MfaDeviceServiceStore: MfaDeviceStore + UserStore {}
impl<T> MfaDeviceServiceStore for T where T: MfaDeviceStore + UserStore {}

/// Service for managing IAM MFA devices
///
/// Provides high-level operations for MFA device management.
/// Optionally holds an [`Authorizer`] for authorization guards on every method.
#[wami_macros::service(
    store_trait = "crate::service::credentials::mfa_device::MfaDeviceServiceStore",
    generate_new = false
)]
pub struct MfaDeviceService<S> {
    store: Arc<RwLock<S>>,
    authz: Option<Arc<dyn Authorizer>>,
}

impl<S: MfaDeviceServiceStore> MfaDeviceService<S> {
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

    /// Create and enable a new MFA device
    pub async fn create_mfa_device(
        &self,
        context: &WamiContext,
        request: EnableMfaDeviceRequest,
    ) -> Result<MfaDevice> {
        guard(
            self.authz.as_ref(),
            context,
            WamiAction::IamManageCredentials,
            "user",
            &request.user,
        )
        .await?;
        let owner = super::read_owner(&*self.read_store().await, context, &request.user).await?;
        let mfa_device = mfa_builder::build_mfa_device(&owner, request.serial_number, context)?;

        // Store it
        self.write_store().await.create_mfa_device(mfa_device).await
    }

    /// Get an MFA device by serial number
    pub async fn get_mfa_device(
        &self,
        context: &WamiContext,
        serial_number: &str,
    ) -> Result<Option<MfaDevice>> {
        self.read_judged(context, serial_number).await
    }

    /// Read the device stored under `serial_number`, then judge its OWNER;
    /// an absent serial and a denied owner are one refusal (A1).
    async fn read_judged(
        &self,
        context: &WamiContext,
        serial_number: &str,
    ) -> Result<Option<MfaDevice>> {
        let device = self
            .read_store()
            .await
            .get_mfa_device(serial_number)
            .await?;
        let owner = device
            .as_ref()
            .map(|d| target_arn(context, "user", &d.owner));
        guard_by_id(
            self.authz.as_ref(),
            context,
            WamiAction::IamManageCredentials,
            "MFA device",
            serial_number,
            owner,
        )
        .await?;
        Ok(device)
    }

    /// Delete an MFA device
    pub async fn delete_mfa_device(
        &self,
        context: &WamiContext,
        serial_number: &str,
    ) -> Result<()> {
        self.read_judged(context, serial_number).await?;
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
        guard(
            self.authz.as_ref(),
            context,
            WamiAction::IamManageCredentials,
            "user",
            &request.user,
        )
        .await?;
        self.read_store()
            .await
            .list_mfa_devices(&request.user)
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
    async fn setup_service() -> MfaDeviceService<InMemoryWamiStore> {
        use crate::store::traits::UserStore;
        let mut seeded = InMemoryWamiStore::default();
        for name in ["alice", "bob", "charlie", "david"] {
            let user =
                crate::wami::identity::user::builder::build_user(&key(name), None, &test_context())
                    .unwrap();
            seeded.create_user(user).await.unwrap();
        }
        MfaDeviceService::new(Arc::new(RwLock::new(seeded)))
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
        let service = setup_service().await;
        let context = test_context();

        let request = EnableMfaDeviceRequest {
            user: key("alice"),
            serial_number: "arn:aws:iam::123456789012:mfa/alice-device".to_string(),
            authentication_code_1: "123456".to_string(),
            authentication_code_2: "789012".to_string(),
        };

        let mfa_device = service.create_mfa_device(&context, request).await.unwrap();
        assert_eq!(mfa_device.owner.name(), "alice");

        let retrieved = service
            .get_mfa_device(&context, &mfa_device.serial_number)
            .await
            .unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().owner.name(), "alice");
    }

    #[tokio::test]
    async fn test_delete_mfa_device() {
        let service = setup_service().await;
        let context = test_context();

        let request = EnableMfaDeviceRequest {
            user: key("bob"),
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
        let service = setup_service().await;
        let context = test_context();

        // Create multiple MFA devices for same user
        for i in 0..3 {
            let request = EnableMfaDeviceRequest {
                user: key("charlie"),
                serial_number: format!("arn:aws:iam::123456789012:mfa/charlie-device-{}", i),
                authentication_code_1: "123456".to_string(),
                authentication_code_2: "789012".to_string(),
            };
            service.create_mfa_device(&context, request).await.unwrap();
        }

        let list_request = ListMfaDevicesRequest {
            user: key("charlie"),
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
    }

    #[tokio::test]
    async fn test_guard_create_mfa_device_denied() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let service = MfaDeviceService::with_authorizer(store, Arc::new(DenyAllAuthorizer));
        let context = test_context();

        let request = EnableMfaDeviceRequest {
            user: key("alice"),
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

        let request = ListMfaDevicesRequest { user: key("alice") };

        let result = service.list_mfa_devices(&context, request).await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }
}
