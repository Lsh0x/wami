//! Login Profile Service
//!
//! Orchestrates login profile management operations.

use crate::credentials::login_profile::{
    builder as login_builder, CreateLoginProfileRequest, LoginProfile, UpdateLoginProfileRequest,
};
use crate::service::auth::authorizer::{confirm, guard, Authorizer};
use crate::store::traits::{LoginProfileStore, UserStore};
use std::sync::Arc;
use tokio::sync::RwLock;
use wami_core::actions::WamiAction;
use wami_core::arn::ScopedName;
use wami_core::context::WamiContext;
use wami_core::error::Result;

/// What the login profile service reads: the profiles, and their owners.
pub trait LoginProfileServiceStore: LoginProfileStore + UserStore {}
impl<T> LoginProfileServiceStore for T where T: LoginProfileStore + UserStore {}

/// Service for managing IAM login profiles
///
/// Provides high-level operations for console password management.
/// Optionally holds an [`Authorizer`] for authorization guards on every method.
#[wami_macros::service(
    store_trait = "crate::service::credentials::login_profile::LoginProfileServiceStore",
    generate_new = false
)]
pub struct LoginProfileService<S> {
    store: Arc<RwLock<S>>,
    authz: Option<Arc<dyn Authorizer>>,
}

impl<S: LoginProfileServiceStore> LoginProfileService<S> {
    /// Create a new LoginProfileService without authorization guards (backward compatible).
    pub fn new(store: Arc<RwLock<S>>) -> Self {
        Self { store, authz: None }
    }

    /// Create a new LoginProfileService with an authorization guard.
    pub fn with_authorizer(store: Arc<RwLock<S>>, authz: Arc<dyn Authorizer>) -> Self {
        Self {
            store,
            authz: Some(authz),
        }
    }

    /// Create a new login profile
    pub async fn create_login_profile(
        &self,
        context: &WamiContext,
        request: CreateLoginProfileRequest,
    ) -> Result<LoginProfile> {
        guard(
            self.authz.as_ref(),
            context,
            WamiAction::IamManageCredentials,
            "user",
            &request.user,
        )
        .await?;
        let owner = super::read_owner(&*self.read_store().await, context, &request.user).await?;

        // Note: Password is validated but not stored in the model for security
        let login_profile =
            login_builder::build_login_profile(&owner, request.password_reset_required, context)?;

        // Store it
        self.write_store()
            .await
            .create_login_profile(login_profile)
            .await
    }

    /// Get a login profile for a user
    pub async fn get_login_profile(
        &self,
        context: &WamiContext,
        user: &ScopedName,
    ) -> Result<Option<LoginProfile>> {
        guard(
            self.authz.as_ref(),
            context,
            WamiAction::IamManageCredentials,
            "user",
            user,
        )
        .await?;
        let profile = self.read_store().await.get_login_profile(user).await?;
        if let Some(profile) = &profile {
            // The record read must be the one asked for, of this instance (Δ12).
            confirm(
                context,
                "user",
                user,
                &profile.owner,
                &profile.wami_arn.wami_instance_id,
            )?;
        }
        Ok(profile)
    }

    /// Update a login profile
    pub async fn update_login_profile(
        &self,
        context: &WamiContext,
        request: UpdateLoginProfileRequest,
    ) -> Result<LoginProfile> {
        guard(
            self.authz.as_ref(),
            context,
            WamiAction::IamManageCredentials,
            "user",
            &request.user,
        )
        .await?;

        // Get existing profile
        let profile = self
            .read_store()
            .await
            .get_login_profile(&request.user)
            .await?
            .ok_or_else(|| crate::error::AmiError::ResourceNotFound {
                resource: format!("LoginProfile for user: {}", request.user),
            })?;
        confirm(
            context,
            "user",
            &request.user,
            &profile.owner,
            &profile.wami_arn.wami_instance_id,
        )?;

        // Apply updates using builder functions
        // Note: Password updates are handled separately for security
        let updated_profile =
            login_builder::update_login_profile(profile, request.password_reset_required);

        // Store updated profile
        self.write_store()
            .await
            .update_login_profile(updated_profile)
            .await
    }

    /// Delete a login profile
    pub async fn delete_login_profile(
        &self,
        context: &WamiContext,
        user: &ScopedName,
    ) -> Result<()> {
        guard(
            self.authz.as_ref(),
            context,
            WamiAction::IamManageCredentials,
            "user",
            user,
        )
        .await?;
        self.write_store().await.delete_login_profile(user).await
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
    async fn setup_service() -> LoginProfileService<InMemoryWamiStore> {
        use crate::store::traits::UserStore;
        let mut seeded = InMemoryWamiStore::default();
        for name in ["alice", "bob", "charlie", "david"] {
            let user =
                crate::wami::identity::user::builder::build_user(&key(name), None, &test_context())
                    .unwrap();
            seeded.create_user(user).await.unwrap();
        }
        LoginProfileService::new(Arc::new(RwLock::new(seeded)))
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
    async fn test_create_and_get_login_profile() {
        let service = setup_service().await;
        let context = test_context();

        let request = CreateLoginProfileRequest {
            user: key("alice"),
            password: "P@ssw0rd123!".to_string(), // Validated but not stored
            password_reset_required: true,
        };

        let profile = service
            .create_login_profile(&context, request)
            .await
            .unwrap();
        assert_eq!(profile.owner.name(), "alice");
        assert!(profile.password_reset_required);

        let retrieved = service
            .get_login_profile(&context, &key("alice"))
            .await
            .unwrap();
        assert!(retrieved.is_some());
        let retrieved_profile = retrieved.unwrap();
        assert_eq!(retrieved_profile.owner.name(), "alice");
        assert!(retrieved_profile.password_reset_required);
    }

    #[tokio::test]
    async fn test_update_login_profile() {
        let service = setup_service().await;
        let context = test_context();

        // Create profile
        let create_request = CreateLoginProfileRequest {
            user: key("bob"),
            password: "InitialP@ss123".to_string(),
            password_reset_required: true,
        };
        service
            .create_login_profile(&context, create_request)
            .await
            .unwrap();

        // Update profile - change password_reset_required flag
        let update_request = UpdateLoginProfileRequest {
            user: key("bob"),
            password: Some("NewP@ssw0rd456!".to_string()), // Password validation only
            password_reset_required: Some(false),
        };
        let updated = service
            .update_login_profile(&context, update_request)
            .await
            .unwrap();
        assert_eq!(updated.owner.name(), "bob");
        assert!(!updated.password_reset_required);
    }

    #[tokio::test]
    async fn test_delete_login_profile() {
        let service = setup_service().await;
        let context = test_context();

        let request = CreateLoginProfileRequest {
            user: key("charlie"),
            password: "TempP@ss789".to_string(),
            password_reset_required: false,
        };
        service
            .create_login_profile(&context, request)
            .await
            .unwrap();

        service
            .delete_login_profile(&context, &key("charlie"))
            .await
            .unwrap();

        let retrieved = service
            .get_login_profile(&context, &key("charlie"))
            .await
            .unwrap();
        assert!(retrieved.is_none());
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
    async fn test_guard_create_login_profile_denied() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let service = LoginProfileService::with_authorizer(store, Arc::new(DenyAllAuthorizer));
        let context = test_context();

        let request = CreateLoginProfileRequest {
            user: key("alice"),
            password: "P@ssw0rd123!".to_string(),
            password_reset_required: false,
        };

        let result = service.create_login_profile(&context, request).await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn test_guard_get_login_profile_denied() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let service = LoginProfileService::with_authorizer(store, Arc::new(DenyAllAuthorizer));
        let context = test_context();

        let result = service.get_login_profile(&context, &key("alice")).await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn test_guard_update_login_profile_denied() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let service = LoginProfileService::with_authorizer(store, Arc::new(DenyAllAuthorizer));
        let context = test_context();

        let request = UpdateLoginProfileRequest {
            user: key("alice"),
            password: None,
            password_reset_required: Some(true),
        };

        let result = service.update_login_profile(&context, request).await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn test_guard_delete_login_profile_denied() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let service = LoginProfileService::with_authorizer(store, Arc::new(DenyAllAuthorizer));
        let context = test_context();

        let result = service.delete_login_profile(&context, &key("alice")).await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }
}
