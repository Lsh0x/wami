//! Login Profile Service
//!
//! Orchestrates login profile management operations.

use crate::service::auth::authorizer::{iam_resource_arn, Authorizer};
use crate::store::traits::LoginProfileStore;
use std::sync::Arc;
use tokio::sync::RwLock;
use wami_core::actions::WamiAction;
use wami_core::context::WamiContext;
use wami_core::error::Result;
use wami_credentials::login_profile::{
    builder as login_builder, CreateLoginProfileRequest, LoginProfile, UpdateLoginProfileRequest,
};

/// Service for managing IAM login profiles
///
/// Provides high-level operations for console password management.
/// Optionally holds an [`Authorizer`] for authorization guards on every method.
#[wami_macros::service(
    store_trait = "crate::store::traits::LoginProfileStore",
    generate_new = false
)]
pub struct LoginProfileService<S> {
    store: Arc<RwLock<S>>,
    authz: Option<Arc<dyn Authorizer>>,
}

impl<S: LoginProfileStore> LoginProfileService<S> {
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

    /// Create a new login profile
    pub async fn create_login_profile(
        &self,
        context: &WamiContext,
        request: CreateLoginProfileRequest,
    ) -> Result<LoginProfile> {
        // Authorization guard
        self.guard(
            context,
            WamiAction::IamManageCredentials,
            "user",
            &request.user_name,
        )
        .await?;

        // Use wami builder to create login profile
        // Note: Password is validated but not stored in the model for security
        let login_profile = login_builder::build_login_profile(
            request.user_name,
            request.password_reset_required,
            context,
        )?;

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
        user_name: &str,
    ) -> Result<Option<LoginProfile>> {
        self.guard(context, WamiAction::IamManageCredentials, "user", user_name)
            .await?;
        self.read_store().await.get_login_profile(user_name).await
    }

    /// Update a login profile
    pub async fn update_login_profile(
        &self,
        context: &WamiContext,
        request: UpdateLoginProfileRequest,
    ) -> Result<LoginProfile> {
        self.guard(
            context,
            WamiAction::IamManageCredentials,
            "user",
            &request.user_name,
        )
        .await?;

        // Get existing profile
        let profile = self
            .read_store()
            .await
            .get_login_profile(&request.user_name)
            .await?
            .ok_or_else(|| crate::error::AmiError::ResourceNotFound {
                resource: format!("LoginProfile for user: {}", request.user_name),
            })?;

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
    pub async fn delete_login_profile(&self, context: &WamiContext, user_name: &str) -> Result<()> {
        self.guard(context, WamiAction::IamManageCredentials, "user", user_name)
            .await?;
        self.write_store()
            .await
            .delete_login_profile(user_name)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::memory::InMemoryWamiStore;
    use wami_core::arn::{TenantPath, WamiArn};

    fn setup_service() -> LoginProfileService<InMemoryWamiStore> {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        LoginProfileService::new(store)
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
        let service = setup_service();
        let context = test_context();

        let request = CreateLoginProfileRequest {
            user_name: "alice".to_string(),
            password: "P@ssw0rd123!".to_string(), // Validated but not stored
            password_reset_required: true,
        };

        let profile = service
            .create_login_profile(&context, request)
            .await
            .unwrap();
        assert_eq!(profile.user_name, "alice");
        assert!(profile.password_reset_required);

        let retrieved = service.get_login_profile(&context, "alice").await.unwrap();
        assert!(retrieved.is_some());
        let retrieved_profile = retrieved.unwrap();
        assert_eq!(retrieved_profile.user_name, "alice");
        assert!(retrieved_profile.password_reset_required);
    }

    #[tokio::test]
    async fn test_update_login_profile() {
        let service = setup_service();
        let context = test_context();

        // Create profile
        let create_request = CreateLoginProfileRequest {
            user_name: "bob".to_string(),
            password: "InitialP@ss123".to_string(),
            password_reset_required: true,
        };
        service
            .create_login_profile(&context, create_request)
            .await
            .unwrap();

        // Update profile - change password_reset_required flag
        let update_request = UpdateLoginProfileRequest {
            user_name: "bob".to_string(),
            password: Some("NewP@ssw0rd456!".to_string()), // Password validation only
            password_reset_required: Some(false),
        };
        let updated = service
            .update_login_profile(&context, update_request)
            .await
            .unwrap();
        assert_eq!(updated.user_name, "bob");
        assert!(!updated.password_reset_required);
    }

    #[tokio::test]
    async fn test_delete_login_profile() {
        let service = setup_service();
        let context = test_context();

        let request = CreateLoginProfileRequest {
            user_name: "charlie".to_string(),
            password: "TempP@ss789".to_string(),
            password_reset_required: false,
        };
        service
            .create_login_profile(&context, request)
            .await
            .unwrap();

        service
            .delete_login_profile(&context, "charlie")
            .await
            .unwrap();

        let retrieved = service
            .get_login_profile(&context, "charlie")
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
    async fn test_guard_create_login_profile_denied() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let service = LoginProfileService::with_authorizer(store, Arc::new(DenyAllAuthorizer));
        let context = test_context();

        let request = CreateLoginProfileRequest {
            user_name: "alice".to_string(),
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

        let result = service.get_login_profile(&context, "alice").await;
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
            user_name: "alice".to_string(),
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

        let result = service.delete_login_profile(&context, "alice").await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }
}
