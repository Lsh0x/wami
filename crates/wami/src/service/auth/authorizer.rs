//! Authorizer trait — object-safe interface for authorization checks.
//!
//! This trait decouples services from the concrete `AuthorizationService<S>`,
//! allowing injection via `Arc<dyn Authorizer>` without widening store trait bounds.

use async_trait::async_trait;
use std::sync::Arc;
use wami_core::arn::WamiArn;
use wami_core::context::WamiContext;
use wami_core::error::Result;

/// Object-safe authorization interface.
///
/// Services hold an `Option<Arc<dyn Authorizer>>` and call [`Authorizer::check_or_deny`]
/// at the top of each method. When `None`, no authorization check is performed
/// (backward compatibility with existing callers).
#[async_trait]
pub trait Authorizer: Send + Sync {
    /// Check if `context` is allowed to perform `action` on `resource_arn`.
    ///
    /// Returns `Ok(true)` if allowed, `Ok(false)` if denied.
    async fn authorize(
        &self,
        context: &WamiContext,
        action: &str,
        resource_arn: &WamiArn,
    ) -> Result<bool>;

    /// Like [`Authorizer::authorize`], but returns `Err(AccessDenied)` instead of `Ok(false)`.
    async fn check_or_deny(
        &self,
        context: &WamiContext,
        action: &str,
        resource_arn: &WamiArn,
    ) -> Result<()>;
}

/// Helper: build a WAMI ARN for an IAM resource from the caller's context.
///
/// Produces: `arn:wami:iam:{tenant}:wami:{instance}:{resource_type}/{resource_id}`
pub fn iam_resource_arn(
    context: &WamiContext,
    resource_type: &str,
    resource_id: &str,
) -> Result<WamiArn> {
    use wami_core::arn::{Resource, Service};

    Ok(WamiArn {
        service: Service::Iam,
        tenant_path: context.tenant_path().clone(),
        wami_instance_id: context.instance_id().to_string(),
        cloud_mapping: None,
        resource: Resource {
            resource_type: resource_type.to_string(),
            resource_id: resource_id.to_string(),
        },
    })
}

/// Extension: implement `Authorizer` for the concrete `AuthorizationService<S>`.
///
/// This is done via a blanket impl so any `AuthorizationService<S>` can be
/// used as `Arc<dyn Authorizer>`.
mod impl_for_authz_service {
    use super::*;
    use crate::service::auth::authorization::AuthorizationService;
    use crate::store::traits::{GroupStore, PolicyStore, RoleStore, UserStore};

    #[async_trait]
    impl<S> Authorizer for AuthorizationService<S>
    where
        S: UserStore + GroupStore + RoleStore + PolicyStore + Send + Sync + 'static,
    {
        async fn authorize(
            &self,
            context: &WamiContext,
            action: &str,
            resource_arn: &WamiArn,
        ) -> Result<bool> {
            AuthorizationService::authorize(self, context, action, resource_arn).await
        }

        async fn check_or_deny(
            &self,
            context: &WamiContext,
            action: &str,
            resource_arn: &WamiArn,
        ) -> Result<()> {
            AuthorizationService::check_or_deny(self, context, action, resource_arn).await
        }
    }

    /// Convenience: wrap an `AuthorizationService<S>` into an `Arc<dyn Authorizer>`.
    pub fn into_authorizer<S>(service: AuthorizationService<S>) -> Arc<dyn Authorizer>
    where
        S: UserStore + GroupStore + RoleStore + PolicyStore + Send + Sync + 'static,
    {
        Arc::new(service)
    }
}

pub use impl_for_authz_service::into_authorizer;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::auth::authorization::AuthorizationService;
    use crate::store::memory::InMemoryWamiStore;
    use crate::store::traits::UserStore;
    use crate::wami::identity::user::builder as user_builder;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use wami_core::arn::TenantPath;
    use wami_core::context::WamiContext;
    use wami_core::error::AmiError;

    fn make_context() -> WamiContext {
        let arn: WamiArn = "arn:wami:iam:12345678:wami:999:user/alice".parse().unwrap();
        WamiContext::builder()
            .instance_id("999")
            .tenant_path(TenantPath::single(12345678))
            .caller_arn(arn)
            .is_root(false)
            .build()
            .unwrap()
    }

    // ---- iam_resource_arn tests ----

    #[test]
    fn test_iam_resource_arn_produces_correct_arn() {
        let ctx = make_context();
        let arn = iam_resource_arn(&ctx, "user", "bob").unwrap();

        assert_eq!(arn.to_string(), "arn:wami:iam:12345678:wami:999:user/bob");
    }

    #[test]
    fn test_iam_resource_arn_with_role_type() {
        let ctx = make_context();
        let arn = iam_resource_arn(&ctx, "role", "admin-role").unwrap();

        assert_eq!(
            arn.to_string(),
            "arn:wami:iam:12345678:wami:999:role/admin-role"
        );
    }

    #[test]
    fn test_iam_resource_arn_with_policy_type() {
        let ctx = make_context();
        let arn = iam_resource_arn(&ctx, "policy", "readonly").unwrap();

        assert_eq!(
            arn.to_string(),
            "arn:wami:iam:12345678:wami:999:policy/readonly"
        );
    }

    // ---- into_authorizer tests ----

    #[test]
    fn test_into_authorizer_returns_arc_dyn_authorizer() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let service = AuthorizationService::new(store);
        let authorizer: Arc<dyn Authorizer> = into_authorizer(service);

        // Confirm we get a valid Arc<dyn Authorizer> (the type system enforces this,
        // but we verify it is usable as a trait object).
        assert_eq!(Arc::strong_count(&authorizer), 1);
    }

    // ---- Authorizer trait delegation tests ----

    fn allow_policy_json(actions: &[&str], resources: &[&str]) -> String {
        let actions_json: Vec<String> = actions.iter().map(|a| format!("\"{}\"", a)).collect();
        let resources_json: Vec<String> = resources.iter().map(|r| format!("\"{}\"", r)).collect();
        format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":[{}],"Resource":[{}]}}]}}"#,
            actions_json.join(","),
            resources_json.join(",")
        )
    }

    async fn setup_store_with_allow_policy(ctx: &WamiContext) -> Arc<RwLock<InMemoryWamiStore>> {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let user =
            user_builder::build_user("alice".to_string(), Some("/".to_string()), ctx).unwrap();
        store.write().await.create_user(user).await.unwrap();

        // Give alice an inline policy that allows iam:*
        store
            .write()
            .await
            .put_user_policy("alice", "AllowAll", allow_policy_json(&["iam:*"], &["*"]))
            .await
            .unwrap();

        store
    }

    #[tokio::test]
    async fn test_authorizer_trait_authorize_delegates_allow() {
        let ctx = make_context();
        let store = setup_store_with_allow_policy(&ctx).await;
        let authorizer: Arc<dyn Authorizer> = into_authorizer(AuthorizationService::new(store));

        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();
        let allowed = authorizer
            .authorize(&ctx, "iam:GetUser", &resource)
            .await
            .unwrap();
        assert!(allowed);
    }

    #[tokio::test]
    async fn test_authorizer_trait_authorize_delegates_deny() {
        let ctx = make_context();
        // Store with user but no policies -> default deny
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let user =
            user_builder::build_user("alice".to_string(), Some("/".to_string()), &ctx).unwrap();
        store.write().await.create_user(user).await.unwrap();

        let authorizer: Arc<dyn Authorizer> = into_authorizer(AuthorizationService::new(store));
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();
        let allowed = authorizer
            .authorize(&ctx, "iam:GetUser", &resource)
            .await
            .unwrap();
        assert!(!allowed);
    }

    #[tokio::test]
    async fn test_authorizer_trait_check_or_deny_ok() {
        let ctx = make_context();
        let store = setup_store_with_allow_policy(&ctx).await;
        let authorizer: Arc<dyn Authorizer> = into_authorizer(AuthorizationService::new(store));

        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();
        let result = authorizer
            .check_or_deny(&ctx, "iam:GetUser", &resource)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_authorizer_trait_check_or_deny_returns_access_denied() {
        let ctx = make_context();
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let user =
            user_builder::build_user("alice".to_string(), Some("/".to_string()), &ctx).unwrap();
        store.write().await.create_user(user).await.unwrap();

        let authorizer: Arc<dyn Authorizer> = into_authorizer(AuthorizationService::new(store));
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();
        let err = authorizer
            .check_or_deny(&ctx, "iam:GetUser", &resource)
            .await
            .unwrap_err();

        assert!(
            matches!(err, AmiError::AccessDenied { .. }),
            "Expected AccessDenied, got: {:?}",
            err
        );
    }
}
