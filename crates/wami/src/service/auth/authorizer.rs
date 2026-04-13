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
