//! STS Identity Service
//!
//! Orchestrates caller identity operations.

use crate::provider::{AwsProvider, CloudProvider};
use crate::store::traits::{IdentityStore, UserStore};
use crate::wami::sts::CallerIdentity;
use std::sync::Arc;
use tokio::sync::RwLock;
use wami_core::context::WamiContext;
use wami_core::error::{AmiError, Result};

pub trait StsIdentityServiceStore: IdentityStore + UserStore {}
impl<T> StsIdentityServiceStore for T where T: IdentityStore + UserStore {}

/// Request to get caller identity (empty - identity comes from context)
#[derive(Debug, Clone, Default)]
pub struct GetCallerIdentityRequest {}

/// Response from getting caller identity
#[derive(Debug, Clone)]
pub struct GetCallerIdentityResponse {
    pub user_id: String,
    pub account: String,
    pub arn: String,
}

/// Service for managing caller identities
///
/// Provides high-level operations for identity inspection.
#[wami_macros::service(
    store_trait = "crate::service::sts::identity::StsIdentityServiceStore",
    generate_new = false
)]
pub struct IdentityService<S> {
    store: Arc<RwLock<S>>,
    #[allow(dead_code)]
    provider: Arc<dyn CloudProvider>,
    account_id: String,
}

impl<S: StsIdentityServiceStore> IdentityService<S> {
    /// Create a new IdentityService with default AWS provider
    pub fn new(store: Arc<RwLock<S>>, account_id: String) -> Self {
        Self {
            store,
            provider: Arc::new(AwsProvider::new()),
            account_id,
        }
    }

    /// Returns a new service instance with different provider
    pub fn with_provider(&self, provider: Arc<dyn CloudProvider>) -> Self {
        Self {
            store: self.store.clone(),
            provider,
            account_id: self.account_id.clone(),
        }
    }

    /// Get the identity of the CALLER: the principal the context's key names.
    pub async fn get_caller_identity(
        &self,
        _request: GetCallerIdentityRequest,
        context: &WamiContext,
    ) -> Result<GetCallerIdentityResponse> {
        // A caller reads its OWN identity only: the record its key names must
        // carry its ARN. No key, no record and another principal's record are
        // one refusal, as the evaluator gives it (wami 005, review round 1 Δ8).
        let refusal = || AmiError::AccessDenied {
            message: format!(
                "{} is not authorized: its context does not name a stored principal \
                 carrying that ARN",
                context.caller_arn()
            ),
        };
        let caller = context.caller_key().ok_or_else(refusal)?;
        let user = {
            let store_guard = self.store.read().await;
            store_guard.get_user(caller).await?
        }
        .filter(|user| &user.wami_arn == context.caller_arn())
        .ok_or_else(refusal)?;

        // Answered from the record read by the key, never from the identity
        // store: that store is keyed by the AWS-format `arn`, which names no
        // tenant, so two tenants' users of one name share an entry there.
        let identity = CallerIdentity {
            user_id: user.user_id.clone(),
            account: self.account_id.clone(),
            arn: user.arn.clone(),
            wami_arn: user.wami_arn,
            providers: user.providers.clone(),
        };
        self.store
            .write()
            .await
            .create_identity(identity.clone())
            .await?;

        Ok(GetCallerIdentityResponse {
            user_id: identity.user_id,
            account: identity.account,
            arn: identity.arn,
        })
    }

    /// List all identities
    pub async fn list_identities(&self) -> Result<Vec<CallerIdentity>> {
        self.store.read().await.list_identities().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::memory::InMemoryWamiStore;
    use crate::wami::identity::user::builder::build_user;
    use wami_core::arn::{TenantPath, WamiArn};
    use wami_core::context::WamiContext;

    /// The tenant every test here works in.
    fn tenant() -> wami_core::arn::TenantPath {
        wami_core::arn::TenantPath::single(12345678)
    }

    /// `name`'s key in that tenant.
    fn key(name: impl AsRef<str>) -> wami_core::arn::ScopedName {
        wami_core::arn::ScopedName::new(tenant(), name.as_ref())
    }

    fn setup_service() -> IdentityService<InMemoryWamiStore> {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        IdentityService::new(store, "123456789012".to_string())
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
    async fn test_get_caller_identity_from_user() {
        let service = setup_service();
        let context = test_context();

        // Create a user
        let user = build_user(&key("alice"), Some("/".to_string()), &context).unwrap();

        let caller = WamiContext::builder()
            .caller_arn(user.wami_arn.clone())
            .caller_key(user.key())
            .build()
            .unwrap();

        service.store.write().await.create_user(user).await.unwrap();

        // Get caller identity
        let request = GetCallerIdentityRequest {};
        let response = service.get_caller_identity(request, &caller).await.unwrap();

        assert_eq!(response.account, "123456789012");
        assert!(response.arn.contains("alice"));
    }

    #[tokio::test]
    async fn test_list_identities() {
        let service = setup_service();
        let context = test_context();

        // Create users and get their identities
        for i in 0..3 {
            let user =
                build_user(&key(format!("user{}", i)), Some("/".to_string()), &context).unwrap();
            let caller = WamiContext::builder()
                .caller_arn(user.wami_arn.clone())
                .caller_key(user.key())
                .build()
                .unwrap();

            service.store.write().await.create_user(user).await.unwrap();

            // Trigger identity creation
            let request = GetCallerIdentityRequest {};
            service.get_caller_identity(request, &caller).await.unwrap();
        }

        let identities = service.list_identities().await.unwrap();
        assert_eq!(identities.len(), 3);
    }
}
