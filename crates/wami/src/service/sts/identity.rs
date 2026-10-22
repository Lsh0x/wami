//! STS Identity Service
//!
//! Orchestrates caller identity operations.

use crate::provider::{AwsProvider, CloudProvider};
use crate::store::traits::{IdentityStore, UserStore};
use crate::wami::identity::User;
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

    /// The caller's own record: the one its key names, carrying its ARN.
    /// No key, no record and another principal's record are one refusal, as
    /// the evaluator gives it (wami 005, review round 1 Δ8).
    async fn verified_caller(&self, context: &WamiContext) -> Result<User> {
        let refusal = || AmiError::AccessDenied {
            message: format!(
                "{} is not authorized: its context does not name a stored principal \
                 carrying that ARN",
                context.caller_arn()
            ),
        };
        let caller = context.caller_key().ok_or_else(refusal)?;
        let user = self.store.read().await.get_user(caller).await?;
        user.filter(|user| &user.wami_arn == context.caller_arn())
            .ok_or_else(refusal)
    }

    /// Get the identity of the CALLER: the principal the context's key names.
    pub async fn get_caller_identity(
        &self,
        _request: GetCallerIdentityRequest,
        context: &WamiContext,
    ) -> Result<GetCallerIdentityResponse> {
        let user = self.verified_caller(context).await?;
        let key = user.key();

        // Answered from the record read by the key, and written under that
        // key — tenant and name — never under the AWS-format `arn`, which
        // names no tenant (review round 2 F4).
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
            .create_identity(&key, identity.clone())
            .await?;

        Ok(GetCallerIdentityResponse {
            user_id: identity.user_id,
            account: identity.account,
            arn: identity.arn,
        })
    }

    /// List the identities of the caller's OWN tenant — its verified key's,
    /// never a tenant it declares; a caller with no stored principal behind
    /// its key is refused (review round 2 F4).
    pub async fn list_identities(&self, context: &WamiContext) -> Result<Vec<CallerIdentity>> {
        let user = self.verified_caller(context).await?;
        self.store
            .read()
            .await
            .list_identities(user.key().tenant())
            .await
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
        let mut last = None;

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
            last = Some(caller);
        }

        let identities = service.list_identities(&last.unwrap()).await.unwrap();
        assert_eq!(identities.len(), 3);
    }

    /// `name` of `tenant`, stored, and the context its own record gives it.
    async fn signed_in(
        service: &IdentityService<InMemoryWamiStore>,
        tenant: &[u64],
        name: &str,
    ) -> WamiContext {
        let key = wami_core::arn::ScopedName::new(TenantPath::new(tenant.to_vec()), name);
        let user = build_user(&key, None, &test_context()).unwrap();
        let caller = WamiContext::builder()
            .caller_arn(user.wami_arn.clone())
            .caller_key(user.key())
            .build()
            .unwrap();
        service.store.write().await.create_user(user).await.unwrap();
        caller
    }

    #[tokio::test]
    async fn two_tenants_users_of_one_name_keep_two_identities() {
        // Keyed by the AWS-format arn, which names no tenant, 6/7's alice
        // overwrote 5/7's (wami 005, review round 2 F4).
        let service = setup_service();
        let mut ids = Vec::new();
        for tenant in [[5, 7], [6, 7]] {
            let caller = signed_in(&service, &tenant, "alice").await;
            let answer = service
                .get_caller_identity(GetCallerIdentityRequest {}, &caller)
                .await
                .unwrap();
            ids.push((caller.caller_key().unwrap().clone(), answer.user_id));
        }
        let store = service.store.read().await;
        for (key, user_id) in &ids {
            let entry = store.get_identity(key).await.unwrap();
            assert_eq!(
                entry.map(|e| e.user_id).as_ref(),
                Some(user_id),
                "{key}'s entry"
            );
        }
        assert_ne!(ids[0].1, ids[1].1, "two principals");
    }

    #[tokio::test]
    async fn a_caller_lists_its_own_tenants_identities_only() {
        let service = setup_service();
        let mut callers = Vec::new();
        for (tenant, name) in [([5, 7], "alice"), ([6, 7], "bob")] {
            let caller = signed_in(&service, &tenant, name).await;
            service
                .get_caller_identity(GetCallerIdentityRequest {}, &caller)
                .await
                .unwrap();
            callers.push(caller);
        }
        let listed = service.list_identities(&callers[0]).await.unwrap();
        let theirs: Vec<_> = listed
            .iter()
            .filter(|i| i.wami_arn.tenant_path != TenantPath::new(vec![5, 7]))
            .collect();
        assert_eq!(theirs.len(), 0, "another tenant's identities: {theirs:?}");
        assert_eq!(listed.len(), 1, "its own tenant's: {listed:?}");

        // A cross-tenant list: alice naming 6/7's bob as her key, declared
        // in 6/7 — no longer even built (round 3 L3: a key of another tenant
        // than the caller's is refused at build, as on the wire).
        let forged = WamiContext::builder()
            .caller_arn(callers[0].caller_arn().clone())
            .tenant_path(TenantPath::new(vec![6, 7]))
            .caller_key(callers[1].caller_key().unwrap().clone())
            .build();
        assert!(forged.is_err(), "another tenant's key built: {forged:?}");
        // Without a key, a declared 6/7 is refused at use, as no key at all.
        let keyless = WamiContext::builder()
            .caller_arn(callers[0].caller_arn().clone())
            .tenant_path(TenantPath::new(vec![6, 7]))
            .build()
            .unwrap();
        let got = service.list_identities(&keyless).await;
        assert!(
            matches!(&got, Err(AmiError::AccessDenied { .. })),
            "no key: {got:?}"
        );
    }
}
