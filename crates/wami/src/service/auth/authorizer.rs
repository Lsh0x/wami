//! Authorizer trait — object-safe interface for authorization checks.
//!
//! This trait decouples services from the concrete `AuthorizationService<S>`,
//! allowing injection via `Arc<dyn Authorizer>` without widening store trait bounds.

use async_trait::async_trait;
use std::sync::Arc;
use wami_core::actions::WamiAction;
use wami_core::arn::{Resource, ScopedName, Service, TenantPath, WamiArn};
use wami_core::context::WamiContext;
use wami_core::error::{AmiError, Result};

use super::decision::{Decision, DenyReason};

/// Object-safe authorization interface.
///
/// Services hold an `Option<Arc<dyn Authorizer>>` and call [`Authorizer::check_or_deny`]
/// at the top of each method. When `None`, no authorization check is performed
/// (backward compatibility with existing callers).
///
/// The check AT USE of the caller's key — the record it names must carry the
/// caller ARN, a session's role likewise, policies only of the principal's
/// tenant (wami 005) — lives in wami's implementation,
/// `AuthorizationService::authorize`, which holds the store; the trait and
/// the guards get no store handle. An implementation of this trait of one's
/// own decides without those checks unless it makes them.
#[async_trait]
pub trait Authorizer: Send + Sync {
    /// Decide whether `context` may perform `action` on `resource_arn`.
    ///
    /// Returns the verdict *and what produced it*, so a caller can write an
    /// audit line naming the statement that decided, and tell a refused user
    /// what they lack.
    ///
    /// # Errors
    ///
    /// [`AmiError::UnreadablePolicy`] when a policy document cannot be parsed.
    /// That is deliberately not a denial: an unreadable policy might have held
    /// a deny, so no decision can honestly be made from it — a statement's
    /// condition that cannot be read refuses the document the same way.
    ///
    /// [`AmiError::UnreadableCondition`] when a statement that reaches the
    /// request carries a condition that cannot be evaluated against it. Not a
    /// denial either, and for the same reason: that statement might have been
    /// a deny.
    ///
    /// [`AmiError::UnreadablePolicy`]: wami_core::error::AmiError::UnreadablePolicy
    /// [`AmiError::UnreadableCondition`]: wami_core::error::AmiError::UnreadableCondition
    async fn authorize(
        &self,
        context: &WamiContext,
        action: &str,
        resource_arn: &WamiArn,
    ) -> Result<Decision>;

    /// Like [`Authorizer::authorize`], but returns `Err(AccessDenied)` on refusal.
    ///
    /// Implemented in terms of `authorize`, so implementors only supply the
    /// latter — and the two cannot drift apart. The error message quotes the
    /// [`Decision`], which is why overriding this is rarely worth it.
    async fn check_or_deny(
        &self,
        context: &WamiContext,
        action: &str,
        resource_arn: &WamiArn,
    ) -> Result<()> {
        match self.authorize(context, action, resource_arn).await? {
            Decision::Allow(_) => Ok(()),
            denied => Err(AmiError::AccessDenied {
                message: format!(
                    "{} is not authorized to perform {} on {}: {}",
                    context.caller_arn(),
                    action,
                    resource_arn,
                    denied
                ),
            }),
        }
    }
}

/// The ARN a guard judges for the `kind` named by `target`:
/// `arn:wami:iam:{target's tenant}:wami:{instance}:{kind}/{target's name}`.
///
/// The tenant is the TARGET's, never the caller's (wami 005): rendered from
/// the caller's, a right on one tenant's `user/*` covered every tenant's
/// user of the same name. The resource is the name, so documents written as
/// `user/alice` or `user/*` keep their meaning.
pub fn target_arn(context: &WamiContext, kind: &str, target: &ScopedName) -> WamiArn {
    iam_arn(context, target.tenant(), kind, target.name())
}

/// The ARN a guard judges for a verb on every `kind` of `tenant` — a list:
/// `{kind}/*` in exactly that tenant.
pub fn tenant_arn(context: &WamiContext, kind: &str, tenant: &TenantPath) -> WamiArn {
    iam_arn(context, tenant, kind, "*")
}

/// `arn:wami:iam:{tenant}:wami:{instance}:{kind}/{id}`.
pub(crate) fn iam_arn(context: &WamiContext, tenant: &TenantPath, kind: &str, id: &str) -> WamiArn {
    WamiArn {
        service: Service::Iam,
        tenant_path: tenant.clone(),
        wami_instance_id: context.instance_id().to_string(),
        cloud_mapping: None,
        resource: Resource {
            resource_type: kind.to_string(),
            resource_id: id.to_string(),
        },
    }
}

/// THE guard (wami 005): judge `action` on `target`'s ARN, before anything is
/// read.
///
/// Every service calls this one function; there is no per-service copy. It
/// runs before the target is read, so a refusal is the same whether the
/// target exists or not — `NotFound` only ever follows an allowed guard. With
/// no authorizer, nothing is judged (services built without one).
///
/// # Errors
///
/// [`AmiError::AccessDenied`] naming the target's ARN when the decision is
/// not an Allow, and whatever the authorizer returns when it cannot decide.
pub async fn guard(
    authz: Option<&Arc<dyn Authorizer>>,
    context: &WamiContext,
    action: WamiAction,
    kind: &str,
    target: &ScopedName,
) -> Result<()> {
    guard_arn(authz, context, action, &target_arn(context, kind, target)).await
}

/// [`guard`] for a verb on a whole tenant (a list): judges `{kind}/*` in
/// `tenant`.
///
/// # Errors
///
/// As [`guard`].
pub async fn guard_tenant(
    authz: Option<&Arc<dyn Authorizer>>,
    context: &WamiContext,
    action: WamiAction,
    kind: &str,
    tenant: &TenantPath,
) -> Result<()> {
    guard_arn(authz, context, action, &tenant_arn(context, kind, tenant)).await
}

/// [`guard`] on an ARN already rendered from the target's stored tenant.
///
/// # Errors
///
/// As [`guard`].
pub async fn guard_arn(
    authz: Option<&Arc<dyn Authorizer>>,
    context: &WamiContext,
    action: WamiAction,
    arn: &WamiArn,
) -> Result<()> {
    match authz {
        Some(authz) => authz.check_or_deny(context, action.as_str(), arn).await,
        None => Ok(()),
    }
}

/// What a guard by id reads of the record it found under the id.
#[derive(Debug, Clone)]
pub struct Found {
    /// The instance the record belongs to. One store holds one instance: a
    /// record of another is refused as an absent one (review round 1, Δ12).
    pub instance: String,
    /// The ARN an Allow is needed on: its owner's key (`user/<owner>` in the
    /// owner's tenant) or, for a policy, its own ARN in its stored tenant.
    pub owner: WamiArn,
    /// The record's own ARN (`credential/<id>` in the owner's tenant), when
    /// it has one a document may name: a Deny on it wins too (A5, ruling 9).
    pub itself: Option<WamiArn>,
}

/// The guard for a record addressed by an id (an access key, an MFA serial, a
/// policy ARN, a deletion task): `found` is what the record READ under that
/// id says of itself, and `None` when nothing is stored there.
///
/// The record's owner must be allowed `action`, and an explicit Deny on the
/// record itself refuses it as well: an Allow needs the owner, a Deny on
/// either wins (A5). An absent id, a record of another instance (Δ12) and a
/// refusal are ONE answer, naming the id the caller gave and nothing else: a
/// message naming the owner, or saying "not found", would tell a caller with
/// no right who owns what, one probe at a time (A1). With no authorizer an
/// absent id is not refused: the verb answers as it always did.
///
/// # Errors
///
/// [`AmiError::AccessDenied`] naming `what` and `id`; any other error of the
/// authorizer as it came.
pub async fn guard_by_id(
    authz: Option<&Arc<dyn Authorizer>>,
    context: &WamiContext,
    action: WamiAction,
    what: &str,
    id: &str,
    found: Option<Found>,
) -> Result<()> {
    let Some(authz) = authz else {
        return Ok(());
    };
    let refusal = || AmiError::AccessDenied {
        message: format!(
            "{} is not authorized to perform {} on {what} {id}",
            context.caller_arn(),
            action.as_str()
        ),
    };
    let Some(found) = found.filter(|found| found.instance == context.instance_id()) else {
        return Err(refusal());
    };
    match authz
        .check_or_deny(context, action.as_str(), &found.owner)
        .await
    {
        Err(AmiError::AccessDenied { .. }) => return Err(refusal()),
        other => other?,
    }
    if let Some(itself) = &found.itself {
        if explicitly_denied(&authz.authorize(context, action.as_str(), itself).await?) {
            return Err(refusal());
        }
    }
    Ok(())
}

/// What a guard by id reads of a CREDENTIAL found under `id`: its owner's
/// key, its own `credential/<id>` in the owner's tenant, and its instance.
pub fn credential_found(
    context: &WamiContext,
    owner: &ScopedName,
    id: &str,
    instance: &str,
) -> Found {
    Found {
        instance: instance.to_string(),
        owner: target_arn(context, "user", owner),
        itself: Some(iam_arn(context, owner.tenant(), "credential", id)),
    }
}

/// A decision some statement refused outright — as opposed to nothing having
/// matched.
fn explicitly_denied(decision: &Decision) -> bool {
    match decision {
        Decision::Deny(DenyReason::Statements(_)) => true,
        Decision::Deny(DenyReason::BoundaryRestricted { denied_by, .. }) => !denied_by.is_empty(),
        _ => false,
    }
}

/// The record read by `requested` must be the one the guard judged: `read`
/// is the key the stored record carries, `read_instance` its instance.
///
/// For a store keyed by [`ScopedName`] the two are equal by construction;
/// this refuses a store that returns another record than the one asked for —
/// another tenant's of the same name — rather than acting on it.
///
/// # Errors
///
/// [`AmiError::AccessDenied`] naming the guarded ARN, the refusal a denied
/// guard gives, when the record is not the requested one.
pub fn confirm(
    context: &WamiContext,
    kind: &str,
    requested: &ScopedName,
    read: &ScopedName,
    read_instance: &str,
) -> Result<()> {
    if read == requested && read_instance == context.instance_id() {
        return Ok(());
    }
    Err(AmiError::AccessDenied {
        message: format!(
            "{} is not authorized to act on {}: the store returned another record",
            context.caller_arn(),
            target_arn(context, kind, requested)
        ),
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
        ) -> Result<Decision> {
            AuthorizationService::authorize(self, context, action, resource_arn).await
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
    use super::super::decision::{AllowReason, DenyReason};
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

    /// The key a test context names: its ARN's tenant and resource, as the
    /// test records are written under (test code: production never builds a
    /// key from an ARN, wami 005).
    fn keyed(arn: &wami_core::arn::WamiArn) -> wami_core::arn::ScopedName {
        wami_core::arn::ScopedName::new(arn.tenant_path.clone(), arn.resource.resource_id.clone())
    }

    /// The tenant every test here works in.
    fn tenant() -> wami_core::arn::TenantPath {
        wami_core::arn::TenantPath::single(12345678)
    }

    /// `name`'s key in that tenant.
    fn key(name: impl AsRef<str>) -> wami_core::arn::ScopedName {
        wami_core::arn::ScopedName::new(tenant(), name.as_ref())
    }

    fn make_context() -> WamiContext {
        let arn: WamiArn = "arn:wami:iam:12345678:wami:999:user/alice".parse().unwrap();
        WamiContext::builder()
            .instance_id("999")
            .tenant_path(TenantPath::single(12345678))
            .caller_key(keyed(&arn))
            .caller_arn(arn)
            .is_root(false)
            .build()
            .unwrap()
    }

    // ---- target_arn tests ----

    #[test]
    fn the_guarded_arn_takes_the_targets_tenant_never_the_callers() {
        // The caller is of 12345678; the target is 5/7's bob.
        let ctx = make_context();
        let bob = wami_core::arn::ScopedName::new(TenantPath::new(vec![5, 7]), "bob");
        assert_eq!(
            target_arn(&ctx, "user", &bob).to_string(),
            "arn:wami:iam:5/7:wami:999:user/bob"
        );
    }

    #[test]
    fn the_guarded_arn_carries_the_kind_and_the_name() {
        let ctx = make_context();
        assert_eq!(
            target_arn(&ctx, "role", &key("admin-role")).to_string(),
            "arn:wami:iam:12345678:wami:999:role/admin-role"
        );
    }

    #[test]
    fn a_list_is_guarded_on_every_kind_of_the_tenant_it_lists() {
        let ctx = make_context();
        assert_eq!(
            tenant_arn(&ctx, "user", &TenantPath::new(vec![6, 7])).to_string(),
            "arn:wami:iam:6/7:wami:999:user/*"
        );
    }

    #[test]
    fn confirm_refuses_a_record_of_another_tenant() {
        let ctx = make_context();
        let asked = wami_core::arn::ScopedName::new(TenantPath::new(vec![5, 7]), "alice");
        let other = wami_core::arn::ScopedName::new(TenantPath::new(vec![6, 7]), "alice");
        assert!(confirm(&ctx, "user", &asked, &asked, "999").is_ok());
        let refused = confirm(&ctx, "user", &asked, &other, "999");
        assert!(
            matches!(&refused, Err(AmiError::AccessDenied { message }) if message.contains("arn:wami:iam:5/7:wami:999:user/alice")),
            "{refused:?}"
        );
        assert!(confirm(&ctx, "user", &asked, &asked, "another-instance").is_err());
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
        let mut user = user_builder::build_user(&key("alice"), Some("/".to_string()), ctx).unwrap();
        user.wami_arn = ctx.caller_arn().clone();
        store.write().await.create_user(user).await.unwrap();

        // Give alice an inline policy that allows iam:*
        store
            .write()
            .await
            .put_user_policy(
                &key("alice"),
                "AllowAll",
                allow_policy_json(&["iam:*"], &["*"]),
            )
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
        assert!(allowed.is_allowed());
        // The grant names what granted it — that is the point of the change.
        assert!(matches!(
            allowed,
            Decision::Allow(AllowReason::Statements(_))
        ));
    }

    #[tokio::test]
    async fn test_authorizer_trait_authorize_delegates_deny() {
        let ctx = make_context();
        // Store with user but no policies -> default deny
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let mut user =
            user_builder::build_user(&key("alice"), Some("/".to_string()), &ctx).unwrap();
        user.wami_arn = ctx.caller_arn().clone();
        store.write().await.create_user(user).await.unwrap();

        let authorizer: Arc<dyn Authorizer> = into_authorizer(AuthorizationService::new(store));
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();
        let allowed = authorizer
            .authorize(&ctx, "iam:GetUser", &resource)
            .await
            .unwrap();
        // Nothing matched, so there is no statement to name.
        assert_eq!(allowed, Decision::Deny(DenyReason::NoMatch));
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
        let mut user =
            user_builder::build_user(&key("alice"), Some("/".to_string()), &ctx).unwrap();
        user.wami_arn = ctx.caller_arn().clone();
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
