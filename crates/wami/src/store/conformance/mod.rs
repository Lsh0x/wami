//! A conformance suite every store implementation must pass (wami 005).
//!
//! Each check is a plain `async fn` taking a **fresh, empty** store and
//! panicking when the store breaks the property it is named for. A backend
//! runs them from its own tests, one `#[tokio::test]` per check, so "every
//! store keys principals by (tenant, name)" holds by construction rather than
//! by review: wami's memory store runs them in `tests/conformance_memory.rs`.
//!
//! Each check asks only for the store traits it traverses, so a backend that
//! implements a subset of [`WamiStore`](crate::store::WamiStore) runs the
//! checks that subset reaches. A store of exactly `UserStore`, `RoleStore`,
//! `PolicyStore` and `AccessKeyStore` — no groups, no other credential kind —
//! runs the user, role and policy key checks, the user and role freed-name
//! checks, [`names`] and [`root`]: wami's `tests/conformance_minimal.rs`
//! compiles and passes them against such a store, so the claim is a build,
//! not a comment. The evaluator's checks ([`conditions`], [`caller_key`],
//! most of [`guard`], [`policies`], [`scope`]) need its traits —
//! `UserStore`, `GroupStore`, `RoleStore`, `PolicyStore`
//! ([`conditions::EvaluatorStore`]) — plus what each names.
//!
//! Every check asserts its arrange (both records present, distinct ids)
//! before its property: a check whose fixture silently failed would pass on
//! the very defect it is there to catch.
//!
//! Behind the `conformance` feature: it is test code shipped for other
//! crates' tests, not something a consumer runs.
//!
//! A backend runs it from its own tests, with `wami = { features =
//! ["conformance"] }` among its dev-dependencies — one test per check, each
//! handed a fresh store:
//!
//! ```rust,ignore
//! use wami::store::conformance::{keys, Shared};
//!
//! fn fresh() -> Shared<MyStore> {
//!     std::sync::Arc::new(tokio::sync::RwLock::new(MyStore::empty()))
//! }
//!
//! #[tokio::test]
//! async fn two_tenants_each_hold_a_user_of_one_name() {
//!     keys::two_tenants_each_hold_a_user_of_one_name(fresh()).await;
//! }
//! ```
//!
//! The modules: [`keys`] (S1, S3, a held policy ARN, freed names),
//! [`guard`] (S2, S11, S12, S13, deletion tasks, policies, renames, caller
//! identity, ids judged on owner and record, one instance per store),
//! [`names`] (S4), [`root`] (S5), [`scope`] (S6, S10, S13, foreign
//! policies), [`caller_key`] (S9, S13 sessions, S15), [`conditions`]
//! (aws:username, `${principal}`, tenant keys) and [`policies`] (a policy
//! decides only its own tenant's principals). The source scans (S7, S14) are
//! wami's own, in `tests/keys_scan.rs`.

pub mod caller_key;
pub mod conditions;
pub mod guard;
pub mod keys;
pub mod names;
pub mod policies;
pub mod root;
pub mod scope;

use std::sync::Arc;
use tokio::sync::RwLock;
use wami_core::arn::{ScopedName, Service, TenantPath, WamiArn};
use wami_core::context::WamiContext;

/// The instance every check works in.
pub const INSTANCE: &str = "conformance";

/// Tenant `5/7`: shares its leaf with [`t67`], so a store keyed by the leaf
/// fails the checks as surely as one keyed by the bare name.
pub fn t57() -> TenantPath {
    TenantPath::new(vec![5, 7])
}

/// Tenant `6/7`.
pub fn t67() -> TenantPath {
    TenantPath::new(vec![6, 7])
}

/// `name` in `tenant`.
pub fn key(tenant: &TenantPath, name: &str) -> ScopedName {
    ScopedName::new(tenant.clone(), name)
}

/// A caller of `tenant` named `name`, for services built without an
/// authorizer: the checks of this module are about what the store holds, not
/// about who may ask.
///
/// # Panics
///
/// When the context cannot be built, which would be a defect of the suite.
pub fn caller(tenant: &TenantPath, name: &str) -> WamiContext {
    let arn = WamiArn::builder()
        .service(Service::Iam)
        .tenant_path(tenant.clone())
        .wami_instance(INSTANCE)
        .resource("user", name)
        .build()
        .expect("a caller ARN");
    WamiContext::builder()
        .instance_id(INSTANCE)
        .tenant_path(tenant.clone())
        .caller_arn(arn)
        .is_root(false)
        .build()
        .expect("a caller context")
}

/// The store a check is handed, as every service takes it.
pub type Shared<S> = Arc<RwLock<S>>;
