//! wami's memory store against the store conformance suite (wami 005).
#![cfg(feature = "conformance")]

use std::sync::Arc;
use tokio::sync::RwLock;
use wami::store::conformance::{guard, keys, names, Shared};
use wami::store::memory::InMemoryWamiStore;

fn fresh() -> Shared<InMemoryWamiStore> {
    Arc::new(RwLock::new(InMemoryWamiStore::default()))
}

/// One `#[tokio::test]` per check, named as the check is.
macro_rules! conformance {
    ($($module:ident :: $check:ident),* $(,)?) => {
        $(
            #[tokio::test]
            async fn $check() {
                $module::$check(fresh()).await;
            }
        )*
    };
}

conformance!(
    keys::two_tenants_each_hold_a_user_of_one_name,
    keys::two_tenants_each_hold_a_group_of_one_name,
    keys::two_tenants_each_hold_a_role_of_one_name,
    keys::a_create_on_a_held_user_key_is_refused,
    keys::a_create_on_a_held_group_key_is_refused,
    keys::a_create_on_a_held_role_key_is_refused,
    keys::a_create_on_a_held_policy_arn_is_refused,
    keys::a_deleted_users_name_hands_nothing_to_its_next_holder,
    keys::a_renamed_user_carries_everything_and_leaves_nothing_behind,
    keys::a_freed_group_or_role_name_hands_nothing_to_its_next_holder,
    guard::a_tenant_admin_is_refused_on_another_tenants_users,
    guard::a_tenant_admin_is_refused_every_credential_of_another_tenant,
    guard::a_credential_takes_its_owners_tenant_never_the_callers,
    guard::an_allow_on_one_tenants_alice_never_reaches_anothers,
    guard::every_family_refuses_another_tenants_target,
    guard::a_deletion_task_is_judged_on_its_roles_tenant,
    guard::a_policy_is_judged_in_its_own_tenant,
    names::a_reserved_name_is_refused_at_create_in_every_tenant,
    names::a_reserved_name_is_refused_at_rename,
);
