//! wami's memory store against the store conformance suite (wami 005).
#![cfg(feature = "conformance")]

use std::sync::Arc;
use tokio::sync::RwLock;
use wami::store::conformance::{keys, Shared};
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
);
