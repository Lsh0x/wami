//! wami's memory store against the store conformance suite (wami 005).
#![cfg(feature = "conformance")]

use std::sync::Arc;
use tokio::sync::RwLock;
use wami::store::conformance::{
    caller_key, conditions, guard, keys, names, policies, root, scope, Shared,
};
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
    keys::a_freed_group_or_member_name_hands_nothing_to_its_next_holder,
    keys::a_freed_role_name_hands_nothing_to_its_next_holder,
    guard::a_tenant_admin_is_refused_on_another_tenants_users,
    guard::a_tenant_admin_is_refused_every_credential_of_another_tenant,
    guard::a_credential_takes_its_owners_tenant_never_the_callers,
    guard::an_allow_on_one_tenants_alice_never_reaches_anothers,
    guard::every_family_refuses_another_tenants_target,
    guard::a_deletion_task_is_judged_on_its_roles_tenant,
    guard::a_policy_is_judged_in_its_own_tenant,
    guard::a_rename_is_judged_on_its_destination,
    guard::caller_identity_answers_the_caller_only,
    guard::every_credential_verb_refuses_another_tenant,
    guard::a_credential_by_id_is_judged_on_its_owner_and_on_itself,
    guard::a_record_of_another_instance_is_refused_as_absent,
    names::a_reserved_name_is_refused_at_create_in_every_tenant,
    names::a_reserved_name_is_refused_at_rename,
    root::only_the_principal_at_path_zero_authenticates_as_root,
    scope::a_list_returns_exactly_the_tenant_it_names,
    scope::a_principals_policies_are_never_found_for_another_tenants_namesake,
    scope::a_policy_never_crosses_into_another_tenant,
    scope::simulation_and_caller_identity_read_the_named_tenant,
    caller_key::an_authenticated_principal_finds_its_own_policy_and_only_its_own,
    caller_key::a_session_is_judged_on_its_roles_policies_only,
    caller_key::a_forged_caller_key_decides_nothing,
    conditions::aws_username_is_the_callers_name,
    conditions::the_principal_variable_is_the_callers_name,
    conditions::tenant_condition_keys_are_full_paths,
    policies::a_foreign_or_dangling_policy_takes_no_part_silently,
    policies::an_attached_policy_is_not_deleted,
    policies::a_membership_needs_both_parties_in_one_tenant,
    policies::a_foreign_policy_and_an_absent_one_are_one_refusal,
);
