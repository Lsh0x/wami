//! The conformance checks a store WITHOUT groups runs (review round 1, Δ9):
//! a store implementing exactly UserStore, RoleStore, PolicyStore and
//! AccessKeyStore — the wami traits anatta-auth's SQLite and Firestore stores
//! implement — compiles and passes the key, freed-name, reserved-name and
//! root checks. A check that needed a trait outside that set would not
//! compile here: the bound is the proof.
#![cfg(feature = "conformance")]

use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;
use wami::store::conformance::{keys, names, root, Shared};
use wami::store::memory::InMemoryWamiStore;
use wami::store::traits::{AccessKeyStore, PolicyStore, RoleStore, UserStore};
use wami::wami::identity::{Role, User};
use wami::{AccessKey, Policy};
use wami_core::arn::{ScopedName, TenantPath};
use wami_core::error::Result;
use wami_core::types::{PaginationParams, Tag};

/// Four traits and no more, each delegated to the memory store.
#[derive(Default)]
struct MinimalStore(InMemoryWamiStore);

fn fresh() -> Shared<MinimalStore> {
    Arc::new(RwLock::new(MinimalStore::default()))
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
    keys::two_tenants_each_hold_a_role_of_one_name,
    keys::a_create_on_a_held_user_key_is_refused,
    keys::a_create_on_a_held_role_key_is_refused,
    keys::a_create_on_a_held_policy_arn_is_refused,
    keys::a_deleted_users_name_hands_nothing_to_its_next_holder,
    keys::a_renamed_user_carries_everything_and_leaves_nothing_behind,
    keys::a_freed_role_name_hands_nothing_to_its_next_holder,
    names::a_reserved_name_is_refused_at_create_in_every_tenant,
    names::a_reserved_name_is_refused_at_rename,
    root::only_the_principal_at_path_zero_authenticates_as_root,
);

#[async_trait]
impl UserStore for MinimalStore {
    async fn create_user(&mut self, user: User) -> Result<User> {
        UserStore::create_user(&mut self.0, user).await
    }
    async fn get_user(&self, key: &ScopedName) -> Result<Option<User>> {
        UserStore::get_user(&self.0, key).await
    }
    async fn update_user(&mut self, user: User) -> Result<User> {
        UserStore::update_user(&mut self.0, user).await
    }
    async fn delete_user(&mut self, key: &ScopedName) -> Result<()> {
        UserStore::delete_user(&mut self.0, key).await
    }
    async fn list_users(
        &self,
        tenant: &TenantPath,
        path_prefix: Option<&str>,
        pagination: Option<&PaginationParams>,
    ) -> Result<(Vec<User>, bool, Option<String>)> {
        UserStore::list_users(&self.0, tenant, path_prefix, pagination).await
    }
    async fn tag_user(&mut self, key: &ScopedName, tags: Vec<Tag>) -> Result<()> {
        UserStore::tag_user(&mut self.0, key, tags).await
    }
    async fn list_user_tags(&self, key: &ScopedName) -> Result<Vec<Tag>> {
        UserStore::list_user_tags(&self.0, key).await
    }
    async fn untag_user(&mut self, key: &ScopedName, tag_keys: Vec<String>) -> Result<()> {
        UserStore::untag_user(&mut self.0, key, tag_keys).await
    }
    async fn attach_user_policy(&mut self, key: &ScopedName, policy_arn: &str) -> Result<()> {
        UserStore::attach_user_policy(&mut self.0, key, policy_arn).await
    }
    async fn detach_user_policy(&mut self, key: &ScopedName, policy_arn: &str) -> Result<()> {
        UserStore::detach_user_policy(&mut self.0, key, policy_arn).await
    }
    async fn list_attached_user_policies(&self, key: &ScopedName) -> Result<Vec<String>> {
        UserStore::list_attached_user_policies(&self.0, key).await
    }
    async fn put_user_policy(
        &mut self,
        key: &ScopedName,
        policy_name: &str,
        policy_document: String,
    ) -> Result<()> {
        UserStore::put_user_policy(&mut self.0, key, policy_name, policy_document).await
    }
    async fn get_user_policy(&self, key: &ScopedName, policy_name: &str) -> Result<Option<String>> {
        UserStore::get_user_policy(&self.0, key, policy_name).await
    }
    async fn delete_user_policy(&mut self, key: &ScopedName, policy_name: &str) -> Result<()> {
        UserStore::delete_user_policy(&mut self.0, key, policy_name).await
    }
    async fn list_user_policies(&self, key: &ScopedName) -> Result<Vec<String>> {
        UserStore::list_user_policies(&self.0, key).await
    }
}

#[async_trait]
impl RoleStore for MinimalStore {
    async fn create_role(&mut self, role: Role) -> Result<Role> {
        RoleStore::create_role(&mut self.0, role).await
    }
    async fn get_role(&self, key: &ScopedName) -> Result<Option<Role>> {
        RoleStore::get_role(&self.0, key).await
    }
    async fn update_role(&mut self, role: Role) -> Result<Role> {
        RoleStore::update_role(&mut self.0, role).await
    }
    async fn delete_role(&mut self, key: &ScopedName) -> Result<()> {
        RoleStore::delete_role(&mut self.0, key).await
    }
    async fn list_roles(
        &self,
        tenant: &TenantPath,
        path_prefix: Option<&str>,
        pagination: Option<&PaginationParams>,
    ) -> Result<(Vec<Role>, bool, Option<String>)> {
        RoleStore::list_roles(&self.0, tenant, path_prefix, pagination).await
    }
    async fn attach_role_policy(&mut self, key: &ScopedName, policy_arn: &str) -> Result<()> {
        RoleStore::attach_role_policy(&mut self.0, key, policy_arn).await
    }
    async fn detach_role_policy(&mut self, key: &ScopedName, policy_arn: &str) -> Result<()> {
        RoleStore::detach_role_policy(&mut self.0, key, policy_arn).await
    }
    async fn list_attached_role_policies(&self, key: &ScopedName) -> Result<Vec<String>> {
        RoleStore::list_attached_role_policies(&self.0, key).await
    }
    async fn put_role_policy(
        &mut self,
        key: &ScopedName,
        policy_name: &str,
        policy_document: String,
    ) -> Result<()> {
        RoleStore::put_role_policy(&mut self.0, key, policy_name, policy_document).await
    }
    async fn get_role_policy(&self, key: &ScopedName, policy_name: &str) -> Result<Option<String>> {
        RoleStore::get_role_policy(&self.0, key, policy_name).await
    }
    async fn delete_role_policy(&mut self, key: &ScopedName, policy_name: &str) -> Result<()> {
        RoleStore::delete_role_policy(&mut self.0, key, policy_name).await
    }
    async fn list_role_policies(&self, key: &ScopedName) -> Result<Vec<String>> {
        RoleStore::list_role_policies(&self.0, key).await
    }
}

#[async_trait]
impl PolicyStore for MinimalStore {
    async fn create_policy(&mut self, policy: Policy) -> Result<Policy> {
        PolicyStore::create_policy(&mut self.0, policy).await
    }
    async fn get_policy(&self, policy_arn: &str) -> Result<Option<Policy>> {
        PolicyStore::get_policy(&self.0, policy_arn).await
    }
    async fn update_policy(&mut self, policy: Policy) -> Result<Policy> {
        PolicyStore::update_policy(&mut self.0, policy).await
    }
    async fn delete_policy(&mut self, policy_arn: &str) -> Result<()> {
        PolicyStore::delete_policy(&mut self.0, policy_arn).await
    }
    async fn list_policies(
        &self,
        tenant: &TenantPath,
        scope: Option<&str>,
        pagination: Option<&PaginationParams>,
    ) -> Result<(Vec<Policy>, bool, Option<String>)> {
        PolicyStore::list_policies(&self.0, tenant, scope, pagination).await
    }
}

#[async_trait]
impl AccessKeyStore for MinimalStore {
    async fn create_access_key(&mut self, access_key: AccessKey) -> Result<AccessKey> {
        AccessKeyStore::create_access_key(&mut self.0, access_key).await
    }
    async fn get_access_key(&self, access_key_id: &str) -> Result<Option<AccessKey>> {
        AccessKeyStore::get_access_key(&self.0, access_key_id).await
    }
    async fn update_access_key(&mut self, access_key: AccessKey) -> Result<AccessKey> {
        AccessKeyStore::update_access_key(&mut self.0, access_key).await
    }
    async fn delete_access_key(&mut self, access_key_id: &str) -> Result<()> {
        AccessKeyStore::delete_access_key(&mut self.0, access_key_id).await
    }
    async fn list_access_keys(
        &self,
        owner: &ScopedName,
        pagination: Option<&PaginationParams>,
    ) -> Result<(Vec<AccessKey>, bool, Option<String>)> {
        AccessKeyStore::list_access_keys(&self.0, owner, pagination).await
    }
}
