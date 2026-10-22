//! User Store Implementation for InMemoryWamiStore

use super::{insert_new, move_key, page, replace_by_id};
use crate::store::memory::InMemoryWamiStore;
use crate::store::traits::UserStore;
use crate::wami::identity::User;
use async_trait::async_trait;
use wami_core::arn::{ScopedName, TenantPath};
use wami_core::error::Result;
use wami_core::types::{PaginationParams, Tag};

impl InMemoryWamiStore {
    /// Carry everything hanging off a user from `from` to `to` — what a rename
    /// does. Left behind, the next user created under the old name would
    /// inherit the policies, the memberships and the credentials of this one.
    fn move_user(&mut self, from: &ScopedName, to: &ScopedName) {
        if from == to {
            return;
        }
        move_key(&mut self.user_attached_policies, from, to);
        move_key(&mut self.user_inline_policies, from, to);
        move_key(&mut self.user_groups, from, to);
        if let Some(mut profile) = self.login_profiles.remove(from) {
            profile.owner = to.clone();
            self.login_profiles.insert(to.clone(), profile);
        }
        self.access_keys
            .values_mut()
            .filter(|k| &k.owner == from)
            .for_each(|k| k.owner = to.clone());
        self.mfa_devices
            .values_mut()
            .filter(|d| &d.owner == from)
            .for_each(|d| d.owner = to.clone());
        self.service_specific_credentials
            .values_mut()
            .filter(|c| &c.owner == from)
            .for_each(|c| c.owner = to.clone());
        self.signing_certificates
            .values_mut()
            .filter(|c| &c.owner == from)
            .for_each(|c| c.owner = to.clone());
    }

    /// Remove everything hanging off a deleted user, for the same reason.
    fn forget_user(&mut self, key: &ScopedName) {
        self.user_attached_policies.remove(key);
        self.user_inline_policies.remove(key);
        self.user_groups.remove(key);
        self.login_profiles.remove(key);
        self.access_keys.retain(|_, k| &k.owner != key);
        self.mfa_devices.retain(|_, d| &d.owner != key);
        self.service_specific_credentials
            .retain(|_, c| &c.owner != key);
        self.signing_certificates.retain(|_, c| &c.owner != key);
    }
}

#[async_trait]
impl UserStore for InMemoryWamiStore {
    async fn create_user(&mut self, user: User) -> Result<User> {
        insert_new(&mut self.users, user.key(), user, |u| &u.user_id, "user")
    }

    async fn get_user(&self, key: &ScopedName) -> Result<Option<User>> {
        Ok(self.users.get(key).cloned())
    }

    async fn update_user(&mut self, user: User) -> Result<User> {
        let key = user.key();
        let (old, user) =
            replace_by_id(&mut self.users, key.clone(), user, |u| &u.user_id, "user")?;
        self.move_user(&old, &key);
        Ok(user)
    }

    async fn delete_user(&mut self, key: &ScopedName) -> Result<()> {
        self.users.remove(key);
        self.forget_user(key);
        Ok(())
    }

    async fn list_users(
        &self,
        tenant: &TenantPath,
        path_prefix: Option<&str>,
        pagination: Option<&PaginationParams>,
    ) -> Result<(Vec<User>, bool, Option<String>)> {
        let users: Vec<User> = self
            .users
            .iter()
            .filter(|(key, _)| key.tenant() == tenant)
            .map(|(_, user)| user.clone())
            .collect();
        Ok(page(
            users,
            path_prefix,
            |u| &u.path,
            |u| &u.user_name,
            pagination,
        ))
    }

    async fn tag_user(&mut self, key: &ScopedName, tags: Vec<Tag>) -> Result<()> {
        if let Some(user) = self.users.get_mut(key) {
            user.tags.extend(tags);
        }
        Ok(())
    }

    async fn list_user_tags(&self, key: &ScopedName) -> Result<Vec<Tag>> {
        Ok(self
            .users
            .get(key)
            .map(|u| u.tags.clone())
            .unwrap_or_default())
    }

    async fn untag_user(&mut self, key: &ScopedName, tag_keys: Vec<String>) -> Result<()> {
        if let Some(user) = self.users.get_mut(key) {
            user.tags.retain(|tag| !tag_keys.contains(&tag.key));
        }
        Ok(())
    }

    // Managed policy attachment methods
    async fn attach_user_policy(&mut self, key: &ScopedName, policy_arn: &str) -> Result<()> {
        let policies = self.user_attached_policies.entry(key.clone()).or_default();
        if !policies.iter().any(|p| p == policy_arn) {
            policies.push(policy_arn.to_string());
        }
        Ok(())
    }

    async fn detach_user_policy(&mut self, key: &ScopedName, policy_arn: &str) -> Result<()> {
        if let Some(policies) = self.user_attached_policies.get_mut(key) {
            policies.retain(|p| p != policy_arn);
        }
        Ok(())
    }

    async fn list_attached_user_policies(&self, key: &ScopedName) -> Result<Vec<String>> {
        Ok(self
            .user_attached_policies
            .get(key)
            .cloned()
            .unwrap_or_default())
    }

    // Inline policy methods
    async fn put_user_policy(
        &mut self,
        key: &ScopedName,
        policy_name: &str,
        policy_document: String,
    ) -> Result<()> {
        self.user_inline_policies
            .entry(key.clone())
            .or_default()
            .insert(policy_name.to_string(), policy_document);
        Ok(())
    }

    async fn get_user_policy(&self, key: &ScopedName, policy_name: &str) -> Result<Option<String>> {
        Ok(self
            .user_inline_policies
            .get(key)
            .and_then(|policies| policies.get(policy_name).cloned()))
    }

    async fn delete_user_policy(&mut self, key: &ScopedName, policy_name: &str) -> Result<()> {
        if let Some(policies) = self.user_inline_policies.get_mut(key) {
            policies.remove(policy_name);
        }
        Ok(())
    }

    async fn list_user_policies(&self, key: &ScopedName) -> Result<Vec<String>> {
        Ok(self
            .user_inline_policies
            .get(key)
            .map(|policies| policies.keys().cloned().collect())
            .unwrap_or_default())
    }
}
