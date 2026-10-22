//! Group Store Implementation for InMemoryWamiStore

use super::{insert_new, move_key, page, replace_by_id};
use crate::store::memory::InMemoryWamiStore;
use crate::store::traits::GroupStore;
use crate::wami::identity::Group;
use async_trait::async_trait;
use wami_core::arn::{ScopedName, TenantPath};
use wami_core::error::Result;
use wami_core::types::PaginationParams;

#[async_trait]
impl GroupStore for InMemoryWamiStore {
    async fn create_group(&mut self, group: Group) -> Result<Group> {
        insert_new(
            &mut self.groups,
            group.key(),
            group,
            |g| &g.group_id,
            "group",
        )
    }

    async fn get_group(&self, key: &ScopedName) -> Result<Option<Group>> {
        Ok(self.groups.get(key).cloned())
    }

    async fn update_group(&mut self, group: Group) -> Result<Group> {
        let key = group.key();
        let (old, group) = replace_by_id(
            &mut self.groups,
            key.clone(),
            group,
            |g| &g.group_id,
            "group",
        )?;
        if old != key {
            // Its policies and its members follow it; left on the old key, the
            // next group of that name would inherit both.
            move_key(&mut self.group_attached_policies, &old, &key);
            move_key(&mut self.group_inline_policies, &old, &key);
            for groups in self.user_groups.values_mut() {
                for g in groups.iter_mut().filter(|g| **g == old) {
                    *g = key.clone();
                }
            }
        }
        Ok(group)
    }

    async fn delete_group(&mut self, key: &ScopedName) -> Result<()> {
        self.groups.remove(key);
        self.group_attached_policies.remove(key);
        self.group_inline_policies.remove(key);
        for groups in self.user_groups.values_mut() {
            groups.retain(|g| g != key);
        }
        Ok(())
    }

    async fn list_groups(
        &self,
        tenant: &TenantPath,
        path_prefix: Option<&str>,
        pagination: Option<&PaginationParams>,
    ) -> Result<(Vec<Group>, bool, Option<String>)> {
        let groups: Vec<Group> = self
            .groups
            .iter()
            .filter(|(key, _)| key.tenant() == tenant)
            .map(|(_, group)| group.clone())
            .collect();
        Ok(page(
            groups,
            path_prefix,
            |g| &g.path,
            |g| &g.group_name,
            pagination,
        ))
    }

    async fn list_groups_for_user(&self, user: &ScopedName) -> Result<Vec<Group>> {
        Ok(self
            .user_groups
            .get(user)
            .map(|keys| {
                keys.iter()
                    .filter_map(|key| self.groups.get(key).cloned())
                    .collect()
            })
            .unwrap_or_default())
    }

    async fn add_user_to_group(&mut self, group: &ScopedName, user: &ScopedName) -> Result<()> {
        let groups = self.user_groups.entry(user.clone()).or_default();
        if !groups.contains(group) {
            groups.push(group.clone());
        }
        Ok(())
    }

    async fn remove_user_from_group(
        &mut self,
        group: &ScopedName,
        user: &ScopedName,
    ) -> Result<()> {
        if let Some(groups) = self.user_groups.get_mut(user) {
            groups.retain(|g| g != group);
        }
        Ok(())
    }

    // Managed policy attachment methods
    async fn attach_group_policy(&mut self, key: &ScopedName, policy_arn: &str) -> Result<()> {
        let policies = self.group_attached_policies.entry(key.clone()).or_default();
        if !policies.iter().any(|p| p == policy_arn) {
            policies.push(policy_arn.to_string());
        }
        Ok(())
    }

    async fn detach_group_policy(&mut self, key: &ScopedName, policy_arn: &str) -> Result<()> {
        if let Some(policies) = self.group_attached_policies.get_mut(key) {
            policies.retain(|p| p != policy_arn);
        }
        Ok(())
    }

    async fn list_attached_group_policies(&self, key: &ScopedName) -> Result<Vec<String>> {
        Ok(self
            .group_attached_policies
            .get(key)
            .cloned()
            .unwrap_or_default())
    }

    // Inline policy methods
    async fn put_group_policy(
        &mut self,
        key: &ScopedName,
        policy_name: &str,
        policy_document: String,
    ) -> Result<()> {
        self.group_inline_policies
            .entry(key.clone())
            .or_default()
            .insert(policy_name.to_string(), policy_document);
        Ok(())
    }

    async fn get_group_policy(
        &self,
        key: &ScopedName,
        policy_name: &str,
    ) -> Result<Option<String>> {
        Ok(self
            .group_inline_policies
            .get(key)
            .and_then(|policies| policies.get(policy_name).cloned()))
    }

    async fn delete_group_policy(&mut self, key: &ScopedName, policy_name: &str) -> Result<()> {
        if let Some(policies) = self.group_inline_policies.get_mut(key) {
            policies.remove(policy_name);
        }
        Ok(())
    }

    async fn list_group_policies(&self, key: &ScopedName) -> Result<Vec<String>> {
        Ok(self
            .group_inline_policies
            .get(key)
            .map(|policies| policies.keys().cloned().collect())
            .unwrap_or_default())
    }
}
