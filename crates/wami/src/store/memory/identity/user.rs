//! User Store Implementation for InMemoryWamiStore

use crate::store::memory::InMemoryWamiStore;
use crate::store::traits::UserStore;
use crate::wami::identity::User;
use async_trait::async_trait;
use wami_core::error::Result;
use wami_core::types::{PaginationParams, Tag};

#[async_trait]
impl UserStore for InMemoryWamiStore {
    async fn create_user(&mut self, user: User) -> Result<User> {
        self.users.insert(user.user_name.clone(), user.clone());
        Ok(user)
    }

    async fn get_user(&self, user_name: &str) -> Result<Option<User>> {
        Ok(self.users.get(user_name).cloned())
    }

    async fn update_user(&mut self, user: User) -> Result<User> {
        self.users.insert(user.user_name.clone(), user.clone());
        Ok(user)
    }

    async fn delete_user(&mut self, user_name: &str) -> Result<()> {
        self.users.remove(user_name);
        // Also remove associated access keys
        self.access_keys.retain(|_, key| key.user_name != user_name);
        // Remove from user-groups mapping
        self.user_groups.remove(user_name);
        Ok(())
    }

    async fn list_users(
        &self,
        path_prefix: Option<&str>,
        pagination: Option<&PaginationParams>,
    ) -> Result<(Vec<User>, bool, Option<String>)> {
        let mut users: Vec<User> = self.users.values().cloned().collect();

        // Apply path prefix filter
        if let Some(prefix) = path_prefix {
            // Empty string prefix should only match empty paths, not all paths
            if prefix.is_empty() {
                users.retain(|user| user.path.is_empty());
            } else {
                users.retain(|user| user.path.starts_with(prefix));
            }
        }

        // Sort by user name
        users.sort_by(|a, b| a.user_name.cmp(&b.user_name));

        // Apply pagination
        let mut is_truncated = false;
        let mut marker = None;

        if let Some(pagination) = pagination {
            if let Some(max_items) = pagination.max_items {
                if max_items > 0 && users.len() > max_items as usize {
                    users.truncate(max_items as usize);
                    is_truncated = true;
                    if let Some(last_user) = users.last() {
                        marker = Some(last_user.user_name.clone());
                    }
                } else if max_items == 0 {
                    // max_items = 0 means return empty list but indicate truncation if there are items
                    is_truncated = !users.is_empty();
                    users.clear();
                }
            }
        }

        Ok((users, is_truncated, marker))
    }

    async fn tag_user(&mut self, user_name: &str, tags: Vec<Tag>) -> Result<()> {
        if let Some(user) = self.users.get_mut(user_name) {
            user.tags.extend(tags);
        }
        Ok(())
    }

    async fn list_user_tags(&self, user_name: &str) -> Result<Vec<Tag>> {
        Ok(self
            .users
            .get(user_name)
            .map(|u| u.tags.clone())
            .unwrap_or_default())
    }

    async fn untag_user(&mut self, user_name: &str, tag_keys: Vec<String>) -> Result<()> {
        if let Some(user) = self.users.get_mut(user_name) {
            user.tags.retain(|tag| !tag_keys.contains(&tag.key));
        }
        Ok(())
    }

    // Managed policy attachment methods
    async fn attach_user_policy(&mut self, user_name: &str, policy_arn: &str) -> Result<()> {
        let policies = self
            .user_attached_policies
            .entry(user_name.to_string())
            .or_default();

        if !policies.contains(&policy_arn.to_string()) {
            policies.push(policy_arn.to_string());
        }
        Ok(())
    }

    async fn detach_user_policy(&mut self, user_name: &str, policy_arn: &str) -> Result<()> {
        if let Some(policies) = self.user_attached_policies.get_mut(user_name) {
            policies.retain(|p| p != policy_arn);
        }
        Ok(())
    }

    async fn list_attached_user_policies(&self, user_name: &str) -> Result<Vec<String>> {
        Ok(self
            .user_attached_policies
            .get(user_name)
            .cloned()
            .unwrap_or_default())
    }

    // Inline policy methods
    async fn put_user_policy(
        &mut self,
        user_name: &str,
        policy_name: &str,
        policy_document: String,
    ) -> Result<()> {
        let policies = self
            .user_inline_policies
            .entry(user_name.to_string())
            .or_default();

        policies.insert(policy_name.to_string(), policy_document);
        Ok(())
    }

    async fn get_user_policy(&self, user_name: &str, policy_name: &str) -> Result<Option<String>> {
        Ok(self
            .user_inline_policies
            .get(user_name)
            .and_then(|policies| policies.get(policy_name).cloned()))
    }

    async fn delete_user_policy(&mut self, user_name: &str, policy_name: &str) -> Result<()> {
        if let Some(policies) = self.user_inline_policies.get_mut(user_name) {
            policies.remove(policy_name);
        }
        Ok(())
    }

    async fn list_user_policies(&self, user_name: &str) -> Result<Vec<String>> {
        Ok(self
            .user_inline_policies
            .get(user_name)
            .map(|policies| policies.keys().cloned().collect())
            .unwrap_or_default())
    }
}
