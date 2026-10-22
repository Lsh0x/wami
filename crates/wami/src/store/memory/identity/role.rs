//! Role Store Implementation for InMemoryWamiStore

use super::{insert_new, move_key, page, replace_by_id};
use crate::store::memory::InMemoryWamiStore;
use crate::store::traits::RoleStore;
use crate::wami::identity::Role;
use async_trait::async_trait;
use wami_core::arn::{ScopedName, TenantPath};
use wami_core::error::Result;
use wami_core::types::PaginationParams;

#[async_trait]
impl RoleStore for InMemoryWamiStore {
    async fn create_role(&mut self, role: Role) -> Result<Role> {
        insert_new(&mut self.roles, role.key(), role, |r| &r.role_id, "role")
    }

    async fn get_role(&self, key: &ScopedName) -> Result<Option<Role>> {
        Ok(self.roles.get(key).cloned())
    }

    async fn update_role(&mut self, role: Role) -> Result<Role> {
        let key = role.key();
        let (old, role) =
            replace_by_id(&mut self.roles, key.clone(), role, |r| &r.role_id, "role")?;
        // A role's policies are its own: they follow it, or the next role of
        // the old name inherits them.
        move_key(&mut self.role_attached_policies, &old, &key);
        move_key(&mut self.role_inline_policies, &old, &key);
        Ok(role)
    }

    async fn delete_role(&mut self, key: &ScopedName) -> Result<()> {
        self.roles.remove(key);
        self.role_attached_policies.remove(key);
        self.role_inline_policies.remove(key);
        Ok(())
    }

    async fn list_roles(
        &self,
        tenant: &TenantPath,
        path_prefix: Option<&str>,
        pagination: Option<&PaginationParams>,
    ) -> Result<(Vec<Role>, bool, Option<String>)> {
        let roles: Vec<Role> = self
            .roles
            .iter()
            .filter(|(key, _)| key.tenant() == tenant)
            .map(|(_, role)| role.clone())
            .collect();
        Ok(page(
            roles,
            path_prefix,
            |r| &r.path,
            |r| &r.role_name,
            pagination,
        ))
    }

    // Managed policy attachment methods
    async fn attach_role_policy(&mut self, key: &ScopedName, policy_arn: &str) -> Result<()> {
        let policies = self.role_attached_policies.entry(key.clone()).or_default();
        if !policies.iter().any(|p| p == policy_arn) {
            policies.push(policy_arn.to_string());
        }
        Ok(())
    }

    async fn detach_role_policy(&mut self, key: &ScopedName, policy_arn: &str) -> Result<()> {
        if let Some(policies) = self.role_attached_policies.get_mut(key) {
            policies.retain(|p| p != policy_arn);
        }
        Ok(())
    }

    async fn list_attached_role_policies(&self, key: &ScopedName) -> Result<Vec<String>> {
        Ok(self
            .role_attached_policies
            .get(key)
            .cloned()
            .unwrap_or_default())
    }

    // Inline policy methods
    async fn put_role_policy(
        &mut self,
        key: &ScopedName,
        policy_name: &str,
        policy_document: String,
    ) -> Result<()> {
        self.role_inline_policies
            .entry(key.clone())
            .or_default()
            .insert(policy_name.to_string(), policy_document);
        Ok(())
    }

    async fn get_role_policy(&self, key: &ScopedName, policy_name: &str) -> Result<Option<String>> {
        Ok(self
            .role_inline_policies
            .get(key)
            .and_then(|policies| policies.get(policy_name).cloned()))
    }

    async fn delete_role_policy(&mut self, key: &ScopedName, policy_name: &str) -> Result<()> {
        if let Some(policies) = self.role_inline_policies.get_mut(key) {
            policies.remove(policy_name);
        }
        Ok(())
    }

    async fn list_role_policies(&self, key: &ScopedName) -> Result<Vec<String>> {
        Ok(self
            .role_inline_policies
            .get(key)
            .map(|policies| policies.keys().cloned().collect())
            .unwrap_or_default())
    }
}
