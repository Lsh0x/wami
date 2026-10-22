//! Login Profile Store Implementation for InMemoryWamiStore

use crate::credentials::LoginProfile;
use crate::store::memory::InMemoryWamiStore;
use crate::store::traits::LoginProfileStore;
use async_trait::async_trait;
use wami_core::arn::ScopedName;
use wami_core::error::Result;

#[async_trait]
impl LoginProfileStore for InMemoryWamiStore {
    async fn create_login_profile(&mut self, profile: LoginProfile) -> Result<LoginProfile> {
        if self.login_profiles.contains_key(&profile.owner) {
            return Err(wami_core::error::AmiError::ResourceExists {
                resource: format!("login profile of {}", profile.owner),
            });
        }
        self.login_profiles
            .insert(profile.owner.clone(), profile.clone());
        Ok(profile)
    }

    async fn get_login_profile(&self, owner: &ScopedName) -> Result<Option<LoginProfile>> {
        Ok(self.login_profiles.get(owner).cloned())
    }

    async fn update_login_profile(&mut self, profile: LoginProfile) -> Result<LoginProfile> {
        self.login_profiles
            .insert(profile.owner.clone(), profile.clone());
        Ok(profile)
    }

    async fn delete_login_profile(&mut self, owner: &ScopedName) -> Result<()> {
        self.login_profiles.remove(owner);
        Ok(())
    }
}
