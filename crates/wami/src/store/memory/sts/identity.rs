//! Identity Store Implementation for InMemoryStsStore and InMemoryWamiStore

use crate::store::memory::sts::InMemoryStsStore;
use crate::store::memory::InMemoryWamiStore;
use crate::store::traits::IdentityStore;
use crate::wami::sts::CallerIdentity;
use async_trait::async_trait;
use std::collections::HashMap;
use wami_core::arn::{ScopedName, TenantPath};
use wami_core::error::Result;

#[async_trait]
impl IdentityStore for InMemoryStsStore {
    async fn create_identity(
        &mut self,
        key: &ScopedName,
        identity: CallerIdentity,
    ) -> Result<CallerIdentity> {
        self.identities.insert(key.clone(), identity.clone());
        Ok(identity)
    }

    async fn get_identity(&self, key: &ScopedName) -> Result<Option<CallerIdentity>> {
        Ok(self.identities.get(key).cloned())
    }

    async fn list_identities(&self, tenant: &TenantPath) -> Result<Vec<CallerIdentity>> {
        Ok(of_tenant(&self.identities, tenant))
    }
}

#[async_trait]
impl IdentityStore for InMemoryWamiStore {
    async fn create_identity(
        &mut self,
        key: &ScopedName,
        identity: CallerIdentity,
    ) -> Result<CallerIdentity> {
        self.identities.insert(key.clone(), identity.clone());
        Ok(identity)
    }

    async fn get_identity(&self, key: &ScopedName) -> Result<Option<CallerIdentity>> {
        Ok(self.identities.get(key).cloned())
    }

    async fn list_identities(&self, tenant: &TenantPath) -> Result<Vec<CallerIdentity>> {
        Ok(of_tenant(&self.identities, tenant))
    }
}

/// The identities keyed in `tenant`, in no particular order.
fn of_tenant(
    identities: &HashMap<ScopedName, CallerIdentity>,
    tenant: &TenantPath,
) -> Vec<CallerIdentity> {
    identities
        .iter()
        .filter(|(key, _)| key.tenant() == tenant)
        .map(|(_, identity)| identity.clone())
        .collect()
}
