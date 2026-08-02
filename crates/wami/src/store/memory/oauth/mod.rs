//! In-memory OAuth store.
//!
//! Throwaway, like the rest of `store/memory` — it exists so the service layer
//! and its tests have something to run against, not to be deployed.

use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use wami_core::error::{AmiError, Result};

use crate::store::traits::oauth::{OAuthClientStore, OAuthTokenStore};
use crate::wami::oauth::{AccessToken, OAuthClient};

/// Clients and issued tokens, held in maps.
#[derive(Debug, Clone, Default)]
pub struct InMemoryOAuthStore {
    clients: HashMap<String, OAuthClient>,
    tokens: HashMap<String, AccessToken>,
}

impl InMemoryOAuthStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl OAuthClientStore for InMemoryOAuthStore {
    async fn create_oauth_client(&mut self, client: OAuthClient) -> Result<OAuthClient> {
        if self.clients.contains_key(&client.client_id) {
            return Err(AmiError::ResourceExists {
                resource: format!("OAuth client {}", client.client_id),
            });
        }
        self.clients
            .insert(client.client_id.clone(), client.clone());
        Ok(client)
    }

    async fn get_oauth_client(&self, client_id: &str) -> Result<Option<OAuthClient>> {
        Ok(self.clients.get(client_id).cloned())
    }

    async fn update_oauth_client(&mut self, client: OAuthClient) -> Result<OAuthClient> {
        if !self.clients.contains_key(&client.client_id) {
            return Err(AmiError::ResourceNotFound {
                resource: format!("OAuth client {}", client.client_id),
            });
        }
        self.clients
            .insert(client.client_id.clone(), client.clone());
        Ok(client)
    }

    async fn delete_oauth_client(&mut self, client_id: &str) -> Result<()> {
        self.clients.remove(client_id);
        Ok(())
    }

    async fn list_oauth_clients(&self) -> Result<Vec<OAuthClient>> {
        let mut clients: Vec<_> = self.clients.values().cloned().collect();
        // Sorted so a listing does not depend on hash order — the same reason
        // authorization sorts its sources.
        clients.sort_by(|a, b| a.client_id.cmp(&b.client_id));
        Ok(clients)
    }
}

#[async_trait]
impl OAuthTokenStore for InMemoryOAuthStore {
    async fn record_oauth_token(&mut self, token: AccessToken) -> Result<AccessToken> {
        self.tokens.insert(token.jti.clone(), token.clone());
        Ok(token)
    }

    async fn get_oauth_token(&self, jti: &str) -> Result<Option<AccessToken>> {
        Ok(self.tokens.get(jti).cloned())
    }

    async fn revoke_oauth_token(&mut self, jti: &str) -> Result<bool> {
        match self.tokens.get_mut(jti) {
            Some(token) if token.revoked_at.is_none() => {
                token.revoked_at = Some(Utc::now());
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn revoke_oauth_tokens_for_client(&mut self, client_id: &str) -> Result<u64> {
        let now = Utc::now();
        let mut revoked = 0;
        for token in self.tokens.values_mut() {
            if token.client_id == client_id && token.revoked_at.is_none() {
                token.revoked_at = Some(now);
                revoked += 1;
            }
        }
        Ok(revoked)
    }

    async fn list_oauth_tokens_for_client(&self, client_id: &str) -> Result<Vec<AccessToken>> {
        let mut tokens: Vec<_> = self
            .tokens
            .values()
            .filter(|t| t.client_id == client_id)
            .cloned()
            .collect();
        tokens.sort_by_key(|t| t.issued_at);
        Ok(tokens)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wami::oauth::{build_client, GrantType};

    fn a_client(id: &str) -> OAuthClient {
        build_client(
            id.to_string(),
            "secret",
            "Test".to_string(),
            vec![GrantType::ClientCredentials],
            vec!["read".to_string()],
            "wami".to_string(),
        )
        .unwrap()
    }

    fn a_token(jti: &str, client_id: &str) -> AccessToken {
        AccessToken {
            jti: jti.to_string(),
            client_id: client_id.to_string(),
            scopes: vec!["read".to_string()],
            issued_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::minutes(15),
            revoked_at: None,
        }
    }

    #[tokio::test]
    async fn a_client_id_cannot_be_registered_twice() {
        let mut store = InMemoryOAuthStore::new();
        store.create_oauth_client(a_client("svc")).await.unwrap();

        let err = store
            .create_oauth_client(a_client("svc"))
            .await
            .unwrap_err();
        assert!(matches!(err, AmiError::ResourceExists { .. }));
    }

    #[tokio::test]
    async fn updating_an_unknown_client_is_an_error_not_an_insert() {
        let mut store = InMemoryOAuthStore::new();
        let err = store
            .update_oauth_client(a_client("ghost"))
            .await
            .unwrap_err();
        assert!(matches!(err, AmiError::ResourceNotFound { .. }));
        assert!(store.get_oauth_client("ghost").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn revoking_twice_reports_only_the_first_as_a_change() {
        let mut store = InMemoryOAuthStore::new();
        store
            .record_oauth_token(a_token("j1", "svc"))
            .await
            .unwrap();

        assert!(store.revoke_oauth_token("j1").await.unwrap());
        assert!(!store.revoke_oauth_token("j1").await.unwrap());
        assert!(!store.revoke_oauth_token("never-existed").await.unwrap());
    }

    #[tokio::test]
    async fn revoking_a_client_stops_every_token_it_holds_and_no_others() {
        let mut store = InMemoryOAuthStore::new();
        store
            .record_oauth_token(a_token("j1", "svc"))
            .await
            .unwrap();
        store
            .record_oauth_token(a_token("j2", "svc"))
            .await
            .unwrap();
        store
            .record_oauth_token(a_token("j3", "other"))
            .await
            .unwrap();

        assert_eq!(
            store.revoke_oauth_tokens_for_client("svc").await.unwrap(),
            2
        );
        // Already-revoked tokens are not counted a second time.
        assert_eq!(
            store.revoke_oauth_tokens_for_client("svc").await.unwrap(),
            0
        );

        let untouched = store.get_oauth_token("j3").await.unwrap().unwrap();
        assert!(untouched.revoked_at.is_none());
    }

    #[tokio::test]
    async fn listings_do_not_depend_on_hash_order() {
        let mut store = InMemoryOAuthStore::new();
        for id in ["c", "a", "b"] {
            store.create_oauth_client(a_client(id)).await.unwrap();
        }
        let ids: Vec<_> = store
            .list_oauth_clients()
            .await
            .unwrap()
            .into_iter()
            .map(|c| c.client_id)
            .collect();
        assert_eq!(ids, vec!["a", "b", "c"]);
    }
}
