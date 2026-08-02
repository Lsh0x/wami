//! In-memory OAuth store.
//!
//! Throwaway, like the rest of `store/memory` — it exists so the service layer
//! and its tests have something to run against, not to be deployed.

use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use wami_core::error::{AmiError, Result};

use crate::store::traits::oauth::{
    OAuthAuthorizationStore, OAuthClientStore, OAuthConsentStore, OAuthRefreshStore,
    OAuthTokenStore,
};
use crate::wami::oauth::{AccessToken, AuthorizationCode, OAuthClient, RefreshToken, UserConsent};

/// Clients and issued tokens, held in maps.
#[derive(Debug, Clone, Default)]
pub struct InMemoryOAuthStore {
    clients: HashMap<String, OAuthClient>,
    tokens: HashMap<String, AccessToken>,
    codes: HashMap<String, AuthorizationCode>,
    refresh: HashMap<String, RefreshToken>,
    /// Keyed by `(client_id, user_name)`.
    consents: HashMap<(String, String), UserConsent>,
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

#[async_trait]
impl OAuthAuthorizationStore for InMemoryOAuthStore {
    async fn store_authorization_code(&mut self, code: AuthorizationCode) -> Result<()> {
        self.codes.insert(code.code.clone(), code);
        Ok(())
    }

    async fn consume_authorization_code(
        &mut self,
        code: &str,
    ) -> Result<Option<AuthorizationCode>> {
        // `remove` returns the value it took out, so this really is one
        // operation — the trait's contract, not merely its spirit. `&mut self`
        // means the caller holds the write lock for its whole duration.
        Ok(self.codes.remove(code))
    }
}

#[async_trait]
impl OAuthRefreshStore for InMemoryOAuthStore {
    async fn store_refresh_token(&mut self, token: RefreshToken) -> Result<()> {
        self.refresh.insert(token.token.clone(), token);
        Ok(())
    }

    async fn get_refresh_token(&self, token: &str) -> Result<Option<RefreshToken>> {
        Ok(self.refresh.get(token).cloned())
    }

    async fn rotate_refresh_token(
        &mut self,
        token: &str,
        replacement: RefreshToken,
    ) -> Result<Option<RefreshToken>> {
        let now = Utc::now();
        let Some(existing) = self.refresh.get_mut(token) else {
            return Ok(None);
        };
        if !existing.is_usable_at(now) {
            // Returning the spent token rather than `None` is what lets the
            // service tell "never existed" from "used twice" — the second is a
            // leak, and it reacts differently.
            return Ok(Some(existing.clone()));
        }
        existing.used_at = Some(now);
        existing.replaced_by = Some(replacement.token.clone());
        let spent = existing.clone();
        self.refresh.insert(replacement.token.clone(), replacement);
        Ok(Some(spent))
    }

    async fn revoke_refresh_chain(&mut self, client_id: &str, user_name: &str) -> Result<u64> {
        let now = Utc::now();
        let mut revoked = 0;
        for token in self.refresh.values_mut() {
            if token.client_id == client_id
                && token.user_name == user_name
                && token.used_at.is_none()
            {
                token.used_at = Some(now);
                revoked += 1;
            }
        }
        Ok(revoked)
    }
}

#[async_trait]
impl OAuthConsentStore for InMemoryOAuthStore {
    async fn record_consent(&mut self, consent: UserConsent) -> Result<UserConsent> {
        let key = (consent.client_id.clone(), consent.user_name.clone());
        self.consents.insert(key, consent.clone());
        Ok(consent)
    }

    async fn get_consent(&self, client_id: &str, user_name: &str) -> Result<Option<UserConsent>> {
        Ok(self
            .consents
            .get(&(client_id.to_string(), user_name.to_string()))
            .cloned())
    }

    async fn revoke_consent(&mut self, client_id: &str, user_name: &str) -> Result<bool> {
        Ok(self
            .consents
            .remove(&(client_id.to_string(), user_name.to_string()))
            .is_some())
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
            vec![],
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

    fn a_code(code: &str) -> AuthorizationCode {
        AuthorizationCode {
            code: code.to_string(),
            client_id: "svc".to_string(),
            user_name: "alice".to_string(),
            scopes: vec!["openid".to_string()],
            redirect_uri: "https://app.test/cb".to_string(),
            challenge: None,
            nonce: None,
            event: None,
            expires_at: Utc::now() + chrono::Duration::seconds(60),
        }
    }

    fn a_refresh(token: &str, user: &str) -> RefreshToken {
        RefreshToken {
            token: token.to_string(),
            client_id: "svc".to_string(),
            user_name: user.to_string(),
            scopes: vec!["openid".to_string()],
            expires_at: Utc::now() + chrono::Duration::days(30),
            used_at: None,
            replaced_by: None,
            event: None,
        }
    }

    #[tokio::test]
    async fn a_code_can_only_be_consumed_once() {
        let mut store = InMemoryOAuthStore::new();
        store.store_authorization_code(a_code("abc")).await.unwrap();

        let first = store.consume_authorization_code("abc").await.unwrap();
        assert_eq!(first.unwrap().user_name, "alice");

        let second = store.consume_authorization_code("abc").await.unwrap();
        assert!(second.is_none(), "a replayed code must find nothing");
    }

    #[tokio::test]
    async fn rotating_marks_the_old_token_spent_and_points_at_its_replacement() {
        let mut store = InMemoryOAuthStore::new();
        store
            .store_refresh_token(a_refresh("r1", "alice"))
            .await
            .unwrap();

        let spent = store
            .rotate_refresh_token("r1", a_refresh("r2", "alice"))
            .await
            .unwrap()
            .unwrap();
        assert!(spent.used_at.is_some());
        assert_eq!(spent.replaced_by.as_deref(), Some("r2"));

        // The replacement is usable; the original is not.
        assert!(store
            .get_refresh_token("r2")
            .await
            .unwrap()
            .unwrap()
            .is_usable_at(Utc::now()));
        assert!(!store
            .get_refresh_token("r1")
            .await
            .unwrap()
            .unwrap()
            .is_usable_at(Utc::now()));
    }

    #[tokio::test]
    async fn a_second_rotation_returns_the_spent_token_not_none() {
        // The distinction matters: `None` is an unknown token, a spent one is a
        // leak, and the service revokes the chain only for the second.
        let mut store = InMemoryOAuthStore::new();
        store
            .store_refresh_token(a_refresh("r1", "alice"))
            .await
            .unwrap();
        store
            .rotate_refresh_token("r1", a_refresh("r2", "alice"))
            .await
            .unwrap();

        let replayed = store
            .rotate_refresh_token("r1", a_refresh("r3", "alice"))
            .await
            .unwrap();
        assert!(replayed.is_some_and(|t| t.used_at.is_some()));
        assert!(
            store.get_refresh_token("r3").await.unwrap().is_none(),
            "a refused rotation must not have minted anything"
        );

        assert!(store
            .rotate_refresh_token("never-existed", a_refresh("r4", "alice"))
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn revoking_a_chain_spares_other_users_and_other_clients() {
        let mut store = InMemoryOAuthStore::new();
        store
            .store_refresh_token(a_refresh("r1", "alice"))
            .await
            .unwrap();
        store
            .store_refresh_token(a_refresh("r2", "alice"))
            .await
            .unwrap();
        store
            .store_refresh_token(a_refresh("r3", "bob"))
            .await
            .unwrap();
        let mut other = a_refresh("r4", "alice");
        other.client_id = "other".to_string();
        store.store_refresh_token(other).await.unwrap();

        assert_eq!(store.revoke_refresh_chain("svc", "alice").await.unwrap(), 2);
        assert_eq!(
            store.revoke_refresh_chain("svc", "alice").await.unwrap(),
            0,
            "already-revoked tokens are not counted again"
        );

        for spared in ["r3", "r4"] {
            assert!(store
                .get_refresh_token(spared)
                .await
                .unwrap()
                .unwrap()
                .is_usable_at(Utc::now()));
        }
    }

    #[tokio::test]
    async fn consent_is_per_client_and_per_user() {
        let mut store = InMemoryOAuthStore::new();
        let consent = UserConsent {
            user_name: "alice".to_string(),
            client_id: "svc".to_string(),
            scopes: vec!["openid".to_string()],
            granted_at: Utc::now(),
        };
        store.record_consent(consent).await.unwrap();

        assert!(store.get_consent("svc", "alice").await.unwrap().is_some());
        assert!(store.get_consent("svc", "bob").await.unwrap().is_none());
        assert!(store.get_consent("other", "alice").await.unwrap().is_none());

        assert!(store.revoke_consent("svc", "alice").await.unwrap());
        assert!(!store.revoke_consent("svc", "alice").await.unwrap());
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
