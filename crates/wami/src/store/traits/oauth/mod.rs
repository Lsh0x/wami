//! OAuth store traits.
//!
//! Both names carry the `OAuth` prefix on purpose. `ConsentStore` is already
//! taken by GDPR and `SessionStore` by STS, and the user-facing OAuth flows
//! will want both names for entirely different concepts. Prefixing now costs
//! nothing and avoids a rename later, when consumers have already implemented
//! against them.

use async_trait::async_trait;
use wami_core::error::Result;

use crate::wami::oauth::{AccessToken, OAuthClient};

/// Storage for registered OAuth clients.
#[async_trait]
pub trait OAuthClientStore: Send + Sync {
    /// Register a client. Fails if `client_id` is taken.
    async fn create_oauth_client(&mut self, client: OAuthClient) -> Result<OAuthClient>;

    /// Look a client up by its public identifier.
    async fn get_oauth_client(&self, client_id: &str) -> Result<Option<OAuthClient>>;

    /// Replace a client's record — used to disable it, or rotate its secret.
    async fn update_oauth_client(&mut self, client: OAuthClient) -> Result<OAuthClient>;

    /// Remove a client. Tokens it already holds stay valid until they expire
    /// unless they are revoked too; deleting the client is not a revocation.
    async fn delete_oauth_client(&mut self, client_id: &str) -> Result<()>;

    /// Every registered client.
    async fn list_oauth_clients(&self) -> Result<Vec<OAuthClient>>;
}

/// Storage for issued tokens, so they can be revoked before they expire.
///
/// A signed JWT is valid until its `exp` no matter what the issuer thinks.
/// Revocation is the one operation that cannot be done offline, and this trait
/// is what makes it possible: everything else about a token can be checked from
/// its signature alone.
#[async_trait]
pub trait OAuthTokenStore: Send + Sync {
    /// Record a token at issuance.
    async fn record_oauth_token(&mut self, token: AccessToken) -> Result<AccessToken>;

    /// Look a token up by its `jti`.
    async fn get_oauth_token(&self, jti: &str) -> Result<Option<AccessToken>>;

    /// Mark a token revoked. Returns whether it existed and was not already
    /// revoked, so a caller can distinguish "done" from "nothing to do" —
    /// though RFC 7009 requires both to look the same on the wire.
    async fn revoke_oauth_token(&mut self, jti: &str) -> Result<bool>;

    /// Revoke every token a client holds, returning how many were affected.
    ///
    /// The operation an operator reaches for when a client is compromised:
    /// disabling the client stops new tokens, this stops the ones already out.
    async fn revoke_oauth_tokens_for_client(&mut self, client_id: &str) -> Result<u64>;

    /// Tokens issued to a client, revoked ones included.
    async fn list_oauth_tokens_for_client(&self, client_id: &str) -> Result<Vec<AccessToken>>;
}
