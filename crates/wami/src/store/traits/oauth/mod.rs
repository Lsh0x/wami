//! OAuth store traits.
//!
//! Both names carry the `OAuth` prefix on purpose. `ConsentStore` is already
//! taken by GDPR and `SessionStore` by STS, and the user-facing OAuth flows
//! will want both names for entirely different concepts. Prefixing now costs
//! nothing and avoids a rename later, when consumers have already implemented
//! against them.

use async_trait::async_trait;
use wami_core::error::Result;

use crate::wami::oauth::{AccessToken, AuthorizationCode, OAuthClient, RefreshToken, UserConsent};

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

/// Storage for authorization codes.
#[async_trait]
pub trait OAuthAuthorizationStore: Send + Sync {
    /// Store a freshly issued code.
    async fn store_authorization_code(&mut self, code: AuthorizationCode) -> Result<()>;

    /// Take a code, atomically.
    ///
    /// **The contract is that this is one operation.** An implementation that
    /// reads the code and then deletes it leaves a window in which two
    /// exchanges can both succeed — which is precisely the replay an
    /// authorization code is meant to be immune to. If your backend cannot do
    /// it in one statement, use a conditional delete that returns the row
    /// (`DELETE ... RETURNING`) or a transaction; do not emulate it with a get
    /// followed by a delete.
    ///
    /// Returns `None` if the code does not exist, which includes the case where
    /// somebody else consumed it a moment ago.
    async fn consume_authorization_code(&mut self, code: &str)
        -> Result<Option<AuthorizationCode>>;
}

/// Storage for refresh tokens.
#[async_trait]
pub trait OAuthRefreshStore: Send + Sync {
    /// Store a refresh token.
    async fn store_refresh_token(&mut self, token: RefreshToken) -> Result<()>;

    /// Read a refresh token without consuming it.
    async fn get_refresh_token(&self, token: &str) -> Result<Option<RefreshToken>>;

    /// Mark a refresh token used and record what replaced it.
    ///
    /// Same atomicity requirement as consuming a code, and for the same reason:
    /// rotation only detects a leak if exactly one of two concurrent uses can
    /// win.
    ///
    /// # Contract
    ///
    /// - Return `None` when `token` is unknown.
    /// - On success, stamp `used_at`, set `replaced_by` to the replacement's
    ///   token, persist the replacement, and return the token as it now stands.
    /// - When the rotation cannot be granted — already used, or expired —
    ///   return the existing record **unchanged** and persist nothing. The
    ///   caller distinguishes "unknown", "expired" and "reused" from what comes
    ///   back, and mints nothing of its own if the replacement is not named.
    ///
    /// **`used_at` must only ever be stamped by a rotation that won, or by
    /// [`revoke_refresh_chain`].** A store that stamps it on a *failed*
    /// presentation — say, to record an attempt — turns every expired token
    /// into a reported leak, and every idle user into a forced sign-out across
    /// the client. The field means "this token was spent", not "this token was
    /// shown to us".
    ///
    /// [`revoke_refresh_chain`]: Self::revoke_refresh_chain
    async fn rotate_refresh_token(
        &mut self,
        token: &str,
        replacement: RefreshToken,
    ) -> Result<Option<RefreshToken>>;

    /// Invalidate every refresh token in a user's chain with a client.
    ///
    /// What to do when a used token is presented again: the legitimate client
    /// has already rotated, so a second use means the token leaked, and the
    /// whole chain is suspect.
    async fn revoke_refresh_chain(&mut self, client_id: &str, user_name: &str) -> Result<u64>;
}

/// Storage for standing user consent.
///
/// Named `OAuthConsentStore`, not `ConsentStore` — that name belongs to GDPR
/// consent, which is an unrelated concept.
#[async_trait]
pub trait OAuthConsentStore: Send + Sync {
    /// Record or widen a user's approval of a client.
    async fn record_consent(&mut self, consent: UserConsent) -> Result<UserConsent>;

    /// What a user has already approved for a client.
    async fn get_consent(&self, client_id: &str, user_name: &str) -> Result<Option<UserConsent>>;

    /// Withdraw approval.
    async fn revoke_consent(&mut self, client_id: &str, user_name: &str) -> Result<bool>;
}
