//! Trusted Token Issuer Store Trait

use crate::wami::sso_admin::TrustedTokenIssuer;
use async_trait::async_trait;
use wami_core::error::Result;

/// Trait for trusted token issuer storage operations
#[async_trait]
pub trait TrustedTokenIssuerStore: Send + Sync {
    async fn create_trusted_token_issuer(
        &mut self,
        issuer: TrustedTokenIssuer,
    ) -> Result<TrustedTokenIssuer>;

    async fn get_trusted_token_issuer(
        &self,
        issuer_arn: &str,
    ) -> Result<Option<TrustedTokenIssuer>>;

    async fn delete_trusted_token_issuer(&mut self, issuer_arn: &str) -> Result<()>;

    async fn list_trusted_token_issuers(
        &self,
        instance_arn: &str,
    ) -> Result<Vec<TrustedTokenIssuer>>;
}
