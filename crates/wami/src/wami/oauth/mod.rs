//! OAuth 2.0 — machine-to-machine token issuance.
//!
//! wami as the authorization server for the `client_credentials` grant: a
//! service authenticates as itself and receives a signed, short-lived JWT.
//!
//! Tokens are signed by the same [`KeyManager`] that signs STS credentials, so
//! there is one keyset, one rotation policy, and one JWKS to publish. They are
//! verifiable offline; the store exists so they can be revoked before they
//! expire.
//!
//! The flows that involve a human — authorization code, PKCE, consent, ID
//! tokens — are a separate concern and are not here.
//!
//! [`KeyManager`]: crate::wami::sts::jwt::KeyManager

pub mod builder;
pub mod model;

pub use builder::{
    build_claims, build_client, build_response, build_token_record, generate_client_secret,
    DEFAULT_TOKEN_LIFETIME,
};
pub use model::{
    AccessToken, GrantRequest, GrantType, OAuthClaims, OAuthClient, TokenIntrospection,
    TokenResponse,
};
