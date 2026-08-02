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
//! The flows that involve a human — authorization code with PKCE, consent, ID
//! tokens, refresh rotation — live in [`oidc`]. What separates them is not the
//! cryptography but the browser: a value travels through a user agent nobody
//! controls, and everything there exists to survive that trip.
//!
//! [`KeyManager`]: crate::wami::sts::jwt::KeyManager

pub mod builder;
pub mod model;
pub mod oidc;

pub use builder::{
    build_claims, build_client, build_response, build_token_record, build_user_claims,
    generate_client_secret, DEFAULT_TOKEN_LIFETIME,
};
pub use model::{
    AccessToken, GrantRequest, GrantType, OAuthClaims, OAuthClient, TokenIntrospection,
    TokenResponse,
};
pub use oidc::{
    build_discovery_document, build_id_token_claims, build_user_info, derive_s256_challenge,
    generate_opaque_value, validate_redirect_uri, AuthorizationCode, CodeChallenge,
    CodeChallengeMethod, DiscoveryDocument, IdTokenClaims, IdTokenRequest, RefreshToken,
    UserConsent, UserInfo, UserProfile, AUTHORIZATION_CODE_LIFETIME, REFRESH_TOKEN_LIFETIME,
};
