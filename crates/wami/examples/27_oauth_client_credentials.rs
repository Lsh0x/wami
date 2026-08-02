//! Example 27: OAuth 2.0 client credentials
//!
//! wami as an authorization server for machine-to-machine traffic: a service
//! authenticates as itself and gets a short-lived signed token.
//!
//! What this shows, in order:
//!
//! 1. Registering a client — the secret is shown once and stored hashed
//! 2. Issuing a token, and verifying it offline against the JWKS
//! 3. Scope narrowing, and refusal of a scope the client does not hold
//! 4. Introspection (RFC 7662) and revocation (RFC 7009)
//! 5. Containing a compromised client in two moves
//!
//! Tokens are signed by the same `KeyManager` that signs STS credentials, so
//! there is one keyset and one JWKS to publish for both.

use std::sync::Arc;
use tokio::sync::RwLock;
use wami::service::oauth::OAuthService;
use wami::store::memory::InMemoryOAuthStore;
use wami::wami::oauth::{
    build_client, generate_client_secret, GrantRequest, GrantType, OAuthClaims,
};
use wami::wami::sts::jwt::KeyManager;

const AUDIENCE: &str = "reporting-api";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔑 OAuth 2.0 — client credentials\n");
    println!("{}", "=".repeat(60));

    // ── 1. Register a client ─────────────────────────────────────
    println!("\n📝 Step 1: Register a client");

    let store = Arc::new(RwLock::new(InMemoryOAuthStore::new()));
    let keys = Arc::new(KeyManager::generate());
    let service = OAuthService::new(store, keys.clone(), "wami-oauth".to_string());

    let secret = generate_client_secret();
    let client = build_client(
        "nightly-reports".to_string(),
        &secret,
        "Nightly reporting job".to_string(),
        vec![GrantType::ClientCredentials],
        vec!["reports:read".to_string(), "reports:write".to_string()],
        AUDIENCE.to_string(),
        vec![],
    )?;
    let registered = service.register_client(client).await?;

    println!("✅ client_id: {}", registered.client_id);
    println!(
        "   secret:    {}… (shown once, stored hashed)",
        &secret[..16]
    );
    println!("   scopes:    {}", registered.scopes.join(", "));

    // ── 2. Issue a token ─────────────────────────────────────────
    println!("\n🎟️  Step 2: Issue a token");

    let token = service
        .issue_token(GrantRequest::ClientCredentials {
            client_id: "nightly-reports".to_string(),
            client_secret: secret.clone(),
            scope: vec!["reports:read".to_string()],
        })
        .await?;

    println!(
        "✅ {} token, expires in {}s",
        token.token_type, token.expires_in
    );
    println!("   granted scope: {}", token.scope);

    // Any holder of the public key can check it without asking wami.
    let claims: OAuthClaims = keys.verify_claims(&token.access_token, AUDIENCE)?;
    println!("\n🔍 Verified offline against the JWKS:");
    println!(
        "   sub={} iss={} jti={}",
        claims.sub,
        claims.iss,
        &claims.jti[..8]
    );
    println!(
        "   the JWKS has {} key(s) to publish",
        service.jwks().keys.len()
    );

    // ── 3. Scopes are a ceiling, not a suggestion ────────────────
    println!("\n🚧 Step 3: Scope enforcement");

    let refused = service
        .issue_token(GrantRequest::ClientCredentials {
            client_id: "nightly-reports".to_string(),
            client_secret: secret.clone(),
            scope: vec!["billing:write".to_string()],
        })
        .await;
    match refused {
        Err(e) => println!("✅ refused a scope it does not hold: {e}"),
        Ok(_) => println!("❌ a scope outside the client's set was granted!"),
    }

    // ── 4. Introspection and revocation ──────────────────────────
    println!("\n🔎 Step 4: Introspection, then revocation");

    let info = service
        .introspect_token(&token.access_token, AUDIENCE)
        .await?;
    println!("✅ active={} client_id={:?}", info.active, info.client_id);

    service.revoke_token(&token.access_token, AUDIENCE).await?;
    let after = service
        .introspect_token(&token.access_token, AUDIENCE)
        .await?;
    println!("✅ after revocation: active={}", after.active);
    println!("   (nothing else is disclosed — RFC 7662 forbids it)");

    // ── 5. Containing a compromise ───────────────────────────────
    println!("\n🚨 Step 5: The client's secret leaked");

    for _ in 0..3 {
        service
            .issue_token(GrantRequest::ClientCredentials {
                client_id: "nightly-reports".to_string(),
                client_secret: secret.clone(),
                scope: vec!["reports:read".to_string()],
            })
            .await?;
    }

    service.disable_client("nightly-reports").await?;
    println!("✅ client disabled — no new tokens");

    let revoked = service.revoke_all_for_client("nightly-reports").await?;
    println!("✅ revoked {revoked} token(s) already in the wild");

    println!("\n{}", "=".repeat(60));
    println!("⚠️  The limit worth knowing");
    println!("{}", "=".repeat(60));
    println!("Revocation binds on whoever introspects. A verifier checking the");
    println!("signature offline keeps accepting a revoked token until it expires —");
    println!("which is why the default lifetime is 15 minutes, and why anything");
    println!("with immediate cost should introspect rather than verify locally.");

    println!("\n✅ Example completed successfully!");
    Ok(())
}
