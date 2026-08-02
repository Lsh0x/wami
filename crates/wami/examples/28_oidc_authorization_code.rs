//! Example 28: OpenID Connect — authorization code with PKCE
//!
//! wami as the identity provider for a flow with a human in it: a user signs
//! in, approves what an application may see, and the application ends up with
//! an ID token saying who they are and an access token saying what it may do.
//!
//! What this shows, in order:
//!
//! 1. Registering a client with a redirect URI
//! 2. Consent — asked once, remembered afterwards
//! 3. The code exchange, bound to a PKCE verifier
//! 4. ID token, access token, `/userinfo` — and what each is for
//! 5. Refresh rotation, and what happens when a token is used twice
//! 6. Withdrawing consent
//! 7. The discovery document
//!
//! Two things the host opts into, shown along the way: reporting *how* it
//! authenticated the user (`auth_time`/`acr`/`amr`), and labelling access
//! tokens `at+jwt` so a resource server can refuse an ID token structurally
//! rather than by checking the audience.
//!
//! wami does not authenticate the user. The host does that — a password, a
//! passkey, an upstream IdP — and then tells wami who signed in.

use chrono::{Duration, Utc};
use std::sync::Arc;
use tokio::sync::RwLock;
use wami::service::oauth::oidc::{
    Authorization, AuthorizationRequest, CodeExchange, UserClaimsSource,
};
use wami::service::oauth::OAuthService;
use wami::store::memory::InMemoryOAuthStore;
use wami::wami::oauth::{
    build_client, derive_s256_challenge, generate_client_secret, AuthenticationEvent,
    CodeChallenge, GrantType, IdTokenClaims, OAuthClaims, UserProfile,
};
use wami::wami::sts::jwt::{KeyManager, TokenType};
use wami_core::error::Result;

const AUDIENCE: &str = "photos-api";
const REDIRECT: &str = "https://gallery.example.test/callback";

/// The host's user directory. wami asks it what may be released.
struct Directory;

#[async_trait::async_trait]
impl UserClaimsSource for Directory {
    async fn claims_for(&self, user_name: &str) -> Result<Option<UserProfile>> {
        Ok((user_name == "alice").then(|| UserProfile {
            name: Some("Alice Martin".to_string()),
            email: Some("alice@example.test".to_string()),
        }))
    }
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    println!("🪪  OpenID Connect — authorization code + PKCE\n");
    println!("{}", "=".repeat(60));

    // ── 1. Register a client ─────────────────────────────────────
    println!("\n📝 Step 1: Register a client");

    let store = Arc::new(RwLock::new(InMemoryOAuthStore::new()));
    let keys = Arc::new(KeyManager::generate());
    let service = OAuthService::new(store, keys.clone(), "https://id.example.test".to_string())
        .with_user_claims(Arc::new(Directory))
        // RFC 9068: access tokens get `typ: at+jwt`, ID tokens keep `JWT`.
        // Opt-in, because a resource server pinning the old value would break.
        .with_explicit_typ();

    let secret = generate_client_secret();
    let client = build_client(
        "gallery".to_string(),
        &secret,
        "Photo Gallery".to_string(),
        vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
        vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
            "photos:read".to_string(),
        ],
        AUDIENCE.to_string(),
        vec![REDIRECT.to_string()],
    )?;
    service.register_client(client).await?;
    println!("✅ client_id: gallery");
    println!("   redirect:  {REDIRECT}");

    // The client generates a verifier, keeps it, and sends only its hash.
    let verifier = generate_client_secret();
    let challenge = CodeChallenge::s256(derive_s256_challenge(&verifier));

    let asked = vec![
        "openid".to_string(),
        "profile".to_string(),
        "photos:read".to_string(),
    ];
    // The host authenticated Alice two hours ago with a password and a
    // hardware key, and is willing to say so. wami cannot know this — it never
    // performs the sign-in.
    let signed_in = AuthenticationEvent {
        at: Utc::now() - Duration::hours(2),
        acr: Some("urn:mace:incommon:iap:silver".to_string()),
        amr: vec!["pwd".to_string(), "hwk".to_string()],
    };

    let request = || AuthorizationRequest {
        client_id: "gallery".to_string(),
        user_name: "alice".to_string(), // the host has just authenticated her
        redirect_uri: REDIRECT.to_string(),
        scopes: asked.clone(),
        challenge: challenge.clone(),
        nonce: Some("n-0S6_WzA2Mj".to_string()),
        event: Some(signed_in.clone()),
        state: Some("opaque-client-state".to_string()),
    };

    // ── 2. Consent ───────────────────────────────────────────────
    println!("\n🙋 Step 2: Alice has never used this application");

    match service.authorize(request()).await? {
        Authorization::ConsentRequired { scopes, .. } => {
            println!("✅ consent required for: {}", scopes.join(", "));
            println!("   (the host shows a screen; nothing was issued)");
            service.grant_consent("gallery", "alice", scopes).await?;
            println!("   Alice approves");
        }
        Authorization::Code { .. } => println!("❌ a code was issued without consent!"),
    }

    let code = match service.authorize(request()).await? {
        Authorization::Code { code, state, .. } => {
            println!("✅ code issued, state handed back untouched: {state:?}");
            code
        }
        Authorization::ConsentRequired { .. } => unreachable!("consent was just granted"),
    };

    // ── 3. The exchange ──────────────────────────────────────────
    println!("\n🔄 Step 3: The client redeems the code with its verifier");

    let tokens = service
        .exchange_code(CodeExchange {
            client_id: "gallery".to_string(),
            client_secret: secret.clone(),
            code: code.clone(),
            redirect_uri: REDIRECT.to_string(),
            code_verifier: verifier.clone(),
        })
        .await?;
    println!("✅ access + refresh + id token, scope: {}", tokens.scope);

    // A code is spent whether or not the exchange succeeded.
    let replay = service
        .exchange_code(CodeExchange {
            client_id: "gallery".to_string(),
            client_secret: secret.clone(),
            code,
            redirect_uri: REDIRECT.to_string(),
            code_verifier: verifier,
        })
        .await;
    println!("✅ replaying the code: {}", refused(&replay));

    // ── 4. Two tokens, two jobs ──────────────────────────────────
    println!("\n🎭 Step 4: What each token is for");

    let id: IdTokenClaims = keys.verify_claims(tokens.id_token.as_ref().unwrap(), "gallery")?;
    println!("   ID token   → who signed in");
    println!("      sub={} name={:?}", id.sub, id.name);
    println!("      nonce echoed: {:?}", id.nonce);
    println!("      acr={:?} amr={:?}", id.acr, id.amr);
    println!(
        "      email={:?} (the `email` scope was never asked for)",
        id.email
    );

    // A verifier of access tokens has to say so, now that they are labelled.
    // `verify_claims` is the ID-token-shaped door and refuses an `at+jwt`.
    let access: OAuthClaims =
        keys.verify_claims_as(&tokens.access_token, AUDIENCE, TokenType::AccessToken)?;
    println!("   Access token → what may be done");
    println!("      sub={} client_id={}", access.sub, access.client_id);
    println!("      scope={}", access.scope);

    // Two independent barriers. The audiences differ, so an ID token does not
    // verify against the API's audience — and with explicit typing on, the
    // header says `at+jwt` vs `JWT`, which a resource server can refuse without
    // looking at a single claim.
    let confused: std::result::Result<IdTokenClaims, _> =
        keys.verify_claims(tokens.id_token.as_ref().unwrap(), AUDIENCE);
    println!(
        "✅ the API refuses the ID token as authorisation: {}",
        confused.is_err()
    );
    println!(
        "   headers say typ={:?} (access) vs {:?} (id)",
        jsonwebtoken::decode_header(&tokens.access_token)?.typ,
        jsonwebtoken::decode_header(tokens.id_token.as_ref().unwrap())?.typ,
    );

    let info = service.user_info(&tokens.access_token, AUDIENCE).await?;
    println!("   /userinfo  → sub={} name={:?}", info.sub, info.name);

    // ── 5. Refresh rotation ──────────────────────────────────────
    println!("\n♻️  Step 5: Refreshing, and a leak");

    let next = service
        .refresh_tokens("gallery", &secret, &tokens.refresh_token)
        .await?;
    println!("✅ refreshed — the old token is spent, a new one took its place");

    // OIDC Core §12.2: auth_time is the ORIGINAL sign-in, not this moment.
    let refreshed: IdTokenClaims =
        keys.verify_claims(next.id_token.as_ref().unwrap(), "gallery")?;
    println!(
        "   auth_time unchanged: {} — the session did not get younger",
        if refreshed.auth_time == Some(signed_in.at.timestamp()) {
            "yes"
        } else {
            "NO — §12.2 violated!"
        }
    );

    // Someone stole the first refresh token and tries it after the client used
    // it. There is no way to tell the thief from the client, so both lose.
    let stolen = service
        .refresh_tokens("gallery", &secret, &tokens.refresh_token)
        .await;
    println!("🚨 reuse detected: {}", refused(&stolen));

    let legitimate = service
        .refresh_tokens("gallery", &secret, &next.refresh_token)
        .await;
    println!(
        "   the honest client is locked out too: {}",
        refused(&legitimate)
    );
    println!("   (that is the point — Alice signs in again, the thief cannot)");

    // ── 6. Withdrawing consent ───────────────────────────────────
    println!("\n🚪 Step 6: Alice changes her mind");

    service.withdraw_consent("gallery", "alice").await?;
    println!("✅ consent withdrawn, and every refresh token with it");
    match service.authorize(request()).await? {
        Authorization::ConsentRequired { .. } => println!("   she is asked again next time"),
        Authorization::Code { .. } => println!("❌ a code was issued after withdrawal!"),
    }

    // ── 7. Discovery ─────────────────────────────────────────────
    println!("\n🧭 Step 7: What a relying party discovers");

    let doc = service.discovery("https://id.example.test");
    println!("   issuer:    {}", doc.issuer);
    println!("   token:     {}", doc.token_endpoint);
    println!("   jwks:      {}", doc.jwks_uri);
    println!("   pkce:      {:?}", doc.code_challenge_methods_supported);
    println!("   grants:    {}", doc.grant_types_supported.join(", "));

    println!("\n{}", "=".repeat(60));
    println!("⚠️  What wami does not do");
    println!("{}", "=".repeat(60));
    println!("It never authenticates the user, and it serves no HTTP. The host");
    println!("proves who is at the keyboard, mounts the endpoints discovery");
    println!("advertises, and hands the browser its redirects. wami decides what");
    println!("may be issued, and signs it.");

    println!("\n✅ Example completed successfully!");
    Ok(())
}

/// Print an error's message, or complain loudly if there was no error.
fn refused<T>(outcome: &std::result::Result<T, wami_core::error::AmiError>) -> String {
    match outcome {
        Err(e) => e.to_string(),
        Ok(_) => "❌ ACCEPTED — this should have been refused!".to_string(),
    }
}
