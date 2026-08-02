# OAuth 2.0 & OpenID Connect Guide

wami as an authorization server and an OpenID Provider. One Ed25519 keyset signs
everything — STS credentials, machine-to-machine access tokens, and ID tokens —
so there is one JWKS to publish and one rotation policy to run.

## Table of Contents

1. [What wami does, and what it does not](#what-wami-does-and-what-it-does-not)
2. [Machine-to-machine: client credentials](#machine-to-machine-client-credentials)
3. [Users: authorization code with PKCE](#users-authorization-code-with-pkce)
4. [The flow, end to end](#the-flow-end-to-end)
5. [Two tokens, two audiences](#two-tokens-two-audiences)
6. [Explicit token typing (RFC 9068)](#explicit-token-typing-rfc-9068)
7. [Reporting the sign-in](#reporting-the-sign-in)
8. [Refresh rotation and leak detection](#refresh-rotation-and-leak-detection)
9. [Implementing a store](#implementing-a-store)
10. [What is deliberately absent](#what-is-deliberately-absent)

---

## What wami does, and what it does not

**wami decides what may be issued, and signs it.**

It does **not** authenticate the user, and it serves **no HTTP**. The host
application proves who is at the keyboard — a password, a passkey, an upstream
IdP — mounts the endpoints the discovery document advertises, and hands the
browser its redirects.

That split is why `authorize` takes a `user_name` rather than credentials: by
the time wami is called, the question of *who* is already settled.

> If you want the opposite direction — wami consuming an external IdP rather
> than being one — see `IdentityProviderService`.

---

## Machine-to-machine: client credentials

A service authenticates as itself and receives a short-lived signed JWT.

```rust
use std::sync::Arc;
use tokio::sync::RwLock;
use wami::service::oauth::OAuthService;
use wami::store::memory::InMemoryOAuthStore;
use wami::wami::oauth::{build_client, generate_client_secret, GrantRequest, GrantType};
use wami::wami::sts::jwt::KeyManager;

let store = Arc::new(RwLock::new(InMemoryOAuthStore::new()));
let keys = Arc::new(KeyManager::generate());
let service = OAuthService::new(store, keys, "https://id.example.test".to_string());

let secret = generate_client_secret();
let client = build_client(
    "nightly-reports".to_string(),
    &secret,                                  // hashed on the way in
    "Nightly reporting job".to_string(),
    vec![GrantType::ClientCredentials],
    vec!["reports:read".to_string()],
    "reporting-api".to_string(),              // the audience
    vec![],                                   // no redirect URIs needed
)?;
service.register_client(client).await?;

let token = service.issue_token(GrantRequest::ClientCredentials {
    client_id: "nightly-reports".to_string(),
    client_secret: secret,
    scope: vec!["reports:read".to_string()],
}).await?;
```

Scopes are a ceiling, not a suggestion: asking for one the client does not hold
is **refused**, not silently narrowed. A client that believes it holds a scope
it does not is worse off than one told it cannot have it.

Introspection (RFC 7662) and revocation (RFC 7009) work as specified, including
the part where an inactive token discloses nothing but `active: false`.

> **The limit worth knowing.** A signed token is verifiable offline, so a
> verifier that checks the signature locally keeps accepting a revoked token
> until it expires. Revocation binds on whoever *introspects*. That is why the
> default lifetime is 15 minutes, and why anything with immediate cost should
> introspect rather than verify locally.

Runnable: [`examples/27_oauth_client_credentials.rs`](../crates/wami/examples/27_oauth_client_credentials.rs)

---

## Users: authorization code with PKCE

The host authenticates the user, then asks wami for a code:

```rust
use wami::service::oauth::oidc::{Authorization, AuthorizationRequest, CodeExchange};
use wami::wami::oauth::{derive_s256_challenge, CodeChallenge};

// The client generated a verifier and kept it; only its hash travels.
let challenge = CodeChallenge::s256(derive_s256_challenge(&verifier));

let request = AuthorizationRequest {
    client_id: "gallery".to_string(),
    user_name: "alice".to_string(),          // the host just authenticated her
    redirect_uri: "https://gallery.example.test/callback".to_string(),
    scopes: vec!["openid".into(), "profile".into()],
    challenge,                                // NOT an Option — see below
    nonce: Some("n-0S6_WzA2Mj".to_string()),
    event: None,                              // see "Reporting the sign-in"
    state: Some("opaque-client-state".to_string()),
};

match service.authorize(request).await? {
    Authorization::ConsentRequired { scopes, .. } => {
        // Show a screen. Nothing was issued.
        service.grant_consent("gallery", "alice", scopes).await?;
        // Then call authorize again.
    }
    Authorization::Code { code, redirect_uri, state } => {
        // 302 to redirect_uri?code=..&state=..
    }
}
```

Then the client redeems it:

```rust
let tokens = service.exchange_code(CodeExchange {
    client_id: "gallery".to_string(),
    client_secret: secret,
    code,
    redirect_uri: "https://gallery.example.test/callback".to_string(),
    code_verifier: verifier,
}).await?;
// tokens.access_token, tokens.refresh_token, tokens.id_token
```

Runnable: [`examples/28_oidc_authorization_code.rs`](../crates/wami/examples/28_oidc_authorization_code.rs)

### `state` is yours to check

wami passes `state` through untouched and does nothing with it — it cannot.
`state` defends against CSRF by being compared **at the callback**, and wami
never sees the callback; it has no browser session to bind to.

**The host must** generate it, tie it to the user agent's session, and reject a
callback whose `state` does not match. Passing it through here saves you
carrying it yourself; it is not a check.

---

## The flow, end to end

```mermaid
sequenceDiagram
    autonumber
    actor U as User
    participant H as Host app
    participant S as OAuthService
    participant St as Store
    participant K as KeyManager
    participant C as Client
    participant RS as Resource server

    rect rgb(232,244,255)
    Note over U,St: A. registration refuses a collapsed audience
    H->>S: build_client(client_id, .., audience, ..)
    alt audience == client_id
        S-->>H: InvalidParameter
        Note right of S: an access token (aud=audience) and an ID token<br/>(aud=client_id) would be addressed identically,<br/>and aud would stop separating them
    end
    end

    rect rgb(240,248,255)
    Note over U,St: B. the host may describe the sign-in
    H->>U: password + hardware key
    H->>S: authorize(.., event: Some(AuthenticationEvent{at, acr, amr}))
    S->>St: store_authorization_code{ .., event }
    end

    rect rgb(255,248,235)
    Note over S,K: C. mint
    C->>S: exchange_code(code, verifier)
    S->>St: consume_authorization_code (one op)
    S->>K: sign_claims_as(access, access_token_type())
    Note right of K: at+jwt with with_explicit_typ(), else JWT
    opt openid granted
        S->>K: sign_claims_as(id, TokenType::Jwt)
        Note right of K: ID tokens always JWT — OIDC registers no typ
    end
    S->>St: store_refresh_token{ .., event }
    S-->>C: OidcTokens
    end

    rect rgb(255,235,238)
    Note over C,St: D. refresh — the old token is spent, not kept
    C->>S: refresh_tokens(old)
    S->>St: rotate_refresh_token(old, replacement{event: existing.event})
    St->>St: old.used_at = now; old.replaced_by = replacement
    St-->>S: the record it took
    alt replaced_by != our replacement
        alt used_at was None
            S-->>C: AccessDenied — expired, chain untouched
        else used_at was Some
            S->>St: revoke_refresh_chain
            S-->>C: AccessDenied — reuse, chain revoked
        end
    end
    S->>K: sign id{ auth_time = event.at, nonce = None }
    Note right of K: §12.2 — the ORIGINAL sign-in
    end

    rect rgb(240,255,240)
    Note over C,RS: E. the three verification doors
    RS->>K: verify_claims(token, aud)
    Note right of K: no typ examined, ever.<br/>pre-RFC-9068 contract, unchanged
    RS->>K: verify_claims_as(token, aud, AccessToken, Lenient)
    Note right of K: signature + aud FIRST, label after.<br/>absent / JWT / at+jwt all pass
    RS->>K: verify_claims_as(token, aud, AccessToken, Strict)
    Note right of K: RFC 9068 §4 — ONLY at+jwt.<br/>absent and JWT are refused too
    C->>K: verify_claims_as(id, client_id, Jwt, Lenient)
    Note right of K: absent / JWT pass; at+jwt REFUSED
    end
```

---

## Two tokens, two audiences

An **ID token** says *who signed in*. An **access token** says *what may be
done*. They are not the same object with different fields:

| | `aud` | `sub` |
|---|---|---|
| access token | the resource server (`client.audience`) | the **user** |
| ID token | the **client** (`client.client_id`) | the user |

A resource server handed an ID token simply fails to verify it — the audience
does not match. That is the barrier, and it is why **`build_client` refuses a
client whose `audience` equals its `client_id`**: the two tokens would then be
addressed identically, and an access token would deserialise and verify as an
ID token.

---

## Explicit token typing (RFC 9068)

The audience split holds — but only for a verifier that checks the audience.
RFC 9068 adds a structural label so it does not have to:

> The resource server MUST verify that the `typ` header value is `at+jwt` or
> `application/at+jwt` and reject tokens carrying any other value.

### Issuing

```rust
let service = OAuthService::new(store, keys, issuer)
    .with_explicit_typ();          // access tokens get `typ: at+jwt`
```

ID tokens keep `JWT` — OIDC registers no `typ` of its own for them — and **that
difference is the point**: once typing is on, nothing wami signs as an access
token can be read as an ID token.

It is opt-in because every token wami issued before this carries `typ: JWT`, and
a resource server pinning that value would break the moment the header changed.
The default flips at the next major.

### Verifying — three doors

```rust
use wami::wami::sts::jwt::{TokenType, TypePolicy};

// 1. No typ examined, ever. The pre-RFC-9068 contract, unchanged.
let claims: OAuthClaims = keys.verify_claims(&token, audience)?;

// 2. Lenient — for a deployment mid-migration.
let claims: OAuthClaims = keys.verify_claims_as(
    &token, audience, TokenType::AccessToken, TypePolicy::Lenient)?;

// 3. Strict — RFC 9068 §4 as written.
let claims: OAuthClaims = keys.verify_claims_as(
    &token, audience, TokenType::AccessToken, TypePolicy::Strict)?;
```

| policy | expecting | header says | |
|---|---|---|---|
| `Lenient` | `AccessToken` | absent, `JWT`, or `at+jwt` | accepted |
| `Lenient` | `Jwt` | absent or `JWT` | accepted |
| `Lenient` | `Jwt` | `at+jwt` | **refused** |
| `Strict` | either | exactly the expected label | accepted |
| either | either | anything unrecognised | refused |

**Which to use.** `Lenient` while any issuer you accept still predates
labelling — it already closes the direction that matters. `Strict` once they all
label; until then it refuses your own legacy tokens, which is exactly why it is
a choice and not a default.

The signature and audience are checked **first**, always. The label is examined
only once the token has proven genuine, so no decision rests on bytes an
attacker chose.

### Turning it on is not an outage

A token minted before the flip carries `typ: JWT`, and `Lenient` verification —
which is what `introspect_token` and `user_info` use — still accepts it. Nothing
is reissued. Tokens in flight expire normally.

---

## Reporting the sign-in

A relying party enforcing `max_age` needs `auth_time`; one that cares whether a
password or a passkey was used needs `acr`/`amr`. wami cannot know any of it, so
the host says:

```rust
use wami::wami::oauth::AuthenticationEvent;

AuthorizationRequest {
    // ...
    event: Some(AuthenticationEvent {
        at: signed_in_at,
        acr: Some("urn:mace:incommon:iap:silver".to_string()),
        amr: vec!["pwd".to_string(), "hwk".to_string()],   // RFC 8176
    }),
}
```

Omit it and the claims do not appear — in the struct or on the wire.

### The event is carried, not recomputed

OIDC Core §12.2:

> if the ID Token contains an `auth_time` Claim, its value MUST represent the
> time of the original authentication - not the time that the new ID token is
> issued

So the event travels into the refresh chain. A chain that forgot it would
silently reset the user's session age on every refresh — precisely what an RP
enforcing `max_age` is trying to detect.

### One sign-in, one chain

`acr`/`amr` stay fixed for the life of the chain. A user who signs in with a
password and later adds a hardware key keeps reporting `amr: ["pwd"]` until the
chain ends.

That is not a gap: **a stronger authentication is a new authentication**, and the
honest way to reflect it is a new authorization, which mints a new chain with a
new event. An RP that needs a *fresh* assurance must ask for one, not trust a
claim minted a month ago.

---

## Refresh rotation and leak detection

A refresh token is **single-use**. Exchanging it spends it and issues a
replacement.

Presenting a spent token means it leaked — the legitimate client has already
moved on to its replacement. wami revokes the entire chain for that user and
client. **Both** the thief and the legitimate client are forced back through
sign-in, because there is no way to tell them apart from here, and a silent
second use is indistinguishable from theft.

An **expiry** is not a leak, and is not punished that way: the token is refused,
the chain is untouched, the user signs in again.

### Withdrawing consent kills the chain

```rust
service.withdraw_consent("gallery", "alice").await?;
```

Revoking the consent alone would leave the client holding a refresh token that
keeps minting access tokens for a month. The user would have said no and nothing
would have stopped.

---

## Implementing a store

Five traits, in `wami::store::traits::oauth`:

| trait | holds |
|---|---|
| `OAuthClientStore` | registered clients |
| `OAuthTokenStore` | issued access tokens, so they can be revoked |
| `OAuthAuthorizationStore` | authorization codes |
| `OAuthRefreshStore` | refresh tokens |
| `OAuthConsentStore` | standing user consent |

They carry the `OAuth` prefix because `ConsentStore` belongs to GDPR consent and
`SessionStore` to STS — unrelated concepts that would otherwise collide.

### Two contracts that are not optional

**`consume_authorization_code` must be one operation.** Reading the code and
then deleting it leaves a window in which two exchanges can both succeed —
precisely the replay an authorization code exists to be immune to. If your
backend cannot do it in one statement, use `DELETE ... RETURNING` or a
transaction. Do not emulate it with a get followed by a delete.

**`used_at` means "this token was spent", not "this token was shown to us".** It
may only be stamped by a rotation that won, or by `revoke_refresh_chain`. A
store that stamps it on a *failed* presentation — to record an attempt, say —
turns every expired token into a reported leak and every idle user into a forced
sign-out.

`rotate_refresh_token` returns the record it took, so the caller can tell
"unknown" from "expired" from "reused". When it cannot grant the rotation, it
must return the existing record **unchanged** and persist nothing.

### Not a transaction, on purpose

`exchange_code` consumes the code in one operation and writes the tokens in
another. A process that dies between the two leaves the code spent and no tokens
issued: the exchange fails, the user signs in again. **That is the direction to
fail in.** Minting first and consuming after turns the same crash into a code
still redeemable after tokens were handed out.

---

## What is deliberately absent

**No `plain` PKCE.** It defends against nothing: an attacker who intercepts the
authorization request sees the challenge, and under `plain` the challenge *is*
the verifier. It is absent from the code and from the discovery document.

**PKCE is not optional.** `AuthorizationRequest::challenge` is a
`CodeChallenge`, not an `Option<CodeChallenge>`. A caller cannot forget it.

**No implicit flow.** `response_types_supported` is `["code"]`.

**Redirect URIs match exactly, never by prefix.** A prefix match on
`https://app.test/cb` accepts `https://app.test/cb.attacker.test`, which is how
codes get delivered to the wrong party. An unregistered URI is an error to *the
caller of this library*, never a redirect — sending an error to an unverified
redirect URI is itself the vulnerability.

**No `at_hash`.** OIDC Core §3.1.3.6 makes it OPTIONAL for a token-endpoint ID
token in the code flow — REQUIRED only for front-channel delivery, which this
library never does. And the spec derives its hash from `alg`, which for EdDSA no
specification defines: implementations split between SHA-256 and Ed25519's
internal SHA-512. An `at_hash` a relying party recomputes differently is a hard
validation failure, where its absence is a no-op.

**No `claims_supported` in discovery.** Advertising `auth_time`/`acr`/`amr`
would be a claim wami cannot keep: whether they appear depends entirely on
whether the host reports them, which is not knowable at discovery time.

---

## See also

- [STS Guide](STS_GUIDE.md) — the same keyset, for temporary credentials
- [SSO Admin Guide](SSO_ADMIN_GUIDE.md) — permission sets
- [Store Implementation](STORE_IMPLEMENTATION.md) — persistence in general
- [Security](SECURITY.md) — reporting a vulnerability
