# wami

**Who Am I** — multicloud identity, IAM, STS and SSO for Rust.

[![crates.io](https://img.shields.io/crates/v/wami.svg)](https://crates.io/crates/wami)
[![docs.rs](https://docs.rs/wami/badge.svg)](https://docs.rs/wami)
[![CI](https://github.com/Lsh0x/wami/workflows/CI/badge.svg)](https://github.com/Lsh0x/wami/actions)
[![MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/Lsh0x/wami/blob/main/LICENSE)

An AWS-IAM-shaped identity model — users, groups, roles, policies, permission
boundaries — that is not tied to AWS. Policy evaluation, temporary credentials,
tenant isolation and token issuance are all yours to run, against whatever
storage you already have.

wami holds no database and serves no HTTP. It decides, and it signs.

## Install

```toml
[dependencies]
wami = "0.16"
tokio = { version = "1", features = ["full"] }
```

Requires Rust 1.90.

## Quick start

```rust
use wami::arn::{TenantPath, WamiArn};
use wami::context::WamiContext;
use wami::store::memory::InMemoryWamiStore;
use wami::store::traits::UserStore;
use wami::wami::identity::user::builder::build_user;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut store = InMemoryWamiStore::default();

    // Who is asking, and on whose behalf. Every operation carries one.
    let context = WamiContext::builder()
        .instance_id("123456789012")
        .tenant_path(TenantPath::single(0))
        .caller_arn(
            WamiArn::builder()
                .service(wami::arn::Service::Iam)
                .tenant_path(TenantPath::single(0))
                .wami_instance("123456789012")
                .resource("user", "admin")
                .build()?,
        )
        .is_root(false)
        .build()?;

    // Building is pure; storing is the side effect. The two are separate
    // throughout, so a domain object can be constructed and checked without a
    // store in sight.
    let user = build_user("alice".to_string(), Some("/engineering/".to_string()), &context)?;
    let created = store.create_user(user).await?;

    println!("{} → {}", created.user_name, created.wami_arn);
    Ok(())
}
```

## What is in the box

| | |
|---|---|
| **Identity** | users, groups, roles, service-linked roles, instance profiles |
| **Policies** | managed and inline, permission boundaries, condition keys, and an evaluator that returns *why* it decided, not just yes or no |
| **STS** | temporary credentials, role assumption, session tags, federation |
| **OAuth 2.0** | `client_credentials`, introspection (RFC 7662), revocation (RFC 7009) |
| **OpenID Connect** | authorization code with mandatory PKCE, consent, refresh rotation with leak detection, ID tokens, `/userinfo`, discovery |
| **Multi-tenancy** | hierarchical tenants, isolation enforced at the ARN level |
| **ARNs** | a native scheme, with translation to and from AWS, GCP, Azure and Scaleway |

Authorization does not answer with a bare boolean. It returns a `Decision`
naming the statements that produced it — which policy, which `Sid`, which
index — so an audit log can say *why* a request was refused.

## Storage is yours

Everything persistent sits behind a trait. `InMemoryWamiStore` ships for tests
and examples; a real deployment implements the traits over Postgres, SQLite,
DynamoDB, or whatever it already runs. Nothing in the domain or service layers
knows the difference.

## Feature flags

```toml
wami = { version = "0.16", features = ["aws"] }
```

| flag | default | what it adds |
|---|---|---|
| `sts-jwt` | **on** | Ed25519 signing for STS credentials, OAuth and OIDC tokens |
| `aws`, `gcp`, `azure`, `scaleway` | off | ARN translation for that provider |
| `all-providers` | off | all four |

Providers are off by default on purpose: a build that never touches GCP should
not carry the code that knows about it.

## Documentation

- [Getting started](https://github.com/Lsh0x/wami/blob/main/docs/GETTING_STARTED.md)
- [IAM guide](https://github.com/Lsh0x/wami/blob/main/docs/IAM_GUIDE.md) ·
  [STS](https://github.com/Lsh0x/wami/blob/main/docs/STS_GUIDE.md) ·
  [OAuth & OIDC](https://github.com/Lsh0x/wami/blob/main/docs/OAUTH_OIDC_GUIDE.md) ·
  [Multi-tenant](https://github.com/Lsh0x/wami/blob/main/docs/MULTI_TENANT_GUIDE.md)
- [Implementing a store](https://github.com/Lsh0x/wami/blob/main/docs/STORE_IMPLEMENTATION.md)
- [Architecture](https://github.com/Lsh0x/wami/blob/main/docs/ARCHITECTURE.md)
- [API reference on docs.rs](https://docs.rs/wami)

Twenty-eight runnable [examples](https://github.com/Lsh0x/wami/tree/main/crates/wami/examples),
from a five-line hello to a full OIDC sign-in:

```bash
cargo run --example 01_hello_wami
cargo run --example 28_oidc_authorization_code
```

## Security

Report vulnerabilities per [SECURITY.md](https://github.com/Lsh0x/wami/blob/main/docs/SECURITY.md).
Please do not open a public issue for them.

## License

MIT. See [LICENSE](https://github.com/Lsh0x/wami/blob/main/LICENSE).
