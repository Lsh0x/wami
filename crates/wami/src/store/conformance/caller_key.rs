//! The caller's key: the evaluator finds a principal's policies by the key
//! its context carries — set from the record at authentication — and checks
//! it at use, so a forged or stale key decides nothing (S9, S13, S15).

use super::conditions::EvaluatorStore;
use super::{caller, key, t57, t67, Shared, INSTANCE};
use crate::credentials::access_key::builder::build_access_key;
use crate::service::auth::authentication::hash_secret;
use crate::service::{AuthenticationService, AuthorizationService};
use crate::store::traits::AccessKeyStore;
use crate::wami::identity::role::builder::build_role;
use crate::wami::identity::user::builder::build_user;
use wami_core::arn::{ScopedName, TenantPath, WamiArn};
use wami_core::context::WamiContext;

fn allow(action: &str) -> String {
    format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":"{action}","Resource":"*"}}]}}"#
    )
}

fn anything() -> WamiArn {
    format!("arn:wami:iam:{}:wami:{INSTANCE}:user/anyone", t57())
        .parse()
        .expect("an ARN")
}

/// Store `name` in `tenant`, with an inline policy allowing `action` when
/// given, and an access key whose secret is `secret`; returns the key id.
async fn stored<S: EvaluatorStore + AccessKeyStore>(
    store: &Shared<S>,
    tenant: &TenantPath,
    name: &str,
    action: Option<&str>,
    secret: &str,
) -> String {
    let ctx = caller(tenant, "seed");
    let mut s = store.write().await;
    let user = build_user(&key(tenant, name), None, &ctx).expect("a user");
    s.create_user(user).await.expect("the user");
    if let Some(action) = action {
        s.put_user_policy(&key(tenant, name), "own", allow(action))
            .await
            .expect("its policy");
    }
    let mut access_key = build_access_key(&key(tenant, name), &ctx).expect("a key");
    access_key.secret_access_key = Some(hash_secret(secret).expect("a hash"));
    let id = access_key.access_key_id.clone();
    s.create_access_key(access_key).await.expect("the key");
    id
}

/// S9: an AUTHENTICATED principal's own inline policy is found — the
/// context `authenticate` builds carries its key — and a same-named
/// principal of another tenant, authenticated the same way, is not judged on
/// it.
///
/// # Panics
///
/// When a principal's own policy is missed, or found for its namesake.
pub async fn an_authenticated_principal_finds_its_own_policy_and_only_its_own<
    S: EvaluatorStore + AccessKeyStore,
>(
    store: Shared<S>,
) {
    let mine = stored(&store, &t57(), "alice", Some("iam:GetUser"), "five-secret").await;
    let theirs = stored(&store, &t67(), "alice", None, "six-secret").await;
    let auth = AuthenticationService::new(store.clone());
    let authz = AuthorizationService::new(store.clone());

    let five = auth
        .authenticate(&mine, "five-secret")
        .await
        .expect("5/7's alice");
    let decision = authz.authorize(&five, "iam:GetUser", &anything()).await;
    assert!(
        matches!(&decision, Ok(d) if d.is_allowed()),
        "5/7's alice's own policy was not found: {decision:?}"
    );
    let six = auth
        .authenticate(&theirs, "six-secret")
        .await
        .expect("6/7's alice");
    let decision = authz.authorize(&six, "iam:GetUser", &anything()).await;
    assert!(
        !matches!(&decision, Ok(d) if d.is_allowed()),
        "6/7's alice was judged on 5/7's alice's policy: {decision:?}"
    );
}

/// The context a role session of `assumer` on `role` carries, as a consumer
/// builds it from the two records.
fn session(
    assumer: &crate::wami::identity::User,
    role: &crate::wami::identity::Role,
) -> WamiContext {
    WamiContext::builder()
        .caller_arn(assumer.wami_arn.clone())
        .caller_key(assumer.key())
        .session_info(wami_core::context::SessionInfo {
            session_token: "session".to_string(),
            expiration: i64::MAX,
            assumed_role_arn: Some(role.wami_arn.clone()),
            assumed_role_key: Some(role.key()),
        })
        .build()
        .expect("a session context")
}

/// S13 (sessions): a session on 5/7's `admin` role finds 5/7's admin's
/// policies, a session on 6/7's `admin` does not, and the policies found are
/// the role's — never the assuming user's own.
///
/// # Panics
///
/// When a session is judged on another tenant's role, or on its assumer.
pub async fn a_session_is_judged_on_its_roles_policies_only<S: EvaluatorStore>(store: Shared<S>) {
    let ctx = caller(&t57(), "seed");
    let (bob, r57, r67) = {
        let mut s = store.write().await;
        let bob = build_user(&key(&t57(), "bob"), None, &ctx).expect("bob");
        s.create_user(bob.clone()).await.expect("bob");
        s.put_user_policy(&bob.key(), "own", allow("iam:DeleteUser"))
            .await
            .expect("bob's own");
        let mut roles = Vec::new();
        for tenant in [t57(), t67()] {
            let role = build_role(
                &key(&tenant, "admin"),
                allow("sts:AssumeRole"),
                None,
                None,
                None,
                &caller(&tenant, "seed"),
            )
            .expect("a role");
            s.create_role(role.clone()).await.expect("a role");
            roles.push(role);
        }
        s.put_role_policy(&roles[0].key(), "role", allow("iam:GetUser"))
            .await
            .expect("5/7's role policy");
        (bob, roles[0].clone(), roles[1].clone())
    };
    let authz = AuthorizationService::new(store.clone());

    let on57 = session(&bob, &r57);
    let got = authz.authorize(&on57, "iam:GetUser", &anything()).await;
    assert!(
        matches!(&got, Ok(d) if d.is_allowed()),
        "a session on 5/7's admin misses its role's policy: {got:?}"
    );
    let got = authz.authorize(&on57, "iam:DeleteUser", &anything()).await;
    assert!(
        !matches!(&got, Ok(d) if d.is_allowed()),
        "a session was judged on its assumer's own policy: {got:?}"
    );

    let on67 = session(&bob, &r67);
    let got = authz.authorize(&on67, "iam:GetUser", &anything()).await;
    assert!(
        !matches!(&got, Ok(d) if d.is_allowed()),
        "a session on 6/7's admin found 5/7's admin's policy: {got:?}"
    );

    // A session whose role KEY names 5/7's admin while its role ARN is 6/7's
    // admin's is refused: the key is checked against the ARN at use.
    let forged = WamiContext::builder()
        .caller_arn(bob.wami_arn.clone())
        .caller_key(bob.key())
        .session_info(wami_core::context::SessionInfo {
            session_token: "session".to_string(),
            expiration: i64::MAX,
            assumed_role_arn: Some(r67.wami_arn.clone()),
            assumed_role_key: Some(r57.key()),
        })
        .build()
        .expect("a context");
    let got = authz.authorize(&forged, "iam:GetUser", &anything()).await;
    assert!(
        matches!(got, Err(wami_core::error::AmiError::AccessDenied { .. })),
        "a session with a forged role key → {got:?}"
    );
}

/// S15: a context whose key names another record than its caller ARN is
/// refused — a forged name at use, a forged tenant (or both) already at
/// build — and so is one with no key or a key with no record; every refusal
/// at use is the SAME refusal. A context deserialised with a key whose tenant
/// differs from its caller ARN's is refused at the wire.
///
/// # Panics
///
/// When a forged, absent or dangling key decides anything, or the refusals
/// differ.
pub async fn a_forged_caller_key_decides_nothing<S: EvaluatorStore + AccessKeyStore>(
    store: Shared<S>,
) {
    stored(&store, &t57(), "alice", Some("iam:GetUser"), "s1").await;
    stored(&store, &t57(), "admin", Some("iam:*"), "s2").await;
    stored(&store, &t67(), "alice", Some("iam:*"), "s3").await;
    let alice = store
        .read()
        .await
        .get_user(&key(&t57(), "alice"))
        .await
        .expect("a read")
        .expect("alice");
    let authz = AuthorizationService::new(store.clone());
    let built = |k: Option<ScopedName>| {
        let b = WamiContext::builder().caller_arn(alice.wami_arn.clone());
        match k {
            // The path declared as the key's: beside any other, the build
            // refuses a forged tenant before the check at use is reached
            // (review round 2 F1), and this test is about that check.
            Some(k) => b.tenant_path(k.tenant().clone()).caller_key(k),
            None => b,
        }
        .build()
    };
    let with_key = |k: Option<ScopedName>| built(k).expect("a context");

    // A key of another tenant than the caller's is not even built (review
    // round 3 L3), as the wire refuses it below.
    for (what, k) in [
        ("forged tenant", key(&t67(), "alice")),
        ("forged both", key(&t67(), "admin")),
    ] {
        let got = built(Some(k));
        assert!(got.is_err(), "{what}: built {got:?}");
    }

    // The genuine context is allowed: the arrange works.
    let genuine = authz
        .authorize(&with_key(Some(alice.key())), "iam:GetUser", &anything())
        .await;
    assert!(
        matches!(&genuine, Ok(d) if d.is_allowed()),
        "arrange: alice's own context: {genuine:?}"
    );

    let mut refusals = Vec::new();
    for (what, k) in [
        ("forged name", Some(key(&t57(), "admin"))),
        ("no record", Some(key(&t57(), "ghost"))),
        ("no key", None),
    ] {
        let got = authz
            .authorize(&with_key(k), "iam:GetUser", &anything())
            .await;
        match got {
            Err(wami_core::error::AmiError::AccessDenied { message }) => {
                refusals.push((what, message))
            }
            other => panic!("{what}: expected the refusal, got {other:?}"),
        }
    }
    let first = refusals[0].1.clone();
    for (what, message) in &refusals {
        assert_eq!(
            message, &first,
            "{what} is refused differently from {}",
            refusals[0].0
        );
    }

    // At the wire: a key whose tenant is not the caller ARN's.
    let mut json = serde_json::to_value(with_key(Some(alice.key()))).expect("serialised");
    json["caller_key"] = serde_json::to_value(key(&t67(), "alice")).expect("a key");
    let back = serde_json::from_value::<WamiContext>(json);
    assert!(
        back.is_err(),
        "a context with a key of another tenant was accepted: {back:?}"
    );
}
