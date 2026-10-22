//! What a condition reads of the caller: its NAME, never the id its ARN
//! carries (D8), and tenants as full paths, never a first segment (D6's
//! class) — review round 1, Δ2 and Δ11.

use super::guard::signed_in;
use super::{caller, key, t57, Shared, INSTANCE};
use crate::service::AuthorizationService;
use crate::store::traits::{GroupStore, PolicyStore, RoleStore, UserStore};
use crate::wami::identity::user::builder::build_user;
use wami_core::arn::{TenantPath, WamiArn};
use wami_core::context::WamiContext;

/// What the condition checks traverse: the evaluator's traits.
pub trait EvaluatorStore: UserStore + GroupStore + RoleStore + PolicyStore + 'static {}
impl<T> EvaluatorStore for T where T: UserStore + GroupStore + RoleStore + PolicyStore + 'static {}

fn target(tenant: &TenantPath, name: &str) -> WamiArn {
    format!("arn:wami:iam:{tenant}:wami:{INSTANCE}:user/{name}")
        .parse()
        .expect("an ARN")
}

/// Store 5/7's `alice` with `documents` as inline policies; her context, as
/// authentication builds it from the record.
async fn alice<S: EvaluatorStore>(store: &Shared<S>, documents: &[String]) -> WamiContext {
    let mut s = store.write().await;
    let user = build_user(&key(&t57(), "alice"), None, &caller(&t57(), "seed")).expect("alice");
    s.create_user(user.clone()).await.expect("alice");
    for (i, document) in documents.iter().enumerate() {
        s.put_user_policy(&user.key(), &format!("p{i}"), document.clone())
            .await
            .expect("a policy");
    }
    signed_in(&user)
}

async fn allowed<S: EvaluatorStore>(store: &Shared<S>, ctx: &WamiContext, on: &WamiArn) -> bool {
    AuthorizationService::new(store.clone())
        .authorize(ctx, "iam:GetUser", on)
        .await
        .expect("a decision")
        .is_allowed()
}

/// T3: a Deny conditioned on `aws:username` = alice fires for alice — the
/// name, not the id her ARN carries — and one on bob does not.
///
/// # Panics
///
/// When `aws:username` is not the caller's name.
pub async fn aws_username_is_the_callers_name<S: EvaluatorStore>(store: Shared<S>) {
    let allow_all = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"}]}"#;
    let deny_if = |name: &str| {
        format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Deny","Action":"iam:GetUser","Resource":"*","Condition":{{"StringEquals":{{"aws:username":"{name}"}}}}}}]}}"#
        )
    };
    let ctx = alice(&store, &[allow_all.to_string(), deny_if("alice")]).await;
    assert!(
        !allowed(&store, &ctx, &target(&t57(), "anyone")).await,
        "a Deny on aws:username = alice did not fire for alice"
    );
    // The pair, on a fresh store: a Deny on another name leaves the Allow.
    let other: Shared<S> = store.clone();
    {
        let mut s = other.write().await;
        s.delete_user_policy(&key(&t57(), "alice"), "p1")
            .await
            .expect("delete");
        s.put_user_policy(&key(&t57(), "alice"), "p1", deny_if("bob"))
            .await
            .expect("put");
    }
    assert!(
        allowed(&other, &ctx, &target(&t57(), "anyone")).await,
        "a Deny on aws:username = bob fired for alice"
    );
}

/// T3: an Allow on `user/${principal}` matches the caller's own NAME, and
/// nobody else's.
///
/// # Panics
///
/// When `${principal}` is not the caller's name.
pub async fn the_principal_variable_is_the_callers_name<S: EvaluatorStore>(store: Shared<S>) {
    let own = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":"iam:GetUser","Resource":"arn:wami:iam:{}:wami:{INSTANCE}:user/${{principal}}"}}]}}"#,
        t57()
    );
    let ctx = alice(&store, &[own]).await;
    assert!(
        allowed(&store, &ctx, &target(&t57(), "alice")).await,
        "user/${{principal}} does not match alice's own name"
    );
    assert!(
        !allowed(&store, &ctx, &target(&t57(), "bob")).await,
        "user/${{principal}} matched bob"
    );
}

/// Δ11: the tenant condition keys are FULL paths: a principal of 5/7 is not
/// of tenant `5`, and a resource of 5/9 is not of 5/7.
///
/// # Panics
///
/// When a tenant key compares a first segment.
pub async fn tenant_condition_keys_are_full_paths<S: EvaluatorStore>(store: Shared<S>) {
    let allow_if = |key: &str, value: &str| {
        format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":"iam:GetUser","Resource":"*","Condition":{{"StringEquals":{{"{key}":"{value}"}}}}}}]}}"#
        )
    };
    let ctx = alice(&store, &[allow_if("wami:PrincipalTenantId", "5")]).await;
    let replace = |document: String| {
        let store = store.clone();
        async move {
            let mut s = store.write().await;
            s.delete_user_policy(&key(&t57(), "alice"), "p0")
                .await
                .expect("delete");
            s.put_user_policy(&key(&t57(), "alice"), "p0", document)
                .await
                .expect("put");
        }
    };
    let nine = TenantPath::new(vec![5, 9]);
    assert!(
        !allowed(&store, &ctx, &target(&t57(), "x")).await,
        "a 5/7 principal passed PrincipalTenantId = 5"
    );
    replace(allow_if("wami:PrincipalTenantId", "5/7")).await;
    assert!(
        allowed(&store, &ctx, &target(&t57(), "x")).await,
        "PrincipalTenantId = 5/7 does not match a 5/7 principal"
    );
    replace(allow_if("wami:ResourceTenantId", "5/7")).await;
    assert!(
        !allowed(&store, &ctx, &target(&nine, "x")).await,
        "a 5/9 resource passed ResourceTenantId = 5/7"
    );
    assert!(
        allowed(&store, &ctx, &target(&t57(), "x")).await,
        "ResourceTenantId = 5/7 does not match a 5/7 resource"
    );
}
