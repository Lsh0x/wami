//! A policy never decides another tenant's principal — at evaluation, where
//! a second writer cannot bypass it, and at every write that could set one
//! up (review round 1, Δ1, Δ4, Δ5, Δ6; orchestrator ruling 1).

use super::conditions::EvaluatorStore;
use super::guard::signed_in;
use super::{caller, key, t57, t67, Shared, INSTANCE};
use crate::service::{
    AttachmentService, AuthorizationService, GroupService, PermissionsBoundaryService,
    PolicyService, RoleService, UserService,
};
use crate::wami::identity::group::requests::CreateGroupRequest;
use crate::wami::identity::role::requests::CreateRoleRequest;
use crate::wami::identity::user::requests::CreateUserRequest;
use crate::wami::policies::attachment::requests::{
    AttachUserPolicyRequest, DetachUserPolicyRequest,
};
use crate::wami::policies::permissions_boundary::{PrincipalType, PutPermissionsBoundaryRequest};
use crate::wami::policies::policy::requests::CreatePolicyRequest;
use wami_core::arn::{ScopedName, TenantPath, WamiArn};
use wami_core::error::{AmiError, Result};

fn allow_get() -> String {
    r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser","Resource":"*"}]}"#
        .to_string()
}

fn policy(tenant: &TenantPath, name: &str) -> CreatePolicyRequest {
    CreatePolicyRequest {
        tenant: tenant.clone(),
        policy_name: name.to_string(),
        policy_document: allow_get(),
        path: None,
        description: None,
        tags: None,
    }
}

fn user(key: ScopedName, boundary: Option<String>) -> CreateUserRequest {
    CreateUserRequest {
        user: key,
        path: None,
        permissions_boundary: boundary,
        tags: None,
    }
}

fn anything() -> WamiArn {
    format!("arn:wami:iam:{}:wami:{INSTANCE}:user/anyone", t57())
        .parse()
        .expect("an ARN")
}

/// The one message two answers must share, the ARN they name masked.
fn masked<T: std::fmt::Debug>(got: Result<T>, arn: &str) -> String {
    match got {
        Ok(v) => panic!("expected a refusal for {arn}, got Ok({v:?})"),
        Err(e) => format!("{e:?}").replace(arn, "<ARN>"),
    }
}

/// The evaluation rule: a managed policy whose recorded tenant is not the
/// principal's — attached straight into the store, past every service — is
/// an error naming the attachment, never an Allow and never silently
/// skipped; and so is an attachment whose ARN holds no policy.
///
/// # Panics
///
/// When a foreign or dangling attachment allows, or is skipped silently.
pub async fn a_foreign_or_dangling_policy_takes_no_part_silently<S: EvaluatorStore>(
    store: Shared<S>,
) {
    let theirs = PolicyService::new(store.clone())
        .create_policy(&caller(&t67(), "seed"), policy(&t67(), "theirs"))
        .await
        .expect("6/7's policy")
        .arn;
    let alice = {
        let mut s = store.write().await;
        let alice = crate::wami::identity::user::builder::build_user(
            &key(&t57(), "alice"),
            None,
            &caller(&t57(), "seed"),
        )
        .expect("alice");
        s.create_user(alice.clone()).await.expect("alice");
        s.attach_user_policy(&alice.key(), &theirs)
            .await
            .expect("a row written past the services");
        alice
    };
    let authz = AuthorizationService::new(store.clone());
    let got = authz
        .authorize(&signed_in(&alice), "iam:GetUser", &anything())
        .await;
    match &got {
        Err(AmiError::UnreadablePolicy { policy, .. }) => assert!(
            policy.contains(&theirs),
            "the error does not name the attachment: {got:?}"
        ),
        other => panic!("a foreign policy took part, or was skipped: {other:?}"),
    }
    {
        let mut s = store.write().await;
        s.detach_user_policy(&alice.key(), &theirs)
            .await
            .expect("detach");
        s.attach_user_policy(&alice.key(), "arn:aws:iam::conformance:policy/nowhere")
            .await
            .expect("a dangling row");
    }
    let got = authz
        .authorize(&signed_in(&alice), "iam:GetUser", &anything())
        .await;
    assert!(
        matches!(&got, Err(AmiError::UnreadablePolicy { policy, .. }) if policy.contains("policy/nowhere")),
        "a dangling attachment was skipped: {got:?}"
    );
}

/// Δ1: a policy is not deleted while it is attached anywhere or serves as a
/// boundary — no dangling ARN for another tenant to re-create — and is once
/// it is free.
///
/// # Panics
///
/// When an attached policy can be deleted.
pub async fn an_attached_policy_is_not_deleted<S: EvaluatorStore>(store: Shared<S>) {
    let ctx = caller(&t57(), "seed");
    let p = PolicyService::new(store.clone())
        .create_policy(&ctx, policy(&t57(), "ops"))
        .await
        .expect("ops")
        .arn;
    UserService::new(store.clone())
        .create_user(&ctx, user(key(&t57(), "alice"), None))
        .await
        .expect("alice");
    UserService::new(store.clone())
        .create_user(&ctx, user(key(&t57(), "bob"), Some(p.clone())))
        .await
        .expect("bob, bounded by ops");
    AttachmentService::new(store.clone())
        .attach_user_policy(
            &ctx,
            AttachUserPolicyRequest {
                user: key(&t57(), "alice"),
                policy_arn: p.clone(),
            },
        )
        .await
        .expect("attached to alice");
    let policies = PolicyService::new(store.clone());
    assert!(
        policies.delete_policy(&ctx, &p).await.is_err(),
        "an attached policy was deleted"
    );
    AttachmentService::new(store.clone())
        .detach_user_policy(
            &ctx,
            DetachUserPolicyRequest {
                user: key(&t57(), "alice"),
                policy_arn: p.clone(),
            },
        )
        .await
        .expect("detached");
    assert!(
        policies.delete_policy(&ctx, &p).await.is_err(),
        "a boundary in use was deleted"
    );
    UserService::new(store.clone())
        .delete_user(&ctx, &key(&t57(), "bob"))
        .await
        .expect("bob gone");
    policies
        .delete_policy(&ctx, &p)
        .await
        .expect("a free policy is deleted");
}

/// Δ4: a membership needs both its group and its user to exist and to share
/// a tenant; a row refused for an absent user does not come alive when the
/// user is created.
///
/// # Panics
///
/// When a membership is written for an absent party or across tenants.
pub async fn a_membership_needs_both_parties_in_one_tenant<S: EvaluatorStore>(store: Shared<S>) {
    let ctx = caller(&t57(), "seed");
    let groups = GroupService::new(store.clone());
    for tenant in [t57(), t67()] {
        groups
            .create_group(
                &caller(&tenant, "seed"),
                CreateGroupRequest {
                    group: key(&tenant, "devs"),
                    path: None,
                    tags: None,
                },
            )
            .await
            .expect("devs");
    }
    UserService::new(store.clone())
        .create_user(&ctx, user(key(&t57(), "alice"), None))
        .await
        .expect("alice");
    UserService::new(store.clone())
        .create_user(&caller(&t67(), "seed"), user(key(&t67(), "bob"), None))
        .await
        .expect("bob");

    assert!(
        groups
            .add_user_to_group(&ctx, &key(&t57(), "devs"), &key(&t57(), "ghost"))
            .await
            .is_err(),
        "a member that does not exist"
    );
    assert!(
        groups
            .add_user_to_group(&ctx, &key(&t57(), "nobody"), &key(&t57(), "alice"))
            .await
            .is_err(),
        "a group that does not exist"
    );
    assert!(
        groups
            .add_user_to_group(&ctx, &key(&t57(), "devs"), &key(&t67(), "bob"))
            .await
            .is_err(),
        "6/7's bob joined 5/7's group"
    );
    UserService::new(store.clone())
        .create_user(&ctx, user(key(&t57(), "ghost"), None))
        .await
        .expect("ghost, now");
    let s = store.read().await;
    assert_eq!(
        s.list_groups_for_user(&key(&t57(), "ghost"))
            .await
            .expect("groups")
            .len(),
        0,
        "a refused row came alive"
    );
    assert_eq!(
        s.list_groups_for_user(&key(&t67(), "bob"))
            .await
            .expect("groups")
            .len(),
        0
    );
    drop(s);
    groups
        .add_user_to_group(&ctx, &key(&t57(), "devs"), &key(&t57(), "alice"))
        .await
        .expect("the pair: a 5/7 membership");
}

/// Δ5 and Δ6: a boundary set at create passes the checks an attachment does,
/// and a policy of another tenant and an absent one answer the SAME refusal
/// — at create, at attach and at put_permissions_boundary — naming no tenant.
///
/// # Panics
///
/// When a foreign boundary is accepted at create, or the answers tell a
/// foreign policy from an absent one.
pub async fn a_foreign_policy_and_an_absent_one_are_one_refusal<S: EvaluatorStore>(
    store: Shared<S>,
) {
    let ctx = caller(&t57(), "seed");
    let theirs = PolicyService::new(store.clone())
        .create_policy(&caller(&t67(), "seed"), policy(&t67(), "theirs"))
        .await
        .expect("6/7's")
        .arn;
    let mine = PolicyService::new(store.clone())
        .create_policy(&ctx, policy(&t57(), "mine"))
        .await
        .expect("5/7's")
        .arn;
    let absent = "arn:aws:iam::conformance:policy/nowhere".to_string();
    let users = UserService::new(store.clone());
    let roles = RoleService::new(store.clone());
    let role = |key: ScopedName, boundary: &str| CreateRoleRequest {
        role: key,
        assume_role_policy_document: allow_get(),
        path: None,
        description: None,
        max_session_duration: None,
        permissions_boundary: Some(boundary.to_string()),
        tags: None,
    };

    let foreign = masked(
        users
            .create_user(&ctx, user(key(&t57(), "a"), Some(theirs.clone())))
            .await,
        &theirs,
    );
    let missing = masked(
        users
            .create_user(&ctx, user(key(&t57(), "b"), Some(absent.clone())))
            .await,
        &absent,
    );
    assert_eq!(
        foreign, missing,
        "create_user tells a foreign boundary from an absent one"
    );
    assert!(
        !foreign.contains("6/7"),
        "the refusal names the policy's tenant: {foreign}"
    );
    let foreign = masked(
        roles
            .create_role(&ctx, role(key(&t57(), "r1"), &theirs))
            .await,
        &theirs,
    );
    let missing = masked(
        roles
            .create_role(&ctx, role(key(&t57(), "r2"), &absent))
            .await,
        &absent,
    );
    assert_eq!(
        foreign, missing,
        "create_role tells a foreign boundary from an absent one"
    );

    users
        .create_user(&ctx, user(key(&t57(), "alice"), None))
        .await
        .expect("alice");
    let attach = AttachmentService::new(store.clone());
    let at = |arn: &str| AttachUserPolicyRequest {
        user: key(&t57(), "alice"),
        policy_arn: arn.to_string(),
    };
    assert_eq!(
        masked(attach.attach_user_policy(&ctx, at(&theirs)).await, &theirs),
        masked(attach.attach_user_policy(&ctx, at(&absent)).await, &absent),
        "attach tells a foreign policy from an absent one"
    );
    let boundary = PermissionsBoundaryService::new(store.clone(), INSTANCE.to_string());
    let put = |arn: &str| PutPermissionsBoundaryRequest {
        principal_type: PrincipalType::User,
        principal: key(&t57(), "alice"),
        permissions_boundary: arn.to_string(),
    };
    assert_eq!(
        masked(
            boundary.put_permissions_boundary(&ctx, put(&theirs)).await,
            &theirs
        ),
        masked(
            boundary.put_permissions_boundary(&ctx, put(&absent)).await,
            &absent
        ),
        "put_permissions_boundary tells a foreign policy from an absent one"
    );

    // The pair: the tenant's own policy, at create and at attach.
    users
        .create_user(&ctx, user(key(&t57(), "c"), Some(mine.clone())))
        .await
        .expect("a 5/7 boundary at create");
    roles
        .create_role(&ctx, role(key(&t57(), "r3"), &mine))
        .await
        .expect("a 5/7 boundary on a role");
    attach
        .attach_user_policy(&ctx, at(&mine))
        .await
        .expect("a 5/7 attachment");
}
