//! Tenant scope: a list returns exactly the tenant it names, a principal's
//! policies are never found for another tenant's principal of the same
//! name, and a policy never crosses into another tenant (S6, S10, S13).

use super::guard::GuardStore;
use super::{caller, key, t57, t67, Shared, INSTANCE};
use crate::credentials::server_certificate::requests::{
    ListServerCertificatesRequest, UploadServerCertificateRequest,
};
use crate::service::auth::authorizer::into_authorizer;
use crate::service::sts::identity::GetCallerIdentityRequest;
use crate::service::{
    AttachmentService, AuthorizationService, EvaluationService, GroupService, IdentityService,
    PermissionsBoundaryService, PolicyService, RoleService, ServerCertificateService, UserService,
};
use crate::store::traits::IdentityStore;
use crate::wami::identity::group::requests::{CreateGroupRequest, ListGroupsRequest};
use crate::wami::identity::role::requests::{CreateRoleRequest, ListRolesRequest};
use crate::wami::identity::user::requests::{CreateUserRequest, ListUsersRequest};
use crate::wami::policies::attachment::requests::{
    AttachGroupPolicyRequest, AttachRolePolicyRequest, AttachUserPolicyRequest,
};
use crate::wami::policies::evaluation::SimulatePrincipalPolicyRequest;
use crate::wami::policies::permissions_boundary::{PrincipalType, PutPermissionsBoundaryRequest};
use crate::wami::policies::policy::requests::{CreatePolicyRequest, ListPoliciesRequest};
use wami_core::arn::{ScopedName, TenantPath, WamiArn};
use wami_core::error::AmiError;

fn document(action: &str, effect: &str) -> String {
    format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"{effect}","Action":"{action}","Resource":"*"}}]}}"#
    )
}

fn policy(tenant: &TenantPath, name: &str, doc: String) -> CreatePolicyRequest {
    CreatePolicyRequest {
        tenant: tenant.clone(),
        policy_name: name.to_string(),
        policy_document: doc,
        path: None,
        description: None,
        tags: None,
    }
}

fn user(key: ScopedName) -> CreateUserRequest {
    CreateUserRequest {
        user: key,
        path: None,
        permissions_boundary: None,
        tags: None,
    }
}

fn role(key: ScopedName) -> CreateRoleRequest {
    CreateRoleRequest {
        role: key,
        assume_role_policy_document: document("sts:AssumeRole", "Allow"),
        path: None,
        description: None,
        max_session_duration: None,
        permissions_boundary: None,
        tags: None,
    }
}

/// S10: a list in 5/7 returns 5/7's records only, and a list in 6/7 returns
/// 6/7's — both non-empty — for users, groups, roles, policies and server
/// certificates.
///
/// # Panics
///
/// When a list returns another tenant's record, or misses its own.
pub async fn a_list_returns_exactly_the_tenant_it_names<S: GuardStore>(store: Shared<S>) {
    for (tenant, mine) in [(t57(), "five"), (t67(), "six")] {
        let ctx = caller(&tenant, "seed");
        UserService::new(store.clone())
            .create_user(&ctx, user(key(&tenant, mine)))
            .await
            .expect("a user");
        GroupService::new(store.clone())
            .create_group(
                &ctx,
                CreateGroupRequest {
                    group: key(&tenant, mine),
                    path: None,
                    tags: None,
                },
            )
            .await
            .expect("a group");
        RoleService::new(store.clone())
            .create_role(&ctx, role(key(&tenant, mine)))
            .await
            .expect("a role");
        PolicyService::new(store.clone())
            .create_policy(
                &ctx,
                policy(&tenant, mine, document("iam:GetUser", "Allow")),
            )
            .await
            .expect("a policy");
        ServerCertificateService::new(store.clone())
            .upload_server_certificate(
                &ctx,
                UploadServerCertificateRequest {
                    server_certificate: key(&tenant, mine),
                    certificate_body:
                        "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----".into(),
                    private_key:
                        "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----"
                            .into(),
                    certificate_chain: None,
                    path: None,
                    tags: None,
                },
            )
            .await
            .expect("a certificate");
    }
    for (tenant, mine) in [(t57(), "five"), (t67(), "six")] {
        let ctx = caller(&tenant, "seed");
        let users: Vec<String> = UserService::new(store.clone())
            .list_users(
                &ctx,
                ListUsersRequest {
                    tenant: tenant.clone(),
                    path_prefix: None,
                    pagination: None,
                },
            )
            .await
            .expect("users")
            .0
            .into_iter()
            .map(|u| u.user_name)
            .collect();
        assert_eq!(users, vec![mine.to_string()], "{tenant}'s users");
        let groups: Vec<String> = GroupService::new(store.clone())
            .list_groups(
                &ctx,
                ListGroupsRequest {
                    tenant: tenant.clone(),
                    path_prefix: None,
                    pagination: None,
                },
            )
            .await
            .expect("groups")
            .0
            .into_iter()
            .map(|g| g.group_name)
            .collect();
        assert_eq!(groups, vec![mine.to_string()], "{tenant}'s groups");
        let roles: Vec<String> = RoleService::new(store.clone())
            .list_roles(
                &ctx,
                ListRolesRequest {
                    tenant: tenant.clone(),
                    path_prefix: None,
                    pagination: None,
                },
            )
            .await
            .expect("roles")
            .0
            .into_iter()
            .map(|r| r.role_name)
            .collect();
        assert_eq!(roles, vec![mine.to_string()], "{tenant}'s roles");
        let policies: Vec<String> = PolicyService::new(store.clone())
            .list_policies(
                &ctx,
                ListPoliciesRequest {
                    tenant: tenant.clone(),
                    scope: None,
                    only_attached: None,
                    path_prefix: None,
                    pagination: None,
                },
            )
            .await
            .expect("policies")
            .0
            .into_iter()
            .map(|p| p.policy_name)
            .collect();
        assert_eq!(policies, vec![mine.to_string()], "{tenant}'s policies");
        let certs: Vec<String> = ServerCertificateService::new(store.clone())
            .list_server_certificates(
                &ctx,
                ListServerCertificatesRequest {
                    tenant: tenant.clone(),
                    path_prefix: None,
                    marker: None,
                    max_items: None,
                },
            )
            .await
            .expect("certificates")
            .0
            .into_iter()
            .map(|c| c.server_certificate_name)
            .collect();
        assert_eq!(certs, vec![mine.to_string()], "{tenant}'s certificates");
    }

    // A list is judged on the tenant it names: 5/7's admin, granted
    // everything of 5/7, is refused 6/7's list.
    let admin = super::guard::admin57_everything(&store).await;
    let users = UserService::with_authorizer(
        store.clone(),
        into_authorizer(AuthorizationService::new(store.clone())),
    );
    let got = users
        .list_users(
            &admin,
            ListUsersRequest {
                tenant: t67(),
                path_prefix: None,
                pagination: None,
            },
        )
        .await;
    assert!(
        matches!(got, Err(AmiError::AccessDenied { .. })),
        "5/7 lists 6/7's users → {got:?}"
    );
    users
        .list_users(
            &admin,
            ListUsersRequest {
                tenant: t57(),
                path_prefix: None,
                pagination: None,
            },
        )
        .await
        .expect("5/7 lists its own users");
}

/// S6: the policies of 5/7's `admin` — inline, and through its group — are
/// never found for 6/7's `admin`: the same action is allowed to the one and
/// refused to the other.
///
/// # Panics
///
/// When a principal is judged on another tenant's same-named principal's
/// policies.
pub async fn a_principals_policies_are_never_found_for_another_tenants_namesake<S: GuardStore>(
    store: Shared<S>,
) {
    let authz = AuthorizationService::new(store.clone());
    let target: WamiArn = format!("arn:wami:iam:{}:wami:{INSTANCE}:user/anyone", t57())
        .parse()
        .expect("an ARN");
    {
        let mut s = store.write().await;
        for tenant in [t57(), t67()] {
            let ctx = caller(&tenant, "admin");
            let u = crate::wami::identity::user::builder::build_user(
                &key(&tenant, "admin"),
                None,
                &ctx,
            )
            .expect("a user");
            s.create_user(u).await.expect("an admin");
            let g = crate::wami::identity::group::builder::build_group(
                &key(&tenant, "admins"),
                None,
                &ctx,
            )
            .expect("a group");
            s.create_group(g).await.expect("a group");
            s.add_user_to_group(&key(&tenant, "admins"), &key(&tenant, "admin"))
                .await
                .expect("a membership");
        }
        // Only 5/7's admin holds anything: inline on the user, and on its group.
        s.put_user_policy(
            &key(&t57(), "admin"),
            "inline",
            document("iam:GetUser", "Allow"),
        )
        .await
        .expect("inline");
        s.put_group_policy(
            &key(&t57(), "admins"),
            "group",
            document("iam:ListUsers", "Allow"),
        )
        .await
        .expect("group");
    }
    let signed_in = |user: Option<crate::wami::identity::User>| {
        super::guard::signed_in(&user.expect("an admin"))
    };
    let ctx57 = signed_in(
        store
            .read()
            .await
            .get_user(&key(&t57(), "admin"))
            .await
            .expect("a read"),
    );
    let ctx67 = signed_in(
        store
            .read()
            .await
            .get_user(&key(&t67(), "admin"))
            .await
            .expect("a read"),
    );
    for action in ["iam:GetUser", "iam:ListUsers"] {
        let five = authz
            .authorize(&ctx57, action, &target)
            .await
            .expect("a decision");
        assert!(
            five.is_allowed(),
            "arrange: 5/7's admin holds {action}: {five:?}"
        );
        let six = authz
            .authorize(&ctx67, action, &target)
            .await
            .expect("a decision");
        assert!(
            !six.is_allowed(),
            "6/7's admin was judged on 5/7's admin's policies for {action}: {six:?}"
        );
    }
}

/// A policy never crosses into another tenant: a 6/7 managed policy is
/// refused as an attachment or a permissions boundary on a 5/7 user, group
/// or role, and a 5/7 policy attaches (A7).
///
/// # Panics
///
/// When a policy of one tenant is attached to a principal of another.
pub async fn a_policy_never_crosses_into_another_tenant<S: GuardStore>(store: Shared<S>) {
    let ctx = caller(&t57(), "seed");
    let theirs = PolicyService::new(store.clone())
        .create_policy(
            &caller(&t67(), "seed"),
            policy(&t67(), "theirs", document("iam:*", "Allow")),
        )
        .await
        .expect("6/7's policy")
        .arn;
    let mine = PolicyService::new(store.clone())
        .create_policy(&ctx, policy(&t57(), "mine", document("iam:*", "Allow")))
        .await
        .expect("5/7's policy")
        .arn;
    UserService::new(store.clone())
        .create_user(&ctx, user(key(&t57(), "alice")))
        .await
        .expect("alice");
    GroupService::new(store.clone())
        .create_group(
            &ctx,
            CreateGroupRequest {
                group: key(&t57(), "devs"),
                path: None,
                tags: None,
            },
        )
        .await
        .expect("devs");
    RoleService::new(store.clone())
        .create_role(&ctx, role(key(&t57(), "ops")))
        .await
        .expect("ops");
    let attach = AttachmentService::new(store.clone());

    let got = attach
        .attach_user_policy(
            &ctx,
            AttachUserPolicyRequest {
                user: key(&t57(), "alice"),
                policy_arn: theirs.clone(),
            },
        )
        .await;
    assert!(
        matches!(got, Err(AmiError::InvalidParameter { .. })),
        "6/7's policy on 5/7's user → {got:?}"
    );
    let got = attach
        .attach_group_policy(
            &ctx,
            AttachGroupPolicyRequest {
                group: key(&t57(), "devs"),
                policy_arn: theirs.clone(),
            },
        )
        .await;
    assert!(
        matches!(got, Err(AmiError::InvalidParameter { .. })),
        "6/7's policy on 5/7's group → {got:?}"
    );
    let got = attach
        .attach_role_policy(
            &ctx,
            AttachRolePolicyRequest {
                role: key(&t57(), "ops"),
                policy_arn: theirs.clone(),
            },
        )
        .await;
    assert!(
        matches!(got, Err(AmiError::InvalidParameter { .. })),
        "6/7's policy on 5/7's role → {got:?}"
    );
    let boundary = PermissionsBoundaryService::new(store.clone(), INSTANCE.to_string());
    let got = boundary
        .put_permissions_boundary(
            &ctx,
            PutPermissionsBoundaryRequest {
                principal_type: PrincipalType::User,
                principal: key(&t57(), "alice"),
                permissions_boundary: theirs.clone(),
            },
        )
        .await;
    assert!(
        matches!(got, Err(AmiError::InvalidParameter { .. })),
        "6/7's policy as 5/7's boundary → {got:?}"
    );
    let s = store.read().await;
    assert_eq!(
        s.list_attached_user_policies(&key(&t57(), "alice"))
            .await
            .expect("attached")
            .len(),
        0
    );
    drop(s);

    // The pair: 5/7's own policy attaches.
    attach
        .attach_user_policy(
            &ctx,
            AttachUserPolicyRequest {
                user: key(&t57(), "alice"),
                policy_arn: mine.clone(),
            },
        )
        .await
        .expect("5/7's policy on 5/7's user");
    boundary
        .put_permissions_boundary(
            &ctx,
            PutPermissionsBoundaryRequest {
                principal_type: PrincipalType::User,
                principal: key(&t57(), "alice"),
                permissions_boundary: mine,
            },
        )
        .await
        .expect("5/7's policy as 5/7's boundary");
}

/// S13 (simulation, caller identity): a simulation of 6/7's `admin` reads
/// 6/7's record, never 5/7's namesake's boundary; `get_caller_identity` of
/// 5/7's `alice` answers 5/7's alice.
///
/// # Panics
///
/// When either reads another tenant's same-named principal.
pub async fn simulation_and_caller_identity_read_the_named_tenant<S>(store: Shared<S>)
where
    S: GuardStore + IdentityStore,
{
    let deny_all = PolicyService::new(store.clone())
        .create_policy(
            &caller(&t57(), "seed"),
            policy(&t57(), "nothing", document("s3:GetObject", "Allow")),
        )
        .await
        .expect("a boundary allowing nothing of iam")
        .arn;
    for tenant in [t57(), t67()] {
        let mut req = user(key(&tenant, "admin"));
        if tenant == t57() {
            req.permissions_boundary = Some(deny_all.clone());
        }
        UserService::new(store.clone())
            .create_user(&caller(&tenant, "seed"), req)
            .await
            .expect("an admin");
    }
    let sim = EvaluationService::new(store.clone(), INSTANCE.to_string());
    let simulate = |tenant: TenantPath| SimulatePrincipalPolicyRequest {
        principal_type: PrincipalType::User,
        principal: key(&tenant, "admin"),
        action_names: vec!["iam:GetUser".to_string()],
        resource_arns: None,
        policy_input_list: Some(vec![document("iam:*", "Allow")]),
        context_entries: None,
    };
    let five = sim
        .simulate_principal_policy(simulate(t57()))
        .await
        .expect("5/7's simulation");
    assert_ne!(
        five.evaluation_results[0].eval_decision, "allowed",
        "arrange: 5/7's boundary bounds 5/7's admin"
    );
    let six = sim
        .simulate_principal_policy(simulate(t67()))
        .await
        .expect("6/7's simulation");
    assert_eq!(
        six.evaluation_results[0].eval_decision, "allowed",
        "6/7's admin was simulated under 5/7's boundary"
    );

    UserService::new(store.clone())
        .create_user(&caller(&t57(), "seed"), user(key(&t57(), "alice")))
        .await
        .expect("5/7's alice");
    let six_alice = UserService::new(store.clone())
        .create_user(&caller(&t67(), "seed"), user(key(&t67(), "alice")))
        .await
        .expect("6/7's alice");
    let me = IdentityService::new(store.clone(), INSTANCE.to_string())
        .get_caller_identity(GetCallerIdentityRequest {}, &key(&t57(), "alice"))
        .await
        .expect("5/7's alice's identity");
    assert_ne!(
        me.user_id, six_alice.user_id,
        "5/7's alice was answered with 6/7's"
    );
}
