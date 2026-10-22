//! The key: a principal, a group or a role is stored under its
//! [`ScopedName`], never its bare name (S1, S3),
//! a policy ARN is never overwritten, and a freed name hands nothing to its
//! next holder.

use super::{caller, key, t57, t67, Shared};
use crate::service::{
    AccessKeyService, AttachmentService, GroupService, InlinePolicyService, PolicyService,
    RoleService, UserService,
};
use crate::store::traits::{AccessKeyStore, GroupStore, PolicyStore, RoleStore, UserStore};
use crate::wami::identity::group::requests::{CreateGroupRequest, UpdateGroupRequest};
use crate::wami::identity::role::requests::CreateRoleRequest;
use crate::wami::identity::user::requests::{CreateUserRequest, UpdateUserRequest};
use crate::wami::policies::attachment::requests::{
    AttachGroupPolicyRequest, AttachRolePolicyRequest, AttachUserPolicyRequest,
};
use crate::wami::policies::inline::requests::{
    PutGroupPolicyRequest, PutRolePolicyRequest, PutUserPolicyRequest,
};
use crate::wami::policies::policy::requests::CreatePolicyRequest;
use crate::CreateAccessKeyRequest;
use wami_core::arn::{ScopedName, TenantPath};
use wami_core::error::AmiError;

/// A document every reader accepts.
fn allow_all() -> String {
    r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"}]}"#
        .to_string()
}

fn user(key: ScopedName) -> CreateUserRequest {
    CreateUserRequest {
        user: key,
        path: None,
        permissions_boundary: None,
        tags: None,
    }
}

fn group(key: ScopedName) -> CreateGroupRequest {
    CreateGroupRequest {
        group: key,
        path: None,
        tags: None,
    }
}

fn role(key: ScopedName) -> CreateRoleRequest {
    CreateRoleRequest {
        role: key,
        assume_role_policy_document: allow_all(),
        path: None,
        description: None,
        max_session_duration: None,
        permissions_boundary: None,
        tags: None,
    }
}

fn policy(tenant: &TenantPath, name: &str, document: String) -> CreatePolicyRequest {
    CreatePolicyRequest {
        tenant: tenant.clone(),
        policy_name: name.to_string(),
        policy_document: document,
        path: None,
        description: None,
        tags: None,
    }
}

/// S1 (users): two tenants each hold an `alice`; reading one never returns
/// the other's.
///
/// # Panics
///
/// When the store hands one tenant's `alice` to the other.
pub async fn two_tenants_each_hold_a_user_of_one_name<S: UserStore + 'static>(store: Shared<S>) {
    let users = UserService::new(store);
    let a5 = users
        .create_user(&caller(&t57(), "x"), user(key(&t57(), "alice")))
        .await
        .expect("5/7's alice");
    let a6 = users
        .create_user(&caller(&t67(), "x"), user(key(&t67(), "alice")))
        .await
        .expect("6/7's alice: a second tenant may hold the same name");
    assert_ne!(a5.user_id, a6.user_id, "arrange: two distinct records");

    for (tenant, id) in [(t57(), &a5.user_id), (t67(), &a6.user_id)] {
        let got = users
            .get_user(&caller(&tenant, "x"), &key(&tenant, "alice"))
            .await
            .expect("a read")
            .expect("each tenant's alice is there");
        assert_eq!(
            &got.user_id, id,
            "reading {tenant}'s alice returned {}",
            got.wami_arn
        );
        assert_eq!(got.wami_arn.tenant_path, tenant);
    }
}

/// S1 (groups).
///
/// # Panics
///
/// When the store hands one tenant's group to the other.
pub async fn two_tenants_each_hold_a_group_of_one_name<S: GroupStore + 'static>(store: Shared<S>) {
    let groups = GroupService::new(store);
    let g5 = groups
        .create_group(&caller(&t57(), "x"), group(key(&t57(), "admins")))
        .await
        .expect("5/7's admins");
    let g6 = groups
        .create_group(&caller(&t67(), "x"), group(key(&t67(), "admins")))
        .await
        .expect("6/7's admins");
    assert_ne!(g5.group_id, g6.group_id, "arrange: two distinct records");

    for (tenant, id) in [(t57(), &g5.group_id), (t67(), &g6.group_id)] {
        let got = groups
            .get_group(&caller(&tenant, "x"), &key(&tenant, "admins"))
            .await
            .expect("a read")
            .expect("each tenant's group is there");
        assert_eq!(
            &got.group_id, id,
            "reading {tenant}'s group returned {}",
            got.wami_arn
        );
    }
}

/// S1 (roles).
///
/// # Panics
///
/// When the store hands one tenant's role to the other.
pub async fn two_tenants_each_hold_a_role_of_one_name<S: RoleStore + 'static>(store: Shared<S>) {
    let roles = RoleService::new(store);
    let r5 = roles
        .create_role(&caller(&t57(), "x"), role(key(&t57(), "admin")))
        .await
        .expect("5/7's admin");
    let r6 = roles
        .create_role(&caller(&t67(), "x"), role(key(&t67(), "admin")))
        .await
        .expect("6/7's admin");
    assert_ne!(r5.role_id, r6.role_id, "arrange: two distinct records");

    for (tenant, id) in [(t57(), &r5.role_id), (t67(), &r6.role_id)] {
        let got = roles
            .get_role(&caller(&tenant, "x"), &key(&tenant, "admin"))
            .await
            .expect("a read")
            .expect("each tenant's role is there");
        assert_eq!(
            &got.role_id, id,
            "reading {tenant}'s role returned {}",
            got.wami_arn
        );
    }
}

/// S3 (users): a create on a held key is refused, and the first record is
/// unchanged.
///
/// # Panics
///
/// When the second create succeeds or rewrites the first record.
pub async fn a_create_on_a_held_user_key_is_refused<S: UserStore + 'static>(store: Shared<S>) {
    let users = UserService::new(store);
    let ctx = caller(&t57(), "x");
    let first = users
        .create_user(&ctx, user(key(&t57(), "alice")))
        .await
        .expect("the first alice");
    let mut again = user(key(&t57(), "alice"));
    again.path = Some("/rewritten/".to_string());
    let second = users.create_user(&ctx, again).await;
    assert!(
        matches!(second, Err(AmiError::ResourceExists { .. })),
        "second create in the same tenant → {second:?}"
    );
    let now = users
        .get_user(&ctx, &key(&t57(), "alice"))
        .await
        .expect("a read")
        .expect("alice");
    assert_eq!(now.user_id, first.user_id);
    assert_eq!(now.path, first.path);
}

/// S3 (groups).
///
/// # Panics
///
/// When the second create succeeds or rewrites the first record.
pub async fn a_create_on_a_held_group_key_is_refused<S: GroupStore + 'static>(store: Shared<S>) {
    let groups = GroupService::new(store);
    let ctx = caller(&t57(), "x");
    let first = groups
        .create_group(&ctx, group(key(&t57(), "admins")))
        .await
        .expect("the first group");
    let second = groups
        .create_group(&ctx, group(key(&t57(), "admins")))
        .await;
    assert!(
        matches!(second, Err(AmiError::ResourceExists { .. })),
        "duplicate group → {second:?}"
    );
    let now = groups
        .get_group(&ctx, &key(&t57(), "admins"))
        .await
        .expect("a read")
        .expect("the group");
    assert_eq!(now.group_id, first.group_id);
}

/// S3 (roles).
///
/// # Panics
///
/// When the second create succeeds or rewrites the first record.
pub async fn a_create_on_a_held_role_key_is_refused<S: RoleStore + 'static>(store: Shared<S>) {
    let roles = RoleService::new(store);
    let ctx = caller(&t57(), "x");
    let first = roles
        .create_role(&ctx, role(key(&t57(), "admin")))
        .await
        .expect("the first role");
    let second = roles.create_role(&ctx, role(key(&t57(), "admin"))).await;
    assert!(
        matches!(second, Err(AmiError::ResourceExists { .. })),
        "duplicate role → {second:?}"
    );
    let now = roles
        .get_role(&ctx, &key(&t57(), "admin"))
        .await
        .expect("a read")
        .expect("the role");
    assert_eq!(now.role_id, first.role_id);
}

/// A policy ARN names no tenant (wami 011), so two tenants' same-named
/// policies share one: the second create is refused, and the first document
/// is unchanged — never rewritten under the first tenant's attachments.
///
/// # Panics
///
/// When the second create succeeds or rewrites the first policy.
pub async fn a_create_on_a_held_policy_arn_is_refused<S: PolicyStore + 'static>(store: Shared<S>) {
    let policies = PolicyService::new(store);
    let narrow = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser","Resource":"*"}]}"#;
    let first = policies
        .create_policy(
            &caller(&t57(), "x"),
            policy(&t57(), "ops", narrow.to_string()),
        )
        .await
        .expect("5/7's ops");
    let second = policies
        .create_policy(&caller(&t67(), "x"), policy(&t67(), "ops", allow_all()))
        .await;
    assert!(
        matches!(second, Err(AmiError::ResourceExists { .. })),
        "6/7's ops over 5/7's → {second:?}"
    );
    let now = policies
        .get_policy(&caller(&t57(), "x"), &first.arn)
        .await
        .expect("a read")
        .expect("5/7's ops");
    assert_eq!(now.policy_id, first.policy_id);
    assert_eq!(now.policy_document, narrow);
    assert_eq!(now.wami_arn.tenant_path, t57());
}

/// The store traits the freed-name checks traverse.
pub trait FreedNameStore:
    UserStore + GroupStore + RoleStore + PolicyStore + AccessKeyStore + 'static
{
}
impl<T> FreedNameStore for T where
    T: UserStore + GroupStore + RoleStore + PolicyStore + AccessKeyStore + 'static
{
}

/// Give `holder` (a user of 5/7) an inline policy, an attached policy, a
/// membership and an access key; returns the attached policy's ARN.
async fn endow<S: FreedNameStore>(store: &Shared<S>, holder: &ScopedName) -> String {
    let ctx = caller(&t57(), "x");
    let admins = key(&t57(), "admins");
    if GroupService::new(store.clone())
        .get_group(&ctx, &admins)
        .await
        .expect("a read")
        .is_none()
    {
        GroupService::new(store.clone())
            .create_group(&ctx, group(admins.clone()))
            .await
            .expect("the group");
    }
    let ops = match PolicyService::new(store.clone())
        .create_policy(&ctx, policy(&t57(), "ops", allow_all()))
        .await
    {
        Ok(p) => p.arn,
        Err(AmiError::ResourceExists { .. }) => {
            format!("arn:aws:iam::{}:policy/ops", super::INSTANCE)
        }
        Err(e) => panic!("the managed policy: {e:?}"),
    };
    InlinePolicyService::new(store.clone())
        .put_user_policy(
            &ctx,
            PutUserPolicyRequest {
                user: holder.clone(),
                policy_name: "p".to_string(),
                policy_document: allow_all(),
            },
        )
        .await
        .expect("an inline policy");
    AttachmentService::new(store.clone())
        .attach_user_policy(
            &ctx,
            AttachUserPolicyRequest {
                user: holder.clone(),
                policy_arn: ops.clone(),
            },
        )
        .await
        .expect("an attachment");
    GroupService::new(store.clone())
        .add_user_to_group(&ctx, &admins, holder)
        .await
        .expect("a membership");
    AccessKeyService::new(store.clone())
        .create_access_key(
            &ctx,
            CreateAccessKeyRequest {
                user: holder.clone(),
            },
        )
        .await
        .expect("an access key");
    ops
}

/// Everything `holder` holds: inline names, attached ARNs, group names, and
/// how many access keys.
async fn holdings<S: FreedNameStore>(
    store: &Shared<S>,
    holder: &ScopedName,
) -> (Vec<String>, Vec<String>, Vec<String>, usize) {
    let s = store.read().await;
    let inline = s.list_user_policies(holder).await.expect("inline");
    let attached = s
        .list_attached_user_policies(holder)
        .await
        .expect("attached");
    let groups = s
        .list_groups_for_user(holder)
        .await
        .expect("groups")
        .into_iter()
        .map(|g| g.group_name)
        .collect();
    let keys = s
        .list_access_keys(holder, None)
        .await
        .expect("keys")
        .0
        .len();
    (inline, attached, groups, keys)
}

/// A deleted user's name hands nothing to its next holder: no policy, no
/// membership, no credential (wami 005, freed names).
///
/// # Panics
///
/// When the new holder inherits anything of the deleted user.
pub async fn a_deleted_users_name_hands_nothing_to_its_next_holder<S: FreedNameStore>(
    store: Shared<S>,
) {
    let users = UserService::new(store.clone());
    let ctx = caller(&t57(), "x");
    let alice = key(&t57(), "alice");
    let first = users
        .create_user(&ctx, user(alice.clone()))
        .await
        .expect("alice");
    endow(&store, &alice).await;
    let before = holdings(&store, &alice).await;
    assert_eq!(
        (before.0.len(), before.1.len(), before.2.len(), before.3),
        (1, 1, 1, 1),
        "arrange: alice holds one of each: {before:?}"
    );

    users.delete_user(&ctx, &alice).await.expect("the delete");
    let next = users
        .create_user(&ctx, user(alice.clone()))
        .await
        .expect("the next alice");
    assert_ne!(next.user_id, first.user_id, "arrange: a new record");

    let inherited = holdings(&store, &alice).await;
    assert_eq!(
        inherited,
        (vec![], vec![], vec![], 0),
        "the new alice inherits the deleted alice's {inherited:?}"
    );
}

/// A renamed user carries its policies, memberships and credentials to its
/// new name, and leaves nothing on the old one for its next holder.
///
/// # Panics
///
/// When anything stays behind on the old name, or is lost on the way.
pub async fn a_renamed_user_carries_everything_and_leaves_nothing_behind<S: FreedNameStore>(
    store: Shared<S>,
) {
    let users = UserService::new(store.clone());
    let ctx = caller(&t57(), "x");
    let alice = key(&t57(), "alice");
    let alicia = alice.renamed("alicia");
    let first = users
        .create_user(&ctx, user(alice.clone()))
        .await
        .expect("alice");
    let ops = endow(&store, &alice).await;

    let renamed = users
        .update_user(
            &ctx,
            UpdateUserRequest {
                user: alice.clone(),
                new_user_name: Some("alicia".to_string()),
                new_path: None,
            },
        )
        .await
        .expect("the rename");
    assert_eq!(
        renamed.user_id, first.user_id,
        "a rename keeps the stable id"
    );

    let carried = holdings(&store, &alicia).await;
    assert_eq!(
        carried,
        (
            vec!["p".to_string()],
            vec![ops],
            vec!["admins".to_string()],
            1
        ),
        "alicia lost what alice held"
    );
    let keys = store
        .read()
        .await
        .list_access_keys(&alicia, None)
        .await
        .expect("keys")
        .0;
    assert_eq!(keys[0].owner, alicia, "the key's owner follows the rename");

    users
        .create_user(&ctx, user(alice.clone()))
        .await
        .expect("the next alice");
    let left = holdings(&store, &alice).await;
    assert_eq!(
        left,
        (vec![], vec![], vec![], 0),
        "the new alice holds {left:?}"
    );
}

/// A freed group or role name hands nothing to its next holder: a deleted
/// group's members and policies, a renamed group's, a deleted role's policies.
///
/// # Panics
///
/// When a new group or role inherits anything of the one that held the name.
pub async fn a_freed_group_or_role_name_hands_nothing_to_its_next_holder<S: FreedNameStore>(
    store: Shared<S>,
) {
    let ctx = caller(&t57(), "x");
    let groups = GroupService::new(store.clone());
    let roles = RoleService::new(store.clone());
    let inline = InlinePolicyService::new(store.clone());
    let attach = AttachmentService::new(store.clone());
    let ops = PolicyService::new(store.clone())
        .create_policy(&ctx, policy(&t57(), "ops", allow_all()))
        .await
        .expect("ops")
        .arn;
    let bob = key(&t57(), "bob");
    UserService::new(store.clone())
        .create_user(&ctx, user(bob.clone()))
        .await
        .expect("bob");

    // A group endowed, then renamed: the old name is free, and empty.
    let devs = key(&t57(), "devs");
    groups
        .create_group(&ctx, group(devs.clone()))
        .await
        .expect("devs");
    groups
        .add_user_to_group(&ctx, &devs, &bob)
        .await
        .expect("a member");
    inline
        .put_group_policy(
            &ctx,
            PutGroupPolicyRequest {
                group: devs.clone(),
                policy_name: "p".into(),
                policy_document: allow_all(),
            },
        )
        .await
        .expect("an inline group policy");
    attach
        .attach_group_policy(
            &ctx,
            AttachGroupPolicyRequest {
                group: devs.clone(),
                policy_arn: ops.clone(),
            },
        )
        .await
        .expect("a group attachment");
    groups
        .update_group(
            &ctx,
            UpdateGroupRequest {
                group: devs.clone(),
                new_group_name: Some("builders".into()),
                new_path: None,
            },
        )
        .await
        .expect("the rename");
    groups
        .create_group(&ctx, group(devs.clone()))
        .await
        .expect("the next devs");
    {
        let s = store.read().await;
        let member_of: Vec<String> = s
            .list_groups_for_user(&bob)
            .await
            .expect("groups")
            .into_iter()
            .map(|g| g.group_name)
            .collect();
        assert_eq!(
            member_of,
            vec!["builders".to_string()],
            "bob's membership follows the rename"
        );
        assert_eq!(
            s.list_group_policies(&devs).await.expect("inline").len(),
            0,
            "the new devs inherits an inline policy"
        );
        assert_eq!(
            s.list_attached_group_policies(&devs)
                .await
                .expect("attached")
                .len(),
            0,
            "the new devs inherits an attachment"
        );
        let builders = devs.renamed("builders");
        assert_eq!(
            s.list_group_policies(&builders).await.expect("inline"),
            vec!["p".to_string()]
        );
        assert_eq!(
            s.list_attached_group_policies(&builders)
                .await
                .expect("attached"),
            vec![ops.clone()]
        );
    }

    // A group deleted: its members are no longer members of the next holder.
    groups
        .delete_group(&ctx, &devs.renamed("builders"))
        .await
        .expect("the delete");
    groups
        .create_group(&ctx, group(devs.renamed("builders")))
        .await
        .expect("the next builders");
    let member_of = store
        .read()
        .await
        .list_groups_for_user(&bob)
        .await
        .expect("groups");
    assert_eq!(
        member_of.len(),
        0,
        "bob is a member of the next builders: {member_of:?}"
    );

    // A role deleted: its policies do not pass to the next role of the name.
    let admin = key(&t57(), "admin");
    roles
        .create_role(&ctx, role(admin.clone()))
        .await
        .expect("admin");
    inline
        .put_role_policy(
            &ctx,
            PutRolePolicyRequest {
                role: admin.clone(),
                policy_name: "p".into(),
                policy_document: allow_all(),
            },
        )
        .await
        .expect("an inline role policy");
    attach
        .attach_role_policy(
            &ctx,
            AttachRolePolicyRequest {
                role: admin.clone(),
                policy_arn: ops.clone(),
            },
        )
        .await
        .expect("a role attachment");
    roles.delete_role(&ctx, &admin).await.expect("the delete");
    roles
        .create_role(&ctx, role(admin.clone()))
        .await
        .expect("the next admin");
    let s = store.read().await;
    assert_eq!(
        s.list_role_policies(&admin).await.expect("inline").len(),
        0,
        "the next admin inherits an inline policy"
    );
    assert_eq!(
        s.list_attached_role_policies(&admin)
            .await
            .expect("attached")
            .len(),
        0,
        "the next admin inherits an attachment"
    );
}
