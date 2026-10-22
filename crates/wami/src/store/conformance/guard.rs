//! The guard judges the TARGET: the ARN it decides on is rendered from the
//! requested key — the target's tenant, never the caller's — before anything
//! is read, so the refusal is the same whether the target exists or not
//! (S2, S11, S12, S13).

use super::{caller, key, t57, t67, Shared, INSTANCE};
use crate::credentials::login_profile::requests::CreateLoginProfileRequest;
use crate::credentials::mfa_device::requests::EnableMfaDeviceRequest;
use crate::credentials::server_certificate::requests::UploadServerCertificateRequest;
use crate::credentials::service_credential::requests::CreateServiceSpecificCredentialRequest;
use crate::credentials::signing_certificate::requests::UploadSigningCertificateRequest;
use crate::service::auth::authorizer::{into_authorizer, Authorizer};
use crate::service::{
    AccessKeyService, AuthorizationService, GroupService, LoginProfileService, MfaDeviceService,
    PermissionsBoundaryService, RoleService, ServerCertificateService, ServiceCredentialService,
    ServiceLinkedRoleService, SigningCertificateService, UserService,
};
use crate::store::traits::{
    AccessKeyStore, GroupStore, LoginProfileStore, MfaDeviceStore, PolicyStore, RoleStore,
    ServerCertificateStore, ServiceCredentialStore, ServiceLinkedRoleStore,
    SigningCertificateStore, UserStore,
};
use crate::wami::identity::group::requests::CreateGroupRequest;
use crate::wami::identity::role::requests::CreateRoleRequest;
use crate::wami::identity::root_user::ROOT_USER_NAME;
use crate::wami::identity::user::builder::build_user;
use crate::wami::identity::user::requests::{CreateUserRequest, UpdateUserRequest};
use crate::wami::policies::permissions_boundary::{PrincipalType, PutPermissionsBoundaryRequest};
use crate::{CreateAccessKeyRequest, InstanceBootstrap};
use std::fmt::Debug;
use std::sync::Arc;
use wami_core::arn::{ScopedName, TenantPath, WamiArn};
use wami_core::context::WamiContext;
use wami_core::error::{AmiError, Result};

/// The store traits the guard checks traverse.
pub trait GuardStore:
    UserStore
    + GroupStore
    + RoleStore
    + PolicyStore
    + AccessKeyStore
    + LoginProfileStore
    + MfaDeviceStore
    + ServiceCredentialStore
    + SigningCertificateStore
    + ServerCertificateStore
    + 'static
{
}
impl<T> GuardStore for T where
    T: UserStore
        + GroupStore
        + RoleStore
        + PolicyStore
        + AccessKeyStore
        + LoginProfileStore
        + MfaDeviceStore
        + ServiceCredentialStore
        + SigningCertificateStore
        + ServerCertificateStore
        + 'static
{
}

fn allow(resources: &[String]) -> String {
    let list: Vec<String> = resources.iter().map(|r| format!("\"{r}\"")).collect();
    format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":"iam:*","Resource":[{}]}}]}}"#,
        list.join(",")
    )
}

/// `kind/*` in `tenant`, as a policy writes it.
fn every(tenant: &TenantPath, kind: &str) -> String {
    format!("arn:wami:iam:{tenant}:wami:{INSTANCE}:{kind}/*")
}

/// The guarded ARN of `name` of `kind` in `tenant`.
fn target(tenant: &TenantPath, kind: &str, name: &str) -> String {
    format!("arn:wami:iam:{tenant}:wami:{INSTANCE}:{kind}/{name}")
}

/// Store `name` in `tenant` with an inline policy allowing `iam:*` on
/// `resources`, written straight into the store (no guard), and return its
/// context.
async fn principal<S: GuardStore>(
    store: &Shared<S>,
    tenant: &TenantPath,
    name: &str,
    resources: &[String],
) -> WamiContext {
    let mut s = store.write().await;
    let user = build_user(&key(tenant, name), None, &caller(tenant, name)).expect("a user");
    s.create_user(user.clone())
        .await
        .expect("the caller's record");
    s.put_user_policy(&key(tenant, name), "grant", allow(resources))
        .await
        .expect("the caller's grant");
    signed_in(&user)
}

/// The context authentication builds from `user`'s record: its ARN and its
/// key, read off the same record.
pub(crate) fn signed_in(user: &crate::wami::identity::User) -> WamiContext {
    WamiContext::builder()
        .caller_arn(user.wami_arn.clone())
        .caller_key(user.key())
        .build()
        .expect("a signed-in context")
}

/// Create `name` in `tenant` with no guard.
async fn plain_user<S: GuardStore>(store: &Shared<S>, tenant: &TenantPath, name: &str) {
    UserService::new(store.clone())
        .create_user(
            &caller(tenant, "seed"),
            CreateUserRequest {
                user: key(tenant, name),
                path: None,
                permissions_boundary: None,
                tags: None,
            },
        )
        .await
        .expect("a seeded user");
}

fn authz<S: GuardStore>(store: &Shared<S>) -> Arc<dyn Authorizer> {
    into_authorizer(AuthorizationService::new(store.clone()))
}

/// The refusal's message, asserting it IS a refusal and names `arn`.
fn refused<T: Debug>(what: &str, got: Result<T>, arn: &str) -> String {
    match got {
        Err(AmiError::AccessDenied { message }) => {
            assert!(
                message.contains(arn),
                "{what}: the refusal does not name {arn}: {message}"
            );
            message
        }
        other => panic!("{what}: expected AccessDenied on {arn}, got {other:?}"),
    }
}

/// The caller of S2: tenant 5/7's `admin`, whose ONLY grant is `iam:*` on
/// 5/7's `user/*` and `credential/*` — never `*`.
async fn admin57<S: GuardStore>(store: &Shared<S>) -> WamiContext {
    principal(
        store,
        &t57(),
        "admin",
        &[every(&t57(), "user"), every(&t57(), "credential")],
    )
    .await
}

/// S2 (users): a tenant admin is refused — never `NotFound` — on an
/// existing user of tenant `0` (root) or `6/7`, for read, create, update and
/// delete; the refusal names the TARGET's ARN and is the same for an absent
/// target of that tenant; and the same verbs succeed on tenant 5/7.
///
/// # Panics
///
/// When a verb crosses into another tenant, or refuses inside its own.
pub async fn a_tenant_admin_is_refused_on_another_tenants_users<S: GuardStore>(store: Shared<S>) {
    InstanceBootstrap::initialize_instance(store.clone(), INSTANCE)
        .await
        .expect("bootstrap: root at tenant 0");
    let admin = admin57(&store).await;
    plain_user(&store, &t67(), "bob").await;
    plain_user(&store, &t57(), "alice").await;
    let users = UserService::with_authorizer(store.clone(), authz(&store));
    let root = TenantPath::single(0);

    for (tenant, name) in [(t67(), "bob"), (root.clone(), ROOT_USER_NAME)] {
        let arn = target(&tenant, "user", name);
        let there = key(&tenant, name);
        let read = refused("get", users.get_user(&admin, &there).await, &arn);
        let ghost = refused(
            "get absent",
            users.get_user(&admin, &key(&tenant, "ghost")).await,
            &target(&tenant, "user", "ghost"),
        );
        assert_eq!(
            read.replace(name, "ghost"),
            ghost,
            "the refusal tells an existing target from an absent one"
        );
        refused(
            "update",
            users
                .update_user(
                    &admin,
                    UpdateUserRequest {
                        user: there.clone(),
                        new_user_name: None,
                        new_path: Some("/x/".into()),
                    },
                )
                .await,
            &arn,
        );
        refused("delete", users.delete_user(&admin, &there).await, &arn);
        refused("tag", users.tag_user(&admin, &there, vec![]).await, &arn);
    }
    refused(
        "create in 6/7",
        users
            .create_user(
                &admin,
                CreateUserRequest {
                    user: key(&t67(), "carol"),
                    path: None,
                    permissions_boundary: None,
                    tags: None,
                },
            )
            .await,
        &target(&t67(), "user", "carol"),
    );

    // The pair: the same caller, inside its own tenant.
    let mine = key(&t57(), "alice");
    let got = users
        .get_user(&admin, &mine)
        .await
        .expect("a read in 5/7")
        .expect("alice");
    assert_eq!(got.key(), mine);
    users
        .update_user(
            &admin,
            UpdateUserRequest {
                user: mine.clone(),
                new_user_name: None,
                new_path: Some("/x/".into()),
            },
        )
        .await
        .expect("an update in 5/7");
    users
        .create_user(
            &admin,
            CreateUserRequest {
                user: key(&t57(), "carol"),
                path: None,
                permissions_boundary: None,
                tags: None,
            },
        )
        .await
        .expect("a create in 5/7");
    users
        .delete_user(&admin, &key(&t57(), "carol"))
        .await
        .expect("a delete in 5/7");
}

/// S2 (every credential kind): the same admin is refused minting or reading
/// a credential of root (tenant `0`) or of 6/7's `bob`, whatever its kind —
/// access key, login profile, MFA device, service credential, signing
/// certificate — and mints each for 5/7's `alice`.
///
/// # Panics
///
/// When a credential verb crosses into another tenant, or refuses inside its own.
pub async fn a_tenant_admin_is_refused_every_credential_of_another_tenant<S: GuardStore>(
    store: Shared<S>,
) {
    let root_creds = InstanceBootstrap::initialize_instance(store.clone(), INSTANCE)
        .await
        .expect("bootstrap: root at tenant 0");
    let admin = admin57(&store).await;
    plain_user(&store, &t67(), "bob").await;
    plain_user(&store, &t57(), "alice").await;
    let a = authz(&store);
    let keys = AccessKeyService::with_authorizer(store.clone(), a.clone());
    let profiles = LoginProfileService::with_authorizer(store.clone(), a.clone());
    let mfa = MfaDeviceService::with_authorizer(store.clone(), a.clone());
    let service_creds = ServiceCredentialService::with_authorizer(store.clone(), a.clone());
    let signing = SigningCertificateService::with_authorizer(store.clone(), a.clone());
    let body = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----".to_string();

    for owner in [
        key(&TenantPath::single(0), ROOT_USER_NAME),
        key(&t67(), "bob"),
    ] {
        let arn = target(owner.tenant(), "user", owner.name());
        refused(
            "access key",
            keys.create_access_key(
                &admin,
                CreateAccessKeyRequest {
                    user: owner.clone(),
                },
            )
            .await,
            &arn,
        );
        refused(
            "login profile",
            profiles
                .create_login_profile(
                    &admin,
                    CreateLoginProfileRequest {
                        user: owner.clone(),
                        password: "Chosen-by-5!x".into(),
                        password_reset_required: false,
                    },
                )
                .await,
            &arn,
        );
        refused(
            "read a login profile",
            profiles.get_login_profile(&admin, &owner).await,
            &arn,
        );
        refused(
            "MFA device",
            mfa.create_mfa_device(
                &admin,
                EnableMfaDeviceRequest {
                    user: owner.clone(),
                    serial_number: format!("mfa-{}", owner.name()),
                    authentication_code_1: "123456".into(),
                    authentication_code_2: "789012".into(),
                },
            )
            .await,
            &arn,
        );
        refused(
            "service credential",
            service_creds
                .create_service_specific_credential(
                    &admin,
                    CreateServiceSpecificCredentialRequest {
                        user: owner.clone(),
                        service_name: "codecommit.amazonaws.com".into(),
                    },
                )
                .await,
            &arn,
        );
        refused(
            "signing certificate",
            signing
                .upload_signing_certificate(
                    &admin,
                    UploadSigningCertificateRequest {
                        user: owner.clone(),
                        certificate_body: body.clone(),
                    },
                )
                .await,
            &arn,
        );
    }

    // Addressed by id: root's existing key is refused, and an absent id gets
    // the very same refusal (A1: the message names the id, never the owner).
    let id = &root_creds.access_key_id;
    let existing = refused(
        "delete root's key",
        keys.delete_access_key(&admin, id).await,
        id,
    );
    let absent = refused(
        "delete an absent key",
        keys.delete_access_key(&admin, "AKIAABSENTABSENTABSE").await,
        "AKIAABSENTABSENTABSE",
    );
    assert_eq!(
        existing.replace(id.as_str(), "AKIAABSENTABSENTABSE"),
        absent,
        "the refusal tells an existing key from an absent one"
    );
    refused("read root's key", keys.get_access_key(&admin, id).await, id);
    assert!(
        store
            .read()
            .await
            .get_access_key(id)
            .await
            .expect("a read")
            .is_some(),
        "root's key is still there"
    );

    // The pair: each kind, for 5/7's alice.
    let alice = key(&t57(), "alice");
    let k = keys
        .create_access_key(
            &admin,
            CreateAccessKeyRequest {
                user: alice.clone(),
            },
        )
        .await
        .expect("a key for alice");
    assert_eq!(k.owner, alice);
    keys.get_access_key(&admin, &k.access_key_id)
        .await
        .expect("alice's key read")
        .expect("alice's key");
    profiles
        .create_login_profile(
            &admin,
            CreateLoginProfileRequest {
                user: alice.clone(),
                password: "Chosen-by-5!x".into(),
                password_reset_required: false,
            },
        )
        .await
        .expect("a profile for alice");
    mfa.create_mfa_device(
        &admin,
        EnableMfaDeviceRequest {
            user: alice.clone(),
            serial_number: "mfa-alice".into(),
            authentication_code_1: "123456".into(),
            authentication_code_2: "789012".into(),
        },
    )
    .await
    .expect("an MFA device for alice");
    service_creds
        .create_service_specific_credential(
            &admin,
            CreateServiceSpecificCredentialRequest {
                user: alice.clone(),
                service_name: "codecommit.amazonaws.com".into(),
            },
        )
        .await
        .expect("a service credential for alice");
    signing
        .upload_signing_certificate(
            &admin,
            UploadSigningCertificateRequest {
                user: alice.clone(),
                certificate_body: body,
            },
        )
        .await
        .expect("a signing certificate for alice");
    keys.delete_access_key(&admin, &k.access_key_id)
        .await
        .expect("alice's key deleted");
}

/// S11: a caller of 6/7 granted on 5/7 mints a credential for a 5/7
/// principal: its ARN carries 5/7's path, and its owner is the principal's
/// key — never the caller's tenant.
///
/// # Panics
///
/// When the credential is stamped with the caller's tenant.
pub async fn a_credential_takes_its_owners_tenant_never_the_callers<S: GuardStore>(
    store: Shared<S>,
) {
    let operator = principal(
        &store,
        &t67(),
        "operator",
        &[every(&t57(), "user"), every(&t57(), "credential")],
    )
    .await;
    plain_user(&store, &t57(), "alice").await;
    let alice = key(&t57(), "alice");
    let k = AccessKeyService::with_authorizer(store.clone(), authz(&store))
        .create_access_key(
            &operator,
            CreateAccessKeyRequest {
                user: alice.clone(),
            },
        )
        .await
        .expect("a 6/7 caller granted on 5/7 mints alice's key");
    assert_eq!(k.owner, alice);
    assert_eq!(
        k.wami_arn.tenant_path,
        t57(),
        "the key's ARN carries {}",
        k.wami_arn
    );
}

/// S12: an Allow on 5/7's `user/alice` permits acting on 5/7's alice and
/// not on 6/7's alice.
///
/// # Panics
///
/// When the grant on one tenant's alice reaches the other's.
pub async fn an_allow_on_one_tenants_alice_never_reaches_anothers<S: GuardStore>(store: Shared<S>) {
    let helper = principal(&store, &t57(), "helper", &[target(&t57(), "user", "alice")]).await;
    plain_user(&store, &t57(), "alice").await;
    plain_user(&store, &t67(), "alice").await;
    let users = UserService::with_authorizer(store.clone(), authz(&store));
    let got = users
        .get_user(&helper, &key(&t57(), "alice"))
        .await
        .expect("5/7's alice")
        .expect("there");
    assert_eq!(got.wami_arn.tenant_path, t57());
    refused(
        "6/7's alice",
        users.get_user(&helper, &key(&t67(), "alice")).await,
        &target(&t67(), "user", "alice"),
    );
}

/// S13 (groups, roles, boundary, server certificates): one cross-tenant
/// refusal per family for a caller granted everything of 5/7, and the pair
/// inside 5/7.
///
/// # Panics
///
/// When a verb of one of those families crosses into 6/7.
pub async fn every_family_refuses_another_tenants_target<S: GuardStore>(store: Shared<S>) {
    // `**`: a single `*` stops at the `/` of `group/devs`.
    let all57 = format!("arn:wami:iam:{}:wami:{INSTANCE}:**", t57());
    let admin = principal(&store, &t57(), "admin", &[all57]).await;
    let seed = caller(&t67(), "seed");
    let a = authz(&store);
    for tenant in [t57(), t67()] {
        plain_user(&store, &tenant, "bob").await;
        GroupService::new(store.clone())
            .create_group(
                &caller(&tenant, "seed"),
                CreateGroupRequest {
                    group: key(&tenant, "devs"),
                    path: None,
                    tags: None,
                },
            )
            .await
            .expect("a group");
        RoleService::new(store.clone())
            .create_role(&caller(&tenant, "seed"), role(key(&tenant, "ops")))
            .await
            .expect("a role");
        ServerCertificateService::new(store.clone())
            .upload_server_certificate(&caller(&tenant, "seed"), cert(key(&tenant, "web")))
            .await
            .expect("a certificate");
    }
    let _ = seed;

    let groups = GroupService::with_authorizer(store.clone(), a.clone());
    refused(
        "get 6/7's group",
        groups.get_group(&admin, &key(&t67(), "devs")).await,
        &target(&t67(), "group", "devs"),
    );
    refused(
        "add 6/7's bob to 5/7's group",
        groups
            .add_user_to_group(&admin, &key(&t57(), "devs"), &key(&t67(), "bob"))
            .await,
        &target(&t67(), "user", "bob"),
    );
    refused(
        "add 5/7's bob to 6/7's group",
        groups
            .add_user_to_group(&admin, &key(&t67(), "devs"), &key(&t57(), "bob"))
            .await,
        &target(&t67(), "group", "devs"),
    );
    groups
        .get_group(&admin, &key(&t57(), "devs"))
        .await
        .expect("5/7's group")
        .expect("there");
    groups
        .add_user_to_group(&admin, &key(&t57(), "devs"), &key(&t57(), "bob"))
        .await
        .expect("a 5/7 membership");

    let roles = RoleService::with_authorizer(store.clone(), a.clone());
    refused(
        "get 6/7's role",
        roles.get_role(&admin, &key(&t67(), "ops")).await,
        &target(&t67(), "role", "ops"),
    );
    refused(
        "delete 6/7's role",
        roles.delete_role(&admin, &key(&t67(), "ops")).await,
        &target(&t67(), "role", "ops"),
    );
    roles
        .get_role(&admin, &key(&t57(), "ops"))
        .await
        .expect("5/7's role")
        .expect("there");

    let boundary =
        PermissionsBoundaryService::with_authorizer(store.clone(), INSTANCE.to_string(), a.clone());
    let put = |principal: ScopedName| PutPermissionsBoundaryRequest {
        principal_type: PrincipalType::User,
        principal,
        permissions_boundary: "arn:aws:iam::conformance:policy/none".into(),
    };
    refused(
        "6/7's bob's boundary",
        boundary
            .put_permissions_boundary(&admin, put(key(&t67(), "bob")))
            .await,
        &target(&t67(), "user", "bob"),
    );
    // The pair: inside 5/7 the guard lets it through (the boundary policy
    // does not exist, so what follows the guard may still refuse).
    if let Err(AmiError::AccessDenied { message }) = boundary
        .put_permissions_boundary(&admin, put(key(&t57(), "bob")))
        .await
    {
        panic!("5/7's bob's boundary refused: {message}")
    }

    let certs = ServerCertificateService::with_authorizer(store.clone(), a);
    refused(
        "6/7's certificate",
        certs
            .get_server_certificate(&admin, &key(&t67(), "web"))
            .await,
        &target(&t67(), "credential", "web"),
    );
    let mine = certs
        .get_server_certificate(&admin, &key(&t57(), "web"))
        .await
        .expect("5/7's certificate")
        .expect("there");
    assert_eq!(mine.server_certificate_name, "web");
}

fn role(key: ScopedName) -> CreateRoleRequest {
    CreateRoleRequest {
        role: key,
        assume_role_policy_document: allow(&["*".to_string()]),
        path: None,
        description: None,
        max_session_duration: None,
        permissions_boundary: None,
        tags: None,
    }
}

fn cert(key: ScopedName) -> UploadServerCertificateRequest {
    UploadServerCertificateRequest {
        server_certificate: key,
        certificate_body: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----".into(),
        private_key: "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----".into(),
        certificate_chain: None,
        path: None,
        tags: None,
    }
}

/// A service-linked role's deletion task is judged on the ROLE it records,
/// in the role's tenant: a caller of 6/7 is refused 5/7's task exactly as it
/// is refused an absent id, and a caller of 5/7 reads it (ruling on the
/// deletion tasks, process #13080).
///
/// # Panics
///
/// When a caller reads another tenant's deletion task, or the refusal tells
/// an existing task from an absent one.
pub async fn a_deletion_task_is_judged_on_its_roles_tenant<S>(store: Shared<S>)
where
    S: GuardStore + ServiceLinkedRoleStore,
{
    let task = crate::wami::identity::service_linked_role::builder::build_deletion_task(&key(
        &t57(),
        "svc",
    ));
    let id = task.deletion_task_id.clone();
    store
        .write()
        .await
        .create_service_linked_role_deletion_task(task)
        .await
        .expect("5/7's task");
    let other = principal(&store, &t67(), "admin", &[every(&t67(), "role")]).await;
    let owner = principal(&store, &t57(), "admin", &[every(&t57(), "role")]).await;
    let slr = ServiceLinkedRoleService::with_authorizer(store.clone(), authz(&store));

    let existing = refused(
        "6/7 reads 5/7's task",
        slr.get_service_linked_role_deletion_task(&other, &id).await,
        &id,
    );
    let absent = refused(
        "6/7 reads an absent task",
        slr.get_service_linked_role_deletion_task(&other, "absent-task")
            .await,
        "absent-task",
    );
    assert_eq!(
        existing.replace(id.as_str(), "absent-task"),
        absent,
        "the refusal tells an existing task from an absent one"
    );
    let mine = slr
        .get_service_linked_role_deletion_task(&owner, &id)
        .await
        .expect("5/7 reads its own task")
        .expect("there");
    assert_eq!(mine.role, key(&t57(), "svc"));
}

/// S2 (policies): a policy addressed by its ARN is read first and judged in
/// ITS tenant — the one its `wami_arn` records — never the caller's; an absent
/// ARN gets the very refusal a denied one gets; a create is judged in the
/// tenant the request names.
///
/// # Panics
///
/// When a policy verb crosses into another tenant, or refuses inside its own.
pub async fn a_policy_is_judged_in_its_own_tenant<S: GuardStore>(store: Shared<S>) {
    use crate::service::PolicyService;
    use crate::wami::policies::policy::requests::CreatePolicyRequest;
    let create = |tenant: &TenantPath, name: &str| CreatePolicyRequest {
        tenant: tenant.clone(),
        policy_name: name.to_string(),
        policy_document: allow(&["*".to_string()]),
        path: None,
        description: None,
        tags: None,
    };
    let theirs = PolicyService::new(store.clone())
        .create_policy(&caller(&t67(), "seed"), create(&t67(), "theirs"))
        .await
        .expect("6/7's policy");
    // `**`: the resource of an ARN-addressed policy verb is `policy/<the ARN>`,
    // and an ARN holds `/` (wami 007 decides that id).
    let admin = principal(
        &store,
        &t57(),
        "admin",
        &[format!("arn:wami:iam:{}:wami:{INSTANCE}:policy/**", t57())],
    )
    .await;
    let policies = PolicyService::with_authorizer(store.clone(), authz(&store));

    let existing = refused(
        "get 6/7's policy",
        policies.get_policy(&admin, &theirs.arn).await,
        &theirs.arn,
    );
    let ghost = "arn:aws:iam::conformance:policy/ghost";
    let absent = refused(
        "get an absent policy",
        policies.get_policy(&admin, ghost).await,
        ghost,
    );
    assert_eq!(
        existing.replace(theirs.arn.as_str(), ghost),
        absent,
        "the refusal tells an existing policy from an absent one"
    );
    refused(
        "delete 6/7's policy",
        policies.delete_policy(&admin, &theirs.arn).await,
        &theirs.arn,
    );
    refused(
        "create in 6/7",
        policies.create_policy(&admin, create(&t67(), "mine")).await,
        &target(&t67(), "policy", "mine"),
    );
    assert!(
        store
            .read()
            .await
            .get_policy(&theirs.arn)
            .await
            .expect("a read")
            .is_some(),
        "6/7's policy is still there"
    );

    // The pair: the same caller on a policy of its own tenant.
    let mine = policies
        .create_policy(&admin, create(&t57(), "mine"))
        .await
        .expect("a 5/7 create");
    policies
        .get_policy(&admin, &mine.arn)
        .await
        .expect("a 5/7 read")
        .expect("there");
    policies
        .delete_policy(&admin, &mine.arn)
        .await
        .expect("a 5/7 delete");
}

/// 5/7's `admin`, granted `iam:*` on everything of 5/7 (`**`: a single `*`
/// stops at a `/`), for the checks of other modules.
pub(crate) async fn admin57_everything<S: GuardStore>(store: &Shared<S>) -> WamiContext {
    let all57 = format!("arn:wami:iam:{}:wami:{INSTANCE}:**", t57());
    principal(store, &t57(), "admin", &[all57]).await
}

/// T7 (Δ7): a rename has two targets and the DESTINATION is judged too,
/// before anything about it is read: a caller whose only right is on 5/7's
/// `user/alice` (or `group/devs`) is refused renaming into `bob` (absent) and
/// into `carol` (held) — the same refusal, naming the destination, never
/// ResourceExists.
///
/// # Panics
///
/// When a rename into a name the caller holds no right on goes through, or
/// tells a held destination from an absent one.
pub async fn a_rename_is_judged_on_its_destination<S: GuardStore>(store: Shared<S>) {
    use crate::wami::identity::group::requests::UpdateGroupRequest;
    plain_user(&store, &t57(), "alice").await;
    plain_user(&store, &t57(), "carol").await;
    let ctx = caller(&t57(), "seed");
    for name in ["devs", "ops"] {
        GroupService::new(store.clone())
            .create_group(
                &ctx,
                CreateGroupRequest {
                    group: key(&t57(), name),
                    path: None,
                    tags: None,
                },
            )
            .await
            .expect("a group");
    }
    let helper = principal(
        &store,
        &t57(),
        "helper",
        &[
            target(&t57(), "user", "alice"),
            target(&t57(), "group", "devs"),
        ],
    )
    .await;
    let a = authz(&store);
    let users = UserService::with_authorizer(store.clone(), a.clone());
    let rename = |to: &str| UpdateUserRequest {
        user: key(&t57(), "alice"),
        new_user_name: Some(to.to_string()),
        new_path: None,
    };
    let absent = refused(
        "rename into bob",
        users.update_user(&helper, rename("bob")).await,
        &target(&t57(), "user", "bob"),
    );
    let held = refused(
        "rename into carol",
        users.update_user(&helper, rename("carol")).await,
        &target(&t57(), "user", "carol"),
    );
    assert_eq!(
        absent.replace("bob", "carol"),
        held,
        "a held destination is told from an absent one"
    );
    let still = store
        .read()
        .await
        .get_user(&key(&t57(), "alice"))
        .await
        .expect("a read");
    assert!(still.is_some(), "alice was renamed");

    let groups = GroupService::with_authorizer(store.clone(), a);
    let regroup = |to: &str| UpdateGroupRequest {
        group: key(&t57(), "devs"),
        new_group_name: Some(to.to_string()),
        new_path: None,
    };
    let absent = refused(
        "rename devs into builders",
        groups.update_group(&helper, regroup("builders")).await,
        &target(&t57(), "group", "builders"),
    );
    let held = refused(
        "rename devs into ops",
        groups.update_group(&helper, regroup("ops")).await,
        &target(&t57(), "group", "ops"),
    );
    assert_eq!(
        absent.replace("builders", "ops"),
        held,
        "a held group destination is told from an absent one"
    );

    // The pair: a path change (no new name) needs the source only.
    users
        .update_user(
            &helper,
            UpdateUserRequest {
                user: key(&t57(), "alice"),
                new_user_name: None,
                new_path: Some("/x/".into()),
            },
        )
        .await
        .expect("a path change on alice");
}

/// T8 (Δ8): `get_caller_identity` answers the CONTEXT's caller and nobody
/// else: a context whose key names another principal than its ARN, or no
/// key at all, gets the one refusal; the genuine context gets its own
/// identity.
///
/// # Panics
///
/// When it answers for a key that is not the caller's.
pub async fn caller_identity_answers_the_caller_only<S>(store: Shared<S>)
where
    S: GuardStore + crate::store::traits::IdentityStore,
{
    use crate::service::sts::identity::GetCallerIdentityRequest;
    use crate::service::IdentityService;
    plain_user(&store, &t57(), "alice").await;
    plain_user(&store, &t67(), "alice").await;
    let mine = store
        .read()
        .await
        .get_user(&key(&t57(), "alice"))
        .await
        .expect("a read")
        .expect("5/7's alice");
    let theirs = store
        .read()
        .await
        .get_user(&key(&t67(), "alice"))
        .await
        .expect("a read")
        .expect("6/7's alice");
    let identity = IdentityService::new(store.clone(), INSTANCE.to_string());

    let own = identity
        .get_caller_identity(GetCallerIdentityRequest {}, &signed_in(&mine))
        .await
        .expect("alice's own identity");
    assert_eq!(own.user_id, mine.user_id);

    let forged = WamiContext::builder()
        .caller_arn(mine.wami_arn.clone())
        .caller_key(theirs.key())
        .build()
        .expect("a context");
    let keyless = WamiContext::builder()
        .caller_arn(mine.wami_arn.clone())
        .build()
        .expect("a context");
    let mut refusals = Vec::new();
    for (what, ctx) in [("another principal's key", forged), ("no key", keyless)] {
        match identity
            .get_caller_identity(GetCallerIdentityRequest {}, &ctx)
            .await
        {
            Err(AmiError::AccessDenied { message }) => refusals.push(message),
            other => panic!("{what}: expected the refusal, got {other:?}"),
        }
    }
    assert_eq!(refusals[0], refusals[1], "the refusals differ");
}

/// T1: every credential verb — update, list and delete included, not only
/// create and read — refuses another tenant's owner, and the credential is
/// left as it was. `update_access_key` is judged on the STORED key's owner,
/// whatever owner the record handed in names (the takeover path: replace a
/// key's state through a record naming oneself).
///
/// # Panics
///
/// When a credential verb of any kind reaches another tenant's owner.
pub async fn every_credential_verb_refuses_another_tenant<S: GuardStore>(store: Shared<S>) {
    use crate::credentials::access_key::requests::ListAccessKeysRequest;
    use crate::credentials::login_profile::requests::UpdateLoginProfileRequest;
    use crate::credentials::mfa_device::requests::ListMfaDevicesRequest;
    use crate::credentials::service_credential::requests::{
        DeleteServiceSpecificCredentialRequest, ListServiceSpecificCredentialsRequest,
        UpdateServiceSpecificCredentialRequest,
    };
    use crate::credentials::signing_certificate::requests::{
        DeleteSigningCertificateRequest, ListSigningCertificatesRequest,
        UpdateSigningCertificateRequest,
    };
    use crate::credentials::signing_certificate::CertificateStatus;
    let admin = admin57(&store).await;
    plain_user(&store, &t67(), "bob").await;
    let bob = key(&t67(), "bob");
    let seed = caller(&t67(), "seed");
    let body = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----".to_string();
    let key_of_bob = AccessKeyService::new(store.clone())
        .create_access_key(&seed, CreateAccessKeyRequest { user: bob.clone() })
        .await
        .expect("bob's key");
    LoginProfileService::new(store.clone())
        .create_login_profile(
            &seed,
            CreateLoginProfileRequest {
                user: bob.clone(),
                password: "Chosen-by-6!x".into(),
                password_reset_required: false,
            },
        )
        .await
        .expect("bob's profile");
    let device = MfaDeviceService::new(store.clone())
        .create_mfa_device(
            &seed,
            EnableMfaDeviceRequest {
                user: bob.clone(),
                serial_number: "mfa-bob".into(),
                authentication_code_1: "123456".into(),
                authentication_code_2: "789012".into(),
            },
        )
        .await
        .expect("bob's device");
    let credential = ServiceCredentialService::new(store.clone())
        .create_service_specific_credential(
            &seed,
            CreateServiceSpecificCredentialRequest {
                user: bob.clone(),
                service_name: "codecommit.amazonaws.com".into(),
            },
        )
        .await
        .expect("bob's service credential");
    let certificate = SigningCertificateService::new(store.clone())
        .upload_signing_certificate(
            &seed,
            UploadSigningCertificateRequest {
                user: bob.clone(),
                certificate_body: body,
            },
        )
        .await
        .expect("bob's signing certificate");
    let a = authz(&store);
    let arn = target(&t67(), "user", "bob");
    let denied = |what: &str, got: std::result::Result<(), AmiError>| match got {
        Err(AmiError::AccessDenied { .. }) => {}
        other => panic!("{what}: expected AccessDenied, got {other:?}"),
    };

    let keys = AccessKeyService::with_authorizer(store.clone(), a.clone());
    let mut handed = key_of_bob.clone();
    handed.status = "Inactive".into();
    denied(
        "update bob's key",
        keys.update_access_key(&admin, handed.clone())
            .await
            .map(drop),
    );
    handed.owner = key(&t57(), "admin");
    denied(
        "update bob's key through a record naming 5/7's admin",
        keys.update_access_key(&admin, handed).await.map(drop),
    );
    refused(
        "list bob's keys",
        keys.list_access_keys(
            &admin,
            ListAccessKeysRequest {
                user: bob.clone(),
                pagination: None,
            },
        )
        .await,
        &arn,
    );
    let stored = store
        .read()
        .await
        .get_access_key(&key_of_bob.access_key_id)
        .await
        .expect("a read")
        .expect("bob's key");
    assert_eq!(
        (stored.status.as_str(), &stored.owner),
        ("Active", &bob),
        "bob's key was changed"
    );

    let profiles = LoginProfileService::with_authorizer(store.clone(), a.clone());
    refused(
        "update bob's profile",
        profiles
            .update_login_profile(
                &admin,
                UpdateLoginProfileRequest {
                    user: bob.clone(),
                    password: None,
                    password_reset_required: Some(true),
                },
            )
            .await,
        &arn,
    );
    refused(
        "delete bob's profile",
        profiles.delete_login_profile(&admin, &bob).await,
        &arn,
    );

    let mfa = MfaDeviceService::with_authorizer(store.clone(), a.clone());
    denied(
        "delete bob's device",
        mfa.delete_mfa_device(&admin, &device.serial_number).await,
    );
    refused(
        "list bob's devices",
        mfa.list_mfa_devices(&admin, ListMfaDevicesRequest { user: bob.clone() })
            .await,
        &arn,
    );

    let services = ServiceCredentialService::with_authorizer(store.clone(), a.clone());
    let id = credential.service_specific_credential_id.clone();
    denied(
        "update bob's service credential",
        services
            .update_service_specific_credential(
                &admin,
                UpdateServiceSpecificCredentialRequest {
                    user: bob.clone(),
                    service_specific_credential_id: id.clone(),
                    status: "Inactive".into(),
                },
            )
            .await
            .map(drop),
    );
    denied(
        "delete bob's service credential",
        services
            .delete_service_specific_credential(
                &admin,
                DeleteServiceSpecificCredentialRequest {
                    user: bob.clone(),
                    service_specific_credential_id: id,
                },
            )
            .await,
    );
    refused(
        "list bob's service credentials",
        services
            .list_service_specific_credentials(
                &admin,
                ListServiceSpecificCredentialsRequest {
                    tenant: t67(),
                    user: Some(bob.clone()),
                    service_name: None,
                },
            )
            .await,
        &arn,
    );

    let signing = SigningCertificateService::with_authorizer(store.clone(), a);
    let id = certificate.certificate_id.clone();
    denied(
        "update bob's signing certificate",
        signing
            .update_signing_certificate(
                &admin,
                UpdateSigningCertificateRequest {
                    user: bob.clone(),
                    certificate_id: id.clone(),
                    status: CertificateStatus::Inactive,
                },
            )
            .await
            .map(drop),
    );
    denied(
        "delete bob's signing certificate",
        signing
            .delete_signing_certificate(
                &admin,
                DeleteSigningCertificateRequest {
                    user: bob.clone(),
                    certificate_id: id,
                },
            )
            .await,
    );
    refused(
        "list bob's signing certificates",
        signing
            .list_signing_certificates(
                &admin,
                ListSigningCertificatesRequest {
                    tenant: t67(),
                    user: Some(bob.clone()),
                },
            )
            .await,
        &arn,
    );
}

/// A5 (ruling 9): a credential addressed by id is judged on BOTH its owner,
/// `user/<owner>`, and itself, `credential/<id>`: an Allow needs the owner, a
/// Deny on either wins — so a document denying `credential/*` still reaches
/// the id verbs, and an Allow on `credential/*` alone reaches nothing.
///
/// # Panics
///
/// When a Deny on `credential/*` is ignored, or a right on the credential
/// alone stands in for the owner.
pub async fn a_credential_by_id_is_judged_on_its_owner_and_on_itself<S: GuardStore>(
    store: Shared<S>,
) {
    plain_user(&store, &t57(), "alice").await;
    let k = AccessKeyService::new(store.clone())
        .create_access_key(
            &caller(&t57(), "seed"),
            CreateAccessKeyRequest {
                user: key(&t57(), "alice"),
            },
        )
        .await
        .expect("alice's key");
    let owner_only = principal(&store, &t57(), "owner-only", &[every(&t57(), "user")]).await;
    let fenced = principal(&store, &t57(), "fenced", &[every(&t57(), "user")]).await;
    store
        .write()
        .await
        .put_user_policy(
            &key(&t57(), "fenced"),
            "fence",
            format!(
                r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Deny","Action":"iam:*","Resource":"{}"}}]}}"#,
                every(&t57(), "credential")
            ),
        )
        .await
        .expect("the fence");
    let credential_only = principal(
        &store,
        &t57(),
        "credential-only",
        &[every(&t57(), "credential")],
    )
    .await;
    let keys = AccessKeyService::with_authorizer(store.clone(), authz(&store));

    keys.get_access_key(&owner_only, &k.access_key_id)
        .await
        .expect("the owner's right reaches the key")
        .expect("there");
    let fenced_out = refused(
        "a Deny on credential/*",
        keys.get_access_key(&fenced, &k.access_key_id).await,
        &k.access_key_id,
    );
    let absent = refused(
        "an absent key",
        keys.get_access_key(&fenced, "AKIAABSENTABSENTABSE").await,
        "AKIAABSENTABSENTABSE",
    );
    assert_eq!(
        fenced_out.replace(k.access_key_id.as_str(), "AKIAABSENTABSENTABSE"),
        absent,
        "the fence tells an existing key from an absent one"
    );
    refused(
        "credential/* alone",
        keys.get_access_key(&credential_only, &k.access_key_id)
            .await,
        &k.access_key_id,
    );
}

/// T14 (Δ12, ruling 8): one store holds one instance — a record of another
/// instance found under an id is refused exactly as an absent id, for an
/// access key and for a policy.
///
/// # Panics
///
/// When a record of another instance is acted on, or refused differently
/// from an absent one.
pub async fn a_record_of_another_instance_is_refused_as_absent<S: GuardStore>(store: Shared<S>) {
    use crate::service::PolicyService;
    let admin = admin57_everything(&store).await;
    plain_user(&store, &t57(), "alice").await;
    let elsewhere = WamiContext::builder()
        .caller_arn(
            WamiArn::builder()
                .service(wami_core::arn::Service::Iam)
                .tenant_path(t57())
                .wami_instance("elsewhere")
                .resource("user", "seed")
                .build()
                .expect("an ARN"),
        )
        .build()
        .expect("a context");
    let mut foreign_key = crate::credentials::access_key::builder::build_access_key(
        &key(&t57(), "alice"),
        &elsewhere,
    )
    .expect("a key");
    foreign_key.access_key_id = "AKIAELSEWHEREELSEWHR".into();
    let foreign_policy = crate::wami::policies::policy::builder::build_policy(
        "theirs".into(),
        allow(&["*".to_string()]),
        None,
        None,
        None,
        &t57(),
        &elsewhere,
    )
    .expect("a policy");
    let policy_arn = foreign_policy.arn.clone();
    {
        let mut s = store.write().await;
        s.create_access_key(foreign_key)
            .await
            .expect("the foreign key");
        s.create_policy(foreign_policy)
            .await
            .expect("the foreign policy");
    }
    let keys = AccessKeyService::with_authorizer(store.clone(), authz(&store));
    let other = refused(
        "another instance's key",
        keys.get_access_key(&admin, "AKIAELSEWHEREELSEWHR").await,
        "AKIAELSEWHEREELSEWHR",
    );
    let absent = refused(
        "an absent key",
        keys.get_access_key(&admin, "AKIAABSENTABSENTABSE").await,
        "AKIAABSENTABSENTABSE",
    );
    assert_eq!(
        other.replace("AKIAELSEWHEREELSEWHR", "AKIAABSENTABSENTABSE"),
        absent,
        "another instance's key is told from an absent one"
    );
    let policies = PolicyService::with_authorizer(store.clone(), authz(&store));
    refused(
        "another instance's policy",
        policies.get_policy(&admin, &policy_arn).await,
        &policy_arn,
    );
}
