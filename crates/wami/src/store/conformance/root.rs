//! Root by identity: root is the one stored principal at tenant path
//! EXACTLY `0`, recognised from its record — never from a name, never from
//! the first segment of a path (S5).

use super::{caller, Shared, INSTANCE};
use crate::credentials::access_key::builder::build_access_key;
use crate::service::auth::authentication::hash_secret;
use crate::service::AuthenticationService;
use crate::store::traits::{AccessKeyStore, UserStore};
use crate::wami::identity::user::builder::build_user;
use crate::wami::identity::User;
use crate::InstanceBootstrap;
use wami_core::arn::{ScopedName, TenantPath, WamiArn};
use wami_core::error::AmiError;

/// What the root checks traverse.
pub trait RootStore: UserStore + AccessKeyStore + 'static {}
impl<T> RootStore for T where T: UserStore + AccessKeyStore + 'static {}

/// Store `user` straight into the store (no service refuses its name) with an
/// access key whose secret is `secret`; returns the key id.
async fn with_key<S: RootStore>(store: &Shared<S>, user: User, secret: &str) -> String {
    let owner = user.key();
    let mut s = store.write().await;
    s.create_user(user).await.expect("the user");
    let mut key = build_access_key(&owner, &caller(owner.tenant(), "seed")).expect("a key");
    key.secret_access_key = Some(hash_secret(secret).expect("a hash"));
    let id = key.access_key_id.clone();
    s.create_access_key(key).await.expect("the key");
    id
}

/// S5: the bootstrapped root — the stored principal at tenant path `0` —
/// authenticates as root; a principal named `root` at `0/7`, whatever its
/// ARN says, never does, through `authenticate` or `authenticate_root`.
///
/// # Panics
///
/// When anything but the stored root at `0` authenticates as root, or root
/// itself does not.
pub async fn only_the_principal_at_path_zero_authenticates_as_root<S: RootStore>(store: Shared<S>) {
    let root = InstanceBootstrap::initialize_instance(store.clone(), INSTANCE)
        .await
        .expect("bootstrap");
    let auth = AuthenticationService::new(store.clone());

    let ctx = auth
        .authenticate(&root.access_key_id, &root.secret_access_key)
        .await
        .expect("root authenticates");
    assert!(
        ctx.is_root(),
        "the stored root at 0 is not root: {}",
        ctx.caller_arn()
    );
    assert_eq!(ctx.tenant_path(), &TenantPath::single(0));
    // Its key is the stored root record's (wami 005, S5 and (c)).
    let root_key = crate::wami::identity::RootUser::for_instance(INSTANCE)
        .as_user()
        .key();
    let stored = store
        .read()
        .await
        .get_user(&root_key)
        .await
        .expect("a read")
        .expect("root's record");
    assert_eq!(
        ctx.caller_key(),
        Some(&stored.key()),
        "root's context carries another key"
    );
    let ctx = auth
        .authenticate_root(INSTANCE, &root.access_key_id, &root.secret_access_key)
        .await
        .expect("authenticate_root on root's key");
    assert!(ctx.is_root());
    assert_eq!(ctx.caller_key(), Some(&stored.key()));

    // A user named root at 0/7 — written straight into the store, since the
    // service refuses the name (S4) — whose ARN reads `0/7:…:user/root`:
    // exactly the record the first-segment check took for root (P6).
    let deep = TenantPath::new(vec![0, 7]);
    let mut impostor = build_user(
        &ScopedName::new(deep.clone(), "root"),
        None,
        &caller(&deep, "seed"),
    )
    .expect("a user");
    impostor.wami_arn = WamiArn::builder()
        .service(wami_core::arn::Service::Iam)
        .tenant_path(deep.clone())
        .wami_instance(INSTANCE)
        .resource("user", "root")
        .build()
        .expect("an ARN");
    let id = with_key(&store, impostor, "impostor-secret").await;

    let got = auth
        .authenticate(&id, "impostor-secret")
        .await
        .expect("an ordinary principal authenticates");
    assert!(
        !got.is_root(),
        "{} at 0/7 authenticates as root",
        got.caller_arn()
    );
    let as_root = auth
        .authenticate_root(INSTANCE, &id, "impostor-secret")
        .await;
    assert!(
        matches!(as_root, Err(AmiError::AccessDenied { .. })),
        "authenticate_root on 0/7's root → {as_root:?}"
    );

    // And a principal named root in an ordinary tenant, ARN as build_user
    // writes it: refused by authenticate_root, which used to compare the name.
    let t57 = TenantPath::new(vec![5, 7]);
    let named = build_user(
        &ScopedName::new(t57.clone(), "root"),
        None,
        &caller(&t57, "seed"),
    )
    .expect("a user");
    let id = with_key(&store, named, "named-secret").await;
    let as_root = auth.authenticate_root(INSTANCE, &id, "named-secret").await;
    assert!(
        matches!(as_root, Err(AmiError::AccessDenied { .. })),
        "authenticate_root on 5/7's root → {as_root:?}"
    );
}
