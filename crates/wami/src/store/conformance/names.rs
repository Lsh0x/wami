//! Reserved names: `root` names the instance's root principal, and no
//! tenant may create or rename a user to it, in any case (S4).

use super::{caller, key, t57, Shared};
use crate::service::UserService;
use crate::store::traits::UserStore;
use crate::wami::identity::user::requests::{CreateUserRequest, UpdateUserRequest};
use wami_core::arn::{ScopedName, TenantPath};
use wami_core::error::AmiError;

fn create(user: ScopedName) -> CreateUserRequest {
    CreateUserRequest {
        user,
        path: None,
        permissions_boundary: None,
        tags: None,
    }
}

/// S4: a user named `root` — `Root`, `ROOT` — is refused at create in any
/// tenant, tenant `0` and its children included, and nothing is stored.
///
/// # Panics
///
/// When a reserved name is created anywhere.
pub async fn a_reserved_name_is_refused_at_create_in_every_tenant<S: UserStore + 'static>(
    store: Shared<S>,
) {
    let users = UserService::new(store.clone());
    for tenant in [t57(), TenantPath::single(0), TenantPath::new(vec![0, 7])] {
        for name in ["root", "Root", "ROOT"] {
            let got = users
                .create_user(&caller(&tenant, "x"), create(key(&tenant, name)))
                .await;
            assert!(
                matches!(got, Err(AmiError::InvalidParameter { .. })),
                "create_user({name}) in {tenant} → {got:?}"
            );
            assert!(
                store
                    .read()
                    .await
                    .get_user(&key(&tenant, name))
                    .await
                    .expect("a read")
                    .is_none(),
                "{name} was stored in {tenant}"
            );
        }
    }
    // The pair: an ordinary name is created.
    users
        .create_user(&caller(&t57(), "x"), create(key(&t57(), "rooted")))
        .await
        .expect("a name that only starts like the reserved one");
}

/// S4: a rename onto `root`, in any case, is refused, and the user keeps its
/// name.
///
/// # Panics
///
/// When a user is renamed to a reserved name.
pub async fn a_reserved_name_is_refused_at_rename<S: UserStore + 'static>(store: Shared<S>) {
    let users = UserService::new(store.clone());
    let ctx = caller(&t57(), "x");
    let alice = key(&t57(), "alice");
    users
        .create_user(&ctx, create(alice.clone()))
        .await
        .expect("alice");
    for name in ["root", "Root", "ROOT"] {
        let got = users
            .update_user(
                &ctx,
                UpdateUserRequest {
                    user: alice.clone(),
                    new_user_name: Some(name.to_string()),
                    new_path: None,
                },
            )
            .await;
        assert!(
            matches!(got, Err(AmiError::InvalidParameter { .. })),
            "rename alice → {name} → {got:?}"
        );
    }
    let still = users
        .get_user(&ctx, &alice)
        .await
        .expect("a read")
        .expect("alice keeps her name");
    assert_eq!(still.user_name, "alice");
    // The pair: an ordinary rename goes through.
    users
        .update_user(
            &ctx,
            UpdateUserRequest {
                user: alice,
                new_user_name: Some("alicia".to_string()),
                new_path: None,
            },
        )
        .await
        .expect("an ordinary rename");
}
