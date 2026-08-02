//! What #115 was about, from the outside.
//!
//! Two properties a consumer needs and could not have while the services
//! disagreed on their lock type:
//!
//! 1. One store handle serves every service. When `TenantService` took
//!    `std::sync::RwLock` and `AuthenticationService` took `tokio::sync::RwLock`,
//!    the two were distinct types, so anything needing both had to hold two
//!    handles onto the same data and hope they agreed.
//!
//! 2. The futures are `Send`. A `std::sync` guard held across an `.await` — which
//!    is what the services did, since the store traits are async — makes the
//!    future non-`Send`, so it cannot be spawned on a multi-threaded runtime nor
//!    handed to a server framework.
//!
//! These are compile-time properties as much as runtime ones: the file failing
//! to build is the regression.

use std::sync::Arc;
use tokio::sync::RwLock;
use wami::store::memory::InMemoryWamiStore;
use wami::{
    AuthenticationService, CreateUserRequest, InstanceBootstrap, TenantService, UserService,
};
use wami_core::context::WamiContext;

/// Accepts only a `Send` future. Calling it is the assertion.
fn assert_send<F: Send>(_: F) {}

/// A store with an instance bootstrapped on it, and the root context to drive it.
async fn bootstrapped() -> (Arc<RwLock<InMemoryWamiStore>>, WamiContext) {
    let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
    let root = InstanceBootstrap::initialize_instance(store.clone(), "999888777")
        .await
        .unwrap();
    let context = AuthenticationService::new(store.clone())
        .authenticate(&root.access_key_id, &root.secret_access_key)
        .await
        .unwrap();
    (store, context)
}

#[tokio::test]
async fn one_store_handle_serves_every_service() {
    // Bootstrap and authentication took the handle...
    let (store, context) = bootstrapped().await;

    // ...and so do the services that used to want the other lock type.
    let tenants = TenantService::new(store.clone());
    let users = UserService::new(store.clone());

    let tenant = tenants
        .create_tenant(&context, "acme".to_string(), None, None)
        .await
        .unwrap();

    users
        .create_user(
            &context,
            CreateUserRequest {
                user_name: "alice".to_string(),
                path: Some("/".to_string()),
                permissions_boundary: None,
                tags: None,
            },
        )
        .await
        .unwrap();

    // One store, so each write is visible through the other handle.
    assert!(tenants.get_tenant(&tenant.id).await.unwrap().is_some());
    assert!(users.get_user(&context, "alice").await.unwrap().is_some());
}

#[tokio::test]
async fn service_futures_are_send() {
    let (store, context) = bootstrapped().await;
    let tenants = TenantService::new(store.clone());
    let users = UserService::new(store.clone());

    // A read and a write on each, since both guards used to be the blocking kind.
    assert_send(tenants.list_tenants());
    assert_send(tenants.create_tenant(&context, "acme".to_string(), None, None));
    assert_send(users.get_user(&context, "alice"));
    assert_send(users.create_user(
        &context,
        CreateUserRequest {
            user_name: "bob".to_string(),
            path: None,
            permissions_boundary: None,
            tags: None,
        },
    ));
}

/// `tokio::spawn` demands `Send + 'static` — the shape a server framework needs.
/// Non-`Send` futures were rejected here before anything ran.
#[tokio::test(flavor = "multi_thread")]
async fn service_calls_can_be_spawned_on_a_multi_thread_runtime() {
    let (store, context) = bootstrapped().await;
    let tenants = Arc::new(TenantService::new(store.clone()));

    let handles: Vec<_> = (0..4)
        .map(|i| {
            let tenants = tenants.clone();
            let context = context.clone();
            tokio::spawn(async move {
                tenants
                    .create_tenant(&context, format!("tenant-{i}"), None, None)
                    .await
                    .unwrap()
            })
        })
        .collect();

    for handle in handles {
        handle.await.unwrap();
    }

    assert_eq!(tenants.list_tenants().await.unwrap().len(), 4);
}
