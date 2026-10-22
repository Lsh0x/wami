//! Tests for Credentials Store Implementations
//!
//! Tests for AccessKeyStore, MfaDeviceStore, and LoginProfileStore

use crate::arn::{TenantPath, WamiArn};
use crate::context::WamiContext;
use crate::credentials::access_key::builder as access_key_builder;
use crate::credentials::login_profile::builder as login_profile_builder;
use crate::credentials::mfa_device::builder as mfa_builder;
use crate::store::memory::InMemoryWamiStore;
use crate::store::traits::{AccessKeyStore, LoginProfileStore, MfaDeviceStore};
use wami_core::types::PaginationParams;

/// The tenant every test here works in.
fn tenant() -> wami_core::arn::TenantPath {
    wami_core::arn::TenantPath::single(12345678)
}

/// `name`'s key in that tenant.
fn key(name: impl AsRef<str>) -> wami_core::arn::ScopedName {
    wami_core::arn::ScopedName::new(tenant(), name.as_ref())
}

fn test_context() -> WamiContext {
    let arn: WamiArn = "arn:wami:.*:12345678:wami:123456789012:user/test"
        .parse()
        .unwrap();
    WamiContext::builder()
        .instance_id("123456789012")
        .tenant_path(TenantPath::single(12345678))
        .caller_arn(arn)
        .is_root(false)
        .build()
        .unwrap()
}

// ============================================================================
// ACCESS KEY STORE TESTS
// ============================================================================

#[tokio::test]
async fn test_access_key_create_and_get() {
    let mut store = InMemoryWamiStore::new();
    let context = test_context();

    let access_key = access_key_builder::build_access_key(&key("alice"), &context).unwrap();

    let key_id = access_key.access_key_id.clone();

    // Create access key
    let created = store.create_access_key(access_key.clone()).await.unwrap();
    assert_eq!(created.owner.name(), "alice");

    // Get access key
    let retrieved = store.get_access_key(&key_id).await.unwrap();
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().owner.name(), "alice");
}

#[tokio::test]
async fn test_access_key_get_nonexistent() {
    let store = InMemoryWamiStore::new();

    let result = store.get_access_key("nonexistent-key").await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_access_key_update() {
    let mut store = InMemoryWamiStore::new();
    let context = test_context();

    let access_key = access_key_builder::build_access_key(&key("bob"), &context).unwrap();

    let key_id = access_key.access_key_id.clone();
    store.create_access_key(access_key.clone()).await.unwrap();

    // Update key status
    let mut updated_key = access_key;
    updated_key.status = "Inactive".to_string();
    store.update_access_key(updated_key).await.unwrap();

    // Verify update
    let retrieved = store.get_access_key(&key_id).await.unwrap().unwrap();
    assert_eq!(retrieved.status, "Inactive");
}

#[tokio::test]
async fn test_access_key_delete() {
    let mut store = InMemoryWamiStore::new();
    let context = test_context();

    let access_key = access_key_builder::build_access_key(&key("charlie"), &context).unwrap();

    let key_id = access_key.access_key_id.clone();
    store.create_access_key(access_key).await.unwrap();

    // Delete key
    store.delete_access_key(&key_id).await.unwrap();

    // Verify deleted
    let result = store.get_access_key(&key_id).await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_access_key_list_for_user() {
    let mut store = InMemoryWamiStore::new();
    let context = test_context();

    // Create multiple access keys for same user
    for _ in 0..3 {
        let access_key = access_key_builder::build_access_key(&key("alice"), &context).unwrap();
        store.create_access_key(access_key).await.unwrap();
    }

    // Create keys for different user
    let other_key = access_key_builder::build_access_key(&key("bob"), &context).unwrap();
    store.create_access_key(other_key).await.unwrap();

    // List keys for alice
    let (keys, is_truncated, _) = store.list_access_keys(&key("alice"), None).await.unwrap();

    assert_eq!(keys.len(), 3);
    assert!(!is_truncated);
    assert!(keys.iter().all(|k| k.owner.name() == "alice"));
}

#[tokio::test]
async fn test_access_key_list_with_pagination() {
    let mut store = InMemoryWamiStore::new();
    let context = test_context();

    // Create 5 access keys for one user
    for _ in 0..5 {
        let access_key = access_key_builder::build_access_key(&key("alice"), &context).unwrap();
        store.create_access_key(access_key).await.unwrap();
    }

    let pagination = PaginationParams {
        max_items: Some(2),
        marker: None,
    };

    let (keys, is_truncated, marker) = store
        .list_access_keys(&key("alice"), Some(&pagination))
        .await
        .unwrap();

    assert_eq!(keys.len(), 2);
    assert!(is_truncated);
    assert!(marker.is_some());
}

#[tokio::test]
async fn test_access_key_list_empty() {
    let store = InMemoryWamiStore::new();

    let (keys, is_truncated, marker) = store
        .list_access_keys(&key("nonexistent"), None)
        .await
        .unwrap();

    assert_eq!(keys.len(), 0);
    assert!(!is_truncated);
    assert!(marker.is_none());
}

// ============================================================================
// MFA DEVICE STORE TESTS
// ============================================================================

#[tokio::test]
async fn test_mfa_device_create_and_get() {
    let mut store = InMemoryWamiStore::new();
    let context = test_context();

    let mfa_device = mfa_builder::build_mfa_device(
        &key("alice"),
        "arn:aws:iam::123456789012:mfa/alice".to_string(),
        &context,
    )
    .unwrap();

    let serial = mfa_device.serial_number.clone();

    // Create MFA device
    let created = store.create_mfa_device(mfa_device.clone()).await.unwrap();
    assert_eq!(created.owner.name(), "alice");

    // Get MFA device
    let retrieved = store.get_mfa_device(&serial).await.unwrap();
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().owner.name(), "alice");
}

#[tokio::test]
async fn test_mfa_device_delete() {
    let mut store = InMemoryWamiStore::new();
    let context = test_context();

    let mfa_device = mfa_builder::build_mfa_device(
        &key("bob"),
        "arn:aws:iam::123456789012:mfa/bob".to_string(),
        &context,
    )
    .unwrap();

    let serial = mfa_device.serial_number.clone();
    store.create_mfa_device(mfa_device).await.unwrap();

    // Delete MFA device
    store.delete_mfa_device(&serial).await.unwrap();

    // Verify deleted
    let result = store.get_mfa_device(&serial).await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_mfa_device_list_for_user() {
    let mut store = InMemoryWamiStore::new();
    let context = test_context();

    // Create MFA devices for alice
    for i in 0..2 {
        let mfa_device = mfa_builder::build_mfa_device(
            &key("alice"),
            format!("arn:aws:iam::123456789012:mfa/alice-device-{}", i),
            &context,
        )
        .unwrap();
        store.create_mfa_device(mfa_device).await.unwrap();
    }

    // Create device for different user
    let other_device = mfa_builder::build_mfa_device(
        &key("bob"),
        "arn:aws:iam::123456789012:mfa/bob".to_string(),
        &context,
    )
    .unwrap();
    store.create_mfa_device(other_device).await.unwrap();

    // List devices for alice
    let devices = store.list_mfa_devices(&key("alice")).await.unwrap();

    assert_eq!(devices.len(), 2);
    assert!(devices.iter().all(|d| d.owner.name() == "alice"));
}

#[tokio::test]
async fn test_mfa_device_list_empty() {
    let store = InMemoryWamiStore::new();

    let devices = store.list_mfa_devices(&key("nonexistent")).await.unwrap();

    assert_eq!(devices.len(), 0);
}

// ============================================================================
// LOGIN PROFILE STORE TESTS
// ============================================================================

#[tokio::test]
async fn test_login_profile_create_and_get() {
    let mut store = InMemoryWamiStore::new();
    let context = test_context();

    let login_profile =
        login_profile_builder::build_login_profile(&key("alice"), true, &context).unwrap();

    // Create login profile
    let created = store
        .create_login_profile(login_profile.clone())
        .await
        .unwrap();
    assert_eq!(created.owner.name(), "alice");

    // Get login profile
    let retrieved = store.get_login_profile(&key("alice")).await.unwrap();
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().owner.name(), "alice");
}

#[tokio::test]
async fn test_login_profile_get_nonexistent() {
    let store = InMemoryWamiStore::new();

    let result = store.get_login_profile(&key("nonexistent")).await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_login_profile_update() {
    let mut store = InMemoryWamiStore::new();
    let context = test_context();

    let login_profile =
        login_profile_builder::build_login_profile(&key("bob"), true, &context).unwrap();

    store
        .create_login_profile(login_profile.clone())
        .await
        .unwrap();

    // Update password reset requirement
    let updated = login_profile_builder::update_login_profile(login_profile, Some(false));
    store.update_login_profile(updated).await.unwrap();

    // Verify update (note: password is hashed, so we just verify profile exists)
    let retrieved = store.get_login_profile(&key("bob")).await.unwrap();
    assert!(retrieved.is_some());
}

#[tokio::test]
async fn test_login_profile_delete() {
    let mut store = InMemoryWamiStore::new();
    let context = test_context();

    let login_profile =
        login_profile_builder::build_login_profile(&key("charlie"), false, &context).unwrap();

    store.create_login_profile(login_profile).await.unwrap();

    // Delete login profile
    store.delete_login_profile(&key("charlie")).await.unwrap();

    // Verify deleted
    let result = store.get_login_profile(&key("charlie")).await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_login_profile_password_reset_required() {
    let mut store = InMemoryWamiStore::new();
    let context = test_context();

    let login_profile = login_profile_builder::build_login_profile(
        &key("alice"),
        true, // password_reset_required
        &context,
    )
    .unwrap();

    store.create_login_profile(login_profile).await.unwrap();

    let retrieved = store
        .get_login_profile(&key("alice"))
        .await
        .unwrap()
        .unwrap();
    assert!(retrieved.password_reset_required);
}

#[tokio::test]
async fn test_login_profile_one_per_user() {
    let mut store = InMemoryWamiStore::new();
    let context = test_context();

    let profile1 =
        login_profile_builder::build_login_profile(&key("alice"), false, &context).unwrap();

    store.create_login_profile(profile1).await.unwrap();

    // A second create for the same user is refused: an overwrite would let
    // anyone able to create a profile replace the owner's password (wami 005).
    let profile2 =
        login_profile_builder::build_login_profile(&key("alice"), true, &context).unwrap();

    let second = store.create_login_profile(profile2).await;
    assert!(
        matches!(
            second,
            Err(wami_core::error::AmiError::ResourceExists { .. })
        ),
        "{second:?}"
    );

    // The first profile is unchanged.
    let retrieved = store
        .get_login_profile(&key("alice"))
        .await
        .unwrap()
        .unwrap();
    assert!(!retrieved.password_reset_required);
}
