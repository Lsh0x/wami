//! Tests for Identity Store Implementations
//!
//! Tests for UserStore, GroupStore, RoleStore, and ServiceLinkedRoleStore

use crate::arn::{TenantPath, WamiArn};
use crate::context::WamiContext;
use crate::store::memory::InMemoryWamiStore;
use crate::store::traits::{GroupStore, RoleStore, ServiceLinkedRoleStore, UserStore};
use crate::wami::identity::group::builder as group_builder;
use crate::wami::identity::role::builder as role_builder;
use crate::wami::identity::service_linked_role::builder as slr_builder;
use crate::wami::identity::user::builder as user_builder;
use wami_core::types::{PaginationParams, Tag};

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
// USER STORE TESTS
// ============================================================================

#[tokio::test]
async fn test_user_create_and_get() {
    let mut store = InMemoryWamiStore::new();
    let context = test_context();

    let user =
        user_builder::build_user("alice".to_string(), Some("/".to_string()), &context).unwrap();

    // Create user
    let created = store.create_user(user.clone()).await.unwrap();
    assert_eq!(created.user_name, "alice");

    // Get user
    let retrieved = store.get_user("alice").await.unwrap();
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().user_name, "alice");
}

#[tokio::test]
async fn test_user_get_nonexistent() {
    let store = InMemoryWamiStore::new();

    let result = store.get_user("nonexistent").await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_user_update() {
    let mut store = InMemoryWamiStore::new();
    let context = test_context();

    let user =
        user_builder::build_user("bob".to_string(), Some("/".to_string()), &context).unwrap();

    store.create_user(user.clone()).await.unwrap();

    // Update user
    let updated = user_builder::update_user_path(user, "/admin/".to_string());
    let result = store.update_user(updated).await.unwrap();

    assert_eq!(result.path, "/admin/");

    // Verify update persisted
    let retrieved = store.get_user("bob").await.unwrap().unwrap();
    assert_eq!(retrieved.path, "/admin/");
}

#[tokio::test]
async fn test_user_delete() {
    let mut store = InMemoryWamiStore::new();
    let context = test_context();

    let user =
        user_builder::build_user("charlie".to_string(), Some("/".to_string()), &context).unwrap();

    store.create_user(user).await.unwrap();

    // Delete user
    store.delete_user("charlie").await.unwrap();

    // Verify deleted
    let result = store.get_user("charlie").await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_user_list_empty() {
    let store = InMemoryWamiStore::new();

    let (users, is_truncated, marker) = store.list_users(None, None).await.unwrap();

    assert_eq!(users.len(), 0);
    assert!(!is_truncated);
    assert!(marker.is_none());
}

#[tokio::test]
async fn test_user_list_multiple() {
    let mut store = InMemoryWamiStore::new();
    let context = test_context();

    // Create multiple users
    for name in &["alice", "bob", "charlie", "david"] {
        let user =
            user_builder::build_user(name.to_string(), Some("/".to_string()), &context).unwrap();
        store.create_user(user).await.unwrap();
    }

    let (users, is_truncated, _) = store.list_users(None, None).await.unwrap();

    assert_eq!(users.len(), 4);
    assert!(!is_truncated);
    // Should be sorted by name
    assert_eq!(users[0].user_name, "alice");
    assert_eq!(users[3].user_name, "david");
}

#[tokio::test]
async fn test_user_list_with_path_prefix() {
    let mut store = InMemoryWamiStore::new();
    let context = test_context();

    let user1 =
        user_builder::build_user("admin1".to_string(), Some("/admin/".to_string()), &context)
            .unwrap();
    let user2 =
        user_builder::build_user("user1".to_string(), Some("/users/".to_string()), &context)
            .unwrap();
    let user3 =
        user_builder::build_user("admin2".to_string(), Some("/admin/".to_string()), &context)
            .unwrap();

    store.create_user(user1).await.unwrap();
    store.create_user(user2).await.unwrap();
    store.create_user(user3).await.unwrap();

    let (users, _, _) = store.list_users(Some("/admin/"), None).await.unwrap();

    assert_eq!(users.len(), 2);
    assert!(users.iter().all(|u| u.path.starts_with("/admin/")));
}

#[tokio::test]
async fn test_user_list_with_pagination() {
    let mut store = InMemoryWamiStore::new();
    let context = test_context();

    // Create 10 users
    for i in 0..10 {
        let user =
            user_builder::build_user(format!("user{:02}", i), Some("/".to_string()), &context)
                .unwrap();
        store.create_user(user).await.unwrap();
    }

    let pagination = PaginationParams {
        max_items: Some(5),
        marker: None,
    };

    let (users, is_truncated, marker) = store.list_users(None, Some(&pagination)).await.unwrap();

    assert_eq!(users.len(), 5);
    assert!(is_truncated);
    assert!(marker.is_some());
}

#[tokio::test]
async fn test_user_tag_operations() {
    let mut store = InMemoryWamiStore::new();
    let context = test_context();

    let user =
        user_builder::build_user("alice".to_string(), Some("/".to_string()), &context).unwrap();

    store.create_user(user).await.unwrap();

    // Add tags
    let tags = vec![
        Tag {
            key: "Environment".to_string(),
            value: "Production".to_string(),
        },
        Tag {
            key: "Team".to_string(),
            value: "Backend".to_string(),
        },
    ];

    store.tag_user("alice", tags).await.unwrap();

    // List tags
    let retrieved_tags = store.list_user_tags("alice").await.unwrap();
    assert_eq!(retrieved_tags.len(), 2);

    // Untag
    store
        .untag_user("alice", vec!["Team".to_string()])
        .await
        .unwrap();

    let remaining_tags = store.list_user_tags("alice").await.unwrap();
    assert_eq!(remaining_tags.len(), 1);
    assert_eq!(remaining_tags[0].key, "Environment");
}

// ============================================================================
// GROUP STORE TESTS
// ============================================================================

#[tokio::test]
async fn test_group_create_and_get() {
    let mut store = InMemoryWamiStore::new();
    let context = test_context();

    let group =
        group_builder::build_group("admins".to_string(), Some("/".to_string()), &context).unwrap();

    let created = store.create_group(group.clone()).await.unwrap();
    assert_eq!(created.group_name, "admins");

    let retrieved = store.get_group("admins").await.unwrap();
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().group_name, "admins");
}

#[tokio::test]
async fn test_group_delete() {
    let mut store = InMemoryWamiStore::new();
    let context = test_context();

    let group =
        group_builder::build_group("devs".to_string(), Some("/".to_string()), &context).unwrap();

    store.create_group(group).await.unwrap();
    store.delete_group("devs").await.unwrap();

    let result = store.get_group("devs").await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_group_list() {
    let mut store = InMemoryWamiStore::new();
    let context = test_context();

    for name in &["admins", "devs", "ops"] {
        let group =
            group_builder::build_group(name.to_string(), Some("/".to_string()), &context).unwrap();
        store.create_group(group).await.unwrap();
    }

    let (groups, is_truncated, _) = store.list_groups(None, None).await.unwrap();

    assert_eq!(groups.len(), 3);
    assert!(!is_truncated);
}

#[tokio::test]
async fn test_group_user_membership() {
    let mut store = InMemoryWamiStore::new();
    let context = test_context();

    let user =
        user_builder::build_user("alice".to_string(), Some("/".to_string()), &context).unwrap();
    let group =
        group_builder::build_group("admins".to_string(), Some("/".to_string()), &context).unwrap();

    store.create_user(user).await.unwrap();
    store.create_group(group).await.unwrap();

    // Add user to group
    store.add_user_to_group("admins", "alice").await.unwrap();

    // List groups for user
    let groups = store.list_groups_for_user("alice").await.unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].group_name, "admins");

    // Remove user from group
    store
        .remove_user_from_group("admins", "alice")
        .await
        .unwrap();

    let groups_after = store.list_groups_for_user("alice").await.unwrap();
    assert_eq!(groups_after.len(), 0);
}

#[tokio::test]
async fn test_group_list_with_filters_and_pagination() {
    let mut store = InMemoryWamiStore::new();
    let context = test_context();

    let engineering = group_builder::build_group(
        "eng-admins".to_string(),
        Some("/engineering/".to_string()),
        &context,
    )
    .unwrap();
    let engineering_ops = group_builder::build_group(
        "eng-ops".to_string(),
        Some("/engineering/".to_string()),
        &context,
    )
    .unwrap();
    let finance = group_builder::build_group(
        "finance".to_string(),
        Some("/finance/".to_string()),
        &context,
    )
    .unwrap();

    for group in [engineering, engineering_ops, finance] {
        store.create_group(group).await.unwrap();
    }

    let (filtered, _, _) = store
        .list_groups(Some("/engineering/"), None)
        .await
        .unwrap();
    assert_eq!(filtered.len(), 2);
    assert!(filtered
        .iter()
        .all(|group| group.path.starts_with("/engineering/")));

    let pagination = PaginationParams {
        max_items: Some(2),
        marker: None,
    };

    let (page, truncated, marker) = store.list_groups(None, Some(&pagination)).await.unwrap();

    assert_eq!(page.len(), 2);
    assert!(truncated);
    assert_eq!(
        marker.as_deref(),
        Some(page.last().unwrap().group_name.as_str())
    );
}

#[tokio::test]
async fn test_group_policy_management() {
    let mut store = InMemoryWamiStore::new();
    let context = test_context();

    let group =
        group_builder::build_group("admins".to_string(), Some("/".to_string()), &context).unwrap();
    store.create_group(group).await.unwrap();

    let policy_admin = "arn:aws:iam::aws:policy/AdministratorAccess";
    let policy_read_only = "arn:aws:iam::aws:policy/ReadOnlyAccess";

    store
        .attach_group_policy("admins", policy_admin)
        .await
        .unwrap();
    // Attaching the same policy twice should not create duplicates
    store
        .attach_group_policy("admins", policy_admin)
        .await
        .unwrap();
    store
        .attach_group_policy("admins", policy_read_only)
        .await
        .unwrap();

    let attached = store.list_attached_group_policies("admins").await.unwrap();
    assert_eq!(
        attached,
        vec![policy_admin.to_string(), policy_read_only.to_string()]
    );

    store
        .detach_group_policy("admins", policy_admin)
        .await
        .unwrap();

    let remaining = store.list_attached_group_policies("admins").await.unwrap();
    assert_eq!(remaining, vec![policy_read_only.to_string()]);

    store
        .detach_group_policy("admins", policy_admin)
        .await
        .unwrap();
    let unchanged = store.list_attached_group_policies("admins").await.unwrap();
    assert_eq!(unchanged, vec![policy_read_only.to_string()]);
}

#[tokio::test]
async fn test_group_inline_policy_management() {
    let mut store = InMemoryWamiStore::new();
    let context = test_context();

    let group =
        group_builder::build_group("analytics".to_string(), Some("/".to_string()), &context)
            .unwrap();
    store.create_group(group).await.unwrap();

    store
        .put_group_policy("analytics", "InlinePolicyA", "{}".to_string())
        .await
        .unwrap();
    store
        .put_group_policy(
            "analytics",
            "InlinePolicyB",
            "{\"Statement\":[]}".to_string(),
        )
        .await
        .unwrap();

    let document = store
        .get_group_policy("analytics", "InlinePolicyA")
        .await
        .unwrap();
    assert_eq!(document.as_deref(), Some("{}"));

    let mut policy_names = store.list_group_policies("analytics").await.unwrap();
    policy_names.sort();
    assert_eq!(
        policy_names,
        vec!["InlinePolicyA".to_string(), "InlinePolicyB".to_string()]
    );

    store
        .delete_group_policy("analytics", "InlinePolicyA")
        .await
        .unwrap();
    let after_delete = store
        .get_group_policy("analytics", "InlinePolicyA")
        .await
        .unwrap();
    assert!(after_delete.is_none());
}

// ============================================================================
// ROLE STORE TESTS
// ============================================================================

#[tokio::test]
async fn test_role_create_and_get() {
    let mut store = InMemoryWamiStore::new();
    let context = test_context();

    let trust_policy = r#"{"Version":"2012-10-17"}"#.to_string();
    let role = role_builder::build_role(
        "admin-role".to_string(),
        trust_policy,
        Some("/".to_string()),
        Some("Administrator role".to_string()),
        Some(3600),
        &context,
    )
    .unwrap();

    let created = store.create_role(role.clone()).await.unwrap();
    assert_eq!(created.role_name, "admin-role");

    let retrieved = store.get_role("admin-role").await.unwrap();
    assert!(retrieved.is_some());
    assert_eq!(
        retrieved.unwrap().description,
        Some("Administrator role".to_string())
    );
}

#[tokio::test]
async fn test_role_update() {
    let mut store = InMemoryWamiStore::new();
    let context = test_context();

    let trust_policy = r#"{"Version":"2012-10-17"}"#.to_string();
    let role = role_builder::build_role(
        "test-role".to_string(),
        trust_policy,
        Some("/".to_string()),
        None,
        None,
        &context,
    )
    .unwrap();

    store.create_role(role.clone()).await.unwrap();

    let updated = role_builder::update_description(role, Some("Updated description".to_string()));
    store.update_role(updated).await.unwrap();

    let retrieved = store.get_role("test-role").await.unwrap().unwrap();
    assert_eq!(
        retrieved.description,
        Some("Updated description".to_string())
    );
}

#[tokio::test]
async fn test_role_delete() {
    let mut store = InMemoryWamiStore::new();
    let context = test_context();

    let trust_policy = r#"{"Version":"2012-10-17"}"#.to_string();
    let role = role_builder::build_role(
        "temp-role".to_string(),
        trust_policy,
        Some("/".to_string()),
        None,
        None,
        &context,
    )
    .unwrap();

    store.create_role(role).await.unwrap();
    store.delete_role("temp-role").await.unwrap();

    let result = store.get_role("temp-role").await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_role_list_multiple() {
    let mut store = InMemoryWamiStore::new();
    let context = test_context();
    let trust_policy = r#"{"Version":"2012-10-17"}"#.to_string();

    for name in &["role-a", "role-b", "role-c"] {
        let role = role_builder::build_role(
            name.to_string(),
            trust_policy.clone(),
            Some("/".to_string()),
            None,
            None,
            &context,
        )
        .unwrap();
        store.create_role(role).await.unwrap();
    }

    let (roles, is_truncated, _) = store.list_roles(None, None).await.unwrap();

    assert_eq!(roles.len(), 3);
    assert!(!is_truncated);
}

#[tokio::test]
async fn test_role_with_path_prefix() {
    let mut store = InMemoryWamiStore::new();
    let context = test_context();
    let trust_policy = r#"{"Version":"2012-10-17"}"#.to_string();

    let role1 = role_builder::build_role(
        "service-role".to_string(),
        trust_policy.clone(),
        Some("/service/".to_string()),
        None,
        None,
        &context,
    )
    .unwrap();
    let role2 = role_builder::build_role(
        "admin-role".to_string(),
        trust_policy,
        Some("/admin/".to_string()),
        None,
        None,
        &context,
    )
    .unwrap();

    store.create_role(role1).await.unwrap();
    store.create_role(role2).await.unwrap();

    let (roles, _, _) = store.list_roles(Some("/service/"), None).await.unwrap();

    assert_eq!(roles.len(), 1);
    assert_eq!(roles[0].role_name, "service-role");
}

#[tokio::test]
async fn test_role_list_with_pagination() {
    let mut store = InMemoryWamiStore::new();
    let context = test_context();
    let trust_policy = r#"{"Version":"2012-10-17"}"#.to_string();

    for name in ["role-a", "role-b", "role-c"] {
        let role = role_builder::build_role(
            name.to_string(),
            trust_policy.clone(),
            Some("/".to_string()),
            None,
            None,
            &context,
        )
        .unwrap();
        store.create_role(role).await.unwrap();
    }

    let pagination = PaginationParams {
        max_items: Some(2),
        marker: None,
    };

    let (page, truncated, marker) = store.list_roles(None, Some(&pagination)).await.unwrap();

    assert_eq!(page.len(), 2);
    assert!(truncated);
    assert_eq!(
        marker.as_deref(),
        Some(page.last().unwrap().role_name.as_str())
    );
}

#[tokio::test]
async fn test_role_policy_management() {
    let mut store = InMemoryWamiStore::new();
    let context = test_context();
    let trust_policy = r#"{"Version":"2012-10-17"}"#.to_string();

    let role = role_builder::build_role(
        "analytics-role".to_string(),
        trust_policy,
        Some("/".to_string()),
        None,
        None,
        &context,
    )
    .unwrap();

    store.create_role(role).await.unwrap();

    let policy_admin = "arn:aws:iam::aws:policy/AdministratorAccess";
    let policy_security = "arn:aws:iam::aws:policy/SecurityAudit";

    store
        .attach_role_policy("analytics-role", policy_admin)
        .await
        .unwrap();
    store
        .attach_role_policy("analytics-role", policy_admin)
        .await
        .unwrap();
    store
        .attach_role_policy("analytics-role", policy_security)
        .await
        .unwrap();

    let attached = store
        .list_attached_role_policies("analytics-role")
        .await
        .unwrap();
    assert_eq!(
        attached,
        vec![policy_admin.to_string(), policy_security.to_string()]
    );

    store
        .detach_role_policy("analytics-role", policy_admin)
        .await
        .unwrap();

    let remaining = store
        .list_attached_role_policies("analytics-role")
        .await
        .unwrap();
    assert_eq!(remaining, vec![policy_security.to_string()]);
}

#[tokio::test]
async fn test_role_inline_policy_management() {
    let mut store = InMemoryWamiStore::new();
    let context = test_context();
    let trust_policy = r#"{"Version":"2012-10-17"}"#.to_string();

    let role = role_builder::build_role(
        "inline-role".to_string(),
        trust_policy,
        Some("/".to_string()),
        None,
        None,
        &context,
    )
    .unwrap();
    store.create_role(role).await.unwrap();

    store
        .put_role_policy("inline-role", "PolicyA", "{}".to_string())
        .await
        .unwrap();
    store
        .put_role_policy(
            "inline-role",
            "PolicyB",
            "{\"Statement\":[{\"Effect\":\"Allow\"}]}".to_string(),
        )
        .await
        .unwrap();

    let policy = store
        .get_role_policy("inline-role", "PolicyB")
        .await
        .unwrap();
    assert!(policy.as_deref().unwrap().contains("\"Effect\":\"Allow\""));

    let mut names = store.list_role_policies("inline-role").await.unwrap();
    names.sort();
    assert_eq!(names, vec!["PolicyA".to_string(), "PolicyB".to_string()]);

    store
        .delete_role_policy("inline-role", "PolicyA")
        .await
        .unwrap();
    let deleted = store
        .get_role_policy("inline-role", "PolicyA")
        .await
        .unwrap();
    assert!(deleted.is_none());
}

// ============================================================================
// SERVICE-LINKED ROLE STORE TESTS
// ============================================================================

#[tokio::test]
async fn test_service_linked_role_deletion_task() {
    let mut store = InMemoryWamiStore::new();
    let _context = test_context();

    let task = slr_builder::build_deletion_task("test-service-role".to_string());

    let task_id = task.deletion_task_id.clone();

    // Create deletion task
    store
        .create_service_linked_role_deletion_task(task.clone())
        .await
        .unwrap();

    // Get deletion task
    let retrieved = store
        .get_service_linked_role_deletion_task(&task_id)
        .await
        .unwrap();
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().role_name, "test-service-role");
}

#[tokio::test]
async fn test_service_linked_role_deletion_task_nonexistent() {
    let store = InMemoryWamiStore::new();

    let result = store
        .get_service_linked_role_deletion_task("nonexistent-task")
        .await
        .unwrap();
    assert!(result.is_none());
}

// ========== Edge Case Tests ==========

#[tokio::test]
async fn test_user_list_path_prefix_empty_string() {
    let mut store = InMemoryWamiStore::new();
    let context = test_context();

    let user1 =
        user_builder::build_user("user1".to_string(), Some("".to_string()), &context).unwrap();
    let user2 =
        user_builder::build_user("user2".to_string(), Some("/".to_string()), &context).unwrap();
    let user3 =
        user_builder::build_user("user3".to_string(), Some("/admin/".to_string()), &context)
            .unwrap();

    store.create_user(user1).await.unwrap();
    store.create_user(user2).await.unwrap();
    store.create_user(user3).await.unwrap();

    let (users, _, _) = store.list_users(Some(""), None).await.unwrap();
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].user_name, "user1");
}

#[tokio::test]
async fn test_user_list_pagination_max_items_zero() {
    let mut store = InMemoryWamiStore::new();
    let context = test_context();

    for i in 0..5 {
        let user = user_builder::build_user(format!("user{}", i), None, &context).unwrap();
        store.create_user(user).await.unwrap();
    }

    let pagination = PaginationParams {
        max_items: Some(0),
        marker: None,
    };

    let (users, is_truncated, marker) = store.list_users(None, Some(&pagination)).await.unwrap();
    assert_eq!(users.len(), 0);
    assert!(is_truncated);
    assert!(marker.is_none());
}

#[tokio::test]
async fn test_user_list_pagination_max_items_one() {
    let mut store = InMemoryWamiStore::new();
    let context = test_context();

    for i in 0..5 {
        let user = user_builder::build_user(format!("user{}", i), None, &context).unwrap();
        store.create_user(user).await.unwrap();
    }

    let pagination = PaginationParams {
        max_items: Some(1),
        marker: None,
    };

    let (users, is_truncated, marker) = store.list_users(None, Some(&pagination)).await.unwrap();
    assert_eq!(users.len(), 1);
    assert!(is_truncated);
    assert!(marker.is_some());
}

#[tokio::test]
async fn test_user_list_pagination_max_items_greater_than_total() {
    let mut store = InMemoryWamiStore::new();
    let context = test_context();

    for i in 0..3 {
        let user = user_builder::build_user(format!("user{}", i), None, &context).unwrap();
        store.create_user(user).await.unwrap();
    }

    let pagination = PaginationParams {
        max_items: Some(10),
        marker: None,
    };

    let (users, is_truncated, marker) = store.list_users(None, Some(&pagination)).await.unwrap();
    assert_eq!(users.len(), 3);
    assert!(!is_truncated);
    assert!(marker.is_none());
}

#[tokio::test]
async fn test_user_tag_operations_edge_cases() {
    let mut store = InMemoryWamiStore::new();
    let context = test_context();

    let user = user_builder::build_user("alice".to_string(), None, &context).unwrap();
    store.create_user(user).await.unwrap();

    // Tag with empty key should be handled
    let tags = vec![Tag {
        key: "".to_string(),
        value: "value".to_string(),
    }];
    store.tag_user("alice", tags).await.unwrap();

    // Untag with non-existent keys should not error
    store
        .untag_user("alice", vec!["NonexistentKey".to_string()])
        .await
        .unwrap();

    let remaining_tags = store.list_user_tags("alice").await.unwrap();
    assert_eq!(remaining_tags.len(), 1);
}

#[tokio::test]
async fn test_user_list_path_prefix_case_sensitive() {
    let mut store = InMemoryWamiStore::new();
    let context = test_context();

    let user1 =
        user_builder::build_user("user1".to_string(), Some("/Admin/".to_string()), &context)
            .unwrap();
    let user2 =
        user_builder::build_user("user2".to_string(), Some("/admin/".to_string()), &context)
            .unwrap();

    store.create_user(user1).await.unwrap();
    store.create_user(user2).await.unwrap();

    let (users, _, _) = store.list_users(Some("/admin/"), None).await.unwrap();
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].user_name, "user2");
}

#[tokio::test]
async fn test_user_list_path_prefix_partial_match() {
    let mut store = InMemoryWamiStore::new();
    let context = test_context();

    let user1 =
        user_builder::build_user("user1".to_string(), Some("/admin/".to_string()), &context)
            .unwrap();
    let user2 = user_builder::build_user(
        "user2".to_string(),
        Some("/admin/users/".to_string()),
        &context,
    )
    .unwrap();
    let user3 =
        user_builder::build_user("user3".to_string(), Some("/admins/".to_string()), &context)
            .unwrap();

    store.create_user(user1).await.unwrap();
    store.create_user(user2).await.unwrap();
    store.create_user(user3).await.unwrap();

    let (users, _, _) = store.list_users(Some("/admin/"), None).await.unwrap();
    assert_eq!(users.len(), 2);
    assert!(users.iter().all(|u| u.path.starts_with("/admin/")));
}

#[tokio::test]
async fn test_group_list_path_prefix_empty_string() {
    let mut store = InMemoryWamiStore::new();
    let context = test_context();

    let group1 =
        group_builder::build_group("group1".to_string(), Some("".to_string()), &context).unwrap();
    let group2 =
        group_builder::build_group("group2".to_string(), Some("/".to_string()), &context).unwrap();
    let group3 =
        group_builder::build_group("group3".to_string(), Some("/admin/".to_string()), &context)
            .unwrap();

    store.create_group(group1).await.unwrap();
    store.create_group(group2).await.unwrap();
    store.create_group(group3).await.unwrap();

    let (groups, _, _) = store.list_groups(Some(""), None).await.unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].group_name, "group1");
}

#[tokio::test]
async fn test_group_list_pagination_max_items_zero() {
    let mut store = InMemoryWamiStore::new();
    let context = test_context();

    for i in 0..5 {
        let group = group_builder::build_group(format!("group{}", i), None, &context).unwrap();
        store.create_group(group).await.unwrap();
    }

    let pagination = PaginationParams {
        max_items: Some(0),
        marker: None,
    };

    let (groups, is_truncated, marker) = store.list_groups(None, Some(&pagination)).await.unwrap();
    assert_eq!(groups.len(), 0);
    assert!(is_truncated);
    assert!(marker.is_none());
}

#[tokio::test]
async fn test_role_list_path_prefix_empty_string() {
    let mut store = InMemoryWamiStore::new();
    let context = test_context();
    let trust_policy = r#"{"Version":"2012-10-17"}"#.to_string();

    let role1 = role_builder::build_role(
        "role1".to_string(),
        trust_policy.clone(),
        Some("".to_string()),
        None,
        None,
        &context,
    )
    .unwrap();
    let role2 = role_builder::build_role(
        "role2".to_string(),
        trust_policy.clone(),
        Some("/".to_string()),
        None,
        None,
        &context,
    )
    .unwrap();
    let role3 = role_builder::build_role(
        "role3".to_string(),
        trust_policy,
        Some("/admin/".to_string()),
        None,
        None,
        &context,
    )
    .unwrap();

    store.create_role(role1).await.unwrap();
    store.create_role(role2).await.unwrap();
    store.create_role(role3).await.unwrap();

    let (roles, _, _) = store.list_roles(Some(""), None).await.unwrap();
    assert_eq!(roles.len(), 1);
    assert_eq!(roles[0].role_name, "role1");
}

#[tokio::test]
async fn test_role_list_pagination_max_items_zero() {
    let mut store = InMemoryWamiStore::new();
    let context = test_context();
    let trust_policy = r#"{"Version":"2012-10-17"}"#.to_string();

    for i in 0..5 {
        let role = role_builder::build_role(
            format!("role{}", i),
            trust_policy.clone(),
            None,
            None,
            None,
            &context,
        )
        .unwrap();
        store.create_role(role).await.unwrap();
    }

    let pagination = PaginationParams {
        max_items: Some(0),
        marker: None,
    };

    let (roles, is_truncated, marker) = store.list_roles(None, Some(&pagination)).await.unwrap();
    assert_eq!(roles.len(), 0);
    assert!(is_truncated);
    assert!(marker.is_none());
}
