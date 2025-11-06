//! User Builder Functions

use super::model::User;
use crate::arn::{Service, WamiArn};
use crate::context::WamiContext;
use crate::error::Result;
use crate::provider::{CloudProvider, ResourceType};
use chrono::Utc;
use uuid::Uuid;

/// Build a new User with context-based identifiers
#[allow(clippy::result_large_err)]
pub fn build_user(user_name: String, path: Option<String>, context: &WamiContext) -> Result<User> {
    let user_id = Uuid::new_v4().to_string();
    let path = path.unwrap_or_else(|| "/".to_string());

    // Build WAMI ARN using context
    let wami_arn = WamiArn::builder()
        .service(Service::Iam)
        .tenant_path(context.tenant_path().clone())
        .wami_instance(context.instance_id())
        .resource("user", &user_id)
        .build()?;

    // Generate AWS-compatible ARN (for backward compatibility)
    let arn = format!(
        "arn:aws:iam::{}:user{}/{}",
        context.instance_id(),
        if path == "/" { "" } else { &path },
        user_name
    );

    Ok(User {
        user_name,
        user_id,
        arn,
        path,
        create_date: Utc::now(),
        password_last_used: None,
        permissions_boundary: None,
        tags: vec![],
        wami_arn,
        providers: Vec::new(),
        tenant_id: None,
    })
}

/// Build a new User with provider-specific identifiers (legacy)
#[deprecated(note = "Use build_user with WamiContext instead")]
pub fn build_user_legacy(
    user_name: String,
    path: Option<String>,
    provider: &dyn CloudProvider,
    account_id: &str,
) -> User {
    let user_id = provider.generate_resource_id(ResourceType::User);
    let path = path.unwrap_or_else(|| "/".to_string());
    let arn =
        provider.generate_resource_identifier(ResourceType::User, account_id, &path, &user_name);
    let wami_arn_str =
        provider.generate_wami_arn(ResourceType::User, account_id, &path, &user_name);

    // Parse the wami_arn string to WamiArn
    let wami_arn = wami_arn_str.parse().unwrap_or_else(|_| {
        // Fallback: create a basic ARN
        WamiArn::builder()
            .service(Service::Iam)
            .tenant(12345678u64) // Test tenant ID
            .wami_instance(account_id)
            .resource("user", &user_id)
            .build()
            .expect("Failed to build fallback ARN")
    });

    User {
        user_name,
        user_id,
        arn,
        path,
        create_date: Utc::now(),
        password_last_used: None,
        permissions_boundary: None,
        tags: vec![],
        wami_arn,
        providers: Vec::new(),
        tenant_id: None,
    }
}

/// Update user's name (pure transformation)
pub fn update_user_name(mut user: User, new_name: String) -> User {
    user.user_name = new_name;
    user
}

/// Update user's path (pure transformation)
pub fn update_user_path(mut user: User, new_path: String) -> User {
    user.path = new_path;
    user
}

/// Add provider info to user (pure transformation)
pub fn add_provider_to_user(
    mut user: User,
    provider_config: crate::provider::ProviderConfig,
) -> User {
    if !user
        .providers
        .iter()
        .any(|p| p.provider_name == provider_config.provider_name)
    {
        user.providers.push(provider_config);
    }
    user
}

/// Set user's tenant ID (pure transformation)
pub fn set_tenant_id(mut user: User, tenant_id: crate::wami::tenant::TenantId) -> User {
    user.tenant_id = Some(tenant_id);
    user
}

/// Clear user's permissions boundary (pure transformation)
pub fn clear_permissions_boundary(mut user: User) -> User {
    user.permissions_boundary = None;
    user
}

/// Set user's permissions boundary (pure transformation)
pub fn set_permissions_boundary(mut user: User, boundary_arn: String) -> User {
    user.permissions_boundary = Some(boundary_arn);
    user
}

/// Add tags to user (pure transformation)
pub fn add_tags(mut user: User, tags: Vec<crate::types::Tag>) -> User {
    for tag in tags {
        if !user.tags.iter().any(|t| t.key == tag.key) {
            user.tags.push(tag);
        }
    }
    user
}

/// Remove tags from user (pure transformation)
pub fn remove_tags(mut user: User, tag_keys: &[String]) -> User {
    user.tags.retain(|tag| !tag_keys.contains(&tag.key));
    user
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arn::TenantPath;
    use crate::types::Tag;
    use crate::wami::tenant::TenantId;

    fn test_context() -> WamiContext {
        let user_arn: WamiArn = "arn:wami:iam:12345678:wami:999:user/test".parse().unwrap();
        WamiContext::builder()
            .instance_id("999888777")
            .tenant_path(TenantPath::single(12345678))
            .caller_arn(user_arn)
            .is_root(false)
            .build()
            .unwrap()
    }

    #[test]
    fn test_build_user() {
        let context = test_context();
        let user = build_user("alice".to_string(), None, &context).unwrap();

        assert_eq!(user.user_name, "alice");
        assert_eq!(user.path, "/");
        assert!(!user.user_id.is_empty());
        assert!(user.arn.contains("alice"));
        assert_eq!(user.wami_arn.resource.resource_type, "user");
        assert!(user.permissions_boundary.is_none());
        assert!(user.tags.is_empty());
        assert!(user.tenant_id.is_none());
    }

    #[test]
    fn test_build_user_with_custom_path() {
        let context = test_context();
        let user = build_user(
            "bob".to_string(),
            Some("/engineering/".to_string()),
            &context,
        )
        .unwrap();

        assert_eq!(user.user_name, "bob");
        assert_eq!(user.path, "/engineering/");
    }

    #[test]
    fn test_build_user_with_defaults() {
        let context = test_context();
        let user = build_user("test".to_string(), None, &context).unwrap();

        assert!(user.password_last_used.is_none());
        assert!(user.permissions_boundary.is_none());
        assert_eq!(user.tags.len(), 0);
        assert_eq!(user.providers.len(), 0);
        assert!(user.tenant_id.is_none());
    }

    #[test]
    fn test_update_user_name() {
        let context = test_context();
        let user = build_user("old".to_string(), None, &context).unwrap();
        let updated = update_user_name(user, "new".to_string());

        assert_eq!(updated.user_name, "new");
    }

    #[test]
    fn test_update_user_path() {
        let context = test_context();
        let user = build_user("alice".to_string(), None, &context).unwrap();
        let updated = update_user_path(user, "/admin/".to_string());

        assert_eq!(updated.path, "/admin/");
    }

    #[test]
    fn test_add_provider_to_user() {
        let context = test_context();
        let user = build_user("alice".to_string(), None, &context).unwrap();

        let provider_config = crate::provider::ProviderConfig {
            provider_name: "aws".to_string(),
            account_id: "123456789012".to_string(),
            native_arn: "arn:aws:iam::123456789012:user/alice".to_string(),
            synced_at: chrono::Utc::now(),
            tenant_id: None,
        };

        let updated = add_provider_to_user(user, provider_config);
        assert_eq!(updated.providers.len(), 1);
        assert_eq!(updated.providers[0].provider_name, "aws");
    }

    #[test]
    fn test_build_user_empty_name() {
        let context = test_context();
        // Empty user name should still work (no validation in builder)
        let user = build_user("".to_string(), None, &context).unwrap();
        assert_eq!(user.user_name, "");
        assert!(!user.user_id.is_empty());
    }

    #[test]
    fn test_build_user_empty_path() {
        let context = test_context();
        // Empty string path is used as-is (only None defaults to "/")
        let user = build_user("alice".to_string(), Some("".to_string()), &context).unwrap();
        assert_eq!(user.path, "");
    }

    #[test]
    fn test_build_user_invalid_path_format() {
        let context = test_context();
        // Path without leading slash should still work (builder doesn't validate format)
        let user = build_user(
            "alice".to_string(),
            Some("engineering".to_string()),
            &context,
        )
        .unwrap();
        assert_eq!(user.path, "engineering");
    }

    #[test]
    fn test_build_user_very_long_name() {
        let context = test_context();
        let long_name = "a".repeat(1000);
        let user = build_user(long_name.clone(), None, &context).unwrap();
        assert_eq!(user.user_name, long_name);
    }

    #[test]
    fn test_build_user_special_characters_in_name() {
        let context = test_context();
        // User names with special characters should work
        let user = build_user("user+test@example.com".to_string(), None, &context).unwrap();
        assert_eq!(user.user_name, "user+test@example.com");
    }

    #[test]
    fn test_build_user_with_whitespace_only_path() {
        let context = test_context();
        // Whitespace-only path should be used as-is (not defaulted)
        let user = build_user("alice".to_string(), Some("   ".to_string()), &context).unwrap();
        assert_eq!(user.path, "   ");
    }

    #[test]
    fn test_build_user_with_newline_in_path() {
        let context = test_context();
        // Paths with newlines should be handled
        let user = build_user(
            "alice".to_string(),
            Some("/path\nwith\nnewline/".to_string()),
            &context,
        )
        .unwrap();
        assert_eq!(user.path, "/path\nwith\nnewline/");
    }

    #[test]
    fn test_build_user_with_unicode_in_name() {
        let context = test_context();
        // Unicode characters should be handled
        let user = build_user("用户".to_string(), None, &context).unwrap();
        assert_eq!(user.user_name, "用户");
    }

    #[test]
    fn test_build_user_with_unicode_in_path() {
        let context = test_context();
        // Unicode in paths should be handled
        let user = build_user("alice".to_string(), Some("/路径/".to_string()), &context).unwrap();
        assert_eq!(user.path, "/路径/");
    }

    #[test]
    fn test_build_user_path_with_trailing_slash_edge_cases() {
        let context = test_context();
        // Multiple trailing slashes
        let user = build_user("alice".to_string(), Some("///".to_string()), &context).unwrap();
        assert_eq!(user.path, "///");

        // Path that is just a slash
        let user2 = build_user("bob".to_string(), Some("/".to_string()), &context).unwrap();
        assert_eq!(user2.path, "/");
    }

    #[test]
    fn test_build_user_with_context_whitespace_instance_id() {
        // This should fail when building context, but test what happens if it doesn't
        let user_arn: WamiArn = "arn:wami:iam:12345678:wami:999:user/test".parse().unwrap();
        let context_result = WamiContext::builder()
            .instance_id("   ".to_string()) // Whitespace-only
            .tenant_path(TenantPath::single(12345678))
            .caller_arn(user_arn)
            .is_root(false)
            .build();

        // Should fail because instance_id.trim().is_empty()
        assert!(context_result.is_err());
    }

    #[test]
    fn test_build_user_with_context_empty_instance_id_after_trim() {
        let user_arn: WamiArn = "arn:wami:iam:12345678:wami:999:user/test".parse().unwrap();
        let context_result = WamiContext::builder()
            .instance_id("\t\n\r ".to_string()) // Only whitespace
            .tenant_path(TenantPath::single(12345678))
            .caller_arn(user_arn)
            .is_root(false)
            .build();

        // Should fail
        assert!(context_result.is_err());
    }

    #[test]
    fn test_build_user_with_empty_tenant_path() {
        // Test what happens if tenant_path is empty (should fail in ARN building)
        let user_arn: WamiArn = "arn:wami:iam:12345678:wami:999:user/test".parse().unwrap();
        let context_result = WamiContext::builder()
            .instance_id("123456789012")
            .tenant_path(TenantPath::new(vec![])) // Empty tenant path
            .caller_arn(user_arn)
            .is_root(false)
            .build();

        // Context might build, but ARN building should fail
        if let Ok(context) = context_result {
            let user_result = build_user("alice".to_string(), None, &context);
            // ARN building should fail because tenant_path is empty
            assert!(user_result.is_err());
        }
    }

    #[test]
    fn test_add_provider_duplicate() {
        let context = test_context();
        let user = build_user("alice".to_string(), None, &context).unwrap();

        let provider_config = crate::provider::ProviderConfig {
            provider_name: "aws".to_string(),
            account_id: "123456789012".to_string(),
            native_arn: "arn:aws:iam::123456789012:user/alice".to_string(),
            synced_at: chrono::Utc::now(),
            tenant_id: None,
        };

        let updated = add_provider_to_user(user, provider_config.clone());
        let updated = add_provider_to_user(updated, provider_config);

        // Should not add duplicate
        assert_eq!(updated.providers.len(), 1);
    }

    #[test]
    fn test_set_tenant_id() {
        let context = test_context();
        let user = build_user("alice".to_string(), None, &context).unwrap();
        let tenant_id = TenantId::root(); // Test with root tenant

        let updated = set_tenant_id(user, tenant_id.clone());
        assert_eq!(updated.tenant_id, Some(tenant_id));
    }

    #[test]
    fn test_clear_permissions_boundary() {
        let context = test_context();
        let mut user = build_user("alice".to_string(), None, &context).unwrap();
        user.permissions_boundary = Some("arn:aws:iam::123:policy/boundary".to_string());

        let updated = clear_permissions_boundary(user);
        assert!(updated.permissions_boundary.is_none());
    }

    #[test]
    fn test_set_permissions_boundary() {
        let context = test_context();
        let user = build_user("alice".to_string(), None, &context).unwrap();

        let updated =
            set_permissions_boundary(user, "arn:aws:iam::123:policy/boundary".to_string());
        assert_eq!(
            updated.permissions_boundary,
            Some("arn:aws:iam::123:policy/boundary".to_string())
        );
    }

    #[test]
    fn test_add_tags() {
        let context = test_context();
        let user = build_user("alice".to_string(), None, &context).unwrap();

        let tags = vec![
            Tag {
                key: "Env".to_string(),
                value: "Prod".to_string(),
            },
            Tag {
                key: "Team".to_string(),
                value: "Backend".to_string(),
            },
        ];

        let updated = add_tags(user, tags);
        assert_eq!(updated.tags.len(), 2);
    }

    #[test]
    fn test_add_tags_no_duplicates() {
        let context = test_context();
        let user = build_user("alice".to_string(), None, &context).unwrap();

        let tags1 = vec![Tag {
            key: "Env".to_string(),
            value: "Prod".to_string(),
        }];
        let tags2 = vec![Tag {
            key: "Env".to_string(),
            value: "Dev".to_string(),
        }];

        let updated = add_tags(user, tags1);
        let updated = add_tags(updated, tags2);

        // Should not add duplicate key
        assert_eq!(updated.tags.len(), 1);
        assert_eq!(updated.tags[0].value, "Prod"); // Keeps first value
    }

    #[test]
    fn test_remove_tags() {
        let context = test_context();
        let user = build_user("alice".to_string(), None, &context).unwrap();

        let tags = vec![
            Tag {
                key: "Env".to_string(),
                value: "Prod".to_string(),
            },
            Tag {
                key: "Team".to_string(),
                value: "Backend".to_string(),
            },
            Tag {
                key: "Project".to_string(),
                value: "WAMI".to_string(),
            },
        ];

        let updated = add_tags(user, tags);
        let updated = remove_tags(updated, &["Team".to_string()]);

        assert_eq!(updated.tags.len(), 2);
        assert!(!updated.tags.iter().any(|t| t.key == "Team"));
    }

    #[test]
    fn test_remove_tags_multiple() {
        let context = test_context();
        let user = build_user("alice".to_string(), None, &context).unwrap();

        let tags = vec![
            Tag {
                key: "A".to_string(),
                value: "1".to_string(),
            },
            Tag {
                key: "B".to_string(),
                value: "2".to_string(),
            },
            Tag {
                key: "C".to_string(),
                value: "3".to_string(),
            },
        ];

        let updated = add_tags(user, tags);
        let updated = remove_tags(updated, &["A".to_string(), "C".to_string()]);

        assert_eq!(updated.tags.len(), 1);
        assert_eq!(updated.tags[0].key, "B");
    }

    #[test]
    fn test_remove_tags_nonexistent() {
        let context = test_context();
        let user = build_user("alice".to_string(), None, &context).unwrap();

        let tags = vec![Tag {
            key: "A".to_string(),
            value: "1".to_string(),
        }];
        let updated = add_tags(user, tags);
        let updated = remove_tags(updated, &["Z".to_string()]);

        // Should not affect existing tags
        assert_eq!(updated.tags.len(), 1);
    }
}
