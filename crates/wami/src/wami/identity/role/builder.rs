//! Role Builder Functions

use super::model::Role;
use crate::arn::{Service, WamiArn};
use crate::context::WamiContext;
use crate::error::Result;
use crate::provider::{CloudProvider, ResourceType};
use chrono::Utc;
use uuid::Uuid;

/// Build a new Role with context-based identifiers
#[allow(clippy::result_large_err)]
pub fn build_role(
    role_name: String,
    assume_role_policy_document: String,
    path: Option<String>,
    description: Option<String>,
    max_session_duration: Option<i32>,
    context: &WamiContext,
) -> Result<Role> {
    let role_id = Uuid::new_v4().to_string();
    let path = path.unwrap_or_else(|| "/".to_string());

    // Build WAMI ARN using context
    let wami_arn = WamiArn::builder()
        .service(Service::Iam)
        .tenant_path(context.tenant_path().clone())
        .wami_instance(context.instance_id())
        .resource("role", &role_id)
        .build()?;

    // Generate AWS-compatible ARN (for backward compatibility)
    let arn = format!(
        "arn:aws:iam::{}:role{}{}",
        context.instance_id(),
        if path == "/" { "" } else { &path },
        role_name
    );

    Ok(Role {
        role_name,
        role_id,
        arn,
        path,
        create_date: Utc::now(),
        assume_role_policy_document,
        description,
        max_session_duration,
        permissions_boundary: None,
        tags: vec![],
        wami_arn,
        providers: Vec::new(),
        tenant_id: None,
    })
}

/// Build a new Role with provider-specific identifiers (legacy)
#[deprecated(note = "Use build_role with WamiContext instead")]
pub fn build_role_legacy(
    role_name: String,
    assume_role_policy_document: String,
    path: Option<String>,
    description: Option<String>,
    max_session_duration: Option<i32>,
    provider: &dyn CloudProvider,
    account_id: &str,
) -> Role {
    let role_id = provider.generate_resource_id(ResourceType::Role);
    let path = path.unwrap_or_else(|| "/".to_string());
    let arn =
        provider.generate_resource_identifier(ResourceType::Role, account_id, &path, &role_name);
    let wami_arn_str =
        provider.generate_wami_arn(ResourceType::Role, account_id, &path, &role_name);

    // Parse the wami_arn string to WamiArn
    let wami_arn = wami_arn_str.parse().unwrap_or_else(|_| {
        // Fallback: create a basic ARN
        WamiArn::builder()
            .service(Service::Iam)
            .tenant(12345678u64) // Test tenant ID
            .wami_instance(account_id)
            .resource("role", &role_id)
            .build()
            .expect("Failed to build fallback ARN")
    });

    Role {
        role_name,
        role_id,
        arn,
        path,
        create_date: Utc::now(),
        assume_role_policy_document,
        description,
        max_session_duration,
        permissions_boundary: None,
        tags: vec![],
        wami_arn,
        providers: Vec::new(),
        tenant_id: None,
    }
}

/// Update role's assume role policy (pure transformation)
pub fn update_assume_role_policy(mut role: Role, new_policy: String) -> Role {
    role.assume_role_policy_document = new_policy;
    role
}

/// Update role's description (pure transformation)
pub fn update_description(mut role: Role, description: Option<String>) -> Role {
    role.description = description;
    role
}

/// Update role's max session duration (pure transformation)
pub fn update_max_session_duration(mut role: Role, duration: i32) -> Role {
    role.max_session_duration = Some(duration);
    role
}

/// Set role's permissions boundary (pure transformation)
pub fn set_permissions_boundary(mut role: Role, boundary_arn: String) -> Role {
    role.permissions_boundary = Some(boundary_arn);
    role
}

/// Clear role's permissions boundary (pure transformation)
pub fn clear_permissions_boundary(mut role: Role) -> Role {
    role.permissions_boundary = None;
    role
}

/// Add tags to role (pure transformation)
pub fn add_tags(mut role: Role, tags: Vec<crate::types::Tag>) -> Role {
    for tag in tags {
        if !role.tags.iter().any(|t| t.key == tag.key) {
            role.tags.push(tag);
        }
    }
    role
}

/// Set tenant ID (pure transformation)
pub fn set_tenant_id(mut role: Role, tenant_id: crate::wami::tenant::TenantId) -> Role {
    role.tenant_id = Some(tenant_id);
    role
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arn::TenantPath;
    use crate::types::Tag;
    use crate::wami::tenant::TenantId;

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

    fn test_trust_policy() -> String {
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#.to_string()
    }

    #[test]
    fn test_build_role_minimal() {
        let context = test_context();
        let role = build_role(
            "test-role".to_string(),
            test_trust_policy(),
            None,
            None,
            None,
            &context,
        )
        .unwrap();

        assert_eq!(role.role_name, "test-role");
        assert_eq!(role.path, "/");
        assert!(!role.role_id.is_empty());
        assert!(role.arn.contains("test-role"));
        assert!(role.description.is_none());
        assert!(role.max_session_duration.is_none());
        assert!(role.permissions_boundary.is_none());
        assert_eq!(role.tags.len(), 0);
    }

    #[test]
    fn test_build_role_with_all_options() {
        let context = test_context();
        let role = build_role(
            "admin-role".to_string(),
            test_trust_policy(),
            Some("/admin/".to_string()),
            Some("Administrator role".to_string()),
            Some(7200),
            &context,
        )
        .unwrap();

        assert_eq!(role.role_name, "admin-role");
        assert_eq!(role.path, "/admin/");
        assert_eq!(role.description, Some("Administrator role".to_string()));
        assert_eq!(role.max_session_duration, Some(7200));
    }

    #[test]
    fn test_update_assume_role_policy() {
        let context = test_context();
        let role = build_role(
            "test-role".to_string(),
            test_trust_policy(),
            None,
            None,
            None,
            &context,
        )
        .unwrap();

        let new_policy = r#"{"Version":"2012-10-17"}"#.to_string();
        let updated = update_assume_role_policy(role, new_policy.clone());

        assert_eq!(updated.assume_role_policy_document, new_policy);
    }

    #[test]
    fn test_update_description() {
        let context = test_context();
        let role = build_role(
            "test-role".to_string(),
            test_trust_policy(),
            None,
            None,
            None,
            &context,
        )
        .unwrap();

        let updated = update_description(role, Some("New description".to_string()));
        assert_eq!(updated.description, Some("New description".to_string()));

        let updated = update_description(updated, None);
        assert_eq!(updated.description, None);
    }

    #[test]
    fn test_update_max_session_duration() {
        let context = test_context();
        let role = build_role(
            "test-role".to_string(),
            test_trust_policy(),
            None,
            None,
            None,
            &context,
        )
        .unwrap();

        let updated = update_max_session_duration(role, 3600);
        assert_eq!(updated.max_session_duration, Some(3600));
    }

    #[test]
    fn test_build_role_empty_name() {
        let context = test_context();
        // Empty role name should still work
        let role = build_role(
            "".to_string(),
            test_trust_policy(),
            None,
            None,
            None,
            &context,
        )
        .unwrap();
        assert_eq!(role.role_name, "");
        assert!(!role.role_id.is_empty());
    }

    #[test]
    fn test_build_role_empty_path() {
        let context = test_context();
        // Empty string path is used as-is (only None defaults to "/")
        let role = build_role(
            "test-role".to_string(),
            test_trust_policy(),
            Some("".to_string()),
            None,
            None,
            &context,
        )
        .unwrap();
        assert_eq!(role.path, "");
    }

    #[test]
    fn test_build_role_invalid_path_format() {
        let context = test_context();
        // Path without leading slash should still work
        let role = build_role(
            "test-role".to_string(),
            test_trust_policy(),
            Some("engineering".to_string()),
            None,
            None,
            &context,
        )
        .unwrap();
        assert_eq!(role.path, "engineering");
    }

    #[test]
    fn test_build_role_very_long_name() {
        let context = test_context();
        let long_name = "a".repeat(1000);
        let role = build_role(
            long_name.clone(),
            test_trust_policy(),
            None,
            None,
            None,
            &context,
        )
        .unwrap();
        assert_eq!(role.role_name, long_name);
    }

    #[test]
    fn test_build_role_special_characters_in_name() {
        let context = test_context();
        let role = build_role(
            "role+test@example.com".to_string(),
            test_trust_policy(),
            None,
            None,
            None,
            &context,
        )
        .unwrap();
        assert_eq!(role.role_name, "role+test@example.com");
    }

    #[test]
    fn test_build_role_empty_trust_policy() {
        let context = test_context();
        // Empty trust policy should still work (no validation in builder)
        let role = build_role(
            "test-role".to_string(),
            "".to_string(),
            None,
            None,
            None,
            &context,
        )
        .unwrap();
        assert_eq!(role.assume_role_policy_document, "");
    }

    #[test]
    fn test_build_role_invalid_json_trust_policy() {
        let context = test_context();
        // Invalid JSON should still work (no validation in builder)
        let role = build_role(
            "test-role".to_string(),
            "not valid json".to_string(),
            None,
            None,
            None,
            &context,
        )
        .unwrap();
        assert_eq!(role.assume_role_policy_document, "not valid json");
    }

    #[test]
    fn test_build_role_empty_description() {
        let context = test_context();
        let role = build_role(
            "test-role".to_string(),
            test_trust_policy(),
            None,
            Some("".to_string()),
            None,
            &context,
        )
        .unwrap();
        assert_eq!(role.description, Some("".to_string()));
    }

    #[test]
    fn test_build_role_zero_max_session_duration() {
        let context = test_context();
        // Zero should be allowed (though not recommended)
        let role = build_role(
            "test-role".to_string(),
            test_trust_policy(),
            None,
            None,
            Some(0),
            &context,
        )
        .unwrap();
        assert_eq!(role.max_session_duration, Some(0));
    }

    #[test]
    fn test_build_role_negative_max_session_duration() {
        let context = test_context();
        // Negative values should be allowed (no validation in builder)
        let role = build_role(
            "test-role".to_string(),
            test_trust_policy(),
            None,
            None,
            Some(-100),
            &context,
        )
        .unwrap();
        assert_eq!(role.max_session_duration, Some(-100));
    }

    #[test]
    fn test_build_role_very_large_max_session_duration() {
        let context = test_context();
        // Very large values should be allowed (no validation in builder)
        let role = build_role(
            "test-role".to_string(),
            test_trust_policy(),
            None,
            None,
            Some(i32::MAX),
            &context,
        )
        .unwrap();
        assert_eq!(role.max_session_duration, Some(i32::MAX));
    }

    #[test]
    fn test_build_role_trust_policy_with_null_bytes() {
        let context = test_context();
        // Trust policy with null bytes should be handled
        let policy =
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow"}]}"#.replace('}', "\0}");
        let role = build_role(
            "test-role".to_string(),
            policy.clone(),
            None,
            None,
            None,
            &context,
        )
        .unwrap();
        assert_eq!(role.assume_role_policy_document, policy);
    }

    #[test]
    fn test_build_role_trust_policy_very_long() {
        let context = test_context();
        // Very long trust policy should be handled
        let long_policy = format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"Service":"{}"}}}}]}}"#,
            "a".repeat(10000)
        );
        let role = build_role(
            "test-role".to_string(),
            long_policy.clone(),
            None,
            None,
            None,
            &context,
        )
        .unwrap();
        assert_eq!(role.assume_role_policy_document, long_policy);
    }

    #[test]
    fn test_build_role_with_unicode_in_name() {
        let context = test_context();
        let role = build_role(
            "角色".to_string(),
            test_trust_policy(),
            None,
            None,
            None,
            &context,
        )
        .unwrap();
        assert_eq!(role.role_name, "角色");
    }

    #[test]
    fn test_build_role_with_empty_tenant_path_context() {
        let user_arn: WamiArn = "arn:wami:iam:12345678:wami:999:user/test".parse().unwrap();
        let context_result = WamiContext::builder()
            .instance_id("123456789012")
            .tenant_path(TenantPath::new(vec![]))
            .caller_arn(user_arn)
            .is_root(false)
            .build();

        if let Ok(context) = context_result {
            let role_result = build_role(
                "test-role".to_string(),
                test_trust_policy(),
                None,
                None,
                None,
                &context,
            );
            assert!(role_result.is_err());
        }
    }

    #[test]
    fn test_set_permissions_boundary() {
        let context = test_context();
        let role = build_role(
            "test-role".to_string(),
            test_trust_policy(),
            None,
            None,
            None,
            &context,
        )
        .unwrap();

        let boundary = "arn:aws:iam::123:policy/boundary".to_string();
        let updated = set_permissions_boundary(role, boundary.clone());

        assert_eq!(updated.permissions_boundary, Some(boundary));
    }

    #[test]
    fn test_clear_permissions_boundary() {
        let context = test_context();
        let mut role = build_role(
            "test-role".to_string(),
            test_trust_policy(),
            None,
            None,
            None,
            &context,
        )
        .unwrap();

        role.permissions_boundary = Some("arn:aws:iam::123:policy/boundary".to_string());
        let updated = clear_permissions_boundary(role);

        assert!(updated.permissions_boundary.is_none());
    }

    #[test]
    fn test_add_tags() {
        let context = test_context();
        let role = build_role(
            "test-role".to_string(),
            test_trust_policy(),
            None,
            None,
            None,
            &context,
        )
        .unwrap();

        let tags = vec![
            Tag {
                key: "Env".to_string(),
                value: "Prod".to_string(),
            },
            Tag {
                key: "Team".to_string(),
                value: "Platform".to_string(),
            },
        ];

        let updated = add_tags(role, tags);
        assert_eq!(updated.tags.len(), 2);
    }

    #[test]
    fn test_add_tags_no_duplicates() {
        let context = test_context();
        let role = build_role(
            "test-role".to_string(),
            test_trust_policy(),
            None,
            None,
            None,
            &context,
        )
        .unwrap();

        let tags1 = vec![Tag {
            key: "Env".to_string(),
            value: "Prod".to_string(),
        }];
        let tags2 = vec![Tag {
            key: "Env".to_string(),
            value: "Dev".to_string(),
        }];

        let updated = add_tags(role, tags1);
        let updated = add_tags(updated, tags2);

        assert_eq!(updated.tags.len(), 1);
        assert_eq!(updated.tags[0].value, "Prod");
    }

    #[test]
    fn test_set_tenant_id() {
        let context = test_context();
        let role = build_role(
            "test-role".to_string(),
            test_trust_policy(),
            None,
            None,
            None,
            &context,
        )
        .unwrap();

        let tenant_id = TenantId::root(); // Test with root tenant
        let updated = set_tenant_id(role, tenant_id.clone());

        assert_eq!(updated.tenant_id, Some(tenant_id));
    }

    #[test]
    fn test_role_immutability() {
        let context = test_context();
        let role = build_role(
            "test-role".to_string(),
            test_trust_policy(),
            None,
            None,
            None,
            &context,
        )
        .unwrap();

        let original_name = role.role_name.clone();
        let _ = update_max_session_duration(role.clone(), 9999);

        assert_eq!(role.role_name, original_name);
        assert_eq!(role.max_session_duration, None);
    }
}
