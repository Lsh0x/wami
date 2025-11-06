//! AccessKey Builder

use super::model::AccessKey;
use uuid::Uuid;
use wami_core::arn::{Service, WamiArn};
use wami_core::context::WamiContext;
use wami_core::error::Result;
use wami_provider::ProviderConfig;

/// Build a new AccessKey resource with context-based identifiers
#[allow(clippy::result_large_err)]
pub fn build_access_key(user_name: String, context: &WamiContext) -> Result<AccessKey> {
    // Generate AWS-compatible access key ID (AKIA prefix + 16 alphanumeric chars)
    let random_part = Uuid::new_v4().to_string().replace('-', "").to_uppercase();
    let access_key_id = format!("AKIA{}", &random_part[..16]);

    // Build WAMI ARN using context
    let wami_arn = WamiArn::builder()
        .service(Service::Iam)
        .tenant_path(context.tenant_path().clone())
        .wami_instance(context.instance_id())
        .resource("access-key", &access_key_id)
        .build()?;

    // Generate secret access key (40 random chars)
    let secret_access_key = uuid::Uuid::new_v4().to_string().replace('-', "")
        + &uuid::Uuid::new_v4().to_string().replace('-', "")[..8];

    Ok(AccessKey {
        user_name,
        access_key_id,
        status: "Active".to_string(),
        create_date: chrono::Utc::now(),
        secret_access_key: Some(secret_access_key),
        wami_arn,
        providers: Vec::new(),
    })
}

/// Update an AccessKey's status
pub fn update_access_key_status(mut access_key: AccessKey, new_status: String) -> AccessKey {
    access_key.status = new_status;
    access_key
}

/// Add a provider configuration to an AccessKey
pub fn add_provider_to_access_key(mut access_key: AccessKey, config: ProviderConfig) -> AccessKey {
    access_key.providers.push(config);
    access_key
}

#[cfg(test)]
mod tests {
    use super::*;
    use wami_core::arn::{TenantPath, WamiArn};

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
    fn test_build_access_key() {
        let context = test_context();
        let access_key = build_access_key("alice".to_string(), &context).unwrap();

        assert_eq!(access_key.user_name, "alice");
        assert!(access_key.access_key_id.starts_with("AKIA"));
        assert_eq!(access_key.access_key_id.len(), 20); // AKIA + 16 chars
        assert_eq!(access_key.status, "Active");
        assert!(access_key.secret_access_key.is_some());
        assert_eq!(access_key.wami_arn.resource.resource_type, "access-key");
        assert_eq!(access_key.providers.len(), 0);
    }

    #[test]
    fn test_build_access_key_empty_user_name() {
        let context = test_context();
        // Empty user name should still work
        let access_key = build_access_key("".to_string(), &context).unwrap();
        assert_eq!(access_key.user_name, "");
        assert!(access_key.access_key_id.starts_with("AKIA"));
    }

    #[test]
    fn test_build_access_key_very_long_user_name() {
        let context = test_context();
        let long_name = "a".repeat(1000);
        let access_key = build_access_key(long_name.clone(), &context).unwrap();
        assert_eq!(access_key.user_name, long_name);
    }

    #[test]
    fn test_update_access_key_status() {
        let context = test_context();
        let access_key = build_access_key("alice".to_string(), &context).unwrap();
        let updated = update_access_key_status(access_key, "Inactive".to_string());

        assert_eq!(updated.status, "Inactive");
    }

    #[test]
    fn test_update_access_key_status_empty() {
        let context = test_context();
        let access_key = build_access_key("alice".to_string(), &context).unwrap();
        let updated = update_access_key_status(access_key, "".to_string());

        assert_eq!(updated.status, "");
    }

    #[test]
    fn test_add_provider_to_access_key() {
        let context = test_context();
        let access_key = build_access_key("alice".to_string(), &context).unwrap();

        let provider_config = ProviderConfig {
            provider_name: "aws".to_string(),
            account_id: "123456789012".to_string(),
            native_arn: "arn:aws:iam::123456789012:user/alice".to_string(),
            synced_at: chrono::Utc::now(),
            tenant_id: None,
        };

        let updated = add_provider_to_access_key(access_key, provider_config);
        assert_eq!(updated.providers.len(), 1);
        assert_eq!(updated.providers[0].provider_name, "aws");
    }

    #[test]
    fn test_build_access_key_with_unicode_user_name() {
        let context = test_context();
        let access_key = build_access_key("用户".to_string(), &context).unwrap();
        assert_eq!(access_key.user_name, "用户");
    }

    #[test]
    fn test_build_access_key_with_empty_tenant_path_context() {
        let user_arn: WamiArn = "arn:wami:iam:12345678:wami:999:user/test".parse().unwrap();
        let context_result = WamiContext::builder()
            .instance_id("123456789012")
            .tenant_path(wami_core::arn::TenantPath::new(vec![]))
            .caller_arn(user_arn)
            .is_root(false)
            .build();

        if let Ok(context) = context_result {
            let key_result = build_access_key("alice".to_string(), &context);
            assert!(key_result.is_err());
        }
    }

    #[test]
    fn test_build_access_key_with_whitespace_instance_id_context() {
        let user_arn: WamiArn = "arn:wami:iam:12345678:wami:999:user/test".parse().unwrap();
        let context_result = WamiContext::builder()
            .instance_id("   ".to_string())
            .tenant_path(wami_core::arn::TenantPath::single(12345678))
            .caller_arn(user_arn)
            .is_root(false)
            .build();

        // Should fail because instance_id.trim().is_empty()
        assert!(context_result.is_err());
    }

    #[test]
    fn test_update_access_key_status_with_unicode() {
        let context = test_context();
        let access_key = build_access_key("alice".to_string(), &context).unwrap();
        let updated = update_access_key_status(access_key, "非アクティブ".to_string());
        assert_eq!(updated.status, "非アクティブ");
    }
}
