//! Microsoft Azure Provider Implementation
//!
//! This crate contains the Azure-specific implementation of the `CloudProvider` trait.
//! Currently a stub implementation - full Azure support to be added in future versions.
//!
//! # Example
//!
//! ```rust
//! use wami::provider::{CloudProvider, ResourceLimits, ResourceType};
//! use wami::provider::AzureProvider;
//!
//! let provider = AzureProvider::new("sub-123", "rg-example");
//! assert_eq!(provider.name(), "azure");
//! let id = provider.generate_resource_identifier(ResourceType::User, "", "", "alice");
//! assert!(id.contains("/subscriptions/sub-123/"));
//! ```

use crate::provider::{CloudProvider, ResourceLimits, ResourceType};
use wami_core::error::Result;

/// Microsoft Azure provider implementation
#[derive(Debug, Clone)]
pub struct AzureProvider {
    subscription_id: String,
    resource_group: String,
    limits: ResourceLimits,
}

impl AzureProvider {
    /// Creates a new Azure provider
    pub fn new(subscription_id: impl Into<String>, resource_group: impl Into<String>) -> Self {
        Self {
            subscription_id: subscription_id.into(),
            resource_group: resource_group.into(),
            limits: ResourceLimits {
                max_tags_per_resource: 50,
                ..Default::default()
            },
        }
    }
}

impl CloudProvider for AzureProvider {
    fn name(&self) -> &str {
        "azure"
    }

    fn generate_resource_identifier(
        &self,
        resource_type: ResourceType,
        _account_id: &str,
        _path: &str,
        name: &str,
    ) -> String {
        let resource_type_name = match resource_type {
            ResourceType::User => "users",
            ResourceType::Group => "groups",
            ResourceType::Role => "roleAssignments",
            ResourceType::SamlProvider => "samlIdentityProviders",
            ResourceType::OidcProvider => "oidcIdentityProviders",
            _ => "resources",
        };

        if matches!(
            resource_type,
            ResourceType::SamlProvider | ResourceType::OidcProvider
        ) {
            format!(
                "/tenants/{}/identityProviders/{}",
                self.subscription_id, name
            )
        } else {
            format!(
                "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Authorization/{}/{}",
                self.subscription_id, self.resource_group, resource_type_name, name
            )
        }
    }

    fn generate_resource_id(&self, _resource_type: ResourceType) -> String {
        uuid::Uuid::new_v4().to_string()
    }

    fn resource_limits(&self) -> &ResourceLimits {
        &self.limits
    }

    fn validate_service_name(&self, _service: &str) -> Result<()> {
        Ok(())
    }

    fn validate_path(&self, _path: &str) -> Result<()> {
        Ok(())
    }

    fn generate_service_linked_role_name(
        &self,
        service_name: &str,
        custom_suffix: Option<&str>,
    ) -> String {
        if let Some(suffix) = custom_suffix {
            format!("{}-{}", service_name, suffix)
        } else {
            service_name.to_string()
        }
    }

    fn generate_service_linked_role_path(&self, _service_name: &str) -> String {
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_azure_provider_name() {
        let provider = AzureProvider::new("sub-123", "my-rg");
        assert_eq!(provider.name(), "azure");
    }

    #[test]
    fn test_generate_azure_resource_id_format() {
        let provider = AzureProvider::new("sub-123", "my-rg");
        let resource_id =
            provider.generate_resource_identifier(ResourceType::User, "", "", "alice");
        assert!(resource_id.contains("/subscriptions/sub-123/"));
        assert!(resource_id.contains("/resourceGroups/my-rg/"));
        assert!(resource_id.contains("Microsoft.Authorization"));
    }

    #[test]
    fn test_generate_guid() {
        let provider = AzureProvider::new("sub-123", "my-rg");
        let id = provider.generate_resource_id(ResourceType::User);
        assert!(uuid::Uuid::parse_str(&id).is_ok());
    }

    #[test]
    fn each_resource_type_lands_in_its_own_azure_collection() {
        // A match with a `_` fallback: a type that should have its own
        // collection but was never added silently becomes a generic
        // "resources" entry, and nothing complains.
        let p = AzureProvider::new("sub-1".to_string(), "rg-1".to_string());
        let id = |t| p.generate_resource_identifier(t, "acct", "/", "thing");

        let base = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Authorization";
        assert_eq!(id(ResourceType::User), format!("{base}/users/thing"));
        assert_eq!(id(ResourceType::Group), format!("{base}/groups/thing"));
        assert_eq!(
            id(ResourceType::Role),
            format!("{base}/roleAssignments/thing")
        );
        assert_eq!(
            id(ResourceType::Policy),
            format!("{base}/resources/thing"),
            "anything unmapped falls back to the generic collection"
        );
    }

    #[test]
    fn an_identity_provider_is_addressed_at_the_tenant_not_the_resource_group() {
        // The one branch that leaves the subscription/resourceGroup shape
        // entirely — an identity provider belongs to the tenant.
        let p = AzureProvider::new("sub-1".to_string(), "rg-1".to_string());
        for t in [ResourceType::SamlProvider, ResourceType::OidcProvider] {
            assert_eq!(
                p.generate_resource_identifier(t, "acct", "/", "corp-idp"),
                "/tenants/sub-1/identityProviders/corp-idp",
                "{t:?} was addressed as an ordinary resource"
            );
        }
    }

    #[test]
    fn azure_limits_and_validation_are_permissive_by_design() {
        let p = AzureProvider::new("s".to_string(), "r".to_string());
        // Azure imposes none of AWS's per-user counts here, so anything passes.
        assert!(p.validate_service_name("whatever").is_ok());
        assert!(p.validate_path("no rules here").is_ok());
        assert!(p.resource_limits().max_access_keys_per_user > 0);
        assert_eq!(p.name(), "azure");
    }
}
