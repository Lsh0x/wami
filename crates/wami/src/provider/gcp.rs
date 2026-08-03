//! Google Cloud Platform Provider Implementation
//!
//! This crate contains the GCP-specific implementation of the `CloudProvider` trait.
//! Currently a stub implementation - full GCP support to be added in future versions.
//!
//! # Example
//!
//! ```rust
//! use wami::provider::{CloudProvider, ResourceLimits, ResourceType};
//! use wami::provider::GcpProvider;
//!
//! let provider = GcpProvider::new("my-project-123");
//! assert_eq!(provider.name(), "gcp");
//! let urn = provider.generate_resource_identifier(ResourceType::User, "", "", "alice");
//! assert!(urn.contains("serviceAccounts"));
//! ```

use crate::provider::{CloudProvider, ResourceLimits, ResourceType};
use wami_core::error::Result;

/// Google Cloud Platform provider implementation
#[derive(Debug, Clone)]
pub struct GcpProvider {
    project_id: String,
    limits: ResourceLimits,
}

impl GcpProvider {
    /// Creates a new GCP provider for a specific project
    pub fn new(project_id: impl Into<String>) -> Self {
        Self {
            project_id: project_id.into(),
            limits: ResourceLimits {
                max_access_keys_per_user: 10,
                max_service_credentials_per_user_per_service: 10,
                max_tags_per_resource: 64,
                session_duration_max: 3600,
                ..Default::default()
            },
        }
    }
}

impl CloudProvider for GcpProvider {
    fn name(&self) -> &str {
        "gcp"
    }

    fn generate_resource_identifier(
        &self,
        resource_type: ResourceType,
        _account_id: &str,
        _path: &str,
        name: &str,
    ) -> String {
        match resource_type {
            ResourceType::User => format!(
                "projects/{}/serviceAccounts/{}@{}.iam.gserviceaccount.com",
                self.project_id, name, self.project_id
            ),
            ResourceType::Role => format!("projects/{}/roles/{}", self.project_id, name),
            ResourceType::SamlProvider => format!(
                "projects/{}/locations/global/workforcePools/default/providers/{}",
                self.project_id, name
            ),
            ResourceType::OidcProvider => format!(
                "projects/{}/locations/global/workloadIdentityPools/default/providers/{}",
                self.project_id, name
            ),
            _ => format!("projects/{}/resources/{}", self.project_id, name),
        }
    }

    fn generate_resource_id(&self, _resource_type: ResourceType) -> String {
        format!("{}", uuid::Uuid::new_v4().as_u128())
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
    fn test_gcp_provider_name() {
        let provider = GcpProvider::new("test-project");
        assert_eq!(provider.name(), "gcp");
    }

    #[test]
    fn test_generate_service_account_urn() {
        let provider = GcpProvider::new("my-project-123");
        let urn = provider.generate_resource_identifier(ResourceType::User, "", "", "alice");
        assert_eq!(
            urn,
            "projects/my-project-123/serviceAccounts/alice@my-project-123.iam.gserviceaccount.com"
        );
    }

    #[test]
    fn test_generate_role_urn() {
        let provider = GcpProvider::new("my-project-123");
        let urn = provider.generate_resource_identifier(ResourceType::Role, "", "", "CustomRole");
        assert_eq!(urn, "projects/my-project-123/roles/CustomRole");
    }

    #[test]
    fn test_generate_numeric_id() {
        let provider = GcpProvider::new("test-project");
        let id = provider.generate_resource_id(ResourceType::User);
        assert!(id.parse::<u128>().is_ok());
    }

    #[test]
    fn test_gcp_resource_limits() {
        let provider = GcpProvider::new("test-project");
        let limits = provider.resource_limits();
        assert_eq!(limits.max_access_keys_per_user, 10);
        assert_eq!(limits.max_tags_per_resource, 64);
    }

    #[test]
    fn each_resource_type_gets_its_own_gcp_shape() {
        // Four distinct formats plus a fallback. A type routed to the wrong
        // arm produces a well-formed but meaningless resource name.
        let p = GcpProvider::new("proj".to_string());
        let id = |t| p.generate_resource_identifier(t, "acct", "/", "thing");

        assert_eq!(
            id(ResourceType::User),
            "projects/proj/serviceAccounts/thing@proj.iam.gserviceaccount.com",
            "a user is a service account, and the project appears twice"
        );
        assert_eq!(id(ResourceType::Role), "projects/proj/roles/thing");
        assert_eq!(
            id(ResourceType::SamlProvider),
            "projects/proj/locations/global/workforcePools/default/providers/thing",
            "SAML federates a workforce"
        );
        assert_eq!(
            id(ResourceType::OidcProvider),
            "projects/proj/locations/global/workloadIdentityPools/default/providers/thing",
            "OIDC federates a workload — a different pool entirely"
        );
        assert_eq!(
            id(ResourceType::Policy),
            "projects/proj/resources/thing",
            "anything unmapped falls back"
        );
    }

    #[test]
    fn gcp_ids_are_numeric_and_do_not_repeat() {
        // GCP identifiers are decimal, not the hyphenated UUID other providers
        // hand out.
        let p = GcpProvider::new("proj".to_string());
        let a = p.generate_resource_id(ResourceType::User);
        let b = p.generate_resource_id(ResourceType::User);
        assert_ne!(a, b);
        assert!(a.chars().all(|c| c.is_ascii_digit()), "{a} is not decimal");
        assert_eq!(p.name(), "gcp");
    }
}
