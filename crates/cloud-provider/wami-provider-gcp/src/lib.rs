//! Google Cloud Platform Provider Implementation
//!
//! This crate contains the GCP-specific implementation of the `CloudProvider` trait.
//! Currently a stub implementation - full GCP support to be added in future versions.
//!
//! # Example
//!
//! ```rust
//! use wami_provider::{CloudProvider, ResourceLimits, ResourceType};
//! use wami_provider_gcp::GcpProvider;
//!
//! let provider = GcpProvider::new("my-project-123");
//! assert_eq!(provider.name(), "gcp");
//! let urn = provider.generate_resource_identifier(ResourceType::User, "", "", "alice");
//! assert!(urn.contains("serviceAccounts"));
//! ```

<<<<<<<< HEAD:crates/cloud-provider/wami-provider-gcp/src/lib.rs
use wami_core::error::Result;
use wami_provider::{CloudProvider, ResourceLimits, ResourceType};
========
use super::{CloudProvider, ResourceLimits, ResourceType};
use wami_core::error::Result;
>>>>>>>> fcc0841 (Refactor: Reorganize codebase into workspace structure):crates/wami-provider/src/gcp.rs

/// Google Cloud Platform provider implementation
#[derive(Debug, Clone)]
pub struct GcpProvider {
    project_id: String,
    limits: ResourceLimits,
}

impl GcpProvider {
    /// Creates a new GCP provider for a specific project
<<<<<<<< HEAD:crates/cloud-provider/wami-provider-gcp/src/lib.rs
========
    ///
    /// # Example
    ///
    /// ```rust
    /// use wami_provider::GcpProvider;
    ///
    /// let provider = GcpProvider::new("my-project-123");
    /// ```
>>>>>>>> fcc0841 (Refactor: Reorganize codebase into workspace structure):crates/wami-provider/src/gcp.rs
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
}
