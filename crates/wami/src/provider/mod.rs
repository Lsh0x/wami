//! Cloud Provider Abstraction
//!
//! This module provides abstractions for different cloud providers (AWS, GCP, Azure, custom).
//! It allows the IAM system to work across multiple cloud platforms by abstracting
//! provider-specific details like ARN formats, ID generation, and resource limits.
//!
//! # Example
//!
//! ```rust,no_run
//! use wami::provider::{CloudProvider, ResourceType};
//! // Provider implementations are in separate crates (e.g., wami-provider-aws)
//! // use wami::provider::AwsProvider;
//!
//! // Use AWS provider (default)
//! // let aws = AwsProvider::default();
//! // let user_arn = aws.generate_resource_identifier(
//! //     ResourceType::User,
//! //     "123456789012",
//! //     "/",
//! //     "alice"
//! // );
//! // // → "arn:aws:iam::123456789012:user/alice"
//! ```

pub mod arn_builder;
pub mod provider_info;
pub mod registry;

pub mod aws;
pub mod azure;
pub mod custom;
pub mod gcp;

pub use registry::ProviderRegistry;

// The names the façade used to re-export from four separate crates. Kept so
// `wami::provider::AwsProvider` still resolves.
pub use aws::AwsProvider;
pub use azure::AzureProvider;
pub use custom::CustomProvider;
pub use gcp::GcpProvider;
pub use provider_info::ProviderInfo;

// Note: Tests are located in individual module files (e.g., aws.rs, gcp.rs, etc.)

use serde::{Deserialize, Serialize};
use wami_core::error::{AmiError, Result};

/// Provider configuration for tracking which cloud providers a resource exists on
///
/// This struct tracks the synchronization state of a resource across multiple cloud providers,
/// including the provider-specific identifiers and sync timestamps.
///
/// # Tenant Support
///
/// When `tenant_id` is provided, resources are isolated to that tenant. The ARN will
/// include the tenant path, e.g., `arn:aws:iam::123456789012:user/tenants/acme/engineering/alice`
///
/// # Example
///
/// ```rust
/// use wami::provider::ProviderConfig;
/// use chrono::Utc;
///
/// let config = ProviderConfig {
///     provider_name: "aws".to_string(),
///     account_id: "123456789012".to_string(),
///     native_arn: "arn:aws:iam::123456789012:user/alice".to_string(),
///     synced_at: Utc::now(),
///     tenant_id: None, // Single-tenant mode
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProviderConfig {
    /// The provider name (e.g., "aws", "gcp", "azure", "custom")
    pub provider_name: String,
    /// The account/project/subscription identifier
    pub account_id: String,
    /// The provider-specific ARN/identifier
    pub native_arn: String,
    /// When this resource was last synced to this provider
    pub synced_at: chrono::DateTime<chrono::Utc>,
    /// Optional tenant ID for multi-tenant isolation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
}

/// Resource type enumeration for cloud resources
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceType {
    /// IAM User
    User,
    /// IAM Group
    Group,
    /// IAM Role
    Role,
    /// IAM Policy
    Policy,
    /// Access Key for programmatic access
    AccessKey,
    /// Server Certificate (SSL/TLS)
    ServerCertificate,
    /// Service-specific Credential
    ServiceCredential,
    /// Service-Linked Role
    ServiceLinkedRole,
    /// MFA Device
    MfaDevice,
    /// Signing Certificate
    SigningCertificate,
    /// SAML Identity Provider
    SamlProvider,
    /// OIDC Identity Provider
    OidcProvider,
    /// STS assumed role session
    StsAssumedRole,
    /// STS federated user session
    StsFederatedUser,
    /// STS session token session
    StsSession,
    /// Multi-tenant organization unit
    Tenant,
}

/// Resource limits configuration per cloud provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Maximum number of access keys per user
    pub max_access_keys_per_user: usize,
    /// Maximum number of signing certificates per user
    pub max_signing_certificates_per_user: usize,
    /// Maximum number of service credentials per user per service
    pub max_service_credentials_per_user_per_service: usize,
    /// Maximum number of tags per resource
    pub max_tags_per_resource: usize,
    /// Maximum number of MFA devices per user
    pub max_mfa_devices_per_user: usize,
    /// Minimum session duration in seconds
    pub session_duration_min: i32,
    /// Maximum session duration in seconds
    pub session_duration_max: i32,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        // AWS defaults
        Self {
            max_access_keys_per_user: 2,
            max_signing_certificates_per_user: 2,
            max_service_credentials_per_user_per_service: 2,
            max_tags_per_resource: 50,
            max_mfa_devices_per_user: 8,
            session_duration_min: 3600,  // 1 hour
            session_duration_max: 43200, // 12 hours
        }
    }
}

/// Cloud provider trait for abstracting provider-specific logic
///
/// This trait allows the library to work with different cloud providers
/// by abstracting provider-specific details like ARN formats, ID generation,
/// resource limits, and validation rules.
pub trait CloudProvider: Send + Sync + std::fmt::Debug {
    /// Returns the provider name (e.g., "aws", "gcp", "azure", "custom")
    fn name(&self) -> &str;

    /// Generates a resource identifier (ARN, URN, Resource ID, etc.)
    ///
    /// # Arguments
    ///
    /// * `resource_type` - The type of resource
    /// * `account_id` - The account/project/subscription identifier
    /// * `path` - The resource path (may be empty for providers that don't use paths)
    /// * `name` - The resource name
    ///
    /// # Returns
    ///
    /// A fully qualified resource identifier in the provider's format
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use wami::provider::{CloudProvider, ResourceType};
    /// // use wami::provider::AwsProvider;
    ///
    /// // let provider = AwsProvider::default();
    /// // let arn = provider.generate_resource_identifier(
    /// //     ResourceType::User,
    /// //     "123456789012",
    /// //     "/engineering/",
    /// //     "alice"
    /// // );
    /// // assert_eq!(arn, "arn:aws:iam::123456789012:user/engineering/alice");
    /// ```
    fn generate_resource_identifier(
        &self,
        resource_type: ResourceType,
        account_id: &str,
        path: &str,
        name: &str,
    ) -> String;

    /// Generates a unique resource ID
    ///
    /// # Arguments
    ///
    /// * `resource_type` - The type of resource to generate an ID for
    ///
    /// # Returns
    ///
    /// A unique identifier in the provider's format
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use wami::provider::{CloudProvider, ResourceType};
    /// // use wami::provider::AwsProvider;
    ///
    /// // let provider = AwsProvider::default();
    /// // let id = provider.generate_resource_id(ResourceType::User);
    /// // assert!(id.starts_with("AIDA")); // AWS format
    /// // assert_eq!(id.len(), 21); // AIDA + 17 chars
    /// ```
    fn generate_resource_id(&self, resource_type: ResourceType) -> String;

    /// Returns the resource limits for this provider
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use wami::provider::CloudProvider;
    /// // use wami::provider::AwsProvider;
    ///
    /// // let provider = AwsProvider::default();
    /// // let limits = provider.resource_limits();
    /// // assert_eq!(limits.max_access_keys_per_user, 2); // AWS limit
    /// ```
    fn resource_limits(&self) -> &ResourceLimits;

    /// Validates a service name for service-specific credentials
    ///
    /// # Arguments
    ///
    /// * `service` - The service name to validate
    ///
    /// # Returns
    ///
    /// Ok(()) if valid, Err otherwise
    #[allow(clippy::result_large_err)]
    fn validate_service_name(&self, service: &str) -> Result<()>;

    /// Validates a path format
    ///
    /// # Arguments
    ///
    /// * `path` - The path to validate
    ///
    /// # Returns
    ///
    /// Ok(()) if valid, Err otherwise
    #[allow(clippy::result_large_err)]
    fn validate_path(&self, path: &str) -> Result<()>;

    /// Validates a session duration
    ///
    /// # Arguments
    ///
    /// * `duration` - The session duration in seconds
    ///
    /// # Returns
    ///
    /// Ok(()) if valid, Err otherwise
    ///
    /// # Default Implementation
    ///
    /// Checks against the provider's resource limits
    #[allow(clippy::result_large_err)]
    fn validate_session_duration(&self, duration: i32) -> Result<()> {
        let limits = self.resource_limits();
        if duration < limits.session_duration_min || duration > limits.session_duration_max {
            return Err(AmiError::InvalidParameter {
                message: format!(
                    "Session duration must be between {} and {} seconds",
                    limits.session_duration_min, limits.session_duration_max
                ),
            });
        }
        Ok(())
    }

    /// Generates a service-linked role name
    ///
    /// # Arguments
    ///
    /// * `service_name` - The service name (e.g., "elasticbeanstalk.amazonaws.com")
    /// * `custom_suffix` - Optional custom suffix for the role name
    ///
    /// # Returns
    ///
    /// A service-linked role name in the provider's format
    fn generate_service_linked_role_name(
        &self,
        service_name: &str,
        custom_suffix: Option<&str>,
    ) -> String;

    /// Generates a service-linked role path
    ///
    /// # Arguments
    ///
    /// * `service_name` - The service name
    ///
    /// # Returns
    ///
    /// A service-linked role path in the provider's format
    fn generate_service_linked_role_path(&self, service_name: &str) -> String;

    /// Generates a WAMI ARN for cross-provider resource identification
    ///
    /// WAMI ARNs use the format `arn:wami:service::account:resource/path/name`
    /// to provide a unified identifier across multiple cloud providers.
    ///
    /// # Arguments
    ///
    /// * `resource_type` - The type of resource
    /// * `account_id` - The account/project/subscription identifier
    /// * `path` - The resource path (may be empty for providers that don't use paths)
    /// * `name` - The resource name
    ///
    /// # Returns
    ///
    /// A WAMI ARN in the format `arn:wami:iam::account:resource/path/name`
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use wami::provider::{CloudProvider, ResourceType};
    /// // use wami::provider::AwsProvider;
    ///
    /// // let provider = AwsProvider::default();
    /// // let wami_arn = provider.generate_wami_arn(
    /// //     ResourceType::User,
    /// //     "123456789012",
    /// //     "/engineering/",
    /// //     "alice"
    /// // );
    /// // assert_eq!(wami_arn, "arn:wami:iam::123456789012:user/engineering/alice");
    /// ```
    fn generate_wami_arn(
        &self,
        resource_type: ResourceType,
        account_id: &str,
        path: &str,
        name: &str,
    ) -> String {
        // Default implementation: convert to AWS-style ARN format but with "wami" as provider
        let service = match resource_type {
            ResourceType::User
            | ResourceType::Group
            | ResourceType::Role
            | ResourceType::Policy
            | ResourceType::AccessKey
            | ResourceType::MfaDevice
            | ResourceType::ServiceLinkedRole
            | ResourceType::ServiceCredential
            | ResourceType::SigningCertificate
            | ResourceType::ServerCertificate
            | ResourceType::SamlProvider
            | ResourceType::OidcProvider => "iam",
            ResourceType::StsAssumedRole
            | ResourceType::StsFederatedUser
            | ResourceType::StsSession => "sts",
            ResourceType::Tenant => "organizations",
        };

        let resource_prefix = match resource_type {
            ResourceType::User => "user",
            ResourceType::Group => "group",
            ResourceType::Role => "role",
            ResourceType::Policy => "policy",
            ResourceType::ServerCertificate => "server-certificate",
            ResourceType::AccessKey => "access-key",
            ResourceType::ServiceCredential => "service-credential",
            ResourceType::ServiceLinkedRole => "role",
            ResourceType::MfaDevice => "mfa",
            ResourceType::SigningCertificate => "signing-certificate",
            ResourceType::SamlProvider => "saml-provider",
            ResourceType::OidcProvider => "oidc-provider",
            ResourceType::StsAssumedRole => "assumed-role",
            ResourceType::StsFederatedUser => "federated-user",
            ResourceType::StsSession => "session",
            ResourceType::Tenant => "ou",
        };

        // Normalize path: ensure it starts with / and ends with / if not empty
        let normalized_path = if path.is_empty() || path == "/" {
            String::new()
        } else {
            // Normalize path format: /path/name/ -> path/name/
            let trimmed = path.trim();
            if trimmed.is_empty() || trimmed == "/" {
                String::new()
            } else {
                let mut p = trimmed.to_string();
                // Ensure starts with / (unless already normalized)
                if !p.starts_with('/') {
                    p.insert(0, '/');
                }
                // Ensure ends with /
                if !p.ends_with('/') {
                    p.push('/');
                }
                // Remove leading / for the final format since we add it in the format string
                p[1..].to_string()
            }
        };

        if normalized_path.is_empty() {
            format!(
                "arn:wami:{}::{}:{}/{}",
                service, account_id, resource_prefix, name
            )
        } else {
            format!(
                "arn:wami:{}::{}:{}/{}{}",
                service, account_id, resource_prefix, normalized_path, name
            )
        }
    }
}

/// Helper functions for multi-tenant resource management
impl dyn CloudProvider {
    /// Generate a tenant-aware path for resources
    ///
    /// # Arguments
    ///
    /// * `tenant_id` - Optional tenant ID (e.g., "acme/engineering")
    /// * `base_path` - Base resource path (e.g., "/")
    ///
    /// # Returns
    ///
    /// A path that includes tenant isolation
    ///
    /// # Example
    ///
    /// ```rust
    /// # use wami::provider::CloudProvider;
    /// let path = <dyn CloudProvider>::tenant_aware_path(Some("acme/engineering"), "/");
    /// assert_eq!(path, "/tenants/acme/engineering/");
    ///
    /// let path = <dyn CloudProvider>::tenant_aware_path(None, "/admin/");
    /// assert_eq!(path, "/admin/");
    /// ```
    pub fn tenant_aware_path(tenant_id: Option<&str>, base_path: &str) -> String {
        match tenant_id {
            Some(tid) if !tid.is_empty() => {
                let normalized_base = base_path.trim_end_matches('/');
                format!("{}/tenants/{}/", normalized_base, tid)
            }
            _ => base_path.to_string(),
        }
    }

    /// Extract tenant ID from a tenant-aware path
    ///
    /// # Arguments
    ///
    /// * `path` - The resource path that may contain tenant information
    ///
    /// # Returns
    ///
    /// The extracted tenant ID, or None if not tenant-aware
    ///
    /// # Example
    ///
    /// ```rust
    /// # use wami::provider::CloudProvider;
    /// let tenant = <dyn CloudProvider>::extract_tenant_from_path("/tenants/acme/engineering/");
    /// assert_eq!(tenant, Some("acme/engineering".to_string()));
    ///
    /// let tenant = <dyn CloudProvider>::extract_tenant_from_path("/admin/");
    /// assert_eq!(tenant, None);
    /// ```
    pub fn extract_tenant_from_path(path: &str) -> Option<String> {
        // Look for /tenants/ pattern in the path
        if let Some(tenant_start) = path.find("/tenants/") {
            // Extract everything after "/tenants/"
            let tenant_part = &path[tenant_start + "/tenants/".len()..];
            // Get all non-empty segments after /tenants/ (stop at empty segment or end)
            let segments: Vec<&str> = tenant_part.split('/').filter(|s| !s.is_empty()).collect();

            if !segments.is_empty() {
                // Join segments to support multi-level tenants (e.g., "acme/engineering")
                return Some(segments.join("/"));
            }
        }
        None
    }
}

// Re-export provider implementations

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::aws::AwsProvider;

    /// Exercised through a real provider: no implementation overrides
    /// [`CloudProvider::generate_wami_arn`], so this is the code every one of
    /// them runs.
    fn provider() -> AwsProvider {
        AwsProvider::default()
    }

    #[test]
    fn every_resource_type_maps_to_a_service_and_a_prefix() {
        // The mapping is a pair of sixteen-arm matches with no fallback, so a
        // new variant is a compile error rather than a silent miscategory —
        // but nothing checked the arms themselves led anywhere sensible.
        let p = provider();
        let cases = [
            (ResourceType::User, "iam", "user"),
            (ResourceType::Group, "iam", "group"),
            (ResourceType::Role, "iam", "role"),
            (ResourceType::Policy, "iam", "policy"),
            (ResourceType::AccessKey, "iam", "access-key"),
            (ResourceType::MfaDevice, "iam", "mfa"),
            (ResourceType::ServiceLinkedRole, "iam", "role"),
            (ResourceType::ServiceCredential, "iam", "service-credential"),
            (
                ResourceType::SigningCertificate,
                "iam",
                "signing-certificate",
            ),
            (ResourceType::ServerCertificate, "iam", "server-certificate"),
            (ResourceType::SamlProvider, "iam", "saml-provider"),
            (ResourceType::OidcProvider, "iam", "oidc-provider"),
            (ResourceType::StsAssumedRole, "sts", "assumed-role"),
            (ResourceType::StsFederatedUser, "sts", "federated-user"),
            (ResourceType::StsSession, "sts", "session"),
            (ResourceType::Tenant, "organizations", "ou"),
        ];

        for (ty, service, prefix) in cases {
            let arn = p.generate_wami_arn(ty, "123456789012", "/", "thing");
            assert_eq!(
                arn,
                format!("arn:wami:{service}::123456789012:{prefix}/thing"),
                "{ty:?} landed in the wrong place"
            );
        }
    }

    #[test]
    fn a_service_linked_role_is_a_role_but_a_session_is_not_an_identity() {
        // The two arms that are easy to get wrong: one collapses onto another
        // prefix on purpose, the other changes service entirely.
        let p = provider();
        assert_eq!(
            p.generate_wami_arn(ResourceType::ServiceLinkedRole, "1", "/", "n"),
            p.generate_wami_arn(ResourceType::Role, "1", "/", "n"),
            "a service-linked role is addressed as a role"
        );
        assert!(p
            .generate_wami_arn(ResourceType::StsSession, "1", "/", "n")
            .starts_with("arn:wami:sts::"));
    }

    #[test]
    fn a_path_reaches_the_arn_in_one_shape_however_it_was_written() {
        // Callers pass paths with and without either slash. All four spellings
        // of the same path must produce the same ARN, or the same resource
        // gets two identifiers.
        let p = provider();
        let expected = "arn:wami:iam::123456789012:user/engineering/alice";
        for spelling in [
            "/engineering/",
            "engineering",
            "/engineering",
            "engineering/",
        ] {
            assert_eq!(
                p.generate_wami_arn(ResourceType::User, "123456789012", spelling, "alice"),
                expected,
                "{spelling:?} produced a different ARN"
            );
        }
    }

    #[test]
    fn an_empty_path_leaves_no_trace() {
        let p = provider();
        for empty in ["", "/", "  "] {
            assert_eq!(
                p.generate_wami_arn(ResourceType::User, "123456789012", empty, "alice"),
                "arn:wami:iam::123456789012:user/alice",
                "{empty:?} left something behind"
            );
        }
    }

    #[test]
    fn a_nested_path_keeps_its_depth() {
        let p = provider();
        assert_eq!(
            p.generate_wami_arn(ResourceType::Role, "1", "/eng/platform/", "deployer"),
            "arn:wami:iam::1:role/eng/platform/deployer"
        );
    }

    #[test]
    fn a_session_duration_is_checked_against_the_providers_own_limits() {
        // The default implementation reads `resource_limits()`, so it enforces
        // whatever the provider declares rather than a constant.
        let p = provider();
        let limits = p.resource_limits();

        assert!(p
            .validate_session_duration(limits.session_duration_min)
            .is_ok());
        assert!(p
            .validate_session_duration(limits.session_duration_max)
            .is_ok());
        assert!(p
            .validate_session_duration(limits.session_duration_min - 1)
            .is_err());
        assert!(p
            .validate_session_duration(limits.session_duration_max + 1)
            .is_err());
    }

    #[test]
    fn a_tenant_path_round_trips() {
        let path = <dyn CloudProvider>::tenant_aware_path(Some("acme/engineering"), "/");
        assert_eq!(path, "/tenants/acme/engineering/");
        assert_eq!(
            <dyn CloudProvider>::extract_tenant_from_path(&path),
            Some("acme/engineering".to_string())
        );
    }

    #[test]
    fn a_path_without_a_tenant_is_left_alone_and_yields_none() {
        assert_eq!(
            <dyn CloudProvider>::tenant_aware_path(None, "/admin/"),
            "/admin/"
        );
        // An empty tenant id is not a tenant.
        assert_eq!(
            <dyn CloudProvider>::tenant_aware_path(Some(""), "/admin/"),
            "/admin/"
        );
        assert_eq!(
            <dyn CloudProvider>::extract_tenant_from_path("/admin/"),
            None
        );
        assert_eq!(
            <dyn CloudProvider>::extract_tenant_from_path("/tenants/"),
            None,
            "the marker alone names no tenant"
        );
    }
}
