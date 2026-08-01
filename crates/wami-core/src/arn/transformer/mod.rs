//! Translating WAMI ARNs to and from provider formats.
//!
//! The contract and the registry live here; each provider's translation
//! lives in its own file. Adding one is adding a file, not editing a
//! seven-hundred-line module shared with three others.

mod aws;
mod azure;
mod gcp;
mod scaleway;

pub use aws::AwsArnTransformer;
pub use azure::AzureArnTransformer;
pub use gcp::GcpArnTransformer;
pub use scaleway::ScalewayArnTransformer;

use crate::arn::types::WamiArn;
use crate::error::Result;

/// Trait for transforming WAMI ARNs to and from provider-specific formats.
pub trait ArnTransformer {
    /// Converts a WAMI ARN to a provider-specific ARN format.
    ///
    /// Returns an error if the ARN is not cloud-synced or if the provider doesn't match.
    #[allow(clippy::result_large_err)]
    fn to_provider_arn(&self, arn: &WamiArn) -> Result<String>;

    /// Attempts to convert a provider-specific ARN back to a WAMI ARN.
    ///
    /// Note: This may require additional context (tenant_path, wami_instance_id)
    /// that may not be present in the provider ARN, so this operation may be lossy.
    #[allow(clippy::wrong_self_convention, clippy::result_large_err)]
    fn from_provider_arn(&self, provider_arn: &str) -> Result<ProviderArnInfo>;
}

/// Information extracted from a provider-specific ARN.
///
/// This doesn't contain the full WAMI context (tenant hierarchy, instance ID)
/// as those are not typically present in provider ARNs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderArnInfo {
    /// The cloud provider name
    pub provider: String,
    /// The provider's account ID
    pub account_id: String,
    /// The service name (may need mapping to WAMI service)
    pub service: String,
    /// Resource type
    pub resource_type: String,
    /// Resource ID
    pub resource_id: String,
    /// Optional region
    pub region: Option<String>,
}

/// Gets the appropriate transformer for a given provider.
///
/// # Examples
///
/// ```
/// use wami_core::arn::get_transformer;
///
/// let transformer = get_transformer("aws");
/// assert!(transformer.is_some());
///
/// let transformer = get_transformer("unknown");
/// assert!(transformer.is_none());
/// ```
pub fn get_transformer(provider: &str) -> Option<Box<dyn ArnTransformer>> {
    match provider {
        "aws" => Some(Box::new(AwsArnTransformer)),
        "gcp" => Some(Box::new(GcpArnTransformer)),
        "azure" => Some(Box::new(AzureArnTransformer)),
        "scaleway" => Some(Box::new(ScalewayArnTransformer)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_transformer() {
        assert!(get_transformer("aws").is_some());
        assert!(get_transformer("gcp").is_some());
        assert!(get_transformer("azure").is_some());
        assert!(get_transformer("scaleway").is_some());
        assert!(get_transformer("unknown").is_none());
    }
}
