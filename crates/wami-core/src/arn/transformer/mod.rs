//! Translating WAMI ARNs to and from provider formats.
//!
//! The contract and the registry live here; each provider's translation
//! lives in its own file. Adding one is adding a file, not editing a
//! seven-hundred-line module shared with three others.

#[cfg(feature = "aws")]
mod aws;
#[cfg(feature = "azure")]
mod azure;
#[cfg(feature = "gcp")]
mod gcp;
#[cfg(feature = "scaleway")]
mod scaleway;

#[cfg(feature = "aws")]
pub use aws::AwsArnTransformer;
#[cfg(feature = "azure")]
pub use azure::AzureArnTransformer;
#[cfg(feature = "gcp")]
pub use gcp::GcpArnTransformer;
#[cfg(feature = "scaleway")]
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
/// Returns `None` for a provider whose feature is not enabled, which by
/// default is all of them. Ask [`available_providers`] what this build can
/// actually translate for.
///
/// # Examples
///
/// ```
/// use wami_core::arn::{available_providers, get_transformer};
///
/// // Holds for any set of enabled features, including none.
/// for provider in available_providers() {
///     assert!(get_transformer(provider).is_some());
/// }
///
/// assert!(get_transformer("unknown").is_none());
/// ```
///
/// With the `aws` feature enabled:
///
/// ```
/// # #[cfg(feature = "aws")] {
/// use wami_core::arn::get_transformer;
/// assert!(get_transformer("aws").is_some());
/// # }
/// ```
pub fn get_transformer(provider: &str) -> Option<Box<dyn ArnTransformer>> {
    match provider {
        #[cfg(feature = "aws")]
        "aws" => Some(Box::new(AwsArnTransformer)),
        #[cfg(feature = "gcp")]
        "gcp" => Some(Box::new(GcpArnTransformer)),
        #[cfg(feature = "azure")]
        "azure" => Some(Box::new(AzureArnTransformer)),
        #[cfg(feature = "scaleway")]
        "scaleway" => Some(Box::new(ScalewayArnTransformer)),
        _ => None,
    }
}

/// The providers this build can translate for.
///
/// With no provider feature enabled — the default — this is empty and
/// [`get_transformer`] returns `None` for everything. That is correct for a
/// deployment that syncs with no cloud, and indistinguishable from a typo
/// without somewhere to ask. This is that place, so the answer does not
/// require reading a Cargo.toml.
pub fn available_providers() -> &'static [&'static str] {
    &[
        #[cfg(feature = "aws")]
        "aws",
        #[cfg(feature = "gcp")]
        "gcp",
        #[cfg(feature = "azure")]
        "azure",
        #[cfg(feature = "scaleway")]
        "scaleway",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_inventory_and_the_registry_agree() {
        // Stated as a property rather than a list of providers, so it holds
        // whatever set of features a build enables — including none, which is
        // the default and the case that matters to a consumer with no cloud.
        for provider in available_providers() {
            assert!(
                get_transformer(provider).is_some(),
                "{provider} is advertised but cannot be built"
            );
        }
        assert!(get_transformer("unknown").is_none());
    }

    #[test]
    fn no_provider_is_available_unless_asked_for() {
        // The reason the inventory exists: without it, an empty result is
        // indistinguishable from a typo, and nothing says which it was.
        #[cfg(not(any(
            feature = "aws",
            feature = "gcp",
            feature = "azure",
            feature = "scaleway"
        )))]
        {
            assert!(available_providers().is_empty());
            assert!(get_transformer("aws").is_none());
        }

        #[cfg(feature = "aws")]
        assert!(available_providers().contains(&"aws"));
    }
}
