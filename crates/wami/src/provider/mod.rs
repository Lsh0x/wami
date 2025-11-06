//! Provider facade for the `wami` crate.
//!
//! This module re-exports the core `CloudProvider` traits and concrete provider
//! implementations so downstream users can continue to access them via
//! `wami::provider::*`.

pub use wami_provider::arn_builder;
pub use wami_provider::provider_info;

pub use wami_provider::{
    CloudProvider, ProviderConfig, ProviderRegistry, ResourceLimits, ResourceType,
};

pub use wami_provider::provider_info::ProviderInfo;

pub use wami_provider_aws::AwsProvider;
pub use wami_provider_azure::AzureProvider;
pub use wami_provider_custom::CustomProvider;
pub use wami_provider_gcp::GcpProvider;
