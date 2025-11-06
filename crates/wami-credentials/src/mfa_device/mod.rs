//! MfaDevice Resource Module
//!
//! This module provides self-contained handling of IAM MFA device resources.

pub mod builder;
pub mod model;
// pub mod operations; // TODO: Fix field mismatches in tests
pub mod requests;

pub use builder::{add_provider_to_mfa_device, build_mfa_device};
pub use model::MfaDevice;
// Operations moved to service layer
// pub use operations::MfaDeviceOperations;
pub use requests::{EnableMfaDeviceRequest, ListMfaDevicesRequest};
