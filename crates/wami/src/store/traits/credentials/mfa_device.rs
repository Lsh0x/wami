//! MFA Device Store Trait
//!
//! Focused trait for MFA device storage operations

use crate::credentials::MfaDevice;
use async_trait::async_trait;
use wami_core::arn::ScopedName;
use wami_core::error::Result;

/// Store trait for IAM MFA device operations
#[async_trait]
pub trait MfaDeviceStore: Send + Sync {
    /// Create a new MFA device
    async fn create_mfa_device(&mut self, device: MfaDevice) -> Result<MfaDevice>;

    /// Get an MFA device by serial number
    async fn get_mfa_device(&self, serial_number: &str) -> Result<Option<MfaDevice>>;

    /// Delete an MFA device
    async fn delete_mfa_device(&mut self, serial_number: &str) -> Result<()>;

    /// List the MFA devices of the user stored under `owner`
    async fn list_mfa_devices(&self, owner: &ScopedName) -> Result<Vec<MfaDevice>>;
}
