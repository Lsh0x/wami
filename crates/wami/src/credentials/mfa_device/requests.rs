//! MfaDevice Request and Response Types

use crate::arn::ScopedName;
use serde::{Deserialize, Serialize};

/// Request parameters for enabling an MFA device
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnableMfaDeviceRequest {
    /// The user — its tenant and its name
    pub user: ScopedName,
    /// The serial number that uniquely identifies the MFA device
    pub serial_number: String,
    /// First authentication code from the device
    pub authentication_code_1: String,
    /// Second authentication code from the device
    pub authentication_code_2: String,
}

/// Request parameters for listing MFA devices
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListMfaDevicesRequest {
    /// The user — its tenant and its name
    pub user: ScopedName,
}
