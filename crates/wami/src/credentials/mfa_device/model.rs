//! MfaDevice Domain Model

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use wami_core::arn::{ScopedName, WamiArn};

/// Represents an MFA (Multi-Factor Authentication) device
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaDevice {
    /// The key of the user it belongs to — its tenant and its name
    pub owner: ScopedName,
    /// The serial number that uniquely identifies the MFA device
    pub serial_number: String,
    /// The date when the MFA device was enabled
    pub enable_date: DateTime<Utc>,
    /// The WAMI ARN for cross-provider identification
    pub wami_arn: WamiArn,
    /// List of cloud providers where this resource exists
    pub providers: Vec<crate::provider::ProviderConfig>,
}
