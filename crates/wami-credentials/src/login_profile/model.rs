//! LoginProfile Domain Model

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use wami_core::arn::WamiArn;

/// Represents a login profile (console password) for an IAM user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginProfile {
    /// The user with whom the login profile is associated
    pub user_name: String,
    /// The date when the login profile was created
    pub create_date: DateTime<Utc>,
    /// Whether the user must reset their password on next sign-in
    pub password_reset_required: bool,
    /// The WAMI ARN for cross-provider identification
    pub wami_arn: WamiArn,
    /// List of cloud providers where this resource exists
    pub providers: Vec<wami_provider::ProviderConfig>,
}
