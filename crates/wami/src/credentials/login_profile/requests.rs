//! LoginProfile Request and Response Types

use crate::arn::ScopedName;
use serde::{Deserialize, Serialize};

/// Request to create a login profile (console password) for a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateLoginProfileRequest {
    /// The user — its tenant and its name
    pub user: ScopedName,
    /// The new password for the user
    pub password: String,
    /// Whether the user must reset their password on next sign-in
    #[serde(default)]
    pub password_reset_required: bool,
}

/// Request to update a login profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateLoginProfileRequest {
    /// The user — its tenant and its name
    pub user: ScopedName,
    /// The new password (optional)
    pub password: Option<String>,
    /// Whether the user must reset their password on next sign-in (optional)
    pub password_reset_required: Option<bool>,
}

/// Request to get a login profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetLoginProfileRequest {
    /// The user — its tenant and its name
    pub user: ScopedName,
}
