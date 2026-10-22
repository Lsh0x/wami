//! Role Domain Model

use crate::arn::{ScopedName, WamiArn};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Represents an IAM role
///
/// An IAM role is similar to a user but is intended to be assumable by anyone who needs it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    /// The friendly name identifying the role
    pub role_name: String,
    /// The stable and unique identifier for the role
    pub role_id: String,
    /// The Amazon Resource Name (ARN) that identifies the role
    pub arn: String,
    /// The path to the role
    pub path: String,
    /// The date and time when the role was created
    pub create_date: DateTime<Utc>,
    /// The trust policy that grants permission to assume the role
    pub assume_role_policy_document: String,
    /// A description of the role
    pub description: Option<String>,
    /// The maximum session duration in seconds
    pub max_session_duration: Option<i32>,
    /// The ARN of the policy used to set the permissions boundary
    pub permissions_boundary: Option<String>,
    /// A list of tags associated with the role
    pub tags: Vec<crate::types::Tag>,
    /// The WAMI ARN for cross-provider identification (structured type)
    pub wami_arn: WamiArn,
    /// List of cloud providers where this resource exists
    pub providers: Vec<crate::provider::ProviderConfig>,
    /// Optional tenant ID for multi-tenant isolation
    pub tenant_id: Option<crate::wami::tenant::TenantId>,
}

impl Role {
    /// The key this role is stored and addressed under: the tenant path
    /// its `wami_arn` carries, and its name.
    ///
    /// Read from the record — never built from an ARN's resource id, which is
    /// the role's stable id, not its name (wami 005).
    pub fn key(&self) -> ScopedName {
        ScopedName::new(self.wami_arn.tenant_path.clone(), &self.role_name)
    }
}
