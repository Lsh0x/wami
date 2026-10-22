//! Group Domain Model

use crate::arn::{ScopedName, WamiArn};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Represents an IAM group
///
/// A group is a collection of IAM users. Groups let you specify permissions for multiple users.
///
/// # Example
///
/// ```rust
/// use wami::wami::identity::group::Group;
/// use wami::arn::{WamiArn, Service};
/// use chrono::Utc;
///
/// let wami_arn = WamiArn::builder()
///     .service(Service::Iam)
///     .tenant(12345678)
///     .wami_instance("main")
///     .resource("group", "AGPACKCEVSQ6C2EXAMPLE")
///     .build()
///     .unwrap();
///
/// let group = Group {
///     group_name: "Developers".to_string(),
///     group_id: "AGPACKCEVSQ6C2EXAMPLE".to_string(),
///     arn: "arn:aws:iam::123456789012:group/Developers".to_string(),
///     path: "/engineering/".to_string(),
///     create_date: Utc::now(),
///     tags: vec![],
///     wami_arn,
///     providers: vec![],
///     tenant_id: None,
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    /// The friendly name identifying the group
    pub group_name: String,
    /// The stable and unique identifier for the group
    pub group_id: String,
    /// The Amazon Resource Name (ARN) that identifies the group
    pub arn: String,
    /// The path to the group
    pub path: String,
    /// The date and time when the group was created
    pub create_date: DateTime<Utc>,
    /// A list of tags associated with the group
    pub tags: Vec<crate::types::Tag>,
    /// The WAMI ARN for cross-provider identification (structured type)
    pub wami_arn: WamiArn,
    /// List of cloud providers where this resource exists
    pub providers: Vec<crate::provider::ProviderConfig>,
    /// Optional tenant ID for multi-tenant isolation
    pub tenant_id: Option<crate::wami::tenant::TenantId>,
}

impl Group {
    /// The key this group is stored and addressed under: the tenant path
    /// its `wami_arn` carries, and its name.
    ///
    /// Read from the record — never built from an ARN's resource id, which is
    /// the group's stable id, not its name (wami 005).
    pub fn key(&self) -> ScopedName {
        ScopedName::new(self.wami_arn.tenant_path.clone(), &self.group_name)
    }
}
