//! Group Request and Response Types

use crate::arn::ScopedName;
use crate::arn::TenantPath;
use serde::{Deserialize, Serialize};

use super::model::Group;
use crate::types::{PaginationParams, Tag};

/// Parameters for creating a group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGroupRequest {
    /// The group — its tenant and its name
    pub group: ScopedName,
    pub path: Option<String>,
    pub tags: Option<Vec<Tag>>,
}

/// Parameters for updating a group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateGroupRequest {
    /// The group — its tenant and its name
    pub group: ScopedName,
    pub new_group_name: Option<String>,
    pub new_path: Option<String>,
}

/// Parameters for listing groups
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListGroupsRequest {
    /// The tenant to list — exactly this one: never its children, never the
    /// whole store (wami 005).
    pub tenant: TenantPath,
    pub path_prefix: Option<String>,
    pub pagination: Option<PaginationParams>,
}

/// Response for listing groups
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListGroupsResponse {
    pub groups: Vec<Group>,
    pub is_truncated: bool,
    pub marker: Option<String>,
}
