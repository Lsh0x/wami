//! User Request and Response Types

use crate::arn::ScopedName;
use crate::arn::TenantPath;
use serde::{Deserialize, Serialize};

use super::model::User;
use crate::types::{PaginationParams, Tag};

/// Parameters for creating a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUserRequest {
    /// The user — its tenant and its name
    pub user: ScopedName,
    pub path: Option<String>,
    pub permissions_boundary: Option<String>,
    pub tags: Option<Vec<Tag>>,
}

/// Parameters for updating a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateUserRequest {
    /// The user — its tenant and its name
    pub user: ScopedName,
    pub new_user_name: Option<String>,
    pub new_path: Option<String>,
}

/// Parameters for listing users
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListUsersRequest {
    /// The tenant to list — exactly this one: never its children, never the
    /// whole store (wami 005).
    pub tenant: TenantPath,
    pub path_prefix: Option<String>,
    pub pagination: Option<PaginationParams>,
}

/// Response for listing users
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListUsersResponse {
    pub users: Vec<User>,
    pub is_truncated: bool,
    pub marker: Option<String>,
}
