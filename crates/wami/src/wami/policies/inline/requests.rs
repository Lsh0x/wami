//! Inline Policy Request Types

use crate::arn::ScopedName;
use serde::{Deserialize, Serialize};

// User inline policy requests

/// Request to put an inline policy on a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PutUserPolicyRequest {
    /// The user — its tenant and its name
    pub user: ScopedName,
    /// The name of the policy
    pub policy_name: String,
    /// The policy document in JSON format
    pub policy_document: String,
}

/// Request to get an inline policy from a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetUserPolicyRequest {
    /// The user — its tenant and its name
    pub user: ScopedName,
    /// The name of the policy
    pub policy_name: String,
}

/// Request to delete an inline policy from a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteUserPolicyRequest {
    /// The user — its tenant and its name
    pub user: ScopedName,
    /// The name of the policy
    pub policy_name: String,
}

/// Request to list inline policies for a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListUserPoliciesRequest {
    /// The user — its tenant and its name
    pub user: ScopedName,
}

// Group inline policy requests

/// Request to put an inline policy on a group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PutGroupPolicyRequest {
    /// The group — its tenant and its name
    pub group: ScopedName,
    /// The name of the policy
    pub policy_name: String,
    /// The policy document in JSON format
    pub policy_document: String,
}

/// Request to get an inline policy from a group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetGroupPolicyRequest {
    /// The group — its tenant and its name
    pub group: ScopedName,
    /// The name of the policy
    pub policy_name: String,
}

/// Request to delete an inline policy from a group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteGroupPolicyRequest {
    /// The group — its tenant and its name
    pub group: ScopedName,
    /// The name of the policy
    pub policy_name: String,
}

/// Request to list inline policies for a group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListGroupPoliciesRequest {
    /// The group — its tenant and its name
    pub group: ScopedName,
}

// Role inline policy requests

/// Request to put an inline policy on a role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PutRolePolicyRequest {
    /// The role — its tenant and its name
    pub role: ScopedName,
    /// The name of the policy
    pub policy_name: String,
    /// The policy document in JSON format
    pub policy_document: String,
}

/// Request to get an inline policy from a role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetRolePolicyRequest {
    /// The role — its tenant and its name
    pub role: ScopedName,
    /// The name of the policy
    pub policy_name: String,
}

/// Request to delete an inline policy from a role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteRolePolicyRequest {
    /// The role — its tenant and its name
    pub role: ScopedName,
    /// The name of the policy
    pub policy_name: String,
}

/// Request to list inline policies for a role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListRolePoliciesRequest {
    /// The role — its tenant and its name
    pub role: ScopedName,
}
