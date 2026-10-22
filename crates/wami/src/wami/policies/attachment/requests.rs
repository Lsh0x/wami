//! Policy Attachment Request Types

use crate::arn::ScopedName;
use serde::{Deserialize, Serialize};

/// Request to attach a managed policy to a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachUserPolicyRequest {
    /// The user — its tenant and its name
    pub user: ScopedName,
    /// The ARN of the policy to attach
    pub policy_arn: String,
}

/// Request to detach a managed policy from a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetachUserPolicyRequest {
    /// The user — its tenant and its name
    pub user: ScopedName,
    /// The ARN of the policy to detach
    pub policy_arn: String,
}

/// Request to list attached policies for a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListAttachedUserPoliciesRequest {
    /// The user — its tenant and its name
    pub user: ScopedName,
}

/// Request to attach a managed policy to a group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachGroupPolicyRequest {
    /// The group — its tenant and its name
    pub group: ScopedName,
    /// The ARN of the policy to attach
    pub policy_arn: String,
}

/// Request to detach a managed policy from a group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetachGroupPolicyRequest {
    /// The group — its tenant and its name
    pub group: ScopedName,
    /// The ARN of the policy to detach
    pub policy_arn: String,
}

/// Request to list attached policies for a group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListAttachedGroupPoliciesRequest {
    /// The group — its tenant and its name
    pub group: ScopedName,
}

/// Request to attach a managed policy to a role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachRolePolicyRequest {
    /// The role — its tenant and its name
    pub role: ScopedName,
    /// The ARN of the policy to attach
    pub policy_arn: String,
}

/// Request to detach a managed policy from a role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetachRolePolicyRequest {
    /// The role — its tenant and its name
    pub role: ScopedName,
    /// The ARN of the policy to detach
    pub policy_arn: String,
}

/// Request to list attached policies for a role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListAttachedRolePoliciesRequest {
    /// The role — its tenant and its name
    pub role: ScopedName,
}
