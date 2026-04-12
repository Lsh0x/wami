//! Canonical Policy Evaluator
//!
//! Single source of truth for IAM policy evaluation logic. Used by both:
//! - [`AuthorizationService`] for real-time authorization decisions
//! - [`EvaluationService`] for policy simulation (simulate-custom-policy / simulate-principal-policy)
//!
//! # Evaluation Rules
//!
//! 1. **Deny overrides Allow**: an explicit Deny from ANY statement wins
//! 2. **Conditions narrow applicability**: a failed condition means NoMatch, not Deny
//! 3. **Glob matching**: `*` = single segment, `**` = multi-segment
//! 4. **Variable substitution**: `${tenant}`, `${principal}`, `${service}` from context

use wami_condition::{evaluate_condition_block, evaluator::parse_condition_block, ConditionContext};
use wami_core::arn::matching::{glob_match, matches_arn_pattern, MatchContext};
use wami_core::arn::WamiArn;
use wami_core::context::WamiContext;
use wami_core::types::{PolicyDocument, PolicyStatement};

/// Policy evaluation result for a single policy document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyEffect {
    /// Policy explicitly allows the action
    Allow,
    /// Policy explicitly denies the action (overrides any allow)
    Deny,
    /// Policy doesn't match this action/resource (or condition failed)
    NoMatch,
}

/// Evaluate a single policy document against an action and resource.
///
/// Returns:
/// - `Allow` if the policy explicitly allows the action
/// - `Deny` if the policy explicitly denies the action
/// - `NoMatch` if the policy doesn't apply
pub fn evaluate_policy_document(
    policy: &PolicyDocument,
    action: &str,
    resource_arn: &WamiArn,
    context: &WamiContext,
) -> PolicyEffect {
    let resource_str = resource_arn.to_string();
    let match_ctx = MatchContext {
        tenant: Some(context.tenant_path().as_string()),
        principal: Some(context.caller_arn().resource.resource_id.clone()),
        service: Some(context.caller_arn().service.to_string()),
    };
    let cond_ctx = build_condition_context(context, resource_arn);

    // First check for explicit denies (deny overrides allow)
    for statement in &policy.statement {
        if statement.effect.to_lowercase() == "deny"
            && matches_action(&statement.action, action)
            && matches_resource(&statement.resource, &resource_str, &match_ctx)
            && matches_condition(statement, &cond_ctx)
        {
            return PolicyEffect::Deny;
        }
    }

    // Then check for allows
    for statement in &policy.statement {
        if statement.effect.to_lowercase() == "allow"
            && matches_action(&statement.action, action)
            && matches_resource(&statement.resource, &resource_str, &match_ctx)
            && matches_condition(statement, &cond_ctx)
        {
            return PolicyEffect::Allow;
        }
    }

    PolicyEffect::NoMatch
}

/// Check if an action matches any of the policy action patterns.
///
/// Supports wildcards via `glob_match`: `iam:*`, `*`, `iam:Get*`
pub fn matches_action(policy_actions: &[String], action: &str) -> bool {
    for policy_action in policy_actions {
        if glob_match(policy_action, action) {
            return true;
        }
    }
    false
}

/// Check if a resource matches any of the policy resource patterns.
///
/// Supports:
/// - `*` (match all)
/// - Single-star wildcards: `arn:wami:iam:*:user/*`
/// - Double-star globbing: `arn:wami:hub:*:space/le-zinc/**`
/// - Variable substitution: `${tenant}`, `${principal}`, `${service}`
pub fn matches_resource(
    policy_resources: &[String],
    resource: &str,
    match_ctx: &MatchContext,
) -> bool {
    for policy_resource in policy_resources {
        if matches_arn_pattern(policy_resource, resource, match_ctx) {
            return true;
        }
    }
    false
}

/// Build a [`ConditionContext`] from a [`WamiContext`] and the target resource ARN.
pub fn build_condition_context(context: &WamiContext, resource_arn: &WamiArn) -> ConditionContext {
    let mut builder = ConditionContext::builder()
        .principal_arn(context.caller_arn().to_string())
        .username(context.caller_arn().resource.resource_id.clone())
        .principal_type(context.caller_arn().resource.resource_type.clone())
        .resource_arn(resource_arn.to_string());

    // Tenant info
    if let Some(primary) = context.tenant_path().root_u64() {
        builder = builder.tenant_id(primary).principal_tenant_id(primary);
    }
    if let Some(resource_tenant) = resource_arn.tenant_path.root_u64() {
        builder = builder.resource_tenant_id(resource_tenant);
    }

    // Request metadata (set by HTTP/transport layer)
    if let Some(ip) = context.source_ip() {
        builder = builder.source_ip(ip);
    }
    if let Some(mfa) = context.mfa_present() {
        builder = builder.mfa_present(mfa);
    }
    if let Some(secure) = context.secure_transport() {
        builder = builder.secure_transport(secure);
    }

    builder.build()
}

/// Evaluate the condition block of a policy statement (if present).
///
/// Returns `true` if:
/// - The statement has no condition (unconditional match), OR
/// - The condition block evaluates to `true`.
///
/// Returns `false` if the condition cannot be parsed or evaluates to `false`.
pub fn matches_condition(statement: &PolicyStatement, cond_ctx: &ConditionContext) -> bool {
    let condition_value = match &statement.condition {
        Some(v) if !v.is_null() => v,
        _ => return true, // No condition → always matches
    };

    let block = match parse_condition_block(condition_value) {
        Ok(b) => b,
        Err(_) => return false,
    };

    match evaluate_condition_block(&block, cond_ctx) {
        Ok(result) => result,
        Err(_) => false,
    }
}

/// Parse a policy document JSON string, returning an empty doc on error.
pub fn parse_policy_doc(json: &str) -> PolicyDocument {
    serde_json::from_str(json).unwrap_or_else(|_| PolicyDocument {
        version: "2012-10-17".to_string(),
        statement: vec![],
    })
}
