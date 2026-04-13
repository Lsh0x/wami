//! Canonical Policy Evaluator
//!
//! Single source of truth for IAM policy evaluation logic. Used by both:
//! - `AuthorizationService` for real-time authorization decisions
//! - `EvaluationService` for policy simulation (simulate-custom-policy / simulate-principal-policy)
//!
//! # Evaluation Rules
//!
//! 1. **Deny overrides Allow**: an explicit Deny from ANY statement wins
//! 2. **Conditions narrow applicability**: a failed condition means NoMatch, not Deny
//! 3. **Glob matching**: `*` = single segment, `**` = multi-segment
//! 4. **Variable substitution**: `${tenant}`, `${principal}`, `${service}` from context

use wami_condition::{
    evaluate_condition_block, evaluator::parse_condition_block, ConditionContext,
};
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

    evaluate_condition_block(&block, cond_ctx).unwrap_or_default()
}

/// Parse a policy document JSON string, returning an empty doc on error.
pub fn parse_policy_doc(json: &str) -> PolicyDocument {
    serde_json::from_str(json).unwrap_or_else(|_| PolicyDocument {
        version: "2012-10-17".to_string(),
        statement: vec![],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use wami_core::arn::TenantPath;

    fn make_context() -> WamiContext {
        let arn: WamiArn = "arn:wami:iam:12345678:wami:999:user/alice".parse().unwrap();
        WamiContext::builder()
            .instance_id("999")
            .tenant_path(TenantPath::single(12345678))
            .caller_arn(arn)
            .is_root(false)
            .build()
            .unwrap()
    }

    fn make_policy(effect: &str, actions: &[&str], resources: &[&str]) -> PolicyDocument {
        PolicyDocument {
            version: "2012-10-17".to_string(),
            statement: vec![PolicyStatement {
                effect: effect.to_string(),
                action: actions.iter().map(|a| a.to_string()).collect(),
                resource: resources.iter().map(|r| r.to_string()).collect(),
                condition: None,
            }],
        }
    }

    fn make_statement(
        effect: &str,
        actions: &[&str],
        resources: &[&str],
        condition: Option<serde_json::Value>,
    ) -> PolicyStatement {
        PolicyStatement {
            effect: effect.to_string(),
            action: actions.iter().map(|a| a.to_string()).collect(),
            resource: resources.iter().map(|r| r.to_string()).collect(),
            condition,
        }
    }

    // ─── matches_action ───────────────────────────────────────

    #[test]
    fn matches_action_exact() {
        let actions = vec!["iam:GetUser".to_string()];
        assert!(matches_action(&actions, "iam:GetUser"));
    }

    #[test]
    fn matches_action_wildcard_star() {
        let actions = vec!["*".to_string()];
        assert!(matches_action(&actions, "iam:GetUser"));
        assert!(matches_action(&actions, "sts:AssumeRole"));
    }

    #[test]
    fn matches_action_prefix_wildcard() {
        let actions = vec!["iam:Get*".to_string()];
        assert!(matches_action(&actions, "iam:GetUser"));
        assert!(matches_action(&actions, "iam:GetRole"));
        assert!(!matches_action(&actions, "iam:PutUser"));
    }

    #[test]
    fn matches_action_no_match() {
        let actions = vec!["iam:GetUser".to_string()];
        assert!(!matches_action(&actions, "iam:DeleteUser"));
    }

    #[test]
    fn matches_action_multiple_patterns() {
        let actions = vec!["iam:GetUser".to_string(), "iam:ListUsers".to_string()];
        assert!(matches_action(&actions, "iam:GetUser"));
        assert!(matches_action(&actions, "iam:ListUsers"));
        assert!(!matches_action(&actions, "iam:DeleteUser"));
    }

    #[test]
    fn matches_action_service_wildcard() {
        let actions = vec!["iam:*".to_string()];
        assert!(matches_action(&actions, "iam:GetUser"));
        assert!(matches_action(&actions, "iam:DeleteRole"));
        assert!(!matches_action(&actions, "sts:AssumeRole"));
    }

    // ─── matches_resource ─────────────────────────────────────

    #[test]
    fn matches_resource_wildcard() {
        let resources = vec!["*".to_string()];
        let ctx = MatchContext {
            tenant: None,
            principal: None,
            service: None,
        };
        assert!(matches_resource(
            &resources,
            "arn:wami:iam:123:wami:999:user/bob",
            &ctx
        ));
    }

    #[test]
    fn matches_resource_exact() {
        let resources = vec!["arn:wami:iam:12345678:wami:999:user/bob".to_string()];
        let ctx = MatchContext {
            tenant: None,
            principal: None,
            service: None,
        };
        assert!(matches_resource(
            &resources,
            "arn:wami:iam:12345678:wami:999:user/bob",
            &ctx
        ));
        assert!(!matches_resource(
            &resources,
            "arn:wami:iam:12345678:wami:999:user/alice",
            &ctx
        ));
    }

    #[test]
    fn matches_resource_no_match() {
        let resources = vec!["arn:wami:iam:999:wami:1:role/admin".to_string()];
        let ctx = MatchContext {
            tenant: None,
            principal: None,
            service: None,
        };
        assert!(!matches_resource(
            &resources,
            "arn:wami:iam:12345678:wami:999:user/bob",
            &ctx
        ));
    }

    #[test]
    fn matches_resource_multiple() {
        let resources = vec![
            "arn:wami:iam:12345678:wami:999:user/alice".to_string(),
            "arn:wami:iam:12345678:wami:999:user/bob".to_string(),
        ];
        let ctx = MatchContext {
            tenant: None,
            principal: None,
            service: None,
        };
        assert!(matches_resource(
            &resources,
            "arn:wami:iam:12345678:wami:999:user/bob",
            &ctx
        ));
    }

    // ─── matches_condition ────────────────────────────────────

    #[test]
    fn matches_condition_no_condition() {
        let stmt = make_statement("Allow", &["iam:*"], &["*"], None);
        let cond_ctx = ConditionContext::builder().build();
        assert!(matches_condition(&stmt, &cond_ctx));
    }

    #[test]
    fn matches_condition_null_condition() {
        let stmt = make_statement("Allow", &["iam:*"], &["*"], Some(serde_json::Value::Null));
        let cond_ctx = ConditionContext::builder().build();
        assert!(matches_condition(&stmt, &cond_ctx));
    }

    #[test]
    fn matches_condition_invalid_json() {
        // A non-null, non-object value that can't be parsed as a condition block
        let stmt = make_statement(
            "Allow",
            &["iam:*"],
            &["*"],
            Some(serde_json::json!("not a condition")),
        );
        let cond_ctx = ConditionContext::builder().build();
        assert!(!matches_condition(&stmt, &cond_ctx));
    }

    // ─── parse_policy_doc ─────────────────────────────────────

    #[test]
    fn parse_policy_doc_valid() {
        let json = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:GetUser"],"Resource":["*"]}]}"#;
        let doc = parse_policy_doc(json);
        assert_eq!(doc.statement.len(), 1);
        assert_eq!(doc.statement[0].effect, "Allow");
    }

    #[test]
    fn parse_policy_doc_invalid_returns_empty() {
        let doc = parse_policy_doc("not json at all");
        assert_eq!(doc.version, "2012-10-17");
        assert!(doc.statement.is_empty());
    }

    #[test]
    fn parse_policy_doc_empty_string() {
        let doc = parse_policy_doc("");
        assert!(doc.statement.is_empty());
    }

    // ─── evaluate_policy_document ─────────────────────────────

    #[test]
    fn evaluate_allow_policy() {
        let ctx = make_context();
        let policy = make_policy("Allow", &["iam:GetUser"], &["*"]);
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();
        assert_eq!(
            evaluate_policy_document(&policy, "iam:GetUser", &resource, &ctx),
            PolicyEffect::Allow
        );
    }

    #[test]
    fn evaluate_deny_overrides_allow() {
        let ctx = make_context();
        let policy = PolicyDocument {
            version: "2012-10-17".to_string(),
            statement: vec![
                make_statement("Allow", &["iam:*"], &["*"], None),
                make_statement("Deny", &["iam:DeleteUser"], &["*"], None),
            ],
        };
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();
        assert_eq!(
            evaluate_policy_document(&policy, "iam:DeleteUser", &resource, &ctx),
            PolicyEffect::Deny
        );
    }

    #[test]
    fn evaluate_no_match() {
        let ctx = make_context();
        let policy = make_policy("Allow", &["sts:AssumeRole"], &["*"]);
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();
        assert_eq!(
            evaluate_policy_document(&policy, "iam:GetUser", &resource, &ctx),
            PolicyEffect::NoMatch
        );
    }

    #[test]
    fn evaluate_deny_only() {
        let ctx = make_context();
        let policy = make_policy("Deny", &["iam:*"], &["*"]);
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();
        assert_eq!(
            evaluate_policy_document(&policy, "iam:GetUser", &resource, &ctx),
            PolicyEffect::Deny
        );
    }

    #[test]
    fn evaluate_empty_statements() {
        let ctx = make_context();
        let policy = PolicyDocument {
            version: "2012-10-17".to_string(),
            statement: vec![],
        };
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();
        assert_eq!(
            evaluate_policy_document(&policy, "iam:GetUser", &resource, &ctx),
            PolicyEffect::NoMatch
        );
    }

    #[test]
    fn evaluate_wildcard_action_and_resource() {
        let ctx = make_context();
        let policy = make_policy("Allow", &["*"], &["*"]);
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();
        assert_eq!(
            evaluate_policy_document(&policy, "anything:Here", &resource, &ctx),
            PolicyEffect::Allow
        );
    }

    // ─── build_condition_context ──────────────────────────────

    #[test]
    fn build_condition_context_populates_fields() {
        let ctx = make_context();
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();
        let cond_ctx = build_condition_context(&ctx, &resource);
        // Verify the context was built (non-panicking is the test)
        // The builder returns a ConditionContext with the fields set
        let _ = cond_ctx;
    }

    #[test]
    fn build_condition_context_with_source_ip() {
        let arn: WamiArn = "arn:wami:iam:12345678:wami:999:user/alice".parse().unwrap();
        let ctx = WamiContext::builder()
            .instance_id("999")
            .tenant_path(TenantPath::single(12345678))
            .caller_arn(arn)
            .is_root(false)
            .source_ip("10.0.0.1")
            .build()
            .unwrap();
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();
        let cond_ctx = build_condition_context(&ctx, &resource);
        let _ = cond_ctx;
    }

    #[test]
    fn build_condition_context_with_mfa() {
        let arn: WamiArn = "arn:wami:iam:12345678:wami:999:user/alice".parse().unwrap();
        let ctx = WamiContext::builder()
            .instance_id("999")
            .tenant_path(TenantPath::single(12345678))
            .caller_arn(arn)
            .is_root(false)
            .mfa_present(true)
            .secure_transport(true)
            .build()
            .unwrap();
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();
        let cond_ctx = build_condition_context(&ctx, &resource);
        let _ = cond_ctx;
    }
}
