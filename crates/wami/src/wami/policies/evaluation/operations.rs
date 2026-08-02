//! Policy Evaluation Domain Operations
//!
//! **Deprecated**: Use [`crate::service::auth::policy_evaluator`] instead.
//!
//! This module is kept for backward compatibility but delegates to the
//! canonical policy evaluator. The old simple matchers (no glob, no conditions,
//! no variable substitution) have been replaced.

/// Evaluation result (deprecated — use [`crate::service::auth::PolicyEffect`])
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvaluationResult {
    Allow,
    Deny,
    ImplicitDeny,
}

#[deprecated(note = "Use crate::service::auth::policy_evaluator functions instead")]
pub mod policy_evaluation_operations {
    use super::EvaluationResult;
    use crate::service::auth::policy_evaluator;
    use wami_core::arn::matching::MatchContext;
    use wami_core::types::PolicyDocument;

    /// Evaluate if an action is allowed by a policy.
    ///
    /// **Deprecated**: Does not support conditions, glob, or variable substitution.
    /// Use [`policy_evaluator::evaluate_policy_document`] instead.
    pub fn is_action_allowed(
        policy_doc: &PolicyDocument,
        action: &str,
        _resource: &str,
    ) -> bool {
        // Simplified: only check action matching (no WamiContext available)
        for statement in &policy_doc.statement {
            let action_matches = policy_evaluator::matches_action(&statement.action, action);
            if action_matches && statement.effect.to_lowercase() == "allow" {
                return true;
            }
        }
        false
    }

    /// Evaluate multiple policies.
    ///
    /// **Deprecated**: Use the full authorization pipeline instead.
    pub fn evaluate_policies(
        policies: &[PolicyDocument],
        action: &str,
        _resource: &str,
    ) -> EvaluationResult {
        let mut has_allow = false;
        let mut has_deny = false;

        for policy in policies {
            for statement in &policy.statement {
                let action_matches = policy_evaluator::matches_action(&statement.action, action);
                if action_matches {
                    if statement.effect.to_lowercase() == "deny" {
                        has_deny = true;
                    } else if statement.effect.to_lowercase() == "allow" {
                        has_allow = true;
                    }
                }
            }
        }

        if has_deny {
            EvaluationResult::Deny
        } else if has_allow {
            EvaluationResult::Allow
        } else {
            EvaluationResult::ImplicitDeny
        }
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use policy_evaluation_operations::*;
    use wami_core::types::{PolicyDocument, PolicyStatement};

    fn make_policy(effect: &str, actions: &[&str]) -> PolicyDocument {
        PolicyDocument {
            version: "2012-10-17".to_string(),
            statement: vec![PolicyStatement {
                sid: None,
                effect: effect.to_string(),
                action: actions.iter().map(|a| a.to_string()).collect(),
                resource: vec!["*".to_string()],
                condition: None,
            }],
        }
    }

    // ─── is_action_allowed ────────────────────────────────────

    #[test]
    fn is_action_allowed_matching() {
        let policy = make_policy("Allow", &["iam:GetUser"]);
        assert!(is_action_allowed(&policy, "iam:GetUser", "*"));
    }

    #[test]
    fn is_action_allowed_no_match() {
        let policy = make_policy("Allow", &["iam:GetUser"]);
        assert!(!is_action_allowed(&policy, "iam:DeleteUser", "*"));
    }

    #[test]
    fn is_action_allowed_wildcard() {
        let policy = make_policy("Allow", &["*"]);
        assert!(is_action_allowed(&policy, "iam:GetUser", "*"));
        assert!(is_action_allowed(&policy, "sts:AssumeRole", "*"));
    }

    #[test]
    fn is_action_allowed_deny_effect_returns_false() {
        let policy = make_policy("Deny", &["iam:GetUser"]);
        assert!(!is_action_allowed(&policy, "iam:GetUser", "*"));
    }

    #[test]
    fn is_action_allowed_prefix_wildcard() {
        let policy = make_policy("Allow", &["iam:Get*"]);
        assert!(is_action_allowed(&policy, "iam:GetUser", "*"));
        assert!(is_action_allowed(&policy, "iam:GetRole", "*"));
        assert!(!is_action_allowed(&policy, "iam:PutUser", "*"));
    }

    // ─── evaluate_policies ────────────────────────────────────

    #[test]
    fn evaluate_single_allow() {
        let policies = vec![make_policy("Allow", &["iam:GetUser"])];
        assert_eq!(
            evaluate_policies(&policies, "iam:GetUser", "*"),
            EvaluationResult::Allow
        );
    }

    #[test]
    fn evaluate_single_deny() {
        let policies = vec![make_policy("Deny", &["iam:GetUser"])];
        assert_eq!(
            evaluate_policies(&policies, "iam:GetUser", "*"),
            EvaluationResult::Deny
        );
    }

    #[test]
    fn evaluate_deny_overrides_allow() {
        let policies = vec![
            make_policy("Allow", &["iam:GetUser"]),
            make_policy("Deny", &["iam:GetUser"]),
        ];
        assert_eq!(
            evaluate_policies(&policies, "iam:GetUser", "*"),
            EvaluationResult::Deny
        );
    }

    #[test]
    fn evaluate_no_match_implicit_deny() {
        let policies = vec![make_policy("Allow", &["sts:AssumeRole"])];
        assert_eq!(
            evaluate_policies(&policies, "iam:GetUser", "*"),
            EvaluationResult::ImplicitDeny
        );
    }

    #[test]
    fn evaluate_empty_policies() {
        let policies: Vec<PolicyDocument> = vec![];
        assert_eq!(
            evaluate_policies(&policies, "iam:GetUser", "*"),
            EvaluationResult::ImplicitDeny
        );
    }

    #[test]
    fn evaluate_mixed_policies() {
        let policies = vec![
            make_policy("Allow", &["iam:*"]),
            make_policy("Deny", &["iam:DeleteUser"]),
        ];
        // GetUser matches allow but not deny
        assert_eq!(
            evaluate_policies(&policies, "iam:GetUser", "*"),
            EvaluationResult::Allow
        );
        // DeleteUser matches both → deny wins
        assert_eq!(
            evaluate_policies(&policies, "iam:DeleteUser", "*"),
            EvaluationResult::Deny
        );
    }

    // ─── EvaluationResult ─────────────────────────────────────

    #[test]
    fn evaluation_result_debug() {
        assert_eq!(format!("{:?}", EvaluationResult::Allow), "Allow");
        assert_eq!(format!("{:?}", EvaluationResult::Deny), "Deny");
        assert_eq!(
            format!("{:?}", EvaluationResult::ImplicitDeny),
            "ImplicitDeny"
        );
    }

    #[test]
    fn evaluation_result_eq() {
        assert_eq!(EvaluationResult::Allow, EvaluationResult::Allow);
        assert_ne!(EvaluationResult::Allow, EvaluationResult::Deny);
    }
}
