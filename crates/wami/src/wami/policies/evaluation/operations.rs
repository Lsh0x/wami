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
