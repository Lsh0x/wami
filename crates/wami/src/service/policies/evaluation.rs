//! Policy Evaluation Service
//!
//! Orchestrates policy simulation and evaluation operations.
//!
//! The simulation walks statements with its own evaluator, not with
//! `service::auth::policy_evaluator` — two evaluators until wami 003. A
//! simulation exists to tell an operator what the authorizer does, so where
//! the authorizer refuses a document (an unreadable condition), the simulation
//! returns the same error rather than a verdict; a test holds the two to it
//! (`the_simulation_and_the_authorizer_agree_on_an_unreadable_condition`).

use crate::provider::{AwsProvider, CloudProvider};
use crate::service::auth::decision::PolicySource;
use crate::service::auth::policy_evaluator::{self, PolicyEffect};
use crate::store::traits::{PolicyStore, RoleStore, UserStore};
use crate::wami::policies::evaluation::{
    ContextEntry, EvaluationResult, SimulateCustomPolicyRequest, SimulatePolicyResponse,
    SimulatePrincipalPolicyRequest, StatementMatch,
};
use crate::wami::policies::permissions_boundary::PrincipalType;
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::RwLock;
use wami_condition::evaluator::parse_condition_block;
use wami_condition::{evaluate_condition_block, keys, ConditionContext, ConditionValue};
use wami_core::arn::ScopedName;
use wami_core::error::{AmiError, Result};
use wami_core::types::{PolicyDocument, PolicyStatement};

/// A document and the name an error gives it.
type Named = (String, PolicyDocument);

/// Where a simulated document comes from, in reading order: the principal's
/// stored documents, then the request's.
type Origin = (u8, usize);

/// Parse the documents a request hands in, through the authorizer's own
/// decoder. JSON that is no policy document is a malformed request
/// (`InvalidParameter`, as before, now saying where rather than quoting it);
/// the documents are then checked as the authorizer checks them, by
/// [`check_every_document`].
fn parse_simulated(jsons: &[String]) -> Result<Vec<(Origin, Named)>> {
    jsons
        .iter()
        .enumerate()
        .map(|(i, json)| {
            let name = format!("policy_input_list[{i}]");
            let document = policy_evaluator::decode_policy_document(json, &name).map_err(|e| {
                AmiError::InvalidParameter {
                    message: format!("Invalid policy document: {e}"),
                }
            })?;
            Ok(((1, i), (name, document)))
        })
        .collect()
}

/// The documents in the authorizer's reading order — by the same function —
/// with their names.
fn in_reading_order(identity: Vec<(Origin, Named)>, boundary: Option<Named>) -> Vec<Named> {
    policy_evaluator::in_reading_order(identity, boundary.map(|named| ((2, 0), named)))
        .into_iter()
        .map(|(_, named)| named)
        .collect()
}

/// Check every document as the authorizer does before it evaluates anything
/// (wami 001: read everything before deciding); refuse, naming every one that
/// cannot be read, in the order given.
///
/// `boundary_unreadable` is a boundary whose JSON could not be parsed: named
/// last, where the authorizer names the boundary.
fn check_every_document(documents: &[Named], boundary_unreadable: Option<AmiError>) -> Result<()> {
    let unreadable = documents
        .iter()
        .filter_map(|(name, document)| policy_evaluator::check_statements(document, name).err())
        .chain(boundary_unreadable)
        .collect();
    match policy_evaluator::combine(unreadable) {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// What a simulation reads of its principal.
struct SimulatedPrincipal {
    /// Its stored `wami_arn`, for the condition context.
    arn: String,
    /// The ARN of its permissions boundary, if any.
    boundary: Option<String>,
}

pub trait EvaluationServiceStore: UserStore + RoleStore + PolicyStore {}
impl<T> EvaluationServiceStore for T where T: UserStore + RoleStore + PolicyStore {}

/// Service for policy simulation and evaluation
///
/// Provides high-level operations for testing and validating IAM policies.
#[wami_macros::service(
    store_trait = "crate::service::policies::evaluation::EvaluationServiceStore",
    generate_new = false
)]
pub struct EvaluationService<S> {
    store: Arc<RwLock<S>>,
    #[allow(dead_code)]
    provider: Arc<dyn CloudProvider>,
    account_id: String,
}

impl<S: EvaluationServiceStore> EvaluationService<S> {
    /// Create a new EvaluationService with default AWS provider
    pub fn new(store: Arc<RwLock<S>>, account_id: String) -> Self {
        Self {
            store,
            provider: Arc::new(AwsProvider::new()),
            account_id,
        }
    }

    /// Returns a new service instance with different provider
    pub fn with_provider(&self, provider: Arc<dyn CloudProvider>) -> Self {
        Self {
            store: self.store.clone(),
            provider,
            account_id: self.account_id.clone(),
        }
    }

    /// Simulate custom policy documents without creating them
    ///
    /// This is a stateless operation that evaluates policy documents directly.
    ///
    /// # Errors
    ///
    /// The authorizer's own errors where it would refuse to decide:
    /// [`AmiError::UnreadablePolicy`] for a statement that cannot be read —
    /// a misspelt `Effect`, a condition that cannot be — and
    /// [`AmiError::UnreadableCondition`] for a condition that cannot be
    /// evaluated against the request's context. Every document is read
    /// before any verdict, and every unreadable one is named
    /// (`policy_input_list[i]` and the statement), in order. The whole call
    /// errs: a response carries one verdict string per action and resource,
    /// and a verdict is exactly what cannot honestly be given.
    pub async fn simulate_custom_policy(
        &self,
        request: SimulateCustomPolicyRequest,
    ) -> Result<SimulatePolicyResponse> {
        // Parse policy documents, and read every one before deciding anything
        let policies = in_reading_order(parse_simulated(&request.policy_input_list)?, None);
        check_every_document(&policies, None)?;

        // Default resource if not provided
        let resources = request
            .resource_arns
            .unwrap_or_else(|| vec!["*".to_string()]);

        // Build condition context from request context entries
        let condition_context = self.build_condition_context(
            request.context_entries.as_deref(),
            None, // principal_arn not available in custom policy simulation
            None, // resource_arn will be set per evaluation
        )?;

        // Evaluate each action against each resource
        let mut results = Vec::new();

        for action in &request.action_names {
            for resource in &resources {
                // Update context with current resource
                let mut context = condition_context.clone();
                context.resource_arn = Some(resource.clone());

                let decision = self.evaluate_action(&policies, action, resource, &context)?;
                let matched_statements = self.find_matching_statements(&policies, action, resource);

                results.push(EvaluationResult {
                    eval_action_name: action.clone(),
                    eval_resource_name: resource.clone(),
                    eval_decision: decision,
                    matched_statements,
                    missing_context_values: vec![], // TODO: Track missing context keys
                });
            }
        }

        Ok(SimulatePolicyResponse {
            evaluation_results: results,
            is_truncated: false,
        })
    }

    /// Simulate a principal's (user or role) effective policies
    ///
    /// Fetches the principal's attached policies from the store and evaluates them.
    ///
    /// # Errors
    ///
    /// As [`Self::simulate_custom_policy`]; and the permissions boundary is
    /// read with the identity documents, last, as the authorizer reads it —
    /// before any verdict and whatever the identity verdict — so a boundary
    /// the authorizer cannot read or compare fails here with the same error.
    pub async fn simulate_principal_policy(
        &self,
        request: SimulatePrincipalPolicyRequest,
    ) -> Result<SimulatePolicyResponse> {
        // The principal is named by its key — the tenant explicitly — and read
        // once: a name parsed out of an ARN named a principal in every tenant,
        // and the resource id of a wami ARN is an id, not a name (wami 005).
        let principal = self
            .fetch_principal(request.principal_type, &request.principal)
            .await?;

        // The principal's own documents are not gathered here yet (the store
        // holds them; this simulation has never read them): the request's
        // `policy_input_list` stands in, checked with the others all the same.
        let mut identity: Vec<(Origin, Named)> = Vec::new();

        // Add additional policy documents from request if provided
        if let Some(extra_policies) = request.policy_input_list {
            identity.extend(parse_simulated(&extra_policies)?);
        }
        let policies = in_reading_order(identity, None);

        // The boundary, named as the authorizer names it and read with the
        // identity documents, last, as the authorizer reads it: before any
        // evaluation and whatever the identity verdict.
        let boundary = match principal.boundary {
            // A boundary of another tenant takes no part (ruling 1).
            Some(arn) => match self.store.read().await.get_policy(&arn).await? {
                Some(policy) if &policy.wami_arn.tenant_path != request.principal.tenant() => {
                    return Err(AmiError::UnreadablePolicy {
                        policy: format!("permissions boundary {arn}"),
                        message: "the policy is not of the principal's tenant".to_string(),
                    });
                }
                other => other,
            },
            None => None,
        };
        let boundary_named = boundary.as_ref().map(|boundary| {
            let source = PolicySource::PermissionsBoundary {
                arn: boundary.arn.clone(),
            };
            policy_evaluator::decode_policy_document(&boundary.policy_document, &source.to_string())
                .map(|document| (source.to_string(), document))
        });
        let (boundary_named, boundary_unreadable) = match boundary_named {
            Some(Ok(named)) => (Some(named), None),
            Some(Err(e)) => (None, Some(e)),
            None => (None, None),
        };
        let read = policies
            .iter()
            .cloned()
            .enumerate()
            .map(|(i, named)| ((0, i), named))
            .collect();
        let read = in_reading_order(read, boundary_named.clone());
        check_every_document(&read, boundary_unreadable)?;

        // Default resource if not provided
        let resources = request
            .resource_arns
            .unwrap_or_else(|| vec!["*".to_string()]);

        // Build condition context from request context entries and principal ARN
        let condition_context = self.build_condition_context(
            request.context_entries.as_deref(),
            Some(&principal.arn),
            None, // resource_arn will be set per evaluation
        )?;

        // Evaluate each action against each resource
        let mut results = Vec::new();

        for action in &request.action_names {
            for resource in &resources {
                // Update context with current resource
                let mut context = condition_context.clone();
                context.resource_arn = Some(resource.clone());

                // Use boundary-aware evaluation if boundary exists
                let decision = self.evaluate_action_with_boundary(
                    &policies,
                    action,
                    resource,
                    boundary.as_ref().zip(boundary_named.as_ref()),
                    &context,
                )?;
                let matched_statements = self.find_matching_statements(&policies, action, resource);

                results.push(EvaluationResult {
                    eval_action_name: action.clone(),
                    eval_resource_name: resource.clone(),
                    eval_decision: decision,
                    matched_statements,
                    missing_context_values: vec![], // TODO: Track missing context keys
                });
            }
        }

        Ok(SimulatePolicyResponse {
            evaluation_results: results,
            is_truncated: false,
        })
    }

    // Helper methods

    /// The principal stored under `key`, as the simulation needs it: its ARN
    /// (for the condition context) and the ARN of its permissions boundary.
    async fn fetch_principal(
        &self,
        principal_type: PrincipalType,
        key: &ScopedName,
    ) -> Result<SimulatedPrincipal> {
        let store = self.store.read().await;
        match principal_type {
            PrincipalType::User => {
                let user =
                    store
                        .get_user(key)
                        .await?
                        .ok_or_else(|| AmiError::ResourceNotFound {
                            resource: format!("User: {key}"),
                        })?;
                Ok(SimulatedPrincipal {
                    arn: user.wami_arn.to_string(),
                    boundary: user.permissions_boundary,
                })
            }
            PrincipalType::Role => {
                let role =
                    store
                        .get_role(key)
                        .await?
                        .ok_or_else(|| AmiError::ResourceNotFound {
                            resource: format!("Role: {key}"),
                        })?;
                Ok(SimulatedPrincipal {
                    arn: role.wami_arn.to_string(),
                    boundary: role.permissions_boundary,
                })
            }
        }
    }

    /// Read every statement of every document that matches the action and
    /// resource, and say per document whether a Deny and whether an Allow
    /// applies — or refuse, naming every statement whose condition cannot be
    /// compared, before any verdict (wami 001, read everything before
    /// deciding: a Deny that holds does not excuse a broken statement).
    fn effects_per_document(
        &self,
        policies: &[Named],
        action: &str,
        resource: &str,
        context: &ConditionContext,
    ) -> Result<Vec<(bool, bool)>> {
        let mut effects = Vec::new();
        let mut unreadable = Vec::new();
        for (name, policy) in policies {
            let (mut deny, mut allow) = (false, false);
            for (index, statement) in policy.statement.iter().enumerate() {
                let matches = statement
                    .action
                    .iter()
                    .any(|a| Self::matches_pattern(action, a))
                    && statement
                        .resource
                        .iter()
                        .any(|r| Self::matches_pattern(resource, r));
                if !matches {
                    continue;
                }
                match self.condition_holds(name, index, statement, context) {
                    Ok(true) => match policy_evaluator::effect_of(statement) {
                        Some(PolicyEffect::Deny) => deny = true,
                        Some(PolicyEffect::Allow) => allow = true,
                        _ => {}
                    },
                    Ok(false) => {}
                    Err(e) => unreadable.push(e),
                }
            }
            effects.push((deny, allow));
        }
        match policy_evaluator::combine(unreadable) {
            Some(error) => Err(error),
            None => Ok(effects),
        }
    }

    /// Evaluate a single action/resource combination against policies
    fn evaluate_action(
        &self,
        policies: &[Named],
        action: &str,
        resource: &str,
        context: &ConditionContext,
    ) -> Result<String> {
        let effects = self.effects_per_document(policies, action, resource, context)?;
        // Explicit deny always wins
        Ok(if effects.iter().any(|(deny, _)| *deny) {
            "denied".to_string()
        } else if effects.iter().any(|(_, allow)| *allow) {
            "allowed".to_string()
        } else {
            "implicitDeny".to_string()
        })
    }

    /// Evaluate action with permissions boundary
    ///
    /// Implements AWS permissions boundary logic:
    /// 1. Check identity policies (user/role policies)
    /// 2. Check permissions boundary
    /// 3. Effective permissions = intersection of both
    ///
    /// If either denies, the final result is deny.
    ///
    /// The boundary's statements are read with the identity documents, before
    /// any verdict, so a condition the authorizer cannot compare refuses here
    /// too, whatever the identity verdict.
    fn evaluate_action_with_boundary(
        &self,
        policies: &[Named],
        action: &str,
        resource: &str,
        boundary: Option<(&crate::wami::policies::Policy, &Named)>,
        context: &ConditionContext,
    ) -> Result<String> {
        let mut read = policies.to_vec();
        read.extend(boundary.map(|(_, named)| named.clone()));
        let mut effects = self.effects_per_document(&read, action, resource, context)?;
        if boundary.is_some() {
            effects.pop();
        }

        // Step 1: an explicit deny in the identity policies
        if effects.iter().any(|(deny, _)| *deny) {
            return Ok("denied".to_string());
        }
        // Step 2: something must allow it
        if !effects.iter().any(|(_, allow)| *allow) {
            return Ok("implicitDeny".to_string());
        }

        // Step 3: Check permissions boundary (if present)
        // Note: the verdict below does not support conditions: a FALSE
        // condition in the boundary is ignored here while the authorizer
        // honours it — a divergence of its own, for wami 003. An UNREADABLE
        // one cannot get this far: the boundary was read above, with the
        // identity documents, as the authorizer reads it.
        if let Some((boundary_policy, _)) = boundary {
            // A boundary that cannot be evaluated is an error, never a
            // verdict: it used to answer "denied" (wami 001, Δ15).
            let allowed =
                crate::wami::policies::permissions_boundary::operations::is_allowed_by_boundary(
                    action,
                    resource,
                    boundary_policy,
                )?;
            if !allowed {
                return Ok("denied".to_string()); // Boundary restricts the action
            }
        }

        // Both identity policies and boundary allow
        Ok("allowed".to_string())
    }

    /// Find all statements that match the action/resource
    fn find_matching_statements(
        &self,
        policies: &[Named],
        action: &str,
        resource: &str,
    ) -> Vec<StatementMatch> {
        let mut matches = Vec::new();

        for (_, policy) in policies {
            for statement in &policy.statement {
                let action_matches = statement
                    .action
                    .iter()
                    .any(|a| Self::matches_pattern(action, a));

                let resource_matches = statement
                    .resource
                    .iter()
                    .any(|r| Self::matches_pattern(resource, r));

                if action_matches || resource_matches {
                    matches.push(StatementMatch {
                        source_policy_id: None, // PolicyStatement doesn't have sid field
                        effect: statement.effect.clone(),
                        matched_action: action_matches,
                        matched_resource: resource_matches,
                    });
                }
            }
        }

        matches
    }

    /// Check if a value matches a pattern (with wildcard support)
    fn matches_pattern(value: &str, pattern: &str) -> bool {
        if pattern == "*" {
            return true;
        }

        if let Some(prefix) = pattern.strip_suffix('*') {
            return value.starts_with(prefix);
        }

        value == pattern
    }

    /// Build a ConditionContext from request context entries
    ///
    /// Every DECLARED key is written through the key table, to the field it is
    /// read from, parsed as its declared type (wami 001): written to the custom
    /// values as before, a declared key read as absent, so a Deny on it was
    /// false; and an entry whose value did not parse vanished the same way. A
    /// key nobody declared is kept as text — one string, or a list of them —
    /// whatever type the entry claims, since only string operators compare it.
    ///
    /// # Errors
    ///
    /// [`AmiError::InvalidParameter`] naming the entry and its key's type when
    /// its value does not read as that type — never the value.
    fn build_condition_context(
        &self,
        context_entries: Option<&[ContextEntry]>,
        principal_arn: Option<&str>,
        resource_arn: Option<&str>,
    ) -> Result<ConditionContext> {
        let mut builder = ConditionContext::builder().current_time(chrono::Utc::now());
        if let Some(arn) = resource_arn {
            builder = builder.resource_arn(arn);
        }
        if let Some(arn) = principal_arn {
            builder = builder.principal_arn(arn);
            if let Some(account_id) = self.extract_account_id_from_arn(arn) {
                builder = builder.principal_account(account_id);
            }
        }
        let mut context = builder.build();

        for entry in context_entries.unwrap_or_default() {
            let key = &entry.context_key_name;
            let values = &entry.context_key_values;
            match keys::assign_context_value(&mut context, key, values) {
                Ok(true) => {}
                Ok(false) => {
                    let value = match values.as_slice() {
                        [one] if !entry.context_key_type.ends_with("List") => {
                            ConditionValue::String(one.clone())
                        }
                        _ => ConditionValue::Array(values.clone()),
                    };
                    context.custom_values.insert(key.clone(), value);
                }
                Err(_) => {
                    let expected = keys::key_type(key).map_or("text", |t| t.describe());
                    return Err(AmiError::InvalidParameter {
                        message: format!(
                            "context entry {key} cannot be read as {expected} (one value \
                             unless the key holds a list)"
                        ),
                    });
                }
            }
        }
        Ok(context)
    }

    /// Extract account ID from ARN (e.g., "arn:aws:iam::123456789012:user/alice" -> "123456789012")
    fn extract_account_id_from_arn(&self, arn: &str) -> Option<String> {
        let parts: Vec<&str> = arn.split(':').collect();
        if parts.len() >= 5 {
            Some(parts[4].to_string())
        } else {
            None
        }
    }

    /// Whether a statement's condition holds, or — when it cannot be read —
    /// the error the authorizer gives for it, `policy` and the statement named.
    ///
    /// Each of the three call sites used to answer `Err(_) => false`, so a
    /// simulation said "allowed" for a Deny the authorizer refuses to read.
    fn condition_holds(
        &self,
        policy: &str,
        index: usize,
        statement: &PolicyStatement,
        context: &ConditionContext,
    ) -> Result<bool> {
        match &statement.condition {
            Some(condition) if !condition.is_null() => self
                .evaluate_statement_condition(condition, context)
                .map_err(|e| policy_evaluator::unreadable_condition(policy, statement, index, &e)),
            _ => Ok(true),
        }
    }

    /// Evaluate a statement's condition block
    fn evaluate_statement_condition(
        &self,
        condition_value: &Value,
        context: &ConditionContext,
    ) -> std::result::Result<bool, wami_condition::ConditionError> {
        // Parse the condition block from JSON
        let condition_block = parse_condition_block(condition_value)?;

        // Evaluate the condition block
        evaluate_condition_block(&condition_block, context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::memory::InMemoryWamiStore;
    use crate::wami::identity::role::builder::build_role;
    use crate::wami::identity::user::builder::build_user;
    use crate::wami::policies::policy::builder::build_policy;
    use wami_core::arn::{TenantPath, WamiArn};
    use wami_core::context::WamiContext;

    /// The key a test context names: its ARN's tenant and resource, as the
    /// test records are written under (test code: production never builds a
    /// key from an ARN, wami 005).
    fn keyed(arn: &wami_core::arn::WamiArn) -> wami_core::arn::ScopedName {
        wami_core::arn::ScopedName::new(arn.tenant_path.clone(), arn.resource.resource_id.clone())
    }

    /// The tenant every test here works in.
    fn tenant() -> wami_core::arn::TenantPath {
        wami_core::arn::TenantPath::single(12345678)
    }

    /// `name`'s key in that tenant.
    fn key(name: impl AsRef<str>) -> wami_core::arn::ScopedName {
        wami_core::arn::ScopedName::new(tenant(), name.as_ref())
    }

    fn setup_service() -> EvaluationService<InMemoryWamiStore> {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        EvaluationService::new(store, "123456789012".to_string())
    }

    fn test_context() -> WamiContext {
        let arn: WamiArn = "arn:wami:.*:12345678:wami:123456789012:user/test"
            .parse()
            .unwrap();
        WamiContext::builder()
            .instance_id("123456789012")
            .tenant_path(TenantPath::single(12345678))
            .caller_key(keyed(&arn))
            .caller_arn(arn)
            .is_root(false)
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn test_simulate_custom_policy_allow() {
        let service = setup_service();

        let policy_doc = r#"{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::mybucket/*"
                }
            ]
        }"#;

        let request = SimulateCustomPolicyRequest {
            policy_input_list: vec![policy_doc.to_string()],
            action_names: vec!["s3:GetObject".to_string()],
            resource_arns: Some(vec!["arn:aws:s3:::mybucket/file.txt".to_string()]),
            context_entries: None,
        };

        let response = service.simulate_custom_policy(request).await.unwrap();

        assert_eq!(response.evaluation_results.len(), 1);
        assert_eq!(response.evaluation_results[0].eval_decision, "allowed");
    }

    #[tokio::test]
    async fn test_simulate_custom_policy_deny() {
        let service = setup_service();

        let policy_doc = r#"{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "s3:DeleteObject",
                    "Resource": "*"
                }
            ]
        }"#;

        let request = SimulateCustomPolicyRequest {
            policy_input_list: vec![policy_doc.to_string()],
            action_names: vec!["s3:DeleteObject".to_string()],
            resource_arns: Some(vec!["arn:aws:s3:::mybucket/file.txt".to_string()]),
            context_entries: None,
        };

        let response = service.simulate_custom_policy(request).await.unwrap();

        assert_eq!(response.evaluation_results.len(), 1);
        assert_eq!(response.evaluation_results[0].eval_decision, "denied");
    }

    #[tokio::test]
    async fn test_simulate_custom_policy_implicit_deny() {
        let service = setup_service();

        let policy_doc = r#"{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::mybucket/*"
                }
            ]
        }"#;

        let request = SimulateCustomPolicyRequest {
            policy_input_list: vec![policy_doc.to_string()],
            action_names: vec!["s3:PutObject".to_string()],
            resource_arns: Some(vec!["arn:aws:s3:::mybucket/file.txt".to_string()]),
            context_entries: None,
        };

        let response = service.simulate_custom_policy(request).await.unwrap();

        assert_eq!(response.evaluation_results.len(), 1);
        assert_eq!(response.evaluation_results[0].eval_decision, "implicitDeny");
    }

    #[tokio::test]
    async fn test_simulate_custom_policy_wildcard() {
        let service = setup_service();

        let policy_doc = r#"{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "Resource": "*"
                }
            ]
        }"#;

        let request = SimulateCustomPolicyRequest {
            policy_input_list: vec![policy_doc.to_string()],
            action_names: vec!["s3:GetObject".to_string(), "s3:PutObject".to_string()],
            resource_arns: Some(vec!["arn:aws:s3:::anybucket/anyfile".to_string()]),
            context_entries: None,
        };

        let response = service.simulate_custom_policy(request).await.unwrap();

        assert_eq!(response.evaluation_results.len(), 2);
        assert!(response
            .evaluation_results
            .iter()
            .all(|r| r.eval_decision == "allowed"));
    }

    #[tokio::test]
    async fn test_simulate_principal_policy_user() {
        let service = setup_service();
        let context = test_context();

        // Create a user
        let mut user = build_user(&key("alice"), Some("/".to_string()), &context).unwrap();
        user.wami_arn = context.caller_arn().clone();

        service.store.write().await.create_user(user).await.unwrap();

        // Create a policy document for testing
        let policy_doc = r#"{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "ec2:DescribeInstances",
                    "Resource": "*"
                }
            ]
        }"#;

        // Note: Since User model doesn't have attached_policies yet,
        // we pass the policy via policy_input_list
        let request = SimulatePrincipalPolicyRequest {
            principal_type: crate::wami::policies::permissions_boundary::PrincipalType::User,
            principal: key("alice"),
            action_names: vec!["ec2:DescribeInstances".to_string()],
            resource_arns: None,
            policy_input_list: Some(vec![policy_doc.to_string()]),
            context_entries: None,
        };

        let response = service.simulate_principal_policy(request).await.unwrap();

        assert_eq!(response.evaluation_results.len(), 1);
        assert_eq!(response.evaluation_results[0].eval_decision, "allowed");
    }

    #[tokio::test]
    async fn test_simulate_principal_policy_role_with_boundary() {
        // Drives the `role` arms of both fetch_principal_policies and
        // fetch_permissions_boundary, and the boundary lookup that follows.
        let service = setup_service();
        let context = test_context();

        let boundary = build_policy(
            "Boundary".to_string(),
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:DescribeInstances","Resource":"*"}]}"#
                .to_string(),
            None,
            None,
            None,
            &tenant(),
            &context,
        )
        .unwrap();
        let boundary_arn = boundary.arn.clone();
        service
            .store
            .write()
            .await
            .create_policy(boundary)
            .await
            .unwrap();

        let mut role = build_role(
            &key("AppRole"),
            r#"{"Version":"2012-10-17","Statement":[]}"#.to_string(),
            Some("/".to_string()),
            None,
            None,
            &context,
        )
        .unwrap();
        role.permissions_boundary = Some(boundary_arn);
        service.store.write().await.create_role(role).await.unwrap();

        let identity = r#"{
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "ec2:DescribeInstances", "Resource": "*"},
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
            ]
        }"#;

        let response = service
            .simulate_principal_policy(SimulatePrincipalPolicyRequest {
                principal_type: crate::wami::policies::permissions_boundary::PrincipalType::Role,
                principal: key("AppRole"),
                action_names: vec![
                    "ec2:DescribeInstances".to_string(),
                    "s3:GetObject".to_string(),
                ],
                resource_arns: None,
                policy_input_list: Some(vec![identity.to_string()]),
                context_entries: None,
            })
            .await
            .unwrap();

        assert_eq!(response.evaluation_results.len(), 2);
        // Allowed by both the identity policy and the boundary.
        assert_eq!(response.evaluation_results[0].eval_decision, "allowed");
        // Allowed by the identity policy but outside the boundary.
        assert_ne!(response.evaluation_results[1].eval_decision, "allowed");
    }

    #[tokio::test]
    async fn test_simulate_principal_policy_unknown_role() {
        let service = setup_service();

        let result = service
            .simulate_principal_policy(SimulatePrincipalPolicyRequest {
                principal_type: crate::wami::policies::permissions_boundary::PrincipalType::Role,
                principal: key("Missing"),
                action_names: vec!["ec2:DescribeInstances".to_string()],
                resource_arns: None,
                policy_input_list: None,
                context_entries: None,
            })
            .await;

        assert!(matches!(result, Err(AmiError::ResourceNotFound { .. })));
    }

    #[tokio::test]
    async fn test_multiple_policies_deny_wins() {
        let service = setup_service();

        // Policy 1: Allows all S3 actions
        let policy1 = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*"
            }]
        }"#;

        // Policy 2: Denies DeleteObject
        let policy2 = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Deny",
                "Action": "s3:DeleteObject",
                "Resource": "*"
            }]
        }"#;

        let request = SimulateCustomPolicyRequest {
            policy_input_list: vec![policy1.to_string(), policy2.to_string()],
            action_names: vec!["s3:DeleteObject".to_string()],
            resource_arns: Some(vec!["arn:aws:s3:::bucket/key".to_string()]),
            context_entries: None,
        };

        let response = service.simulate_custom_policy(request).await.unwrap();
        assert_eq!(response.evaluation_results[0].eval_decision, "denied");
    }

    #[tokio::test]
    async fn test_multiple_statements_in_single_policy() {
        let service = setup_service();

        let policy = r#"{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::bucket1/*"
                },
                {
                    "Effect": "Allow",
                    "Action": "s3:PutObject",
                    "Resource": "arn:aws:s3:::bucket2/*"
                },
                {
                    "Effect": "Deny",
                    "Action": "s3:DeleteObject",
                    "Resource": "*"
                }
            ]
        }"#;

        let request = SimulateCustomPolicyRequest {
            policy_input_list: vec![policy.to_string()],
            action_names: vec![
                "s3:GetObject".to_string(),
                "s3:PutObject".to_string(),
                "s3:DeleteObject".to_string(),
            ],
            resource_arns: Some(vec![
                "arn:aws:s3:::bucket1/file".to_string(),
                "arn:aws:s3:::bucket2/file".to_string(),
                "arn:aws:s3:::bucket1/file".to_string(),
            ]),
            context_entries: None,
        };

        let response = service.simulate_custom_policy(request).await.unwrap();
        // 3 actions × 3 resources = 9 results
        assert_eq!(response.evaluation_results.len(), 9);
        // GetObject on bucket1/file - allowed
        assert_eq!(response.evaluation_results[0].eval_decision, "allowed");
        // GetObject on bucket2/file - implicitDeny (bucket2 doesn't match bucket1/*)
        assert_eq!(response.evaluation_results[1].eval_decision, "implicitDeny");
        // GetObject on bucket1/file (duplicate) - allowed
        assert_eq!(response.evaluation_results[2].eval_decision, "allowed");
        // PutObject on bucket1/file - implicitDeny (bucket1 doesn't match bucket2/*)
        assert_eq!(response.evaluation_results[3].eval_decision, "implicitDeny");
        // PutObject on bucket2/file - allowed
        assert_eq!(response.evaluation_results[4].eval_decision, "allowed");
        // PutObject on bucket1/file - implicitDeny
        assert_eq!(response.evaluation_results[5].eval_decision, "implicitDeny");
        // DeleteObject on bucket1/file - denied
        assert_eq!(response.evaluation_results[6].eval_decision, "denied");
        // DeleteObject on bucket2/file - denied
        assert_eq!(response.evaluation_results[7].eval_decision, "denied");
        // DeleteObject on bucket1/file (duplicate) - denied
        assert_eq!(response.evaluation_results[8].eval_decision, "denied");
    }

    #[tokio::test]
    async fn test_wildcard_prefix_matching() {
        let service = setup_service();

        let policy = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:Get*",
                "Resource": "arn:aws:s3:::bucket/*"
            }]
        }"#;

        let request = SimulateCustomPolicyRequest {
            policy_input_list: vec![policy.to_string()],
            action_names: vec![
                "s3:GetObject".to_string(),
                "s3:GetObjectVersion".to_string(),
                "s3:PutObject".to_string(),
            ],
            resource_arns: Some(vec!["arn:aws:s3:::bucket/file".to_string()]),
            context_entries: None,
        };

        let response = service.simulate_custom_policy(request).await.unwrap();
        assert_eq!(response.evaluation_results.len(), 3);
        assert_eq!(response.evaluation_results[0].eval_decision, "allowed");
        assert_eq!(response.evaluation_results[1].eval_decision, "allowed");
        assert_eq!(response.evaluation_results[2].eval_decision, "implicitDeny");
    }

    #[tokio::test]
    async fn test_multiple_actions_in_statement() {
        let service = setup_service();

        let policy = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                "Resource": "*"
            }]
        }"#;

        let request = SimulateCustomPolicyRequest {
            policy_input_list: vec![policy.to_string()],
            action_names: vec![
                "s3:GetObject".to_string(),
                "s3:PutObject".to_string(),
                "s3:ListBucket".to_string(),
                "s3:DeleteObject".to_string(),
            ],
            resource_arns: None,
            context_entries: None,
        };

        let response = service.simulate_custom_policy(request).await.unwrap();
        assert_eq!(response.evaluation_results.len(), 4);
        assert_eq!(response.evaluation_results[0].eval_decision, "allowed");
        assert_eq!(response.evaluation_results[1].eval_decision, "allowed");
        assert_eq!(response.evaluation_results[2].eval_decision, "allowed");
        assert_eq!(response.evaluation_results[3].eval_decision, "implicitDeny");
    }

    #[tokio::test]
    async fn test_multiple_resources_in_statement() {
        let service = setup_service();

        let policy = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": [
                    "arn:aws:s3:::bucket1/*",
                    "arn:aws:s3:::bucket2/*"
                ]
            }]
        }"#;

        let request = SimulateCustomPolicyRequest {
            policy_input_list: vec![policy.to_string()],
            action_names: vec!["s3:GetObject".to_string()],
            resource_arns: Some(vec![
                "arn:aws:s3:::bucket1/file".to_string(),
                "arn:aws:s3:::bucket2/file".to_string(),
                "arn:aws:s3:::bucket3/file".to_string(),
            ]),
            context_entries: None,
        };

        let response = service.simulate_custom_policy(request).await.unwrap();
        assert_eq!(response.evaluation_results.len(), 3);
        assert_eq!(response.evaluation_results[0].eval_decision, "allowed");
        assert_eq!(response.evaluation_results[1].eval_decision, "allowed");
        assert_eq!(response.evaluation_results[2].eval_decision, "implicitDeny");
    }

    #[tokio::test]
    async fn test_empty_policy_list() {
        let service = setup_service();

        let request = SimulateCustomPolicyRequest {
            policy_input_list: vec![],
            action_names: vec!["s3:GetObject".to_string()],
            resource_arns: None,
            context_entries: None,
        };

        let response = service.simulate_custom_policy(request).await.unwrap();
        assert_eq!(response.evaluation_results.len(), 1);
        assert_eq!(response.evaluation_results[0].eval_decision, "implicitDeny");
    }

    #[tokio::test]
    async fn test_invalid_json_policy() {
        let service = setup_service();

        let request = SimulateCustomPolicyRequest {
            policy_input_list: vec!["{ invalid json }".to_string()],
            action_names: vec!["s3:GetObject".to_string()],
            resource_arns: None,
            context_entries: None,
        };

        let result = service.simulate_custom_policy(request).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid policy document"));
    }

    #[tokio::test]
    async fn test_wildcard_resource_matching() {
        let service = setup_service();

        let policy = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "arn:aws:s3:::mybucket/*"
            }]
        }"#;

        let request = SimulateCustomPolicyRequest {
            policy_input_list: vec![policy.to_string()],
            action_names: vec!["s3:GetObject".to_string()],
            resource_arns: Some(vec![
                "arn:aws:s3:::mybucket/file".to_string(),
                "arn:aws:s3:::mybucket/subdir/file".to_string(),
                "arn:aws:s3:::otherbucket/file".to_string(),
            ]),
            context_entries: None,
        };

        let response = service.simulate_custom_policy(request).await.unwrap();
        assert_eq!(response.evaluation_results.len(), 3);
        assert_eq!(response.evaluation_results[0].eval_decision, "allowed");
        assert_eq!(response.evaluation_results[1].eval_decision, "allowed");
        assert_eq!(response.evaluation_results[2].eval_decision, "implicitDeny");
    }

    #[tokio::test]
    async fn test_exact_vs_wildcard_precedence() {
        let service = setup_service();

        // Policy with both exact and wildcard actions
        let policy = r#"{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "*"
                },
                {
                    "Effect": "Deny",
                    "Action": "s3:*",
                    "Resource": "arn:aws:s3:::restricted/*"
                }
            ]
        }"#;

        let request = SimulateCustomPolicyRequest {
            policy_input_list: vec![policy.to_string()],
            action_names: vec!["s3:GetObject".to_string()],
            resource_arns: Some(vec![
                "arn:aws:s3:::allowed/file".to_string(),
                "arn:aws:s3:::restricted/file".to_string(),
            ]),
            context_entries: None,
        };

        let response = service.simulate_custom_policy(request).await.unwrap();
        assert_eq!(response.evaluation_results.len(), 2);
        // Deny should win for restricted bucket
        assert_eq!(response.evaluation_results[0].eval_decision, "allowed");
        assert_eq!(response.evaluation_results[1].eval_decision, "denied");
    }

    #[tokio::test]
    async fn test_action_wildcard_edge_cases() {
        let service = setup_service();

        let policy = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:List*",
                "Resource": "*"
            }]
        }"#;

        let request = SimulateCustomPolicyRequest {
            policy_input_list: vec![policy.to_string()],
            action_names: vec![
                "s3:ListBucket".to_string(),
                "s3:ListBucketVersions".to_string(),
                "s3:ListMultipartUploads".to_string(),
                "s3:GetObject".to_string(), // Should not match
            ],
            resource_arns: None,
            context_entries: None,
        };

        let response = service.simulate_custom_policy(request).await.unwrap();
        assert_eq!(response.evaluation_results.len(), 4);
        assert_eq!(response.evaluation_results[0].eval_decision, "allowed");
        assert_eq!(response.evaluation_results[1].eval_decision, "allowed");
        assert_eq!(response.evaluation_results[2].eval_decision, "allowed");
        assert_eq!(response.evaluation_results[3].eval_decision, "implicitDeny");
    }

    #[tokio::test]
    async fn test_resource_wildcard_edge_cases() {
        let service = setup_service();

        let policy = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "arn:aws:s3:::bucket/prefix/*"
            }]
        }"#;

        let request = SimulateCustomPolicyRequest {
            policy_input_list: vec![policy.to_string()],
            action_names: vec!["s3:GetObject".to_string()],
            resource_arns: Some(vec![
                "arn:aws:s3:::bucket/prefix/file".to_string(),
                "arn:aws:s3:::bucket/prefix/subdir/file".to_string(),
                "arn:aws:s3:::bucket/prefix".to_string(), // Should not match (no trailing slash)
                "arn:aws:s3:::bucket/other/file".to_string(), // Should not match
            ]),
            context_entries: None,
        };

        let response = service.simulate_custom_policy(request).await.unwrap();
        assert_eq!(response.evaluation_results.len(), 4);
        assert_eq!(response.evaluation_results[0].eval_decision, "allowed");
        assert_eq!(response.evaluation_results[1].eval_decision, "allowed");
        assert_eq!(response.evaluation_results[2].eval_decision, "implicitDeny");
        assert_eq!(response.evaluation_results[3].eval_decision, "implicitDeny");
    }

    #[tokio::test]
    async fn test_multiple_policies_allow_combination() {
        let service = setup_service();

        // Policy 1: Allows GetObject on bucket1
        let policy1 = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::bucket1/*"
            }]
        }"#;

        // Policy 2: Allows PutObject on bucket2
        let policy2 = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:PutObject",
                "Resource": "arn:aws:s3:::bucket2/*"
            }]
        }"#;

        let request = SimulateCustomPolicyRequest {
            policy_input_list: vec![policy1.to_string(), policy2.to_string()],
            action_names: vec!["s3:GetObject".to_string(), "s3:PutObject".to_string()],
            resource_arns: Some(vec![
                "arn:aws:s3:::bucket1/file".to_string(),
                "arn:aws:s3:::bucket2/file".to_string(),
            ]),
            context_entries: None,
        };

        let response = service.simulate_custom_policy(request).await.unwrap();
        // 2 actions × 2 resources = 4 results
        assert_eq!(response.evaluation_results.len(), 4);
        // GetObject on bucket1/file - allowed
        assert_eq!(response.evaluation_results[0].eval_decision, "allowed");
        // GetObject on bucket2/file - implicitDeny (bucket2 doesn't match bucket1/*)
        assert_eq!(response.evaluation_results[1].eval_decision, "implicitDeny");
        // PutObject on bucket1/file - implicitDeny (bucket1 doesn't match bucket2/*)
        assert_eq!(response.evaluation_results[2].eval_decision, "implicitDeny");
        // PutObject on bucket2/file - allowed
        assert_eq!(response.evaluation_results[3].eval_decision, "allowed");
    }

    #[tokio::test]
    async fn test_empty_action_list() {
        let service = setup_service();

        let policy = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": [],
                "Resource": "*"
            }]
        }"#;

        let request = SimulateCustomPolicyRequest {
            policy_input_list: vec![policy.to_string()],
            action_names: vec!["s3:GetObject".to_string()],
            resource_arns: None,
            context_entries: None,
        };

        let response = service.simulate_custom_policy(request).await.unwrap();
        assert_eq!(response.evaluation_results[0].eval_decision, "implicitDeny");
    }

    #[tokio::test]
    async fn test_empty_resource_list() {
        let service = setup_service();

        let policy = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": []
            }]
        }"#;

        let request = SimulateCustomPolicyRequest {
            policy_input_list: vec![policy.to_string()],
            action_names: vec!["s3:GetObject".to_string()],
            resource_arns: None,
            context_entries: None,
        };

        let response = service.simulate_custom_policy(request).await.unwrap();
        assert_eq!(response.evaluation_results[0].eval_decision, "implicitDeny");
    }

    #[tokio::test]
    async fn test_deny_before_allow_in_same_policy() {
        let service = setup_service();

        // Deny statement comes first, but should still win
        let policy = r#"{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "s3:DeleteObject",
                    "Resource": "*"
                },
                {
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "Resource": "*"
                }
            ]
        }"#;

        let request = SimulateCustomPolicyRequest {
            policy_input_list: vec![policy.to_string()],
            action_names: vec!["s3:DeleteObject".to_string()],
            resource_arns: None,
            context_entries: None,
        };

        let response = service.simulate_custom_policy(request).await.unwrap();
        assert_eq!(response.evaluation_results[0].eval_decision, "denied");
    }

    #[tokio::test]
    async fn test_allow_before_deny_in_same_policy() {
        let service = setup_service();

        // Allow statement comes first, but Deny should still win
        let policy = r#"{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "Resource": "*"
                },
                {
                    "Effect": "Deny",
                    "Action": "s3:DeleteObject",
                    "Resource": "*"
                }
            ]
        }"#;

        let request = SimulateCustomPolicyRequest {
            policy_input_list: vec![policy.to_string()],
            action_names: vec!["s3:DeleteObject".to_string()],
            resource_arns: None,
            context_entries: None,
        };

        let response = service.simulate_custom_policy(request).await.unwrap();
        assert_eq!(response.evaluation_results[0].eval_decision, "denied");
    }

    #[tokio::test]
    async fn test_multiple_actions_and_resources_combination() {
        let service = setup_service();

        let policy = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": ["arn:aws:s3:::bucket1/*", "arn:aws:s3:::bucket2/*"]
            }]
        }"#;

        let request = SimulateCustomPolicyRequest {
            policy_input_list: vec![policy.to_string()],
            action_names: vec!["s3:GetObject".to_string(), "s3:PutObject".to_string()],
            resource_arns: Some(vec![
                "arn:aws:s3:::bucket1/file".to_string(),
                "arn:aws:s3:::bucket2/file".to_string(),
                "arn:aws:s3:::bucket3/file".to_string(),
            ]),
            context_entries: None,
        };

        let response = service.simulate_custom_policy(request).await.unwrap();
        assert_eq!(response.evaluation_results.len(), 6); // 2 actions × 3 resources
                                                          // All combinations with bucket1 and bucket2 should be allowed
                                                          // bucket3 should be denied
        assert_eq!(response.evaluation_results[0].eval_decision, "allowed"); // GetObject, bucket1
        assert_eq!(response.evaluation_results[1].eval_decision, "allowed"); // GetObject, bucket2
        assert_eq!(response.evaluation_results[2].eval_decision, "implicitDeny"); // GetObject, bucket3
        assert_eq!(response.evaluation_results[3].eval_decision, "allowed"); // PutObject, bucket1
        assert_eq!(response.evaluation_results[4].eval_decision, "allowed"); // PutObject, bucket2
        assert_eq!(response.evaluation_results[5].eval_decision, "implicitDeny");
        // PutObject, bucket3
    }

    #[tokio::test]
    async fn test_policy_with_condition_source_ip() {
        let service = setup_service();

        // Policy that allows S3 access only from specific IP
        let policy = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*",
                "Condition": {
                    "IpAddress": {
                        "aws:SourceIp": "203.0.113.0/24"
                    }
                }
            }]
        }"#;

        // Test with matching IP
        let request = SimulateCustomPolicyRequest {
            policy_input_list: vec![policy.to_string()],
            action_names: vec!["s3:GetObject".to_string()],
            resource_arns: None,
            context_entries: Some(vec![ContextEntry {
                context_key_name: "aws:SourceIp".to_string(),
                context_key_values: vec!["203.0.113.42".to_string()],
                context_key_type: "String".to_string(),
            }]),
        };

        let response = service.simulate_custom_policy(request).await.unwrap();
        assert_eq!(response.evaluation_results[0].eval_decision, "allowed");

        // Test with non-matching IP
        let request = SimulateCustomPolicyRequest {
            policy_input_list: vec![policy.to_string()],
            action_names: vec!["s3:GetObject".to_string()],
            resource_arns: None,
            context_entries: Some(vec![ContextEntry {
                context_key_name: "aws:SourceIp".to_string(),
                context_key_values: vec!["198.51.100.42".to_string()],
                context_key_type: "String".to_string(),
            }]),
        };

        let response = service.simulate_custom_policy(request).await.unwrap();
        assert_eq!(response.evaluation_results[0].eval_decision, "implicitDeny");
    }

    #[tokio::test]
    async fn test_policy_with_condition_date() {
        let service = setup_service();

        // Policy that allows access only during business hours (9 AM - 5 PM UTC)
        let policy = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*",
                "Condition": {
                    "DateGreaterThan": {
                        "aws:CurrentTime": "2024-01-01T09:00:00Z"
                    },
                    "DateLessThan": {
                        "aws:CurrentTime": "2024-01-01T17:00:00Z"
                    }
                }
            }]
        }"#;

        // Test with time during business hours
        let request = SimulateCustomPolicyRequest {
            policy_input_list: vec![policy.to_string()],
            action_names: vec!["s3:GetObject".to_string()],
            resource_arns: None,
            context_entries: Some(vec![ContextEntry {
                context_key_name: "aws:CurrentTime".to_string(),
                context_key_values: vec!["2024-01-01T12:00:00Z".to_string()],
                context_key_type: "String".to_string(),
            }]),
        };

        let response = service.simulate_custom_policy(request).await.unwrap();
        assert_eq!(response.evaluation_results[0].eval_decision, "allowed");

        // Test with time outside business hours
        let request = SimulateCustomPolicyRequest {
            policy_input_list: vec![policy.to_string()],
            action_names: vec!["s3:GetObject".to_string()],
            resource_arns: None,
            context_entries: Some(vec![ContextEntry {
                context_key_name: "aws:CurrentTime".to_string(),
                context_key_values: vec!["2024-01-01T20:00:00Z".to_string()],
                context_key_type: "String".to_string(),
            }]),
        };

        let response = service.simulate_custom_policy(request).await.unwrap();
        assert_eq!(response.evaluation_results[0].eval_decision, "implicitDeny");
    }

    #[tokio::test]
    async fn test_policy_with_condition_deny() {
        let service = setup_service();

        // Policy that allows S3 access but denies from specific IP
        let policy = r#"{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "Resource": "*"
                },
                {
                    "Effect": "Deny",
                    "Action": "s3:*",
                    "Resource": "*",
                    "Condition": {
                        "IpAddress": {
                            "aws:SourceIp": "198.51.100.0/24"
                        }
                    }
                }
            ]
        }"#;

        // Test with blocked IP - deny should win
        let request = SimulateCustomPolicyRequest {
            policy_input_list: vec![policy.to_string()],
            action_names: vec!["s3:GetObject".to_string()],
            resource_arns: None,
            context_entries: Some(vec![ContextEntry {
                context_key_name: "aws:SourceIp".to_string(),
                context_key_values: vec!["198.51.100.42".to_string()],
                context_key_type: "String".to_string(),
            }]),
        };

        let response = service.simulate_custom_policy(request).await.unwrap();
        assert_eq!(response.evaluation_results[0].eval_decision, "denied");

        // Test with allowed IP
        let request = SimulateCustomPolicyRequest {
            policy_input_list: vec![policy.to_string()],
            action_names: vec!["s3:GetObject".to_string()],
            resource_arns: None,
            context_entries: Some(vec![ContextEntry {
                context_key_name: "aws:SourceIp".to_string(),
                context_key_values: vec!["203.0.113.42".to_string()],
                context_key_type: "String".to_string(),
            }]),
        };

        let response = service.simulate_custom_policy(request).await.unwrap();
        assert_eq!(response.evaluation_results[0].eval_decision, "allowed");
    }

    #[tokio::test]
    async fn test_build_condition_context_with_string_list() {
        let service = setup_service();
        let request = SimulateCustomPolicyRequest {
            policy_input_list: vec![r#"{
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "Resource": "*"
                }]
            }"#
            .to_string()],
            action_names: vec!["s3:GetObject".to_string()],
            resource_arns: None,
            context_entries: Some(vec![ContextEntry {
                context_key_name: "aws:TagKeys".to_string(),
                context_key_values: vec!["Env".to_string(), "Owner".to_string()],
                context_key_type: "StringList".to_string(),
            }]),
        };

        let response = service.simulate_custom_policy(request).await.unwrap();
        assert_eq!(response.evaluation_results[0].eval_decision, "allowed");
    }

    #[tokio::test]
    async fn test_build_condition_context_with_numeric() {
        let service = setup_service();
        let request = SimulateCustomPolicyRequest {
            policy_input_list: vec![r#"{
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "Resource": "*"
                }]
            }"#
            .to_string()],
            action_names: vec!["s3:GetObject".to_string()],
            resource_arns: None,
            context_entries: Some(vec![ContextEntry {
                context_key_name: "wami:RequestsPerMinute".to_string(),
                context_key_values: vec!["50".to_string()],
                context_key_type: "Numeric".to_string(),
            }]),
        };

        let response = service.simulate_custom_policy(request).await.unwrap();
        assert_eq!(response.evaluation_results[0].eval_decision, "allowed");
    }

    #[tokio::test]
    async fn test_build_condition_context_with_boolean() {
        let service = setup_service();
        let request = SimulateCustomPolicyRequest {
            policy_input_list: vec![r#"{
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "Resource": "*"
                }]
            }"#
            .to_string()],
            action_names: vec!["s3:GetObject".to_string()],
            resource_arns: None,
            context_entries: Some(vec![ContextEntry {
                context_key_name: "wami:VpnDetected".to_string(),
                context_key_values: vec!["false".to_string()],
                context_key_type: "Boolean".to_string(),
            }]),
        };

        let response = service.simulate_custom_policy(request).await.unwrap();
        assert_eq!(response.evaluation_results[0].eval_decision, "allowed");
    }

    #[tokio::test]
    async fn test_build_condition_context_with_default_type() {
        let service = setup_service();
        let request = SimulateCustomPolicyRequest {
            policy_input_list: vec![r#"{
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "Resource": "*"
                }]
            }"#
            .to_string()],
            action_names: vec!["s3:GetObject".to_string()],
            resource_arns: None,
            context_entries: Some(vec![ContextEntry {
                context_key_name: "custom:Key".to_string(),
                context_key_values: vec!["value".to_string()],
                context_key_type: "Unknown".to_string(),
            }]),
        };

        let response = service.simulate_custom_policy(request).await.unwrap();
        assert_eq!(response.evaluation_results[0].eval_decision, "allowed");
    }

    #[tokio::test]
    async fn test_build_condition_context_with_principal_arn() {
        // Create a user first so the principal exists
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let mut user = build_user(&key("alice"), None, &test_context()).unwrap();
        user.wami_arn = test_context().caller_arn().clone();
        store.write().await.create_user(user).await.unwrap();

        let service = EvaluationService::new(store, "123456789012".to_string());
        let request = SimulatePrincipalPolicyRequest {
            principal_type: crate::wami::policies::permissions_boundary::PrincipalType::User,
            principal: key("alice"),
            policy_input_list: None,
            action_names: vec!["s3:GetObject".to_string()],
            resource_arns: None,
            context_entries: None,
        };

        let response = service.simulate_principal_policy(request).await.unwrap();
        // Should work even if principal ARN is provided
        assert!(!response.evaluation_results.is_empty());
    }

    // Note: extract_account_id_from_arn is private and tested indirectly
    // through build_condition_context when principal_arn is provided

    #[tokio::test]
    async fn test_condition_evaluation_error_handling() {
        let service = setup_service();

        // Policy with invalid condition JSON
        let policy = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "invalid:key": null
                    }
                }
            }]
        }"#;

        let request = SimulateCustomPolicyRequest {
            policy_input_list: vec![policy.to_string()],
            action_names: vec!["s3:GetObject".to_string()],
            resource_arns: None,
            context_entries: None,
        };

        // A null is no value anybody wrote. It used to make the condition
        // false and the simulation answer "implicitDeny"; the authorizer
        // refuses such a document, so the simulation does too (wami 001).
        let err = service.simulate_custom_policy(request).await.unwrap_err();
        assert!(matches!(err, AmiError::UnreadablePolicy { .. }), "{err:?}");
        assert!(err.to_string().contains("policy_input_list[0]"), "{err}");
    }

    #[tokio::test]
    async fn test_condition_with_wami_keys() {
        let service = setup_service();

        // Policy using WAMI-specific keys
        let policy = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "wami:ClientType": "web"
                    },
                    "NumericLessThan": {
                        "wami:RequestsPerMinute": "100"
                    }
                }
            }]
        }"#;

        let request = SimulateCustomPolicyRequest {
            policy_input_list: vec![policy.to_string()],
            action_names: vec!["s3:GetObject".to_string()],
            resource_arns: None,
            context_entries: Some(vec![
                ContextEntry {
                    context_key_name: "wami:ClientType".to_string(),
                    context_key_values: vec!["web".to_string()],
                    context_key_type: "String".to_string(),
                },
                ContextEntry {
                    context_key_name: "wami:RequestsPerMinute".to_string(),
                    context_key_values: vec!["50".to_string()],
                    context_key_type: "Numeric".to_string(),
                },
            ]),
        };

        let response = service.simulate_custom_policy(request).await.unwrap();
        assert_eq!(response.evaluation_results[0].eval_decision, "allowed");
    }

    #[tokio::test]
    async fn test_condition_with_rate_limiting_keys() {
        let service = setup_service();

        // Policy using rate limiting keys
        let policy = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*",
                "Condition": {
                    "NumericLessThan": {
                        "wami:RequestsPerMinute": "60",
                        "wami:BurstCapacityUsed": "0.8"
                    },
                    "NumericGreaterThan": {
                        "wami:QuotaRemaining": "1000"
                    }
                }
            }]
        }"#;

        let request = SimulateCustomPolicyRequest {
            policy_input_list: vec![policy.to_string()],
            action_names: vec!["s3:GetObject".to_string()],
            resource_arns: None,
            context_entries: Some(vec![
                ContextEntry {
                    context_key_name: "wami:RequestsPerMinute".to_string(),
                    context_key_values: vec!["45".to_string()],
                    context_key_type: "Numeric".to_string(),
                },
                ContextEntry {
                    context_key_name: "wami:BurstCapacityUsed".to_string(),
                    context_key_values: vec!["0.5".to_string()],
                    context_key_type: "Numeric".to_string(),
                },
                ContextEntry {
                    context_key_name: "wami:QuotaRemaining".to_string(),
                    context_key_values: vec!["5000".to_string()],
                    context_key_type: "Numeric".to_string(),
                },
            ]),
        };

        let response = service.simulate_custom_policy(request).await.unwrap();
        assert_eq!(response.evaluation_results[0].eval_decision, "allowed");
    }

    // ─── wami 001: a simulation tells what the authorizer does ──────────

    fn allow_and_conditional_deny(cond: &str) -> String {
        format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":"*","Resource":"*"}},{{"Sid":"BlockAll","Effect":"Deny","Action":"*","Resource":"*","Condition":{cond}}}]}}"#
        )
    }

    fn custom(
        policy: String,
        context_entries: Option<Vec<ContextEntry>>,
    ) -> SimulateCustomPolicyRequest {
        SimulateCustomPolicyRequest {
            policy_input_list: vec![policy],
            action_names: vec!["s3:GetObject".to_string()],
            resource_arns: None,
            context_entries,
        }
    }

    #[tokio::test]
    async fn a_simulated_deny_with_an_unknown_operator_is_an_error_not_allowed() {
        // It used to answer "allowed": the Deny's condition read as false.
        let service = setup_service();
        let policy = allow_and_conditional_deny(r#"{"StringEqualz":{"aws:username":"alice"}}"#);
        let err = service
            .simulate_custom_policy(custom(policy, None))
            .await
            .expect_err("the authorizer refuses this document; the simulation must say so");
        let message = err.to_string();
        assert!(matches!(err, AmiError::UnreadablePolicy { .. }), "{err:?}");
        assert!(message.contains("BlockAll"), "{message}");
    }

    #[tokio::test]
    async fn a_simulated_context_value_the_condition_cannot_compare_is_an_error() {
        let service = setup_service();
        let policy = allow_and_conditional_deny(r#"{"StringEquals":{"wami:Team":"5"}}"#);
        let entries = vec![ContextEntry {
            context_key_name: "wami:Team".to_string(),
            context_key_values: vec!["5".to_string(), "6".to_string()],
            context_key_type: "StringList".to_string(),
        }];
        let err = service
            .simulate_custom_policy(custom(policy, Some(entries)))
            .await
            .expect_err("an evaluation error must not read as a verdict");
        let message = err.to_string();
        assert!(message.contains("BlockAll"), "{message}");
        assert!(message.contains("condition cannot be read"), "{message}");
    }

    #[tokio::test]
    async fn a_simulated_false_condition_still_lets_the_allow_through() {
        // The regression guard: a FALSE condition is NoMatch in both doors.
        let service = setup_service();
        let policy = allow_and_conditional_deny(r#"{"StringEquals":{"wami:Team":"core"}}"#);
        let entries = vec![ContextEntry {
            context_key_name: "wami:Team".to_string(),
            context_key_values: vec!["infra".to_string()],
            context_key_type: "String".to_string(),
        }];
        let response = service
            .simulate_custom_policy(custom(policy.clone(), Some(entries)))
            .await
            .unwrap();
        assert_eq!(response.evaluation_results[0].eval_decision, "allowed");
        // ... and a missing key is false too.
        let response = service
            .simulate_custom_policy(custom(policy, None))
            .await
            .unwrap();
        assert_eq!(response.evaluation_results[0].eval_decision, "allowed");
    }

    /// Alice in a store both services read, with `boundary` as her permissions
    /// boundary when given.
    async fn alice_for_both_doors(
        boundary: Option<&str>,
    ) -> (Arc<RwLock<InMemoryWamiStore>>, WamiContext) {
        let arn: WamiArn = "arn:wami:iam:12345678:wami:999:user/alice".parse().unwrap();
        let ctx = WamiContext::builder()
            .instance_id("999")
            .tenant_path(TenantPath::single(12345678))
            .caller_key(keyed(&arn))
            .caller_arn(arn)
            .is_root(false)
            .build()
            .unwrap();
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let mut user = build_user(&key("alice"), Some("/".to_string()), &ctx).unwrap();
        user.wami_arn = ctx.caller_arn().clone();
        if let Some(document) = boundary {
            let policy = build_policy(
                "Boundary".to_string(),
                document.to_string(),
                None,
                None,
                None,
                &tenant(),
                &ctx,
            )
            .unwrap();
            user.permissions_boundary = Some(policy.arn.clone());
            store.write().await.create_policy(policy).await.unwrap();
        }
        store.write().await.create_user(user).await.unwrap();
        (store, ctx)
    }

    /// The variant's name and whether the error names `sid` — what the two
    /// doors must agree on.
    fn shape(err: &AmiError, sid: &str) -> (&'static str, bool) {
        let kind = match err {
            AmiError::UnreadablePolicy { .. } => "UnreadablePolicy",
            AmiError::UnreadableCondition { .. } => "UnreadableCondition",
            _ => "other",
        };
        (kind, err.to_string().contains(sid))
    }

    #[tokio::test]
    async fn the_simulation_and_the_authorizer_agree_on_an_unreadable_condition() {
        use crate::service::auth::AuthorizationService;

        let resource = "arn:wami:iam:12345678:wami:999:user/bob";
        let identity = |cond: &str| {
            format!(
                r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":["iam:*"],"Resource":["*"]}},{{"Sid":"BlockAll","Effect":"Deny","Action":["iam:*"],"Resource":["*"],"Condition":{cond}}}]}}"#
            )
        };
        let fence = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:*"],"Resource":["*"]},{"Sid":"BlockAll","Effect":"Deny","Action":["iam:*"],"Resource":["*"],"Condition":{"StringEqualz":{"aws:username":"alice"}}}]}"#;
        let allow_all = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:*"],"Resource":["*"]}]}"#;

        // (identity document, boundary): each unreadable in its own way.
        let cases = [
            (
                identity(r#"{"StringEqualz":{"aws:username":"alice"}}"#),
                None,
            ),
            (
                identity(r#"{"IpAddress":{"aws:SourceIp":"not-an-ip"}}"#),
                None,
            ),
            (identity(r#"{"Bool":{"aws:SecureTransport":"yes"}}"#), None),
            // The principal's ARN compared as a number: refused at parse, keys
            // having declared types.
            (
                identity(r#"{"NumericLessThan":{"aws:PrincipalArn":"5"}}"#),
                None,
            ),
            (allow_all.to_string(), Some(fence)),
        ];
        for (document, boundary) in cases {
            let (store, ctx) = alice_for_both_doors(boundary).await;
            store
                .write()
                .await
                .put_user_policy(&key("alice"), "Doc", document.clone())
                .await
                .unwrap();

            let authorizer = AuthorizationService::new(store.clone())
                .authorize(&ctx, "iam:GetUser", &resource.parse().unwrap())
                .await;
            let simulation = EvaluationService::new(store, "999".to_string())
                .simulate_principal_policy(SimulatePrincipalPolicyRequest {
                    principal_type:
                        crate::wami::policies::permissions_boundary::PrincipalType::User,
                    principal: key("alice"),
                    action_names: vec!["iam:GetUser".to_string()],
                    resource_arns: Some(vec![resource.to_string()]),
                    policy_input_list: Some(vec![document.clone()]),
                    context_entries: None,
                })
                .await;

            let (Err(a), Err(s)) = (&authorizer, &simulation) else {
                panic!(
                    "both doors must refuse {document} (boundary {boundary:?}):\n authorizer {authorizer:?}\n simulation {simulation:?}"
                );
            };
            assert_eq!(shape(a, "BlockAll"), shape(s, "BlockAll"), "{a} / {s}");
            assert_ne!(shape(a, "BlockAll").0, "other", "{a}");
        }
    }

    // ─── wami 001, review round 1: read everything before deciding ──────

    const OFFICE: &str = r#"{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}"#;
    const TYPO: &str = r#"{"StringEqualz":{"aws:username":"alice"}}"#;

    fn stmt(sid: &str, effect: &str, condition: Option<&str>) -> String {
        let condition = condition.map_or(String::new(), |c| format!(r#","Condition":{c}"#));
        format!(
            r#"{{"Sid":"{sid}","Effect":"{effect}","Action":["iam:*"],"Resource":["*"]{condition}}}"#
        )
    }

    fn doc(statements: &[String]) -> String {
        format!(
            r#"{{"Version":"2012-10-17","Statement":[{}]}}"#,
            statements.join(",")
        )
    }

    /// The request comes from somewhere that is no address.
    fn from_nowhere() -> Vec<ContextEntry> {
        vec![ContextEntry {
            context_key_name: "aws:SourceIp".to_string(),
            context_key_values: vec!["not-an-ip".to_string()],
            context_key_type: "String".to_string(),
        }]
    }

    /// A custom key compared as one string...
    const ONE_TEAM: &str = r#"{"StringEquals":{"wami:Team":"core"}}"#;

    /// ... while the request holds a list for it: the comparison cannot be
    /// made, at evaluation (custom keys are strings, so parse cannot know).
    fn two_teams() -> Vec<ContextEntry> {
        vec![ContextEntry {
            context_key_name: "wami:Team".to_string(),
            context_key_values: vec!["core".to_string(), "infra".to_string()],
            context_key_type: "StringList".to_string(),
        }]
    }

    fn principal(
        documents: Vec<String>,
        context_entries: Option<Vec<ContextEntry>>,
    ) -> SimulatePrincipalPolicyRequest {
        SimulatePrincipalPolicyRequest {
            principal_type: crate::wami::policies::permissions_boundary::PrincipalType::User,
            principal: key("alice"),
            action_names: vec!["iam:GetUser".to_string()],
            resource_arns: Some(vec!["arn:wami:iam:12345678:wami:999:user/bob".to_string()]),
            policy_input_list: Some(documents),
            context_entries,
        }
    }

    #[tokio::test]
    async fn a_simulated_deny_does_not_hide_a_broken_document_after_it() {
        // It answered "denied" at the first Deny; the authorizer reads every
        // document and refuses. The simulation tells what the authorizer does.
        let (store, _) = alice_for_both_doors(None).await;
        let documents = vec![
            doc(&[stmt("DenyAll", "Deny", None)]),
            doc(&[stmt("Teams", "Deny", Some(ONE_TEAM))]),
        ];
        let err = EvaluationService::new(store, "999".to_string())
            .simulate_principal_policy(principal(documents, Some(two_teams())))
            .await
            .expect_err("a Deny earlier must not hide a document that cannot be read");
        assert!(
            matches!(err, AmiError::UnreadableCondition { .. }),
            "{err:?}"
        );
        assert!(err.to_string().contains("Teams"), "{err}");
    }

    #[tokio::test]
    async fn a_simulated_boundary_is_read_whatever_the_identity_verdict() {
        // A boundary whose condition cannot be compared: the authorizer reads
        // it before deciding, so the simulation must too.
        let boundary = doc(&[stmt("Teams", "Allow", Some(ONE_TEAM))]);
        let (store, _) = alice_for_both_doors(Some(&boundary)).await;
        let documents = vec![doc(&[stmt("AllowAll", "Allow", None)])];
        let err = EvaluationService::new(store, "999".to_string())
            .simulate_principal_policy(principal(documents, Some(two_teams())))
            .await
            .expect_err("a boundary that cannot be compared must not read as allowing");
        assert!(
            matches!(err, AmiError::UnreadableCondition { .. }),
            "{err:?}"
        );
        assert!(err.to_string().contains("permissions boundary"), "{err}");
    }

    #[tokio::test]
    async fn every_unreadable_simulated_document_is_named() {
        let service = setup_service();
        let broken = doc(&[stmt("Broken", "Deny", Some(TYPO))]);
        let request = SimulateCustomPolicyRequest {
            policy_input_list: vec![broken.clone(), broken],
            action_names: vec!["iam:GetUser".to_string()],
            resource_arns: None,
            context_entries: None,
        };
        let err = service.simulate_custom_policy(request).await.unwrap_err();
        let message = err.to_string();
        let first = message.find("policy_input_list[0]");
        let second = message.find("policy_input_list[1]");
        assert!(
            first.is_some() && second.is_some() && first < second,
            "{message}"
        );
    }

    #[tokio::test]
    async fn a_simulated_misspelt_effect_is_an_error() {
        let service = setup_service();
        let request = SimulateCustomPolicyRequest {
            policy_input_list: vec![
                doc(&[stmt("AllowAll", "Allow", None)]),
                doc(&[stmt("NoReads", "Dney", None)]),
            ],
            action_names: vec!["iam:GetUser".to_string()],
            resource_arns: None,
            context_entries: None,
        };
        let err = service.simulate_custom_policy(request).await.unwrap_err();
        assert!(matches!(err, AmiError::UnreadablePolicy { .. }), "{err:?}");
        assert!(err.to_string().contains("NoReads"), "{err}");
    }

    #[tokio::test]
    async fn a_simulated_broken_deny_on_another_action_is_refused_by_the_parse_net() {
        let service = setup_service();
        let broken = format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Sid":"Elsewhere","Effect":"Deny","Action":["s3:*"],"Resource":["*"],"Condition":{TYPO}}}]}}"#
        );
        let request = SimulateCustomPolicyRequest {
            policy_input_list: vec![doc(&[stmt("AllowAll", "Allow", None)]), broken],
            action_names: vec!["iam:GetUser".to_string()],
            resource_arns: None,
            context_entries: None,
        };
        let err = service.simulate_custom_policy(request).await.unwrap_err();
        assert!(matches!(err, AmiError::UnreadablePolicy { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn the_two_doors_agree_when_several_statements_take_part() {
        use crate::service::auth::AuthorizationService;

        let resource = "arn:wami:iam:12345678:wami:999:user/bob";
        let deny_all = doc(&[stmt("DenyAll", "Deny", None)]);
        let allow_all = doc(&[stmt("AllowAll", "Allow", None)]);
        // (identity documents, boundary, the Sid the error must name)
        let cases: Vec<(Vec<String>, Option<String>, &str)> = vec![
            // A Deny, then a document whose Deny cannot be compared.
            (
                vec![
                    deny_all.clone(),
                    doc(&[stmt("Office", "Deny", Some(OFFICE))]),
                ],
                None,
                "Office",
            ),
            // One document: a Deny that holds, an Allow that cannot be compared.
            (
                vec![doc(&[
                    stmt("DenyAll", "Deny", None),
                    stmt("Office", "Allow", Some(OFFICE)),
                ])],
                None,
                "Office",
            ),
            // A boundary that cannot be compared, under an identity Allow.
            (
                vec![allow_all.clone()],
                Some(doc(&[stmt("Office", "Allow", Some(OFFICE))])),
                "Office",
            ),
            // A boundary that cannot be read, under an identity Deny.
            (
                vec![deny_all.clone()],
                Some(doc(&[stmt("Fence", "Deny", Some(TYPO))])),
                "Fence",
            ),
        ];
        for (documents, boundary, sid) in cases {
            let (store, _) = alice_for_both_doors(boundary.as_deref()).await;
            for (i, document) in documents.iter().enumerate() {
                store
                    .write()
                    .await
                    .put_user_policy(&key("alice"), &format!("Doc{i}"), document.clone())
                    .await
                    .unwrap();
            }
            let arn: WamiArn = "arn:wami:iam:12345678:wami:999:user/alice".parse().unwrap();
            let ctx = WamiContext::builder()
                .instance_id("999")
                .tenant_path(TenantPath::single(12345678))
                .caller_key(keyed(&arn))
                .caller_arn(arn)
                .is_root(false)
                .source_ip("not-an-ip")
                .build()
                .unwrap();
            let authorizer = AuthorizationService::new(store.clone())
                .authorize(&ctx, "iam:GetUser", &resource.parse().unwrap())
                .await;
            let simulation = EvaluationService::new(store.clone(), "999".to_string())
                .simulate_principal_policy(principal(documents.clone(), Some(from_nowhere())))
                .await;
            let (Err(a), Err(s)) = (&authorizer, &simulation) else {
                panic!(
                    "both doors must refuse {documents:?} (boundary {boundary:?}):\n authorizer {authorizer:?}\n simulation {simulation:?}"
                );
            };
            let request_side = documents
                .iter()
                .chain(boundary.iter())
                .any(|d| d.contains("aws:SourceIp"));
            if !request_side {
                assert_eq!(shape(a, sid), shape(s, sid), "{a} / {s}");
                assert_ne!(shape(a, sid).0, "other", "{a}");
                continue;
            }
            // The request's address is no address. The authorizer meets it at
            // evaluation; the simulation, handed the address as an entry,
            // refuses the entry before evaluating anything. Both refuse,
            // neither allows — each with its own error.
            assert_eq!(shape(a, sid), ("UnreadableCondition", true), "{a}");
            assert!(
                matches!(s, AmiError::InvalidParameter { message } if message.contains("aws:SourceIp")),
                "{s:?}"
            );

            // The inverse guard: from an address the conditions can read, both
            // doors answer, and alike — so a door that stopped refusing fails
            // the half above, and one that stopped deciding fails this one.
            let ctx = WamiContext::builder()
                .instance_id("999")
                .tenant_path(TenantPath::single(12345678))
                .caller_key(key("alice"))
                .caller_arn("arn:wami:iam:12345678:wami:999:user/alice".parse().unwrap())
                .is_root(false)
                .source_ip("10.1.2.3")
                .build()
                .unwrap();
            let office = vec![ContextEntry {
                context_key_name: "aws:SourceIp".to_string(),
                context_key_values: vec!["10.1.2.3".to_string()],
                context_key_type: "String".to_string(),
            }];
            let authorized = AuthorizationService::new(store.clone())
                .authorize(&ctx, "iam:GetUser", &resource.parse().unwrap())
                .await
                .unwrap()
                .is_allowed();
            let simulated = EvaluationService::new(store, "999".to_string())
                .simulate_principal_policy(principal(documents.clone(), Some(office)))
                .await
                .unwrap();
            assert_eq!(
                authorized,
                simulated.evaluation_results[0].eval_decision == "allowed",
                "{documents:?} (boundary {boundary:?}): {simulated:?}"
            );
        }
    }

    // ─── wami 001, review round 2: the simulation's context, typed ──────

    fn entry(key: &str, kind: &str, values: &[&str]) -> ContextEntry {
        ContextEntry {
            context_key_name: key.to_string(),
            context_key_values: values.iter().map(|v| v.to_string()).collect(),
            context_key_type: kind.to_string(),
        }
    }

    fn custom_with(
        policies: Vec<String>,
        entries: Vec<ContextEntry>,
    ) -> SimulateCustomPolicyRequest {
        SimulateCustomPolicyRequest {
            policy_input_list: policies,
            action_names: vec!["iam:GetUser".to_string()],
            resource_arns: None,
            context_entries: Some(entries),
        }
    }

    #[tokio::test]
    async fn a_simulated_entry_for_a_declared_key_is_read_as_that_key() {
        // aws:SecureTransport is a declared key: its entry used to be written
        // to the custom values, which a declared key is never read from — so
        // the Deny "over plain HTTP" read an absent key and the Allow won.
        let policy = doc(&[
            stmt("AllowAll", "Allow", None),
            stmt(
                "PlainHttp",
                "Deny",
                Some(r#"{"Bool":{"aws:SecureTransport":"false"}}"#),
            ),
        ]);
        let response = setup_service()
            .simulate_custom_policy(custom_with(
                vec![policy],
                vec![entry("aws:SecureTransport", "Boolean", &["false"])],
            ))
            .await
            .unwrap();
        assert_eq!(response.evaluation_results[0].eval_decision, "denied");
    }

    #[tokio::test]
    async fn a_simulated_entry_that_does_not_read_as_its_key_is_refused_naming_it() {
        // Each used to vanish: the key read as absent, a Deny on it as false.
        let allow_all = doc(&[stmt("AllowAll", "Allow", None)]);
        let cases = [
            entry("wami:SessionAge", "Numeric", &["high-s3cr3t"]),
            entry("aws:CurrentTime", "String", &["yesterday-s3cr3t"]),
            entry("aws:MultiFactorAuthPresent", "Boolean", &["yes-s3cr3t"]),
            entry("aws:SourceIp", "String", &["nowhere-s3cr3t"]),
            entry("wami:RequestsPerMinute", "Numeric", &["-3s3cr3t"]),
        ];
        for bad in cases {
            let key = bad.context_key_name.clone();
            let err = setup_service()
                .simulate_custom_policy(custom_with(vec![allow_all.clone()], vec![bad]))
                .await
                .expect_err("an entry that cannot be read as its key must not vanish");
            let AmiError::InvalidParameter { message } = &err else {
                panic!("{key}: expected InvalidParameter, got {err:?}");
            };
            assert!(message.contains(&key), "{key}: {message}");
            assert!(!message.contains("s3cr3t"), "{key}: {message}");
        }
    }

    #[tokio::test]
    async fn a_simulated_custom_key_stays_a_string() {
        // A key nobody declared is compared as a string, whatever type the
        // entry claims: a "Numeric" entry used to become a number, which no
        // operator a custom key accepts can compare.
        let policy = doc(&[
            stmt("AllowAll", "Allow", None),
            stmt(
                "Five",
                "Deny",
                Some(r#"{"StringEquals":{"wami:Team":"5"}}"#),
            ),
        ]);
        let response = setup_service()
            .simulate_custom_policy(custom_with(
                vec![policy],
                vec![entry("wami:Team", "Numeric", &["5"])],
            ))
            .await
            .unwrap();
        assert_eq!(response.evaluation_results[0].eval_decision, "denied");
    }

    #[tokio::test]
    async fn a_simulated_document_that_is_no_policy_is_refused_without_quoting_it() {
        let request = SimulateCustomPolicyRequest {
            policy_input_list: vec![r#"{"Version":"x","Statement":"s3cr3t-statement"}"#.to_string()],
            action_names: vec!["iam:GetUser".to_string()],
            resource_arns: None,
            context_entries: None,
        };
        let err = setup_service()
            .simulate_custom_policy(request)
            .await
            .unwrap_err();
        let message = err.to_string();
        assert!(!message.contains("s3cr3t"), "{message}");
        assert!(message.contains("line 1 column"), "{message}");
    }
}
