//! Policy Evaluation Service
//!
//! Orchestrates policy simulation and evaluation operations.

use crate::provider::{AwsProvider, CloudProvider};
use crate::store::traits::{PolicyStore, RoleStore, UserStore};
use crate::wami::policies::evaluation::{
    ContextEntry, EvaluationResult, SimulateCustomPolicyRequest, SimulatePolicyResponse,
    SimulatePrincipalPolicyRequest, StatementMatch,
};
use serde_json::Value;
use std::sync::{Arc, RwLock};
use wami_condition::evaluator::parse_condition_block;
use wami_condition::{evaluate_condition_block, ConditionContext, ConditionValue};
use wami_core::error::{AmiError, Result};
use wami_core::types::PolicyDocument;

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
    pub async fn simulate_custom_policy(
        &self,
        request: SimulateCustomPolicyRequest,
    ) -> Result<SimulatePolicyResponse> {
        // Parse policy documents
        let policies: Result<Vec<PolicyDocument>> = request
            .policy_input_list
            .iter()
            .map(|policy_str| {
                serde_json::from_str(policy_str).map_err(|e| AmiError::InvalidParameter {
                    message: format!("Invalid policy document: {}", e),
                })
            })
            .collect();

        let policies = policies?;

        // Default resource if not provided
        let resources = request
            .resource_arns
            .unwrap_or_else(|| vec!["*".to_string()]);

        // Build condition context from request context entries
        let condition_context = self.build_condition_context(
            request.context_entries.as_deref(),
            None, // principal_arn not available in custom policy simulation
            None, // resource_arn will be set per evaluation
        );

        // Evaluate each action against each resource
        let mut results = Vec::new();

        for action in &request.action_names {
            for resource in &resources {
                // Update context with current resource
                let mut context = condition_context.clone();
                context.resource_arn = Some(resource.clone());

                let decision = self.evaluate_action(&policies, action, resource, &context);
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
    pub async fn simulate_principal_policy(
        &self,
        request: SimulatePrincipalPolicyRequest,
    ) -> Result<SimulatePolicyResponse> {
        // Parse principal ARN to determine type
        let (principal_type, principal_name) =
            self.parse_principal_arn(&request.policy_source_arn)?;

        // Fetch principal's policies from store
        let mut policies = self
            .fetch_principal_policies(&principal_type, &principal_name)
            .await?;

        // Fetch permissions boundary if present
        let boundary = self
            .fetch_permissions_boundary(&principal_type, &principal_name)
            .await?;

        // Add additional policy documents from request if provided
        if let Some(extra_policies) = request.policy_input_list {
            for policy_str in extra_policies {
                let policy: PolicyDocument =
                    serde_json::from_str(&policy_str).map_err(|e| AmiError::InvalidParameter {
                        message: format!("Invalid policy document: {}", e),
                    })?;
                policies.push(policy);
            }
        }

        // Default resource if not provided
        let resources = request
            .resource_arns
            .unwrap_or_else(|| vec!["*".to_string()]);

        // Build condition context from request context entries and principal ARN
        let condition_context = self.build_condition_context(
            request.context_entries.as_deref(),
            Some(&request.policy_source_arn),
            None, // resource_arn will be set per evaluation
        );

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
                    boundary.as_ref(),
                    &context,
                );
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

    /// Parse principal ARN to extract type and name
    fn parse_principal_arn(&self, arn: &str) -> Result<(String, String)> {
        // Expected formats:
        // arn:aws:iam::123456789012:user/alice
        // arn:aws:iam::123456789012:user/path/to/alice
        // arn:aws:iam::123456789012:role/MyRole
        // arn:aws:iam::123456789012:role/path/MyRole

        let parts: Vec<&str> = arn.split(':').collect();
        if parts.len() < 6 {
            return Err(AmiError::InvalidParameter {
                message: format!("Invalid principal ARN: {}", arn),
            });
        }

        let resource_part = parts[5]; // "user/alice" or "user/path/alice"
        let resource_parts: Vec<&str> = resource_part.split('/').collect();

        if resource_parts.len() < 2 {
            return Err(AmiError::InvalidParameter {
                message: format!("Invalid principal ARN format: {}", arn),
            });
        }

        let principal_type = resource_parts[0].to_string();
        // The principal name is always the last part (after the type and any path components)
        let principal_name = resource_parts[resource_parts.len() - 1].to_string();

        Ok((principal_type, principal_name))
    }

    /// Fetch policies for a user or role
    async fn fetch_principal_policies(
        &self,
        principal_type: &str,
        principal_name: &str,
    ) -> Result<Vec<PolicyDocument>> {
        let policies = Vec::new();

        match principal_type {
            "user" => {
                // Verify user exists
                let _user = self
                    .store
                    .read()
                    .unwrap()
                    .get_user(principal_name)
                    .await?
                    .ok_or_else(|| AmiError::ResourceNotFound {
                        resource: format!("User: {}", principal_name),
                    })?;

                // TODO: Policy attachments are not yet implemented in the User model
                // In a full implementation, we would:
                // 1. Query a policy_attachments table/map
                // 2. Fetch all attached policies
                // 3. Include inline policies if any
                // For now, return empty list (will use policy_input_list from request instead)
            }
            "role" => {
                // Verify role exists
                let _role = self
                    .store
                    .read()
                    .unwrap()
                    .get_role(principal_name)
                    .await?
                    .ok_or_else(|| AmiError::ResourceNotFound {
                        resource: format!("Role: {}", principal_name),
                    })?;

                // TODO: Same as user - policy attachments need separate tracking
            }
            _ => {
                return Err(AmiError::InvalidParameter {
                    message: format!("Unsupported principal type: {}", principal_type),
                })
            }
        }

        Ok(policies)
    }

    /// Fetch permissions boundary for a user or role
    async fn fetch_permissions_boundary(
        &self,
        principal_type: &str,
        principal_name: &str,
    ) -> Result<Option<crate::wami::policies::Policy>> {
        let boundary_arn = match principal_type {
            "user" => {
                let user = self
                    .store
                    .read()
                    .unwrap()
                    .get_user(principal_name)
                    .await?
                    .ok_or_else(|| AmiError::ResourceNotFound {
                        resource: format!("User: {}", principal_name),
                    })?;
                user.permissions_boundary
            }
            "role" => {
                let role = self
                    .store
                    .read()
                    .unwrap()
                    .get_role(principal_name)
                    .await?
                    .ok_or_else(|| AmiError::ResourceNotFound {
                        resource: format!("Role: {}", principal_name),
                    })?;
                role.permissions_boundary
            }
            _ => {
                return Err(AmiError::InvalidParameter {
                    message: format!("Unsupported principal type: {}", principal_type),
                })
            }
        };

        // Fetch the boundary policy if it exists
        if let Some(arn) = boundary_arn {
            let policy = self.store.read().unwrap().get_policy(&arn).await?;
            Ok(policy)
        } else {
            Ok(None)
        }
    }

    /// Evaluate a single action/resource combination against policies
    fn evaluate_action(
        &self,
        policies: &[PolicyDocument],
        action: &str,
        resource: &str,
        context: &ConditionContext,
    ) -> String {
        let mut has_allow = false;
        let mut has_deny = false;

        for policy in policies {
            for statement in &policy.statement {
                let action_matches = statement
                    .action
                    .iter()
                    .any(|a| Self::matches_pattern(action, a));

                let resource_matches = statement
                    .resource
                    .iter()
                    .any(|r| Self::matches_pattern(resource, r));

                // Check if conditions pass (if present)
                let conditions_pass = if let Some(condition_value) = &statement.condition {
                    match self.evaluate_statement_condition(condition_value, context) {
                        Ok(true) => true,
                        Ok(false) => false,
                        Err(_) => false, // If condition evaluation fails, treat as non-match
                    }
                } else {
                    true // No conditions = always pass
                };

                if action_matches && resource_matches && conditions_pass {
                    if statement.effect == "Deny" {
                        has_deny = true;
                    } else if statement.effect == "Allow" {
                        has_allow = true;
                    }
                }
            }
        }

        // Explicit deny always wins
        if has_deny {
            "denied".to_string()
        } else if has_allow {
            "allowed".to_string()
        } else {
            "implicitDeny".to_string()
        }
    }

    /// Evaluate action with permissions boundary
    ///
    /// The effective permissions are the intersection of:
    /// 1. Identity-based policies (must allow)
    /// 2. Permissions boundary (must allow)
    ///
    /// If either denies, the final result is deny.
    fn evaluate_action_with_boundary(
        &self,
        policies: &[PolicyDocument],
        action: &str,
        resource: &str,
        boundary: Option<&crate::wami::policies::Policy>,
        context: &ConditionContext,
    ) -> String {
        // Step 1: Check explicit deny in identity policies
        for policy in policies {
            for statement in &policy.statement {
                let action_matches = statement
                    .action
                    .iter()
                    .any(|a| Self::matches_pattern(action, a));

                let resource_matches = statement
                    .resource
                    .iter()
                    .any(|r| Self::matches_pattern(resource, r));

                // Check conditions
                let conditions_pass = if let Some(condition_value) = &statement.condition {
                    match self.evaluate_statement_condition(condition_value, context) {
                        Ok(true) => true,
                        Ok(false) => false,
                        Err(_) => false,
                    }
                } else {
                    true
                };

                if action_matches
                    && resource_matches
                    && conditions_pass
                    && statement.effect == "Deny"
                {
                    return "denied".to_string();
                }
            }
        }

        // Step 2: Check if identity policies allow
        let identity_allows = policies.iter().any(|policy| {
            policy.statement.iter().any(|statement| {
                let action_matches = statement
                    .action
                    .iter()
                    .any(|a| Self::matches_pattern(action, a));
                let resource_matches = statement
                    .resource
                    .iter()
                    .any(|r| Self::matches_pattern(resource, r));

                // Check conditions
                let conditions_pass = if let Some(condition_value) = &statement.condition {
                    match self.evaluate_statement_condition(condition_value, context) {
                        Ok(true) => true,
                        Ok(false) => false,
                        Err(_) => false,
                    }
                } else {
                    true
                };

                action_matches && resource_matches && conditions_pass && statement.effect == "Allow"
            })
        });

        if !identity_allows {
            return "implicitDeny".to_string();
        }

        // Step 3: Check permissions boundary (if present)
        // Note: Boundary evaluation doesn't currently support conditions, but we should
        // check if the boundary policy document has conditions and evaluate them
        if let Some(boundary_policy) = boundary {
            match crate::wami::policies::permissions_boundary::operations::is_allowed_by_boundary(
                action,
                resource,
                boundary_policy,
            ) {
                Ok(allowed) => {
                    if !allowed {
                        return "denied".to_string(); // Boundary restricts the action
                    }
                }
                Err(_) => {
                    // If boundary evaluation fails, deny for safety
                    return "denied".to_string();
                }
            }
        }

        // Both identity policies and boundary allow
        "allowed".to_string()
    }

    /// Find all statements that match the action/resource
    fn find_matching_statements(
        &self,
        policies: &[PolicyDocument],
        action: &str,
        resource: &str,
    ) -> Vec<StatementMatch> {
        let mut matches = Vec::new();

        for policy in policies {
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
    fn build_condition_context(
        &self,
        context_entries: Option<&[ContextEntry]>,
        principal_arn: Option<&str>,
        resource_arn: Option<&str>,
    ) -> ConditionContext {
        let mut builder = ConditionContext::builder().current_time(chrono::Utc::now());

        if let Some(arn) = resource_arn {
            builder = builder.resource_arn(arn);
        }

        // Set principal ARN if provided
        if let Some(arn) = principal_arn {
            builder = builder.principal_arn(arn);
            // Extract account ID from ARN if possible
            if let Some(account_id) = self.extract_account_id_from_arn(arn) {
                builder = builder.principal_account(account_id);
            }
        }

        // Process context entries from request
        if let Some(entries) = context_entries {
            for entry in entries {
                let key = &entry.context_key_name;
                let values = &entry.context_key_values;

                // Convert context entry to condition context based on key type
                match entry.context_key_type.as_str() {
                    "String" | "StringList" => {
                        if let Some(first_value) = values.first() {
                            let condition_value = if values.len() == 1 {
                                ConditionValue::String(first_value.clone())
                            } else {
                                ConditionValue::Array(values.clone())
                            };
                            builder = builder.custom_value(key.clone(), condition_value);
                        }
                    }
                    "Numeric" => {
                        if let Some(first_value) = values.first() {
                            if let Ok(num) = first_value.parse::<f64>() {
                                builder =
                                    builder.custom_value(key.clone(), ConditionValue::Number(num));
                            }
                        }
                    }
                    "Boolean" => {
                        if let Some(first_value) = values.first() {
                            if let Ok(b) = first_value.parse::<bool>() {
                                builder =
                                    builder.custom_value(key.clone(), ConditionValue::Boolean(b));
                            }
                        }
                    }
                    _ => {
                        // Default to string
                        if let Some(first_value) = values.first() {
                            builder = builder.custom_value(
                                key.clone(),
                                ConditionValue::String(first_value.clone()),
                            );
                        }
                    }
                }

                // Map common AWS context keys to ConditionContext fields
                match key.as_str() {
                    "aws:SourceIp" => {
                        if let Some(ip) = values.first() {
                            builder = builder.source_ip(ip.clone());
                        }
                    }
                    "aws:CurrentTime" => {
                        if let Some(time_str) = values.first() {
                            if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(time_str) {
                                builder = builder.current_time(dt.with_timezone(&chrono::Utc));
                            }
                        }
                    }
                    "aws:RequestedRegion" => {
                        if let Some(region) = values.first() {
                            builder = builder.requested_region(region.clone());
                        }
                    }
                    "aws:MultiFactorAuthPresent" => {
                        if let Some(val) = values.first() {
                            if let Ok(b) = val.parse::<bool>() {
                                builder = builder.mfa_present(b);
                            }
                        }
                    }
                    // Map WAMI-specific keys to their fields
                    "wami:ClientType" => {
                        if let Some(val) = values.first() {
                            builder = builder.client_type(val.clone());
                        }
                    }
                    "wami:RequestsPerMinute" => {
                        if let Some(val) = values.first() {
                            if let Ok(num) = val.parse::<u64>() {
                                builder = builder.requests_per_minute(num);
                            }
                        }
                    }
                    "wami:BurstCapacityUsed" => {
                        if let Some(val) = values.first() {
                            if let Ok(num) = val.parse::<f64>() {
                                builder = builder.burst_capacity_used(num);
                            }
                        }
                    }
                    "wami:QuotaRemaining" => {
                        if let Some(val) = values.first() {
                            if let Ok(num) = val.parse::<u64>() {
                                builder = builder.quota_remaining(num);
                            }
                        }
                    }
                    _ => {
                        // Already handled in custom_values above
                    }
                }
            }
        }

        builder.build()
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
    use crate::wami::identity::user::builder::build_user;
    use wami_core::arn::{TenantPath, WamiArn};
    use wami_core::context::WamiContext;

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
        let user = build_user("alice".to_string(), Some("/".to_string()), &context).unwrap();

        service
            .store
            .write()
            .unwrap()
            .create_user(user)
            .await
            .unwrap();

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
            policy_source_arn: "arn:aws:iam::123456789012:user/alice".to_string(),
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
    async fn test_parse_principal_arn_user() {
        let service = setup_service();

        let (principal_type, principal_name) = service
            .parse_principal_arn("arn:aws:iam::123456789012:user/alice")
            .unwrap();

        assert_eq!(principal_type, "user");
        assert_eq!(principal_name, "alice");
    }

    #[tokio::test]
    async fn test_parse_principal_arn_role() {
        let service = setup_service();

        let (principal_type, principal_name) = service
            .parse_principal_arn("arn:aws:iam::123456789012:role/MyRole")
            .unwrap();

        assert_eq!(principal_type, "role");
        assert_eq!(principal_name, "MyRole");
    }

    #[tokio::test]
    async fn test_parse_principal_arn_with_path() {
        let service = setup_service();

        let (principal_type, principal_name) = service
            .parse_principal_arn("arn:aws:iam::123456789012:user/department/team/alice")
            .unwrap();

        assert_eq!(principal_type, "user");
        // Principal name is just the name, not the path
        // Path is /department/team/ and name is alice
        assert_eq!(principal_name, "alice");
    }

    // ========== Complex Policy Evaluation Tests ==========

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
        let user = build_user("alice".to_string(), None, &test_context()).unwrap();
        store.write().unwrap().create_user(user).await.unwrap();

        let service = EvaluationService::new(store, "123456789012".to_string());
        let request = SimulatePrincipalPolicyRequest {
            policy_source_arn: "arn:aws:iam::123456789012:user/alice".to_string(),
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

        let response = service.simulate_custom_policy(request).await.unwrap();
        // Condition evaluation error should result in implicitDeny
        assert_eq!(response.evaluation_results[0].eval_decision, "implicitDeny");
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
}
