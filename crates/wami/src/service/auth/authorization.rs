//! Authorization Service - Permission checking and policy evaluation
//!
//! This service handles authorization checks:
//! 1. Root users bypass all checks (full access)
//! 2. Regular users are subject to policy evaluation
//! 3. Policies are evaluated from user, groups, and roles
//! 4. Deny overrides Allow
//!
//! # Example
//!
//! ```rust,no_run
//! use wami::{AuthorizationService, WamiContext, store::memory::InMemoryWamiStore, WamiArn};
//! use std::sync::Arc;
//! use tokio::sync::RwLock;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
//!     let authz_service = AuthorizationService::new(store);
//!
//!     // Assume we have an authenticated context
//!     let context = todo!("Get from authentication");
//!     let resource_arn: WamiArn = "arn:wami:iam:12345678:wami:999:user/alice".parse()?;
//!
//!     // Check if user can perform action
//!     let allowed = authz_service
//!         .authorize(&context, "iam:GetUser", &resource_arn)
//!         .await?;
//!
//!     if allowed {
//!         println!("Access granted");
//!     } else {
//!         println!("Access denied");
//!     }
//!
//!     Ok(())
//! }
//! ```

use crate::service::auth::policy_evaluator::{self, PolicyEffect};
use crate::store::traits::{GroupStore, PolicyStore, RoleStore, UserStore};
use std::sync::Arc;
use tokio::sync::RwLock;
use wami_core::arn::WamiArn;
use wami_core::context::WamiContext;
use wami_core::error::{AmiError, Result};

/// Authorization Service
///
/// Handles permission checking based on IAM policies.
pub struct AuthorizationService<S>
where
    S: UserStore + GroupStore + RoleStore + PolicyStore + Send + Sync,
{
    store: Arc<RwLock<S>>,
}

impl<S> AuthorizationService<S>
where
    S: UserStore + GroupStore + RoleStore + PolicyStore + Send + Sync,
{
    /// Create a new authorization service
    pub fn new(store: Arc<RwLock<S>>) -> Self {
        Self { store }
    }

    /// Authorize an action on a resource
    ///
    /// This is the main authorization method. It checks if the caller
    /// (from the context) is allowed to perform the specified action
    /// on the target resource.
    ///
    /// # Arguments
    ///
    /// * `context` - The authenticated context (contains caller info)
    /// * `action` - The action to perform (e.g., "iam:GetUser")
    /// * `resource_arn` - The target resource ARN
    ///
    /// # Returns
    ///
    /// `true` if the action is allowed, `false` otherwise
    ///
    /// # Errors
    ///
    /// Returns an error if there's a problem accessing the store or
    /// evaluating policies.
    pub async fn authorize(
        &self,
        context: &WamiContext,
        action: &str,
        resource_arn: &WamiArn,
    ) -> Result<bool> {
        // Root users bypass all authorization checks
        if context.is_root() {
            return Ok(true);
        }

        // Extract user name from caller ARN
        let user_name = self.extract_user_name_from_arn(context.caller_arn())?;

        // Evaluate policies for this user
        self.evaluate_user_policies(context, &user_name, action, resource_arn)
            .await
    }

    /// Check if access is denied (returns an error if not authorized)
    ///
    /// This is a convenience method that throws an `AccessDenied` error
    /// if the authorization check fails.
    pub async fn check_or_deny(
        &self,
        context: &WamiContext,
        action: &str,
        resource_arn: &WamiArn,
    ) -> Result<()> {
        let allowed = self.authorize(context, action, resource_arn).await?;

        if !allowed {
            return Err(AmiError::AccessDenied {
                message: format!(
                    "User {} is not authorized to perform {} on {}",
                    context.caller_arn(),
                    action,
                    resource_arn
                ),
            });
        }

        Ok(())
    }

    /// Evaluate all policies for a user
    ///
    /// This includes:
    /// - User's attached managed policies
    /// - User's inline policies
    /// - Policies from user's groups (attached + inline)
    /// - Policies from assumed role (if session has one)
    ///
    /// **Deny-overrides-allow**: an explicit Deny from ANY source wins over
    /// an Allow from any other source.
    async fn evaluate_user_policies(
        &self,
        context: &WamiContext,
        user_name: &str,
        action: &str,
        resource_arn: &WamiArn,
    ) -> Result<bool> {
        let store = self.store.read().await;

        // Collect all policy documents from every source, then apply
        // deny-overrides-allow across the whole set.
        let mut all_effects: Vec<PolicyEffect> = Vec::new();

        // ── 1. User attached managed policies ──────────────────────
        let attached_policies = store.list_attached_user_policies(user_name).await?;
        for policy_arn in attached_policies {
            if let Some(policy) = store.get_policy(&policy_arn).await? {
                let doc = policy_evaluator::parse_policy_doc(&policy.policy_document);
                all_effects.push(policy_evaluator::evaluate_policy_document(
                    &doc,
                    action,
                    resource_arn,
                    context,
                ));
            }
        }

        // ── 2. User inline policies ────────────────────────────────
        let inline_policies = store.list_user_policies(user_name).await?;
        for policy_name in inline_policies {
            if let Some(doc_str) = store.get_user_policy(user_name, &policy_name).await? {
                let doc = policy_evaluator::parse_policy_doc(&doc_str);
                all_effects.push(policy_evaluator::evaluate_policy_document(
                    &doc,
                    action,
                    resource_arn,
                    context,
                ));
            }
        }

        // ── 3. Group policies (attached + inline) ──────────────────
        let groups = store.list_groups_for_user(user_name).await?;
        for group in &groups {
            // Group attached managed policies
            let group_attached = store
                .list_attached_group_policies(&group.group_name)
                .await?;
            for policy_arn in group_attached {
                if let Some(policy) = store.get_policy(&policy_arn).await? {
                    let doc = policy_evaluator::parse_policy_doc(&policy.policy_document);
                    all_effects.push(policy_evaluator::evaluate_policy_document(
                        &doc,
                        action,
                        resource_arn,
                        context,
                    ));
                }
            }

            // Group inline policies
            let group_inline = store.list_group_policies(&group.group_name).await?;
            for policy_name in group_inline {
                if let Some(doc_str) = store
                    .get_group_policy(&group.group_name, &policy_name)
                    .await?
                {
                    let doc = policy_evaluator::parse_policy_doc(&doc_str);
                    all_effects.push(policy_evaluator::evaluate_policy_document(
                        &doc,
                        action,
                        resource_arn,
                        context,
                    ));
                }
            }
        }

        // ── 4. Assumed role policies (attached + inline) ───────────
        if let Some(session) = context.session_info() {
            if let Some(ref role_arn) = session.assumed_role_arn {
                if role_arn.resource.resource_type == "role" {
                    let role_name = &role_arn.resource.resource_id;

                    // Role attached managed policies
                    let role_attached = store.list_attached_role_policies(role_name).await?;
                    for policy_arn in role_attached {
                        if let Some(policy) = store.get_policy(&policy_arn).await? {
                            let doc = policy_evaluator::parse_policy_doc(&policy.policy_document);
                            all_effects.push(policy_evaluator::evaluate_policy_document(
                                &doc,
                                action,
                                resource_arn,
                                context,
                            ));
                        }
                    }

                    // Role inline policies
                    let role_inline = store.list_role_policies(role_name).await?;
                    for policy_name in role_inline {
                        if let Some(doc_str) =
                            store.get_role_policy(role_name, &policy_name).await?
                        {
                            let doc = policy_evaluator::parse_policy_doc(&doc_str);
                            all_effects.push(policy_evaluator::evaluate_policy_document(
                                &doc,
                                action,
                                resource_arn,
                                context,
                            ));
                        }
                    }
                }
            }
        }

        // ── 5. Deny-overrides-allow resolution ─────────────────────
        // An explicit Deny from ANY policy source overrides all Allows.
        if all_effects.contains(&PolicyEffect::Deny) {
            return Ok(false);
        }

        // If at least one policy allows, check permissions boundary.
        if all_effects.contains(&PolicyEffect::Allow) {
            // ── 6. Permissions boundary check ─────────────────────
            // If the user has a permissions boundary, the effective permission is
            // the INTERSECTION of the identity policies and the boundary.
            // The action must be allowed by BOTH the policies AND the boundary.
            if let Some(user) = store.get_user(user_name).await? {
                if let Some(ref boundary_arn) = user.permissions_boundary {
                    if let Some(boundary_policy) = store.get_policy(boundary_arn).await? {
                        let boundary_doc =
                            policy_evaluator::parse_policy_doc(&boundary_policy.policy_document);
                        let boundary_effect = policy_evaluator::evaluate_policy_document(
                            &boundary_doc,
                            action,
                            resource_arn,
                            context,
                        );
                        if boundary_effect != PolicyEffect::Allow {
                            // Boundary does not allow → effective deny
                            return Ok(false);
                        }
                    }
                    // If boundary policy not found, fail closed (deny)
                    else {
                        return Ok(false);
                    }
                }
            }
            return Ok(true);
        }

        // Default deny — no policy explicitly allows.
        Ok(false)
    }

    /// Extract user name from a user ARN
    fn extract_user_name_from_arn(&self, arn: &WamiArn) -> Result<String> {
        // Check if this is a user resource
        if arn.resource.resource_type == "user" {
            // Return the resource ID as user_name
            // Note: resource_id is the stable user ID, not necessarily the user name
            // This might need adjustment based on how user_name is mapped
            Ok(arn.resource.resource_id.clone())
        } else {
            Err(AmiError::InvalidParameter {
                message: "Caller ARN is not a user ARN".to_string(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::memory::InMemoryWamiStore;
    use wami_core::arn::matching::MatchContext;
    use wami_core::types::{PolicyDocument, PolicyStatement};

    #[test]
    fn test_matches_action() {
        // Exact match
        assert!(policy_evaluator::matches_action(
            &["iam:GetUser".to_string()],
            "iam:GetUser"
        ));

        // Wildcard all
        assert!(policy_evaluator::matches_action(
            &["*".to_string()],
            "iam:GetUser"
        ));

        // Wildcard prefix
        assert!(policy_evaluator::matches_action(
            &["iam:*".to_string()],
            "iam:GetUser"
        ));
        assert!(policy_evaluator::matches_action(
            &["iam:*".to_string()],
            "iam:CreateUser"
        ));

        // No match
        assert!(!policy_evaluator::matches_action(
            &["s3:GetObject".to_string()],
            "iam:GetUser"
        ));
    }

    #[test]
    fn test_matches_resource() {
        let ctx = MatchContext::default();

        // Exact match
        assert!(policy_evaluator::matches_resource(
            &["arn:wami:iam:12345678:wami:999:user/alice".to_string()],
            "arn:wami:iam:12345678:wami:999:user/alice",
            &ctx,
        ));

        // Wildcard all
        assert!(policy_evaluator::matches_resource(
            &["*".to_string()],
            "arn:wami:iam:12345678:wami:999:user/alice",
            &ctx,
        ));

        // Wildcard pattern
        assert!(policy_evaluator::matches_resource(
            &["arn:wami:iam:*:user/*".to_string()],
            "arn:wami:iam:12345678:wami:999:user/alice",
            &ctx,
        ));

        // No match
        assert!(!policy_evaluator::matches_resource(
            &["arn:wami:iam:12345678:wami:999:role/*".to_string()],
            "arn:wami:iam:12345678:wami:999:user/alice",
            &ctx,
        ));
    }

    #[test]
    fn test_matches_action_edge_cases() {
        // Empty actions
        assert!(!policy_evaluator::matches_action(&[], "iam:GetUser"));

        // Multiple wildcards
        assert!(policy_evaluator::matches_action(
            &["iam:*".to_string(), "s3:*".to_string()],
            "iam:GetUser"
        ));

        // Exact match in list
        assert!(policy_evaluator::matches_action(
            &["s3:GetObject".to_string(), "iam:GetUser".to_string()],
            "iam:GetUser"
        ));

        // No match
        assert!(!policy_evaluator::matches_action(
            &["s3:GetObject".to_string()],
            "iam:GetUser"
        ));

        // Wildcard at end
        assert!(policy_evaluator::matches_action(
            &["iam:Get*".to_string()],
            "iam:GetUser"
        ));
    }

    #[test]
    fn test_matches_resource_edge_cases() {
        let ctx = MatchContext::default();

        // Empty resources
        assert!(!policy_evaluator::matches_resource(
            &[],
            "arn:wami:iam:12345678:wami:999:user/alice",
            &ctx
        ));

        // Multiple patterns
        assert!(policy_evaluator::matches_resource(
            &[
                "arn:wami:iam:*:role/*".to_string(),
                "arn:wami:iam:*:user/*".to_string()
            ],
            "arn:wami:iam:12345678:wami:999:user/alice",
            &ctx,
        ));

        // Complex wildcard pattern (updated for numeric tenant IDs)
        assert!(policy_evaluator::matches_resource(
            &["arn:wami:iam:*:wami:*:user/al*".to_string()],
            "arn:wami:iam:12345678:wami:999:user/alice",
            &ctx,
        ));

        // Double-star glob — matches multi-segment paths
        assert!(policy_evaluator::matches_resource(
            &["arn:wami:hub:*:wami:*:space/le-zinc/**".to_string()],
            "arn:wami:hub:12345678:wami:999:space/le-zinc/db/menu",
            &ctx,
        ));
    }

    #[test]
    fn test_matches_resource_with_variable_substitution() {
        let ctx = MatchContext {
            tenant: Some("12345678".into()),
            principal: Some("alice".into()),
            service: Some("iam".into()),
        };

        // ${tenant} resolved from context
        assert!(policy_evaluator::matches_resource(
            &["arn:wami:iam:${tenant}:wami:*:user/*".to_string()],
            "arn:wami:iam:12345678:wami:999:user/alice",
            &ctx,
        ));

        // Wrong tenant → no match
        let other_ctx = MatchContext {
            tenant: Some("99999999".into()),
            ..Default::default()
        };
        assert!(!policy_evaluator::matches_resource(
            &["arn:wami:iam:${tenant}:wami:*:user/*".to_string()],
            "arn:wami:iam:12345678:wami:999:user/alice",
            &other_ctx,
        ));
    }

    #[test]
    fn test_evaluate_policy_deny_overrides_allow() {
        let policy = PolicyDocument {
            version: "2012-10-17".to_string(),
            statement: vec![
                PolicyStatement {
                    effect: "Allow".to_string(),
                    action: vec!["iam:*".to_string()],
                    resource: vec!["*".to_string()],
                    condition: None,
                },
                PolicyStatement {
                    effect: "Deny".to_string(),
                    action: vec!["iam:DeleteUser".to_string()],
                    resource: vec!["*".to_string()],
                    condition: None,
                },
            ],
        };

        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/alice".parse().unwrap();
        let ctx = dummy_context();
        let effect =
            policy_evaluator::evaluate_policy_document(&policy, "iam:DeleteUser", &resource, &ctx);

        // Deny should override Allow
        assert_eq!(effect, PolicyEffect::Deny);
    }

    #[test]
    fn test_evaluate_policy_no_match() {
        let policy = PolicyDocument {
            version: "2012-10-17".to_string(),
            statement: vec![PolicyStatement {
                effect: "Allow".to_string(),
                action: vec!["s3:GetObject".to_string()],
                resource: vec!["*".to_string()],
                condition: None,
            }],
        };

        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/alice".parse().unwrap();
        let ctx = dummy_context();
        let effect =
            policy_evaluator::evaluate_policy_document(&policy, "iam:GetUser", &resource, &ctx);

        assert_eq!(effect, PolicyEffect::NoMatch);
    }

    #[test]
    fn test_evaluate_policy_case_insensitive_effect() {
        let policy = PolicyDocument {
            version: "2012-10-17".to_string(),
            statement: vec![PolicyStatement {
                effect: "DENY".to_string(), // Uppercase
                action: vec!["iam:GetUser".to_string()],
                resource: vec!["*".to_string()],
                condition: None,
            }],
        };

        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/alice".parse().unwrap();
        let ctx = dummy_context();
        let effect =
            policy_evaluator::evaluate_policy_document(&policy, "iam:GetUser", &resource, &ctx);

        assert_eq!(effect, PolicyEffect::Deny);
    }

    /// Helper: minimal WamiContext for unit tests that only call evaluate_policy_document
    fn dummy_context() -> wami_core::context::WamiContext {
        let arn: WamiArn = "arn:wami:iam:12345678:wami:999:user/test".parse().unwrap();
        wami_core::context::WamiContext::builder()
            .instance_id("999")
            .tenant_path(wami_core::arn::TenantPath::single(12345678))
            .caller_arn(arn)
            .is_root(false)
            .build()
            .unwrap()
    }

    // ========== Integration tests: full policy evaluation pipeline ==========

    use crate::store::traits::{GroupStore, PolicyStore, RoleStore, UserStore};
    use crate::wami::identity::group::builder as group_builder;
    use crate::wami::identity::role::builder as role_builder;
    use crate::wami::identity::user::builder as user_builder;
    use crate::wami::policies::policy::builder as policy_builder;
    use wami_core::arn::{TenantPath, WamiArn as Arn};
    use wami_core::context::{SessionInfo, WamiContext};

    fn test_context() -> WamiContext {
        let arn: Arn = "arn:wami:iam:12345678:wami:999:user/alice".parse().unwrap();
        WamiContext::builder()
            .instance_id("999")
            .tenant_path(TenantPath::single(12345678))
            .caller_arn(arn)
            .is_root(false)
            .build()
            .unwrap()
    }

    fn allow_policy_json(actions: &[&str], resources: &[&str]) -> String {
        let actions_json: Vec<String> = actions.iter().map(|a| format!("\"{}\"", a)).collect();
        let resources_json: Vec<String> = resources.iter().map(|r| format!("\"{}\"", r)).collect();
        format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":[{}],"Resource":[{}]}}]}}"#,
            actions_json.join(","),
            resources_json.join(",")
        )
    }

    fn deny_policy_json(actions: &[&str], resources: &[&str]) -> String {
        let actions_json: Vec<String> = actions.iter().map(|a| format!("\"{}\"", a)).collect();
        let resources_json: Vec<String> = resources.iter().map(|r| format!("\"{}\"", r)).collect();
        format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Deny","Action":[{}],"Resource":[{}]}}]}}"#,
            actions_json.join(","),
            resources_json.join(",")
        )
    }

    /// Helper: set up store with a user named "alice"
    async fn setup_store_with_user(ctx: &WamiContext) -> Arc<RwLock<InMemoryWamiStore>> {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let user =
            user_builder::build_user("alice".to_string(), Some("/".to_string()), ctx).unwrap();
        store.write().await.create_user(user).await.unwrap();
        store
    }

    #[tokio::test]
    async fn test_group_attached_policy_allows() {
        let ctx = test_context();
        let store = setup_store_with_user(&ctx).await;

        // Create a group and add alice
        let group = group_builder::build_group("developers".to_string(), None, &ctx).unwrap();
        {
            let mut s = store.write().await;
            s.create_group(group).await.unwrap();
            s.add_user_to_group("developers", "alice").await.unwrap();
        }

        // Create a managed policy that allows iam:GetUser
        let policy = policy_builder::build_policy(
            "ReadPolicy".to_string(),
            allow_policy_json(&["iam:GetUser"], &["*"]),
            None,
            None,
            None,
            &ctx,
        )
        .unwrap();
        let policy_arn = policy.arn.clone();
        {
            let mut s = store.write().await;
            s.create_policy(policy).await.unwrap();
            s.attach_group_policy("developers", &policy_arn)
                .await
                .unwrap();
        }

        let authz = AuthorizationService::new(store);
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();

        let allowed = authz
            .authorize(&ctx, "iam:GetUser", &resource)
            .await
            .unwrap();
        assert!(allowed, "Group attached policy should allow iam:GetUser");
    }

    #[tokio::test]
    async fn test_group_inline_policy_allows() {
        let ctx = test_context();
        let store = setup_store_with_user(&ctx).await;

        // Create group, add alice, put inline policy
        let group = group_builder::build_group("admins".to_string(), None, &ctx).unwrap();
        {
            let mut s = store.write().await;
            s.create_group(group).await.unwrap();
            s.add_user_to_group("admins", "alice").await.unwrap();
            s.put_group_policy(
                "admins",
                "AdminInline",
                allow_policy_json(&["iam:*"], &["*"]),
            )
            .await
            .unwrap();
        }

        let authz = AuthorizationService::new(store);
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();

        let allowed = authz
            .authorize(&ctx, "iam:DeleteUser", &resource)
            .await
            .unwrap();
        assert!(allowed, "Group inline policy should allow iam:DeleteUser");
    }

    #[tokio::test]
    async fn test_group_deny_overrides_user_allow() {
        let ctx = test_context();
        let store = setup_store_with_user(&ctx).await;

        // Give alice a user inline policy that allows iam:*
        {
            let mut s = store.write().await;
            s.put_user_policy("alice", "UserAllow", allow_policy_json(&["iam:*"], &["*"]))
                .await
                .unwrap();
        }

        // Create group with deny policy for iam:DeleteUser
        let group = group_builder::build_group("restricted".to_string(), None, &ctx).unwrap();
        {
            let mut s = store.write().await;
            s.create_group(group).await.unwrap();
            s.add_user_to_group("restricted", "alice").await.unwrap();
            s.put_group_policy(
                "restricted",
                "DenyDelete",
                deny_policy_json(&["iam:DeleteUser"], &["*"]),
            )
            .await
            .unwrap();
        }

        let authz = AuthorizationService::new(store);
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();

        // Deny from group should override Allow from user inline
        let allowed = authz
            .authorize(&ctx, "iam:DeleteUser", &resource)
            .await
            .unwrap();
        assert!(!allowed, "Group deny should override user allow");

        // But other actions should still be allowed
        let allowed_get = authz
            .authorize(&ctx, "iam:GetUser", &resource)
            .await
            .unwrap();
        assert!(allowed_get, "iam:GetUser should still be allowed");
    }

    #[tokio::test]
    async fn test_assumed_role_attached_policy_allows() {
        let role_arn: WamiArn = "arn:wami:iam:12345678:wami:999:role/admin-role"
            .parse()
            .unwrap();

        let session = SessionInfo {
            session_token: "tok-123".to_string(),
            expiration: chrono::Utc::now().timestamp() + 3600,
            assumed_role_arn: Some(role_arn),
        };

        let user_arn: WamiArn = "arn:wami:iam:12345678:wami:999:user/alice".parse().unwrap();

        let ctx = WamiContext::builder()
            .instance_id("999")
            .tenant_path(TenantPath::single(12345678))
            .caller_arn(user_arn)
            .is_root(false)
            .session_info(session)
            .build()
            .unwrap();

        let store = setup_store_with_user(&ctx).await;

        // Create the role
        let role = role_builder::build_role(
            "admin-role".to_string(),
            r#"{"Version":"2012-10-17","Statement":[]}"#.to_string(),
            None,
            None,
            None,
            &ctx,
        )
        .unwrap();

        let policy = policy_builder::build_policy(
            "AdminAccess".to_string(),
            allow_policy_json(&["iam:*"], &["*"]),
            None,
            None,
            None,
            &ctx,
        )
        .unwrap();
        let policy_arn = policy.arn.clone();

        {
            let mut s = store.write().await;
            s.create_role(role).await.unwrap();
            s.create_policy(policy).await.unwrap();
            s.attach_role_policy("admin-role", &policy_arn)
                .await
                .unwrap();
        }

        let authz = AuthorizationService::new(store);
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();

        let allowed = authz
            .authorize(&ctx, "iam:CreateUser", &resource)
            .await
            .unwrap();
        assert!(allowed, "Assumed role policy should allow iam:CreateUser");
    }

    #[tokio::test]
    async fn test_assumed_role_inline_policy_allows() {
        let role_arn: WamiArn = "arn:wami:iam:12345678:wami:999:role/reader-role"
            .parse()
            .unwrap();

        let session = SessionInfo {
            session_token: "tok-456".to_string(),
            expiration: chrono::Utc::now().timestamp() + 3600,
            assumed_role_arn: Some(role_arn),
        };

        let user_arn: WamiArn = "arn:wami:iam:12345678:wami:999:user/alice".parse().unwrap();

        let ctx = WamiContext::builder()
            .instance_id("999")
            .tenant_path(TenantPath::single(12345678))
            .caller_arn(user_arn)
            .is_root(false)
            .session_info(session)
            .build()
            .unwrap();

        let store = setup_store_with_user(&ctx).await;

        let role = role_builder::build_role(
            "reader-role".to_string(),
            r#"{"Version":"2012-10-17","Statement":[]}"#.to_string(),
            None,
            None,
            None,
            &ctx,
        )
        .unwrap();

        {
            let mut s = store.write().await;
            s.create_role(role).await.unwrap();
            s.put_role_policy(
                "reader-role",
                "ReadOnly",
                allow_policy_json(&["iam:Get*", "iam:List*"], &["*"]),
            )
            .await
            .unwrap();
        }

        let authz = AuthorizationService::new(store);
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();

        let allowed = authz
            .authorize(&ctx, "iam:GetUser", &resource)
            .await
            .unwrap();
        assert!(allowed, "Role inline policy should allow iam:GetUser");

        let denied = authz
            .authorize(&ctx, "iam:DeleteUser", &resource)
            .await
            .unwrap();
        assert!(
            !denied,
            "Role inline policy should not allow iam:DeleteUser"
        );
    }

    #[tokio::test]
    async fn test_assumed_role_deny_overrides_user_and_group_allow() {
        let role_arn: WamiArn = "arn:wami:iam:12345678:wami:999:role/restrictive-role"
            .parse()
            .unwrap();

        let session = SessionInfo {
            session_token: "tok-789".to_string(),
            expiration: chrono::Utc::now().timestamp() + 3600,
            assumed_role_arn: Some(role_arn),
        };

        let user_arn: WamiArn = "arn:wami:iam:12345678:wami:999:user/alice".parse().unwrap();

        let ctx = WamiContext::builder()
            .instance_id("999")
            .tenant_path(TenantPath::single(12345678))
            .caller_arn(user_arn)
            .is_root(false)
            .session_info(session)
            .build()
            .unwrap();

        let store = setup_store_with_user(&ctx).await;

        // User inline: allow iam:*
        {
            let mut s = store.write().await;
            s.put_user_policy("alice", "AllowAll", allow_policy_json(&["iam:*"], &["*"]))
                .await
                .unwrap();
        }

        // Group: also allow iam:*
        let group = group_builder::build_group("power-users".to_string(), None, &ctx).unwrap();
        {
            let mut s = store.write().await;
            s.create_group(group).await.unwrap();
            s.add_user_to_group("power-users", "alice").await.unwrap();
            s.put_group_policy(
                "power-users",
                "AllowAll",
                allow_policy_json(&["iam:*"], &["*"]),
            )
            .await
            .unwrap();
        }

        // Assumed role: deny iam:DeleteUser
        let role = role_builder::build_role(
            "restrictive-role".to_string(),
            r#"{"Version":"2012-10-17","Statement":[]}"#.to_string(),
            None,
            None,
            None,
            &ctx,
        )
        .unwrap();
        {
            let mut s = store.write().await;
            s.create_role(role).await.unwrap();
            s.put_role_policy(
                "restrictive-role",
                "DenyDelete",
                deny_policy_json(&["iam:DeleteUser"], &["*"]),
            )
            .await
            .unwrap();
        }

        let authz = AuthorizationService::new(store);
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();

        // Deny from role should override allows from user + group
        let denied = authz
            .authorize(&ctx, "iam:DeleteUser", &resource)
            .await
            .unwrap();
        assert!(!denied, "Role deny must override user+group allow");

        // Other actions still allowed
        let allowed = authz
            .authorize(&ctx, "iam:GetUser", &resource)
            .await
            .unwrap();
        assert!(allowed, "iam:GetUser should still be allowed");
    }

    #[tokio::test]
    async fn test_no_session_means_no_role_policies() {
        let ctx = test_context(); // no session_info
        let store = setup_store_with_user(&ctx).await;

        // User has no policies — should default deny
        let authz = AuthorizationService::new(store);
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();

        let allowed = authz
            .authorize(&ctx, "iam:GetUser", &resource)
            .await
            .unwrap();
        assert!(!allowed, "No policies → default deny");
    }

    #[tokio::test]
    async fn test_root_bypasses_all() {
        let root_arn: Arn = "arn:wami:iam:12345678:wami:999:user/root".parse().unwrap();
        let ctx = WamiContext::builder()
            .instance_id("999")
            .tenant_path(TenantPath::single(12345678))
            .caller_arn(root_arn)
            .is_root(true)
            .build()
            .unwrap();

        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let authz = AuthorizationService::new(store);
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();

        // Root should bypass even with no policies at all
        let allowed = authz
            .authorize(&ctx, "iam:DeleteUser", &resource)
            .await
            .unwrap();
        assert!(allowed, "Root user must bypass all checks");
    }

    #[tokio::test]
    async fn test_multiple_groups_policies_combined() {
        let ctx = test_context();
        let store = setup_store_with_user(&ctx).await;

        // Group 1: allows iam:GetUser
        let g1 = group_builder::build_group("readers".to_string(), None, &ctx).unwrap();
        {
            let mut s = store.write().await;
            s.create_group(g1).await.unwrap();
            s.add_user_to_group("readers", "alice").await.unwrap();
            s.put_group_policy(
                "readers",
                "ReadPolicy",
                allow_policy_json(&["iam:GetUser"], &["*"]),
            )
            .await
            .unwrap();
        }

        // Group 2: allows iam:CreateUser
        let g2 = group_builder::build_group("creators".to_string(), None, &ctx).unwrap();
        {
            let mut s = store.write().await;
            s.create_group(g2).await.unwrap();
            s.add_user_to_group("creators", "alice").await.unwrap();
            s.put_group_policy(
                "creators",
                "CreatePolicy",
                allow_policy_json(&["iam:CreateUser"], &["*"]),
            )
            .await
            .unwrap();
        }

        let authz = AuthorizationService::new(store);
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();

        // Both actions should be allowed from different groups
        assert!(authz
            .authorize(&ctx, "iam:GetUser", &resource)
            .await
            .unwrap());
        assert!(authz
            .authorize(&ctx, "iam:CreateUser", &resource)
            .await
            .unwrap());
        // But delete is not allowed by any group
        assert!(!authz
            .authorize(&ctx, "iam:DeleteUser", &resource)
            .await
            .unwrap());
    }

    // ========== Condition evaluation tests (P2.2) ==========

    /// Helper: build a policy JSON with a Condition block.
    fn policy_with_condition(
        effect: &str,
        actions: &[&str],
        resources: &[&str],
        condition: &str,
    ) -> String {
        let actions_json: Vec<String> = actions.iter().map(|a| format!("\"{}\"", a)).collect();
        let resources_json: Vec<String> = resources.iter().map(|r| format!("\"{}\"", r)).collect();
        format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"{}","Action":[{}],"Resource":[{}],"Condition":{}}}]}}"#,
            effect,
            actions_json.join(","),
            resources_json.join(","),
            condition
        )
    }

    #[test]
    fn test_condition_ip_restriction_allows_matching_ip() {
        // Policy: Allow iam:GetUser only from 10.0.0.0/8
        let policy_json = policy_with_condition(
            "Allow",
            &["iam:GetUser"],
            &["*"],
            r#"{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}"#,
        );
        let doc: PolicyDocument = serde_json::from_str(&policy_json).unwrap();

        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();

        // Context with matching IP
        let arn: WamiArn = "arn:wami:iam:12345678:wami:999:user/alice".parse().unwrap();
        let ctx = WamiContext::builder()
            .instance_id("999")
            .tenant_path(TenantPath::single(12345678))
            .caller_arn(arn)
            .is_root(false)
            .source_ip("10.1.2.3")
            .build()
            .unwrap();

        let effect =
            policy_evaluator::evaluate_policy_document(&doc, "iam:GetUser", &resource, &ctx);
        assert_eq!(
            effect,
            PolicyEffect::Allow,
            "IP 10.1.2.3 should match 10.0.0.0/8"
        );
    }

    #[test]
    fn test_condition_ip_restriction_denies_non_matching_ip() {
        // Policy: Allow iam:GetUser only from 10.0.0.0/8
        let policy_json = policy_with_condition(
            "Allow",
            &["iam:GetUser"],
            &["*"],
            r#"{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}"#,
        );
        let doc: PolicyDocument = serde_json::from_str(&policy_json).unwrap();

        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();

        // Context with NON-matching IP
        let arn: WamiArn = "arn:wami:iam:12345678:wami:999:user/alice".parse().unwrap();
        let ctx = WamiContext::builder()
            .instance_id("999")
            .tenant_path(TenantPath::single(12345678))
            .caller_arn(arn)
            .is_root(false)
            .source_ip("192.168.1.1")
            .build()
            .unwrap();

        let effect =
            policy_evaluator::evaluate_policy_document(&doc, "iam:GetUser", &resource, &ctx);
        assert_eq!(
            effect,
            PolicyEffect::NoMatch,
            "IP 192.168.1.1 should NOT match 10.0.0.0/8 → NoMatch"
        );
    }

    #[test]
    fn test_condition_mfa_required_allows_with_mfa() {
        // Policy: Allow iam:DeleteUser only when MFA is present
        let policy_json = policy_with_condition(
            "Allow",
            &["iam:DeleteUser"],
            &["*"],
            r#"{"Bool":{"aws:MultiFactorAuthPresent":"true"}}"#,
        );
        let doc: PolicyDocument = serde_json::from_str(&policy_json).unwrap();

        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();

        // Context WITH MFA
        let arn: WamiArn = "arn:wami:iam:12345678:wami:999:user/alice".parse().unwrap();
        let ctx = WamiContext::builder()
            .instance_id("999")
            .tenant_path(TenantPath::single(12345678))
            .caller_arn(arn)
            .is_root(false)
            .mfa_present(true)
            .build()
            .unwrap();

        let effect =
            policy_evaluator::evaluate_policy_document(&doc, "iam:DeleteUser", &resource, &ctx);
        assert_eq!(
            effect,
            PolicyEffect::Allow,
            "MFA present → condition matches → Allow"
        );
    }

    #[test]
    fn test_condition_mfa_required_nomatch_without_mfa() {
        // Policy: Allow iam:DeleteUser only when MFA is present
        let policy_json = policy_with_condition(
            "Allow",
            &["iam:DeleteUser"],
            &["*"],
            r#"{"Bool":{"aws:MultiFactorAuthPresent":"true"}}"#,
        );
        let doc: PolicyDocument = serde_json::from_str(&policy_json).unwrap();

        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();

        // Context WITHOUT MFA
        let arn: WamiArn = "arn:wami:iam:12345678:wami:999:user/alice".parse().unwrap();
        let ctx = WamiContext::builder()
            .instance_id("999")
            .tenant_path(TenantPath::single(12345678))
            .caller_arn(arn)
            .is_root(false)
            .mfa_present(false)
            .build()
            .unwrap();

        let effect =
            policy_evaluator::evaluate_policy_document(&doc, "iam:DeleteUser", &resource, &ctx);
        assert_eq!(
            effect,
            PolicyEffect::NoMatch,
            "MFA absent → condition fails → NoMatch"
        );
    }

    #[test]
    fn test_condition_no_condition_still_works() {
        // Policy without condition should still work normally
        let doc = PolicyDocument {
            version: "2012-10-17".to_string(),
            statement: vec![PolicyStatement {
                effect: "Allow".to_string(),
                action: vec!["iam:GetUser".to_string()],
                resource: vec!["*".to_string()],
                condition: None,
            }],
        };

        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();
        let ctx = dummy_context();

        let effect =
            policy_evaluator::evaluate_policy_document(&doc, "iam:GetUser", &resource, &ctx);
        assert_eq!(
            effect,
            PolicyEffect::Allow,
            "No condition → Allow (backward compat)"
        );
    }

    #[tokio::test]
    async fn test_condition_deny_with_ip_restriction_full_pipeline() {
        let ctx_arn: WamiArn = "arn:wami:iam:12345678:wami:999:user/alice".parse().unwrap();
        let ctx = WamiContext::builder()
            .instance_id("999")
            .tenant_path(TenantPath::single(12345678))
            .caller_arn(ctx_arn)
            .is_root(false)
            .source_ip("203.0.113.50")
            .build()
            .unwrap();

        let store = setup_store_with_user(&ctx).await;

        // User inline: allow iam:*
        {
            let mut s = store.write().await;
            s.put_user_policy("alice", "AllowAll", allow_policy_json(&["iam:*"], &["*"]))
                .await
                .unwrap();
        }

        // User inline: deny iam:DeleteUser from outside 10.0.0.0/8
        {
            let mut s = store.write().await;
            s.put_user_policy(
                "alice",
                "DenyDeleteFromExternal",
                policy_with_condition(
                    "Deny",
                    &["iam:DeleteUser"],
                    &["*"],
                    r#"{"NotIpAddress":{"aws:SourceIp":"10.0.0.0/8"}}"#,
                ),
            )
            .await
            .unwrap();
        }

        let authz = AuthorizationService::new(store);
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();

        // IP 203.0.113.50 is NOT in 10.0.0.0/8, so deny condition matches → deny
        let denied = authz
            .authorize(&ctx, "iam:DeleteUser", &resource)
            .await
            .unwrap();
        assert!(!denied, "Deny condition should fire for external IP");

        // Other actions still allowed
        let allowed = authz
            .authorize(&ctx, "iam:GetUser", &resource)
            .await
            .unwrap();
        assert!(allowed, "iam:GetUser should still be allowed");
    }

    // ========== Permissions boundary tests (P2.3) ==========

    #[tokio::test]
    async fn test_boundary_restricts_effective_permissions() {
        let ctx = test_context();
        let store = setup_store_with_user(&ctx).await;

        // Give alice iam:* via user inline policy
        {
            let mut s = store.write().await;
            s.put_user_policy("alice", "AllowAll", allow_policy_json(&["iam:*"], &["*"]))
                .await
                .unwrap();
        }

        // Create a boundary policy that only allows iam:Get* and iam:List*
        let boundary = policy_builder::build_policy(
            "ReadOnlyBoundary".to_string(),
            allow_policy_json(&["iam:Get*", "iam:List*"], &["*"]),
            None,
            None,
            None,
            &ctx,
        )
        .unwrap();
        let boundary_arn = boundary.arn.clone();
        {
            let mut s = store.write().await;
            s.create_policy(boundary).await.unwrap();
        }

        // Set boundary on alice
        {
            let mut s = store.write().await;
            let mut alice = s.get_user("alice").await.unwrap().unwrap();
            alice.permissions_boundary = Some(boundary_arn);
            s.update_user(alice).await.unwrap();
        }

        let authz = AuthorizationService::new(store);
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();

        // iam:GetUser is in boundary → allowed
        let allowed = authz
            .authorize(&ctx, "iam:GetUser", &resource)
            .await
            .unwrap();
        assert!(allowed, "iam:GetUser should be allowed (within boundary)");

        // iam:ListUsers is in boundary → allowed
        let allowed = authz
            .authorize(&ctx, "iam:ListUsers", &resource)
            .await
            .unwrap();
        assert!(allowed, "iam:ListUsers should be allowed (within boundary)");

        // iam:DeleteUser is NOT in boundary → denied despite policy allowing it
        let denied = authz
            .authorize(&ctx, "iam:DeleteUser", &resource)
            .await
            .unwrap();
        assert!(
            !denied,
            "iam:DeleteUser should be denied (outside boundary)"
        );

        // iam:CreateUser is NOT in boundary → denied
        let denied = authz
            .authorize(&ctx, "iam:CreateUser", &resource)
            .await
            .unwrap();
        assert!(
            !denied,
            "iam:CreateUser should be denied (outside boundary)"
        );
    }

    #[tokio::test]
    async fn test_no_boundary_means_normal_evaluation() {
        let ctx = test_context();
        let store = setup_store_with_user(&ctx).await;

        // Give alice iam:* via user inline policy, NO boundary
        {
            let mut s = store.write().await;
            s.put_user_policy("alice", "AllowAll", allow_policy_json(&["iam:*"], &["*"]))
                .await
                .unwrap();
        }

        let authz = AuthorizationService::new(store);
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();

        // Without boundary, iam:DeleteUser should be allowed
        let allowed = authz
            .authorize(&ctx, "iam:DeleteUser", &resource)
            .await
            .unwrap();
        assert!(allowed, "No boundary → full access per policy");
    }

    #[tokio::test]
    async fn test_boundary_missing_policy_fails_closed() {
        let ctx = test_context();
        let store = setup_store_with_user(&ctx).await;

        // Give alice iam:*
        {
            let mut s = store.write().await;
            s.put_user_policy("alice", "AllowAll", allow_policy_json(&["iam:*"], &["*"]))
                .await
                .unwrap();
        }

        // Set a boundary ARN that doesn't exist in the store
        {
            let mut s = store.write().await;
            let mut alice = s.get_user("alice").await.unwrap().unwrap();
            alice.permissions_boundary =
                Some("arn:wami:iam:12345678:wami:999:policy/nonexistent".to_string());
            s.update_user(alice).await.unwrap();
        }

        let authz = AuthorizationService::new(store);
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();

        // Boundary policy not found → fail closed (deny)
        let denied = authz
            .authorize(&ctx, "iam:GetUser", &resource)
            .await
            .unwrap();
        assert!(!denied, "Missing boundary policy → deny (fail closed)");
    }

    #[tokio::test]
    async fn test_boundary_with_deny_policy_interaction() {
        let ctx = test_context();
        let store = setup_store_with_user(&ctx).await;

        // Give alice iam:* via policy
        {
            let mut s = store.write().await;
            s.put_user_policy("alice", "AllowAll", allow_policy_json(&["iam:*"], &["*"]))
                .await
                .unwrap();
        }

        // Explicit deny on iam:DeleteUser
        {
            let mut s = store.write().await;
            s.put_user_policy(
                "alice",
                "DenyDelete",
                deny_policy_json(&["iam:DeleteUser"], &["*"]),
            )
            .await
            .unwrap();
        }

        // Boundary allows everything — but deny still wins
        let boundary = policy_builder::build_policy(
            "FullBoundary".to_string(),
            allow_policy_json(&["*"], &["*"]),
            None,
            None,
            None,
            &ctx,
        )
        .unwrap();
        let boundary_arn = boundary.arn.clone();
        {
            let mut s = store.write().await;
            s.create_policy(boundary).await.unwrap();
            let mut alice = s.get_user("alice").await.unwrap().unwrap();
            alice.permissions_boundary = Some(boundary_arn);
            s.update_user(alice).await.unwrap();
        }

        let authz = AuthorizationService::new(store);
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();

        // Explicit deny still wins even with permissive boundary
        let denied = authz
            .authorize(&ctx, "iam:DeleteUser", &resource)
            .await
            .unwrap();
        assert!(!denied, "Explicit deny must win over boundary + allow");

        // GetUser: allowed by policy AND boundary
        let allowed = authz
            .authorize(&ctx, "iam:GetUser", &resource)
            .await
            .unwrap();
        assert!(allowed, "iam:GetUser should be allowed");
    }
}
