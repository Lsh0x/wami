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
//!     // The decision carries why it went that way, so it can be logged or
//!     // shown to the user as-is.
//!     let decision = authz_service
//!         .authorize(&context, "iam:GetUser", &resource_arn)
//!         .await?;
//!
//!     println!("{decision}");
//!     if decision.is_allowed() {
//!         // ...
//!     }
//!
//!     Ok(())
//! }
//! ```

use crate::service::auth::decision::{
    AllowReason, Decision, DenyReason, NonEmpty, PolicySource, StatementRef,
};
use crate::service::auth::policy_evaluator::{self, PolicyEffect, StatementHit};
use crate::store::traits::{GroupStore, PolicyStore, RoleStore, UserStore};
use std::sync::Arc;
use tokio::sync::RwLock;
use wami_core::arn::{ScopedName, WamiArn};
use wami_core::context::WamiContext;
use wami_core::error::{AmiError, Result};
use wami_core::types::PolicyDocument;

/// Authorization Service
///
/// Handles permission checking based on IAM policies.
pub struct AuthorizationService<S>
where
    S: UserStore + GroupStore + RoleStore + PolicyStore + Send + Sync,
{
    store: Arc<RwLock<S>>,
}

/// The user's permissions boundary, as the store holds it.
enum Boundary {
    /// The user has none.
    None,
    /// Referenced, but no policy is stored under that ARN.
    Missing {
        /// The referenced ARN.
        arn: String,
    },
    /// Referenced and stored: read with the identity documents.
    Present {
        /// `PolicySource::PermissionsBoundary`, naming it in errors.
        source: PolicySource,
        /// The stored document, not yet parsed.
        document: String,
    },
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
    /// Returns an error if there's a problem accessing the store, and
    /// [`AmiError::UnreadablePolicy`] or [`AmiError::UnreadableCondition`] when
    /// a document or a statement's condition cannot be read: the decision is
    /// refused rather than guessed, the policy and the statement named.
    pub async fn authorize(
        &self,
        context: &WamiContext,
        action: &str,
        resource_arn: &WamiArn,
    ) -> Result<Decision> {
        // Root bypasses everything, permissions boundary included — as it does
        // in AWS, where boundaries do not apply to the account root.
        if context.is_root() {
            return Ok(Decision::Allow(AllowReason::RootBypass));
        }

        let user = self.extract_user_name_from_arn(context.caller_arn())?;

        self.evaluate_user_policies(context, &user, action, resource_arn)
            .await
    }

    /// Check if access is denied (returns an error if not authorized)
    ///
    /// Convenience wrapper over [`AuthorizationService::authorize`] for callers
    /// that only need to proceed or stop. The refusal names what decided, so a
    /// caller gets a usable message without handling [`Decision`] itself.
    pub async fn check_or_deny(
        &self,
        context: &WamiContext,
        action: &str,
        resource_arn: &WamiArn,
    ) -> Result<()> {
        match self.authorize(context, action, resource_arn).await? {
            Decision::Allow(_) => Ok(()),
            denied => Err(AmiError::AccessDenied {
                message: format!(
                    "{} is not authorized to perform {} on {}: {}",
                    context.caller_arn(),
                    action,
                    resource_arn,
                    denied
                ),
            }),
        }
    }

    /// Evaluate all policies for a user
    ///
    /// Collects from every source — the user's managed and inline policies,
    /// those of their groups, and those of an assumed role — then applies
    /// deny-overrides-allow across the whole set, and finally intersects with
    /// the permissions boundary.
    ///
    /// Everything is READ before anything is decided (wami 001): every
    /// document, the boundary included, is parsed first, and any that cannot
    /// be read refuses the decision with all of them named; then every
    /// document is evaluated, and any statement whose condition cannot be
    /// compared refuses it too. A Deny that holds does not excuse a broken
    /// document beside it, and the boundary is read whatever the identity
    /// verdict — so the same documents are refused whatever the action asked.
    ///
    /// The collected sources are sorted before anything is read. That sort
    /// is where determinism comes from: `GroupStore::list_groups_for_user` and
    /// friends promise no ordering, so a SQL backend without an `ORDER BY`
    /// could hand back the same policies in a different order on two identical
    /// calls. Sorting by [`PolicySource`] reproduces the intended precedence —
    /// user, then group, then role — no matter what the store did, and makes
    /// the list of unreadable documents the same on every call.
    async fn evaluate_user_policies(
        &self,
        context: &WamiContext,
        user: &ScopedName,
        action: &str,
        resource_arn: &WamiArn,
    ) -> Result<Decision> {
        let (documents, boundary) = {
            let store = self.store.read().await;
            let documents = Self::identity_documents(&store, context, user).await?;
            (documents, Self::boundary_document(&store, user).await?)
        };
        // Canonical order — see the note on this function — the boundary
        // last; the simulation reads in the same order, by the same function.
        let boundary_document = match &boundary {
            Boundary::Present { source, document } => Some((source.clone(), document.clone())),
            Boundary::None | Boundary::Missing { .. } => None,
        };
        let documents = policy_evaluator::in_reading_order(documents, boundary_document);

        let parsed = Self::read_every_document(&documents)?;
        let mut hits = Self::evaluate_every_document(&parsed, action, resource_arn, context)?;
        let boundary_hit = match &boundary {
            Boundary::Present { .. } => hits
                .pop_if(|(source, _)| matches!(source, PolicySource::PermissionsBoundary { .. })),
            _ => None,
        };
        Ok(Self::decide(&hits, &boundary, boundary_hit))
    }

    /// Parse every document; refuse, naming all of them, if any cannot be read.
    fn read_every_document(
        documents: &[(PolicySource, String)],
    ) -> Result<Vec<(PolicySource, PolicyDocument)>> {
        let mut parsed = Vec::new();
        let mut unreadable = Vec::new();
        for (source, document) in documents {
            match policy_evaluator::parse_policy_doc(document, source) {
                Ok(document) => parsed.push((source.clone(), document)),
                Err(e) => unreadable.push(e),
            }
        }
        match policy_evaluator::combine(unreadable) {
            Some(error) => Err(error),
            None => Ok(parsed),
        }
    }

    /// Evaluate every document; refuse, naming all of them, if a condition
    /// cannot be compared in any. The hits keep the documents' order, the
    /// boundary's last.
    fn evaluate_every_document(
        documents: &[(PolicySource, PolicyDocument)],
        action: &str,
        resource_arn: &WamiArn,
        context: &WamiContext,
    ) -> Result<Vec<(PolicySource, StatementHit)>> {
        let mut hits = Vec::new();
        let mut unreadable = Vec::new();
        for (source, document) in documents {
            match policy_evaluator::evaluate_policy_document(
                document,
                action,
                resource_arn,
                context,
                source,
            ) {
                Ok(Some(hit)) => hits.push((source.clone(), hit)),
                Ok(None) => {}
                Err(e) => unreadable.push(e),
            }
        }
        match policy_evaluator::combine(unreadable) {
            Some(error) => Err(error),
            None => Ok(hits),
        }
    }

    /// Deny-overrides-allow over the identity hits, then the boundary.
    fn decide(
        hits: &[(PolicySource, StatementHit)],
        boundary: &Boundary,
        boundary_hit: Option<(PolicySource, StatementHit)>,
    ) -> Decision {
        let refs = |effect: PolicyEffect| -> Vec<StatementRef> {
            hits.iter()
                .filter(|(_, hit)| hit.effect == effect)
                .map(|(source, hit)| StatementRef {
                    policy: source.clone(),
                    sid: hit.sid.clone(),
                    index: hit.index,
                })
                .collect()
        };

        if let Ok(denied_by) = NonEmpty::new(refs(PolicyEffect::Deny)) {
            return Decision::Deny(DenyReason::Statements(denied_by));
        }

        // Nothing allowed it, so there is no statement to name. The boundary
        // cannot change this: it can only narrow permissions, never grant them.
        let Ok(allowed_by) = NonEmpty::new(refs(PolicyEffect::Allow)) else {
            return Decision::Deny(DenyReason::NoMatch);
        };

        // Effective permissions are the intersection of the identity policies
        // and the boundary: the action must be allowed by both.
        match boundary {
            Boundary::None => Decision::Allow(AllowReason::Statements(allowed_by)),
            // Referenced but absent: a ceiling that cannot be read cannot be
            // honoured, so fail closed.
            Boundary::Missing { arn } => {
                Decision::Deny(DenyReason::BoundaryMissing { arn: arn.clone() })
            }
            Boundary::Present { source, .. } => match boundary_hit {
                Some((_, hit)) if hit.effect == PolicyEffect::Allow => {
                    Decision::Allow(AllowReason::Statements(allowed_by))
                }
                // An explicit deny in the boundary and a boundary that simply
                // does not cover the action are both refusals, but they call
                // for opposite fixes — remove that statement, or widen the
                // boundary. `denied_by` carries which one it was.
                other => Decision::Deny(DenyReason::BoundaryRestricted {
                    arn: match source {
                        PolicySource::PermissionsBoundary { arn } => arn.clone(),
                        _ => String::new(),
                    },
                    allowed_by,
                    denied_by: other
                        .into_iter()
                        .map(|(_, hit)| StatementRef {
                            policy: source.clone(),
                            sid: hit.sid,
                            index: hit.index,
                        })
                        .collect(),
                }),
            },
        }
    }

    /// The user's permissions boundary, as stored.
    async fn boundary_document(store: &S, key: &ScopedName) -> Result<Boundary> {
        let Some(user) = store.get_user(key).await? else {
            return Ok(Boundary::None);
        };
        let Some(arn) = user.permissions_boundary else {
            return Ok(Boundary::None);
        };
        Ok(match store.get_policy(&arn).await? {
            Some(policy) => Boundary::Present {
                source: PolicySource::PermissionsBoundary { arn },
                document: policy.policy_document,
            },
            None => Boundary::Missing { arn },
        })
    }

    /// Every identity document that can take part, with its source.
    async fn identity_documents(
        store: &S,
        context: &WamiContext,
        user: &ScopedName,
    ) -> Result<Vec<(PolicySource, String)>> {
        let mut documents = Vec::new();

        // ── 1. User attached managed policies ──────────────────────
        for policy_arn in store.list_attached_user_policies(user).await? {
            if let Some(policy) = store.get_policy(&policy_arn).await? {
                documents.push((
                    PolicySource::UserManaged { arn: policy_arn },
                    policy.policy_document,
                ));
            }
        }

        // ── 2. User inline policies ────────────────────────────────
        for policy_name in store.list_user_policies(user).await? {
            if let Some(document) = store.get_user_policy(user, &policy_name).await? {
                documents.push((PolicySource::UserInline { name: policy_name }, document));
            }
        }

        // ── 3. Group policies (attached + inline) ──────────────────
        for group in store.list_groups_for_user(user).await? {
            let group_name = &group.group_name;
            let group_key = group.key();
            for policy_arn in store.list_attached_group_policies(&group_key).await? {
                if let Some(policy) = store.get_policy(&policy_arn).await? {
                    documents.push((
                        PolicySource::GroupManaged {
                            group: group_name.clone(),
                            arn: policy_arn,
                        },
                        policy.policy_document,
                    ));
                }
            }
            for policy_name in store.list_group_policies(&group_key).await? {
                if let Some(document) = store.get_group_policy(&group_key, &policy_name).await? {
                    documents.push((
                        PolicySource::GroupInline {
                            group: group_name.clone(),
                            name: policy_name,
                        },
                        document,
                    ));
                }
            }
        }

        // ── 4. Assumed role policies (attached + inline) ───────────
        // TRANSITIONAL (wami 005, until the session carries the role's key):
        // the role is read off its ARN's resource id, which is its id, not its
        // name — D8, kept as it was for one commit.
        let role_key = context
            .session_info()
            .and_then(|session| session.assumed_role_arn.as_ref())
            .filter(|role_arn| role_arn.resource.resource_type == "role")
            .map(|role_arn| {
                ScopedName::new(
                    role_arn.tenant_path.clone(),
                    role_arn.resource.resource_id.clone(),
                )
            });
        if let Some(role_key) = role_key {
            let role_name = role_key.name().to_string();
            for policy_arn in store.list_attached_role_policies(&role_key).await? {
                if let Some(policy) = store.get_policy(&policy_arn).await? {
                    documents.push((
                        PolicySource::RoleManaged {
                            role: role_name.clone(),
                            arn: policy_arn,
                        },
                        policy.policy_document,
                    ));
                }
            }
            for policy_name in store.list_role_policies(&role_key).await? {
                if let Some(document) = store.get_role_policy(&role_key, &policy_name).await? {
                    documents.push((
                        PolicySource::RoleInline {
                            role: role_name.clone(),
                            name: policy_name,
                        },
                        document,
                    ));
                }
            }
        }

        Ok(documents)
    }
    /// Extract user name from a user ARN
    ///
    /// TRANSITIONAL (wami 005, until the context carries the caller's key): the
    /// key is the ARN's tenant path and resource id, as the name was before.
    fn extract_user_name_from_arn(&self, arn: &WamiArn) -> Result<ScopedName> {
        // Check if this is a user resource
        if arn.resource.resource_type == "user" {
            // Return the resource ID as user_name
            // Note: resource_id is the stable user ID, not necessarily the user name
            // This might need adjustment based on how user_name is mapped
            Ok(ScopedName::new(
                arn.tenant_path.clone(),
                arn.resource.resource_id.clone(),
            ))
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

    /// The tenant every test here works in.
    fn tenant() -> wami_core::arn::TenantPath {
        wami_core::arn::TenantPath::single(12345678)
    }

    /// `name`'s key in that tenant.
    fn key(name: impl AsRef<str>) -> wami_core::arn::ScopedName {
        wami_core::arn::ScopedName::new(tenant(), name.as_ref())
    }

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
                    sid: None,
                    effect: "Allow".to_string(),
                    action: vec!["iam:*".to_string()],
                    resource: vec!["*".to_string()],
                    condition: None,
                },
                PolicyStatement {
                    sid: None,
                    effect: "Deny".to_string(),
                    action: vec!["iam:DeleteUser".to_string()],
                    resource: vec!["*".to_string()],
                    condition: None,
                },
            ],
        };

        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/alice".parse().unwrap();
        let ctx = dummy_context();
        let effect = policy_evaluator::evaluate_policy_document(
            &policy,
            "iam:DeleteUser",
            &resource,
            &ctx,
            &a_source(),
        )
        .unwrap();

        // Deny should override Allow
        assert_eq!(effect.map(|hit| hit.effect), Some(PolicyEffect::Deny));
    }

    #[test]
    fn test_evaluate_policy_no_match() {
        let policy = PolicyDocument {
            version: "2012-10-17".to_string(),
            statement: vec![PolicyStatement {
                sid: None,
                effect: "Allow".to_string(),
                action: vec!["s3:GetObject".to_string()],
                resource: vec!["*".to_string()],
                condition: None,
            }],
        };

        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/alice".parse().unwrap();
        let ctx = dummy_context();
        let effect = policy_evaluator::evaluate_policy_document(
            &policy,
            "iam:GetUser",
            &resource,
            &ctx,
            &a_source(),
        )
        .unwrap();

        assert!(effect.is_none());
    }

    #[test]
    fn test_evaluate_policy_case_insensitive_effect() {
        let policy = PolicyDocument {
            version: "2012-10-17".to_string(),
            statement: vec![PolicyStatement {
                sid: None,
                effect: "DENY".to_string(), // Uppercase
                action: vec!["iam:GetUser".to_string()],
                resource: vec!["*".to_string()],
                condition: None,
            }],
        };

        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/alice".parse().unwrap();
        let ctx = dummy_context();
        let effect = policy_evaluator::evaluate_policy_document(
            &policy,
            "iam:GetUser",
            &resource,
            &ctx,
            &a_source(),
        )
        .unwrap();

        assert_eq!(effect.map(|hit| hit.effect), Some(PolicyEffect::Deny));
    }

    /// Helper: the source unit tests name a document by.
    fn a_source() -> PolicySource {
        PolicySource::UserInline {
            name: "p".to_string(),
        }
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
        let user = user_builder::build_user(&key("alice"), Some("/".to_string()), ctx).unwrap();
        store.write().await.create_user(user).await.unwrap();
        store
    }

    #[tokio::test]
    async fn test_group_attached_policy_allows() {
        let ctx = test_context();
        let store = setup_store_with_user(&ctx).await;

        // Create a group and add alice
        let group = group_builder::build_group(&key("developers"), None, &ctx).unwrap();
        {
            let mut s = store.write().await;
            s.create_group(group).await.unwrap();
            s.add_user_to_group(&key("developers"), &key("alice"))
                .await
                .unwrap();
        }

        // Create a managed policy that allows iam:GetUser
        let policy = policy_builder::build_policy(
            "ReadPolicy".to_string(),
            allow_policy_json(&["iam:GetUser"], &["*"]),
            None,
            None,
            None,
            &tenant(),
            &ctx,
        )
        .unwrap();
        let policy_arn = policy.arn.clone();
        {
            let mut s = store.write().await;
            s.create_policy(policy).await.unwrap();
            s.attach_group_policy(&key("developers"), &policy_arn)
                .await
                .unwrap();
        }

        let authz = AuthorizationService::new(store);
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();

        let allowed = authz
            .authorize(&ctx, "iam:GetUser", &resource)
            .await
            .unwrap();
        assert!(
            allowed.is_allowed(),
            "Group attached policy should allow iam:GetUser"
        );
    }

    #[tokio::test]
    async fn test_group_inline_policy_allows() {
        let ctx = test_context();
        let store = setup_store_with_user(&ctx).await;

        // Create group, add alice, put inline policy
        let group = group_builder::build_group(&key("admins"), None, &ctx).unwrap();
        {
            let mut s = store.write().await;
            s.create_group(group).await.unwrap();
            s.add_user_to_group(&key("admins"), &key("alice"))
                .await
                .unwrap();
            s.put_group_policy(
                &key("admins"),
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
        assert!(
            allowed.is_allowed(),
            "Group inline policy should allow iam:DeleteUser"
        );
    }

    #[tokio::test]
    async fn test_group_deny_overrides_user_allow() {
        let ctx = test_context();
        let store = setup_store_with_user(&ctx).await;

        // Give alice a user inline policy that allows iam:*
        {
            let mut s = store.write().await;
            s.put_user_policy(
                &key("alice"),
                "UserAllow",
                allow_policy_json(&["iam:*"], &["*"]),
            )
            .await
            .unwrap();
        }

        // Create group with deny policy for iam:DeleteUser
        let group = group_builder::build_group(&key("restricted"), None, &ctx).unwrap();
        {
            let mut s = store.write().await;
            s.create_group(group).await.unwrap();
            s.add_user_to_group(&key("restricted"), &key("alice"))
                .await
                .unwrap();
            s.put_group_policy(
                &key("restricted"),
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
        assert!(
            !allowed.is_allowed(),
            "Group deny should override user allow"
        );

        // But other actions should still be allowed
        let allowed_get = authz
            .authorize(&ctx, "iam:GetUser", &resource)
            .await
            .unwrap();
        assert!(
            allowed_get.is_allowed(),
            "iam:GetUser should still be allowed"
        );
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
            &key("admin-role"),
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
            &tenant(),
            &ctx,
        )
        .unwrap();
        let policy_arn = policy.arn.clone();

        {
            let mut s = store.write().await;
            s.create_role(role).await.unwrap();
            s.create_policy(policy).await.unwrap();
            s.attach_role_policy(&key("admin-role"), &policy_arn)
                .await
                .unwrap();
        }

        let authz = AuthorizationService::new(store);
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();

        let allowed = authz
            .authorize(&ctx, "iam:CreateUser", &resource)
            .await
            .unwrap();
        assert!(
            allowed.is_allowed(),
            "Assumed role policy should allow iam:CreateUser"
        );
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
            &key("reader-role"),
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
                &key("reader-role"),
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
        assert!(
            allowed.is_allowed(),
            "Role inline policy should allow iam:GetUser"
        );

        let denied = authz
            .authorize(&ctx, "iam:DeleteUser", &resource)
            .await
            .unwrap();
        assert!(
            !denied.is_allowed(),
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
            s.put_user_policy(
                &key("alice"),
                "AllowAll",
                allow_policy_json(&["iam:*"], &["*"]),
            )
            .await
            .unwrap();
        }

        // Group: also allow iam:*
        let group = group_builder::build_group(&key("power-users"), None, &ctx).unwrap();
        {
            let mut s = store.write().await;
            s.create_group(group).await.unwrap();
            s.add_user_to_group(&key("power-users"), &key("alice"))
                .await
                .unwrap();
            s.put_group_policy(
                &key("power-users"),
                "AllowAll",
                allow_policy_json(&["iam:*"], &["*"]),
            )
            .await
            .unwrap();
        }

        // Assumed role: deny iam:DeleteUser
        let role = role_builder::build_role(
            &key("restrictive-role"),
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
                &key("restrictive-role"),
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
        assert!(
            !denied.is_allowed(),
            "Role deny must override user+group allow"
        );

        // Other actions still allowed
        let allowed = authz
            .authorize(&ctx, "iam:GetUser", &resource)
            .await
            .unwrap();
        assert!(allowed.is_allowed(), "iam:GetUser should still be allowed");
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
        assert!(!allowed.is_allowed(), "No policies → default deny");
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
        assert!(allowed.is_allowed(), "Root user must bypass all checks");
    }

    #[tokio::test]
    async fn test_multiple_groups_policies_combined() {
        let ctx = test_context();
        let store = setup_store_with_user(&ctx).await;

        // Group 1: allows iam:GetUser
        let g1 = group_builder::build_group(&key("readers"), None, &ctx).unwrap();
        {
            let mut s = store.write().await;
            s.create_group(g1).await.unwrap();
            s.add_user_to_group(&key("readers"), &key("alice"))
                .await
                .unwrap();
            s.put_group_policy(
                &key("readers"),
                "ReadPolicy",
                allow_policy_json(&["iam:GetUser"], &["*"]),
            )
            .await
            .unwrap();
        }

        // Group 2: allows iam:CreateUser
        let g2 = group_builder::build_group(&key("creators"), None, &ctx).unwrap();
        {
            let mut s = store.write().await;
            s.create_group(g2).await.unwrap();
            s.add_user_to_group(&key("creators"), &key("alice"))
                .await
                .unwrap();
            s.put_group_policy(
                &key("creators"),
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
            .unwrap()
            .is_allowed());
        assert!(authz
            .authorize(&ctx, "iam:CreateUser", &resource)
            .await
            .unwrap()
            .is_allowed());
        // But delete is not allowed by any group
        assert!(!authz
            .authorize(&ctx, "iam:DeleteUser", &resource)
            .await
            .unwrap()
            .is_allowed());
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

        let effect = policy_evaluator::evaluate_policy_document(
            &doc,
            "iam:GetUser",
            &resource,
            &ctx,
            &a_source(),
        )
        .unwrap();
        assert_eq!(
            effect.map(|hit| hit.effect),
            Some(PolicyEffect::Allow),
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

        let effect = policy_evaluator::evaluate_policy_document(
            &doc,
            "iam:GetUser",
            &resource,
            &ctx,
            &a_source(),
        )
        .unwrap();
        assert!(
            effect.is_none(),
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

        let effect = policy_evaluator::evaluate_policy_document(
            &doc,
            "iam:DeleteUser",
            &resource,
            &ctx,
            &a_source(),
        )
        .unwrap();
        assert_eq!(
            effect.map(|hit| hit.effect),
            Some(PolicyEffect::Allow),
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

        let effect = policy_evaluator::evaluate_policy_document(
            &doc,
            "iam:DeleteUser",
            &resource,
            &ctx,
            &a_source(),
        )
        .unwrap();
        assert!(effect.is_none(), "MFA absent → condition fails → NoMatch");
    }

    #[test]
    fn test_condition_no_condition_still_works() {
        // Policy without condition should still work normally
        let doc = PolicyDocument {
            version: "2012-10-17".to_string(),
            statement: vec![PolicyStatement {
                sid: None,
                effect: "Allow".to_string(),
                action: vec!["iam:GetUser".to_string()],
                resource: vec!["*".to_string()],
                condition: None,
            }],
        };

        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();
        let ctx = dummy_context();

        let effect = policy_evaluator::evaluate_policy_document(
            &doc,
            "iam:GetUser",
            &resource,
            &ctx,
            &a_source(),
        )
        .unwrap();
        assert_eq!(
            effect.map(|hit| hit.effect),
            Some(PolicyEffect::Allow),
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
            s.put_user_policy(
                &key("alice"),
                "AllowAll",
                allow_policy_json(&["iam:*"], &["*"]),
            )
            .await
            .unwrap();
        }

        // User inline: deny iam:DeleteUser from outside 10.0.0.0/8
        {
            let mut s = store.write().await;
            s.put_user_policy(
                &key("alice"),
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
        assert!(
            !denied.is_allowed(),
            "Deny condition should fire for external IP"
        );

        // Other actions still allowed
        let allowed = authz
            .authorize(&ctx, "iam:GetUser", &resource)
            .await
            .unwrap();
        assert!(allowed.is_allowed(), "iam:GetUser should still be allowed");
    }

    // ========== Permissions boundary tests (P2.3) ==========

    #[tokio::test]
    async fn test_boundary_restricts_effective_permissions() {
        let ctx = test_context();
        let store = setup_store_with_user(&ctx).await;

        // Give alice iam:* via user inline policy
        {
            let mut s = store.write().await;
            s.put_user_policy(
                &key("alice"),
                "AllowAll",
                allow_policy_json(&["iam:*"], &["*"]),
            )
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
            &tenant(),
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
            let mut alice = s.get_user(&key("alice")).await.unwrap().unwrap();
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
        assert!(
            allowed.is_allowed(),
            "iam:GetUser should be allowed (within boundary)"
        );

        // iam:ListUsers is in boundary → allowed
        let allowed = authz
            .authorize(&ctx, "iam:ListUsers", &resource)
            .await
            .unwrap();
        assert!(
            allowed.is_allowed(),
            "iam:ListUsers should be allowed (within boundary)"
        );

        // iam:DeleteUser is NOT in boundary → denied despite policy allowing it
        let denied = authz
            .authorize(&ctx, "iam:DeleteUser", &resource)
            .await
            .unwrap();
        assert!(
            !denied.is_allowed(),
            "iam:DeleteUser should be denied (outside boundary)"
        );

        // iam:CreateUser is NOT in boundary → denied
        let denied = authz
            .authorize(&ctx, "iam:CreateUser", &resource)
            .await
            .unwrap();
        assert!(
            !denied.is_allowed(),
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
            s.put_user_policy(
                &key("alice"),
                "AllowAll",
                allow_policy_json(&["iam:*"], &["*"]),
            )
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
        assert!(allowed.is_allowed(), "No boundary → full access per policy");
    }

    #[tokio::test]
    async fn test_boundary_missing_policy_fails_closed() {
        let ctx = test_context();
        let store = setup_store_with_user(&ctx).await;

        // Give alice iam:*
        {
            let mut s = store.write().await;
            s.put_user_policy(
                &key("alice"),
                "AllowAll",
                allow_policy_json(&["iam:*"], &["*"]),
            )
            .await
            .unwrap();
        }

        // Set a boundary ARN that doesn't exist in the store
        {
            let mut s = store.write().await;
            let mut alice = s.get_user(&key("alice")).await.unwrap().unwrap();
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
        assert!(
            !denied.is_allowed(),
            "Missing boundary policy → deny (fail closed)"
        );
    }

    #[tokio::test]
    async fn test_boundary_with_deny_policy_interaction() {
        let ctx = test_context();
        let store = setup_store_with_user(&ctx).await;

        // Give alice iam:* via policy
        {
            let mut s = store.write().await;
            s.put_user_policy(
                &key("alice"),
                "AllowAll",
                allow_policy_json(&["iam:*"], &["*"]),
            )
            .await
            .unwrap();
        }

        // Explicit deny on iam:DeleteUser
        {
            let mut s = store.write().await;
            s.put_user_policy(
                &key("alice"),
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
            &tenant(),
            &ctx,
        )
        .unwrap();
        let boundary_arn = boundary.arn.clone();
        {
            let mut s = store.write().await;
            s.create_policy(boundary).await.unwrap();
            let mut alice = s.get_user(&key("alice")).await.unwrap().unwrap();
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
        assert!(
            !denied.is_allowed(),
            "Explicit deny must win over boundary + allow"
        );

        // GetUser: allowed by policy AND boundary
        let allowed = authz
            .authorize(&ctx, "iam:GetUser", &resource)
            .await
            .unwrap();
        assert!(allowed.is_allowed(), "iam:GetUser should be allowed");
    }

    // ─── #100: the decision names what decided ────────────────────

    #[tokio::test]
    async fn an_allow_names_the_statement_that_granted_it() {
        let ctx = test_context();
        let store = setup_store_with_user(&ctx).await;
        store
            .write()
            .await
            .put_user_policy(
                &key("alice"),
                "AllowReads",
                r#"{"Version":"2012-10-17","Statement":[{"Sid":"ReadAnything","Effect":"Allow","Action":["iam:GetUser"],"Resource":["*"]}]}"#
                    .to_string(),
            )
            .await
            .unwrap();

        let authz = AuthorizationService::new(store);
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();
        let decision = authz
            .authorize(&ctx, "iam:GetUser", &resource)
            .await
            .unwrap();

        let Decision::Allow(AllowReason::Statements(refs)) = &decision else {
            panic!("expected a statement-backed allow, got {decision:?}");
        };
        assert_eq!(refs.first().sid.as_deref(), Some("ReadAnything"));
        assert_eq!(
            refs.first().policy,
            PolicySource::UserInline {
                name: "AllowReads".to_string()
            }
        );
        // And it renders into something an audit log can keep verbatim.
        assert!(decision.to_string().contains("ReadAnything"));
    }

    #[tokio::test]
    async fn a_deny_reports_every_source_that_denied_not_just_one() {
        // Two independent denials — a group policy and a user policy. An
        // auditor needs both; reporting only the first would hide one.
        let ctx = test_context();
        let store = setup_store_with_user(&ctx).await;
        {
            let mut s = store.write().await;
            let group = group_builder::build_group(&key("blocked"), None, &ctx).unwrap();
            s.create_group(group).await.unwrap();
            s.add_user_to_group(&key("blocked"), &key("alice"))
                .await
                .unwrap();
            s.put_group_policy(
                &key("blocked"),
                "GroupDeny",
                deny_policy_json(&["iam:*"], &["*"]),
            )
            .await
            .unwrap();
            s.put_user_policy(
                &key("alice"),
                "UserDeny",
                deny_policy_json(&["iam:*"], &["*"]),
            )
            .await
            .unwrap();
        }

        let authz = AuthorizationService::new(store);
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();
        let decision = authz
            .authorize(&ctx, "iam:GetUser", &resource)
            .await
            .unwrap();

        let Decision::Deny(DenyReason::Statements(refs)) = &decision else {
            panic!("expected statement-backed deny, got {decision:?}");
        };
        assert_eq!(refs.len(), 2, "both denials must be reported");
        // Canonical order: the user's own policy before the group's, whatever
        // order the store returned them in.
        assert!(matches!(refs[0].policy, PolicySource::UserInline { .. }));
        assert!(matches!(refs[1].policy, PolicySource::GroupInline { .. }));
    }

    #[tokio::test]
    async fn nothing_matching_is_distinguishable_from_an_explicit_deny() {
        let ctx = test_context();
        let store = setup_store_with_user(&ctx).await;
        let authz = AuthorizationService::new(store);
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();

        // The distinction a bool could not carry: refused because a rule says
        // so, versus refused because no rule applies.
        assert_eq!(
            authz
                .authorize(&ctx, "iam:GetUser", &resource)
                .await
                .unwrap(),
            Decision::Deny(DenyReason::NoMatch)
        );
    }

    #[tokio::test]
    async fn root_is_allowed_without_consulting_any_policy() {
        let ctx = WamiContext::builder()
            .instance_id("999")
            .tenant_path(TenantPath::single(12345678))
            .caller_arn(
                "arn:wami:iam:12345678:wami:999:user/root"
                    .parse::<Arn>()
                    .unwrap(),
            )
            .is_root(true)
            .build()
            .unwrap();

        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let authz = AuthorizationService::new(store);
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();

        assert_eq!(
            authz
                .authorize(&ctx, "iam:DeleteUser", &resource)
                .await
                .unwrap(),
            Decision::Allow(AllowReason::RootBypass)
        );
    }

    // ─── boundary: two refusals, two different fixes ──────────────

    async fn alice_with_boundary(
        ctx: &WamiContext,
        boundary: &str,
    ) -> Arc<RwLock<InMemoryWamiStore>> {
        let store = setup_store_with_user(ctx).await;
        let mut s = store.write().await;
        s.put_user_policy(
            &key("alice"),
            "AllowAll",
            allow_policy_json(&["iam:*"], &["*"]),
        )
        .await
        .unwrap();
        let policy = policy_builder::build_policy(
            "Boundary".to_string(),
            boundary.to_string(),
            None,
            None,
            None,
            &tenant(),
            ctx,
        )
        .unwrap();
        let arn = policy.arn.clone();
        s.create_policy(policy).await.unwrap();
        let mut alice = s.get_user(&key("alice")).await.unwrap().unwrap();
        alice.permissions_boundary = Some(arn);
        s.update_user(alice).await.unwrap();
        drop(s);
        store
    }

    #[tokio::test]
    async fn a_boundary_that_does_not_cover_the_action_says_so() {
        let ctx = test_context();
        // Allows something else entirely — the action is simply not covered.
        let store = alice_with_boundary(&ctx, &allow_policy_json(&["s3:*"], &["*"])).await;
        let authz = AuthorizationService::new(store);
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();

        let decision = authz
            .authorize(&ctx, "iam:GetUser", &resource)
            .await
            .unwrap();
        let Decision::Deny(DenyReason::BoundaryRestricted {
            allowed_by,
            denied_by,
            ..
        }) = &decision
        else {
            panic!("expected boundary restriction, got {decision:?}");
        };
        assert!(
            denied_by.is_empty(),
            "no explicit deny — the fix is to widen the boundary"
        );
        assert!(!allowed_by.is_empty(), "identity policy did allow it");
        assert!(decision.to_string().contains("does not cover"));
    }

    #[tokio::test]
    async fn a_boundary_that_explicitly_denies_names_the_statement() {
        let ctx = test_context();
        let store = alice_with_boundary(&ctx, &deny_policy_json(&["iam:*"], &["*"])).await;
        let authz = AuthorizationService::new(store);
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();

        let decision = authz
            .authorize(&ctx, "iam:GetUser", &resource)
            .await
            .unwrap();
        let Decision::Deny(DenyReason::BoundaryRestricted { denied_by, .. }) = &decision else {
            panic!("expected boundary restriction, got {decision:?}");
        };
        // The opposite remedy from the previous test: remove this statement.
        assert_eq!(denied_by.len(), 1);
        assert!(matches!(
            denied_by[0].policy,
            PolicySource::PermissionsBoundary { .. }
        ));
        assert!(decision.to_string().contains("refuses this action"));
    }

    // ─── #120: an unreadable policy is an error, not a silent allow ──

    #[tokio::test]
    async fn a_malformed_deny_no_longer_disappears() {
        // Written straight to the store, as a third-party backend or a
        // pre-fix row would be — the service layer now rejects this on write.
        let ctx = test_context();
        let store = setup_store_with_user(&ctx).await;
        {
            let mut s = store.write().await;
            s.put_user_policy(
                &key("alice"),
                "Allow",
                allow_policy_json(&["iam:*"], &["*"]),
            )
            .await
            .unwrap();
            s.put_user_policy(
                &key("alice"),
                "BrokenDeny",
                // "Actions" instead of "Action" — valid JSON, invalid policy.
                r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Actions":["iam:*"],"Resource":["*"]}]}"#
                    .to_string(),
            )
            .await
            .unwrap();
        }

        let authz = AuthorizationService::new(store);
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();
        let err = authz
            .authorize(&ctx, "iam:GetUser", &resource)
            .await
            .expect_err("a policy that cannot be read must not yield a decision");

        // Before the fix this returned Ok(true): the Deny parsed to nothing and
        // the Allow won.
        assert!(matches!(err, AmiError::UnreadablePolicy { .. }), "{err:?}");
        assert!(err.to_string().contains("BrokenDeny"));
    }

    #[tokio::test]
    async fn an_unreadable_boundary_is_reported_as_the_boundary() {
        // The second parsing path. It must name the boundary, not leave the
        // operator guessing which of the two documents failed.
        let ctx = test_context();
        let store = alice_with_boundary(&ctx, r#"{"Version":"2012-10-17"}"#).await;
        let authz = AuthorizationService::new(store);
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();

        let err = authz
            .authorize(&ctx, "iam:GetUser", &resource)
            .await
            .expect_err("an unreadable boundary must not be treated as absent");
        assert!(matches!(err, AmiError::UnreadablePolicy { .. }), "{err:?}");
        assert!(err.to_string().contains("permissions boundary"));
    }

    #[tokio::test]
    async fn a_malformed_policy_is_refused_on_write() {
        // The other half of the fix: stop it entering the store at all.
        use crate::service::policies::inline::InlinePolicyService;
        use crate::wami::policies::inline::PutUserPolicyRequest;

        let ctx = test_context();
        let store = setup_store_with_user(&ctx).await;
        let service = InlinePolicyService::new(store);

        let err = service
            .put_user_policy(
                &ctx,
                PutUserPolicyRequest {
                    user: key("alice"),
                    policy_name: "BrokenDeny".to_string(),
                    policy_document: r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Actions":["iam:*"],"Resource":["*"]}]}"#.to_string(),
                },
            )
            .await
            .expect_err("valid JSON that is not a valid policy must be refused");
        assert!(matches!(err, AmiError::InvalidParameter { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn check_or_deny_quotes_the_reason_it_refused() {
        // The convenience wrapper must not throw away the motivation — that is
        // the whole point of the change for callers that never touch Decision.
        let ctx = test_context();
        let store = setup_store_with_user(&ctx).await;
        store
            .write()
            .await
            .put_user_policy(
                &key("alice"),
                "Blocked",
                deny_policy_json(&["iam:*"], &["*"]),
            )
            .await
            .unwrap();

        let authz = AuthorizationService::new(store);
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();

        let err = authz
            .check_or_deny(&ctx, "iam:GetUser", &resource)
            .await
            .expect_err("an explicit deny must refuse");
        let AmiError::AccessDenied { message } = &err else {
            panic!("expected AccessDenied, got {err:?}");
        };
        assert!(message.contains("denied by"), "{message}");
        assert!(message.contains("Blocked"), "{message}");
    }

    #[tokio::test]
    async fn check_or_deny_passes_when_allowed() {
        let ctx = test_context();
        let store = setup_store_with_user(&ctx).await;
        store
            .write()
            .await
            .put_user_policy(
                &key("alice"),
                "Allow",
                allow_policy_json(&["iam:*"], &["*"]),
            )
            .await
            .unwrap();

        let authz = AuthorizationService::new(store);
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();
        authz
            .check_or_deny(&ctx, "iam:GetUser", &resource)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_managed_policy_attached_to_the_user_is_evaluated() {
        // The inline path was covered; the managed one was not.
        let ctx = test_context();
        let store = setup_store_with_user(&ctx).await;
        {
            let mut s = store.write().await;
            let policy = policy_builder::build_policy(
                "ReadOnly".to_string(),
                allow_policy_json(&["iam:GetUser"], &["*"]),
                None,
                None,
                None,
                &tenant(),
                &ctx,
            )
            .unwrap();
            let arn = policy.arn.clone();
            s.create_policy(policy).await.unwrap();
            s.attach_user_policy(&key("alice"), &arn).await.unwrap();
        }

        let authz = AuthorizationService::new(store);
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();
        let decision = authz
            .authorize(&ctx, "iam:GetUser", &resource)
            .await
            .unwrap();

        let Decision::Allow(AllowReason::Statements(refs)) = &decision else {
            panic!("expected an allow from the managed policy, got {decision:?}");
        };
        assert!(matches!(
            refs.first().policy,
            PolicySource::UserManaged { .. }
        ));
    }

    #[tokio::test]
    async fn a_missing_user_cannot_have_a_boundary_to_apply() {
        // The caller is authenticated but the user record is gone. There is no
        // boundary to intersect with, so an allow already found stands.
        let ctx = test_context();
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        store
            .write()
            .await
            .put_user_policy(
                &key("alice"),
                "Allow",
                allow_policy_json(&["iam:*"], &["*"]),
            )
            .await
            .unwrap();

        let authz = AuthorizationService::new(store);
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();
        assert!(authz
            .authorize(&ctx, "iam:GetUser", &resource)
            .await
            .unwrap()
            .is_allowed());
    }

    // ─── wami 001: an unreadable condition is an error, not a false one ──

    /// A Deny on `iam:*` whose condition is `cond`, written straight to the
    /// store beside an Allow on `iam:*` — as a third-party backend or a row
    /// written before the parse check would hold it.
    async fn alice_with_conditional_deny(
        ctx: &WamiContext,
        cond: &str,
    ) -> Arc<RwLock<InMemoryWamiStore>> {
        let store = setup_store_with_user(ctx).await;
        {
            let mut s = store.write().await;
            s.put_user_policy(
                &key("alice"),
                "Allow",
                allow_policy_json(&["iam:*"], &["*"]),
            )
            .await
            .unwrap();
            s.put_user_policy(
                &key("alice"),
                "ConditionalDeny",
                format!(
                    r#"{{"Version":"2012-10-17","Statement":[{{"Sid":"BlockAll","Effect":"Deny","Action":["iam:*"],"Resource":["*"],"Condition":{cond}}}]}}"#
                ),
            )
            .await
            .unwrap();
        }
        store
    }

    #[tokio::test]
    async fn a_deny_with_an_unknown_operator_refuses_the_decision() {
        // `StringEqualz`: one letter. The condition used to read as false, the
        // Deny vanished, and the Allow beside it won.
        let ctx = test_context();
        let store =
            alice_with_conditional_deny(&ctx, r#"{"StringEqualz":{"aws:username":"alice"}}"#).await;
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();

        let outcome = AuthorizationService::new(store)
            .authorize(&ctx, "iam:GetUser", &resource)
            .await;
        let err = outcome.expect_err("an unreadable condition must not yield a decision");
        // Refused by the parse net, whatever the action: UnreadablePolicy.
        assert!(matches!(err, AmiError::UnreadablePolicy { .. }), "{err:?}");
        // Never disguised as an ordinary refusal, and the operator is told
        // which policy and which statement to go fix.
        assert!(!matches!(err, AmiError::AccessDenied { .. }));
        let message = err.to_string();
        assert!(message.contains("ConditionalDeny"), "{message}");
        assert!(message.contains("BlockAll"), "{message}");
    }

    #[tokio::test]
    async fn a_context_value_the_condition_cannot_compare_refuses_the_decision() {
        // A well-formed policy, but the request's source address is no address:
        // the comparison cannot be made. Reachable at evaluation whatever parse
        // checks, since it depends on the request.
        let arn: Arn = "arn:wami:iam:12345678:wami:999:user/alice".parse().unwrap();
        let ctx = WamiContext::builder()
            .instance_id("999")
            .tenant_path(TenantPath::single(12345678))
            .caller_arn(arn)
            .is_root(false)
            .source_ip("not-an-ip")
            .build()
            .unwrap();
        let store =
            alice_with_conditional_deny(&ctx, r#"{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}"#)
                .await;
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();

        let err = AuthorizationService::new(store)
            .authorize(&ctx, "iam:GetUser", &resource)
            .await
            .expect_err("an evaluation error must not yield a decision");
        let message = err.to_string();
        assert!(
            matches!(err, AmiError::UnreadableCondition { .. }),
            "{err:?}"
        );
        assert!(message.contains("ConditionalDeny"), "{message}");
        assert!(message.contains("BlockAll"), "{message}");
    }

    #[tokio::test]
    async fn a_deny_whose_condition_is_false_still_lets_the_allow_through() {
        // The regression guard: a FALSE condition is NoMatch (AWS semantics).
        // A Deny "for mallory" must not apply to alice.
        let ctx = test_context();
        let store =
            alice_with_conditional_deny(&ctx, r#"{"StringEquals":{"aws:username":"mallory"}}"#)
                .await;
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();

        let decision = AuthorizationService::new(store)
            .authorize(&ctx, "iam:GetUser", &resource)
            .await
            .unwrap();
        assert!(decision.is_allowed(), "{decision:?}");
    }

    #[tokio::test]
    async fn a_boundary_with_an_unreadable_condition_refuses_the_decision() {
        let ctx = test_context();
        let boundary = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:*"],"Resource":["*"]},{"Sid":"Fence","Effect":"Deny","Action":["iam:*"],"Resource":["*"],"Condition":{"StringEqualz":{"aws:username":"alice"}}}]}"#;
        let store = alice_with_boundary(&ctx, boundary).await;
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();

        let err = AuthorizationService::new(store)
            .authorize(&ctx, "iam:GetUser", &resource)
            .await
            .expect_err("a boundary that cannot be read must not be honoured as read");
        let message = err.to_string();
        assert!(message.contains("permissions boundary"), "{message}");
        assert!(message.contains("Fence"), "{message}");
    }

    // ─── wami 001, review round 1: read everything before deciding ──────

    /// Alice's context, with the request's source address when given.
    fn alice_from(ip: Option<&str>) -> WamiContext {
        let arn: Arn = "arn:wami:iam:12345678:wami:999:user/alice".parse().unwrap();
        let mut builder = WamiContext::builder()
            .instance_id("999")
            .tenant_path(TenantPath::single(12345678))
            .caller_arn(arn)
            .is_root(false);
        if let Some(ip) = ip {
            builder = builder.source_ip(ip);
        }
        builder.build().unwrap()
    }

    /// A one-statement document on `iam:*`.
    fn statement_json(sid: &str, effect: &str, condition: Option<&str>) -> String {
        let condition = condition.map_or(String::new(), |c| format!(r#","Condition":{c}"#));
        format!(
            r#"{{"Sid":"{sid}","Effect":"{effect}","Action":["iam:*"],"Resource":["*"]{condition}}}"#
        )
    }

    fn document_json(statements: &[String]) -> String {
        format!(
            r#"{{"Version":"2012-10-17","Statement":[{}]}}"#,
            statements.join(",")
        )
    }

    /// The request's address compared as a network: errs when it is no address.
    const FROM_THE_OFFICE: &str = r#"{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}"#;
    const MISSPELT: &str = r#"{"StringEqualz":{"aws:username":"alice"}}"#;

    /// Alice with these inline policies, put in this order.
    async fn alice_with_policies(
        ctx: &WamiContext,
        policies: &[(&str, String)],
    ) -> Arc<RwLock<InMemoryWamiStore>> {
        let store = setup_store_with_user(ctx).await;
        for (name, document) in policies {
            store
                .write()
                .await
                .put_user_policy(&key("alice"), name, document.clone())
                .await
                .unwrap();
        }
        store
    }

    async fn decide(
        store: Arc<RwLock<InMemoryWamiStore>>,
        ctx: &WamiContext,
        action: &str,
    ) -> Result<Decision> {
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();
        AuthorizationService::new(store)
            .authorize(ctx, action, &resource)
            .await
    }

    #[tokio::test]
    async fn a_true_deny_does_not_excuse_a_broken_allow_beside_it() {
        // One document: a Deny that holds, and an Allow whose condition cannot
        // be read for this request. Every matching statement is read before
        // any verdict, so the answer is the error, not the Deny.
        let ctx = alice_from(Some("not-an-ip"));
        let document = document_json(&[
            statement_json("DenyAll", "Deny", None),
            statement_json("FromTheOffice", "Allow", Some(FROM_THE_OFFICE)),
        ]);
        let store = alice_with_policies(&ctx, &[("Mixed", document)]).await;
        let err = decide(store, &ctx, "iam:GetUser")
            .await
            .expect_err("a broken statement must not be skipped because a Deny held");
        assert!(
            matches!(err, AmiError::UnreadableCondition { .. }),
            "{err:?}"
        );
        assert!(err.to_string().contains("FromTheOffice"), "{err}");
    }

    #[tokio::test]
    async fn a_true_deny_in_one_document_does_not_excuse_a_broken_one_in_another() {
        let ctx = alice_from(Some("not-an-ip"));
        let store = alice_with_policies(
            &ctx,
            &[
                (
                    "A",
                    document_json(&[statement_json("DenyAll", "Deny", None)]),
                ),
                (
                    "B",
                    document_json(&[statement_json("Office", "Deny", Some(FROM_THE_OFFICE))]),
                ),
            ],
        )
        .await;
        let err = decide(store, &ctx, "iam:GetUser").await.unwrap_err();
        assert!(
            matches!(err, AmiError::UnreadableCondition { .. }),
            "{err:?}"
        );
        assert!(err.to_string().contains("Office"), "{err}");
    }

    #[tokio::test]
    async fn an_unreadable_boundary_refuses_even_when_nothing_allows() {
        // Nothing allows s3:GetObject: the boundary used to be skipped, and a
        // broken one went unnoticed. It is read whatever the identity verdict.
        let ctx = test_context();
        let boundary = document_json(&[statement_json("Fence", "Deny", Some(MISSPELT))]);
        let store = alice_with_boundary(&ctx, &boundary).await;
        let err = decide(store, &ctx, "s3:GetObject")
            .await
            .expect_err("a boundary that cannot be read must refuse the decision");
        assert!(matches!(err, AmiError::UnreadablePolicy { .. }), "{err:?}");
        assert!(err.to_string().contains("permissions boundary"), "{err}");
    }

    #[tokio::test]
    async fn a_boundary_whose_condition_errs_refuses_even_when_an_identity_policy_denies() {
        let ctx = alice_from(Some("not-an-ip"));
        let boundary = document_json(&[statement_json("Office", "Allow", Some(FROM_THE_OFFICE))]);
        let store = alice_with_boundary(&ctx, &boundary).await;
        store
            .write()
            .await
            .put_user_policy(
                &key("alice"),
                "DenyAll",
                document_json(&[statement_json("DenyAll", "Deny", None)]),
            )
            .await
            .unwrap();
        let err = decide(store, &ctx, "iam:GetUser").await.unwrap_err();
        assert!(
            matches!(err, AmiError::UnreadableCondition { .. }),
            "{err:?}"
        );
        assert!(err.to_string().contains("permissions boundary"), "{err}");
    }

    #[tokio::test]
    async fn every_unreadable_document_is_named_whatever_the_store_order() {
        let broken = || document_json(&[statement_json("Broken", "Deny", Some(MISSPELT))]);
        let mut messages = Vec::new();
        for order in [["A", "B"], ["B", "A"]] {
            let ctx = test_context();
            let policies: Vec<(&str, String)> =
                order.iter().map(|name| (*name, broken())).collect();
            let store = alice_with_policies(&ctx, &policies).await;
            let err = decide(store, &ctx, "iam:GetUser").await.unwrap_err();
            assert!(matches!(err, AmiError::UnreadablePolicy { .. }), "{err:?}");
            messages.push(err.to_string());
        }
        assert_eq!(messages[0], messages[1]);
        let a = messages[0].find("user inline policy A");
        let b = messages[0].find("user inline policy B");
        assert!(a.is_some() && b.is_some() && a < b, "{}", messages[0]);
    }

    #[tokio::test]
    async fn a_misspelt_effect_refuses_the_decision() {
        // "Dney" used to be neither a Deny nor an Allow: the statement vanished.
        let ctx = test_context();
        let store = alice_with_policies(
            &ctx,
            &[
                ("Allow", allow_policy_json(&["iam:*"], &["*"])),
                (
                    "Typo",
                    document_json(&[statement_json("NoDelete", "Dney", None)]),
                ),
            ],
        )
        .await;
        let err = decide(store, &ctx, "iam:GetUser").await.unwrap_err();
        assert!(matches!(err, AmiError::UnreadablePolicy { .. }), "{err:?}");
        assert!(err.to_string().contains("NoDelete"), "{err}");
    }

    #[tokio::test]
    async fn a_broken_deny_on_another_action_is_refused_by_the_parse_net() {
        // The request does not ask for s3:*, so evaluation would never reach
        // the statement: only the parse net can refuse it.
        let ctx = test_context();
        let broken = format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Sid":"Elsewhere","Effect":"Deny","Action":["s3:*"],"Resource":["*"],"Condition":{MISSPELT}}}]}}"#
        );
        let store = alice_with_policies(
            &ctx,
            &[
                ("Allow", allow_policy_json(&["iam:*"], &["*"])),
                ("Broken", broken),
            ],
        )
        .await;
        let err = decide(store, &ctx, "iam:GetUser").await.unwrap_err();
        assert!(matches!(err, AmiError::UnreadablePolicy { .. }), "{err:?}");
        assert!(err.to_string().contains("Elsewhere"), "{err}");
    }

    #[tokio::test]
    async fn if_exists_reads_a_present_value_and_skips_an_absent_one() {
        let office_if_present = r#"{"IpAddressIfExists":{"aws:SourceIp":"10.0.0.0/8"}}"#;
        let policies = || {
            vec![
                ("Allow", allow_policy_json(&["iam:*"], &["*"])),
                (
                    "Office",
                    document_json(&[statement_json("Office", "Deny", Some(office_if_present))]),
                ),
            ]
        };
        // Present but no address: it cannot be compared, so it refuses.
        let ctx = alice_from(Some("not-an-ip"));
        let store = alice_with_policies(&ctx, &policies()).await;
        let err = decide(store, &ctx, "iam:GetUser").await.unwrap_err();
        assert!(
            matches!(err, AmiError::UnreadableCondition { .. }),
            "{err:?}"
        );
        // Absent: IfExists passes, so the Deny applies.
        let ctx = alice_from(None);
        let store = alice_with_policies(&ctx, &policies()).await;
        let decision = decide(store, &ctx, "iam:GetUser").await.unwrap();
        assert!(!decision.is_allowed(), "{decision:?}");
    }

    #[tokio::test]
    async fn every_statement_that_errs_at_evaluation_is_named_whatever_the_store_order() {
        let documents = |name: &str| -> (String, String) {
            let effect = if name == "A" { "Deny" } else { "Allow" };
            (
                name.to_string(),
                document_json(&[statement_json(
                    &format!("Sid{name}"),
                    effect,
                    Some(FROM_THE_OFFICE),
                )]),
            )
        };
        let mut errors = Vec::new();
        for order in [["A", "B"], ["B", "A"]] {
            let ctx = alice_from(Some("not-an-ip"));
            let policies: Vec<(String, String)> = order.iter().map(|n| documents(n)).collect();
            let policies: Vec<(&str, String)> = policies
                .iter()
                .map(|(n, d)| (n.as_str(), d.clone()))
                .collect();
            let store = alice_with_policies(&ctx, &policies).await;
            errors.push(decide(store, &ctx, "iam:GetUser").await.unwrap_err());
        }
        assert_eq!(errors[0].to_string(), errors[1].to_string());
        let AmiError::UnreadableCondition {
            policy, statement, ..
        } = &errors[0]
        else {
            panic!("expected UnreadableCondition, got {:?}", errors[0]);
        };
        assert_eq!(policy, "user inline policy A; user inline policy B");
        assert_eq!(statement, "SidA; SidB");
    }
}
