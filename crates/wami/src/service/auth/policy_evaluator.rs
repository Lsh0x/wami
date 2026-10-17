//! Canonical Policy Evaluator
//!
//! The evaluator `AuthorizationService` decides with. It is not yet the only
//! one: `EvaluationService` (simulate-custom-policy / simulate-principal-policy)
//! still walks statements with its own copy of this logic — two evaluators
//! until wami 003 puts the simulation on this one. Until then, what one does
//! with a condition the other must do too, and a test holds them to it
//! (`the_simulation_and_the_authorizer_agree_on_an_unreadable_condition`).
//!
//! # Evaluation Rules
//!
//! 1. **Deny overrides Allow**: an explicit Deny from ANY statement wins
//! 2. **Conditions narrow applicability — unreadable is not false**: a FALSE
//!    condition (well-formed, not met) means NoMatch, not Deny, as in AWS; a
//!    condition that cannot be READ refuses the decision, naming the policy
//!    and the statement ([`AmiError::UnreadablePolicy`] at parse,
//!    [`AmiError::UnreadableCondition`] at evaluation)
//! 3. **Read everything before deciding**: every statement whose action and
//!    resource match has its condition read before any verdict, so a `Deny`
//!    that holds does not excuse a broken statement beside it
//! 4. **Glob matching**: `*` = single segment, `**` = multi-segment
//! 5. **Variable substitution**: `${tenant}`, `${principal}`, `${service}` from context

use wami_condition::{
    evaluate_condition_block, evaluator::parse_condition_block, ConditionContext, ConditionError,
};
use wami_core::arn::matching::{glob_match, matches_arn_pattern, MatchContext};
use wami_core::arn::WamiArn;
use wami_core::context::WamiContext;
use wami_core::error::{AmiError, Result};
use wami_core::types::{PolicyDocument, PolicyStatement};

use super::decision::PolicySource;

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

/// The statement that decided a document, and what it decided.
///
/// One per document, not one per matching statement: every statement whose
/// action and resource match is read (wami 001), and the first Deny that
/// holds — else the first Allow — is kept, so a document has exactly one
/// decisive statement or none at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatementHit {
    /// What the statement decided — never `NoMatch`.
    pub effect: PolicyEffect,
    /// The statement's `Sid`, if it has one.
    pub sid: Option<String>,
    /// Its position in the document.
    pub index: usize,
}

/// Evaluate a single policy document against an action and resource.
///
/// Returns the statement that decided, or `None` when the document does not
/// apply. Which statement decided is what lets a caller write an audit line
/// naming it — the effect alone cannot be traced back to anything.
///
/// Every statement whose action and resource match has its condition read
/// BEFORE any verdict: a Deny that holds does not excuse a statement beside it
/// whose condition cannot be read, whatever its effect (wami 001, read
/// everything before deciding). Only then does a Deny win over an Allow.
///
/// `source` names the document in an error: it is what an operator needs to
/// find the policy to fix.
///
/// # Errors
///
/// [`AmiError::UnreadableCondition`] when a statement whose action and
/// resource match carries a condition that cannot be evaluated — every such
/// statement named, in document order. The decision is refused rather than
/// guessed: that statement might have been a Deny.
pub fn evaluate_policy_document(
    policy: &PolicyDocument,
    action: &str,
    resource_arn: &WamiArn,
    context: &WamiContext,
    source: &PolicySource,
) -> Result<Option<StatementHit>> {
    let resource_str = resource_arn.to_string();
    let match_ctx = MatchContext {
        tenant: Some(context.tenant_path().as_string()),
        principal: Some(context.caller_arn().resource.resource_id.clone()),
        service: Some(context.caller_arn().service.to_string()),
    };
    let cond_ctx = build_condition_context(context, resource_arn);

    // The condition is read only once action and resource match, as the
    // design orders it: a statement about something else cannot decide.
    let mut applying = Vec::new();
    let mut unreadable = Vec::new();
    for (index, statement) in policy.statement.iter().enumerate() {
        if !(matches_action(&statement.action, action)
            && matches_resource(&statement.resource, &resource_str, &match_ctx))
        {
            continue;
        }
        match matches_condition(statement, index, &cond_ctx, source) {
            Ok(true) => applying.push((index, statement)),
            Ok(false) => {}
            Err(e) => unreadable.push(e),
        }
    }
    if let Some(error) = combine(unreadable) {
        return Err(error);
    }

    let hit = |effect: PolicyEffect| {
        applying
            .iter()
            .find(|(_, statement)| effect_of(statement) == Some(effect))
            .map(|(index, statement)| StatementHit {
                effect,
                sid: statement.sid.clone(),
                index: *index,
            })
    };
    // Explicit denies first — a deny anywhere in the document wins over an
    // allow later in it.
    Ok(hit(PolicyEffect::Deny).or_else(|| hit(PolicyEffect::Allow)))
}

/// A statement's effect, read as the authorizer has always read it: `Allow`
/// or `Deny`, in any case. Anything else is refused at parse
/// ([`parse_policy_doc`]), so `None` here means a document that bypassed it.
pub(crate) fn effect_of(statement: &PolicyStatement) -> Option<PolicyEffect> {
    if statement.effect.eq_ignore_ascii_case("deny") {
        Some(PolicyEffect::Deny)
    } else if statement.effect.eq_ignore_ascii_case("allow") {
        Some(PolicyEffect::Allow)
    } else {
        None
    }
}

/// One error naming every unreadable item, or `None` when there is none.
///
/// Every item is named rather than the first, so an operator fixes them all in
/// one pass and two identical requests name the same documents whatever order
/// a store returned them in — the caller hands them in reading order
/// ([`in_reading_order`]). Each field lists the items' values in order,
/// joined by `"; "`.
///
/// The variant is chosen from what the items are, never from the first: all
/// `UnreadableCondition` stay one; anything else unreadable becomes one
/// `UnreadablePolicy` whose message names every statement. An error that is
/// no unreadable item is never folded into one — it is returned as it is
/// (the match lists every variant, so a new one cannot be erased silently).
pub(crate) fn combine(errors: Vec<AmiError>) -> Option<AmiError> {
    let mut items = Vec::new();
    for error in errors {
        match error {
            AmiError::UnreadablePolicy { policy, message } => items.push((policy, None, message)),
            AmiError::UnreadableCondition {
                policy,
                statement,
                message,
            } => items.push((policy, Some(statement), message)),
            other @ (AmiError::Provider { .. }
            | AmiError::Serialization(_)
            | AmiError::InvalidParameter { .. }
            | AmiError::OperationNotSupported { .. }
            | AmiError::ResourceNotFound { .. }
            | AmiError::PermissionDenied { .. }
            | AmiError::AccessDenied { .. }
            | AmiError::ResourceLimitExceeded { .. }
            | AmiError::ResourceExists { .. }
            | AmiError::StoreError(_)) => return Some(other),
        }
    }
    let join = |parts: Vec<&str>| parts.join("; ");
    let policy = join(items.iter().map(|(policy, _, _)| policy.as_str()).collect());
    match items.as_slice() {
        [] => None,
        _ if items.iter().all(|(_, statement, _)| statement.is_some()) => {
            Some(AmiError::UnreadableCondition {
                policy,
                statement: join(
                    items
                        .iter()
                        .filter_map(|(_, statement, _)| statement.as_deref())
                        .collect(),
                ),
                message: join(
                    items
                        .iter()
                        .map(|(_, _, message)| message.as_str())
                        .collect(),
                ),
            })
        }
        _ => Some(AmiError::UnreadablePolicy {
            policy,
            message: items
                .iter()
                .map(|(_, statement, message)| match statement {
                    Some(statement) => format!("statement {statement}: {message}"),
                    None => message.clone(),
                })
                .collect::<Vec<_>>()
                .join("; "),
        }),
    }
}

/// The order both doors read documents in, and name them in: the identity
/// documents sorted by their key, then the permissions boundary, LAST, whatever
/// its key would sort as. One function for both doors, so the authorizer and
/// the simulation cannot name the same broken documents in two orders.
pub(crate) fn in_reading_order<K: Ord, D>(
    mut identity: Vec<(K, D)>,
    boundary: Option<(K, D)>,
) -> Vec<(K, D)> {
    identity.sort_by(|(a, _), (b, _)| a.cmp(b));
    identity.extend(boundary);
    identity
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
/// `Ok(true)` when the statement has no condition or its condition holds;
/// `Ok(false)` when the condition is well-formed and not met — AWS semantics,
/// a key absent from the request included: the statement does not apply.
///
/// `index` and `source` locate the statement for the error, so an operator
/// learns which policy and which statement to fix.
///
/// # Errors
///
/// [`AmiError::UnreadableCondition`] when the condition cannot be parsed or
/// evaluated. This used to be `false`, so the statement vanished — for a
/// `Deny`, a fail-open. A document read through [`parse_policy_doc`] has had
/// every condition parsed already; what still errs here is the request side
/// (a context value the operator cannot compare) or a document built without
/// going through it.
pub fn matches_condition(
    statement: &PolicyStatement,
    index: usize,
    cond_ctx: &ConditionContext,
    source: &PolicySource,
) -> Result<bool> {
    let condition_value = match &statement.condition {
        Some(v) if !v.is_null() => v,
        _ => return Ok(true), // No condition → always matches
    };

    parse_condition_block(condition_value)
        .and_then(|block| evaluate_condition_block(&block, cond_ctx))
        .map_err(|e| unreadable_condition(&source.to_string(), statement, index, &e))
}

/// How a statement is named in an error: its `Sid`, else `#` and its index.
pub(crate) fn statement_name(statement: &PolicyStatement, index: usize) -> String {
    statement.sid.clone().unwrap_or_else(|| format!("#{index}"))
}

/// The error for a condition that could not be evaluated.
///
/// Shared with the simulation's evaluator (`EvaluationService`, until
/// wami 003), which must answer with the very same error the authorizer does.
pub(crate) fn unreadable_condition(
    policy: &str,
    statement: &PolicyStatement,
    index: usize,
    error: &ConditionError,
) -> AmiError {
    AmiError::UnreadableCondition {
        policy: policy.to_string(),
        statement: statement_name(statement, index),
        message: error.to_string(),
    }
}

/// Refuse a document one of whose statements cannot be read — an `Effect`
/// that is neither `Allow` nor `Deny`, or a condition that cannot be (an
/// unknown operator, an operator its key's type rules out, a value its
/// operator cannot compare).
///
/// Run on every document [`parse_policy_doc`] returns, so the refusal is
/// deterministic: it does not wait for a request whose action happens to
/// reach the broken statement. Shared with the simulation, which parses its
/// documents itself (wami 003).
///
/// # Errors
///
/// [`AmiError::UnreadablePolicy`], `message` naming every broken statement in
/// document order.
pub(crate) fn check_statements(document: &PolicyDocument, policy: &str) -> Result<()> {
    let mut broken = Vec::new();
    for (index, statement) in document.statement.iter().enumerate() {
        let name = statement_name(statement, index);
        // A misspelt "Dney" used to be neither effect: the statement vanished.
        if effect_of(statement).is_none() {
            broken.push(format!("statement {name}: Effect must be Allow or Deny"));
        }
        if let Some(condition) = statement.condition.as_ref().filter(|c| !c.is_null()) {
            if let Err(e) = parse_condition_block(condition) {
                broken.push(format!("statement {name}: {e}"));
            }
        }
    }
    if broken.is_empty() {
        Ok(())
    } else {
        Err(AmiError::UnreadablePolicy {
            policy: policy.to_string(),
            message: broken.join("; "),
        })
    }
}

/// Parse a policy document, refusing to guess when it cannot be read.
///
/// This used to swallow the error and hand back an empty document. For an
/// `Allow` that was merely useless; for a `Deny` it was a fail-open — the
/// statement meant to block the action stopped existing, and any `Allow` from
/// another source won. One typo was enough:
///
/// ```text
/// {"Effect":"Deny","Actions":["iam:*"],"Resource":["*"]}
///                   ^ plural — valid JSON, not a PolicyStatement
/// ```
///
/// Refusing to decide is the only safe answer: a document that cannot be read
/// might have contained a deny, and there is no way to know.
///
/// The same story held one level down, for conditions. A statement's
/// `Condition` that could not be read — `StringEqualz` for `StringEquals`, an
/// `IpAddress` that is no address — was answered as a false condition, so the
/// statement vanished and the Deny with it — and so did a statement whose
/// `Effect` was misspelt. Every statement is therefore checked here too, and a
/// broken one refuses the document with the statement named, whatever the
/// action asked.
///
/// # Errors
///
/// [`AmiError::UnreadablePolicy`] when the JSON is not a policy document, or
/// when one of its statements has an effect or a condition that cannot be
/// read.
pub fn parse_policy_doc(json: &str, policy: &PolicySource) -> Result<PolicyDocument> {
    read_policy_document(json, &policy.to_string())
}

/// [`parse_policy_doc`] for a document with no [`PolicySource`] yet — one being
/// WRITTEN (a managed policy at creation). The write paths call this, so a
/// document is refused at write for exactly what the read refuses: one parser,
/// two names (wami 001).
///
/// # Errors
///
/// As [`parse_policy_doc`].
pub(crate) fn read_policy_document(json: &str, policy: &str) -> Result<PolicyDocument> {
    let document = decode_policy_document(json, policy)?;
    check_statements(&document, policy)?;
    Ok(document)
}

/// JSON into a [`PolicyDocument`] — the one place the auth and policies
/// services do it (a test counts them).
///
/// serde's message quotes the value it choked on — policy text nobody checked
/// (`invalid type: string "…"`) — so the error says WHERE instead, from serde's
/// line and column, never serde's text.
///
/// # Errors
///
/// [`AmiError::UnreadablePolicy`] naming `policy` and the position.
pub(crate) fn decode_policy_document(json: &str, policy: &str) -> Result<PolicyDocument> {
    serde_json::from_str(json).map_err(|e| AmiError::UnreadablePolicy {
        policy: policy.to_string(),
        message: format!(
            "cannot be read as a policy document at line {} column {}",
            e.line(),
            e.column()
        ),
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
                sid: None,
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
            sid: None,
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
        assert!(matches_condition(&stmt, 0, &cond_ctx, &a_policy()).unwrap());
    }

    #[test]
    fn matches_condition_null_condition() {
        let stmt = make_statement("Allow", &["iam:*"], &["*"], Some(serde_json::Value::Null));
        let cond_ctx = ConditionContext::builder().build();
        assert!(matches_condition(&stmt, 0, &cond_ctx, &a_policy()).unwrap());
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
        // Unreadable is not false (wami 001): it used to be `false`.
        let err = matches_condition(&stmt, 0, &cond_ctx, &a_policy()).unwrap_err();
        assert!(
            matches!(err, AmiError::UnreadableCondition { .. }),
            "{err:?}"
        );
    }

    // ─── parse_policy_doc ─────────────────────────────────────

    fn a_policy() -> PolicySource {
        PolicySource::UserInline {
            name: "p".to_string(),
        }
    }

    #[test]
    fn parse_policy_doc_valid() {
        let json = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:GetUser"],"Resource":["*"]}]}"#;
        let doc = parse_policy_doc(json, &a_policy()).unwrap();
        assert_eq!(doc.statement.len(), 1);
        assert_eq!(doc.statement[0].effect, "Allow");
    }

    #[test]
    fn a_sid_survives_a_round_trip() {
        let json = r#"{"Version":"2012-10-17","Statement":[{"Sid":"AllowReads","Effect":"Allow","Action":["iam:GetUser"],"Resource":["*"]}]}"#;
        let doc = parse_policy_doc(json, &a_policy()).unwrap();
        assert_eq!(doc.statement[0].sid.as_deref(), Some("AllowReads"));
        // Documents without a Sid must not gain an empty one when written back.
        let plain = parse_policy_doc(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["a"],"Resource":["*"]}]}"#,
            &a_policy(),
        )
        .unwrap();
        assert!(!serde_json::to_string(&plain).unwrap().contains("Sid"));
    }

    #[test]
    fn an_unreadable_policy_refuses_to_parse_instead_of_returning_nothing() {
        // The whole of #120: this used to yield an empty document, so a Deny
        // written with a typo simply stopped existing and any Allow elsewhere
        // won. Now it cannot be mistaken for a policy that permits nothing.
        for bad in ["not json at all", "", r#"{"Version":"2012-10-17"}"#] {
            let err = parse_policy_doc(bad, &a_policy()).unwrap_err();
            assert!(
                matches!(err, AmiError::UnreadablePolicy { .. }),
                "{bad:?} gave {err:?}"
            );
        }
    }

    #[test]
    fn a_deny_with_a_typo_no_longer_vanishes() {
        // Valid JSON, so it passes a `serde_json::Value` check, but not a
        // PolicyStatement: "Actions" instead of "Action". One character.
        let typo = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Actions":["iam:*"],"Resource":["*"]}]}"#;
        assert!(serde_json::from_str::<serde_json::Value>(typo).is_ok());

        let err = parse_policy_doc(typo, &a_policy()).unwrap_err();
        assert!(matches!(err, AmiError::UnreadablePolicy { .. }));
        // And the operator is told which policy to go fix.
        assert!(err.to_string().contains("user inline policy p"));
    }

    // ─── evaluate_policy_document ─────────────────────────────

    #[test]
    fn evaluate_allow_policy() {
        let ctx = make_context();
        let policy = make_policy("Allow", &["iam:GetUser"], &["*"]);
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();
        assert_eq!(
            evaluate_policy_document(&policy, "iam:GetUser", &resource, &ctx, &a_policy())
                .unwrap()
                .map(|hit| hit.effect),
            Some(PolicyEffect::Allow)
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
            evaluate_policy_document(&policy, "iam:DeleteUser", &resource, &ctx, &a_policy())
                .unwrap()
                .map(|hit| hit.effect),
            Some(PolicyEffect::Deny)
        );
    }

    #[test]
    fn evaluate_no_match() {
        let ctx = make_context();
        let policy = make_policy("Allow", &["sts:AssumeRole"], &["*"]);
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();
        assert!(
            evaluate_policy_document(&policy, "iam:GetUser", &resource, &ctx, &a_policy())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn evaluate_deny_only() {
        let ctx = make_context();
        let policy = make_policy("Deny", &["iam:*"], &["*"]);
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();
        assert_eq!(
            evaluate_policy_document(&policy, "iam:GetUser", &resource, &ctx, &a_policy())
                .unwrap()
                .map(|hit| hit.effect),
            Some(PolicyEffect::Deny)
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
        assert!(
            evaluate_policy_document(&policy, "iam:GetUser", &resource, &ctx, &a_policy())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn evaluate_wildcard_action_and_resource() {
        let ctx = make_context();
        let policy = make_policy("Allow", &["*"], &["*"]);
        let resource: WamiArn = "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap();
        assert_eq!(
            evaluate_policy_document(&policy, "anything:Here", &resource, &ctx, &a_policy())
                .unwrap()
                .map(|hit| hit.effect),
            Some(PolicyEffect::Allow)
        );
    }

    // ─── wami 001: unreadable is not false ────────────────────

    fn bob() -> WamiArn {
        "arn:wami:iam:12345678:wami:999:user/bob".parse().unwrap()
    }

    /// An Allow on `iam:*` and a Deny `BlockAll` on `iam:*` carrying `cond`,
    /// built by hand — as a document from a store that bypassed
    /// [`parse_policy_doc`] would reach evaluation.
    fn allow_and_deny_when(cond: serde_json::Value) -> PolicyDocument {
        let mut deny = make_statement("Deny", &["iam:*"], &["*"], Some(cond));
        deny.sid = Some("BlockAll".to_string());
        PolicyDocument {
            version: "2012-10-17".to_string(),
            statement: vec![make_statement("Allow", &["iam:*"], &["*"], None), deny],
        }
    }

    #[test]
    fn a_deny_with_an_unknown_operator_is_refused_at_parse_with_the_statement_named() {
        let named = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:*"],"Resource":["*"]},{"Sid":"BlockAll","Effect":"Deny","Action":["iam:*"],"Resource":["*"],"Condition":{"StringEqualz":{"aws:username":"alice"}}}]}"#;
        let err = parse_policy_doc(named, &a_policy()).unwrap_err();
        assert!(matches!(err, AmiError::UnreadablePolicy { .. }), "{err:?}");
        let message = err.to_string();
        assert!(message.contains("user inline policy p"), "{message}");
        assert!(message.contains("statement BlockAll"), "{message}");

        // Without a Sid, the statement is named by its index.
        let anonymous = named.replace(r#""Sid":"BlockAll","#, "");
        let message = parse_policy_doc(&anonymous, &a_policy())
            .unwrap_err()
            .to_string();
        assert!(message.contains("statement #1"), "{message}");
    }

    #[test]
    fn a_deny_with_an_unknown_operator_refuses_the_evaluation() {
        // The bug itself: this answered `Some(Allow)` — the Deny's condition
        // read as false, the Deny vanished, the Allow won.
        let policy =
            allow_and_deny_when(serde_json::json!({"StringEqualz": {"aws:username": "alice"}}));
        let err =
            evaluate_policy_document(&policy, "iam:GetUser", &bob(), &make_context(), &a_policy())
                .unwrap_err();
        let AmiError::UnreadableCondition {
            policy, statement, ..
        } = &err
        else {
            panic!("expected UnreadableCondition, got {err:?}");
        };
        assert_eq!(policy, "user inline policy p");
        assert_eq!(statement, "BlockAll");
    }

    #[test]
    fn a_deny_whose_condition_is_false_lets_the_allow_through() {
        // The regression guard: a FALSE condition is NoMatch, as in AWS. A
        // Deny "for mallory" does not apply to alice.
        let policy =
            allow_and_deny_when(serde_json::json!({"StringEquals": {"aws:username": "mallory"}}));
        let effect =
            evaluate_policy_document(&policy, "iam:GetUser", &bob(), &make_context(), &a_policy())
                .unwrap()
                .map(|hit| hit.effect);
        assert_eq!(effect, Some(PolicyEffect::Allow));
    }

    #[test]
    fn an_unreadable_condition_on_a_lone_allow_is_an_error_not_a_silent_none() {
        // Not a deny this time, and still not a quiet "nothing applies": the
        // operator must learn the policy is broken.
        let mut allow = make_statement(
            "Allow",
            &["iam:*"],
            &["*"],
            Some(serde_json::json!({"Bool": {"aws:SecureTransport": "yes"}})),
        );
        allow.sid = Some("Reads".to_string());
        let policy = PolicyDocument {
            version: "2012-10-17".to_string(),
            statement: vec![allow],
        };
        let err =
            evaluate_policy_document(&policy, "iam:GetUser", &bob(), &make_context(), &a_policy())
                .unwrap_err();
        assert!(
            matches!(err, AmiError::UnreadableCondition { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn a_context_value_the_condition_cannot_compare_is_an_error_at_evaluation() {
        // Parses — a network on an address key — but the request's source
        // address is no address. This is the error parse cannot catch, since
        // it depends on the request.
        let json = r#"{"Version":"2012-10-17","Statement":[{"Sid":"Few","Effect":"Allow","Action":["iam:*"],"Resource":["*"],"Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}}]}"#;
        let policy = parse_policy_doc(json, &a_policy()).unwrap();
        let arn: WamiArn = "arn:wami:iam:12345678:wami:999:user/alice".parse().unwrap();
        let from_nowhere = WamiContext::builder()
            .instance_id("999")
            .tenant_path(TenantPath::single(12345678))
            .caller_arn(arn)
            .is_root(false)
            .source_ip("not-an-ip")
            .build()
            .unwrap();
        let err =
            evaluate_policy_document(&policy, "iam:GetUser", &bob(), &from_nowhere, &a_policy())
                .unwrap_err();
        assert!(
            matches!(err, AmiError::UnreadableCondition { .. }),
            "{err:?}"
        );
        assert!(err.to_string().contains("statement Few"), "{err}");
    }

    #[test]
    fn a_missing_context_key_is_a_false_condition() {
        // As read in wami-condition: `get_context_value` has no error path, an
        // absent key reaches the operator as `None`, and `StringEquals` on
        // `None` is false. So a Deny keyed on the source IP does not apply to
        // a request that carries none — AWS semantics.
        let policy =
            allow_and_deny_when(serde_json::json!({"IpAddress": {"aws:SourceIp": "10.0.0.1"}}));
        let effect =
            evaluate_policy_document(&policy, "iam:GetUser", &bob(), &make_context(), &a_policy())
                .unwrap()
                .map(|hit| hit.effect);
        assert_eq!(effect, Some(PolicyEffect::Allow));
        assert!(!matches_condition(
            &policy.statement[1],
            1,
            &ConditionContext::builder().build(),
            &a_policy()
        )
        .unwrap());
    }

    #[test]
    fn a_statement_about_another_action_is_not_read_for_its_condition() {
        // Action and resource are checked before the condition, as the design
        // orders it: a broken statement that cannot decide this request does
        // not refuse it. (`parse_policy_doc` refuses the document anyway.)
        let mut deny = make_statement(
            "Deny",
            &["s3:*"],
            &["*"],
            Some(serde_json::json!({"StringEqualz": {"aws:username": "alice"}})),
        );
        deny.sid = Some("Elsewhere".to_string());
        let policy = PolicyDocument {
            version: "2012-10-17".to_string(),
            statement: vec![make_statement("Allow", &["iam:*"], &["*"], None), deny],
        };
        let effect =
            evaluate_policy_document(&policy, "iam:GetUser", &bob(), &make_context(), &a_policy())
                .unwrap()
                .map(|hit| hit.effect);
        assert_eq!(effect, Some(PolicyEffect::Allow));
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

    // ─── wami 001, review round 2 ────────────────────────────

    #[test]
    fn a_document_that_is_no_policy_is_refused_without_quoting_it() {
        // serde's message quotes the value it choked on — policy text nobody
        // checked. The error says where instead.
        for json in [
            r#"{"Version":"x","Statement":"s3cr3t-statement"}"#,
            r#"{"Version":"x","Statement":[{"Effect":"Allow","Action":{"k":"s3cr3t"},"Resource":"*"}]}"#,
            r#"{"Version":"x","Statement":[{"Effect":"Allow","Action":["iam:*"],"Resource":["*"],"Sid":51234}]}"#,
            r#"{"Version":"x","Statement":[{"Effect":"Allow","Actions":["s3cr3t"],"Resource":["*"]}]}"#,
        ] {
            let message = parse_policy_doc(json, &a_policy()).unwrap_err().to_string();
            assert!(!message.contains("s3cr3t"), "{message}");
            assert!(!message.contains("51234"), "{message}");
            assert!(
                message.contains("cannot be read as a policy document at line 1 column"),
                "{message}"
            );
        }
    }

    #[test]
    fn combining_keeps_an_error_that_is_no_unreadable_item() {
        // Erasing it into an UnreadablePolicy with empty fields would hide it.
        let err = combine(vec![
            AmiError::UnreadablePolicy {
                policy: "A".to_string(),
                message: "statement S1: broken".to_string(),
            },
            AmiError::AccessDenied {
                message: "store said no".to_string(),
            },
        ])
        .unwrap();
        assert!(matches!(err, AmiError::AccessDenied { .. }), "{err:?}");
    }

    #[test]
    fn combining_both_kinds_names_every_statement() {
        let err = combine(vec![
            AmiError::UnreadablePolicy {
                policy: "A".to_string(),
                message: "statement S1: broken".to_string(),
            },
            AmiError::UnreadableCondition {
                policy: "B".to_string(),
                statement: "S2".to_string(),
                message: "cannot compare".to_string(),
            },
        ])
        .unwrap();
        assert!(matches!(err, AmiError::UnreadablePolicy { .. }), "{err:?}");
        let message = err.to_string();
        for part in ["A", "S1", "B", "statement S2", "cannot compare"] {
            assert!(message.contains(part), "{part}: {message}");
        }
    }

    #[test]
    fn the_reading_order_puts_the_boundary_last_whatever_its_key() {
        // Both doors read through this function; the boundary is last even
        // when its key would sort first, so no derive decides it.
        let order = in_reading_order(
            vec![(3, "group"), (1, "user"), (2, "role")],
            Some((0, "boundary")),
        );
        assert_eq!(
            order.iter().map(|(_, d)| *d).collect::<Vec<_>>(),
            ["user", "role", "group", "boundary"]
        );
    }
}
