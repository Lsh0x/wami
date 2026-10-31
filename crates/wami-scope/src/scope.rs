//! The scope: policies folded into allow and deny patterns for one action,
//! and the fence a service puts around a request.

use wami_core::arn::matching::{glob_match, resolve_variables, MatchContext};
use wami_core::types::{PolicyDocument, PolicyStatement};

use crate::Pattern;

/// What a principal's policies let a query reach for one action.
///
/// Built by [`Scope::compile`]; read by a translator ([`Scope::allow`],
/// [`Scope::deny`], [`Scope::prefixes`]) and by the re-check
/// ([`Scope::matches`]). Patterns are resolved: `${tenant}` and the others
/// already hold the caller's values.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Scope {
    /// The patterns an `Allow` statement for the action names. Empty: the
    /// principal reaches nothing.
    pub allow: Vec<Pattern>,
    /// The patterns a `Deny` statement for the action names: a row they match
    /// is out, whatever `allow` says.
    pub deny: Vec<Pattern>,
    /// A statement that applied to the action could not be folded (it carries
    /// a condition, whose truth depends on the request): the scope
    /// over-includes, and the re-check does real work.
    pub residual: bool,
    /// The action the scope was compiled for (`s3:GetObject`): its service is
    /// the service axis of [`Scope::fenced`].
    pub action: String,
    /// The fence, when the scope is fenced ([`Scope::fenced`]): exact patterns
    /// a row must also match — one tenant root and its descendants each, in
    /// the action's service. Empty: no fence.
    pub fence: Vec<Pattern>,
}

/// Why policies could not be compiled.
///
/// Refused, never guessed: a statement whose effect cannot be read might have
/// been a `Deny` (the evaluator refuses the same document, wami 001).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScopeError {
    /// A statement's `Effect` is neither `Allow` nor `Deny`.
    #[error(
        "document {document}, statement {statement}: Effect must be Allow or Deny, not {effect:?}"
    )]
    UnreadableEffect {
        /// The document's position in the slice given.
        document: usize,
        /// The statement's `Sid`, else `#` and its position.
        statement: String,
        /// What it says instead.
        effect: String,
    },
}

/// A statement's effect, read as the evaluator reads it: either word, in any
/// case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Effect {
    Allow,
    Deny,
}

fn effect_of(statement: &PolicyStatement) -> Option<Effect> {
    if statement.effect.eq_ignore_ascii_case("allow") {
        Some(Effect::Allow)
    } else if statement.effect.eq_ignore_ascii_case("deny") {
        Some(Effect::Deny)
    } else {
        None
    }
}

/// Whether the statement's actions reach `action`: the evaluator's glob
/// (`atlas:*`, `atlas:Read*`, `*`).
fn applies_to(statement: &PolicyStatement, action: &str) -> bool {
    statement.action.iter().any(|a| glob_match(a, action))
}

fn has_condition(statement: &PolicyStatement) -> bool {
    statement.condition.as_ref().is_some_and(|c| !c.is_null())
}

impl Scope {
    /// Fold `policies` for `action`: every statement whose actions reach it
    /// contributes its resources, resolved with `ctx`, to `allow` or `deny`
    /// by its effect.
    ///
    /// A conditioned `Allow` is kept and a conditioned `Deny` dropped, both
    /// setting [`Scope::residual`]: the scope over-includes, never excludes
    /// (the invariant every translator is held to).
    ///
    /// # Errors
    ///
    /// [`ScopeError::UnreadableEffect`] for a statement whose effect is
    /// neither `Allow` nor `Deny`, whether or not it reaches `action`: the
    /// evaluator refuses the whole document, so does the scope.
    pub fn compile(
        policies: &[PolicyDocument],
        action: &str,
        ctx: &MatchContext,
    ) -> Result<Self, ScopeError> {
        let mut scope = Self {
            action: action.to_string(),
            ..Self::default()
        };
        for (document, policy) in policies.iter().enumerate() {
            for (index, statement) in policy.statement.iter().enumerate() {
                let effect = effect_of(statement).ok_or_else(|| ScopeError::UnreadableEffect {
                    document,
                    statement: statement.sid.clone().unwrap_or_else(|| format!("#{index}")),
                    effect: statement.effect.clone(),
                })?;
                if applies_to(statement, action) {
                    scope.fold(statement, effect, ctx);
                }
            }
        }
        scope.allow.sort();
        scope.allow.dedup();
        scope.deny.sort();
        scope.deny.dedup();
        Ok(scope)
    }

    fn fold(&mut self, statement: &PolicyStatement, effect: Effect, ctx: &MatchContext) {
        let conditioned = has_condition(statement);
        if conditioned {
            self.residual = true;
        }
        let into = match (effect, conditioned) {
            (Effect::Allow, _) => &mut self.allow,
            (Effect::Deny, false) => &mut self.deny,
            // A Deny that may not hold cannot be pushed down: pushing it would
            // exclude a row the evaluator allows when its condition is false.
            (Effect::Deny, true) => return,
        };
        into.extend(
            statement
                .resource
                .iter()
                .map(|motif| Pattern::resolved(resolve_variables(motif, ctx))),
        );
    }

    /// The service of the action the scope was compiled for: `s3` for
    /// `s3:GetObject`, the whole action when it names no service.
    #[must_use]
    pub fn service(&self) -> &str {
        self.action.split(':').next().unwrap_or_default()
    }

    /// The scope fenced to `tenants` — each a tenant root (`100`, `100/7`):
    /// a row must be of the action's service and of one of those tenants or
    /// its descendants, whatever the policies name. The fence is what the
    /// services' `decide` already refuses before any document (an ARN of
    /// another workspace) and the public space they open; it is theirs to
    /// give per request, never the library's to assume (an assumption judged
    /// by wami's own STS gets none).
    ///
    /// The fence is a conjunction of exact patterns (`arn:wami:<svc>:<t>:wami:*:**`
    /// and `arn:wami:<svc>:<t>/**`): [`Scope::matches`] requires one and
    /// [`Scope::lower`] ands them, so a store narrows on them exactly. An
    /// allow pattern whose literal service or tenant contradicts the fence is
    /// dropped, so the lowering stays tight; denies and `residual` are kept.
    /// A fenced scope **may exclude** what the bare evaluator allows: its
    /// oracle is the evaluator and the fence.
    #[must_use]
    pub fn fenced(&self, tenants: &[&str]) -> Self {
        if tenants.is_empty() {
            return self.clone();
        }
        let service = self.service().to_string();
        let within = |tenant: &str| {
            tenants
                .iter()
                .any(|root| tenant == *root || tenant.starts_with(&format!("{root}/")))
        };
        let allow = self
            .allow
            .iter()
            .filter(|pattern| {
                let parts: Vec<&str> = pattern.as_str().split(':').collect();
                if parts.len() < 6 || parts[0] != "arn" || parts[1] != "wami" {
                    return true;
                }
                let literal = |part: &str| !part.contains('*') && !part.contains("${");
                (!literal(parts[2]) || parts[2] == service)
                    && (!literal(parts[3]) || within(parts[3]))
            })
            .cloned()
            .collect();
        let fence = tenants
            .iter()
            .flat_map(|root| {
                [
                    Pattern::resolved(format!("arn:wami:{service}:{root}:wami:*:**")),
                    Pattern::resolved(format!("arn:wami:{service}:{root}/**")),
                ]
            })
            .collect();
        Self {
            allow,
            deny: self.deny.clone(),
            residual: self.residual,
            action: self.action.clone(),
            fence,
        }
    }

    /// Whether `arn` is in the scope: some allow pattern matches it, the
    /// fence (when there is one) does, and no deny pattern does — the
    /// evaluator's verdict when nothing is residual and nothing is fenced, a
    /// superset of it otherwise. The re-check a store's rows go through.
    ///
    /// `arn` is the row's text, judged as it is: the evaluator judges the
    /// ARN as `WamiArn` displays it once parsed, so the two agree on rows
    /// written that way (`…:100:…`, never `…:0100:…`) — what a store that
    /// writes ARNs through `WamiArn` holds, and the harness checks.
    #[must_use]
    pub fn matches(&self, arn: &str) -> bool {
        self.allow.iter().any(|p| p.matches(arn))
            && (self.fence.is_empty() || self.fence.iter().any(|p| p.matches(arn)))
            && !self.deny.iter().any(|p| p.matches(arn))
    }

    /// The literal prefix of each allow pattern (see [`Pattern::prefix`]):
    /// what an index can narrow on before the re-check. Sorted, without
    /// repeats; an empty prefix means a pattern that reaches everything.
    #[must_use]
    pub fn prefixes(&self) -> Vec<&str> {
        let mut prefixes: Vec<&str> = self.allow.iter().map(Pattern::prefix).collect();
        prefixes.sort_unstable();
        prefixes.dedup();
        prefixes
    }

    /// Nothing granted: a store lists nothing, never everything.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.allow.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn statement(effect: &str, actions: &[&str], resources: &[&str]) -> PolicyStatement {
        PolicyStatement {
            sid: None,
            effect: effect.into(),
            action: actions.iter().map(ToString::to_string).collect(),
            resource: resources.iter().map(ToString::to_string).collect(),
            condition: None,
        }
    }

    fn document(statements: Vec<PolicyStatement>) -> PolicyDocument {
        PolicyDocument {
            version: "2012-10-17".into(),
            statement: statements,
        }
    }

    fn ctx(tenant: &str) -> MatchContext {
        MatchContext {
            tenant: Some(tenant.into()),
            principal: Some("alice".into()),
            service: Some("atlas".into()),
        }
    }

    #[test]
    fn variables_are_resolved_once_and_the_glob_is_the_evaluators() {
        let docs = [document(vec![statement(
            "allow",
            &["atlas:Read*"],
            &["arn:wami:${service}:${tenant}:wami:*:memo/${principal}/*"],
        )])];
        let scope = Scope::compile(&docs, "atlas:ReadMemo", &ctx("100")).unwrap();
        assert_eq!(
            scope.allow[0].as_str(),
            "arn:wami:atlas:100:wami:*:memo/alice/*"
        );
        assert!(scope.matches("arn:wami:atlas:100:wami:1:memo/alice/m1"));
        assert!(
            !scope.matches("arn:wami:atlas:100:wami:1:memo/alice/m1/x"),
            "* stays in its segment"
        );
        assert!(!scope.matches("arn:wami:atlas:100:wami:1:memo/bob/m1"));
        assert_eq!(scope.prefixes(), ["arn:wami:atlas:100:wami:"]);
    }

    #[test]
    fn a_statement_about_another_action_contributes_nothing() {
        let docs = [document(vec![
            statement(
                "Allow",
                &["atlas:Edit*"],
                &["arn:wami:atlas:100:wami:*:realm/**"],
            ),
            statement("Allow", &[], &["arn:wami:atlas:100:wami:*:key/**"]),
        ])];
        let scope = Scope::compile(&docs, "atlas:ReadItem", &ctx("100")).unwrap();
        assert!(scope.is_empty());
        assert!(!scope.matches("arn:wami:atlas:100:wami:1:realm/main"));
        assert_eq!(scope.prefixes().len(), 0);
    }

    #[test]
    fn a_missing_tenant_leaves_the_variable_and_the_pattern_matches_nothing() {
        let docs = [document(vec![statement(
            "Allow",
            &["*"],
            &["arn:wami:atlas:${tenant}:wami:*:realm/**"],
        )])];
        let scope = Scope::compile(&docs, "atlas:ReadItem", &MatchContext::default()).unwrap();
        assert_eq!(
            scope.allow[0].as_str(),
            "arn:wami:atlas:${tenant}:wami:*:realm/**"
        );
        assert!(!scope.matches("arn:wami:atlas:100:wami:1:realm/main"));
        assert!(
            !scope.is_empty(),
            "granted something — that matches nothing"
        );
    }

    #[test]
    fn a_conditioned_allow_is_kept_a_conditioned_deny_dropped_both_residual() {
        let condition = serde_json::json!({ "StringEquals": { "aws:username": "alice" } });
        let mut allow = statement(
            "Allow",
            &["atlas:ReadKey"],
            &["arn:wami:atlas:100:wami:*:key/**"],
        );
        allow.condition = Some(condition.clone());
        let mut deny = statement(
            "Deny",
            &["atlas:ReadKey"],
            &["arn:wami:atlas:100:wami:*:key/k1"],
        );
        deny.condition = Some(condition);
        let scope =
            Scope::compile(&[document(vec![allow, deny])], "atlas:ReadKey", &ctx("100")).unwrap();
        assert!(scope.residual);
        assert_eq!(scope.allow.len(), 1);
        assert_eq!(
            scope.deny.len(),
            0,
            "a Deny that may not hold is never pushed down"
        );
        assert!(
            scope.matches("arn:wami:atlas:100:wami:1:key/k1"),
            "over-included, the re-check decides"
        );

        let mut null = statement(
            "Deny",
            &["atlas:ReadKey"],
            &["arn:wami:atlas:100:wami:*:key/k2"],
        );
        null.condition = Some(serde_json::Value::Null);
        let scope = Scope::compile(&[document(vec![null])], "atlas:ReadKey", &ctx("100")).unwrap();
        assert!(!scope.residual, "a null condition is no condition");
        assert_eq!(scope.deny.len(), 1);
    }

    #[test]
    fn an_unreadable_effect_refuses_the_whole_compile() {
        let mut bad = statement("Dney", &["atlas:Edit*"], &["*"]);
        bad.sid = Some("Typo".into());
        let docs = [
            document(vec![statement("Allow", &["*"], &["*"])]),
            document(vec![statement("Allow", &["*"], &["*"]), bad]),
        ];
        assert_eq!(
            Scope::compile(&docs, "atlas:ReadItem", &ctx("100")),
            Err(ScopeError::UnreadableEffect {
                document: 1,
                statement: "Typo".into(),
                effect: "Dney".into(),
            }),
            "even though the statement is about another action"
        );
    }

    #[test]
    fn patterns_are_sorted_and_deduplicated() {
        let docs = [
            document(vec![statement(
                "Allow",
                &["*"],
                &[
                    "arn:wami:atlas:100:wami:*:b/**",
                    "arn:wami:atlas:100:wami:*:a/**",
                ],
            )]),
            document(vec![statement(
                "allow",
                &["atlas:*"],
                &["arn:wami:atlas:100:wami:*:a/**"],
            )]),
        ];
        let scope = Scope::compile(&docs, "atlas:ReadItem", &ctx("100")).unwrap();
        let texts: Vec<&str> = scope.allow.iter().map(Pattern::as_str).collect();
        assert_eq!(
            texts,
            [
                "arn:wami:atlas:100:wami:*:a/**",
                "arn:wami:atlas:100:wami:*:b/**"
            ]
        );
    }

    #[test]
    fn a_fence_is_the_tenant_and_its_descendants_in_the_actions_service() {
        let docs = [document(vec![statement(
            "Allow",
            &["s3:GetObject"],
            &[
                "arn:wami:s3:300:wami:*:bucket/mine/**",
                "arn:wami:s3:100:wami:*:bucket/atlas/**",
                "arn:wami:s3:*:wami:*:bucket/public-data/**",
                "arn:wami:*:300:wami:*:**",
                "*",
            ],
        )])];
        let erin = MatchContext {
            tenant: Some("300".into()),
            ..MatchContext::default()
        };
        let bare = Scope::compile(&docs, "s3:GetObject", &erin).unwrap();
        assert_eq!(bare.service(), "s3");
        assert!(bare.matches("arn:wami:s3:100:wami:1:bucket/atlas/conv/c1"));
        assert!(bare.matches("arn:wami:lambda:300:wami:1:function/f"));

        let fenced = bare.fenced(&["300", "1"]);
        assert_eq!(fenced.allow.len(), 4, "the literal tenant 100 is dropped");
        assert_eq!(fenced.fence.len(), 4);
        assert!(
            !fenced.matches("arn:wami:s3:100:wami:1:bucket/atlas/conv/c1"),
            "another tenant"
        );
        assert!(
            !fenced.matches("arn:wami:lambda:300:wami:1:function/f"),
            "another service"
        );
        assert!(fenced.matches("arn:wami:s3:300:wami:1:bucket/mine/x"));
        assert!(
            fenced.matches("arn:wami:s3:300/7:wami:1:bucket/mine/x"),
            "a descendant"
        );
        assert!(
            !fenced.matches("arn:wami:s3:3007:wami:1:bucket/mine/x"),
            "a lookalike"
        );
        assert!(
            fenced.matches("arn:wami:s3:1:wami:1:bucket/public-data/catalog.json"),
            "the public tenant given"
        );
        assert!(
            fenced.matches("arn:wami:s3:300:wami:1:anything/at/all"),
            "`*` within the fence"
        );
        assert!(fenced.residual == bare.residual && fenced.deny == bare.deny);
        let lowered = fenced.lower();
        assert!(!lowered.keeps("arn:wami:s3:100:wami:1:bucket/atlas/conv/c1"));
        assert!(lowered.keeps("arn:wami:s3:300/7:wami:1:bucket/mine/x"));
    }

    #[test]
    fn a_fence_never_touches_a_deny_and_an_empty_fence_lists_nothing() {
        let docs = [document(vec![
            statement("Allow", &["s3:*"], &["arn:wami:s3:${tenant}:wami:*:**"]),
            statement(
                "Deny",
                &["s3:*"],
                &["arn:wami:s3:100:wami:1:bucket/atlas/conv/c1/thread/t2/**"],
            ),
        ])];
        let scope = Scope::compile(&docs, "s3:GetObject", &ctx("100")).unwrap();
        let fenced = scope.fenced(&["100"]);
        assert_eq!(fenced.deny, scope.deny);
        assert!(!fenced.matches("arn:wami:s3:100:wami:1:bucket/atlas/conv/c1/thread/t2/msg/1"));
        assert!(fenced.matches("arn:wami:s3:100:wami:1:bucket/atlas/conv/c1/thread/t1/msg/1"));
        let nothing = scope.fenced(&[]);
        assert!(
            nothing.fence.is_empty() && nothing.allow == scope.allow,
            "no tenants: no fence, the bare scope"
        );
    }
}
