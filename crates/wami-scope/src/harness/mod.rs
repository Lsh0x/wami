//! The conformance harness every translator runs (wami 008).
//!
//! Three parts, one invariant. [`world`] is a fixture a public crate can show:
//! tenants, principals with policies, and the resources they reach — none of
//! it any real deployment's. [`oracle`] is wami's evaluator, asked row by row:
//! the only definition of "allowed". [`arbitrary`] draws random policies,
//! principals and ARNs for the property tests.
//!
//! [`check_translator`] holds a translator to the invariant: **what it keeps
//! includes every row the evaluator allows, and once the scope re-checks the
//! rows, exactly those** (a superset when the scope is residual). A translator
//! runs it from its own tests with its store behind the closure:
//!
//! ```rust,ignore
//! let world = World::standard();
//! check_translator(&world, |scope, universe| my_store.rows_kept_by(scope, universe));
//! ```
//!
//! Behind the `harness` feature: test code shipped for other crates' tests.

pub mod arbitrary;
pub mod oracle;
pub mod world;

use wami_core::arn::matching::MatchContext;
use wami_core::types::PolicyDocument;

use crate::Scope;
use world::{Principal, World};

/// What one (principal, action) pair gave: for a translator's own assertions
/// (a count, a sample) once the invariant held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// The principal's name.
    pub principal: String,
    /// The action compiled.
    pub action: String,
    /// The rows the translator kept, before the re-check.
    pub kept: Vec<String>,
    /// The rows the evaluator allows.
    pub allowed: Vec<String>,
    /// Whether the scope was residual.
    pub residual: bool,
}

/// The rows of `universe` the evaluator allows `principal` `action` on.
///
/// # Panics
///
/// When the evaluator refuses a decision: the fixture is broken, not the
/// translator.
#[must_use]
pub fn allowed_rows(principal: &Principal, action: &str, universe: &[String]) -> Vec<String> {
    let ctx = world::context(principal);
    universe
        .iter()
        .filter(|arn| {
            oracle::allows(&principal.policies, action, arn, &ctx)
                .unwrap_or_else(|e| panic!("{}: {action} on {arn}: {e}", principal.name))
        })
        .cloned()
        .collect()
}

/// The scope of `principal` for `action`.
///
/// # Panics
///
/// When the policies cannot be compiled: the fixture is broken.
#[must_use]
pub fn scope_of(principal: &Principal, action: &str) -> Scope {
    Scope::compile(
        &principal.policies,
        action,
        &world::match_context(principal),
    )
    .unwrap_or_else(|e| panic!("{}: {e}", principal.name))
}

/// Holds `keep` — a translator with its store behind it, answering the rows
/// of `universe` it keeps for a scope — to the invariant, for every principal
/// and action of `world`.
///
/// # Panics
///
/// Naming the principal, the action and the row: when a kept row is outside
/// the universe; when an allowed row was not kept (**the** failure: the
/// translator excluded what the evaluator allows); when the kept rows, after
/// the scope's re-check, are not exactly the allowed ones (a superset is
/// accepted only for a residual scope); when the scope alone disagrees with
/// the evaluator on a non-residual case.
pub fn check_translator<F>(world: &World, mut keep: F) -> Vec<Verdict>
where
    F: FnMut(&Scope, &[String]) -> Vec<String>,
{
    let mut verdicts = Vec::new();
    for principal in &world.principals {
        for action in &world.actions {
            let scope = scope_of(principal, action);
            let allowed = allowed_rows(principal, action, &world.universe);
            let kept = keep(&scope, &world.universe);
            check_kept(principal, action, &scope, &world.universe, &kept, &allowed);
            verdicts.push(Verdict {
                principal: principal.name.to_string(),
                action: (*action).to_string(),
                kept,
                allowed,
                residual: scope.residual,
            });
        }
    }
    verdicts
}

fn check_kept(
    principal: &Principal,
    action: &str,
    scope: &Scope,
    universe: &[String],
    kept: &[String],
    allowed: &[String],
) {
    let who = format!("{} {action}", principal.name);
    for row in kept {
        assert!(
            universe.contains(row),
            "{who}: kept {row}, which is not in the universe"
        );
    }
    for row in allowed {
        assert!(
            kept.contains(row),
            "{who}: the evaluator allows {row} and the translator dropped it (scope: {scope:?})"
        );
    }
    let mut rechecked: Vec<&String> = kept.iter().filter(|row| scope.matches(row)).collect();
    rechecked.sort();
    rechecked.dedup();
    let mut expected: Vec<&String> = allowed.iter().collect();
    expected.sort();
    if scope.residual {
        for row in &expected {
            assert!(
                rechecked.contains(row),
                "{who}: residual scope dropped {row}"
            );
        }
    } else {
        assert_eq!(rechecked, expected, "{who}: kept rows after the re-check");
    }
    check_scope_alone(&who, scope, universe, allowed);
}

/// The scope by itself, as a re-check: the evaluator's verdict when nothing
/// is residual, a superset otherwise.
fn check_scope_alone(who: &str, scope: &Scope, universe: &[String], allowed: &[String]) {
    for arn in universe {
        let is_allowed = allowed.contains(arn);
        let in_scope = scope.matches(arn);
        if scope.residual {
            assert!(
                in_scope || !is_allowed,
                "{who}: the evaluator allows {arn}, the residual scope does not"
            );
        } else {
            assert_eq!(
                in_scope, is_allowed,
                "{who}: scope.matches({arn}) against the evaluator"
            );
        }
    }
}

/// [`check_translator`] for one case drawn by [`arbitrary::case`]: the scope
/// of its principal for its action, over `universe`.
///
/// # Panics
///
/// As [`check_translator`].
pub fn check_case<F>(case: &arbitrary::Case, universe: &[String], mut keep: F)
where
    F: FnMut(&Scope, &[String]) -> Vec<String>,
{
    let principal = Principal {
        name: case.principal,
        tenant: case.tenant,
        policies: case.policies.clone(),
    };
    let scope = scope_of(&principal, &case.action);
    let allowed = allowed_rows(&principal, &case.action, universe);
    let kept = keep(&scope, universe);
    check_kept(&principal, &case.action, &scope, universe, &kept, &allowed);
}

/// A scope compiled for a context, as a translator's test may need it
/// without a [`Principal`].
///
/// # Panics
///
/// When the policies cannot be compiled.
#[must_use]
pub fn compile(policies: &[PolicyDocument], action: &str, ctx: &MatchContext) -> Scope {
    Scope::compile(policies, action, ctx).expect("compilable policies")
}
