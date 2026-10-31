//! The scope against the evaluator: on the standard world, case by case, and
//! on random policies. The scope is itself a translator — the one every store
//! re-checks with — so it runs the harness with `matches` as the store.

use proptest::prelude::*;
use wami_scope::harness::{self, arbitrary, world::World};
use wami_scope::Scope;

/// The simplest store: it keeps what the scope matches.
fn by_matches(scope: &Scope, universe: &[String]) -> Vec<String> {
    universe
        .iter()
        .filter(|a| scope.matches(a))
        .cloned()
        .collect()
}

/// A store that filters on the lowered predicate, as every backend does
/// before the re-check.
fn by_predicate(scope: &Scope, universe: &[String]) -> Vec<String> {
    let lowered = scope.lower();
    universe
        .iter()
        .filter(|a| lowered.keeps(a))
        .cloned()
        .collect()
}

#[test]
fn the_lowering_never_excludes_what_the_evaluator_allows_on_the_standard_world() {
    let world = World::standard();
    let verdicts = harness::check_translator(&world, by_predicate);
    let reader = verdicts
        .iter()
        .find(|v| v.principal == "reader" && v.action == "atlas:ReadItem")
        .unwrap();
    assert!(
        reader.kept.len() > reader.allowed.len(),
        "the wildcard deny is left to the re-check"
    );
    let nobody = verdicts
        .iter()
        .filter(|v| v.principal == "nobody")
        .all(|v| v.kept.is_empty());
    assert!(nobody, "nothing granted lists nothing");
}

#[test]
fn the_scope_agrees_with_the_evaluator_on_the_standard_world() {
    let world = World::standard();
    let verdicts = harness::check_translator(&world, by_matches);
    assert_eq!(verdicts.len(), world.principals.len() * world.actions.len());
    let residual: Vec<_> = verdicts
        .iter()
        .filter(|v| v.residual)
        .map(|v| v.principal.as_str())
        .collect();
    assert!(
        residual.iter().all(|p| *p == "auditor"),
        "only the auditor carries conditions: {residual:?}"
    );
    assert!(residual.contains(&"auditor"));
}

#[test]
fn the_owner_reaches_its_tenant_and_the_commons_never_the_other_tenant() {
    let world = World::standard();
    let owner = world.principal("owner");
    let allowed = harness::allowed_rows(owner, "atlas:ReadItem", &world.universe);
    assert!(allowed.iter().any(|a| a.contains(":100:")));
    assert!(allowed
        .iter()
        .any(|a| a.ends_with("archive/commons/recipe/porridge")));
    assert!(
        !allowed.iter().any(|a| a.contains(":200:")),
        "south is not north"
    );
    assert!(
        !allowed.iter().any(|a| a.ends_with(":1:key/k0")),
        "the commons' key is not granted"
    );
    let scope = harness::scope_of(owner, "atlas:ReadItem");
    assert_eq!(by_matches(&scope, &world.universe), allowed);
    assert_eq!(
        scope.prefixes(),
        ["arn:wami:atlas:100:wami:", "arn:wami:atlas:1:wami:"]
    );
}

#[test]
fn a_literal_deny_removes_one_row_a_wildcard_deny_removes_a_kind() {
    let world = World::standard();
    let editor = harness::scope_of(world.principal("editor"), "atlas:EditLayer");
    assert!(editor.matches("arn:wami:atlas:100:wami:1:realm/main/map/alpha/layer/one"));
    assert!(!editor.matches("arn:wami:atlas:100:wami:1:realm/main/map/alpha/layer/two"));
    assert!(!editor.matches("arn:wami:atlas:100:wami:1:realm/main/map/beta"));
    assert_eq!(editor.deny.len(), 1);

    let reader = harness::scope_of(world.principal("reader"), "atlas:ReadItem");
    assert!(reader.matches("arn:wami:atlas:100:wami:1:archive/house/recipe/soup"));
    assert!(!reader.matches("arn:wami:atlas:100:wami:1:archive/house/note/secret"));
    assert!(!reader.matches("arn:wami:atlas:100:wami:1:archive/guild/note/draft"));
    assert_eq!(
        reader.deny[0].trailing_tree(),
        None,
        "a wildcard deny is no exact tree"
    );
}

#[test]
fn an_agent_key_never_reaches_the_keys_and_nobody_reaches_nothing() {
    let world = World::standard();
    let agent = harness::scope_of(world.principal("agent-key"), "atlas:ReadKey");
    assert!(agent.is_empty());
    let agent = harness::scope_of(world.principal("agent-key"), "atlas:Search");
    assert!(!agent.matches("arn:wami:atlas:100:wami:1:key/k1"));
    assert!(agent.matches("arn:wami:atlas:100:wami:1:place/tool/oven"));
    for action in &world.actions {
        assert!(harness::scope_of(world.principal("nobody"), action).is_empty());
        assert_eq!(
            harness::allowed_rows(world.principal("nobody"), action, &world.universe).len(),
            0
        );
    }
}

#[test]
fn the_auditor_is_residual_and_over_included_never_excluded() {
    let world = World::standard();
    let auditor = world.principal("auditor");
    let keys = harness::scope_of(auditor, "atlas:ReadKey");
    assert!(keys.residual);
    let allowed = harness::allowed_rows(auditor, "atlas:ReadKey", &world.universe);
    assert_eq!(
        allowed.len(),
        2,
        "the condition holds for the auditor: both keys"
    );
    let items = harness::scope_of(auditor, "atlas:ReadItem");
    assert!(items.residual);
    assert_eq!(
        items.deny.len(),
        0,
        "the conditioned deny is left to the re-check"
    );
    let allowed = harness::allowed_rows(auditor, "atlas:ReadItem", &world.universe);
    assert!(
        allowed
            .iter()
            .any(|a| a.ends_with("archive/house/note/secret")),
        "the deny's condition is false for the auditor"
    );
}

#[test]
fn the_visitors_pattern_is_outside_the_subset_and_still_right() {
    let world = World::standard();
    let visitor = harness::scope_of(world.principal("visitor"), "atlas:ReadItem");
    assert_eq!(
        wami_scope::Pattern::compilable(visitor.allow[0].as_str()),
        Err(wami_scope::NotCompilable::InnerDoubleStar(
            visitor.allow[0].as_str().into()
        ))
    );
    assert_eq!(visitor.prefixes(), ["arn:wami:atlas:200:wami:"]);
    let allowed = harness::allowed_rows(
        world.principal("visitor"),
        "atlas:ReadItem",
        &world.universe,
    );
    assert_eq!(
        allowed.len(),
        18,
        "everything of south, nothing of north or the commons"
    );
    assert!(allowed.iter().all(|a| a.contains(":200:")));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Random policies, callers and resources: the scope is the evaluator's
    /// verdict when nothing is residual, and never excludes what it allows.
    #[test]
    fn the_scope_never_excludes_what_the_evaluator_allows(
        case in arbitrary::case(),
        universe in arbitrary::universe(),
    ) {
        harness::check_case(&case, &universe, by_matches);
    }

    /// The lowering, on random policies: every allowed row passes the
    /// predicate.
    #[test]
    fn the_lowering_never_excludes_what_the_evaluator_allows(
        case in arbitrary::case(),
        universe in arbitrary::universe(),
    ) {
        harness::check_case(&case, &universe, by_predicate);
    }

    /// Every allow prefix is a prefix of what it matches.
    #[test]
    fn a_prefix_is_a_prefix_of_every_row_its_pattern_matches(
        case in arbitrary::case(),
        rows in proptest::collection::vec(arbitrary::arn(), 1..=16),
    ) {
        let principal = wami_scope::harness::world::Principal {
            name: case.principal, tenant: case.tenant, policies: case.policies.clone(),
        };
        let scope = harness::scope_of(&principal, &case.action);
        for pattern in &scope.allow {
            for row in &rows {
                if pattern.matches(row) {
                    prop_assert!(row.starts_with(pattern.prefix()), "{row} vs {pattern}");
                }
            }
        }
    }
}
