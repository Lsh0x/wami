//! The fragment's shape, and the fragment as a store: a small GQL `WHERE`
//! interpreter stands for the engine, so the harness holds the push-down to
//! the invariant without a database (the real engine is in
//! `wami-scope-grafeo-tests`).

use proptest::prelude::*;
use wami_core::arn::matching::MatchContext;
use wami_scope::harness::{self, arbitrary, world};
use wami_scope::{Predicate, Scope};
use wami_scope_gql::{arn_filter, render, Fragment, FragmentError};

/// What a GQL engine does with the fragment, on one row: `=`, `STARTS WITH`,
/// `OR`, `AND`, `NOT`, parentheses, `true`, `false`, `$param`.
struct Engine<'a> {
    tokens: Vec<&'a str>,
    at: usize,
    params: &'a [(String, String)],
    row: &'a str,
}

impl<'a> Engine<'a> {
    fn keeps(fragment: &'a Fragment, row: &'a str) -> bool {
        let spaced = fragment.text.replace('(', " ( ").replace(')', " ) ");
        let tokens: Vec<&str> = spaced.split_whitespace().collect();
        // The tokens borrow `spaced`, which must outlive the engine: hence the
        // leak, in a test, of a few bytes per row.
        let tokens: Vec<&'a str> = tokens
            .into_iter()
            .map(|t| &*Box::leak(t.to_string().into_boxed_str()))
            .collect();
        let mut engine = Engine {
            tokens,
            at: 0,
            params: &fragment.params,
            row,
        };
        let value = engine.or();
        assert_eq!(
            engine.at,
            engine.tokens.len(),
            "unread tokens in {}",
            fragment.text
        );
        value
    }

    fn peek(&self) -> Option<&'a str> {
        self.tokens.get(self.at).copied()
    }

    fn next(&mut self) -> &'a str {
        let token = self.tokens[self.at];
        self.at += 1;
        token
    }

    fn or(&mut self) -> bool {
        let mut value = self.and();
        while self.peek() == Some("OR") {
            self.next();
            value |= self.and();
        }
        value
    }

    fn and(&mut self) -> bool {
        let mut value = self.not();
        while self.peek() == Some("AND") {
            self.next();
            value &= self.not();
        }
        value
    }

    fn not(&mut self) -> bool {
        if self.peek() == Some("NOT") {
            self.next();
            return !self.not();
        }
        self.atom()
    }

    fn atom(&mut self) -> bool {
        match self.next() {
            "(" => {
                let value = self.or();
                assert_eq!(self.next(), ")");
                value
            }
            "true" => true,
            "false" => false,
            target => {
                assert_eq!(target, "n.arn", "the only target");
                match self.next() {
                    "=" => {
                        let value = self.param();
                        self.row == value
                    }
                    "STARTS" => {
                        assert_eq!(self.next(), "WITH");
                        let value = self.param();
                        self.row.starts_with(&value)
                    }
                    other => panic!("unexpected operator {other}"),
                }
            }
        }
    }

    fn param(&mut self) -> String {
        let name = self.next().strip_prefix('$').expect("a $parameter");
        self.params
            .iter()
            .find(|(n, _)| n == name)
            .map_or_else(|| panic!("unbound parameter {name}"), |(_, v)| v.clone())
    }
}

/// The fragment run as a store over `universe`.
fn store(scope: &Scope, universe: &[String]) -> Vec<String> {
    let fragment = arn_filter(scope, "n", "arn", "s").unwrap();
    universe
        .iter()
        .filter(|row| Engine::keeps(&fragment, row))
        .cloned()
        .collect()
}

fn scope(resources_allow: &[&str], resources_deny: &[&str]) -> Scope {
    let allow: Vec<String> = resources_allow.iter().map(ToString::to_string).collect();
    let deny: Vec<String> = resources_deny.iter().map(ToString::to_string).collect();
    let mut statements = vec![world::statement("Allow", &["*"], &allow, None)];
    if !deny.is_empty() {
        statements.push(world::statement("Deny", &["*"], &deny, None));
    }
    let ctx = MatchContext {
        tenant: Some("100".into()),
        ..MatchContext::default()
    };
    harness::compile(&[world::document(statements)], "atlas:ReadItem", &ctx)
}

/// A random predicate, three levels deep at most.
fn predicate() -> impl Strategy<Value = Predicate> {
    let leaf = prop_oneof![
        Just(Predicate::All),
        Just(Predicate::None),
        arbitrary::arn().prop_map(Predicate::Exact),
        arbitrary::arn().prop_map(|a| Predicate::Prefix(a[..a.len() / 2].to_string())),
    ];
    leaf.prop_recursive(3, 16, 3, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 1..=3).prop_map(Predicate::And),
            proptest::collection::vec(inner.clone(), 1..=3).prop_map(Predicate::Or),
            inner.prop_map(|p| Predicate::Not(Box::new(p))),
        ]
    })
}

#[test]
fn the_lowering_renders_as_the_issue_draws_it() {
    let f = arn_filter(
        &scope(&["arn:wami:atlas:${tenant}:wami:1:key/k1"], &[]),
        "n",
        "arn",
        "s",
    )
    .unwrap();
    assert_eq!(f.text, "(n.arn = $s0)");
    assert_eq!(
        f.params,
        [(
            "s0".to_string(),
            "arn:wami:atlas:100:wami:1:key/k1".to_string()
        )]
    );

    let f = arn_filter(
        &scope(&["arn:wami:atlas:${tenant}:wami:*:archive/*/note/*"], &[]),
        "n",
        "arn",
        "s",
    )
    .unwrap();
    assert_eq!(f.text, "(n.arn STARTS WITH $s0)");
    assert_eq!(f.params[0].1, "arn:wami:atlas:100:wami:");

    let allow = "arn:wami:atlas:${tenant}:wami:1:archive/**";
    let deny = "arn:wami:atlas:${tenant}:wami:1:archive/house/note/secret";
    let f = arn_filter(&scope(&[allow], &[deny]), "n", "arn", "s").unwrap();
    assert_eq!(
        f.text,
        "(((n.arn STARTS WITH $s0) OR (n.arn = $s1)) AND (NOT (n.arn = $s2)))"
    );
    assert_eq!(f.params[0].1, "arn:wami:atlas:100:wami:1:archive/");
    assert_eq!(f.params[1].1, "arn:wami:atlas:100:wami:1:archive");
    assert_eq!(
        f.params[2].1,
        "arn:wami:atlas:100:wami:1:archive/house/note/secret"
    );

    let f = arn_filter(
        &scope(
            &[allow],
            &["arn:wami:atlas:${tenant}:wami:1:archive/*/note/*"],
        ),
        "n",
        "arn",
        "s",
    )
    .unwrap();
    assert_eq!(
        f.text, "((n.arn STARTS WITH $s0) OR (n.arn = $s1))",
        "a wildcard deny is left to the re-check"
    );
    assert_eq!(
        arn_filter(&Scope::default(), "n", "arn", "s").unwrap().text,
        "(false)"
    );
    assert_eq!(
        arn_filter(&scope(&["*"], &[]), "n", "arn", "s")
            .unwrap()
            .text,
        "(true)"
    );
}

#[test]
fn values_stay_in_the_parameters_whatever_they_hold() {
    let hostile = "arn:wami:atlas:${tenant}:wami:1:note/it's) OR true OR ($x";
    let f = arn_filter(&scope(&[hostile], &[]), "n", "arn", "s").unwrap();
    assert_eq!(f.text, "(n.arn = $s0)");
    assert_eq!(
        f.params[0].1,
        "arn:wami:atlas:100:wami:1:note/it's) OR true OR ($x"
    );
    assert_eq!(
        arn_filter(&Scope::default(), "n", "arn;", "s"),
        Err(FragmentError::NotAnIdentifier {
            what: "property",
            name: "arn;".into()
        })
    );
}

#[test]
fn the_names_are_the_callers() {
    let f = arn_filter(
        &scope(&["arn:wami:atlas:${tenant}:wami:*:key/*"], &[]),
        "node",
        "id",
        "rights_",
    )
    .unwrap();
    assert_eq!(f.text, "(node.id STARTS WITH $rights_0)");
    assert_eq!(f.params[0].0, "rights_0");
}

#[test]
fn the_fragment_as_a_store_holds_the_invariant_on_the_standard_world() {
    let world = world::World::standard();
    let verdicts = harness::check_translator(&world, store);
    let reader = verdicts
        .iter()
        .find(|v| v.principal == "reader" && v.action == "atlas:ReadItem")
        .unwrap();
    assert!(
        reader.kept.len() > reader.allowed.len(),
        "the wildcard deny is left to the re-check: the store over-includes"
    );
    let editor = verdicts
        .iter()
        .find(|v| v.principal == "editor" && v.action == "atlas:EditLayer")
        .unwrap();
    assert_eq!(
        editor.kept.len(),
        18,
        "the world's motifs hold `wami:*`: every pattern widens to its tenant prefix"
    );
    assert_eq!(editor.allowed.len(), 3);
    let nobody = verdicts
        .iter()
        .filter(|v| v.principal == "nobody")
        .all(|v| v.kept.is_empty());
    assert!(nobody);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// The rendering is the predicate: what a GQL engine keeps from the text
    /// is what `Predicate::keeps` keeps.
    #[test]
    fn the_rendering_is_equal_to_keeps(
        predicate in predicate(),
        rows in proptest::collection::vec(arbitrary::arn(), 1..=8),
    ) {
        let fragment = render(&predicate, "n", "arn", "s").unwrap();
        for row in &rows {
            prop_assert_eq!(Engine::keeps(&fragment, row), predicate.keeps(row), "{} on {}", fragment.text, row);
        }
    }

    #[test]
    fn the_fragment_never_excludes_what_the_evaluator_allows(
        case in arbitrary::case(),
        universe in arbitrary::universe(),
    ) {
        harness::check_case(&case, &universe, store);
    }
}

#[test]
fn parameters_past_ten_stay_distinct_and_bound() {
    let keys: Vec<String> = (0..12)
        .map(|i| format!("arn:wami:atlas:${{tenant}}:wami:1:key/k{i}"))
        .collect();
    let refs: Vec<&str> = keys.iter().map(String::as_str).collect();
    let scope = scope(&refs, &[]);
    let f = arn_filter(&scope, "n", "arn", "s").unwrap();
    assert_eq!(f.params.len(), 12);
    let mut names: Vec<&str> = f.params.iter().map(|(n, _)| n.as_str()).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), 12, "s0 … s11, no collision");
    assert!(f.text.contains("$s11") && !f.text.contains("$s12"));
    let universe: Vec<String> = (0..14)
        .map(|i| format!("arn:wami:atlas:100:wami:1:key/k{i}"))
        .collect();
    let kept = store(&scope, &universe);
    assert_eq!(kept.len(), 12);
    assert!(!kept
        .iter()
        .any(|k| k.ends_with("k12") || k.ends_with("k13")));
}

#[test]
fn everything_but_one_renders_true_and_a_not() {
    let f = arn_filter(
        &scope(&["*"], &["arn:wami:atlas:${tenant}:wami:1:key/k1"]),
        "n",
        "arn",
        "s",
    )
    .unwrap();
    assert_eq!(f.text, "((true) AND (NOT (n.arn = $s0)))");
    let universe = world::World::standard().universe;
    let kept = store(
        &scope(&["*"], &["arn:wami:atlas:${tenant}:wami:1:key/k1"]),
        &universe,
    );
    assert_eq!(kept.len(), universe.len() - 1);
    assert!(!kept.contains(&"arn:wami:atlas:100:wami:1:key/k1".to_string()));
}

#[test]
fn a_sub_tenants_prefix_stops_at_the_colon() {
    let ctx = MatchContext {
        tenant: Some("100/7".into()),
        ..MatchContext::default()
    };
    let docs = [world::document(vec![world::statement(
        "Allow",
        &["*"],
        &[world::own("realm/**")],
        None,
    )])];
    let sub = harness::compile(&docs, "atlas:ReadItem", &ctx);
    let f = arn_filter(&sub, "n", "arn", "s").unwrap();
    assert_eq!(f.params[0].1, "arn:wami:atlas:100/7:wami:");
    let universe = vec![
        "arn:wami:atlas:100:wami:1:realm/main".to_string(),
        "arn:wami:atlas:100/7:wami:1:realm/main".to_string(),
        "arn:wami:atlas:1007:wami:1:realm/main".to_string(),
    ];
    assert_eq!(store(&sub, &universe), [universe[1].clone()]);
    let parent = scope(&[&world::own("realm/**")], &[]);
    assert_eq!(store(&parent, &universe), [universe[0].clone()]);
}
