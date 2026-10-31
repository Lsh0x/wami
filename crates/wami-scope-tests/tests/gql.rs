//! The GQL rendering: a small `WHERE` interpreter stands for an engine, so
//! the rendering is proven equal to `Predicate::keeps` without a database
//! (the real engine is in `tests/grafeo.rs`), and the fragment runs as a
//! list store on random policies.

use proptest::prelude::*;
use wami_core::arn::matching::MatchContext;
use wami_scope::{Narrowing, Predicate, Scope};
use wami_scope_gql::{arn_filter, narrowing_filter, render, Fragment, FragmentError};
use wami_scope_tests::world::{of, ACME, MARKET};
use wami_scope_tests::{arbitrary, suite};

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

/// The fragment run as a list store over `universe`.
fn store(scope: &Scope, universe: &[String]) -> Vec<String> {
    let fragment = arn_filter(scope, "n", "arn", "s").unwrap();
    universe
        .iter()
        .filter(|row| Engine::keeps(&fragment, row))
        .cloned()
        .collect()
}

fn scope(allow: &[String], deny: &[String]) -> Scope {
    use wami_core::types::{PolicyDocument, PolicyStatement};
    let statement = |effect: &str, resources: &[String]| PolicyStatement {
        sid: None,
        effect: effect.into(),
        action: vec!["*".into()],
        resource: resources.to_vec(),
        condition: None,
    };
    let mut statements = vec![statement("Allow", allow)];
    if !deny.is_empty() {
        statements.push(statement("Deny", deny));
    }
    let ctx = MatchContext {
        tenant: Some(ACME.into()),
        ..MatchContext::default()
    };
    Scope::compile(
        &[PolicyDocument {
            version: "2012-10-17".into(),
            statement: statements,
        }],
        "s3:GetObject",
        &ctx,
    )
    .unwrap()
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
    let f = arn_filter(&scope(&[of("s3", ACME, "key/k1")], &[]), "n", "arn", "s").unwrap();
    assert_eq!(f.text, "(n.arn = $s0)");
    assert_eq!(f.params, [("s0".to_string(), of("s3", ACME, "key/k1"))]);

    let f = arn_filter(
        &scope(
            &["arn:wami:s3:${tenant}:wami:*:bucket/*/conv/*".to_string()],
            &[],
        ),
        "n",
        "arn",
        "s",
    )
    .unwrap();
    assert_eq!(f.text, "(n.arn STARTS WITH $s0)");
    assert_eq!(f.params[0].1, "arn:wami:s3:100:wami:");

    let allow = of("s3", "${tenant}", "bucket/atlas/conv/c1/**");
    let deny = of("s3", "${tenant}", "bucket/atlas/conv/c1/thread/t2/msg/1");
    let f = arn_filter(
        &scope(std::slice::from_ref(&allow), &[deny]),
        "n",
        "arn",
        "s",
    )
    .unwrap();
    assert_eq!(
        f.text,
        "(((n.arn STARTS WITH $s0) OR (n.arn = $s1)) AND (NOT (n.arn = $s2)))"
    );
    assert_eq!(f.params[0].1, of("s3", ACME, "bucket/atlas/conv/c1/"));
    assert_eq!(f.params[1].1, of("s3", ACME, "bucket/atlas/conv/c1"));

    let f = arn_filter(
        &scope(
            &[allow],
            &[of("s3", "${tenant}", "bucket/*/conv/*/thread/t2/**")],
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
        arn_filter(&scope(&["*".to_string()], &[]), "n", "arn", "s")
            .unwrap()
            .text,
        "(true)"
    );
}

#[test]
fn a_fence_renders_as_an_and_of_exact_trees() {
    let fenced = scope(&["*".to_string()], &[]).fenced(&[ACME, MARKET]);
    let f = arn_filter(&fenced, "n", "arn", "s").unwrap();
    assert_eq!(
        f.text,
        "((true) AND ((n.arn STARTS WITH $s0) OR ((n.arn STARTS WITH $s1) OR (n.arn = $s2)) OR (n.arn STARTS WITH $s3) OR ((n.arn STARTS WITH $s4) OR (n.arn = $s5))))"
    );
    assert_eq!(f.params[0].1, "arn:wami:s3:100:wami:");
    assert_eq!(f.params[1].1, "arn:wami:s3:100/");
    assert_eq!(f.params[3].1, "arn:wami:s3:1:wami:");
    let rows = [
        of("s3", ACME, "bucket/atlas"),
        of("s3", "100/7", "bucket/labs-data"),
        of("s3", "1007", "bucket/x"),
        of("s3", MARKET, "bucket/public-data"),
        of("lambda", ACME, "function/ingest"),
    ];
    let kept: Vec<&String> = rows.iter().filter(|r| Engine::keeps(&f, r)).collect();
    assert_eq!(kept, [&rows[0], &rows[1], &rows[3]]);
}

#[test]
fn values_stay_in_the_parameters_whatever_they_hold() {
    let hostile = of("s3", "${tenant}", "bucket/atlas/conv/it's) OR true OR ($x");
    let f = arn_filter(&scope(&[hostile], &[]), "n", "arn", "s").unwrap();
    assert_eq!(f.text, "(n.arn = $s0)");
    assert_eq!(
        f.params[0].1,
        of("s3", ACME, "bucket/atlas/conv/it's) OR true OR ($x")
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
fn a_narrowing_renders_tested_names_too() {
    let n = Narrowing::new()
        .bind("p", scope(&[of("s3", ACME, "bucket/atlas/conv/c1")], &[]))
        .unwrap()
        .test(
            "c",
            scope(&[of("s3", ACME, "bucket/atlas/conv/c1/**")], &[]),
        )
        .unwrap();
    let f = narrowing_filter(&n, "arn", "q").unwrap();
    assert_eq!(
        f.text,
        "((p.arn = $q_p_0) AND ((c.arn STARTS WITH $q_c_0) OR (c.arn = $q_c_1)))"
    );
}

#[test]
fn parameters_past_ten_stay_distinct_and_bound() {
    let keys: Vec<String> = (0..12)
        .map(|i| of("s3", "${tenant}", &format!("key/k{i}")))
        .collect();
    let s = scope(&keys, &[]);
    let f = arn_filter(&s, "n", "arn", "s").unwrap();
    let mut names: Vec<&str> = f.params.iter().map(|(n, _)| n.as_str()).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), 12);
    let universe: Vec<String> = (0..14)
        .map(|i| of("s3", ACME, &format!("key/k{i}")))
        .collect();
    assert_eq!(store(&s, &universe).len(), 12);
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

    /// The fragment as a list store never excludes what the evaluator allows.
    #[test]
    fn the_fragment_never_excludes_what_the_evaluator_allows(
        case in arbitrary::case(),
        universe in arbitrary::universe(),
    ) {
        suite::check_documents_case(&case, &universe, store);
    }
}
