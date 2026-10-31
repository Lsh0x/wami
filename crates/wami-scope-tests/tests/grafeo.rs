//! The suite on a real graph store, Grafeo: the world loaded as nodes and
//! edges, every shape rendered as GQL with the narrowing's fragments, the
//! rows handed back for the suite to judge.

use std::collections::{BTreeMap, HashMap};

use grafeo::GrafeoDB;
use grafeo_common::types::Value;
use proptest::prelude::*;
use wami_core::arn::matching::MatchContext;
use wami_scope::{Narrowing, Predicate, Scope};
use wami_scope_gql::{arn_filter, render, Fragment};
use wami_scope_tests::port::{Row, Shape, Store};
use wami_scope_tests::world::{of, Kind, World, ACME};
use wami_scope_tests::{arbitrary, suite};

fn text(value: &str) -> Value {
    Value::String(value.into())
}

fn params(pairs: &[(String, String)]) -> HashMap<String, Value> {
    pairs.iter().map(|(k, v)| (k.clone(), text(v))).collect()
}

/// Every column of every row, as text.
fn columns(result: &grafeo::database::QueryResult) -> Vec<Vec<String>> {
    result
        .rows()
        .iter()
        .map(|row| {
            row.iter()
                .map(|v| match v {
                    Value::String(s) => s.to_string(),
                    other => panic!("not text: {other:?}"),
                })
                .collect()
        })
        .collect()
}

/// The world in Grafeo.
struct Grafeo {
    db: GrafeoDB,
}

impl Grafeo {
    fn new() -> Self {
        Self {
            db: GrafeoDB::new_in_memory(),
        }
    }

    fn query(&self, query: &str, parameters: &[(String, String)]) -> Vec<Vec<String>> {
        let result = self
            .db
            .session()
            .execute_with_params(query, params(parameters))
            .unwrap_or_else(|e| panic!("{query}: {e}"));
        columns(&result)
    }

    /// The fragment of one bound name, `(true)` when the narrowing does not
    /// bind it: an unbound name is not filtered, which is the leak the suite
    /// proves it would see.
    fn fragment(narrowing: &Narrowing, name: &str) -> Fragment {
        narrowing
            .lowered()
            .into_iter()
            .find(|(n, _)| *n == name)
            .map_or_else(
                || Fragment {
                    text: "(true)".into(),
                    params: Vec::new(),
                },
                |(_, predicate)| render(&predicate, name, "arn", &format!("q_{name}_")).unwrap(),
            )
    }

    /// `WHERE` for the names given: each one's fragment and its `archived`
    /// flag (a store rule: an archived container and its contents are never
    /// returned — every resource under one carries the flag).
    fn clause(narrowing: &Narrowing, names: &[&str]) -> (String, Vec<(String, String)>) {
        let mut texts = Vec::new();
        let mut all = Vec::new();
        for name in names {
            let f = Self::fragment(narrowing, name);
            texts.push(format!("{} AND {name}.archived = false", f.text));
            all.extend(f.params);
        }
        (texts.join(" AND "), all)
    }

    fn rows(&self, query: &str, parameters: &[(String, String)], names: &[&str]) -> Vec<Row> {
        self.query(query, parameters)
            .into_iter()
            .map(|cols| Row {
                arns: names
                    .iter()
                    .zip(cols)
                    .map(|(n, a)| ((*n).to_string(), a))
                    .collect(),
                count: None,
            })
            .collect()
    }

    /// The pairs `(p, c)` of an edge, both filtered.
    fn pairs(
        &self,
        parent: Kind,
        edge: &str,
        child: Kind,
        narrowing: &Narrowing,
    ) -> Vec<(String, String)> {
        let (clause, parameters) = Self::clause(narrowing, &["p", "c"]);
        let query = format!(
            "MATCH (p:{})-[:{edge}]->(c:{}) WHERE {clause} RETURN p.arn, c.arn",
            parent.label(),
            child.label()
        );
        self.query(&query, &parameters)
            .into_iter()
            .map(|mut cols| (cols.remove(0), cols.remove(0)))
            .collect()
    }

    fn parents(&self, kind: Kind, narrowing: &Narrowing) -> Vec<String> {
        let (clause, parameters) = Self::clause(narrowing, &["p"]);
        let query = format!("MATCH (p:{}) WHERE {clause} RETURN p.arn", kind.label());
        self.query(&query, &parameters)
            .into_iter()
            .map(|mut cols| cols.remove(0))
            .collect()
    }
}

impl Store for Grafeo {
    fn load(&mut self, world: &World) {
        let s = self.db.session();
        for r in &world.resources {
            s.execute_with_params(
                &format!(
                    "INSERT (:{} {{arn: $arn, tenant: $tenant, archived: {}}})",
                    r.kind.label(),
                    r.archived
                ),
                HashMap::from([
                    ("arn".to_string(), text(&r.arn)),
                    ("tenant".to_string(), text(r.tenant)),
                ]),
            )
            .unwrap();
        }
        for e in &world.edges {
            let from = world.resource(&e.from).kind.label();
            let to = world.resource(&e.to).kind.label();
            s.execute_with_params(
                &format!(
                    "MATCH (a:{from} {{arn: $a}}), (b:{to} {{arn: $b}}) INSERT (a)-[:{}]->(b)",
                    e.label
                ),
                HashMap::from([
                    ("a".to_string(), text(&e.from)),
                    ("b".to_string(), text(&e.to)),
                ]),
            )
            .unwrap();
        }
    }

    #[allow(clippy::too_many_lines)] // one arm per shape, each its query
    fn run(&self, shape: &Shape, narrowing: &Narrowing) -> Vec<Row> {
        match shape {
            Shape::List { kind } => {
                let (clause, parameters) = Self::clause(narrowing, &["n"]);
                let query = format!("MATCH (n:{}) WHERE {clause} RETURN n.arn", kind.label());
                self.rows(&query, &parameters, &["n"])
            }
            Shape::Lookup { kind, suffix } => {
                let (clause, mut parameters) = Self::clause(narrowing, &["n"]);
                parameters.push(("suffix".into(), suffix.clone()));
                let query = format!(
                    "MATCH (n:{}) WHERE {clause} AND n.arn ENDS WITH $suffix RETURN n.arn",
                    kind.label()
                );
                self.rows(&query, &parameters, &["n"])
            }
            Shape::Children {
                parent,
                edge,
                child,
            } => {
                let (clause, parameters) = Self::clause(narrowing, &["p", "c"]);
                let query = format!(
                    "MATCH (p:{})-[:{edge}]->(c:{}) WHERE {clause} RETURN p.arn, c.arn",
                    parent.label(),
                    child.label()
                );
                self.rows(&query, &parameters, &["p", "c"])
            }
            Shape::Path {
                first,
                edge1,
                middle,
                edge2,
                last,
            } => {
                let (clause, parameters) = Self::clause(narrowing, &["p", "m", "c"]);
                let query = format!(
                    "MATCH (p:{})-[:{edge1}]->(m:{})-[:{edge2}]->(c:{}) WHERE {clause} RETURN p.arn, m.arn, c.arn",
                    first.label(),
                    middle.label(),
                    last.label()
                );
                self.rows(&query, &parameters, &["p", "m", "c"])
            }
            Shape::Exists { kind, edge, target } => {
                let (on_p, mut parameters) = Self::clause(narrowing, &["p"]);
                let (on_c, more) = Self::clause(narrowing, &["c"]);
                parameters.extend(more);
                let query = format!(
                    "MATCH (p:{}) WHERE {on_p} AND EXISTS {{ MATCH (p)-[:{edge}]->(c:{}) WHERE {on_c} }} RETURN p.arn",
                    kind.label(),
                    target.label()
                );
                self.rows(&query, &parameters, &["p"])
            }
            Shape::Count {
                parent,
                edge,
                child,
            } => {
                // Two queries, both narrowed in the store; the adapter counts.
                let mut counts: BTreeMap<String, u64> = self
                    .parents(*parent, narrowing)
                    .into_iter()
                    .map(|p| (p, 0))
                    .collect();
                for (p, _) in self.pairs(*parent, edge, *child, narrowing) {
                    *counts.entry(p).or_insert(0) += 1;
                }
                counts
                    .into_iter()
                    .map(|(p, n)| Row {
                        arns: vec![("p".into(), p)],
                        count: Some(n),
                    })
                    .collect()
            }
            Shape::OrderBy {
                parent,
                edge,
                child,
            } => {
                let mut last: BTreeMap<String, String> = self
                    .parents(*parent, narrowing)
                    .into_iter()
                    .map(|p| (p, String::new()))
                    .collect();
                for (p, c) in self.pairs(*parent, edge, *child, narrowing) {
                    let slot = last.entry(p).or_default();
                    if c > *slot {
                        *slot = c;
                    }
                }
                let mut keyed: Vec<(String, String)> =
                    last.into_iter().map(|(p, c)| (c, p)).collect();
                keyed.sort();
                keyed
                    .into_iter()
                    .map(|(_, p)| Row {
                        arns: vec![("p".into(), p)],
                        count: None,
                    })
                    .collect()
            }
        }
    }
}

#[tokio::test]
async fn the_graph_holds_the_world() {
    let world = World::standard().await;
    let mut store = Grafeo::new();
    store.load(&world);
    let n = store.query(
        "MATCH (n) WHERE n.arn STARTS WITH $p RETURN n.arn",
        &[("p".into(), "arn:wami:".into())],
    );
    assert_eq!(n.len(), world.resources.len());
    let edges = store.query("MATCH (a)-[]->(b) RETURN a.arn, b.arn", &[]);
    assert_eq!(edges.len(), world.edges.len());
}

#[tokio::test]
async fn grafeo_holds_the_invariant_on_every_principal_and_shape() {
    let world = World::standard().await;
    let mut store = Grafeo::new();
    store.load(&world);
    suite::run_all(&world, &store).await;
}

#[test]
fn random_shapes_hold_the_invariant_in_grafeo() {
    use proptest::test_runner::{Config, TestRunner};
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let world = rt.block_on(World::standard());
    let allowed = rt.block_on(suite::allowed_all(&world));
    let mut store = Grafeo::new();
    store.load(&world);
    let mut runner = TestRunner::new(Config::with_cases(64));
    let strategy = (
        arbitrary::shape(&world),
        arbitrary::principal(&world),
        proptest::bool::ANY,
    );
    runner
        .run(&strategy, |(shape, principal, fenced)| {
            rt.block_on(suite::check_random(
                &world, &store, &allowed, principal, &shape, fenced,
            ));
            Ok(())
        })
        .unwrap();
}

#[tokio::test]
async fn a_hostile_literal_travels_as_a_parameter() {
    let world = World::standard().await;
    let mut store = Grafeo::new();
    store.load(&world);
    let hostile = of("s3", ACME, "bucket/atlas/conv/it's) OR true OR (");
    store
        .db
        .session()
        .execute_with_params(
            "INSERT (:Conversation {arn: $arn, tenant: '100', archived: false})",
            HashMap::from([("arn".to_string(), text(&hostile))]),
        )
        .unwrap();
    let docs = [wami_core::types::PolicyDocument {
        version: "2012-10-17".into(),
        statement: vec![wami_core::types::PolicyStatement {
            sid: None,
            effect: "Allow".into(),
            action: vec!["*".into()],
            resource: vec![hostile.replace(":100:", ":${tenant}:")],
            condition: None,
        }],
    }];
    let ctx = MatchContext {
        tenant: Some(ACME.into()),
        ..MatchContext::default()
    };
    let scope = Scope::compile(&docs, "s3:ListBucket", &ctx).unwrap();
    let narrowing = Narrowing::new().bind("n", scope).unwrap();
    let rows = store.run(
        &Shape::List {
            kind: Kind::Conversation,
        },
        &narrowing,
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].arn("n"), Some(hostile.as_str()));
}

#[tokio::test]
async fn a_row_without_an_arn_is_kept_by_true_alone() {
    let world = World::standard().await;
    let mut store = Grafeo::new();
    store.load(&world);
    store
        .db
        .session()
        .execute("INSERT (:Conversation {tenant: '100', archived: false})")
        .unwrap();
    let everything = Narrowing::new()
        .bind(
            "n",
            Scope::compile(
                &[wami_core::types::PolicyDocument {
                    version: "2012-10-17".into(),
                    statement: vec![wami_core::types::PolicyStatement {
                        sid: None,
                        effect: "Allow".into(),
                        action: vec!["*".into()],
                        resource: vec!["*".into()],
                        condition: None,
                    }],
                }],
                "s3:ListBucket",
                &MatchContext::default(),
            )
            .unwrap(),
        )
        .unwrap();
    let ghost = store.query(
        "MATCH (n:Conversation) WHERE (true) AND n.archived = false RETURN n.tenant",
        &[],
    );
    let live = world
        .of_kind(Kind::Conversation)
        .iter()
        .filter(|r| !r.archived)
        .count();
    assert_eq!(
        ghost.len(),
        live + 1,
        "`true` keeps the ghost (the archived one stays out)"
    );
    let fenced = Narrowing::new()
        .bind("n", everything.bindings()[0].scope.fenced(&[ACME]))
        .unwrap();
    let rows = store.run(
        &Shape::List {
            kind: Kind::Conversation,
        },
        &fenced,
    );
    assert!(
        rows.iter()
            .all(|r| r.arn("n").is_some_and(|a| a.starts_with("arn:wami:"))),
        "`=`, `STARTS WITH` and `NOT` over a null drop the ghost"
    );
    assert_eq!(
        rows.len(),
        world
            .of_kind(Kind::Conversation)
            .iter()
            .filter(|r| r.tenant == ACME && !r.archived)
            .count()
    );
}

/// A random predicate, three levels deep at most, over the world's ARNs.
fn predicate() -> impl Strategy<Value = Predicate> {
    let leaf = prop_oneof![
        Just(Predicate::All),
        Just(Predicate::None),
        arbitrary::arn().prop_map(Predicate::Exact),
        arbitrary::arn().prop_map(|a| Predicate::Prefix(a[..a.len() / 2].to_string())),
        Just(Predicate::Prefix(String::new())),
    ];
    leaf.prop_recursive(3, 16, 3, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 1..=3).prop_map(Predicate::And),
            proptest::collection::vec(inner.clone(), 1..=3).prop_map(Predicate::Or),
            inner.prop_map(|p| Predicate::Not(Box::new(p))),
        ]
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// Grafeo reads the fragment as `Predicate::keeps` does: `=`, `STARTS
    /// WITH` (an empty prefix too), `AND`, `OR`, `NOT`, `true`, `false`,
    /// under the parentheses the renderer writes.
    #[test]
    fn the_rendering_is_equal_to_keeps_in_grafeo(predicate in predicate()) {
        let universe = arbitrary::standard_universe();
        let store = {
            let mut s = Grafeo::new();
            let db = &s.db;
            let session = db.session();
            for arn in &universe {
                session.execute_with_params(
                    "INSERT (:Thing {arn: $arn})",
                    HashMap::from([("arn".to_string(), text(arn))]),
                ).unwrap();
            }
            drop(session);
            let _ = &mut s;
            s
        };
        let fragment = render(&predicate, "n", "arn", "s").unwrap();
        let query = format!("MATCH (n:Thing) WHERE {} RETURN n.arn", fragment.text);
        let mut kept: Vec<String> = store.query(&query, &fragment.params).into_iter().map(|mut c| c.remove(0)).collect();
        kept.sort();
        let mut expected: Vec<String> = universe.iter().filter(|row| predicate.keeps(row)).cloned().collect();
        expected.sort();
        prop_assert_eq!(kept, expected, "{}", fragment.text);
    }
}

#[test]
fn arn_filter_is_the_list_shape() {
    let scope = Scope::compile(
        &[wami_core::types::PolicyDocument {
            version: "2012-10-17".into(),
            statement: vec![wami_core::types::PolicyStatement {
                sid: None,
                effect: "Allow".into(),
                action: vec!["*".into()],
                resource: vec![of("s3", "${tenant}", "bucket/atlas/**")],
                condition: None,
            }],
        }],
        "s3:ListBucket",
        &MatchContext {
            tenant: Some(ACME.into()),
            ..MatchContext::default()
        },
    )
    .unwrap();
    let one = arn_filter(&scope, "n", "arn", "q_n_").unwrap();
    let narrowed = Grafeo::fragment(&Narrowing::new().bind("n", scope).unwrap(), "n");
    assert_eq!(one.text, narrowed.text);
    assert_eq!(one.params, narrowed.params);
}
