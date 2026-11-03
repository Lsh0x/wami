//! The shared authorization suite on a real SQLite store.

use rusqlite::{Connection, ToSql};
use wami_scope::Narrowing;
use wami_scope_sql::{render, Fragment};
use wami_scope_tests::port::{Row, Shape, Store};
use wami_scope_tests::world::{Kind, World};
use wami_scope_tests::{arbitrary, suite};

struct Sqlite {
    db: Connection,
}

impl Sqlite {
    fn new() -> Self {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE TABLE resource (arn TEXT PRIMARY KEY COLLATE BINARY, kind TEXT NOT NULL, archived INTEGER NOT NULL);
             CREATE TABLE edge (source TEXT NOT NULL, label TEXT NOT NULL, target TEXT NOT NULL);
             CREATE INDEX edge_source ON edge(source, label);
             CREATE INDEX edge_target ON edge(target);",
        ).unwrap();
        Self { db }
    }

    fn fragment(narrowing: &Narrowing, name: &str) -> Fragment {
        narrowing
            .lowered()
            .into_iter()
            .find(|(n, _)| *n == name)
            .map_or_else(
                || Fragment {
                    text: "(1)".into(),
                    params: vec![],
                },
                |(_, p)| render(&p, name, "arn", &format!("q_{name}_")).unwrap(),
            )
    }

    fn clauses(narrowing: &Narrowing, names: &[&str]) -> Fragment {
        let mut parts = Vec::new();
        let mut params = Vec::new();
        for name in names {
            let f = Self::fragment(narrowing, name);
            parts.push(format!("{} AND {name}.archived = 0", f.text));
            params.extend(f.params);
        }
        Fragment {
            text: parts.join(" AND "),
            params,
        }
    }

    fn query(&self, sql: &str, fragment: &Fragment, names: &[&str], count: bool) -> Vec<Row> {
        let bindings: Vec<(&str, &dyn ToSql)> = fragment
            .params
            .iter()
            .map(|(name, value)| (name.as_str(), value as &dyn ToSql))
            .collect();
        let mut statement = self
            .db
            .prepare(sql)
            .unwrap_or_else(|e| panic!("{sql}: {e}"));
        statement
            .query_map(bindings.as_slice(), |record| {
                let arns = names
                    .iter()
                    .enumerate()
                    .map(|(i, name)| Ok(((*name).into(), record.get::<_, String>(i)?)))
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                let count = if count {
                    Some(
                        u64::try_from(record.get::<_, i64>(names.len())?)
                            .expect("SQLite count must be non-negative"),
                    )
                } else {
                    None
                };
                Ok(Row { arns, count })
            })
            .unwrap_or_else(|e| panic!("{sql}: {e}"))
            .map(Result::unwrap)
            .collect()
    }

    fn parents(&self, kind: Kind, narrowing: &Narrowing) -> Vec<String> {
        let f = Self::clauses(narrowing, &["p"]);
        let sql = format!(
            "SELECT p.arn FROM resource p WHERE p.kind = '{}' AND {}",
            kind.label(),
            f.text
        );
        self.query(&sql, &f, &["p"], false)
            .into_iter()
            .map(|r| r.arns[0].1.clone())
            .collect()
    }

    fn pairs(&self, parent: Kind, edge: &str, child: Kind, narrowing: &Narrowing) -> Vec<Row> {
        let f = Self::clauses(narrowing, &["p", "c"]);
        let sql = format!(
            "SELECT p.arn, c.arn FROM resource p JOIN edge e ON e.source = p.arn AND e.label = '{edge}' JOIN resource c ON c.arn = e.target WHERE p.kind = '{}' AND c.kind = '{}' AND {}",
            parent.label(), child.label(), f.text,
        );
        self.query(&sql, &f, &["p", "c"], false)
    }
}

impl Store for Sqlite {
    fn load(&mut self, world: &World) {
        for r in &world.resources {
            self.db
                .execute(
                    "INSERT INTO resource VALUES (?1, ?2, ?3)",
                    (&r.arn, r.kind.label(), r.archived),
                )
                .unwrap();
        }
        for e in &world.edges {
            self.db
                .execute(
                    "INSERT INTO edge VALUES (?1, ?2, ?3)",
                    (&e.from, e.label, &e.to),
                )
                .unwrap();
        }
    }

    fn run(&self, shape: &Shape, narrowing: &Narrowing) -> Vec<Row> {
        match shape {
            Shape::List { kind } => {
                let f = Self::clauses(narrowing, &["n"]);
                let sql = format!(
                    "SELECT n.arn FROM resource n WHERE n.kind = '{}' AND {}",
                    kind.label(),
                    f.text
                );
                self.query(&sql, &f, &["n"], false)
            }
            Shape::Lookup { kind, suffix } => {
                let mut f = Self::clauses(narrowing, &["n"]);
                f.params.push((":suffix".into(), suffix.clone()));
                let sql = format!("SELECT n.arn FROM resource n WHERE n.kind = '{}' AND {} AND substr(n.arn, -length(:suffix)) = :suffix", kind.label(), f.text);
                self.query(&sql, &f, &["n"], false)
            }
            Shape::Children {
                parent,
                edge,
                child,
            } => self.pairs(*parent, edge, *child, narrowing),
            Shape::Path {
                first,
                edge1,
                middle,
                edge2,
                last,
            } => {
                let f = Self::clauses(narrowing, &["p", "m", "c"]);
                let sql = format!("SELECT p.arn, m.arn, c.arn FROM resource p JOIN edge e1 ON e1.source = p.arn AND e1.label = '{edge1}' JOIN resource m ON m.arn = e1.target JOIN edge e2 ON e2.source = m.arn AND e2.label = '{edge2}' JOIN resource c ON c.arn = e2.target WHERE p.kind = '{}' AND m.kind = '{}' AND c.kind = '{}' AND {}", first.label(), middle.label(), last.label(), f.text);
                self.query(&sql, &f, &["p", "m", "c"], false)
            }
            Shape::Exists { kind, edge, target } => {
                let p = Self::clauses(narrowing, &["p"]);
                let c = Self::clauses(narrowing, &["c"]);
                let mut f = p.clone();
                f.params.extend(c.params);
                let sql = format!("SELECT p.arn FROM resource p WHERE p.kind = '{}' AND {} AND EXISTS (SELECT 1 FROM edge e JOIN resource c ON c.arn = e.target WHERE e.source = p.arn AND e.label = '{edge}' AND c.kind = '{}' AND {})", kind.label(), p.text, target.label(), c.text);
                self.query(&sql, &f, &["p"], false)
            }
            Shape::Count {
                parent,
                edge,
                child,
            } => {
                use std::collections::BTreeMap;
                let mut counts: BTreeMap<String, u64> = self
                    .parents(*parent, narrowing)
                    .into_iter()
                    .map(|p| (p, 0))
                    .collect();
                for row in self.pairs(*parent, edge, *child, narrowing) {
                    *counts.entry(row.arns[0].1.clone()).or_insert(0) += 1;
                }
                counts
                    .into_iter()
                    .map(|(p, count)| Row {
                        arns: vec![("p".into(), p)],
                        count: Some(count),
                    })
                    .collect()
            }
            Shape::OrderBy {
                parent,
                edge,
                child,
            } => {
                use std::collections::BTreeMap;
                let mut last: BTreeMap<String, String> = self
                    .parents(*parent, narrowing)
                    .into_iter()
                    .map(|p| (p, String::new()))
                    .collect();
                for row in self.pairs(*parent, edge, *child, narrowing) {
                    let slot = last.entry(row.arns[0].1.clone()).or_default();
                    if row.arns[1].1 > *slot {
                        slot.clone_from(&row.arns[1].1);
                    }
                }
                let mut keyed: Vec<_> = last.into_iter().map(|(p, c)| (c, p)).collect();
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
async fn sqlite_holds_the_shared_invariant() {
    let world = World::standard().await;
    let mut store = Sqlite::new();
    store.load(&world);
    suite::run_all(&world, &store).await;
}

#[test]
fn random_shapes_hold_the_invariant_in_sqlite() {
    use proptest::test_runner::{Config, TestRunner};
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let world = rt.block_on(World::standard());
    let allowed = rt.block_on(suite::allowed_all(&world));
    let mut store = Sqlite::new();
    store.load(&world);
    let strategy = (
        arbitrary::shape(&world),
        arbitrary::principal(&world),
        proptest::bool::ANY,
    );
    let mut runner = TestRunner::new(Config::with_cases(64));
    runner
        .run(&strategy, |(shape, principal, fenced)| {
            rt.block_on(suite::check_random(
                &world, &store, &allowed, principal, &shape, fenced,
            ));
            Ok(())
        })
        .unwrap();
}
