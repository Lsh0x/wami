//! The SQL renderer against SQLite's binary string semantics.

use rusqlite::Connection;
use wami_core::arn::matching::MatchContext;
use wami_core::types::{PolicyDocument, PolicyStatement};
use wami_scope::{Narrowing, Predicate, Scope};
use wami_scope_sql::{arn_filter, narrowing_filter, render, Fragment};

fn rows(db: &Connection, fragment: &Fragment) -> Vec<String> {
    let query = format!(
        "SELECT c.arn FROM resource c WHERE {} ORDER BY c.arn",
        fragment.text
    );
    let mut statement = db.prepare(&query).unwrap();
    let named: Vec<(&str, &dyn rusqlite::ToSql)> = fragment
        .params
        .iter()
        .map(|(name, value)| (name.as_str(), value as &dyn rusqlite::ToSql))
        .collect();
    statement
        .query_map(named.as_slice(), |row| row.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn db() -> Connection {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch("CREATE TABLE resource (arn TEXT COLLATE BINARY NOT NULL)")
        .unwrap();
    let arns = [
        "arn:wami:studio:100:wami:anatta:project/p/conversation/a",
        "arn:wami:studio:100:wami:anatta:project/p/conversation/b",
        "arn:wami:studio:100:wami:anatta:project/π/conversation/a",
        "arn:wami:studio:200:wami:anatta:project/p/conversation/a",
    ];
    for arn in arns {
        db.execute("INSERT INTO resource (arn) VALUES (?1)", [arn])
            .unwrap();
    }
    db
}

fn scope(tenant: &str, deny: Option<&str>) -> Scope {
    let mut statement = vec![PolicyStatement {
        sid: None,
        effect: "Allow".into(),
        action: vec!["studio:ReadConversation".into()],
        resource: vec![format!("arn:wami:studio:{tenant}:wami:anatta:project/p/**")],
        condition: None,
    }];
    if let Some(arn) = deny {
        statement.push(PolicyStatement {
            sid: None,
            effect: "Deny".into(),
            action: vec!["studio:ReadConversation".into()],
            resource: vec![arn.into()],
            condition: None,
        });
    }
    Scope::compile(
        &[PolicyDocument {
            version: "2012-10-17".into(),
            statement,
        }],
        "studio:ReadConversation",
        &MatchContext::default(),
    )
    .unwrap()
}

#[test]
fn every_predicate_matches_its_reference_on_sqlite_rows() {
    let db = db();
    let predicates = [
        Predicate::All,
        Predicate::None,
        Predicate::Exact("arn:wami:studio:100:wami:anatta:project/p/conversation/a".into()),
        Predicate::Prefix("arn:wami:studio:100:wami:anatta:project/p/".into()),
        Predicate::Prefix("arn:wami:studio:100:wami:anatta:project/π/".into()),
        Predicate::And(vec![
            Predicate::Prefix("arn:wami:studio:100:".into()),
            Predicate::Not(Box::new(Predicate::Exact(
                "arn:wami:studio:100:wami:anatta:project/p/conversation/b".into(),
            ))),
        ]),
    ];
    let all = rows(&db, &render(&Predicate::All, "c", "arn", "p").unwrap());
    for predicate in predicates {
        let actual = rows(&db, &render(&predicate, "c", "arn", "p").unwrap());
        let expected: Vec<_> = all
            .iter()
            .filter(|arn| predicate.keeps(arn))
            .cloned()
            .collect();
        assert_eq!(actual, expected, "{predicate:?}");
    }
}

#[test]
fn scope_keeps_tenant_and_project_boundaries_and_deny() {
    let scope = scope(
        "100",
        Some("arn:wami:studio:100:wami:anatta:project/p/conversation/b"),
    );
    let fragment = arn_filter(&scope, "c", "arn", "s").unwrap();
    let actual = rows(&db(), &fragment);
    assert_eq!(
        actual,
        ["arn:wami:studio:100:wami:anatta:project/p/conversation/a"]
    );
    assert!(!scope.residual, "the caller still runs decide");
}

#[test]
fn conditioned_deny_is_residual_and_sql_must_keep_the_row() {
    let arn = "arn:wami:studio:100:wami:anatta:project/p/conversation/a";
    let policy = PolicyDocument {
        version: "2012-10-17".into(),
        statement: vec![
            PolicyStatement {
                sid: None,
                effect: "Allow".into(),
                action: vec!["studio:ReadConversation".into()],
                resource: vec![arn.into()],
                condition: None,
            },
            PolicyStatement {
                sid: None,
                effect: "Deny".into(),
                action: vec!["studio:ReadConversation".into()],
                resource: vec![arn.into()],
                condition: Some(serde_json::json!({"StringEquals": {"request:mode": "private"}})),
            },
        ],
    };
    let scope = Scope::compile(
        &[policy],
        "studio:ReadConversation",
        &MatchContext::default(),
    )
    .unwrap();
    assert!(scope.residual);
    assert_eq!(
        rows(&db(), &arn_filter(&scope, "c", "arn", "s").unwrap()),
        [arn]
    );
}

#[test]
fn identifiers_and_values_cannot_enter_sql_syntax() {
    assert!(render(&Predicate::All, "c OR 1=1", "arn", "p").is_err());
    assert!(render(&Predicate::All, "c", "arn) OR 1=1", "p").is_err());
    assert!(render(&Predicate::All, "c", "arn", "p;").is_err());
    let fragment = render(&Predicate::Exact("' OR 1=1 --".into()), "c", "arn", "p").unwrap();
    assert_eq!(rows(&db(), &fragment), Vec::<String>::new());
    assert!(!fragment.text.contains("1=1"));
}

#[test]
fn a_narrowing_filters_each_bound_alias() {
    let narrowing = Narrowing::new()
        .bind("c", scope("100", None))
        .unwrap()
        .bind("m", scope("200", None))
        .unwrap();
    let fragment = narrowing_filter(&narrowing, "arn", "q").unwrap();
    let db = db();
    db.execute(
        "CREATE TABLE message (arn TEXT COLLATE BINARY NOT NULL)",
        [],
    )
    .unwrap();
    db.execute("INSERT INTO message SELECT arn FROM resource", [])
        .unwrap();
    let query = format!(
        "SELECT count(*) FROM resource c JOIN message m ON 1=1 WHERE {}",
        fragment.text
    );
    let named: Vec<(&str, &dyn rusqlite::ToSql)> = fragment
        .params
        .iter()
        .map(|(n, v)| (n.as_str(), v as &dyn rusqlite::ToSql))
        .collect();
    let count: i64 = db
        .query_row(&query, named.as_slice(), |row| row.get(0))
        .unwrap();
    assert_eq!(count, 2);
}
