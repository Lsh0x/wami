//! The fragment against Grafeo: the harness's world loaded as a graph —
//! tenants, users, maps and layers, an archive, keys, memos about items and
//! holding in places — and every (principal, action) scope run as a GQL
//! `WHERE` the store narrows on, before the scope re-checks each row.

use std::collections::HashMap;

use grafeo::GrafeoDB;
use grafeo_common::types::Value;
use proptest::prelude::*;
use wami_core::arn::matching::MatchContext;
use wami_scope::harness::{self, arbitrary, world};
use wami_scope::Scope;
use wami_scope_gql::{arn_filter, Fragment};

fn text(value: &str) -> Value {
    Value::String(value.into())
}

fn params(pairs: &[(String, String)]) -> HashMap<String, Value> {
    pairs.iter().map(|(k, v)| (k.clone(), text(v))).collect()
}

/// The first column of every row, as text.
fn column(result: &grafeo::database::QueryResult) -> Vec<String> {
    result
        .rows()
        .iter()
        .map(|row| match &row[0] {
            Value::String(s) => s.to_string(),
            other => panic!("not text: {other:?}"),
        })
        .collect()
}

/// A graph of the world: one `Tenant` per tenant, one `User` per principal,
/// one `Thing {arn, tenant, kind}` per resource — a `Map` for a map, a
/// `Layer`, an `Item`, a `Key`, a `Memo`, a `Place` — and the memos' edges.
fn graph(world: &world::World) -> GrafeoDB {
    let db = GrafeoDB::new_in_memory();
    let s = db.session();
    for tenant in [world::COMMONS, world::NORTH, world::SOUTH] {
        s.execute_with_params(
            "INSERT (:Tenant {id: $id})",
            HashMap::from([(
                "id".to_string(),
                Value::Int64(i64::try_from(tenant).unwrap()),
            )]),
        )
        .unwrap();
    }
    for principal in &world.principals {
        s.execute_with_params(
            "INSERT (:User {name: $name, tenant: $tenant})",
            HashMap::from([
                ("name".to_string(), text(principal.name)),
                (
                    "tenant".to_string(),
                    Value::Int64(i64::try_from(principal.tenant).unwrap()),
                ),
            ]),
        )
        .unwrap();
    }
    for arn in &world.universe {
        let path = arn.rsplit(':').next().unwrap();
        let kind = match path.split('/').next().unwrap() {
            "realm" if path.contains("/layer/") => "Layer",
            "realm" if path.contains("/map/") => "Map",
            "realm" => "Realm",
            "archive" => "Item",
            "key" => "Key",
            "memo" => "Memo",
            "place" => "Place",
            other => panic!("unknown kind {other}"),
        };
        s.execute_with_params(
            "INSERT (:Thing {arn: $arn, kind: $kind})",
            HashMap::from([
                ("arn".to_string(), text(arn)),
                ("kind".to_string(), text(kind)),
            ]),
        )
        .unwrap();
    }
    memos(&s);
    db
}

/// North's memos: `m1` about the soup recipe, in the oven's place; `m2`
/// about the secret note, in the oven's and the alpha map's places.
fn memos(s: &grafeo::Session) {
    let link = |memo: &str, edge: &str, target: &str| {
        s.execute_with_params(
            &format!(
                "MATCH (m:Thing {{arn: $m}}), (t:Thing {{arn: $t}}) INSERT (m)-[:{edge}]->(t)"
            ),
            HashMap::from([
                ("m".to_string(), text(&world::arn(world::NORTH, memo))),
                ("t".to_string(), text(&world::arn(world::NORTH, target))),
            ]),
        )
        .unwrap();
    };
    link("memo/m1", "ABOUT", "archive/house/recipe/soup");
    link("memo/m1", "IN", "place/tool/oven");
    link("memo/m2", "ABOUT", "archive/house/note/secret");
    link("memo/m2", "IN", "place/tool/oven");
    link("memo/m2", "IN", "place/map/alpha");
}

/// The rows the store keeps for a scope: `MATCH (n:Thing) WHERE <fragment>`.
fn keep(db: &GrafeoDB, scope: &Scope) -> Vec<String> {
    let fragment = arn_filter(scope, "n", "arn", "s").unwrap();
    rows(db, &fragment, "MATCH (n:Thing) WHERE {} RETURN n.arn")
}

fn rows(db: &GrafeoDB, fragment: &Fragment, query: &str) -> Vec<String> {
    let query = query.replace("{}", &fragment.text);
    let result = db
        .session()
        .execute_with_params(&query, params(&fragment.params))
        .unwrap_or_else(|e| panic!("{query}: {e}"));
    column(&result)
}

#[test]
fn the_graph_holds_the_world() {
    let world = world::World::standard();
    let db = graph(&world);
    let s = db.session();
    assert_eq!(
        s.execute("MATCH (t:Tenant) RETURN t.id")
            .unwrap()
            .rows()
            .len(),
        3
    );
    assert_eq!(
        s.execute("MATCH (u:User) RETURN u.name")
            .unwrap()
            .rows()
            .len(),
        7
    );
    assert_eq!(
        s.execute("MATCH (n:Thing) RETURN n.arn")
            .unwrap()
            .rows()
            .len(),
        world.universe.len()
    );
    let maps = s
        .execute("MATCH (n:Thing {kind: 'Map'}) RETURN n.arn")
        .unwrap();
    assert_eq!(maps.rows().len(), 4, "alpha and beta, north and south");
    let memos = s
        .execute("MATCH (m:Thing)-[:ABOUT]->(t:Thing) RETURN m.arn")
        .unwrap();
    assert_eq!(memos.rows().len(), 2);
}

#[test]
fn every_principal_and_action_holds_the_invariant_in_the_store() {
    let world = world::World::standard();
    let db = graph(&world);
    let verdicts = harness::check_translator(&world, |scope, _| keep(&db, scope));
    assert_eq!(verdicts.len(), 35);
    let owner = verdicts
        .iter()
        .find(|v| v.principal == "owner" && v.action == "atlas:ReadItem")
        .unwrap();
    assert_eq!(
        owner.kept.len(),
        21,
        "STARTS WITH on two tenant prefixes: north's 18, the commons' 3"
    );
    assert_eq!(
        owner.allowed.len(),
        20,
        "the commons' key is kept by the prefix, removed by the re-check"
    );
    let visitor = verdicts
        .iter()
        .find(|v| v.principal == "visitor" && v.action == "atlas:ReadItem")
        .unwrap();
    assert_eq!(
        visitor.kept.len(),
        18,
        "a pattern outside the subset, widened to its tenant prefix"
    );
    assert!(
        visitor.kept.iter().all(|a| a.contains(":200:")),
        "and nothing of another tenant"
    );
}

#[test]
fn an_exact_deny_narrows_in_the_store_a_wildcard_deny_after_it() {
    let world = world::World::standard();
    let db = graph(&world);
    let ctx = MatchContext {
        tenant: Some("100".into()),
        ..MatchContext::default()
    };
    let exact = |path: &str| format!("arn:wami:atlas:${{tenant}}:wami:1:{path}");
    let editor = harness::compile(
        &[world::document(vec![
            world::statement("Allow", &["*"], &[exact("realm/main/map/alpha/**")], None),
            world::statement(
                "Deny",
                &["*"],
                &[exact("realm/main/map/alpha/layer/two")],
                None,
            ),
        ])],
        "atlas:EditLayer",
        &ctx,
    );
    let kept = keep(&db, &editor);
    assert!(
        !kept.iter().any(|a| a.ends_with("alpha/layer/two")),
        "the literal deny is in the WHERE"
    );
    assert_eq!(kept.len(), 2, "map/alpha and layer/one, nothing of south");

    let reader = harness::scope_of(world.principal("reader"), "atlas:ReadItem");
    let kept = keep(&db, &reader);
    assert!(
        kept.iter()
            .any(|a| a.ends_with("archive/house/note/secret")),
        "the store cannot express `*/note/*`: kept"
    );
    let rechecked: Vec<&String> = kept.iter().filter(|a| reader.matches(a)).collect();
    assert!(
        !rechecked.iter().any(|a| a.ends_with("/note/secret")),
        "the re-check removes it"
    );
    assert_eq!(rechecked.len(), 4, "soup, bread, tide, stew");
}

#[test]
fn an_empty_scope_reads_no_row_and_tenants_never_mix() {
    let world = world::World::standard();
    let db = graph(&world);
    assert_eq!(keep(&db, &Scope::default()).len(), 0);
    assert_eq!(
        keep(
            &db,
            &harness::scope_of(world.principal("nobody"), "atlas:ReadItem")
        )
        .len(),
        0
    );
    for principal in &world.principals {
        for action in &world.actions {
            let kept = keep(&db, &harness::scope_of(principal, action));
            for arn in kept {
                let tenant: u64 = arn.split(':').nth(3).unwrap().parse().unwrap();
                assert!(
                    tenant == principal.tenant || tenant == world::COMMONS,
                    "{} {action} reached {arn}",
                    principal.name
                );
            }
        }
    }
}

#[test]
fn a_hostile_literal_travels_as_a_parameter() {
    let world = world::World::standard();
    let db = graph(&world);
    let hostile = world::arn(world::NORTH, "archive/house/note/it's) OR true OR (");
    db.session()
        .execute_with_params(
            "INSERT (:Thing {arn: $arn, kind: 'Item'})",
            HashMap::from([("arn".to_string(), text(&hostile))]),
        )
        .unwrap();
    let ctx = MatchContext {
        tenant: Some("100".into()),
        ..MatchContext::default()
    };
    let docs = [world::document(vec![world::statement(
        "Allow",
        &["*"],
        &[hostile.replace(":100:", ":${tenant}:")],
        None,
    )])];
    let scope = harness::compile(&docs, "atlas:ReadItem", &ctx);
    assert_eq!(keep(&db, &scope), [hostile]);
}

/// Two scopes in one query (a memo is read when its item is in the
/// `ReadItem` scope and each place it holds in is in the `ReadPlace` scope),
/// against the oracle on both.
#[test]
fn a_memo_is_read_through_two_scopes_in_one_query() {
    let world = world::World::standard();
    let db = graph(&world);
    let cases = [
        ("agent-key", vec!["memo/m1", "memo/m2"]),
        ("reader", vec![]),
        ("owner", vec!["memo/m1", "memo/m2"]),
    ];
    for (name, expected) in cases {
        let principal = world.principal(name);
        let items = harness::scope_of(principal, "atlas:ReadItem");
        let places = harness::scope_of(principal, "atlas:Search");
        let i = arn_filter(&items, "t", "arn", "i").unwrap();
        let p = arn_filter(&places, "p", "arn", "p").unwrap();
        let query = format!(
            "MATCH (m:Thing {{kind: 'Memo'}})-[:ABOUT]->(t:Thing) WHERE {} \
             AND NOT EXISTS {{ MATCH (m)-[:IN]->(p:Thing) WHERE NOT ({}) }} RETURN m.arn",
            i.text, p.text
        );
        let mut all = params(&i.params);
        all.extend(params(&p.params));
        let result = db
            .session()
            .execute_with_params(&query, all)
            .unwrap_or_else(|e| panic!("{query}: {e}"));
        let mut kept = column(&result);
        kept.sort();
        let mut expected: Vec<String> = expected
            .into_iter()
            .map(|m| world::arn(world::NORTH, m))
            .collect();
        expected.sort();
        assert_eq!(kept, expected, "{name}");
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn random_policies_hold_the_invariant_in_the_store(case in arbitrary::case()) {
        let world = world::World::standard();
        let db = graph(&world);
        harness::check_case(&case, &world.universe, |scope, _| keep(&db, scope));
    }
}
