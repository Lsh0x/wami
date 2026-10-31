//! Random policies, principals and ARNs, for the property tests: every
//! shape the evaluator reads, drawn from the world's vocabulary so that
//! patterns and resources meet often.

use proptest::prelude::*;
use wami_core::types::{PolicyDocument, PolicyStatement};

use super::world::{self, COMMONS, NORTH, SOUTH};

/// One case: a caller, its policies, the action asked.
#[derive(Debug, Clone)]
pub struct Case {
    /// The caller's name.
    pub principal: &'static str,
    /// The caller's tenant.
    pub tenant: u64,
    /// Its policies.
    pub policies: Vec<PolicyDocument>,
    /// The action a scope is compiled for.
    pub action: String,
}

const SEGMENTS: &[&str] = &[
    "realm", "main", "map", "alpha", "beta", "layer", "one", "two", "archive", "house", "guild",
    "commons", "recipe", "chart", "note", "soup", "bread", "tide", "secret", "stew", "draft",
    "key", "k1", "k2", "memo", "m1", "place", "tool", "oven",
];

const ACTIONS: &[&str] = &[
    "atlas:ReadItem",
    "atlas:EditLayer",
    "atlas:ReadKey",
    "atlas:Search",
    "atlas:ListMaps",
];

const ACTION_PATTERNS: &[&str] = &[
    "atlas:ReadItem",
    "atlas:EditLayer",
    "atlas:ReadKey",
    "atlas:Search",
    "atlas:ListMaps",
    "atlas:Read*",
    "atlas:Edit*",
    "atlas:*",
    "*",
    "other:*",
];

const NAMES: &[&str] = &["owner", "editor", "auditor"];

/// A path segment of the world's vocabulary.
pub fn segment() -> impl Strategy<Value = &'static str> {
    proptest::sample::select(SEGMENTS)
}

/// A tenant: the commons, north or south.
pub fn tenant() -> impl Strategy<Value = u64> {
    proptest::sample::select(&[COMMONS, NORTH, SOUTH][..])
}

/// A resource path of two to five segments (an ARN needs `type/id`).
pub fn path() -> impl Strategy<Value = String> {
    proptest::collection::vec(segment(), 2..=5).prop_map(|segments| segments.join("/"))
}

/// A resource ARN of the world.
pub fn arn() -> impl Strategy<Value = String> {
    (tenant(), path()).prop_map(|(tenant, path)| world::arn(tenant, &path))
}

/// A path segment of a motif: a word, `*`, or `${principal}`.
fn motif_segment() -> impl Strategy<Value = String> {
    prop_oneof![
        6 => segment().prop_map(str::to_string),
        3 => Just("*".to_string()),
        1 => Just("${principal}".to_string()),
    ]
}

/// The tenant part of a motif: a tenant, `${tenant}` or `*`.
fn motif_tenant() -> impl Strategy<Value = String> {
    prop_oneof![
        3 => tenant().prop_map(|t| t.to_string()),
        4 => Just("${tenant}".to_string()),
        1 => Just("*".to_string()),
    ]
}

/// A resource motif as a statement writes it: every shape the glob reads —
/// `*` and `${…}` in any part, a trailing `/**`, a `**` within, the bare
/// `*` and `**`.
pub fn motif() -> impl Strategy<Value = String> {
    let body = (
        motif_tenant(),
        prop_oneof![Just("1".to_string()), Just("*".to_string())],
        proptest::collection::vec(motif_segment(), 1..=4),
        prop_oneof![
            5 => Just(""),
            3 => Just("/**"),
            1 => Just("/**/one"),
            1 => Just("/*"),
        ],
    )
        .prop_map(|(tenant, instance, segments, tail)| {
            format!(
                "arn:wami:{}:{tenant}:wami:{instance}:{}{tail}",
                world::SERVICE,
                segments.join("/")
            )
        });
    prop_oneof![
        12 => body,
        1 => Just("*".to_string()),
        1 => Just("**".to_string()),
        1 => Just(format!("arn:wami:{}:**", world::SERVICE)),
    ]
}

/// A statement: an effect, one to three action patterns, one to three
/// motifs, and sometimes a condition on `aws:username`.
pub fn statement() -> impl Strategy<Value = PolicyStatement> {
    (
        prop_oneof![3 => Just("Allow"), 2 => Just("Deny"), 1 => Just("allow")],
        proptest::collection::vec(proptest::sample::select(ACTION_PATTERNS), 1..=3),
        proptest::collection::vec(motif(), 1..=3),
        prop_oneof![
            5 => Just(None),
            1 => proptest::sample::select(&["owner", "editor", "auditor", "nobody"][..])
                .prop_map(|name| Some(world::username_is(name))),
        ],
    )
        .prop_map(|(effect, actions, resources, condition)| {
            world::statement(effect, &actions, &resources, condition)
        })
}

/// A document of one to three statements.
pub fn document() -> impl Strategy<Value = PolicyDocument> {
    proptest::collection::vec(statement(), 1..=3).prop_map(world::document)
}

/// Zero to three documents.
pub fn policies() -> impl Strategy<Value = Vec<PolicyDocument>> {
    proptest::collection::vec(document(), 0..=3)
}

/// An action asked.
pub fn action() -> impl Strategy<Value = String> {
    proptest::sample::select(ACTIONS).prop_map(str::to_string)
}

/// A case: a caller of north or south, its policies, an action.
pub fn case() -> impl Strategy<Value = Case> {
    (
        proptest::sample::select(NAMES),
        proptest::sample::select(&[NORTH, SOUTH][..]),
        policies(),
        action(),
    )
        .prop_map(|(principal, tenant, policies, action)| Case {
            principal,
            tenant,
            policies,
            action,
        })
}

/// A universe: the world's, plus up to eight random ARNs.
pub fn universe() -> impl Strategy<Value = Vec<String>> {
    proptest::collection::vec(arn(), 0..=8).prop_map(|extra| {
        let mut all = world::World::standard().universe;
        all.extend(extra);
        all.sort();
        all.dedup();
        all
    })
}
