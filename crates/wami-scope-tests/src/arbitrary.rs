//! Random policies, callers and ARNs, for the property tests: every shape
//! the evaluator reads, drawn from the world's vocabulary so that patterns
//! and resources meet often. These run on documents alone (no store): the
//! oracle is the evaluator on the documents given.

use proptest::prelude::*;
use wami_core::arn::{ScopedName, Service, TenantPath, WamiArn};
use wami_core::context::WamiContext;
use wami_core::types::{PolicyDocument, PolicyStatement};

use crate::port::Shape;
use crate::world::{self, Kind, World, ACME, INSTANCE, LABS, MARKET, PARTNER};

/// One case: a caller, its policies, the action asked.
#[derive(Debug, Clone)]
pub struct Case {
    /// The caller's name.
    pub principal: &'static str,
    /// The caller's tenant.
    pub tenant: &'static str,
    /// Its policies.
    pub policies: Vec<PolicyDocument>,
    /// The action a scope is compiled for.
    pub action: String,
}

const SEGMENTS: &[&str] = &[
    "bucket",
    "atlas",
    "conv",
    "c1",
    "c2",
    "c10",
    "thread",
    "t1",
    "t2",
    "msg",
    "1",
    "diagram",
    "d1",
    "v",
    "current",
    "repo",
    "r1",
    "r2",
    "src",
    "logs",
    "2026",
    "function",
    "ingest",
    "report",
    "topic",
    "alerts",
    "subscription",
    "s1",
    "key",
];

const ACTIONS: &[&str] = &[
    "s3:ListBucket",
    "s3:GetObject",
    "s3:PutObject",
    "lambda:GetFunction",
    "sns:Publish",
    "kms:Decrypt",
];

const ACTION_PATTERNS: &[&str] = &[
    "s3:ListBucket",
    "s3:GetObject",
    "s3:PutObject",
    "lambda:GetFunction",
    "sns:Publish",
    "kms:Decrypt",
    "s3:Get*",
    "s3:*",
    "lambda:*",
    "*",
    "other:*",
];

const SERVICES: &[&str] = &["s3", "lambda", "sns", "kms"];
const NAMES: &[&str] = &["alice", "bob", "dave"];

/// A path segment of the world's vocabulary.
pub fn segment() -> impl Strategy<Value = &'static str> {
    proptest::sample::select(SEGMENTS)
}

/// A tenant: the marketplace, acme, its sub-tenant or partner.
pub fn tenant() -> impl Strategy<Value = &'static str> {
    proptest::sample::select(&[MARKET, ACME, LABS, PARTNER][..])
}

/// A service of the world.
pub fn service() -> impl Strategy<Value = &'static str> {
    proptest::sample::select(SERVICES)
}

/// A resource path of two to five segments (an ARN needs `type/id`).
pub fn path() -> impl Strategy<Value = String> {
    proptest::collection::vec(segment(), 2..=5).prop_map(|segments| segments.join("/"))
}

/// A resource ARN of the world's vocabulary.
pub fn arn() -> impl Strategy<Value = String> {
    (service(), tenant(), path())
        .prop_map(|(service, tenant, path)| world::arn(service, tenant, &path))
}

/// A path segment of a motif: a word, `*`, or `${principal}`.
fn motif_segment() -> impl Strategy<Value = String> {
    prop_oneof![
        6 => segment().prop_map(str::to_string),
        3 => Just("*".to_string()),
        1 => Just("${principal}".to_string()),
    ]
}

/// The tenant part of a motif: a tenant, `${tenant}`, `${tenant}/*` or `*`.
fn motif_tenant() -> impl Strategy<Value = String> {
    prop_oneof![
        3 => tenant().prop_map(str::to_string),
        4 => Just("${tenant}".to_string()),
        1 => Just("${tenant}/*".to_string()),
        1 => Just("*".to_string()),
    ]
}

/// The service part of a motif: a service, `${service}` or `*`.
fn motif_service() -> impl Strategy<Value = String> {
    prop_oneof![
        6 => service().prop_map(str::to_string),
        1 => Just("${service}".to_string()),
        1 => Just("*".to_string()),
    ]
}

/// A resource motif as a statement writes it: every shape the glob reads —
/// `*` and `${…}` in any part, a trailing `/**`, a `**` within, the bare
/// `*` and `**`.
pub fn motif() -> impl Strategy<Value = String> {
    let body = (
        motif_service(),
        motif_tenant(),
        prop_oneof![Just("1".to_string()), Just("*".to_string())],
        proptest::collection::vec(motif_segment(), 1..=4),
        prop_oneof![
            5 => Just(""),
            3 => Just("/**"),
            1 => Just("/**/one"),
            1 => Just("/*"),
            1 => Just("**"),
            1 => Just("/**/"),
        ],
    )
        .prop_map(|(service, tenant, instance, segments, tail)| {
            format!(
                "arn:wami:{service}:{tenant}:wami:{instance}:{}{tail}",
                segments.join("/")
            )
        });
    prop_oneof![
        12 => body,
        1 => Just("*".to_string()),
        1 => Just("**".to_string()),
        1 => Just("arn:wami:s3:**".to_string()),
    ]
}

/// A statement: an effect in any case, up to three action patterns, up to
/// three motifs (none: a statement reaching nothing), and sometimes a
/// condition on `aws:username` — or an empty one, that always holds.
pub fn statement() -> impl Strategy<Value = PolicyStatement> {
    (
        prop_oneof![
            3 => Just("Allow"),
            2 => Just("Deny"),
            1 => Just("allow"),
            1 => Just("ALLOW"),
            1 => Just("DENY"),
        ],
        proptest::collection::vec(proptest::sample::select(ACTION_PATTERNS), 0..=3),
        proptest::collection::vec(motif(), 0..=3),
        prop_oneof![
            10 => Just(None),
            2 => proptest::sample::select(&["alice", "bob", "dave", "nobody"][..])
                .prop_map(|name| Some(serde_json::json!({ "StringEquals": { "aws:username": name } }))),
            1 => Just(Some(serde_json::json!({}))),
        ],
    )
        .prop_map(|(effect, actions, resources, condition)| PolicyStatement {
            sid: None,
            effect: effect.into(),
            action: actions.iter().map(ToString::to_string).collect(),
            resource: resources,
            condition,
        })
}

/// A document of one to three statements.
pub fn document() -> impl Strategy<Value = PolicyDocument> {
    proptest::collection::vec(statement(), 1..=3).prop_map(|statement| PolicyDocument {
        version: "2012-10-17".into(),
        statement,
    })
}

/// Zero to three documents.
pub fn policies() -> impl Strategy<Value = Vec<PolicyDocument>> {
    proptest::collection::vec(document(), 0..=3)
}

/// An action asked.
pub fn action() -> impl Strategy<Value = String> {
    proptest::sample::select(ACTIONS).prop_map(str::to_string)
}

/// A case: a caller of acme, its sub-tenant or partner, its policies, an
/// action.
pub fn case() -> impl Strategy<Value = Case> {
    (
        proptest::sample::select(NAMES),
        proptest::sample::select(&[ACME, LABS, PARTNER][..]),
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

/// A universe: a few ARNs of the vocabulary and the standard world's.
pub fn universe() -> impl Strategy<Value = Vec<String>> {
    proptest::collection::vec(arn(), 0..=8).prop_map(|extra| {
        let mut all = standard_universe();
        all.extend(extra);
        all.sort();
        all.dedup();
        all
    })
}

/// The standard world's ARNs, without its store (the data is static).
#[must_use]
pub fn standard_universe() -> Vec<String> {
    crate::world::static_universe()
}

/// The caller's context for a case: a user of its tenant, its key carrying
/// its name (so `${tenant}`, `${principal}` and `aws:username` resolve).
///
/// # Panics
///
/// Never for a case of this module.
#[must_use]
pub fn context(case: &Case) -> WamiContext {
    let tenant = TenantPath::new(
        case.tenant
            .split('/')
            .map(|s| s.parse().expect("a numeric tenant"))
            .collect(),
    );
    let caller = WamiArn::builder()
        .service(Service::Iam)
        .tenant_path(tenant.clone())
        .wami_instance(INSTANCE)
        .resource("user", case.principal)
        .build()
        .expect("an ARN");
    WamiContext::builder()
        .instance_id(INSTANCE)
        .tenant_path(tenant.clone())
        .caller_arn(caller)
        .caller_key(ScopedName::new(tenant, case.principal))
        .is_root(false)
        .build()
        .expect("a context")
}

/// A random query shape over `world`: a list or a lookup of any kind, or a
/// traversal along one or two of the world's edges, as children, existence,
/// a count, an ordering.
pub fn shape(world: &World) -> impl Strategy<Value = Shape> {
    let kinds: Vec<Kind> = Kind::ALL.to_vec();
    let edges = world.edge_kinds();
    let two: Vec<((Kind, &'static str, Kind), (Kind, &'static str, Kind))> = edges
        .iter()
        .flat_map(|a| {
            edges
                .iter()
                .filter(move |b| b.0 == a.2)
                .map(move |b| (*a, *b))
        })
        .collect();
    let one = proptest::sample::select(edges);
    let paths = proptest::sample::select(two);
    prop_oneof![
        2 => proptest::sample::select(kinds.clone()).prop_map(|kind| Shape::List { kind }),
        1 => (proptest::sample::select(kinds), proptest::sample::select(&["alerts", "report", "c1", "r1", "t1"][..]))
            .prop_map(|(kind, suffix)| Shape::Lookup { kind, suffix: suffix.to_string() }),
        3 => one.clone().prop_map(|(parent, edge, child)| Shape::Children { parent, edge, child }),
        2 => one.clone().prop_map(|(kind, edge, target)| Shape::Exists { kind, edge, target }),
        2 => one.clone().prop_map(|(parent, edge, child)| Shape::Count { parent, edge, child }),
        1 => one.prop_map(|(parent, edge, child)| Shape::OrderBy { parent, edge, child }),
        2 => paths.prop_map(|((first, edge1, middle), (_, edge2, last))| Shape::Path { first, edge1, middle, edge2, last }),
    ]
}

/// A principal of the world, by name.
pub fn principal(world: &World) -> impl Strategy<Value = &'static str> {
    proptest::sample::select(world.principals.iter().map(|p| p.name).collect::<Vec<_>>())
}
