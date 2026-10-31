//! A world to test scopes in: tenants, principals and what they reach.
//!
//! The service is `atlas`. A tenant has a realm (its workspace) holding maps
//! (its projects) and their layers; an archive of items by vendor and kind
//! (`recipe`, `chart`, `note`); keys; memos, each about an item and holding in
//! places. Tenant 1, `commons`, publishes an archive every tenant may read
//! when its policies say so. Two tenants, `north` (100) and `south` (200),
//! name their resources alike, so a scope that leaks across tenants is caught
//! by name.
//!
//! The principals are the shapes a service needs: an owner reaching
//! everything in its tenant plus the commons; an editor on one map, with a
//! literal deny inside it; a reader of the archive denied one kind by a
//! wildcard (a deny a store cannot push down); an agent key reading and
//! searching the archive, never the keys; an auditor whose statements carry
//! conditions (a residual scope); a visitor of the other tenant granted
//! everything of its own by a pattern outside the compilable subset.

use wami_core::arn::matching::MatchContext;
use wami_core::arn::{ScopedName, TenantPath, WamiArn};
use wami_core::context::WamiContext;
use wami_core::types::{PolicyDocument, PolicyStatement};

/// The service every ARN of the world is in.
pub const SERVICE: &str = "atlas";
/// The wami instance every ARN of the world is in.
pub const INSTANCE: &str = "1";
/// The shared tenant: its archive is readable by whoever is granted it.
pub const COMMONS: u64 = 1;
/// The first tenant.
pub const NORTH: u64 = 100;
/// The second tenant, naming its resources as the first does.
pub const SOUTH: u64 = 200;

/// One caller: a name, a tenant, and the policies that apply to it.
#[derive(Debug, Clone)]
pub struct Principal {
    /// Its name: `${principal}` and `aws:username`.
    pub name: &'static str,
    /// Its tenant: `${tenant}`.
    pub tenant: u64,
    /// The documents the evaluator reads for it.
    pub policies: Vec<PolicyDocument>,
}

/// The fixture: who, what they may do, and every resource there is.
#[derive(Debug, Clone)]
pub struct World {
    /// The callers.
    pub principals: Vec<Principal>,
    /// Every resource, as an ARN: what a store holds.
    pub universe: Vec<String>,
    /// The actions a scope is compiled for.
    pub actions: Vec<&'static str>,
}

/// An ARN of the world: `arn:wami:atlas:<tenant>:wami:1:<path>`.
#[must_use]
pub fn arn(tenant: u64, path: &str) -> String {
    format!("arn:wami:{SERVICE}:{tenant}:wami:{INSTANCE}:{path}")
}

/// A resource motif of the caller's own tenant: `arn:wami:atlas:${tenant}:wami:*:<path>`.
#[must_use]
pub fn own(path: &str) -> String {
    format!("arn:wami:{SERVICE}:${{tenant}}:wami:*:{path}")
}

/// A statement.
#[must_use]
pub fn statement(
    effect: &str,
    actions: &[&str],
    resources: &[String],
    condition: Option<serde_json::Value>,
) -> PolicyStatement {
    PolicyStatement {
        sid: None,
        effect: effect.into(),
        action: actions.iter().map(ToString::to_string).collect(),
        resource: resources.to_vec(),
        condition,
    }
}

/// A document.
#[must_use]
pub fn document(statements: Vec<PolicyStatement>) -> PolicyDocument {
    PolicyDocument {
        version: "2012-10-17".into(),
        statement: statements,
    }
}

/// The condition `aws:username` equals `name`: holds for that caller only.
#[must_use]
pub fn username_is(name: &str) -> serde_json::Value {
    serde_json::json!({ "StringEquals": { "aws:username": name } })
}

/// The caller's context, as the evaluator wants it: its ARN a user of its
/// tenant, its key carrying its name (so `${tenant}`, `${principal}` and
/// `aws:username` resolve).
///
/// # Panics
///
/// Never for a principal of this world.
#[must_use]
pub fn context(principal: &Principal) -> WamiContext {
    let caller: WamiArn = arn(principal.tenant, &format!("user/{}", principal.name))
        .parse()
        .expect("a well-formed ARN");
    WamiContext::builder()
        .caller_arn(caller)
        .caller_key(ScopedName::new(
            TenantPath::single(principal.tenant),
            principal.name,
        ))
        .build()
        .expect("a context of one tenant")
}

/// The caller's variables, as the evaluator derives them from its context.
#[must_use]
pub fn match_context(principal: &Principal) -> MatchContext {
    MatchContext::from(&context(principal))
}

/// The paths every tenant holds.
fn paths() -> Vec<&'static str> {
    vec![
        "realm/main",
        "realm/main/map/alpha",
        "realm/main/map/alpha/layer/one",
        "realm/main/map/alpha/layer/two",
        "realm/main/map/beta",
        "realm/main/map/beta/layer/one",
        "archive/house/recipe/soup",
        "archive/house/recipe/bread",
        "archive/house/chart/tide",
        "archive/house/note/secret",
        "archive/guild/recipe/stew",
        "archive/guild/note/draft",
        "key/k1",
        "key/k2",
        "memo/m1",
        "memo/m2",
        "place/map/alpha",
        "place/tool/oven",
    ]
}

fn universe() -> Vec<String> {
    let mut all: Vec<String> = [NORTH, SOUTH]
        .iter()
        .flat_map(|&tenant| paths().into_iter().map(move |path| arn(tenant, path)))
        .collect();
    all.push(arn(COMMONS, "archive/commons/recipe/porridge"));
    all.push(arn(COMMONS, "archive/commons/chart/stars"));
    all.push(arn(COMMONS, "key/k0"));
    all
}

fn owner() -> Principal {
    Principal {
        name: "owner",
        tenant: NORTH,
        policies: vec![document(vec![
            statement(
                "Allow",
                &["atlas:*"],
                &[
                    own("realm/**"),
                    own("archive/**"),
                    own("key/**"),
                    own("memo/**"),
                    own("place/**"),
                ],
                None,
            ),
            statement(
                "Allow",
                &["atlas:ReadItem", "atlas:Search"],
                &[format!(
                    "arn:wami:{SERVICE}:{COMMONS}:wami:*:archive/commons/**"
                )],
                None,
            ),
        ])],
    }
}

fn editor() -> Principal {
    Principal {
        name: "editor",
        tenant: NORTH,
        policies: vec![
            document(vec![statement(
                "Allow",
                &["atlas:Read*", "atlas:EditLayer"],
                &[own("realm/main"), own("realm/main/map/alpha/**")],
                None,
            )]),
            document(vec![statement(
                "Deny",
                &["atlas:*"],
                &[own("realm/main/map/alpha/layer/two")],
                None,
            )]),
        ],
    }
}

fn reader() -> Principal {
    Principal {
        name: "reader",
        tenant: NORTH,
        policies: vec![document(vec![
            statement("Allow", &["atlas:ReadItem"], &[own("archive/**")], None),
            statement(
                "Deny",
                &["atlas:ReadItem"],
                &[own("archive/*/note/*")],
                None,
            ),
        ])],
    }
}

fn agent_key() -> Principal {
    Principal {
        name: "agent-key",
        tenant: NORTH,
        policies: vec![document(vec![statement(
            "allow",
            &["atlas:ReadItem", "atlas:Search"],
            &[own("archive/**"), own("place/**")],
            None,
        )])],
    }
}

fn auditor() -> Principal {
    Principal {
        name: "auditor",
        tenant: NORTH,
        policies: vec![document(vec![
            statement(
                "Allow",
                &["atlas:ReadKey"],
                &[own("key/**")],
                Some(username_is("auditor")),
            ),
            statement(
                "Allow",
                &["atlas:ReadItem"],
                &[own("archive/house/**")],
                None,
            ),
            statement(
                "Deny",
                &["atlas:ReadItem"],
                &[own("archive/house/note/*")],
                Some(username_is("someone-else")),
            ),
        ])],
    }
}

fn visitor() -> Principal {
    Principal {
        name: "visitor",
        tenant: SOUTH,
        policies: vec![document(vec![statement(
            "Allow",
            &["atlas:ReadItem", "atlas:ListMaps"],
            &[format!("arn:wami:{SERVICE}:${{tenant}}:wami:*:**")],
            None,
        )])],
    }
}

fn nobody() -> Principal {
    Principal {
        name: "nobody",
        tenant: SOUTH,
        policies: vec![],
    }
}

impl World {
    /// The standard world: seven principals, two tenants and the commons,
    /// thirty-nine resources, five actions.
    #[must_use]
    pub fn standard() -> Self {
        Self {
            principals: vec![
                owner(),
                editor(),
                reader(),
                agent_key(),
                auditor(),
                visitor(),
                nobody(),
            ],
            universe: universe(),
            actions: vec![
                "atlas:ReadItem",
                "atlas:EditLayer",
                "atlas:ReadKey",
                "atlas:Search",
                "atlas:ListMaps",
            ],
        }
    }

    /// The principal of that name.
    ///
    /// # Panics
    ///
    /// When no principal has it.
    #[must_use]
    pub fn principal(&self, name: &str) -> &Principal {
        self.principals
            .iter()
            .find(|p| p.name == name)
            .unwrap_or_else(|| panic!("no principal {name}"))
    }
}
