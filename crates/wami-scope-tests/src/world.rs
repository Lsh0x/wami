//! The world the suite runs on: tenants, resources, the edges between them,
//! and the principals with their policies — loaded into a real wami store,
//! so the oracle is `authorize` itself.
//!
//! The world is a cloud account's shape, none of anatta's: S3-like buckets
//! holding directories (conversations, their threads, their messages;
//! diagrams, their versions, their current pointer; repositories, their
//! files), Lambda-like functions with versions, SNS-like topics with
//! subscriptions, KMS-like keys. Five tenants: `1` the marketplace (public
//! datasets), `100` acme (the organisation: alice admin, bob developer, carol
//! auditor), `100/7` acme-labs (a sub-tenant: frank), `200` partner (dave),
//! `300` stranger (erin, whose admin wrote a greedy policy; nobody, with no
//! policy). Shares are **trees**: a conversation shared to partner is a
//! directory and everything under it; a repository shared to an outside
//! user is a folder and its key. Same names in several tenants, prefixes of
//! one another, siblings a share must not reach: a leak is caught by name.
//!
//! Three facts of wami shape it: a session is judged on its role's documents
//! only, and `${tenant}` in them resolves from the *assumer's* key, so a role
//! meant for outsiders names its tenant literally; the trust policy is not
//! evaluated at assumption, so a session is built directly; a token is a
//! session on a role whose permissions boundary is the person's documents.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;
use wami::store::memory::InMemoryWamiStore;
use wami::store::traits::{GroupStore, PolicyStore, RoleStore, UserStore};
use wami::wami::identity::group::builder::build_group;
use wami::wami::identity::role::builder::build_role;
use wami::wami::identity::user::builder::build_user;
use wami::wami::policies::policy::builder::build_policy;
use wami::{Role, User};
use wami_core::arn::{ScopedName, Service, TenantPath, WamiArn};
use wami_core::context::{SessionInfo, WamiContext};

/// The wami instance every ARN of the world is in.
pub const INSTANCE: &str = "1";
/// The public tenant: datasets anyone may read when their policies name it,
/// and the tenant every service puts in its fence.
pub const MARKET: &str = "1";
/// The organisation.
pub const ACME: &str = "100";
/// A sub-tenant of the organisation.
pub const LABS: &str = "100/7";
/// A partner organisation.
pub const PARTNER: &str = "200";
/// A tenant with no relation to acme.
pub const STRANGER: &str = "300";

/// What a resource is, and the action reading it stands for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    /// A project: a bucket.
    Bucket,
    /// A conversation: a directory of a bucket.
    Conversation,
    /// A thread: a directory of a conversation.
    Thread,
    /// A message: an object of a thread.
    Message,
    /// A plain object (a file, a dataset, a log).
    Object,
    /// A repository: a folder of a bucket.
    Repo,
    /// A diagram: a directory of a bucket, a sibling of the conversations.
    Diagram,
    /// A version of a diagram.
    DiagramVersion,
    /// A diagram's current pointer: set by a person, never by a token.
    Current,
    /// A function.
    Function,
    /// A version of a function.
    FunctionVersion,
    /// A topic.
    Topic,
    /// A subscription of a topic.
    Subscription,
    /// A key: the second authority on a repository (source access).
    Key,
}

impl Kind {
    /// Every kind.
    pub const ALL: [Kind; 14] = [
        Kind::Bucket,
        Kind::Conversation,
        Kind::Thread,
        Kind::Message,
        Kind::Object,
        Kind::Repo,
        Kind::Diagram,
        Kind::DiagramVersion,
        Kind::Current,
        Kind::Function,
        Kind::FunctionVersion,
        Kind::Topic,
        Kind::Subscription,
        Kind::Key,
    ];

    /// The label a store files the kind under.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Kind::Bucket => "Bucket",
            Kind::Conversation => "Conversation",
            Kind::Thread => "Thread",
            Kind::Message => "Message",
            Kind::Object => "Object",
            Kind::Repo => "Repo",
            Kind::Diagram => "Diagram",
            Kind::DiagramVersion => "DiagramVersion",
            Kind::Current => "Current",
            Kind::Function => "Function",
            Kind::FunctionVersion => "FunctionVersion",
            Kind::Topic => "Topic",
            Kind::Subscription => "Subscription",
            Kind::Key => "Key",
        }
    }

    /// The action reading a resource of this kind stands for: the table a
    /// service keeps (`Action::on`), here the world's.
    #[must_use]
    pub fn read_action(self) -> &'static str {
        match self {
            Kind::Bucket | Kind::Repo | Kind::Diagram | Kind::Conversation | Kind::Thread => {
                "s3:ListBucket"
            }
            Kind::Message | Kind::Object | Kind::DiagramVersion | Kind::Current => "s3:GetObject",
            Kind::Function | Kind::FunctionVersion => "lambda:GetFunction",
            Kind::Topic => "sns:GetTopicAttributes",
            Kind::Subscription => "sns:ListSubscriptions",
            Kind::Key => "kms:DescribeKey",
        }
    }

    /// The service of the kind's ARNs.
    #[must_use]
    pub fn service(self) -> &'static str {
        match self {
            Kind::Function | Kind::FunctionVersion => "lambda",
            Kind::Topic | Kind::Subscription => "sns",
            Kind::Key => "kms",
            _ => "s3",
        }
    }
}

/// One resource of the world.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resource {
    /// Its ARN, as `WamiArn` displays it.
    pub arn: String,
    /// Its tenant.
    pub tenant: &'static str,
    /// What it is.
    pub kind: Kind,
    /// A store rule, not a right: an archived container hides its contents
    /// from every list.
    pub archived: bool,
}

/// One edge of the world's graph: what a traversal follows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Edge {
    /// The tail's ARN.
    pub from: String,
    /// `HOLDS`, `CITES`, `VERSION`, `TRIGGERED_BY`, `INDEXES`, `READS`,
    /// `PUBLISHES`, `HAS`, `DELIVERS_TO`, `COPY_OF`, `ENCRYPTED_WITH`.
    pub label: &'static str,
    /// The head's ARN.
    pub to: String,
}

/// Who a principal is to wami.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Who {
    /// A user, judged on its own documents and its groups'.
    User {
        /// Its name, in its tenant.
        name: &'static str,
    },
    /// A session: a user that assumed a role, judged on the role's documents
    /// only (within the role's permissions boundary when it has one).
    Session {
        /// The assumer.
        user: &'static str,
        /// The role, in its own tenant.
        role: &'static str,
    },
}

/// A principal the suite runs: every user, and every session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal {
    /// `alice`, `dave@conv-c1-reader`…
    pub name: &'static str,
    /// Who it is.
    pub who: Who,
    /// The tenant it is in at time t: its own, or the role's for a session.
    pub tenant: &'static str,
}

/// The store every service takes.
pub type Shared = Arc<RwLock<InMemoryWamiStore>>;

/// The world: its resources and edges, its principals, the store that holds
/// them, and each principal's context.
pub struct World {
    /// Every resource, canonical ARNs.
    pub resources: Vec<Resource>,
    /// Every edge.
    pub edges: Vec<Edge>,
    /// Every principal.
    pub principals: Vec<Principal>,
    /// The actions the table is written for.
    pub actions: Vec<&'static str>,
    store: Shared,
    contexts: HashMap<&'static str, WamiContext>,
}

/// `arn:wami:<service>:<tenant>:wami:1:<path>`.
#[must_use]
pub fn arn(service: &str, tenant: &str, path: &str) -> String {
    format!("arn:wami:{service}:{tenant}:wami:{INSTANCE}:{path}")
}

/// `arn:wami:<service>:${tenant}:wami:1:<path>`: a motif of the caller's own
/// tenant, the instance literal as the services write it.
#[must_use]
pub fn own(service: &str, path: &str) -> String {
    format!("arn:wami:{service}:${{tenant}}:wami:{INSTANCE}:{path}")
}

/// `arn:wami:<service>:<tenant>:wami:1:<path>`: a motif naming a tenant.
#[must_use]
pub fn of(service: &str, tenant: &str, path: &str) -> String {
    format!("arn:wami:{service}:{tenant}:wami:{INSTANCE}:{path}")
}

/// A policy document in JSON, as a store holds it.
#[must_use]
pub fn document(statements: &[serde_json::Value]) -> String {
    serde_json::json!({ "Version": "2012-10-17", "Statement": statements }).to_string()
}

/// An Allow statement.
#[must_use]
pub fn allow(actions: &[&str], resources: &[String]) -> serde_json::Value {
    serde_json::json!({ "Effect": "Allow", "Action": actions, "Resource": resources })
}

/// A Deny statement.
#[must_use]
pub fn deny(actions: &[&str], resources: &[String]) -> serde_json::Value {
    serde_json::json!({ "Effect": "Deny", "Action": actions, "Resource": resources })
}

/// A statement under the condition `aws:username` equals `name`.
#[must_use]
pub fn when_user(mut statement: serde_json::Value, name: &str) -> serde_json::Value {
    statement["Condition"] = serde_json::json!({ "StringEquals": { "aws:username": name } });
    statement
}

fn tenant_path(tenant: &str) -> TenantPath {
    TenantPath::new(
        tenant
            .split('/')
            .map(|s| s.parse().expect("a numeric tenant segment"))
            .collect(),
    )
}

fn seed(tenant: &str) -> WamiContext {
    let path = tenant_path(tenant);
    let caller = WamiArn::builder()
        .service(Service::Iam)
        .tenant_path(path.clone())
        .wami_instance(INSTANCE)
        .resource("user", "seed")
        .build()
        .expect("an ARN");
    WamiContext::builder()
        .instance_id(INSTANCE)
        .tenant_path(path)
        .caller_arn(caller)
        .is_root(false)
        .build()
        .expect("a context")
}

fn resource(kind: Kind, tenant: &'static str, path: &str) -> Resource {
    Resource {
        arn: arn(kind.service(), tenant, path),
        tenant,
        kind,
        archived: false,
    }
}

fn resources() -> Vec<Resource> {
    use Kind::{
        Bucket, Conversation, Current, Diagram, DiagramVersion, Function, FunctionVersion, Key,
        Message, Object, Repo, Subscription, Thread, Topic,
    };
    let mut all = vec![
        // the marketplace
        resource(Bucket, MARKET, "bucket/public-data"),
        resource(Object, MARKET, "bucket/public-data/catalog.json"),
        resource(Object, MARKET, "bucket/public-data/2026/prices.csv"),
        // acme: the project atlas, its conversations
        resource(Bucket, ACME, "bucket/atlas"),
        resource(Conversation, ACME, "bucket/atlas/conv/c1"),
        resource(Thread, ACME, "bucket/atlas/conv/c1/thread/t1"),
        resource(Message, ACME, "bucket/atlas/conv/c1/thread/t1/msg/1"),
        resource(Message, ACME, "bucket/atlas/conv/c1/thread/t1/msg/2"),
        resource(Thread, ACME, "bucket/atlas/conv/c1/thread/t2"),
        resource(Message, ACME, "bucket/atlas/conv/c1/thread/t2/msg/1"),
        resource(Conversation, ACME, "bucket/atlas/conv/c10"),
        resource(Thread, ACME, "bucket/atlas/conv/c10/thread/t1"),
        resource(Message, ACME, "bucket/atlas/conv/c10/thread/t1/msg/1"),
        resource(Conversation, ACME, "bucket/atlas/conv/c2"),
        resource(Thread, ACME, "bucket/atlas/conv/c2/thread/t1"),
        resource(Message, ACME, "bucket/atlas/conv/c2/thread/t1/msg/1"),
        // its diagrams, siblings of the conversations
        resource(Diagram, ACME, "bucket/atlas/diagram/d1"),
        resource(DiagramVersion, ACME, "bucket/atlas/diagram/d1/v/1"),
        resource(DiagramVersion, ACME, "bucket/atlas/diagram/d1/v/2"),
        resource(Current, ACME, "bucket/atlas/diagram/d1/current"),
        // its repositories, folders with their files
        resource(Repo, ACME, "bucket/atlas/repo/r1"),
        resource(Object, ACME, "bucket/atlas/repo/r1/src/main.rs"),
        resource(Repo, ACME, "bucket/atlas/repo/r2"),
        resource(Object, ACME, "bucket/atlas/repo/r2/src/lib.rs"),
        // a prefix trap of atlas, archived
        resource(Bucket, ACME, "bucket/atlas-archive"),
        resource(Conversation, ACME, "bucket/atlas-archive/conv/c9"),
        resource(
            Message,
            ACME,
            "bucket/atlas-archive/conv/c9/thread/t1/msg/1",
        ),
        // the logs
        resource(Bucket, ACME, "bucket/logs"),
        resource(Object, ACME, "bucket/logs/2026/10/31.log"),
        // functions, topics, keys
        resource(Function, ACME, "function/ingest"),
        resource(FunctionVersion, ACME, "function/ingest/version/3"),
        resource(Function, ACME, "function/report"),
        resource(Topic, ACME, "topic/alerts"),
        resource(Subscription, ACME, "topic/alerts/subscription/s1"),
        resource(Topic, ACME, "topic/billing"),
        resource(Key, ACME, "key/r1"),
        resource(Key, ACME, "key/r2"),
        // acme-labs
        resource(Bucket, LABS, "bucket/labs-data"),
        resource(Object, LABS, "bucket/labs-data/run-1.parquet"),
        resource(Function, LABS, "function/train"),
        // partner: same names as acme's
        resource(Bucket, PARTNER, "bucket/partner-drop"),
        resource(Object, PARTNER, "bucket/partner-drop/inbox.csv"),
        resource(Topic, PARTNER, "topic/alerts"),
        resource(Subscription, PARTNER, "topic/alerts/subscription/p1"),
        resource(Function, PARTNER, "function/report"),
        // stranger
        resource(Bucket, STRANGER, "bucket/erin-stuff"),
        resource(Object, STRANGER, "bucket/erin-stuff/x"),
    ];
    for r in &mut all {
        if r.arn.contains("bucket/atlas-archive") {
            r.archived = true;
        }
    }
    all
}

#[allow(clippy::too_many_lines)] // the world's edges, a table
fn edges() -> Vec<Edge> {
    let s3 = |tenant: &str, path: &str| arn("s3", tenant, path);
    let la = |tenant: &str, path: &str| arn("lambda", tenant, path);
    let sns = |tenant: &str, path: &str| arn("sns", tenant, path);
    let kms = |tenant: &str, path: &str| arn("kms", tenant, path);
    let e = |from: String, label: &'static str, to: String| Edge { from, label, to };
    let holds = |from: String, to: String| e(from, "HOLDS", to);
    vec![
        holds(
            s3(MARKET, "bucket/public-data"),
            s3(MARKET, "bucket/public-data/catalog.json"),
        ),
        holds(
            s3(MARKET, "bucket/public-data"),
            s3(MARKET, "bucket/public-data/2026/prices.csv"),
        ),
        holds(s3(ACME, "bucket/atlas"), s3(ACME, "bucket/atlas/conv/c1")),
        holds(
            s3(ACME, "bucket/atlas/conv/c1"),
            s3(ACME, "bucket/atlas/conv/c1/thread/t1"),
        ),
        holds(
            s3(ACME, "bucket/atlas/conv/c1/thread/t1"),
            s3(ACME, "bucket/atlas/conv/c1/thread/t1/msg/1"),
        ),
        holds(
            s3(ACME, "bucket/atlas/conv/c1/thread/t1"),
            s3(ACME, "bucket/atlas/conv/c1/thread/t1/msg/2"),
        ),
        holds(
            s3(ACME, "bucket/atlas/conv/c1"),
            s3(ACME, "bucket/atlas/conv/c1/thread/t2"),
        ),
        holds(
            s3(ACME, "bucket/atlas/conv/c1/thread/t2"),
            s3(ACME, "bucket/atlas/conv/c1/thread/t2/msg/1"),
        ),
        holds(s3(ACME, "bucket/atlas"), s3(ACME, "bucket/atlas/conv/c10")),
        holds(
            s3(ACME, "bucket/atlas/conv/c10"),
            s3(ACME, "bucket/atlas/conv/c10/thread/t1"),
        ),
        holds(
            s3(ACME, "bucket/atlas/conv/c10/thread/t1"),
            s3(ACME, "bucket/atlas/conv/c10/thread/t1/msg/1"),
        ),
        holds(s3(ACME, "bucket/atlas"), s3(ACME, "bucket/atlas/conv/c2")),
        holds(
            s3(ACME, "bucket/atlas/conv/c2"),
            s3(ACME, "bucket/atlas/conv/c2/thread/t1"),
        ),
        holds(
            s3(ACME, "bucket/atlas/conv/c2/thread/t1"),
            s3(ACME, "bucket/atlas/conv/c2/thread/t1/msg/1"),
        ),
        holds(
            s3(ACME, "bucket/atlas"),
            s3(ACME, "bucket/atlas/diagram/d1"),
        ),
        holds(
            s3(ACME, "bucket/atlas/diagram/d1"),
            s3(ACME, "bucket/atlas/diagram/d1/v/1"),
        ),
        holds(
            s3(ACME, "bucket/atlas/diagram/d1"),
            s3(ACME, "bucket/atlas/diagram/d1/v/2"),
        ),
        holds(
            s3(ACME, "bucket/atlas/diagram/d1"),
            s3(ACME, "bucket/atlas/diagram/d1/current"),
        ),
        e(
            s3(ACME, "bucket/atlas/conv/c1"),
            "CITES",
            s3(ACME, "bucket/atlas/diagram/d1"),
        ),
        holds(s3(ACME, "bucket/atlas"), s3(ACME, "bucket/atlas/repo/r1")),
        holds(
            s3(ACME, "bucket/atlas/repo/r1"),
            s3(ACME, "bucket/atlas/repo/r1/src/main.rs"),
        ),
        holds(s3(ACME, "bucket/atlas"), s3(ACME, "bucket/atlas/repo/r2")),
        holds(
            s3(ACME, "bucket/atlas/repo/r2"),
            s3(ACME, "bucket/atlas/repo/r2/src/lib.rs"),
        ),
        e(
            s3(ACME, "bucket/atlas/repo/r1"),
            "ENCRYPTED_WITH",
            kms(ACME, "key/r1"),
        ),
        e(
            s3(ACME, "bucket/atlas/repo/r2"),
            "ENCRYPTED_WITH",
            kms(ACME, "key/r2"),
        ),
        holds(
            s3(ACME, "bucket/atlas-archive"),
            s3(ACME, "bucket/atlas-archive/conv/c9"),
        ),
        holds(
            s3(ACME, "bucket/atlas-archive/conv/c9"),
            s3(ACME, "bucket/atlas-archive/conv/c9/thread/t1/msg/1"),
        ),
        holds(
            s3(ACME, "bucket/logs"),
            s3(ACME, "bucket/logs/2026/10/31.log"),
        ),
        e(
            la(ACME, "function/ingest"),
            "VERSION",
            la(ACME, "function/ingest/version/3"),
        ),
        e(
            la(ACME, "function/ingest"),
            "TRIGGERED_BY",
            s3(ACME, "bucket/atlas"),
        ),
        e(
            la(ACME, "function/ingest"),
            "INDEXES",
            s3(ACME, "bucket/atlas/repo/r1"),
        ),
        e(
            la(ACME, "function/ingest"),
            "INDEXES",
            s3(ACME, "bucket/atlas/repo/r2"),
        ),
        e(
            la(ACME, "function/report"),
            "READS",
            s3(ACME, "bucket/atlas/conv/c1"),
        ),
        e(
            la(ACME, "function/report"),
            "PUBLISHES",
            sns(ACME, "topic/alerts"),
        ),
        e(
            la(ACME, "function/report"),
            "PUBLISHES",
            sns(PARTNER, "topic/alerts"),
        ),
        e(
            sns(ACME, "topic/alerts"),
            "HAS",
            sns(ACME, "topic/alerts/subscription/s1"),
        ),
        e(
            sns(ACME, "topic/alerts/subscription/s1"),
            "DELIVERS_TO",
            la(ACME, "function/ingest"),
        ),
        e(
            sns(PARTNER, "topic/alerts"),
            "HAS",
            sns(PARTNER, "topic/alerts/subscription/p1"),
        ),
        e(
            sns(PARTNER, "topic/alerts/subscription/p1"),
            "DELIVERS_TO",
            la(ACME, "function/ingest"),
        ),
        holds(
            s3(LABS, "bucket/labs-data"),
            s3(LABS, "bucket/labs-data/run-1.parquet"),
        ),
        holds(
            s3(PARTNER, "bucket/partner-drop"),
            s3(PARTNER, "bucket/partner-drop/inbox.csv"),
        ),
        e(
            s3(PARTNER, "bucket/partner-drop/inbox.csv"),
            "COPY_OF",
            s3(ACME, "bucket/atlas/conv/c1/thread/t1/msg/1"),
        ),
        holds(
            s3(STRANGER, "bucket/erin-stuff"),
            s3(STRANGER, "bucket/erin-stuff/x"),
        ),
    ]
}

/// The policies, as the store holds them.
mod policies {
    use super::{allow, deny, document, of, own, when_user, ACME, MARKET, PARTNER};

    const S3_READ: [&str; 2] = ["s3:ListBucket", "s3:GetObject"];

    /// The members' attached policy (acme): every project is Team.
    pub fn members() -> String {
        document(&[
            allow(&S3_READ, &[own("s3", "bucket/*"), own("s3", "bucket/*/**")]),
            allow(
                &["lambda:GetFunction", "lambda:InvokeFunction"],
                &[own("lambda", "function/*"), own("lambda", "function/*/**")],
            ),
            allow(
                &[
                    "sns:GetTopicAttributes",
                    "sns:ListSubscriptions",
                    "sns:Publish",
                ],
                &[own("sns", "topic/*"), own("sns", "topic/*/**")],
            ),
            allow(&["kms:Decrypt", "kms:DescribeKey"], &[own("kms", "key/*")]),
            allow(&["sts:AssumeRole"], &[own("iam", "role/*")]),
        ])
    }

    /// The viewers' attached policy (acme): reads only.
    pub fn viewers() -> String {
        document(&[
            allow(&S3_READ, &[own("s3", "bucket/*"), own("s3", "bucket/*/**")]),
            allow(&["lambda:GetFunction"], &[own("lambda", "function/*")]),
        ])
    }

    /// alice, the admin: everything of her tenant per service, her direct
    /// sub-tenants, and the logs immutable.
    pub fn alice() -> String {
        document(&[
            allow(&["s3:*"], &[own("s3", "**")]),
            allow(&["lambda:*"], &[own("lambda", "**")]),
            allow(&["sns:*"], &[own("sns", "**")]),
            allow(&["kms:*"], &[own("kms", "**")]),
            allow(&["iam:*", "sts:*"], &[own("iam", "**")]),
            allow(
                &["s3:*"],
                &["arn:wami:s3:${tenant}/*:wami:*:**".to_string()],
            ),
            deny(&["s3:DeleteObject"], &[own("s3", "bucket/logs/**")]),
        ])
    }

    /// bob's own: the owner grant on the conversation he created (a tree),
    /// a locked sub-thread, the marketplace by name.
    pub fn bob() -> String {
        document(&[
            allow(
                &["s3:PutObject"],
                &[
                    own("s3", "bucket/atlas/conv/c1"),
                    own("s3", "bucket/atlas/conv/c1/**"),
                ],
            ),
            deny(
                &["s3:PutObject"],
                &[own("s3", "bucket/atlas/conv/c1/thread/t2/**")],
            ),
            allow(
                &["s3:GetObject"],
                &[of("s3", MARKET, "bucket/public-data/**")],
            ),
        ])
    }

    /// carol's own: the logs under a condition (residual), a wildcard deny
    /// on every t2 thread (left to the re-check), a conditioned deny that
    /// does not hold for her.
    pub fn carol() -> String {
        document(&[
            when_user(
                allow(&["s3:GetObject"], &[own("s3", "bucket/logs/**")]),
                "carol",
            ),
            deny(
                &["s3:GetObject"],
                &[own("s3", "bucket/*/conv/*/thread/t2/**")],
            ),
            when_user(
                deny(&["s3:GetObject"], &[own("s3", "bucket/logs/**")]),
                "someone-else",
            ),
        ])
    }

    /// frank, in the sub-tenant: everything of his, the parent's shared
    /// conversation by name.
    pub fn frank() -> String {
        document(&[
            allow(&["s3:*"], &[own("s3", "**")]),
            allow(&["lambda:*"], &[own("lambda", "**")]),
            allow(
                &S3_READ,
                &[
                    of("s3", ACME, "bucket/atlas/conv/c1"),
                    of("s3", ACME, "bucket/atlas/conv/c1/**"),
                ],
            ),
        ])
    }

    /// dave, at partner: his own, and the right to assume acme's roles.
    pub fn dave() -> String {
        document(&[
            allow(&["sns:*"], &[own("sns", "**")]),
            allow(&["lambda:GetFunction"], &[own("lambda", "**")]),
            allow(
                &S3_READ,
                &[
                    own("s3", "bucket/partner-drop"),
                    own("s3", "bucket/partner-drop/**"),
                ],
            ),
            allow(&["sts:AssumeRole"], &[of("iam", ACME, "role/*")]),
        ])
    }

    /// erin, a stranger: her admin named acme's bucket, and every tenant's
    /// public data.
    pub fn erin() -> String {
        document(&[
            allow(
                &S3_READ,
                &[
                    of("s3", ACME, "bucket/atlas"),
                    of("s3", ACME, "bucket/atlas/**"),
                ],
            ),
            allow(
                &["s3:GetObject"],
                &["arn:wami:s3:*:wami:*:bucket/public-data/**".to_string()],
            ),
            allow(&["s3:*"], &[own("s3", "bucket/erin-stuff/**")]),
        ])
    }

    /// acme's `conv-c1-reader`, assumed by partner's dave: the conversation
    /// tree, the container, a sub-thread denied. Literal tenant: `${tenant}`
    /// would resolve to the assumer's.
    pub fn conv_c1_reader() -> String {
        document(&[
            allow(&["s3:ListBucket"], &[of("s3", ACME, "bucket/atlas")]),
            allow(
                &S3_READ,
                &[
                    of("s3", ACME, "bucket/atlas/conv/c1"),
                    of("s3", ACME, "bucket/atlas/conv/c1/**"),
                ],
            ),
            deny(
                &["s3:*"],
                &[of("s3", ACME, "bucket/atlas/conv/c1/thread/t2/**")],
            ),
        ])
    }

    /// acme's `repo-r1-reader`, assumed by partner's dave: one repository
    /// and its key, never the other.
    pub fn repo_r1_reader() -> String {
        document(&[
            allow(
                &S3_READ,
                &[
                    of("s3", ACME, "bucket/atlas/repo/r1"),
                    of("s3", ACME, "bucket/atlas/repo/r1/**"),
                ],
            ),
            allow(
                &["kms:Decrypt", "kms:DescribeKey"],
                &[of("kms", ACME, "key/r1")],
            ),
        ])
    }

    /// acme's `agent-bob`, bob's token: builds in atlas, never sets a
    /// diagram's current; its boundary is bob's documents.
    pub fn agent_bob() -> String {
        document(&[
            allow(
                &["s3:ListBucket", "s3:GetObject", "s3:PutObject"],
                &[
                    of("s3", ACME, "bucket/atlas"),
                    of("s3", ACME, "bucket/atlas/**"),
                ],
            ),
            allow(
                &["lambda:GetFunction", "lambda:InvokeFunction"],
                &[of("lambda", ACME, "function/*")],
            ),
            deny(
                &["s3:PutObject"],
                &[of("s3", ACME, "bucket/*/diagram/*/current")],
            ),
        ])
    }

    /// The ceiling of bob's token: what bob himself holds (the members'
    /// document and his own, his deny included), as a managed policy.
    pub fn bob_ceiling() -> String {
        document(&[
            allow(
                &S3_READ,
                &[of("s3", ACME, "bucket/*"), of("s3", ACME, "bucket/*/**")],
            ),
            allow(
                &["s3:PutObject"],
                &[
                    of("s3", ACME, "bucket/atlas/conv/c1"),
                    of("s3", ACME, "bucket/atlas/conv/c1/**"),
                ],
            ),
            deny(
                &["s3:PutObject"],
                &[of("s3", ACME, "bucket/atlas/conv/c1/thread/t2/**")],
            ),
            allow(
                &["lambda:GetFunction", "lambda:InvokeFunction"],
                &[
                    of("lambda", ACME, "function/*"),
                    of("lambda", ACME, "function/*/**"),
                ],
            ),
        ])
    }

    /// partner's `alert-publisher`, assumed by acme's `report` function:
    /// one topic to publish to.
    pub fn alert_publisher() -> String {
        document(&[allow(
            &["sns:Publish"],
            &[of("sns", PARTNER, "topic/alerts")],
        )])
    }
}

struct Loaded {
    users: HashMap<&'static str, User>,
    roles: HashMap<&'static str, Role>,
}

#[allow(clippy::too_many_lines)] // the fixture, written once
async fn load(store: &Shared) -> Loaded {
    let mut s = store.write().await;
    let mut users = HashMap::new();
    let mut roles = HashMap::new();
    let user = |tenant: &str, name: &'static str| {
        build_user(
            &ScopedName::new(tenant_path(tenant), name),
            None,
            &seed(tenant),
        )
        .expect("a user")
    };
    // acme
    let members_doc = build_policy(
        "members".into(),
        policies::members(),
        None,
        None,
        None,
        &tenant_path(ACME),
        &seed(ACME),
    )
    .expect("a policy");
    let viewers_doc = build_policy(
        "viewers".into(),
        policies::viewers(),
        None,
        None,
        None,
        &tenant_path(ACME),
        &seed(ACME),
    )
    .expect("a policy");
    let ceiling = build_policy(
        "bob-ceiling".into(),
        policies::bob_ceiling(),
        None,
        None,
        None,
        &tenant_path(ACME),
        &seed(ACME),
    )
    .expect("a policy");
    for policy in [&members_doc, &viewers_doc, &ceiling] {
        s.create_policy(policy.clone()).await.expect("the policy");
    }
    let members = build_group(
        &ScopedName::new(tenant_path(ACME), "members"),
        None,
        &seed(ACME),
    )
    .expect("a group");
    let viewers = build_group(
        &ScopedName::new(tenant_path(ACME), "viewers"),
        None,
        &seed(ACME),
    )
    .expect("a group");
    s.create_group(members.clone()).await.expect("the group");
    s.create_group(viewers.clone()).await.expect("the group");
    s.attach_group_policy(&members.key(), &members_doc.arn)
        .await
        .expect("attached");
    s.attach_group_policy(&viewers.key(), &viewers_doc.arn)
        .await
        .expect("attached");

    for (tenant, name, own, group) in [
        (ACME, "alice", Some(policies::alice()), None),
        (ACME, "bob", Some(policies::bob()), Some(&members)),
        (ACME, "carol", Some(policies::carol()), Some(&viewers)),
        (ACME, "report", None, None),
        (LABS, "frank", Some(policies::frank()), None),
        (PARTNER, "dave", Some(policies::dave()), None),
        (STRANGER, "erin", Some(policies::erin()), None),
        (STRANGER, "nobody", None, None),
    ] {
        let u = user(tenant, name);
        s.create_user(u.clone()).await.expect("the user");
        if let Some(own) = own {
            s.put_user_policy(&u.key(), "own", own)
                .await
                .expect("its policy");
        }
        if let Some(group) = group {
            s.add_user_to_group(&group.key(), &u.key())
                .await
                .expect("the membership");
        }
        users.insert(name, u);
    }
    for (tenant, name, doc, boundary) in [
        (ACME, "conv-c1-reader", policies::conv_c1_reader(), None),
        (ACME, "repo-r1-reader", policies::repo_r1_reader(), None),
        (
            ACME,
            "agent-bob",
            policies::agent_bob(),
            Some(ceiling.arn.clone()),
        ),
        (
            PARTNER,
            "alert-publisher",
            policies::alert_publisher(),
            None,
        ),
    ] {
        let mut role = build_role(
            &ScopedName::new(tenant_path(tenant), name),
            r#"{"Version":"2012-10-17","Statement":[]}"#.into(),
            None,
            None,
            None,
            &seed(tenant),
        )
        .expect("a role");
        role.permissions_boundary = boundary;
        s.create_role(role.clone()).await.expect("the role");
        s.put_role_policy(&role.key(), "own", doc)
            .await
            .expect("its policy");
        roles.insert(name, role);
    }
    Loaded { users, roles }
}

fn context_of(loaded: &Loaded, principal: &Principal) -> WamiContext {
    let (user, role) = match &principal.who {
        Who::User { name } => (&loaded.users[name], None),
        Who::Session { user, role } => (&loaded.users[user], Some(&loaded.roles[role])),
    };
    let mut builder = WamiContext::builder()
        .instance_id(INSTANCE)
        .tenant_path(user.wami_arn.tenant_path.clone())
        .caller_arn(user.wami_arn.clone())
        .caller_key(user.key())
        .is_root(false);
    if let Some(role) = role {
        builder = builder.session_info(SessionInfo {
            session_token: format!("{}@{}", user.user_name, role.role_name),
            expiration: i64::MAX,
            assumed_role_arn: Some(role.wami_arn.clone()),
            assumed_role_key: Some(role.key()),
        });
    }
    builder.build().expect("a context")
}

fn principals() -> Vec<Principal> {
    let user = |name, tenant| Principal {
        name,
        who: Who::User { name },
        tenant,
    };
    let session = |name, user, role, tenant| Principal {
        name,
        who: Who::Session { user, role },
        tenant,
    };
    vec![
        user("alice", ACME),
        user("bob", ACME),
        user("carol", ACME),
        user("frank", LABS),
        user("dave", PARTNER),
        user("erin", STRANGER),
        user("nobody", STRANGER),
        session("dave@conv-c1-reader", "dave", "conv-c1-reader", ACME),
        session("dave@repo-r1-reader", "dave", "repo-r1-reader", ACME),
        session("bob@agent-bob", "bob", "agent-bob", ACME),
        session(
            "report@alert-publisher",
            "report",
            "alert-publisher",
            PARTNER,
        ),
    ]
}

/// The standard world's ARNs, without a store: for the property tests.
#[must_use]
pub fn static_universe() -> Vec<String> {
    resources().into_iter().map(|r| r.arn).collect()
}

impl World {
    /// The standard world, loaded into a fresh store.
    pub async fn standard() -> Self {
        let store: Shared = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let loaded = load(&store).await;
        let principals = principals();
        let contexts = principals
            .iter()
            .map(|p| (p.name, context_of(&loaded, p)))
            .collect();
        Self {
            resources: resources(),
            edges: edges(),
            principals,
            actions: vec![
                "s3:ListBucket",
                "s3:GetObject",
                "s3:PutObject",
                "s3:DeleteObject",
                "lambda:GetFunction",
                "lambda:InvokeFunction",
                "sns:GetTopicAttributes",
                "sns:Publish",
                "kms:Decrypt",
                "kms:DescribeKey",
            ],
            store,
            contexts,
        }
    }

    /// The store the world is loaded in: what `authorize` reads.
    #[must_use]
    pub fn store(&self) -> Shared {
        Arc::clone(&self.store)
    }

    /// Every resource's ARN: the universe a store holds.
    #[must_use]
    pub fn universe(&self) -> Vec<String> {
        self.resources.iter().map(|r| r.arn.clone()).collect()
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

    /// The context the evaluator judges `principal` in.
    #[must_use]
    pub fn context(&self, principal: &Principal) -> &WamiContext {
        &self.contexts[principal.name]
    }

    /// The resource of that ARN.
    ///
    /// # Panics
    ///
    /// When the world has none.
    #[must_use]
    pub fn resource(&self, arn: &str) -> &Resource {
        self.resources
            .iter()
            .find(|r| r.arn == arn)
            .unwrap_or_else(|| panic!("no resource {arn}"))
    }

    /// The resources of a kind.
    #[must_use]
    pub fn of_kind(&self, kind: Kind) -> Vec<&Resource> {
        self.resources.iter().filter(|r| r.kind == kind).collect()
    }

    /// The heads of the edges labelled `label` leaving `from`.
    #[must_use]
    pub fn out(&self, from: &str, label: &str) -> Vec<&Resource> {
        self.edges
            .iter()
            .filter(|e| e.from == from && e.label == label)
            .map(|e| self.resource(&e.to))
            .collect()
    }

    /// The tenants a service puts in `principal`'s fence: its tenant at time
    /// t and the public marketplace.
    #[must_use]
    pub fn fence(principal: &Principal) -> Vec<&'static str> {
        vec![principal.tenant, MARKET]
    }
}
