//! The suite: what every store is held to, on every principal, every shape,
//! bare and fenced — and the proof that it would see a leak.
//!
//! For one principal and one shape, the suite compiles one scope per bound
//! name (the kind's read action), runs the store, and compares with the
//! reference run under the oracle: **every expected row was kept** (never
//! exclude), **every kept row that is admitted and judged is expected**
//! (the re-check is sound), and, when every scope is tight (no residual, no
//! pattern outside the compilable subset), **the kept rows are exactly the
//! expected ones** (narrow before answer). A count is held the same way: a
//! store may never count what the oracle hides.
//!
//! The table ([`expected`]) is the world written by hand: for each principal
//! and action, which resources `authorize` must allow. It is checked against
//! the oracle before anything else, so a world that drifted from its design
//! fails here, not in a translator.

use std::collections::{BTreeSet, HashMap};

use wami_core::arn::WamiArn;
use wami_scope::{Narrowing, Pattern, Scope};

use crate::oracle;
use crate::port::{Row, Shape, Store};
use crate::reference::Reference;
use crate::world::{Kind, Principal, Resource, World, ACME, LABS, MARKET, PARTNER, STRANGER};

/// Every row of `universe` as [`WamiArn`] displays it: the contract the
/// evaluator and the stores agree under.
///
/// # Panics
///
/// Naming the first row that is not an ARN, or not written as [`WamiArn`]
/// displays it (`0100` for `100`, a cloud ARN without its region).
pub fn canonical(universe: &[String]) {
    for row in universe {
        let parsed: WamiArn = row
            .parse()
            .unwrap_or_else(|e| panic!("{row}: not an ARN, outside the contract: {e}"));
        let displayed = parsed.to_string();
        assert!(
            &displayed == row,
            "{row}: not canonical (the evaluator reads it as {displayed}), outside the contract"
        );
    }
}

/// Whether a scope lowers exactly: nothing residual, every allow and every
/// deny a literal or a trailing tree (the fence always is). Then a store's
/// rows are the allowed rows, before any re-check.
#[must_use]
pub fn tight(scope: &Scope) -> bool {
    let exact = |p: &Pattern| p.is_literal() || p.trailing_tree().is_some();
    !scope.residual && scope.allow.iter().all(exact) && scope.deny.iter().all(exact)
}

/// The allowed rows of one principal, by action, as the oracle says.
pub struct Allowed {
    by_action: HashMap<&'static str, BTreeSet<String>>,
}

impl Allowed {
    /// Asks the oracle every read action of every kind, and every action of
    /// the table.
    pub async fn of(world: &World, principal: &Principal) -> Self {
        let mut by_action = HashMap::new();
        let actions: BTreeSet<&'static str> = Kind::ALL
            .iter()
            .map(|k| k.read_action())
            .chain(world.actions.iter().copied())
            .collect();
        for action in actions {
            let rows = oracle::allowed(world, principal, action).await;
            by_action.insert(action, rows.into_iter().collect());
        }
        Self { by_action }
    }

    /// Whether `arn` is allowed under `action`.
    #[must_use]
    pub fn allows(&self, action: &str, arn: &str) -> bool {
        self.by_action
            .get(action)
            .is_some_and(|rows| rows.contains(arn))
    }

    /// The rows allowed under `action`.
    #[must_use]
    pub fn rows(&self, action: &str) -> &BTreeSet<String> {
        static EMPTY: std::sync::OnceLock<BTreeSet<String>> = std::sync::OnceLock::new();
        self.by_action
            .get(action)
            .unwrap_or_else(|| EMPTY.get_or_init(BTreeSet::new))
    }
}

/// The scopes of `shape` for `principal`: one per bound name, under the
/// action reading its kind stands for; fenced to the service's fence when
/// `fenced`.
///
/// # Panics
///
/// As [`oracle::scope_of`]: the world is broken.
pub async fn narrowing_of(
    world: &World,
    principal: &Principal,
    shape: &Shape,
    fenced: bool,
) -> Narrowing {
    let mut narrowing = Narrowing::new();
    let returned = shape.returned();
    for (name, kind) in shape.bindings() {
        let scope = if fenced {
            oracle::fenced_scope_of(world, principal, kind.read_action()).await
        } else {
            oracle::scope_of(world, principal, kind.read_action()).await
        };
        narrowing = if returned.contains(&name) {
            narrowing.bind(name, scope)
        } else {
            narrowing.test(name, scope)
        }
        .expect("distinct names");
    }
    narrowing
}

/// What one check saw: for a store's own assertions once the invariant held.
#[derive(Debug, Clone)]
pub struct Verdict {
    /// The rows the store kept, before the re-check.
    pub kept: Vec<Row>,
    /// The rows the oracle expects.
    pub expected: Vec<Row>,
    /// Whether every scope was tight (then `kept == expected`).
    pub tight: bool,
}

fn action_of(shape: &Shape, name: &str) -> &'static str {
    shape
        .bindings()
        .into_iter()
        .find(|(n, _)| *n == name)
        .map_or_else(
            || panic!("{shape:?} binds no {name}"),
            |(_, kind)| kind.read_action(),
        )
}

/// Holds `store` to the invariant on `shape` for `principal`.
///
/// # Panics
///
/// Naming the principal, the shape and the row: a kept ARN outside the
/// universe; an expected row the store dropped (**the** failure); an
/// admitted and judged row the oracle does not expect; a count above the
/// oracle's; a tight narrowing whose kept rows are not exactly the expected.
pub async fn check(
    world: &World,
    store: &dyn Store,
    allowed: &Allowed,
    principal: &Principal,
    shape: &Shape,
    fenced: bool,
) -> Verdict {
    let who = format!(
        "{} on {shape:?}{}",
        principal.name,
        if fenced { " (fenced)" } else { "" }
    );
    let narrowing = narrowing_of(world, principal, shape, fenced).await;
    let oracle_keeps = |name: &str, arn: &str| {
        allowed.allows(action_of(shape, name), arn)
            && (!fenced || oracle::within_fence(principal, arn))
    };
    let mut reference = Reference::default();
    reference.load(world);
    let expected = reference.run_with(shape, &oracle_keeps);
    let kept = store.run(shape, &narrowing);

    let universe: BTreeSet<String> = world.universe().into_iter().collect();
    for row in &kept {
        for (_, arn) in &row.arns {
            assert!(
                universe.contains(arn),
                "{who}: kept {arn}, not in the universe"
            );
        }
    }
    let as_set = |rows: &[Row]| -> BTreeSet<Row> { rows.iter().cloned().collect() };
    let strip = |row: &Row| Row {
        arns: row.arns.clone(),
        count: None,
    };
    let kept_set: BTreeSet<Row> = kept.iter().map(strip).collect();
    for row in &expected {
        assert!(
            kept_set.contains(&strip(row)),
            "{who}: the oracle expects {row:?} and the store dropped it (narrowing: {narrowing})"
        );
    }
    let judged: Vec<Row> = kept
        .iter()
        .filter(|row| narrowing.admit(&row.pairs()))
        .filter(|row| row.arns.iter().all(|(n, a)| oracle_keeps(n, a)))
        .map(strip)
        .collect();
    let expected_stripped: Vec<Row> = expected.iter().map(strip).collect();
    // A tested name comes back in no row: when its scope is not tight, the
    // store may keep a row for a neighbour the oracle hides, and nothing can
    // re-check it — the suite asks only that nothing expected is missing.
    let tested_loose = narrowing
        .bindings()
        .iter()
        .any(|b| !b.returned && !tight(&b.scope));
    if tested_loose {
        for row in &expected_stripped {
            assert!(
                judged.contains(row),
                "{who}: the judged rows miss {row:?} (a tested name's scope is loose)"
            );
        }
    } else {
        assert_eq!(
            as_set(&judged),
            as_set(&expected_stripped),
            "{who}: the admitted and judged rows against the oracle"
        );
    }
    if matches!(shape, Shape::Count { .. }) {
        for row in &kept {
            let n = row.count.expect("a count");
            let m = expected
                .iter()
                .find(|e| e.arns == row.arns)
                .and_then(|e| e.count)
                .unwrap_or(0);
            assert!(n >= m, "{who}: {row:?} counts less than the oracle's {m}");
            if narrowing.is_exact() {
                assert_eq!(n, m, "{who}: {row:?} counts what the oracle hides");
            }
        }
    }
    if matches!(shape, Shape::OrderBy { .. }) && narrowing.is_exact() {
        assert_eq!(kept, expected, "{who}: the order, with the hidden rows out");
    }
    let tight_all = narrowing.bindings().iter().all(|b| tight(&b.scope));
    if tight_all {
        assert_eq!(
            kept_set,
            as_set(&expected_stripped),
            "{who}: every scope is tight, the store must keep exactly the allowed rows"
        );
        if matches!(shape, Shape::Count { .. }) {
            assert_eq!(as_set(&kept), as_set(&expected), "{who}: the counts");
        }
    }
    Verdict {
        kept,
        expected,
        tight: tight_all,
    }
}

/// The shapes the suite runs: every list, the edges a traversal follows,
/// two-edge paths, existence, counts, orderings, lookups by name.
#[must_use]
#[allow(clippy::too_many_lines)] // a table, not a procedure
pub fn shapes() -> Vec<Shape> {
    use Kind::{
        Bucket, Conversation, Diagram, DiagramVersion, Function, Key, Message, Object, Repo,
        Subscription, Thread, Topic,
    };
    let mut all: Vec<Shape> = Kind::ALL.iter().map(|k| Shape::List { kind: *k }).collect();
    let children = |parent, edge, child| Shape::Children {
        parent,
        edge,
        child,
    };
    all.extend([
        children(Bucket, "HOLDS", Conversation),
        children(Conversation, "HOLDS", Thread),
        children(Thread, "HOLDS", Message),
        children(Bucket, "HOLDS", Repo),
        children(Repo, "HOLDS", Object),
        children(Diagram, "HOLDS", DiagramVersion),
        children(Conversation, "CITES", Diagram),
        children(Function, "PUBLISHES", Topic),
        children(Topic, "HAS", Subscription),
        children(Subscription, "DELIVERS_TO", Function),
        children(Repo, "ENCRYPTED_WITH", Key),
        children(Object, "COPY_OF", Message),
        children(Function, "INDEXES", Repo),
        Shape::Path {
            first: Bucket,
            edge1: "HOLDS",
            middle: Conversation,
            edge2: "HOLDS",
            last: Thread,
        },
        Shape::Path {
            first: Conversation,
            edge1: "HOLDS",
            middle: Thread,
            edge2: "HOLDS",
            last: Message,
        },
        Shape::Path {
            first: Function,
            edge1: "PUBLISHES",
            middle: Topic,
            edge2: "HAS",
            last: Subscription,
        },
        Shape::Path {
            first: Bucket,
            edge1: "HOLDS",
            middle: Repo,
            edge2: "ENCRYPTED_WITH",
            last: Key,
        },
        Shape::Exists {
            kind: Conversation,
            edge: "HOLDS",
            target: Thread,
        },
        Shape::Exists {
            kind: Repo,
            edge: "ENCRYPTED_WITH",
            target: Key,
        },
        Shape::Exists {
            kind: Function,
            edge: "PUBLISHES",
            target: Topic,
        },
        Shape::Count {
            parent: Conversation,
            edge: "HOLDS",
            child: Thread,
        },
        Shape::Count {
            parent: Bucket,
            edge: "HOLDS",
            child: Conversation,
        },
        Shape::Count {
            parent: Topic,
            edge: "HAS",
            child: Subscription,
        },
        Shape::OrderBy {
            parent: Bucket,
            edge: "HOLDS",
            child: Conversation,
        },
        Shape::OrderBy {
            parent: Conversation,
            edge: "HOLDS",
            child: Thread,
        },
        Shape::Lookup {
            kind: Topic,
            suffix: "topic/alerts".into(),
        },
        Shape::Lookup {
            kind: Function,
            suffix: "function/report".into(),
        },
        Shape::Lookup {
            kind: Conversation,
            suffix: "conv/c1".into(),
        },
    ]);
    all
}

/// Holds `store` to the invariant on every principal and every shape, bare
/// and fenced, then proves it would see a leak ([`detector`]).
///
/// # Panics
///
/// As [`check`] and [`detector`]; and when the universe is outside the
/// contract ([`canonical`]).
pub async fn run_all(world: &World, store: &dyn Store) {
    canonical(&world.universe());
    for principal in &world.principals {
        let allowed = Allowed::of(world, principal).await;
        for shape in shapes() {
            for fenced in [false, true] {
                check(world, store, &allowed, principal, &shape, fenced).await;
            }
        }
    }
    detector(world, store).await;
}

/// The negative control: a traversal whose scope sits on the start node
/// only **leaks**, and the suite's own comparison sees it. The partner's
/// session on `conv-c1-reader` lists the threads of its conversation with
/// the child unbound: the denied sub-thread `t2` comes back, and a count of
/// threads counts it.
///
/// # Panics
///
/// When the leak is not visible: the suite could not catch one.
pub async fn detector(world: &World, store: &dyn Store) {
    let principal = world.principal("dave@conv-c1-reader");
    let allowed = Allowed::of(world, principal).await;
    let shape = Shape::Children {
        parent: Kind::Conversation,
        edge: "HOLDS",
        child: Kind::Thread,
    };
    let parent_only = Narrowing::new()
        .bind(
            "p",
            oracle::scope_of(world, principal, Kind::Conversation.read_action()).await,
        )
        .unwrap();
    let kept = store.run(&shape, &parent_only);
    let leaked: Vec<&Row> = kept
        .iter()
        .filter(|row| {
            row.arn("c")
                .is_some_and(|c| !allowed.allows(Kind::Thread.read_action(), c))
        })
        .collect();
    assert!(
        leaked
            .iter()
            .any(|row| row.arn("c").unwrap().ends_with("thread/t2")),
        "the detector: with the child unbound the denied thread t2 must leak, kept {kept:?}"
    );
    assert!(
        leaked.iter().all(|row| parent_only.admit(&row.pairs())),
        "an unbound name is not re-checked: that is the hole the binding closes"
    );
    let count = Shape::Count {
        parent: Kind::Conversation,
        edge: "HOLDS",
        child: Kind::Thread,
    };
    let counted = store.run(&count, &parent_only);
    assert!(
        counted.iter().any(|row| row.count == Some(2)),
        "the detector: a count with the child unbound counts the hidden thread: {counted:?}"
    );
    let bound = narrowing_of(world, principal, &count, false).await;
    let counted = store.run(&count, &bound);
    assert!(
        counted.iter().all(|row| row.count == Some(1)),
        "with the child bound the count is the oracle's: {counted:?}"
    );
}

/// The table: whether `authorize` must allow `principal` `action` on
/// `resource`, written by hand from the world's design (diagram #2 v13),
/// never from the policies' text.
///
/// # Panics
///
/// On a principal the table does not know: add its row.
#[must_use]
#[allow(clippy::too_many_lines)] // a table, not a procedure
pub fn expected(principal: &Principal, action: &str, resource: &Resource) -> bool {
    let path = resource
        .arn
        .rsplit(':')
        .next()
        .unwrap_or_default()
        .to_string();
    let tenant = resource.tenant;
    let service = resource.kind.service();
    let s3 = service == "s3";
    let under = |prefix: &str| path == prefix || path.starts_with(&format!("{prefix}/"));
    let atlas_tree = under("bucket/atlas");
    let c1_tree = under("bucket/atlas/conv/c1");
    let c1_t2 = under("bucket/atlas/conv/c1/thread/t2");
    let logs = under("bucket/logs");
    let s3_read = matches!(action, "s3:ListBucket" | "s3:GetObject");
    match principal.name {
        "alice" => match action {
            "s3:DeleteObject" => s3 && ((tenant == ACME && !logs) || tenant == LABS),
            a if a.starts_with("s3:") => s3 && (tenant == ACME || tenant == LABS),
            a => tenant == ACME && a.starts_with(service),
        },
        "bob" => match action {
            "s3:ListBucket" => s3 && tenant == ACME,
            "s3:GetObject" => s3 && (tenant == ACME || tenant == MARKET),
            "s3:PutObject" => tenant == ACME && c1_tree && !c1_t2,
            "s3:DeleteObject" => false,
            a => tenant == ACME && a.starts_with(service),
        },
        "carol" => match action {
            "s3:ListBucket" => s3 && tenant == ACME,
            "s3:GetObject" => s3 && tenant == ACME && !c1_t2,
            "lambda:GetFunction" => tenant == ACME && matches!(resource.kind, Kind::Function),
            _ => false,
        },
        "frank" => match action {
            "lambda:GetFunction" | "lambda:InvokeFunction" => tenant == LABS && service == "lambda",
            a if a.starts_with("s3:") => {
                s3 && (tenant == LABS || (s3_read && tenant == ACME && c1_tree))
            }
            _ => false,
        },
        "dave" => match action {
            "sns:GetTopicAttributes" | "sns:Publish" => tenant == PARTNER && service == "sns",
            "lambda:GetFunction" => tenant == PARTNER && service == "lambda",
            a if s3_read && a.starts_with("s3:") => {
                tenant == PARTNER && under("bucket/partner-drop")
            }
            _ => false,
        },
        "erin" => match action {
            "s3:ListBucket" => (tenant == ACME && atlas_tree) || (tenant == STRANGER && s3),
            "s3:GetObject" => {
                (tenant == ACME && atlas_tree)
                    || (tenant == STRANGER && s3)
                    || (tenant == MARKET && under("bucket/public-data"))
            }
            a if a.starts_with("s3:") => tenant == STRANGER && s3,
            _ => false,
        },
        "nobody" => false,
        "dave@conv-c1-reader" => match action {
            "s3:ListBucket" => tenant == ACME && (path == "bucket/atlas" || (c1_tree && !c1_t2)),
            "s3:GetObject" => tenant == ACME && c1_tree && !c1_t2,
            _ => false,
        },
        "dave@repo-r1-reader" => match action {
            a if s3_read && a.starts_with("s3:") => tenant == ACME && under("bucket/atlas/repo/r1"),
            "kms:Decrypt" | "kms:DescribeKey" => tenant == ACME && path == "key/r1",
            _ => false,
        },
        "bob@agent-bob" => match action {
            "s3:ListBucket" | "s3:GetObject" => tenant == ACME && atlas_tree,
            "s3:PutObject" => tenant == ACME && c1_tree && !c1_t2,
            "lambda:GetFunction" | "lambda:InvokeFunction" => {
                tenant == ACME && matches!(resource.kind, Kind::Function)
            }
            _ => false,
        },
        "report@alert-publisher" => {
            action == "sns:Publish" && tenant == PARTNER && path == "topic/alerts"
        }
        other => panic!("no expectation for {other}"),
    }
}

/// The table against the oracle: for every principal and action, the rows
/// `authorize` allows are the rows [`expected`] names; then the bare scope
/// agrees with the oracle (a superset when residual) and the fenced scope
/// with the oracle and the fence.
///
/// # Panics
///
/// Naming the principal, the action and the rows that differ.
pub async fn check_table(world: &World) {
    for principal in &world.principals {
        for action in &world.actions {
            let allowed: BTreeSet<String> = oracle::allowed(world, principal, action)
                .await
                .into_iter()
                .collect();
            let wanted: BTreeSet<String> = world
                .resources
                .iter()
                .filter(|r| expected(principal, action, r))
                .map(|r| r.arn.clone())
                .collect();
            assert_eq!(
                allowed, wanted,
                "{} {action}: authorize (left) against the table (right)",
                principal.name
            );
            let scope = oracle::scope_of(world, principal, action).await;
            let fenced = scope.fenced(&World::fence(principal));
            for arn in world.universe() {
                let is_allowed = allowed.contains(&arn);
                if scope.residual {
                    assert!(
                        scope.matches(&arn) || !is_allowed,
                        "{} {action}: the residual scope dropped {arn}",
                        principal.name
                    );
                } else {
                    assert_eq!(
                        scope.matches(&arn),
                        is_allowed,
                        "{} {action}: scope.matches({arn}) against authorize",
                        principal.name
                    );
                    assert_eq!(
                        fenced.matches(&arn),
                        is_allowed && oracle::within_fence(principal, &arn),
                        "{} {action}: the fenced scope on {arn}",
                        principal.name
                    );
                }
            }
        }
    }
}

/// The check of one random case on documents alone (no store), for the
/// property tests: `keep` is a store over `universe`; the scope compiled
/// from `policies` must keep every row the evaluator allows, and after the
/// re-check exactly those (a superset when residual).
///
/// # Panics
///
/// As [`check`], in the words of the documents' oracle.
pub fn check_documents_case<F>(case: &crate::arbitrary::Case, universe: &[String], mut keep: F)
where
    F: FnMut(&Scope, &[String]) -> Vec<String>,
{
    canonical(universe);
    let ctx = crate::arbitrary::context(case);
    let scope = Scope::compile(
        &case.policies,
        &case.action,
        &wami_core::arn::matching::MatchContext::from(&ctx),
    )
    .unwrap_or_else(|e| panic!("{}: {e}", case.principal));
    let allowed: Vec<String> = universe
        .iter()
        .filter(|arn| {
            oracle::documents_allow(&case.policies, &case.action, arn, &ctx)
                .unwrap_or_else(|e| panic!("{}: {} on {arn}: {e}", case.principal, case.action))
        })
        .cloned()
        .collect();
    let kept = keep(&scope, universe);
    let who = format!("{} {}", case.principal, case.action);
    for row in &kept {
        assert!(
            universe.contains(row),
            "{who}: kept {row}, not in the universe"
        );
    }
    for row in &allowed {
        assert!(
            kept.contains(row),
            "{who}: the evaluator allows {row} and the store dropped it (scope: {scope:?})"
        );
    }
    let mut rechecked: Vec<&String> = kept.iter().filter(|row| scope.matches(row)).collect();
    rechecked.sort();
    rechecked.dedup();
    let mut expected: Vec<&String> = allowed.iter().collect();
    expected.sort();
    if scope.residual {
        for row in &expected {
            assert!(
                rechecked.contains(row),
                "{who}: residual scope dropped {row}"
            );
        }
    } else {
        assert_eq!(rechecked, expected, "{who}: kept rows after the re-check");
    }
    for arn in universe {
        let is_allowed = allowed.contains(arn);
        if scope.residual {
            assert!(
                scope.matches(arn) || !is_allowed,
                "{who}: the residual scope drops {arn}"
            );
        } else {
            assert_eq!(
                scope.matches(arn),
                is_allowed,
                "{who}: scope.matches({arn})"
            );
        }
    }
}
