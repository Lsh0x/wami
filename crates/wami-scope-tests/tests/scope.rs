//! The scope against the oracle: the table, the suite on the in-memory
//! reference (the scope is itself a translator: the one every store
//! re-checks with), the named sharing scenarios, and random policies.

use proptest::prelude::*;
use wami_core::arn::matching::MatchContext;
use wami_scope::{NotCompilable, Pattern, Scope};
use wami_scope_tests::port::{Shape, Store};
use wami_scope_tests::reference::Reference;
use wami_scope_tests::world::{arn, Kind, World, ACME, LABS, MARKET, PARTNER};
use wami_scope_tests::{arbitrary, oracle, suite};

/// The simplest store: it keeps what the scope matches.
fn by_matches(scope: &Scope, universe: &[String]) -> Vec<String> {
    universe
        .iter()
        .filter(|a| scope.matches(a))
        .cloned()
        .collect()
}

/// A store that filters on the lowered predicate, as every backend does
/// before the re-check.
fn by_predicate(scope: &Scope, universe: &[String]) -> Vec<String> {
    let lowered = scope.lower();
    universe
        .iter()
        .filter(|a| lowered.keeps(a))
        .cloned()
        .collect()
}

fn s3(tenant: &str, path: &str) -> String {
    arn("s3", tenant, path)
}

#[tokio::test]
async fn the_table_is_the_world_and_the_scope_is_the_oracle() {
    let world = World::standard().await;
    suite::check_table(&world).await;
}

#[tokio::test]
async fn the_reference_store_holds_the_invariant_on_every_principal_and_shape() {
    let world = World::standard().await;
    let mut reference = Reference::default();
    reference.load(&world);
    suite::run_all(&world, &reference).await;
}

#[tokio::test]
async fn a_conversation_shared_to_partner_is_a_tree_and_nothing_beside_it() {
    let world = World::standard().await;
    let session = world.principal("dave@conv-c1-reader");
    let himself = world.principal("dave");
    let read = oracle::scope_of(&world, session, "s3:GetObject").await;
    assert!(read.matches(&s3(ACME, "bucket/atlas/conv/c1/thread/t1/msg/1")));
    assert!(
        read.matches(&s3(ACME, "bucket/atlas/conv/c1")),
        "the directory itself"
    );
    assert!(
        !read.matches(&s3(ACME, "bucket/atlas/conv/c1/thread/t2/msg/1")),
        "the denied sub-thread"
    );
    assert!(
        !read.matches(&s3(ACME, "bucket/atlas/conv/c10/thread/t1/msg/1")),
        "the prefix trap"
    );
    assert!(
        !read.matches(&s3(ACME, "bucket/atlas/conv/c2/thread/t1/msg/1")),
        "a sibling conversation"
    );
    assert!(
        !read.matches(&s3(ACME, "bucket/atlas/diagram/d1/v/1")),
        "the cited diagram: linked, not shared"
    );
    assert!(
        oracle::scope_of(&world, himself, "s3:GetObject")
            .await
            .prefixes()
            .iter()
            .all(|p| p.contains(":200:")),
        "dave himself reaches nothing of acme"
    );
    let lowered = read.lower();
    assert!(
        !lowered.keeps(&s3(ACME, "bucket/atlas/conv/c1/thread/t2/msg/1")),
        "the sub-thread deny is exact: pushed down"
    );
    assert!(
        suite::tight(&read),
        "every pattern of the share is exact: the store lists exactly the share"
    );
    let list = oracle::scope_of(&world, session, "s3:ListBucket").await;
    assert!(
        list.matches(&s3(ACME, "bucket/atlas")),
        "the container, to list the share"
    );
    assert!(!list.matches(&s3(ACME, "bucket/atlas/repo/r1")));
}

#[tokio::test]
async fn one_repository_shared_to_an_outside_user_needs_its_key_too() {
    let world = World::standard().await;
    let session = world.principal("dave@repo-r1-reader");
    let read = oracle::scope_of(&world, session, "s3:GetObject").await;
    assert!(read.matches(&s3(ACME, "bucket/atlas/repo/r1/src/main.rs")));
    assert!(
        !read.matches(&s3(ACME, "bucket/atlas/repo/r2/src/lib.rs")),
        "the other repository of the same project"
    );
    let decrypt = oracle::scope_of(&world, session, "kms:Decrypt").await;
    assert!(decrypt.matches(&arn("kms", ACME, "key/r1")));
    assert!(!decrypt.matches(&arn("kms", ACME, "key/r2")));
    // two scopes in one query: the folder and its key
    let mut reference = Reference::default();
    reference.load(&world);
    let shape = Shape::Children {
        parent: Kind::Repo,
        edge: "ENCRYPTED_WITH",
        child: Kind::Key,
    };
    let narrowing = suite::narrowing_of(&world, session, &shape, false).await;
    let rows = reference.run(&shape, &narrowing);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].arn("c"), Some(arn("kms", ACME, "key/r1").as_str()));
}

#[tokio::test]
async fn a_token_is_a_session_within_its_persons_boundary() {
    let world = World::standard().await;
    let token = world.principal("bob@agent-bob");
    let bob = world.principal("bob");
    for action in ["s3:GetObject", "s3:PutObject", "lambda:InvokeFunction"] {
        let of_token = oracle::allowed(&world, token, action).await;
        let of_bob = oracle::allowed(&world, bob, action).await;
        assert!(
            of_token.iter().all(|a| of_bob.contains(a)),
            "{action}: the token exceeds bob: {of_token:?} vs {of_bob:?}"
        );
    }
    assert!(
        !oracle::allows(
            &world,
            token,
            "s3:PutObject",
            &s3(ACME, "bucket/atlas/diagram/d1/current")
        )
        .await,
        "a token never sets a current"
    );
    assert!(
        oracle::allows(
            &world,
            bob,
            "s3:GetObject",
            &s3(MARKET, "bucket/public-data/catalog.json")
        )
        .await
    );
    assert!(
        !oracle::allows(
            &world,
            token,
            "s3:GetObject",
            &s3(MARKET, "bucket/public-data/catalog.json")
        )
        .await,
        "the role names no marketplace: the session has what the role has, within the boundary"
    );
    let put = oracle::scope_of(&world, token, "s3:PutObject").await;
    assert!(
        put.matches(&s3(ACME, "bucket/atlas/conv/c2/thread/t1/msg/1")),
        "the scope is the role's: it over-includes what the boundary removes"
    );
    assert!(
        !oracle::allows(
            &world,
            token,
            "s3:PutObject",
            &s3(ACME, "bucket/atlas/conv/c2/thread/t1/msg/1")
        )
        .await,
        "and the re-check, through authorize, removes it"
    );
}

#[tokio::test]
async fn a_sub_tenant_reads_its_parents_share_by_name_and_the_admin_reaches_it_by_descent() {
    let world = World::standard().await;
    let frank = world.principal("frank");
    let read = oracle::scope_of(&world, frank, "s3:GetObject").await;
    assert!(read.matches(&s3(LABS, "bucket/labs-data/run-1.parquet")));
    assert!(
        read.matches(&s3(ACME, "bucket/atlas/conv/c1/thread/t1/msg/1")),
        "the parent's shared tree, by name"
    );
    assert!(!read.matches(&s3(ACME, "bucket/atlas/conv/c2/thread/t1/msg/1")));
    let fenced = read.fenced(&World::fence(frank));
    assert!(!fenced.matches(&s3(ACME, "bucket/atlas/conv/c1/thread/t1/msg/1")), "the fence of 100/7 does not hold 100: a service that shares the parent puts it in the fence");
    assert!(
        fenced
            .fenced(&[LABS, ACME])
            .matches(&s3(ACME, "bucket/atlas/conv/c1/thread/t1/msg/1"))
            || read
                .fenced(&[LABS, ACME])
                .matches(&s3(ACME, "bucket/atlas/conv/c1/thread/t1/msg/1"))
    );
    let alice = oracle::scope_of(&world, world.principal("alice"), "s3:GetObject").await;
    assert!(
        alice.matches(&s3(LABS, "bucket/labs-data/run-1.parquet")),
        "the descendants motif reaches the direct sub-tenant"
    );
    assert!(
        alice
            .fenced(&World::fence(world.principal("alice")))
            .matches(&s3(LABS, "bucket/labs-data/run-1.parquet")),
        "and the fence of 100 keeps its descendants"
    );
    assert!(!alice.matches(&s3("1007", "bucket/labs-data/run-1.parquet")));
}

#[tokio::test]
async fn the_strangers_greedy_policy_is_the_evaluators_and_the_fence_drops_it() {
    let world = World::standard().await;
    let erin = world.principal("erin");
    let read = oracle::scope_of(&world, erin, "s3:GetObject").await;
    let secret = s3(ACME, "bucket/atlas/conv/c2/thread/t1/msg/1");
    assert!(
        oracle::allows(&world, erin, "s3:GetObject", &secret).await,
        "authorize has one side: her admin's policy names acme"
    );
    assert!(
        read.matches(&secret),
        "so the bare scope keeps it: the invariant"
    );
    let fenced = read.fenced(&World::fence(erin));
    assert!(
        !fenced.matches(&secret),
        "the fence of 300 and the marketplace drops it"
    );
    assert!(
        fenced.matches(&s3(MARKET, "bucket/public-data/catalog.json")),
        "the tenant wildcard, rewritten by the fence to the marketplace"
    );
    assert!(!fenced.lower().keeps(&secret));
    assert_eq!(
        Pattern::compilable("arn:wami:s3:*:wami:*:bucket/public-data/**"),
        Err(NotCompilable::TenantWildcard(
            "arn:wami:s3:*:wami:*:bucket/public-data/**".into()
        ))
    );
}

#[tokio::test]
async fn acme_publishes_into_partner_by_a_role_and_reads_nothing_there() {
    let world = World::standard().await;
    let report = world.principal("report@alert-publisher");
    let publish = oracle::scope_of(&world, report, "sns:Publish").await;
    assert!(publish.matches(&arn("sns", PARTNER, "topic/alerts")));
    assert!(
        !publish.matches(&arn("sns", ACME, "topic/alerts")),
        "the same name in acme is another topic"
    );
    assert!(oracle::scope_of(&world, report, "sns:GetTopicAttributes")
        .await
        .is_empty());
    let bob = world.principal("bob");
    assert!(
        !oracle::allows(
            &world,
            bob,
            "sns:GetTopicAttributes",
            &arn("sns", PARTNER, "topic/alerts")
        )
        .await,
        "bob follows the edge to partner's topic and may not read it"
    );
}

#[tokio::test]
async fn the_viewer_reads_through_her_group_and_her_denies_are_her_own() {
    let world = World::standard().await;
    let carol = world.principal("carol");
    let read = oracle::scope_of(&world, carol, "s3:GetObject").await;
    assert!(read.residual, "the logs under a condition");
    assert_eq!(
        read.deny.len(),
        1,
        "the wildcard deny; the conditioned one is dropped"
    );
    assert!(!read.matches(&s3(ACME, "bucket/atlas/conv/c1/thread/t2/msg/1")));
    assert!(
        read.lower()
            .keeps(&s3(ACME, "bucket/atlas/conv/c1/thread/t2/msg/1")),
        "a wildcard deny is left to the re-check"
    );
    assert!(
        oracle::allows(
            &world,
            carol,
            "s3:GetObject",
            &s3(ACME, "bucket/logs/2026/10/31.log")
        )
        .await,
        "the condition holds for carol"
    );
    let functions = oracle::scope_of(&world, carol, "lambda:GetFunction").await;
    assert!(functions.matches(&arn("lambda", ACME, "function/ingest")));
    assert!(
        !functions.matches(&arn("lambda", ACME, "function/ingest/version/3")),
        "function/* stops at the slash"
    );
}

#[tokio::test]
async fn nobody_lists_nothing_and_a_session_tenant_is_the_assumers_for_variables() {
    let world = World::standard().await;
    let nobody = world.principal("nobody");
    for action in &world.actions {
        assert!(oracle::scope_of(&world, nobody, action).await.is_empty());
    }
    // the wami fact the roles are written around: `${tenant}` in a role's
    // document resolves from the assumer's key, not the role's tenant
    let session = world.principal("dave@conv-c1-reader");
    let ctx = MatchContext::from(world.context(session));
    assert_eq!(
        ctx.tenant.as_deref(),
        Some(PARTNER),
        "a session on acme's role still resolves ${{tenant}} to dave's 200"
    );
    assert_eq!(ctx.principal.as_deref(), Some("dave"));
}

#[tokio::test]
async fn a_row_written_otherwise_is_outside_the_contract() {
    let universe = vec!["arn:wami:s3:0100:wami:1:bucket/atlas".to_string()];
    let got = std::panic::catch_unwind(|| suite::canonical(&universe));
    assert!(
        got.is_err(),
        "0100 is 100 to the evaluator and another text to a store"
    );
    let legacy = "arn:wami:s3:100:wami:1:aws:123:bucket/atlas";
    let parsed: wami_core::arn::WamiArn = legacy.parse().unwrap();
    assert_ne!(
        parsed.to_string(),
        legacy,
        "a legacy cloud ARN gains its region"
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Random policies, callers and resources: the scope is the evaluator's
    /// verdict when nothing is residual, and never excludes what it allows.
    #[test]
    fn the_scope_never_excludes_what_the_evaluator_allows(
        case in arbitrary::case(),
        universe in arbitrary::universe(),
    ) {
        suite::check_documents_case(&case, &universe, by_matches);
    }

    /// The lowering, on random policies: every allowed row passes the
    /// predicate.
    #[test]
    fn the_lowering_never_excludes_what_the_evaluator_allows(
        case in arbitrary::case(),
        universe in arbitrary::universe(),
    ) {
        suite::check_documents_case(&case, &universe, by_predicate);
    }

    /// A deny the lowering keeps (a literal, a `<literal>/**`) excludes
    /// exactly what its glob matches.
    #[test]
    fn an_exact_deny_lowers_to_exactly_its_glob(
        motif in arbitrary::motif(),
        rows in proptest::collection::vec(arbitrary::arn(), 1..=16),
    ) {
        use wami_core::types::{PolicyDocument, PolicyStatement};
        let statement = |effect: &str, resource: &str| PolicyStatement {
            sid: None, effect: effect.into(), action: vec!["*".into()], resource: vec![resource.into()], condition: None,
        };
        let docs = [PolicyDocument { version: "2012-10-17".into(), statement: vec![statement("Allow", "*"), statement("Deny", &motif)] }];
        let ctx = MatchContext { tenant: Some(ACME.into()), principal: Some("alice".into()), service: Some("s3".into()) };
        let scope = Scope::compile(&docs, "s3:GetObject", &ctx).unwrap();
        let deny = &scope.deny[0];
        let lowered = scope.lower();
        let exact = deny.is_literal() || deny.trailing_tree().is_some();
        for row in &rows {
            if exact {
                prop_assert_eq!(lowered.keeps(row), !deny.matches(row), "{} on {}", deny, row);
            } else {
                prop_assert!(lowered.keeps(row), "a wildcard deny is left to the re-check: {}", deny);
            }
        }
    }

    /// A fenced scope keeps exactly the rows of the bare scope that are in
    /// the fence, whatever the policies.
    #[test]
    fn a_fence_is_an_intersection(
        case in arbitrary::case(),
        rows in proptest::collection::vec(arbitrary::arn(), 1..=16),
    ) {
        let ctx = arbitrary::context(&case);
        let scope = Scope::compile(&case.policies, &case.action, &MatchContext::from(&ctx)).unwrap();
        let fence = [case.tenant, MARKET];
        let fenced = scope.fenced(&fence);
        let service = scope.service().to_string();
        for row in &rows {
            let parts: Vec<&str> = row.split(':').collect();
            let inside = parts[2] == service && fence.iter().any(|t| parts[3] == *t || parts[3].starts_with(&format!("{t}/")));
            prop_assert_eq!(fenced.matches(row), scope.matches(row) && inside, "{} fenced to {:?} on {}", scope.action, fence, row);
            prop_assert!(!fenced.lower().keeps(row) || scope.lower().keeps(row), "the fenced lowering keeps no more than the bare one");
        }
    }
}
