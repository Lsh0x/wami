//! `AuthorizationService::documents`: the documents the evaluator reads for a
//! caller, handed out parsed and in reading order, so a scope (wami 008) is
//! compiled from exactly what a row is judged on.

use std::sync::Arc;

use tokio::sync::RwLock;
use wami::service::auth::{Ceiling, PolicySource};
use wami::service::AuthorizationService;
use wami::store::memory::InMemoryWamiStore;
use wami::store::traits::{GroupStore, PolicyStore, RoleStore, UserStore};
use wami::wami::identity::group::builder::build_group;
use wami::wami::identity::role::builder::build_role;
use wami::wami::identity::user::builder::build_user;
use wami::wami::policies::policy::builder::build_policy;
use wami_core::arn::{ScopedName, TenantPath, WamiArn};
use wami_core::context::{SessionInfo, WamiContext};

const INSTANCE: &str = "docs";

fn allow(action: &str) -> String {
    format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Sid":"{action}","Effect":"Allow","Action":"{action}","Resource":"*"}}]}}"#
    )
}

fn seed(tenant: &TenantPath) -> WamiContext {
    let arn = WamiArn::builder()
        .service(wami_core::arn::Service::Iam)
        .tenant_path(tenant.clone())
        .wami_instance(INSTANCE)
        .resource("user", "seed")
        .build()
        .expect("an ARN");
    WamiContext::builder()
        .instance_id(INSTANCE)
        .tenant_path(tenant.clone())
        .caller_arn(arn)
        .is_root(false)
        .build()
        .expect("a context")
}

fn caller(user: &wami::User) -> WamiContext {
    WamiContext::builder()
        .instance_id(INSTANCE)
        .tenant_path(user.wami_arn.tenant_path.clone())
        .caller_arn(user.wami_arn.clone())
        .caller_key(user.key())
        .is_root(false)
        .build()
        .expect("a context")
}

fn sids(documents: &[(PolicySource, wami_core::types::PolicyDocument)]) -> Vec<String> {
    documents
        .iter()
        .map(|(_, d)| d.statement[0].sid.clone().unwrap_or_default())
        .collect()
}

#[tokio::test]
async fn a_users_documents_are_its_own_and_its_groups_sorted_the_boundary_apart() {
    let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
    let tenant = TenantPath::single(100);
    let ctx = seed(&tenant);
    let alice = {
        let mut s = store.write().await;
        let mut alice = build_user(&ScopedName::new(tenant.clone(), "alice"), None, &ctx).unwrap();
        let viewers_doc = build_policy(
            "viewers".into(),
            allow("s3:ListBucket"),
            None,
            None,
            None,
            &tenant,
            &ctx,
        )
        .unwrap();
        let ceiling = build_policy(
            "ceiling".into(),
            allow("s3:*"),
            None,
            None,
            None,
            &tenant,
            &ctx,
        )
        .unwrap();
        s.create_policy(viewers_doc.clone()).await.unwrap();
        s.create_policy(ceiling.clone()).await.unwrap();
        alice.permissions_boundary = Some(ceiling.arn.clone());
        s.create_user(alice.clone()).await.unwrap();
        s.put_user_policy(&alice.key(), "own", allow("s3:GetObject"))
            .await
            .unwrap();
        let viewers = build_group(&ScopedName::new(tenant.clone(), "viewers"), None, &ctx).unwrap();
        s.create_group(viewers.clone()).await.unwrap();
        s.attach_group_policy(&viewers.key(), &viewers_doc.arn)
            .await
            .unwrap();
        s.add_user_to_group(&viewers.key(), &alice.key())
            .await
            .unwrap();
        alice
    };
    let authz = AuthorizationService::new(store);
    let documents = authz.documents(&caller(&alice)).await.unwrap();
    assert!(!documents.root);
    assert_eq!(
        sids(&documents.identity),
        ["s3:GetObject", "s3:ListBucket"],
        "the user's inline document, then the group's, by PolicySource's order"
    );
    assert!(matches!(
        &documents.identity[1].0,
        PolicySource::GroupManaged { group, .. } if group == "viewers"
    ));
    match &documents.boundary {
        Ceiling::Document { source, document } => {
            assert!(matches!(source, PolicySource::PermissionsBoundary { .. }));
            assert_eq!(document.statement[0].sid.as_deref(), Some("s3:*"));
        }
        other => panic!("the boundary was not read: {other:?}"),
    }
}

#[tokio::test]
async fn a_session_has_the_roles_documents_only_and_root_has_none() {
    let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
    let partner = TenantPath::single(200);
    let acme = TenantPath::single(100);
    let (dave, role) = {
        let mut s = store.write().await;
        let dave = build_user(
            &ScopedName::new(partner.clone(), "dave"),
            None,
            &seed(&partner),
        )
        .unwrap();
        s.create_user(dave.clone()).await.unwrap();
        s.put_user_policy(&dave.key(), "own", allow("sns:Publish"))
            .await
            .unwrap();
        let role = build_role(
            &ScopedName::new(acme.clone(), "conv-c1-reader"),
            r#"{"Version":"2012-10-17","Statement":[]}"#.into(),
            None,
            None,
            None,
            &seed(&acme),
        )
        .unwrap();
        s.create_role(role.clone()).await.unwrap();
        s.put_role_policy(&role.key(), "share", allow("s3:GetObject"))
            .await
            .unwrap();
        (dave, role)
    };
    let authz = AuthorizationService::new(store);
    let session = WamiContext::builder()
        .instance_id(INSTANCE)
        .tenant_path(partner.clone())
        .caller_arn(dave.wami_arn.clone())
        .caller_key(dave.key())
        .session_info(SessionInfo {
            session_token: "session".into(),
            expiration: i64::MAX,
            assumed_role_arn: Some(role.wami_arn.clone()),
            assumed_role_key: Some(role.key()),
        })
        .build()
        .unwrap();
    let documents = authz.documents(&session).await.unwrap();
    assert_eq!(
        sids(&documents.identity),
        ["s3:GetObject"],
        "the role's, never dave's own"
    );
    assert!(matches!(documents.boundary, Ceiling::None));

    let root_arn: WamiArn = format!("arn:wami:iam:0:wami:{INSTANCE}:user/root")
        .parse()
        .unwrap();
    let root = WamiContext::builder()
        .instance_id(INSTANCE)
        .tenant_path(TenantPath::single(0))
        .caller_arn(root_arn)
        .is_root(true)
        .build()
        .unwrap();
    let documents = authz.documents(&root).await.unwrap();
    assert!(documents.root && documents.identity.is_empty());
}

#[tokio::test]
async fn a_missing_boundary_is_named_and_a_foreign_attachment_refuses_the_set() {
    let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
    let tenant = TenantPath::single(100);
    let ctx = seed(&tenant);
    let bob = {
        let mut s = store.write().await;
        let mut bob = build_user(&ScopedName::new(tenant.clone(), "bob"), None, &ctx).unwrap();
        bob.permissions_boundary = Some("arn:aws:iam::docs:policy/gone".into());
        s.create_user(bob.clone()).await.unwrap();
        s.put_user_policy(&bob.key(), "own", allow("s3:GetObject"))
            .await
            .unwrap();
        bob
    };
    let authz = AuthorizationService::new(store.clone());
    let documents = authz.documents(&caller(&bob)).await.unwrap();
    assert!(
        matches!(&documents.boundary, Ceiling::Missing { arn } if arn.ends_with("policy/gone")),
        "{:?}",
        documents.boundary
    );
    assert_eq!(sids(&documents.identity), ["s3:GetObject"]);

    let foreign = build_policy(
        "theirs".into(),
        allow("s3:*"),
        None,
        None,
        None,
        &TenantPath::single(200),
        &seed(&TenantPath::single(200)),
    )
    .unwrap();
    {
        let mut s = store.write().await;
        s.create_policy(foreign.clone()).await.unwrap();
        s.attach_user_policy(&bob.key(), &foreign.arn)
            .await
            .unwrap();
    }
    let got = authz.documents(&caller(&bob)).await;
    assert!(
        matches!(got, Err(wami_core::error::AmiError::UnreadablePolicy { .. })),
        "another tenant's policy attached: the whole set is refused, as authorize refuses it: {got:?}"
    );
}
