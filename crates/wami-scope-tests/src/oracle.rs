//! The oracle: wami's own `authorize` on the world's store, asked one row at
//! a time — the only definition of "allowed". And the scope of a principal,
//! compiled from exactly the documents `authorize` reads
//! (`AuthorizationService::documents`).

use wami::service::auth::policy_evaluator::{evaluate_policy_document, PolicyEffect};
use wami::service::auth::PolicySource;
use wami::service::AuthorizationService;
use wami_core::arn::matching::MatchContext;
use wami_core::arn::WamiArn;
use wami_core::context::WamiContext;
use wami_core::error::AmiError;
use wami_core::types::PolicyDocument;
use wami_scope::Scope;

use crate::world::{Principal, World};

/// Whether `authorize` lets `principal` do `action` on `arn`.
///
/// # Panics
///
/// When the evaluator refuses to decide (an unreadable document, a context
/// naming no principal): the world is broken, not the translator.
pub async fn allows(world: &World, principal: &Principal, action: &str, arn: &str) -> bool {
    // The world's rows are canonical ARNs (`suite::canonical`): a parse
    // failure is a broken fixture, named without echoing the row.
    let resource: WamiArn = arn.parse().expect("a canonical ARN of the world");
    let decision = AuthorizationService::new(world.store())
        .authorize(world.context(principal), action, &resource)
        .await;
    let Ok(decision) = decision else {
        panic!(
            "{}: {action}: the evaluator refused to decide (an unreadable document, a context naming no principal): the world is broken",
            principal.name
        )
    };
    decision.is_allowed()
}

/// The rows of the universe `authorize` allows `principal` `action` on.
pub async fn allowed(world: &World, principal: &Principal, action: &str) -> Vec<String> {
    let mut rows = Vec::new();
    for arn in world.universe() {
        if allows(world, principal, action, &arn).await {
            rows.push(arn);
        }
    }
    rows
}

/// The scope of `principal` for `action`, compiled from the documents
/// `authorize` reads for it — the identity documents; a permissions
/// boundary is not compiled (it only narrows: the scope over-includes, is
/// `residual`, and the re-check pays), a missing boundary gives an empty
/// scope (the evaluator fails closed).
///
/// # Panics
///
/// When the documents cannot be read or compiled: the world is broken.
pub async fn scope_of(world: &World, principal: &Principal, action: &str) -> Scope {
    let ctx = world.context(principal);
    let documents = AuthorizationService::new(world.store())
        .documents(ctx)
        .await
        .unwrap_or_else(|e| panic!("{}: {e}", principal.name));
    assert!(!documents.root, "the world has no root principal");
    let bounded = match documents.boundary {
        wami::service::auth::Ceiling::Missing { .. } => {
            return Scope {
                action: action.to_string(),
                ..Scope::default()
            };
        }
        wami::service::auth::Ceiling::Document { .. } => true,
        wami::service::auth::Ceiling::None => false,
    };
    let identity: Vec<PolicyDocument> = documents.identity.into_iter().map(|(_, d)| d).collect();
    let mut scope = Scope::compile(&identity, action, &MatchContext::from(ctx))
        .unwrap_or_else(|e| panic!("{}: {e}", principal.name));
    // A boundary only narrows: the scope over-includes what it removes and
    // the re-check does real work — residual, as a condition makes it.
    scope.residual |= bounded;
    scope
}

/// [`scope_of`], fenced to what a service gives `principal`
/// ([`World::fence`]).
pub async fn fenced_scope_of(world: &World, principal: &Principal, action: &str) -> Scope {
    scope_of(world, principal, action)
        .await
        .fenced(&World::fence(principal))
}

/// Whether `arn` is within `principal`'s fence: the oracle of a fenced scope
/// is `authorize` and this.
#[must_use]
pub fn within_fence(principal: &Principal, arn: &str) -> bool {
    let parts: Vec<&str> = arn.split(':').collect();
    parts.len() >= 6
        && World::fence(principal)
            .iter()
            .any(|root| parts[3] == *root || parts[3].starts_with(&format!("{root}/")))
}

/// The evaluator on documents alone, for the property tests on random
/// policies (no store): any document that denies wins, else any that
/// allows, else nothing — as `authorize` combines the documents it read.
///
/// # Errors
///
/// What the evaluator refuses: an unreadable condition, or an `arn` that is
/// not one.
pub fn documents_allow(
    policies: &[PolicyDocument],
    action: &str,
    arn: &str,
    ctx: &WamiContext,
) -> Result<bool, AmiError> {
    let resource: WamiArn = arn.parse().map_err(|e| AmiError::InvalidParameter {
        message: format!("{arn:?}: {e}"),
    })?;
    let mut allowed = false;
    for (index, policy) in policies.iter().enumerate() {
        let source = PolicySource::UserInline {
            name: format!("policy-{index}"),
        };
        match evaluate_policy_document(policy, action, &resource, ctx, &source)? {
            Some(hit) if hit.effect == PolicyEffect::Deny => return Ok(false),
            Some(hit) if hit.effect == PolicyEffect::Allow => allowed = true,
            _ => {}
        }
    }
    Ok(allowed)
}
