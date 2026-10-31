//! The evaluator as oracle: what "allowed" means, asked one row at a time.

use wami::service::auth::policy_evaluator::{evaluate_policy_document, PolicyEffect};
use wami::service::auth::PolicySource;
use wami_core::arn::WamiArn;
use wami_core::context::WamiContext;
use wami_core::error::AmiError;
use wami_core::types::PolicyDocument;

/// Whether `policies` let the caller of `ctx` do `action` on `arn`, as the
/// evaluator reads them: any document that denies wins, else any that allows,
/// else nothing. The documents are read as inline policies of the caller.
///
/// # Errors
///
/// What the evaluator refuses: an unreadable condition, or an `arn` that is
/// not one.
pub fn allows(
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
