//! LoginProfile Builder

use super::model::LoginProfile;
use crate::provider::ProviderConfig;
use wami_core::arn::{ScopedName, Service, WamiArn};
use wami_core::context::WamiContext;
use wami_core::error::Result;

/// Build a new LoginProfile resource with context-based identifiers
///
/// Its ARN takes the OWNER's tenant from `owner` — the key read from the
/// owner's stored record — never the caller's (wami 005): a credential minted
/// by a caller of one tenant for a user of another belongs to the user's.
#[allow(clippy::result_large_err)]
pub fn build_login_profile(
    owner: &ScopedName,
    password_reset_required: bool,
    context: &WamiContext,
) -> Result<LoginProfile> {
    // Build WAMI ARN using context (login profile uses user ARN pattern)
    let wami_arn = WamiArn::builder()
        .service(Service::Iam)
        .tenant_path(owner.tenant().clone())
        .wami_instance(context.instance_id())
        .resource("user", owner.name())
        .build()?;

    Ok(LoginProfile {
        owner: owner.clone(),
        create_date: chrono::Utc::now(),
        password_reset_required,
        wami_arn,
        providers: Vec::new(),
    })
}

/// Update a LoginProfile resource
pub fn update_login_profile(
    mut login_profile: LoginProfile,
    password_reset_required: Option<bool>,
) -> LoginProfile {
    if let Some(reset_required) = password_reset_required {
        login_profile.password_reset_required = reset_required;
    }
    login_profile
}

/// Add a provider configuration to a LoginProfile
pub fn add_provider_to_login_profile(
    mut login_profile: LoginProfile,
    config: ProviderConfig,
) -> LoginProfile {
    login_profile.providers.push(config);
    login_profile
}
