//! MfaDevice Builder

use super::model::MfaDevice;
use crate::provider::ProviderConfig;
use wami_core::arn::{ScopedName, Service, WamiArn};
use wami_core::context::WamiContext;
use wami_core::error::Result;

/// Build a new MfaDevice resource with context-based identifiers
///
/// Its ARN takes the OWNER's tenant from `owner` — the key read from the
/// owner's stored record — never the caller's (wami 005): a credential minted
/// by a caller of one tenant for a user of another belongs to the user's.
#[allow(clippy::result_large_err)]
pub fn build_mfa_device(
    owner: &ScopedName,
    serial_number: String,
    context: &WamiContext,
) -> Result<MfaDevice> {
    // Build WAMI ARN using context
    let wami_arn = WamiArn::builder()
        .service(Service::Iam)
        .tenant_path(owner.tenant().clone())
        .wami_instance(context.instance_id())
        .resource("mfa", &serial_number)
        .build()?;

    Ok(MfaDevice {
        owner: owner.clone(),
        serial_number,
        enable_date: chrono::Utc::now(),
        wami_arn,
        providers: Vec::new(),
    })
}

/// Add a provider configuration to an MfaDevice
pub fn add_provider_to_mfa_device(mut mfa_device: MfaDevice, config: ProviderConfig) -> MfaDevice {
    mfa_device.providers.push(config);
    mfa_device
}
