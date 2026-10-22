//! Service-Specific Credential Builder

use super::model::*;
use chrono::Utc;
use uuid::Uuid;
use wami_core::arn::{ScopedName, Service, WamiArn};
use wami_core::context::WamiContext;
use wami_core::error::Result;

/// Build a new ServiceSpecificCredential resource with context-based identifiers
///
/// Its ARN takes the OWNER's tenant from `owner` — the key read from the
/// owner's stored record — never the caller's (wami 005): a credential minted
/// by a caller of one tenant for a user of another belongs to the user's.
#[allow(clippy::result_large_err)]
pub fn build_service_credential(
    owner: &ScopedName,
    service_name: String,
    context: &WamiContext,
) -> Result<ServiceSpecificCredential> {
    let credential_id = Uuid::new_v4().to_string();

    // Build WAMI ARN using context
    let wami_arn = WamiArn::builder()
        .service(Service::Iam)
        .tenant_path(owner.tenant().clone())
        .wami_instance(context.instance_id())
        .resource("service-credential", &credential_id)
        .build()?;

    // Generate service-specific password (for CodeCommit, IoT, etc.)
    let password = uuid::Uuid::new_v4().to_string().replace('-', "");

    let service_user_name = format!("{}-{}", owner.name(), &credential_id[..8]);

    Ok(ServiceSpecificCredential {
        owner: owner.clone(),
        service_name,
        service_user_name,
        service_password: Some(password),
        service_specific_credential_id: credential_id,
        status: "Active".to_string(),
        create_date: Utc::now(),
        wami_arn,
        providers: Vec::new(),
    })
}
