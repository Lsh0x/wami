//! Signing Certificate Builder

use super::model::*;
use chrono::Utc;
use uuid::Uuid;
use wami_core::arn::{ScopedName, Service, WamiArn};
use wami_core::context::WamiContext;
use wami_core::error::Result;

/// Build a new SigningCertificate resource with context-based identifiers
///
/// Its ARN takes the OWNER's tenant from `owner` — the key read from the
/// owner's stored record — never the caller's (wami 005): a credential minted
/// by a caller of one tenant for a user of another belongs to the user's.
#[allow(clippy::result_large_err)]
pub fn build_signing_certificate(
    owner: &ScopedName,
    certificate_body: String,
    context: &WamiContext,
) -> Result<SigningCertificate> {
    let certificate_id = Uuid::new_v4().to_string();

    // Build WAMI ARN using context
    let wami_arn = WamiArn::builder()
        .service(Service::Iam)
        .tenant_path(owner.tenant().clone())
        .wami_instance(context.instance_id())
        .resource("signing-certificate", &certificate_id)
        .build()?;

    Ok(SigningCertificate {
        owner: owner.clone(),
        certificate_id,
        certificate_body,
        status: CertificateStatus::Active,
        upload_date: Utc::now(),
        wami_arn,
        providers: Vec::new(),
    })
}
