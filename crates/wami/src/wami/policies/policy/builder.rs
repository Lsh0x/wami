//! Policy Builder

use super::model::Policy;
use crate::arn::{Service, TenantPath, WamiArn};
use crate::context::WamiContext;
use crate::error::Result;
use crate::provider::ProviderConfig;
use crate::types::Tag;
use uuid::Uuid;

/// Build a new Policy of `tenant`, in the context's instance.
///
/// The tenant is named by the request, never taken from the caller (wami 005):
/// its `wami_arn` records it, and that is the tenant a guard judges for every
/// later act on the policy. The AWS-format `arn` it is stored under carries no
/// tenant (wami 011).
#[allow(clippy::result_large_err, clippy::too_many_arguments)]
pub fn build_policy(
    policy_name: String,
    policy_document: String,
    path: Option<String>,
    description: Option<String>,
    tags: Option<Vec<Tag>>,
    tenant: &TenantPath,
    context: &WamiContext,
) -> Result<Policy> {
    let path = path.unwrap_or_else(|| "/".to_string());
    let policy_id = Uuid::new_v4().to_string();

    let wami_arn = WamiArn::builder()
        .service(Service::Iam)
        .tenant_path(tenant.clone())
        .wami_instance(context.instance_id())
        .resource("policy", &policy_id)
        .build()?;

    // Generate AWS-compatible ARN (for backward compatibility)
    let arn = format!(
        "arn:aws:iam::{}:policy{}/{}",
        context.instance_id(),
        if path == "/" { "" } else { &path },
        policy_name
    );

    Ok(Policy {
        policy_name,
        policy_id,
        arn,
        path,
        default_version_id: "v1".to_string(),
        policy_document,
        attachment_count: 0,
        permissions_boundary_usage_count: 0,
        is_attachable: true,
        description,
        create_date: chrono::Utc::now(),
        update_date: chrono::Utc::now(),
        tags: tags.unwrap_or_default(),
        wami_arn,
        providers: Vec::new(),
        tenant_id: Some(crate::wami::tenant::TenantId::from_path(tenant)),
    })
}

/// Update a Policy resource with new values
pub fn update_policy(
    mut policy: Policy,
    description: Option<String>,
    default_version_id: Option<String>,
) -> Policy {
    if let Some(desc) = description {
        policy.description = Some(desc);
    }
    if let Some(version_id) = default_version_id {
        policy.default_version_id = version_id;
    }
    policy.update_date = chrono::Utc::now();
    policy
}

/// Add a provider configuration to a Policy
pub fn add_provider_to_policy(mut policy: Policy, config: ProviderConfig) -> Policy {
    policy.providers.push(config);
    policy
}
