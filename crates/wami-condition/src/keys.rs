//! Condition Key Resolution
//!
//! Resolves condition keys from the evaluation context.

use super::{ConditionContext, ConditionValue};
use crate::error::Result;

/// Get the value for a condition key from the context
#[allow(clippy::result_large_err)]
pub fn get_context_value(key: &str, context: &ConditionContext) -> Result<Option<ConditionValue>> {
    match key {
        // AWS Principal keys
        "aws:PrincipalArn" => Ok(context.principal_arn.clone().map(ConditionValue::String)),
        "aws:PrincipalAccount" => Ok(context
            .principal_account
            .clone()
            .map(ConditionValue::String)),
        "aws:PrincipalType" => Ok(context.principal_type.clone().map(ConditionValue::String)),
        "aws:username" => Ok(context.username.clone().map(ConditionValue::String)),
        "aws:userid" | "aws:userId" => Ok(context.userid.clone().map(ConditionValue::String)),

        // AWS Authentication keys
        "aws:MultiFactorAuthPresent" => Ok(context.mfa_present.map(ConditionValue::Boolean)),
        "aws:MultiFactorAuthAge" => Ok(context
            .mfa_age
            .map(|age| ConditionValue::Number(age as f64))),
        "aws:TokenIssueTime" => Ok(context
            .token_issue_time
            .map(|time| ConditionValue::String(time.to_rfc3339()))),
        "aws:SecureTransport" => Ok(context.secure_transport.map(ConditionValue::Boolean)),

        // AWS Network keys
        "aws:SourceIp" => Ok(context.source_ip.clone().map(ConditionValue::String)),
        "aws:SourceVpc" => Ok(context.source_vpc.clone().map(ConditionValue::String)),
        "aws:SourceVpce" => Ok(context.source_vpce.clone().map(ConditionValue::String)),

        // AWS Request context keys
        "aws:CurrentTime" => Ok(Some(ConditionValue::String(
            context.current_time.to_rfc3339(),
        ))),
        "aws:EpochTime" => Ok(Some(ConditionValue::Number(
            context.current_time.timestamp() as f64,
        ))),
        "aws:RequestedRegion" => Ok(context.requested_region.clone().map(ConditionValue::String)),
        "aws:Referer" => Ok(context.referer.clone().map(ConditionValue::String)),
        "aws:UserAgent" => Ok(context.user_agent.clone().map(ConditionValue::String)),

        // AWS Resource keys
        "aws:ResourceArn" => Ok(context.resource_arn.clone().map(ConditionValue::String)),
        "aws:ResourceAccount" => Ok(context.resource_account.clone().map(ConditionValue::String)),

        // AWS Tag keys
        "aws:TagKeys" => {
            if context.tag_keys.is_empty() {
                Ok(None)
            } else {
                Ok(Some(ConditionValue::Array(context.tag_keys.clone())))
            }
        }

        // Dynamic tag keys
        key if key.starts_with("aws:PrincipalTag/") => {
            let tag_key = &key["aws:PrincipalTag/".len()..];
            Ok(context
                .principal_tags
                .get(tag_key)
                .map(|v| ConditionValue::String(v.clone())))
        }
        key if key.starts_with("aws:ResourceTag/") => {
            let tag_key = &key["aws:ResourceTag/".len()..];
            Ok(context
                .resource_tags
                .get(tag_key)
                .map(|v| ConditionValue::String(v.clone())))
        }
        key if key.starts_with("aws:RequestTag/") => {
            let tag_key = &key["aws:RequestTag/".len()..];
            Ok(context
                .request_tags
                .get(tag_key)
                .map(|v| ConditionValue::String(v.clone())))
        }

        // WAMI-specific keys
        "wami:TenantId" => Ok(context
            .tenant_id
            .map(|id| ConditionValue::String(id.to_string()))),
        "wami:PrincipalTenantId" => Ok(context
            .principal_tenant_id
            .map(|id| ConditionValue::String(id.to_string()))),
        "wami:ResourceTenantId" => Ok(context
            .resource_tenant_id
            .map(|id| ConditionValue::String(id.to_string()))),
        "wami:Provider" => Ok(context.provider.clone().map(ConditionValue::String)),
        "wami:SourceProvider" => Ok(context.source_provider.clone().map(ConditionValue::String)),
        "wami:TargetProvider" => Ok(context.target_provider.clone().map(ConditionValue::String)),

        // Fallback to custom values
        _ => Ok(context.custom_values.get(key).cloned()),
    }
}
