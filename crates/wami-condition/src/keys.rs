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

        // WAMI-specific - Multi-tenant keys
        "wami:TenantId" => Ok(context
            .tenant_id
            .map(|id| ConditionValue::String(id.to_string()))),
        "wami:PrincipalTenantId" => Ok(context
            .principal_tenant_id
            .map(|id| ConditionValue::String(id.to_string()))),
        "wami:ResourceTenantId" => Ok(context
            .resource_tenant_id
            .map(|id| ConditionValue::String(id.to_string()))),
        "wami:TenantName" => Ok(context.tenant_name.clone().map(ConditionValue::String)),
        "wami:TenantStatus" => Ok(context.tenant_status.clone().map(ConditionValue::String)),
        "wami:CrossTenantRequest" => Ok(context.cross_tenant_request.map(ConditionValue::Boolean)),

        // WAMI-specific - Multi-cloud keys
        "wami:Provider" => Ok(context.provider.clone().map(ConditionValue::String)),
        "wami:SourceProvider" => Ok(context.source_provider.clone().map(ConditionValue::String)),
        "wami:TargetProvider" => Ok(context.target_provider.clone().map(ConditionValue::String)),
        "wami:ProviderRegion" => Ok(context.provider_region.clone().map(ConditionValue::String)),
        "wami:CrossProviderRequest" => {
            Ok(context.cross_provider_request.map(ConditionValue::Boolean))
        }

        // WAMI-specific - Request/HTTP context keys (general purpose)
        "wami:RequestMethod" => Ok(context.request_method.clone().map(ConditionValue::String)),
        "wami:RequestProtocol" => Ok(context.request_protocol.clone().map(ConditionValue::String)),
        "wami:ApiVersion" => Ok(context.api_version.clone().map(ConditionValue::String)),
        "wami:RequestPath" => Ok(context.request_path.clone().map(ConditionValue::String)),
        "wami:RequestQuery" => Ok(context.request_query.clone().map(ConditionValue::String)),
        "wami:ContentType" => Ok(context.content_type.clone().map(ConditionValue::String)),
        "wami:AcceptHeader" => Ok(context.accept_header.clone().map(ConditionValue::String)),
        "wami:Origin" => Ok(context.origin.clone().map(ConditionValue::String)),
        "wami:Host" => Ok(context.host.clone().map(ConditionValue::String)),

        // WAMI-specific - Application context keys (general purpose)
        "wami:ApplicationId" => Ok(context.application_id.clone().map(ConditionValue::String)),
        "wami:ApplicationVersion" => Ok(context
            .application_version
            .clone()
            .map(ConditionValue::String)),
        "wami:ClientId" => Ok(context.client_id.clone().map(ConditionValue::String)),
        "wami:ClientType" => Ok(context.client_type.clone().map(ConditionValue::String)),
        "wami:DeviceId" => Ok(context.device_id.clone().map(ConditionValue::String)),
        "wami:DeviceType" => Ok(context.device_type.clone().map(ConditionValue::String)),
        "wami:Platform" => Ok(context.platform.clone().map(ConditionValue::String)),

        // WAMI-specific - Session & Security keys (general purpose)
        "wami:SessionId" => Ok(context.session_id.clone().map(ConditionValue::String)),
        "wami:SessionAge" => Ok(context
            .session_age
            .map(|age| ConditionValue::Number(age as f64))),
        "wami:AuthenticationMethod" => Ok(context
            .authentication_method
            .clone()
            .map(ConditionValue::String)),
        "wami:AuthenticationStrength" => Ok(context
            .authentication_strength
            .clone()
            .map(ConditionValue::String)),
        "wami:SessionRiskScore" => Ok(context.session_risk_score.map(ConditionValue::Number)),
        "wami:IpReputation" => Ok(context.ip_reputation.clone().map(ConditionValue::String)),
        "wami:SourceCountry" => Ok(context
            .geolocation_country
            .clone()
            .map(ConditionValue::String)),
        "wami:SourceCity" => Ok(context.geolocation_city.clone().map(ConditionValue::String)),
        "wami:VpnDetected" => Ok(context.vpn_detected.map(ConditionValue::Boolean)),
        "wami:ProxyDetected" => Ok(context.proxy_detected.map(ConditionValue::Boolean)),

        // WAMI-specific - Rate Limiting keys (general purpose)
        "wami:RequestsPerMinute" => Ok(context
            .requests_per_minute
            .map(|count| ConditionValue::Number(count as f64))),
        "wami:RequestsPerHour" => Ok(context
            .requests_per_hour
            .map(|count| ConditionValue::Number(count as f64))),
        "wami:RequestsPerDay" => Ok(context
            .requests_per_day
            .map(|count| ConditionValue::Number(count as f64))),
        "wami:QuotaRemaining" => Ok(context
            .quota_remaining
            .map(|remaining| ConditionValue::Number(remaining as f64))),
        "wami:QuotaLimit" => Ok(context
            .quota_limit
            .map(|limit| ConditionValue::Number(limit as f64))),
        "wami:BurstCapacityUsed" => Ok(context.burst_capacity_used.map(ConditionValue::Number)),

        // WAMI-specific - Observability keys (general purpose)
        "wami:RequestId" => Ok(context.request_id.clone().map(ConditionValue::String)),
        "wami:CorrelationId" => Ok(context.correlation_id.clone().map(ConditionValue::String)),
        "wami:TraceId" => Ok(context.trace_id.clone().map(ConditionValue::String)),
        "wami:SpanId" => Ok(context.span_id.clone().map(ConditionValue::String)),
        "wami:DebugModeEnabled" => Ok(context.debug_mode.map(ConditionValue::Boolean)),
        "wami:DryRunMode" => Ok(context.dry_run_mode.map(ConditionValue::Boolean)),

        // WAMI-specific - Data & Compliance keys (general purpose)
        "wami:ResourceDataClassification" => Ok(context
            .data_classification
            .clone()
            .map(ConditionValue::String)),
        "wami:DataResidencyRegion" => Ok(context
            .data_residency_region
            .clone()
            .map(ConditionValue::String)),
        "wami:EncryptionRequired" => Ok(context.encryption_required.map(ConditionValue::Boolean)),
        "wami:EncryptionAlgorithm" => Ok(context
            .encryption_algorithm
            .clone()
            .map(ConditionValue::String)),

        // Fallback to custom values
        _ => Ok(context.custom_values.get(key).cloned()),
    }
}
