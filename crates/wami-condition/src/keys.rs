//! Condition Key Resolution
//!
//! Resolves condition keys from the evaluation context — and says, for each
//! key, the type of value it resolves to.
//!
//! The type is declared beside the resolver, in one table, so that a key
//! cannot be added without one: parse uses it to refuse an operator that
//! cannot compare the key (`StringEquals` on the Boolean `aws:SecureTransport`
//! used to parse and then read `false`, wami 001), and a test holds every
//! resolver to the type it declares.

use std::collections::HashMap;

use super::{ConditionContext, ConditionValue};
use crate::error::Result;

/// The type of value a declared condition key resolves to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// Free text.
    String,
    /// An ARN — text the `Arn*` operators compare.
    Arn,
    /// A number.
    Number,
    /// `true` or `false`.
    Boolean,
    /// An RFC 3339 date, carried as text.
    Date,
    /// An IP address, carried as text.
    Ip,
    /// A list of strings.
    StringList,
}

impl KeyType {
    /// The name an error gives this type, with its article.
    pub fn describe(self) -> &'static str {
        match self {
            KeyType::String => "a String",
            KeyType::Arn => "an ARN",
            KeyType::Number => "a Number",
            KeyType::Boolean => "a Boolean",
            KeyType::Date => "a Date",
            KeyType::Ip => "an IP address",
            KeyType::StringList => "a list of strings",
        }
    }
}

/// How a declared key is read from the context.
type Resolve = fn(&ConditionContext) -> Option<ConditionValue>;

/// Every declared key: its name, its type, how it is read.
const KEYS: &[(&str, KeyType, Resolve)] = &[
    ("aws:PrincipalArn", KeyType::Arn, |c| {
        c.principal_arn.clone().map(ConditionValue::String)
    }),
    ("aws:PrincipalAccount", KeyType::String, |c| {
        c.principal_account.clone().map(ConditionValue::String)
    }),
    ("aws:PrincipalType", KeyType::String, |c| {
        c.principal_type.clone().map(ConditionValue::String)
    }),
    ("aws:username", KeyType::String, |c| {
        c.username.clone().map(ConditionValue::String)
    }),
    ("aws:userid", KeyType::String, |c| {
        c.userid.clone().map(ConditionValue::String)
    }),
    ("aws:userId", KeyType::String, |c| {
        c.userid.clone().map(ConditionValue::String)
    }),
    ("aws:MultiFactorAuthPresent", KeyType::Boolean, |c| {
        c.mfa_present.map(ConditionValue::Boolean)
    }),
    ("aws:MultiFactorAuthAge", KeyType::Number, |c| {
        c.mfa_age.map(|age| ConditionValue::Number(age as f64))
    }),
    ("aws:TokenIssueTime", KeyType::Date, |c| {
        c.token_issue_time
            .map(|time| ConditionValue::String(time.to_rfc3339()))
    }),
    ("aws:SecureTransport", KeyType::Boolean, |c| {
        c.secure_transport.map(ConditionValue::Boolean)
    }),
    ("aws:SourceIp", KeyType::Ip, |c| {
        c.source_ip.clone().map(ConditionValue::String)
    }),
    ("aws:SourceVpc", KeyType::String, |c| {
        c.source_vpc.clone().map(ConditionValue::String)
    }),
    ("aws:SourceVpce", KeyType::String, |c| {
        c.source_vpce.clone().map(ConditionValue::String)
    }),
    ("aws:CurrentTime", KeyType::Date, |c| {
        Some(ConditionValue::String(c.current_time.to_rfc3339()))
    }),
    ("aws:EpochTime", KeyType::Number, |c| {
        Some(ConditionValue::Number(c.current_time.timestamp() as f64))
    }),
    ("aws:RequestedRegion", KeyType::String, |c| {
        c.requested_region.clone().map(ConditionValue::String)
    }),
    ("aws:Referer", KeyType::String, |c| {
        c.referer.clone().map(ConditionValue::String)
    }),
    ("aws:UserAgent", KeyType::String, |c| {
        c.user_agent.clone().map(ConditionValue::String)
    }),
    ("aws:ResourceArn", KeyType::Arn, |c| {
        c.resource_arn.clone().map(ConditionValue::String)
    }),
    ("aws:ResourceAccount", KeyType::String, |c| {
        c.resource_account.clone().map(ConditionValue::String)
    }),
    ("aws:TagKeys", KeyType::StringList, |c| {
        (!c.tag_keys.is_empty()).then(|| ConditionValue::Array(c.tag_keys.clone()))
    }),
    ("wami:TenantId", KeyType::String, |c| {
        c.tenant_id.map(|id| ConditionValue::String(id.to_string()))
    }),
    ("wami:PrincipalTenantId", KeyType::String, |c| {
        c.principal_tenant_id
            .map(|id| ConditionValue::String(id.to_string()))
    }),
    ("wami:ResourceTenantId", KeyType::String, |c| {
        c.resource_tenant_id
            .map(|id| ConditionValue::String(id.to_string()))
    }),
    ("wami:TenantName", KeyType::String, |c| {
        c.tenant_name.clone().map(ConditionValue::String)
    }),
    ("wami:TenantStatus", KeyType::String, |c| {
        c.tenant_status.clone().map(ConditionValue::String)
    }),
    ("wami:CrossTenantRequest", KeyType::Boolean, |c| {
        c.cross_tenant_request.map(ConditionValue::Boolean)
    }),
    ("wami:Provider", KeyType::String, |c| {
        c.provider.clone().map(ConditionValue::String)
    }),
    ("wami:SourceProvider", KeyType::String, |c| {
        c.source_provider.clone().map(ConditionValue::String)
    }),
    ("wami:TargetProvider", KeyType::String, |c| {
        c.target_provider.clone().map(ConditionValue::String)
    }),
    ("wami:ProviderRegion", KeyType::String, |c| {
        c.provider_region.clone().map(ConditionValue::String)
    }),
    ("wami:CrossProviderRequest", KeyType::Boolean, |c| {
        c.cross_provider_request.map(ConditionValue::Boolean)
    }),
    ("wami:RequestMethod", KeyType::String, |c| {
        c.request_method.clone().map(ConditionValue::String)
    }),
    ("wami:RequestProtocol", KeyType::String, |c| {
        c.request_protocol.clone().map(ConditionValue::String)
    }),
    ("wami:ApiVersion", KeyType::String, |c| {
        c.api_version.clone().map(ConditionValue::String)
    }),
    ("wami:RequestPath", KeyType::String, |c| {
        c.request_path.clone().map(ConditionValue::String)
    }),
    ("wami:RequestQuery", KeyType::String, |c| {
        c.request_query.clone().map(ConditionValue::String)
    }),
    ("wami:ContentType", KeyType::String, |c| {
        c.content_type.clone().map(ConditionValue::String)
    }),
    ("wami:AcceptHeader", KeyType::String, |c| {
        c.accept_header.clone().map(ConditionValue::String)
    }),
    ("wami:Origin", KeyType::String, |c| {
        c.origin.clone().map(ConditionValue::String)
    }),
    ("wami:Host", KeyType::String, |c| {
        c.host.clone().map(ConditionValue::String)
    }),
    ("wami:ApplicationId", KeyType::String, |c| {
        c.application_id.clone().map(ConditionValue::String)
    }),
    ("wami:ApplicationVersion", KeyType::String, |c| {
        c.application_version.clone().map(ConditionValue::String)
    }),
    ("wami:ClientId", KeyType::String, |c| {
        c.client_id.clone().map(ConditionValue::String)
    }),
    ("wami:ClientType", KeyType::String, |c| {
        c.client_type.clone().map(ConditionValue::String)
    }),
    ("wami:DeviceId", KeyType::String, |c| {
        c.device_id.clone().map(ConditionValue::String)
    }),
    ("wami:DeviceType", KeyType::String, |c| {
        c.device_type.clone().map(ConditionValue::String)
    }),
    ("wami:Platform", KeyType::String, |c| {
        c.platform.clone().map(ConditionValue::String)
    }),
    ("wami:SessionId", KeyType::String, |c| {
        c.session_id.clone().map(ConditionValue::String)
    }),
    ("wami:SessionAge", KeyType::Number, |c| {
        c.session_age.map(|age| ConditionValue::Number(age as f64))
    }),
    ("wami:AuthenticationMethod", KeyType::String, |c| {
        c.authentication_method.clone().map(ConditionValue::String)
    }),
    ("wami:AuthenticationStrength", KeyType::String, |c| {
        c.authentication_strength
            .clone()
            .map(ConditionValue::String)
    }),
    ("wami:SessionRiskScore", KeyType::Number, |c| {
        c.session_risk_score.map(ConditionValue::Number)
    }),
    ("wami:IpReputation", KeyType::String, |c| {
        c.ip_reputation.clone().map(ConditionValue::String)
    }),
    ("wami:SourceCountry", KeyType::String, |c| {
        c.geolocation_country.clone().map(ConditionValue::String)
    }),
    ("wami:SourceCity", KeyType::String, |c| {
        c.geolocation_city.clone().map(ConditionValue::String)
    }),
    ("wami:VpnDetected", KeyType::Boolean, |c| {
        c.vpn_detected.map(ConditionValue::Boolean)
    }),
    ("wami:ProxyDetected", KeyType::Boolean, |c| {
        c.proxy_detected.map(ConditionValue::Boolean)
    }),
    ("wami:RequestsPerMinute", KeyType::Number, |c| {
        c.requests_per_minute
            .map(|count| ConditionValue::Number(count as f64))
    }),
    ("wami:RequestsPerHour", KeyType::Number, |c| {
        c.requests_per_hour
            .map(|count| ConditionValue::Number(count as f64))
    }),
    ("wami:RequestsPerDay", KeyType::Number, |c| {
        c.requests_per_day
            .map(|count| ConditionValue::Number(count as f64))
    }),
    ("wami:QuotaRemaining", KeyType::Number, |c| {
        c.quota_remaining
            .map(|remaining| ConditionValue::Number(remaining as f64))
    }),
    ("wami:QuotaLimit", KeyType::Number, |c| {
        c.quota_limit
            .map(|limit| ConditionValue::Number(limit as f64))
    }),
    ("wami:BurstCapacityUsed", KeyType::Number, |c| {
        c.burst_capacity_used.map(ConditionValue::Number)
    }),
    ("wami:RequestId", KeyType::String, |c| {
        c.request_id.clone().map(ConditionValue::String)
    }),
    ("wami:CorrelationId", KeyType::String, |c| {
        c.correlation_id.clone().map(ConditionValue::String)
    }),
    ("wami:TraceId", KeyType::String, |c| {
        c.trace_id.clone().map(ConditionValue::String)
    }),
    ("wami:SpanId", KeyType::String, |c| {
        c.span_id.clone().map(ConditionValue::String)
    }),
    ("wami:DebugModeEnabled", KeyType::Boolean, |c| {
        c.debug_mode.map(ConditionValue::Boolean)
    }),
    ("wami:DryRunMode", KeyType::Boolean, |c| {
        c.dry_run_mode.map(ConditionValue::Boolean)
    }),
    ("wami:ResourceDataClassification", KeyType::String, |c| {
        c.data_classification.clone().map(ConditionValue::String)
    }),
    ("wami:DataResidencyRegion", KeyType::String, |c| {
        c.data_residency_region.clone().map(ConditionValue::String)
    }),
    ("wami:EncryptionRequired", KeyType::Boolean, |c| {
        c.encryption_required.map(ConditionValue::Boolean)
    }),
    ("wami:EncryptionAlgorithm", KeyType::String, |c| {
        c.encryption_algorithm.clone().map(ConditionValue::String)
    }),
];

/// Which tag map of the context a tag key reads.
type Tags = fn(&ConditionContext) -> &HashMap<String, String>;

/// The tag keys, declared by prefix: each resolves to the tag's text.
const TAG_PREFIXES: &[(&str, Tags)] = &[
    ("aws:PrincipalTag/", |c| &c.principal_tags),
    ("aws:ResourceTag/", |c| &c.resource_tags),
    ("aws:RequestTag/", |c| &c.request_tags),
];

/// The declared type of `key`, or `None` for a key nobody declared — a custom
/// key, whose value is whatever the caller put in the context.
pub fn key_type(key: &str) -> Option<KeyType> {
    if let Some((_, key_type, _)) = KEYS.iter().find(|(name, _, _)| *name == key) {
        return Some(*key_type);
    }
    TAG_PREFIXES
        .iter()
        .any(|(prefix, _)| key.starts_with(prefix))
        .then_some(KeyType::String)
}

/// Every declared key with its type (tag keys aside, declared by prefix).
pub fn declared_keys() -> impl Iterator<Item = (&'static str, KeyType)> {
    KEYS.iter().map(|(name, key_type, _)| (*name, *key_type))
}

/// Get the value for a condition key from the context
///
/// A key absent from the context is `None` — a false condition, never an
/// error, as in AWS.
#[allow(clippy::result_large_err)]
pub fn get_context_value(key: &str, context: &ConditionContext) -> Result<Option<ConditionValue>> {
    if let Some((_, _, resolve)) = KEYS.iter().find(|(name, _, _)| *name == key) {
        return Ok(resolve(context));
    }
    for (prefix, tags) in TAG_PREFIXES {
        if let Some(tag_key) = key.strip_prefix(prefix) {
            return Ok(tags(context)
                .get(tag_key)
                .cloned()
                .map(ConditionValue::String));
        }
    }
    Ok(context.custom_values.get(key).cloned())
}
