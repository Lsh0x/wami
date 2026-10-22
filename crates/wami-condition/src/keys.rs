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

use chrono::{DateTime, Utc};

use super::{ConditionContext, ConditionError, ConditionValue};
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

/// How a declared key is written into the context from the text a caller
/// supplied (a simulation's context entry): parsed as the key's type, or an
/// error — never written somewhere it is not read from (wami 001).
type Assign = fn(&mut ConditionContext, &[String]) -> std::result::Result<(), ConditionError>;

/// Every declared key: its name, its type, how it is read, how it is written.
const KEYS: &[(&str, KeyType, Resolve, Assign)] = &[
    (
        "aws:PrincipalArn",
        KeyType::Arn,
        |c| c.principal_arn.clone().map(ConditionValue::String),
        |c, v| {
            c.principal_arn = Some(one(v)?);
            Ok(())
        },
    ),
    (
        "aws:PrincipalAccount",
        KeyType::String,
        |c| c.principal_account.clone().map(ConditionValue::String),
        |c, v| {
            c.principal_account = Some(one(v)?);
            Ok(())
        },
    ),
    (
        "aws:PrincipalType",
        KeyType::String,
        |c| c.principal_type.clone().map(ConditionValue::String),
        |c, v| {
            c.principal_type = Some(one(v)?);
            Ok(())
        },
    ),
    (
        "aws:username",
        KeyType::String,
        |c| c.username.clone().map(ConditionValue::String),
        |c, v| {
            c.username = Some(one(v)?);
            Ok(())
        },
    ),
    (
        "aws:userid",
        KeyType::String,
        |c| c.userid.clone().map(ConditionValue::String),
        |c, v| {
            c.userid = Some(one(v)?);
            Ok(())
        },
    ),
    (
        "aws:userId",
        KeyType::String,
        |c| c.userid.clone().map(ConditionValue::String),
        |c, v| {
            c.userid = Some(one(v)?);
            Ok(())
        },
    ),
    (
        "aws:MultiFactorAuthPresent",
        KeyType::Boolean,
        |c| c.mfa_present.map(ConditionValue::Boolean),
        |c, v| {
            c.mfa_present = Some(boolean(v)?);
            Ok(())
        },
    ),
    (
        "aws:MultiFactorAuthAge",
        KeyType::Number,
        |c| c.mfa_age.map(|age| ConditionValue::Number(age as f64)),
        |c, v| {
            c.mfa_age = Some(unsigned(v)?);
            Ok(())
        },
    ),
    (
        "aws:TokenIssueTime",
        KeyType::Date,
        |c| {
            c.token_issue_time
                .map(|time| ConditionValue::String(time.to_rfc3339()))
        },
        |c, v| {
            c.token_issue_time = Some(date(v)?);
            Ok(())
        },
    ),
    (
        "aws:SecureTransport",
        KeyType::Boolean,
        |c| c.secure_transport.map(ConditionValue::Boolean),
        |c, v| {
            c.secure_transport = Some(boolean(v)?);
            Ok(())
        },
    ),
    (
        "aws:SourceIp",
        KeyType::Ip,
        |c| c.source_ip.clone().map(ConditionValue::String),
        |c, v| {
            c.source_ip = Some(address(v)?);
            Ok(())
        },
    ),
    (
        "aws:SourceVpc",
        KeyType::String,
        |c| c.source_vpc.clone().map(ConditionValue::String),
        |c, v| {
            c.source_vpc = Some(one(v)?);
            Ok(())
        },
    ),
    (
        "aws:SourceVpce",
        KeyType::String,
        |c| c.source_vpce.clone().map(ConditionValue::String),
        |c, v| {
            c.source_vpce = Some(one(v)?);
            Ok(())
        },
    ),
    (
        "aws:CurrentTime",
        KeyType::Date,
        |c| Some(ConditionValue::String(c.current_time.to_rfc3339())),
        |c, v| {
            c.current_time = date(v)?;
            Ok(())
        },
    ),
    (
        "aws:EpochTime",
        KeyType::Number,
        |c| Some(ConditionValue::Number(c.current_time.timestamp() as f64)),
        |c, v| {
            c.current_time = epoch(v)?;
            Ok(())
        },
    ),
    (
        "aws:RequestedRegion",
        KeyType::String,
        |c| c.requested_region.clone().map(ConditionValue::String),
        |c, v| {
            c.requested_region = Some(one(v)?);
            Ok(())
        },
    ),
    (
        "aws:Referer",
        KeyType::String,
        |c| c.referer.clone().map(ConditionValue::String),
        |c, v| {
            c.referer = Some(one(v)?);
            Ok(())
        },
    ),
    (
        "aws:UserAgent",
        KeyType::String,
        |c| c.user_agent.clone().map(ConditionValue::String),
        |c, v| {
            c.user_agent = Some(one(v)?);
            Ok(())
        },
    ),
    (
        "aws:ResourceArn",
        KeyType::Arn,
        |c| c.resource_arn.clone().map(ConditionValue::String),
        |c, v| {
            c.resource_arn = Some(one(v)?);
            Ok(())
        },
    ),
    (
        "aws:ResourceAccount",
        KeyType::String,
        |c| c.resource_account.clone().map(ConditionValue::String),
        |c, v| {
            c.resource_account = Some(one(v)?);
            Ok(())
        },
    ),
    (
        "aws:TagKeys",
        KeyType::StringList,
        |c| (!c.tag_keys.is_empty()).then(|| ConditionValue::Array(c.tag_keys.clone())),
        |c, v| {
            c.tag_keys = v.to_vec();
            Ok(())
        },
    ),
    (
        "wami:TenantId",
        KeyType::String,
        |c| c.tenant_id.clone().map(ConditionValue::String),
        |c, v| {
            c.tenant_id = Some(tenant_path(v)?);
            Ok(())
        },
    ),
    (
        "wami:PrincipalTenantId",
        KeyType::String,
        |c| c.principal_tenant_id.clone().map(ConditionValue::String),
        |c, v| {
            c.principal_tenant_id = Some(tenant_path(v)?);
            Ok(())
        },
    ),
    (
        "wami:ResourceTenantId",
        KeyType::String,
        |c| c.resource_tenant_id.clone().map(ConditionValue::String),
        |c, v| {
            c.resource_tenant_id = Some(tenant_path(v)?);
            Ok(())
        },
    ),
    (
        "wami:TenantName",
        KeyType::String,
        |c| c.tenant_name.clone().map(ConditionValue::String),
        |c, v| {
            c.tenant_name = Some(one(v)?);
            Ok(())
        },
    ),
    (
        "wami:TenantStatus",
        KeyType::String,
        |c| c.tenant_status.clone().map(ConditionValue::String),
        |c, v| {
            c.tenant_status = Some(one(v)?);
            Ok(())
        },
    ),
    (
        "wami:CrossTenantRequest",
        KeyType::Boolean,
        |c| c.cross_tenant_request.map(ConditionValue::Boolean),
        |c, v| {
            c.cross_tenant_request = Some(boolean(v)?);
            Ok(())
        },
    ),
    (
        "wami:Provider",
        KeyType::String,
        |c| c.provider.clone().map(ConditionValue::String),
        |c, v| {
            c.provider = Some(one(v)?);
            Ok(())
        },
    ),
    (
        "wami:SourceProvider",
        KeyType::String,
        |c| c.source_provider.clone().map(ConditionValue::String),
        |c, v| {
            c.source_provider = Some(one(v)?);
            Ok(())
        },
    ),
    (
        "wami:TargetProvider",
        KeyType::String,
        |c| c.target_provider.clone().map(ConditionValue::String),
        |c, v| {
            c.target_provider = Some(one(v)?);
            Ok(())
        },
    ),
    (
        "wami:ProviderRegion",
        KeyType::String,
        |c| c.provider_region.clone().map(ConditionValue::String),
        |c, v| {
            c.provider_region = Some(one(v)?);
            Ok(())
        },
    ),
    (
        "wami:CrossProviderRequest",
        KeyType::Boolean,
        |c| c.cross_provider_request.map(ConditionValue::Boolean),
        |c, v| {
            c.cross_provider_request = Some(boolean(v)?);
            Ok(())
        },
    ),
    (
        "wami:RequestMethod",
        KeyType::String,
        |c| c.request_method.clone().map(ConditionValue::String),
        |c, v| {
            c.request_method = Some(one(v)?);
            Ok(())
        },
    ),
    (
        "wami:RequestProtocol",
        KeyType::String,
        |c| c.request_protocol.clone().map(ConditionValue::String),
        |c, v| {
            c.request_protocol = Some(one(v)?);
            Ok(())
        },
    ),
    (
        "wami:ApiVersion",
        KeyType::String,
        |c| c.api_version.clone().map(ConditionValue::String),
        |c, v| {
            c.api_version = Some(one(v)?);
            Ok(())
        },
    ),
    (
        "wami:RequestPath",
        KeyType::String,
        |c| c.request_path.clone().map(ConditionValue::String),
        |c, v| {
            c.request_path = Some(one(v)?);
            Ok(())
        },
    ),
    (
        "wami:RequestQuery",
        KeyType::String,
        |c| c.request_query.clone().map(ConditionValue::String),
        |c, v| {
            c.request_query = Some(one(v)?);
            Ok(())
        },
    ),
    (
        "wami:ContentType",
        KeyType::String,
        |c| c.content_type.clone().map(ConditionValue::String),
        |c, v| {
            c.content_type = Some(one(v)?);
            Ok(())
        },
    ),
    (
        "wami:AcceptHeader",
        KeyType::String,
        |c| c.accept_header.clone().map(ConditionValue::String),
        |c, v| {
            c.accept_header = Some(one(v)?);
            Ok(())
        },
    ),
    (
        "wami:Origin",
        KeyType::String,
        |c| c.origin.clone().map(ConditionValue::String),
        |c, v| {
            c.origin = Some(one(v)?);
            Ok(())
        },
    ),
    (
        "wami:Host",
        KeyType::String,
        |c| c.host.clone().map(ConditionValue::String),
        |c, v| {
            c.host = Some(one(v)?);
            Ok(())
        },
    ),
    (
        "wami:ApplicationId",
        KeyType::String,
        |c| c.application_id.clone().map(ConditionValue::String),
        |c, v| {
            c.application_id = Some(one(v)?);
            Ok(())
        },
    ),
    (
        "wami:ApplicationVersion",
        KeyType::String,
        |c| c.application_version.clone().map(ConditionValue::String),
        |c, v| {
            c.application_version = Some(one(v)?);
            Ok(())
        },
    ),
    (
        "wami:ClientId",
        KeyType::String,
        |c| c.client_id.clone().map(ConditionValue::String),
        |c, v| {
            c.client_id = Some(one(v)?);
            Ok(())
        },
    ),
    (
        "wami:ClientType",
        KeyType::String,
        |c| c.client_type.clone().map(ConditionValue::String),
        |c, v| {
            c.client_type = Some(one(v)?);
            Ok(())
        },
    ),
    (
        "wami:DeviceId",
        KeyType::String,
        |c| c.device_id.clone().map(ConditionValue::String),
        |c, v| {
            c.device_id = Some(one(v)?);
            Ok(())
        },
    ),
    (
        "wami:DeviceType",
        KeyType::String,
        |c| c.device_type.clone().map(ConditionValue::String),
        |c, v| {
            c.device_type = Some(one(v)?);
            Ok(())
        },
    ),
    (
        "wami:Platform",
        KeyType::String,
        |c| c.platform.clone().map(ConditionValue::String),
        |c, v| {
            c.platform = Some(one(v)?);
            Ok(())
        },
    ),
    (
        "wami:SessionId",
        KeyType::String,
        |c| c.session_id.clone().map(ConditionValue::String),
        |c, v| {
            c.session_id = Some(one(v)?);
            Ok(())
        },
    ),
    (
        "wami:SessionAge",
        KeyType::Number,
        |c| c.session_age.map(|age| ConditionValue::Number(age as f64)),
        |c, v| {
            c.session_age = Some(unsigned(v)?);
            Ok(())
        },
    ),
    (
        "wami:AuthenticationMethod",
        KeyType::String,
        |c| c.authentication_method.clone().map(ConditionValue::String),
        |c, v| {
            c.authentication_method = Some(one(v)?);
            Ok(())
        },
    ),
    (
        "wami:AuthenticationStrength",
        KeyType::String,
        |c| {
            c.authentication_strength
                .clone()
                .map(ConditionValue::String)
        },
        |c, v| {
            c.authentication_strength = Some(one(v)?);
            Ok(())
        },
    ),
    (
        "wami:SessionRiskScore",
        KeyType::Number,
        |c| c.session_risk_score.map(ConditionValue::Number),
        |c, v| {
            c.session_risk_score = Some(number(v)?);
            Ok(())
        },
    ),
    (
        "wami:IpReputation",
        KeyType::String,
        |c| c.ip_reputation.clone().map(ConditionValue::String),
        |c, v| {
            c.ip_reputation = Some(one(v)?);
            Ok(())
        },
    ),
    (
        "wami:SourceCountry",
        KeyType::String,
        |c| c.geolocation_country.clone().map(ConditionValue::String),
        |c, v| {
            c.geolocation_country = Some(one(v)?);
            Ok(())
        },
    ),
    (
        "wami:SourceCity",
        KeyType::String,
        |c| c.geolocation_city.clone().map(ConditionValue::String),
        |c, v| {
            c.geolocation_city = Some(one(v)?);
            Ok(())
        },
    ),
    (
        "wami:VpnDetected",
        KeyType::Boolean,
        |c| c.vpn_detected.map(ConditionValue::Boolean),
        |c, v| {
            c.vpn_detected = Some(boolean(v)?);
            Ok(())
        },
    ),
    (
        "wami:ProxyDetected",
        KeyType::Boolean,
        |c| c.proxy_detected.map(ConditionValue::Boolean),
        |c, v| {
            c.proxy_detected = Some(boolean(v)?);
            Ok(())
        },
    ),
    (
        "wami:RequestsPerMinute",
        KeyType::Number,
        |c| {
            c.requests_per_minute
                .map(|count| ConditionValue::Number(count as f64))
        },
        |c, v| {
            c.requests_per_minute = Some(unsigned(v)?);
            Ok(())
        },
    ),
    (
        "wami:RequestsPerHour",
        KeyType::Number,
        |c| {
            c.requests_per_hour
                .map(|count| ConditionValue::Number(count as f64))
        },
        |c, v| {
            c.requests_per_hour = Some(unsigned(v)?);
            Ok(())
        },
    ),
    (
        "wami:RequestsPerDay",
        KeyType::Number,
        |c| {
            c.requests_per_day
                .map(|count| ConditionValue::Number(count as f64))
        },
        |c, v| {
            c.requests_per_day = Some(unsigned(v)?);
            Ok(())
        },
    ),
    (
        "wami:QuotaRemaining",
        KeyType::Number,
        |c| {
            c.quota_remaining
                .map(|remaining| ConditionValue::Number(remaining as f64))
        },
        |c, v| {
            c.quota_remaining = Some(unsigned(v)?);
            Ok(())
        },
    ),
    (
        "wami:QuotaLimit",
        KeyType::Number,
        |c| {
            c.quota_limit
                .map(|limit| ConditionValue::Number(limit as f64))
        },
        |c, v| {
            c.quota_limit = Some(unsigned(v)?);
            Ok(())
        },
    ),
    (
        "wami:BurstCapacityUsed",
        KeyType::Number,
        |c| c.burst_capacity_used.map(ConditionValue::Number),
        |c, v| {
            c.burst_capacity_used = Some(number(v)?);
            Ok(())
        },
    ),
    (
        "wami:RequestId",
        KeyType::String,
        |c| c.request_id.clone().map(ConditionValue::String),
        |c, v| {
            c.request_id = Some(one(v)?);
            Ok(())
        },
    ),
    (
        "wami:CorrelationId",
        KeyType::String,
        |c| c.correlation_id.clone().map(ConditionValue::String),
        |c, v| {
            c.correlation_id = Some(one(v)?);
            Ok(())
        },
    ),
    (
        "wami:TraceId",
        KeyType::String,
        |c| c.trace_id.clone().map(ConditionValue::String),
        |c, v| {
            c.trace_id = Some(one(v)?);
            Ok(())
        },
    ),
    (
        "wami:SpanId",
        KeyType::String,
        |c| c.span_id.clone().map(ConditionValue::String),
        |c, v| {
            c.span_id = Some(one(v)?);
            Ok(())
        },
    ),
    (
        "wami:DebugModeEnabled",
        KeyType::Boolean,
        |c| c.debug_mode.map(ConditionValue::Boolean),
        |c, v| {
            c.debug_mode = Some(boolean(v)?);
            Ok(())
        },
    ),
    (
        "wami:DryRunMode",
        KeyType::Boolean,
        |c| c.dry_run_mode.map(ConditionValue::Boolean),
        |c, v| {
            c.dry_run_mode = Some(boolean(v)?);
            Ok(())
        },
    ),
    (
        "wami:ResourceDataClassification",
        KeyType::String,
        |c| c.data_classification.clone().map(ConditionValue::String),
        |c, v| {
            c.data_classification = Some(one(v)?);
            Ok(())
        },
    ),
    (
        "wami:DataResidencyRegion",
        KeyType::String,
        |c| c.data_residency_region.clone().map(ConditionValue::String),
        |c, v| {
            c.data_residency_region = Some(one(v)?);
            Ok(())
        },
    ),
    (
        "wami:EncryptionRequired",
        KeyType::Boolean,
        |c| c.encryption_required.map(ConditionValue::Boolean),
        |c, v| {
            c.encryption_required = Some(boolean(v)?);
            Ok(())
        },
    ),
    (
        "wami:EncryptionAlgorithm",
        KeyType::String,
        |c| c.encryption_algorithm.clone().map(ConditionValue::String),
        |c, v| {
            c.encryption_algorithm = Some(one(v)?);
            Ok(())
        },
    ),
];

/// The one value a scalar key takes.
fn one(values: &[String]) -> std::result::Result<String, ConditionError> {
    match values {
        [value] => Ok(value.clone()),
        _ => Err(not_read_as("exactly one value")),
    }
}

fn not_read_as(expected: &str) -> ConditionError {
    ConditionError::TypeMismatch {
        expected: expected.to_string(),
        actual: "String".to_string(),
    }
}

fn boolean(values: &[String]) -> std::result::Result<bool, ConditionError> {
    ConditionValue::String(one(values)?).as_boolean()
}

fn number(values: &[String]) -> std::result::Result<f64, ConditionError> {
    ConditionValue::String(one(values)?).as_number()
}

/// A tenant path: whole numbers joined by `/` (`5/7`) — the FULL path, so
/// `5/7` and `5/9` stay apart (wami 005, review round 1 Δ11).
fn tenant_path(values: &[String]) -> std::result::Result<String, ConditionError> {
    let value = one(values)?;
    let readable = !value.is_empty()
        && value
            .split('/')
            .all(|segment| segment.parse::<u64>().is_ok());
    if readable {
        Ok(value)
    } else {
        Err(not_read_as("a tenant path: whole numbers joined by /"))
    }
}

fn unsigned(values: &[String]) -> std::result::Result<u64, ConditionError> {
    one(values)?
        .parse::<u64>()
        .map_err(|_| not_read_as("a whole number, zero or more"))
}

fn date(values: &[String]) -> std::result::Result<DateTime<Utc>, ConditionError> {
    crate::operators::parse_rfc3339(&one(values)?)
}

fn epoch(values: &[String]) -> std::result::Result<DateTime<Utc>, ConditionError> {
    one(values)?
        .parse::<i64>()
        .ok()
        .and_then(|seconds| DateTime::from_timestamp(seconds, 0))
        .ok_or_else(|| not_read_as("seconds since the epoch"))
}

fn address(values: &[String]) -> std::result::Result<String, ConditionError> {
    let value = one(values)?;
    if crate::operators::is_address(&value) {
        Ok(value)
    } else {
        Err(not_read_as("an IP address"))
    }
}

/// Which tag map of the context a tag key reads...
type Tags = fn(&ConditionContext) -> &HashMap<String, String>;
/// ... and the same map, to write.
type TagsMut = fn(&mut ConditionContext) -> &mut HashMap<String, String>;

/// The tag keys, declared by prefix: each resolves to the tag's text.
const TAG_PREFIXES: &[(&str, Tags, TagsMut)] = &[
    (
        "aws:PrincipalTag/",
        |c| &c.principal_tags,
        |c| &mut c.principal_tags,
    ),
    (
        "aws:ResourceTag/",
        |c| &c.resource_tags,
        |c| &mut c.resource_tags,
    ),
    (
        "aws:RequestTag/",
        |c| &c.request_tags,
        |c| &mut c.request_tags,
    ),
];

/// The declared type of `key`, or `None` for a key nobody declared — a custom
/// key, whose value is whatever the caller put in the context.
pub fn key_type(key: &str) -> Option<KeyType> {
    if let Some((_, key_type, _, _)) = KEYS.iter().find(|(name, _, _, _)| *name == key) {
        return Some(*key_type);
    }
    TAG_PREFIXES
        .iter()
        .any(|(prefix, _, _)| key.starts_with(prefix))
        .then_some(KeyType::String)
}

/// Every declared key with its type (tag keys aside, declared by prefix).
pub fn declared_keys() -> impl Iterator<Item = (&'static str, KeyType)> {
    KEYS.iter().map(|(name, key_type, _, _)| (*name, *key_type))
}

/// Write a declared key into `context` from the text a caller supplied — a
/// simulation's context entry — parsed as the key's declared type.
///
/// Returns `Ok(false)` for a key nobody declared: the caller keeps it among
/// the custom values, as text. A declared key is written to the field it is
/// READ from, never to the custom values, which a declared key is not read
/// from: written there, it used to be absent, and a Deny on it false.
///
/// # Errors
///
/// [`ConditionError::TypeMismatch`] when the values do not read as the key's
/// type (or a scalar key is given other than one value). It carries the
/// expected shape, never the value.
pub fn assign_context_value(
    context: &mut ConditionContext,
    key: &str,
    values: &[String],
) -> std::result::Result<bool, ConditionError> {
    if let Some((_, _, _, assign)) = KEYS.iter().find(|(name, _, _, _)| *name == key) {
        assign(context, values)?;
        return Ok(true);
    }
    for (prefix, _, tags) in TAG_PREFIXES {
        if let Some(tag_key) = key.strip_prefix(prefix) {
            tags(context).insert(tag_key.to_string(), one(values)?);
            return Ok(true);
        }
    }
    Ok(false)
}

/// Get the value for a condition key from the context
///
/// A key absent from the context is `None` — a false condition, never an
/// error, as in AWS.
#[allow(clippy::result_large_err)]
pub fn get_context_value(key: &str, context: &ConditionContext) -> Result<Option<ConditionValue>> {
    if let Some((_, _, resolve, _)) = KEYS.iter().find(|(name, _, _, _)| *name == key) {
        return Ok(resolve(context));
    }
    for (prefix, tags, _) in TAG_PREFIXES {
        if let Some(tag_key) = key.strip_prefix(prefix) {
            return Ok(tags(context)
                .get(tag_key)
                .cloned()
                .map(ConditionValue::String));
        }
    }
    Ok(context.custom_values.get(key).cloned())
}
