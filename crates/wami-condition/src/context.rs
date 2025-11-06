//! Condition Context
//!
//! Holds the request context values used for condition evaluation.

use super::ConditionValue;
use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// Context for condition evaluation
///
/// Contains all the values that can be referenced by condition keys.
#[derive(Debug, Clone)]
pub struct ConditionContext {
    // Principal information
    pub principal_arn: Option<String>,
    pub principal_account: Option<String>,
    pub principal_type: Option<String>,
    pub username: Option<String>,
    pub userid: Option<String>,

    // Authentication
    pub mfa_present: Option<bool>,
    pub mfa_age: Option<u64>,
    pub token_issue_time: Option<DateTime<Utc>>,
    pub secure_transport: Option<bool>,

    // Network
    pub source_ip: Option<String>,
    pub source_vpc: Option<String>,
    pub source_vpce: Option<String>,

    // Request context
    pub current_time: DateTime<Utc>,
    pub requested_region: Option<String>,
    pub referer: Option<String>,
    pub user_agent: Option<String>,

    // Resource
    pub resource_arn: Option<String>,
    pub resource_account: Option<String>,

    // Tags
    pub principal_tags: HashMap<String, String>,
    pub resource_tags: HashMap<String, String>,
    pub request_tags: HashMap<String, String>,
    pub tag_keys: Vec<String>,

    // WAMI-specific - Multi-tenant
    pub tenant_id: Option<u64>,
    pub principal_tenant_id: Option<u64>,
    pub resource_tenant_id: Option<u64>,
    pub tenant_name: Option<String>,
    pub tenant_status: Option<String>,
    pub cross_tenant_request: Option<bool>,

    // WAMI-specific - Multi-cloud
    pub provider: Option<String>,
    pub source_provider: Option<String>,
    pub target_provider: Option<String>,
    pub provider_region: Option<String>,
    pub cross_provider_request: Option<bool>,

    // WAMI-specific - Request/HTTP context (general purpose)
    pub request_method: Option<String>, // GET, POST, PUT, DELETE, etc.
    pub request_protocol: Option<String>, // HTTP/1.1, HTTP/2, HTTPS, etc.
    pub api_version: Option<String>,    // API version (v1, v2, etc.)
    pub request_path: Option<String>,   // Request path (/api/users, /admin, etc.)
    pub request_query: Option<String>,  // Query string
    pub content_type: Option<String>,   // Content-Type header
    pub accept_header: Option<String>,  // Accept header
    pub origin: Option<String>,         // Origin header (for CORS)
    pub host: Option<String>,           // Host header

    // WAMI-specific - Application context (general purpose)
    pub application_id: Option<String>, // Application identifier
    pub application_version: Option<String>, // Application version
    pub client_id: Option<String>,      // OAuth client ID, API key ID, etc.
    pub client_type: Option<String>,    // web, mobile, api, cli, etc.
    pub device_id: Option<String>,      // Device identifier
    pub device_type: Option<String>,    // desktop, mobile, tablet, etc.
    pub platform: Option<String>,       // ios, android, windows, linux, macos, web

    // WAMI-specific - Session & Security (general purpose)
    pub session_id: Option<String>,              // Session identifier
    pub session_age: Option<u64>,                // Session age in seconds
    pub authentication_method: Option<String>,   // password, oauth, saml, api_key, etc.
    pub authentication_strength: Option<String>, // low, medium, high
    pub session_risk_score: Option<f64>,         // Risk score (0.0-1.0)
    pub ip_reputation: Option<String>,           // good, suspicious, malicious
    pub geolocation_country: Option<String>,     // ISO country code
    pub geolocation_city: Option<String>,        // City name
    pub vpn_detected: Option<bool>,              // VPN detected
    pub proxy_detected: Option<bool>,            // Proxy detected

    // WAMI-specific - Rate Limiting (general purpose)
    pub requests_per_minute: Option<u64>, // Current request rate
    pub requests_per_hour: Option<u64>,   // Current request rate
    pub requests_per_day: Option<u64>,    // Current request rate
    pub quota_remaining: Option<u64>,     // Remaining quota
    pub quota_limit: Option<u64>,         // Quota limit
    pub burst_capacity_used: Option<f64>, // Burst capacity usage (0.0-1.0)

    // WAMI-specific - Observability (general purpose)
    pub request_id: Option<String>,     // Request ID for tracing
    pub correlation_id: Option<String>, // Correlation ID
    pub trace_id: Option<String>,       // Distributed trace ID
    pub span_id: Option<String>,        // Span ID
    pub debug_mode: Option<bool>,       // Debug mode enabled
    pub dry_run_mode: Option<bool>,     // Dry run mode

    // WAMI-specific - Data & Compliance (general purpose)
    pub data_classification: Option<String>, // public, internal, confidential, restricted
    pub encryption_required: Option<bool>,   // Encryption required
    pub encryption_algorithm: Option<String>, // AES-256, RSA-2048, etc.
    pub data_residency_region: Option<String>, // Required data residency region

    // Extensible map for additional keys
    pub custom_values: HashMap<String, ConditionValue>,
}

impl ConditionContext {
    pub fn builder() -> ConditionContextBuilder {
        ConditionContextBuilder::default()
    }
}

#[derive(Default)]
pub struct ConditionContextBuilder {
    principal_arn: Option<String>,
    principal_account: Option<String>,
    principal_type: Option<String>,
    username: Option<String>,
    userid: Option<String>,
    mfa_present: Option<bool>,
    mfa_age: Option<u64>,
    token_issue_time: Option<DateTime<Utc>>,
    secure_transport: Option<bool>,
    source_ip: Option<String>,
    source_vpc: Option<String>,
    source_vpce: Option<String>,
    current_time: Option<DateTime<Utc>>,
    requested_region: Option<String>,
    referer: Option<String>,
    user_agent: Option<String>,
    resource_arn: Option<String>,
    resource_account: Option<String>,
    principal_tags: HashMap<String, String>,
    resource_tags: HashMap<String, String>,
    request_tags: HashMap<String, String>,
    tag_keys: Vec<String>,
    tenant_id: Option<u64>,
    principal_tenant_id: Option<u64>,
    resource_tenant_id: Option<u64>,
    tenant_name: Option<String>,
    tenant_status: Option<String>,
    cross_tenant_request: Option<bool>,
    provider: Option<String>,
    source_provider: Option<String>,
    target_provider: Option<String>,
    provider_region: Option<String>,
    cross_provider_request: Option<bool>,
    request_method: Option<String>,
    request_protocol: Option<String>,
    api_version: Option<String>,
    request_path: Option<String>,
    request_query: Option<String>,
    content_type: Option<String>,
    accept_header: Option<String>,
    origin: Option<String>,
    host: Option<String>,
    application_id: Option<String>,
    application_version: Option<String>,
    client_id: Option<String>,
    client_type: Option<String>,
    device_id: Option<String>,
    device_type: Option<String>,
    platform: Option<String>,
    session_id: Option<String>,
    session_age: Option<u64>,
    authentication_method: Option<String>,
    authentication_strength: Option<String>,
    session_risk_score: Option<f64>,
    ip_reputation: Option<String>,
    geolocation_country: Option<String>,
    geolocation_city: Option<String>,
    vpn_detected: Option<bool>,
    proxy_detected: Option<bool>,
    requests_per_minute: Option<u64>,
    requests_per_hour: Option<u64>,
    requests_per_day: Option<u64>,
    quota_remaining: Option<u64>,
    quota_limit: Option<u64>,
    burst_capacity_used: Option<f64>,
    request_id: Option<String>,
    correlation_id: Option<String>,
    trace_id: Option<String>,
    span_id: Option<String>,
    debug_mode: Option<bool>,
    dry_run_mode: Option<bool>,
    data_classification: Option<String>,
    encryption_required: Option<bool>,
    encryption_algorithm: Option<String>,
    data_residency_region: Option<String>,
    custom_values: HashMap<String, ConditionValue>,
}

impl ConditionContextBuilder {
    pub fn principal_arn(mut self, arn: impl Into<String>) -> Self {
        self.principal_arn = Some(arn.into());
        self
    }

    pub fn principal_account(mut self, account: impl Into<String>) -> Self {
        self.principal_account = Some(account.into());
        self
    }

    pub fn principal_type(mut self, principal_type: impl Into<String>) -> Self {
        self.principal_type = Some(principal_type.into());
        self
    }

    pub fn username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    pub fn userid(mut self, userid: impl Into<String>) -> Self {
        self.userid = Some(userid.into());
        self
    }

    pub fn mfa_present(mut self, present: bool) -> Self {
        self.mfa_present = Some(present);
        self
    }

    pub fn mfa_age(mut self, age: u64) -> Self {
        self.mfa_age = Some(age);
        self
    }

    pub fn token_issue_time(mut self, time: DateTime<Utc>) -> Self {
        self.token_issue_time = Some(time);
        self
    }

    pub fn secure_transport(mut self, secure: bool) -> Self {
        self.secure_transport = Some(secure);
        self
    }

    pub fn source_ip(mut self, ip: impl Into<String>) -> Self {
        self.source_ip = Some(ip.into());
        self
    }

    pub fn source_vpc(mut self, vpc: impl Into<String>) -> Self {
        self.source_vpc = Some(vpc.into());
        self
    }

    pub fn source_vpce(mut self, vpce: impl Into<String>) -> Self {
        self.source_vpce = Some(vpce.into());
        self
    }

    pub fn current_time(mut self, time: DateTime<Utc>) -> Self {
        self.current_time = Some(time);
        self
    }

    pub fn requested_region(mut self, region: impl Into<String>) -> Self {
        self.requested_region = Some(region.into());
        self
    }

    pub fn referer(mut self, referer: impl Into<String>) -> Self {
        self.referer = Some(referer.into());
        self
    }

    pub fn user_agent(mut self, agent: impl Into<String>) -> Self {
        self.user_agent = Some(agent.into());
        self
    }

    pub fn resource_arn(mut self, arn: impl Into<String>) -> Self {
        self.resource_arn = Some(arn.into());
        self
    }

    pub fn resource_account(mut self, account: impl Into<String>) -> Self {
        self.resource_account = Some(account.into());
        self
    }

    pub fn principal_tag(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.principal_tags.insert(key.into(), value.into());
        self
    }

    pub fn resource_tag(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.resource_tags.insert(key.into(), value.into());
        self
    }

    pub fn request_tag(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.request_tags.insert(key.into(), value.into());
        self
    }

    pub fn tag_keys(mut self, keys: Vec<String>) -> Self {
        self.tag_keys = keys;
        self
    }

    pub fn tenant_id(mut self, id: u64) -> Self {
        self.tenant_id = Some(id);
        self
    }

    pub fn principal_tenant_id(mut self, id: u64) -> Self {
        self.principal_tenant_id = Some(id);
        self
    }

    pub fn resource_tenant_id(mut self, id: u64) -> Self {
        self.resource_tenant_id = Some(id);
        self
    }

    pub fn provider(mut self, provider: impl Into<String>) -> Self {
        self.provider = Some(provider.into());
        self
    }

    pub fn source_provider(mut self, provider: impl Into<String>) -> Self {
        self.source_provider = Some(provider.into());
        self
    }

    pub fn target_provider(mut self, provider: impl Into<String>) -> Self {
        self.target_provider = Some(provider.into());
        self
    }

    // Multi-tenant builder methods
    pub fn tenant_name(mut self, name: impl Into<String>) -> Self {
        self.tenant_name = Some(name.into());
        self
    }

    pub fn tenant_status(mut self, status: impl Into<String>) -> Self {
        self.tenant_status = Some(status.into());
        self
    }

    pub fn cross_tenant_request(mut self, cross: bool) -> Self {
        self.cross_tenant_request = Some(cross);
        self
    }

    // Multi-cloud builder methods
    pub fn provider_region(mut self, region: impl Into<String>) -> Self {
        self.provider_region = Some(region.into());
        self
    }

    pub fn cross_provider_request(mut self, cross: bool) -> Self {
        self.cross_provider_request = Some(cross);
        self
    }

    // Request/HTTP context builder methods
    pub fn request_method(mut self, method: impl Into<String>) -> Self {
        self.request_method = Some(method.into());
        self
    }

    pub fn request_protocol(mut self, protocol: impl Into<String>) -> Self {
        self.request_protocol = Some(protocol.into());
        self
    }

    pub fn api_version(mut self, version: impl Into<String>) -> Self {
        self.api_version = Some(version.into());
        self
    }

    pub fn request_path(mut self, path: impl Into<String>) -> Self {
        self.request_path = Some(path.into());
        self
    }

    pub fn request_query(mut self, query: impl Into<String>) -> Self {
        self.request_query = Some(query.into());
        self
    }

    pub fn content_type(mut self, content_type: impl Into<String>) -> Self {
        self.content_type = Some(content_type.into());
        self
    }

    pub fn accept_header(mut self, accept: impl Into<String>) -> Self {
        self.accept_header = Some(accept.into());
        self
    }

    pub fn origin(mut self, origin: impl Into<String>) -> Self {
        self.origin = Some(origin.into());
        self
    }

    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.host = Some(host.into());
        self
    }

    // Application context builder methods
    pub fn application_id(mut self, id: impl Into<String>) -> Self {
        self.application_id = Some(id.into());
        self
    }

    pub fn application_version(mut self, version: impl Into<String>) -> Self {
        self.application_version = Some(version.into());
        self
    }

    pub fn client_id(mut self, id: impl Into<String>) -> Self {
        self.client_id = Some(id.into());
        self
    }

    pub fn client_type(mut self, client_type: impl Into<String>) -> Self {
        self.client_type = Some(client_type.into());
        self
    }

    pub fn device_id(mut self, id: impl Into<String>) -> Self {
        self.device_id = Some(id.into());
        self
    }

    pub fn device_type(mut self, device_type: impl Into<String>) -> Self {
        self.device_type = Some(device_type.into());
        self
    }

    pub fn platform(mut self, platform: impl Into<String>) -> Self {
        self.platform = Some(platform.into());
        self
    }

    // Session & Security builder methods
    pub fn session_id(mut self, id: impl Into<String>) -> Self {
        self.session_id = Some(id.into());
        self
    }

    pub fn session_age(mut self, age: u64) -> Self {
        self.session_age = Some(age);
        self
    }

    pub fn authentication_method(mut self, method: impl Into<String>) -> Self {
        self.authentication_method = Some(method.into());
        self
    }

    pub fn authentication_strength(mut self, strength: impl Into<String>) -> Self {
        self.authentication_strength = Some(strength.into());
        self
    }

    pub fn session_risk_score(mut self, score: f64) -> Self {
        self.session_risk_score = Some(score);
        self
    }

    pub fn ip_reputation(mut self, reputation: impl Into<String>) -> Self {
        self.ip_reputation = Some(reputation.into());
        self
    }

    pub fn geolocation_country(mut self, country: impl Into<String>) -> Self {
        self.geolocation_country = Some(country.into());
        self
    }

    pub fn geolocation_city(mut self, city: impl Into<String>) -> Self {
        self.geolocation_city = Some(city.into());
        self
    }

    pub fn vpn_detected(mut self, detected: bool) -> Self {
        self.vpn_detected = Some(detected);
        self
    }

    pub fn proxy_detected(mut self, detected: bool) -> Self {
        self.proxy_detected = Some(detected);
        self
    }

    // Rate Limiting builder methods
    pub fn requests_per_minute(mut self, count: u64) -> Self {
        self.requests_per_minute = Some(count);
        self
    }

    pub fn requests_per_hour(mut self, count: u64) -> Self {
        self.requests_per_hour = Some(count);
        self
    }

    pub fn requests_per_day(mut self, count: u64) -> Self {
        self.requests_per_day = Some(count);
        self
    }

    pub fn quota_remaining(mut self, remaining: u64) -> Self {
        self.quota_remaining = Some(remaining);
        self
    }

    pub fn quota_limit(mut self, limit: u64) -> Self {
        self.quota_limit = Some(limit);
        self
    }

    pub fn burst_capacity_used(mut self, used: f64) -> Self {
        self.burst_capacity_used = Some(used);
        self
    }

    // Observability builder methods
    pub fn request_id(mut self, id: impl Into<String>) -> Self {
        self.request_id = Some(id.into());
        self
    }

    pub fn correlation_id(mut self, id: impl Into<String>) -> Self {
        self.correlation_id = Some(id.into());
        self
    }

    pub fn trace_id(mut self, id: impl Into<String>) -> Self {
        self.trace_id = Some(id.into());
        self
    }

    pub fn span_id(mut self, id: impl Into<String>) -> Self {
        self.span_id = Some(id.into());
        self
    }

    pub fn debug_mode(mut self, enabled: bool) -> Self {
        self.debug_mode = Some(enabled);
        self
    }

    pub fn dry_run_mode(mut self, enabled: bool) -> Self {
        self.dry_run_mode = Some(enabled);
        self
    }

    // Data & Compliance builder methods
    pub fn data_classification(mut self, classification: impl Into<String>) -> Self {
        self.data_classification = Some(classification.into());
        self
    }

    pub fn encryption_required(mut self, required: bool) -> Self {
        self.encryption_required = Some(required);
        self
    }

    pub fn encryption_algorithm(mut self, algorithm: impl Into<String>) -> Self {
        self.encryption_algorithm = Some(algorithm.into());
        self
    }

    pub fn data_residency_region(mut self, region: impl Into<String>) -> Self {
        self.data_residency_region = Some(region.into());
        self
    }

    pub fn custom_value(mut self, key: impl Into<String>, value: ConditionValue) -> Self {
        self.custom_values.insert(key.into(), value);
        self
    }

    // Helper methods for test convenience
    pub fn principal_tag_role(mut self, roles: Vec<String>) -> Self {
        // For test convenience - sets principal tag Role
        if let Some(role) = roles.first() {
            self.principal_tags.insert("Role".to_string(), role.clone());
        }
        self
    }

    pub fn build(self) -> ConditionContext {
        ConditionContext {
            principal_arn: self.principal_arn,
            principal_account: self.principal_account,
            principal_type: self.principal_type,
            username: self.username,
            userid: self.userid,
            mfa_present: self.mfa_present,
            mfa_age: self.mfa_age,
            token_issue_time: self.token_issue_time,
            secure_transport: self.secure_transport,
            source_ip: self.source_ip,
            source_vpc: self.source_vpc,
            source_vpce: self.source_vpce,
            current_time: self.current_time.unwrap_or_else(chrono::Utc::now),
            requested_region: self.requested_region,
            referer: self.referer,
            user_agent: self.user_agent,
            resource_arn: self.resource_arn,
            resource_account: self.resource_account,
            principal_tags: self.principal_tags,
            resource_tags: self.resource_tags,
            request_tags: self.request_tags,
            tag_keys: self.tag_keys,
            tenant_id: self.tenant_id,
            principal_tenant_id: self.principal_tenant_id,
            resource_tenant_id: self.resource_tenant_id,
            tenant_name: self.tenant_name,
            tenant_status: self.tenant_status,
            cross_tenant_request: self.cross_tenant_request,
            provider: self.provider,
            source_provider: self.source_provider,
            target_provider: self.target_provider,
            provider_region: self.provider_region,
            cross_provider_request: self.cross_provider_request,
            request_method: self.request_method,
            request_protocol: self.request_protocol,
            api_version: self.api_version,
            request_path: self.request_path,
            request_query: self.request_query,
            content_type: self.content_type,
            accept_header: self.accept_header,
            origin: self.origin,
            host: self.host,
            application_id: self.application_id,
            application_version: self.application_version,
            client_id: self.client_id,
            client_type: self.client_type,
            device_id: self.device_id,
            device_type: self.device_type,
            platform: self.platform,
            session_id: self.session_id,
            session_age: self.session_age,
            authentication_method: self.authentication_method,
            authentication_strength: self.authentication_strength,
            session_risk_score: self.session_risk_score,
            ip_reputation: self.ip_reputation,
            geolocation_country: self.geolocation_country,
            geolocation_city: self.geolocation_city,
            vpn_detected: self.vpn_detected,
            proxy_detected: self.proxy_detected,
            requests_per_minute: self.requests_per_minute,
            requests_per_hour: self.requests_per_hour,
            requests_per_day: self.requests_per_day,
            quota_remaining: self.quota_remaining,
            quota_limit: self.quota_limit,
            burst_capacity_used: self.burst_capacity_used,
            request_id: self.request_id,
            correlation_id: self.correlation_id,
            trace_id: self.trace_id,
            span_id: self.span_id,
            debug_mode: self.debug_mode,
            dry_run_mode: self.dry_run_mode,
            data_classification: self.data_classification,
            encryption_required: self.encryption_required,
            encryption_algorithm: self.encryption_algorithm,
            data_residency_region: self.data_residency_region,
            custom_values: self.custom_values,
        }
    }
}
