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

    // WAMI-specific
    pub tenant_id: Option<u64>,
    pub principal_tenant_id: Option<u64>,
    pub resource_tenant_id: Option<u64>,
    pub provider: Option<String>,
    pub source_provider: Option<String>,
    pub target_provider: Option<String>,

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
    provider: Option<String>,
    source_provider: Option<String>,
    target_provider: Option<String>,
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
            provider: self.provider,
            source_provider: self.source_provider,
            target_provider: self.target_provider,
            custom_values: self.custom_values,
        }
    }
}
