//! WAMI Context - Authentication and Authorization Context
//!
//! The `WamiContext` carries authentication and authorization information for all WAMI operations.
//! It is created during authentication and used throughout the system to determine:
//! - Which tenant and instance the operation targets
//! - Who is performing the operation (caller identity)
//! - Whether authorization checks should be applied
//!
//! # Security
//!
//! **CRITICAL:** Contexts should ONLY be created through `AuthenticationService.authenticate()`.
//! The builder is public for internal use and testing, but manually creating contexts
//! bypasses authentication and is a security risk.
//!
//! # Proper Usage Example
//!
//! This example shows how `WamiContext` is used in the main `wami` crate.
//! In `wami-core`, you typically construct contexts directly using the builder:
//!
//! ```rust
//! use wami_core::arn::{TenantPath, WamiArn};
//! use wami_core::context::WamiContext;
//!
//! // The caller ARN is the only required field: the tenant path, the instance
//! // and whether the caller is root are all read from it.
//! let context = WamiContext::builder()
//!     .caller_arn(
//!         WamiArn::builder()
//!             .service(wami_core::arn::Service::Iam)
//!             .tenant_path(TenantPath::single(0))
//!             .wami_instance("123456789012")
//!             .resource("user", "admin")
//!             .build()
//!             .unwrap(),
//!     )
//!     .build()
//!     .unwrap();
//!
//! assert_eq!(context.instance_id(), "123456789012");
//! assert_eq!(context.tenant_path(), &TenantPath::single(0));
//! assert!(!context.is_root());
//! ```
//!
//! `tenant_path` and `instance_id` can still be set explicitly, but only to
//! widen an operation beyond the caller's own scope — cross-tenant work or
//! impersonation. Restating them to repeat what the ARN already says is what
//! allowed the two to drift apart.

use crate::arn::{TenantPath, WamiArn};
use crate::error::{AmiError, Result};
use serde::{Deserialize, Serialize};

/// How many times authority may pass hands within one context.
///
/// Reaching it refuses the transition rather than dropping the oldest step. A
/// truncated chain still satisfies any check made against it while no longer
/// describing what happened — an audit trail that lies is worse than one that
/// stops.
pub const MAX_PROVENANCE_DEPTH: usize = 8;

/// How authority passed to a principal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Transition {
    /// The principal proved who they are; the start of every chain.
    Authenticated,
    /// A role was assumed, under this session name.
    AssumedRole {
        /// The session name given at assumption time.
        session_name: String,
    },
    /// An SSO permission set was applied.
    PermissionSet {
        /// The permission set name.
        name: String,
    },
    /// An external identity provider vouched for the principal.
    Federated {
        /// The issuer that vouched.
        issuer: String,
    },
}

/// One link in the chain: who held authority, and how they came to hold it.
///
/// Deliberately not constructible from outside this crate. The chain is meant
/// to be trusted by policy conditions, and a `Step` anyone can build is a
/// provenance anyone can claim.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Step {
    principal: WamiArn,
    via: Transition,
}

impl Step {
    /// Who held authority at this step.
    pub fn principal(&self) -> &WamiArn {
        &self.principal
    }

    /// How they came to hold it.
    pub fn via(&self) -> &Transition {
        &self.via
    }
}

/// Session information for temporary credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    /// Session token identifier
    pub session_token: String,
    /// Session expiration time (Unix timestamp)
    pub expiration: i64,
    /// Assumed role ARN (if this is an assumed role session)
    pub assumed_role_arn: Option<WamiArn>,
}

/// WAMI Context - carries authentication and authorization information
///
/// This context is created during authentication and passed to all service operations.
/// It contains information about who is performing the operation and where it should be executed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "WireContext")]
pub struct WamiContext {
    /// The tenant path where operations will be performed
    tenant_path: TenantPath,

    /// The WAMI instance ID
    instance_id: String,

    /// The ARN of the caller (user or assumed role)
    caller_arn: WamiArn,

    /// How authority reached `caller_arn`, oldest first.
    ///
    /// The last step always names `caller_arn`: both are written by the same
    /// call, so the chain cannot come to describe someone other than the
    /// caller. Not settable through the builder — see `through`.
    provenance: Vec<Step>,

    /// Whether the caller is a root user (bypasses all authorization)
    is_root: bool,

    /// Optional default region for operations
    region: Option<String>,

    /// Optional session information for temporary credentials
    session_info: Option<SessionInfo>,

    /// Source IP address of the request (for condition evaluation)
    #[serde(skip_serializing_if = "Option::is_none")]
    source_ip: Option<String>,

    /// Whether MFA was used for authentication (for condition evaluation)
    #[serde(skip_serializing_if = "Option::is_none")]
    mfa_present: Option<bool>,

    /// Whether the request was made over a secure transport (HTTPS)
    #[serde(skip_serializing_if = "Option::is_none")]
    secure_transport: Option<bool>,
}

/// The wire shape a `WamiContext` is deserialised through.
///
/// `build` and `through` are the only ways to construct a context in memory,
/// and both keep the chain ending on `caller_arn`. Deserialisation bypasses
/// them, so it is checked here instead: a context arriving with an empty chain
/// would look entirely normal while `provenance().last()` returned `None` to
/// anything reading the chain to decide — a silent absence rather than a
/// refusal, which is the harder kind to notice.
#[derive(Deserialize)]
struct WireContext {
    tenant_path: TenantPath,
    instance_id: String,
    caller_arn: WamiArn,
    provenance: Vec<Step>,
    is_root: bool,
    region: Option<String>,
    session_info: Option<SessionInfo>,
    source_ip: Option<String>,
    mfa_present: Option<bool>,
    secure_transport: Option<bool>,
}

impl TryFrom<WireContext> for WamiContext {
    type Error = AmiError;

    fn try_from(wire: WireContext) -> Result<Self> {
        match wire.provenance.last() {
            None => {
                return Err(AmiError::InvalidParameter {
                    message: "context has no provenance: every context records how \
                              authority was obtained, starting at authentication"
                        .to_string(),
                })
            }
            Some(last) if last.principal != wire.caller_arn => {
                return Err(AmiError::InvalidParameter {
                    message: format!(
                        "provenance ends on {} but the caller is {}",
                        last.principal, wire.caller_arn
                    ),
                })
            }
            Some(_) => {}
        }

        if wire.provenance.len() > MAX_PROVENANCE_DEPTH {
            return Err(AmiError::InvalidParameter {
                message: format!(
                    "provenance is {} steps deep, past the maximum of {MAX_PROVENANCE_DEPTH}",
                    wire.provenance.len()
                ),
            });
        }

        Ok(WamiContext {
            tenant_path: wire.tenant_path,
            instance_id: wire.instance_id,
            caller_arn: wire.caller_arn,
            provenance: wire.provenance,
            is_root: wire.is_root,
            region: wire.region,
            session_info: wire.session_info,
            source_ip: wire.source_ip,
            mfa_present: wire.mfa_present,
            secure_transport: wire.secure_transport,
        })
    }
}

impl WamiContext {
    /// Create a new context builder
    pub fn builder() -> WamiContextBuilder {
        WamiContextBuilder::default()
    }

    /// Check if the caller is a root user
    ///
    /// Root users have full access and bypass all authorization checks.
    pub fn is_root(&self) -> bool {
        self.is_root
    }

    /// Get the caller's ARN
    pub fn caller_arn(&self) -> &WamiArn {
        &self.caller_arn
    }

    /// How authority reached the current caller, oldest first.
    ///
    /// The chain answers "by what route", which no ARN should: an ARN names a
    /// thing, and one that grows a segment per service traversed stops being
    /// comparable — policies matching on it would break, and a trailing
    /// wildcard added to compensate would swallow segments nobody intended.
    pub fn provenance(&self) -> &[Step] {
        &self.provenance
    }

    /// Derive the context that results from authority passing to `principal`.
    ///
    /// One call writes both the new caller and the step recording the move, so
    /// the chain cannot end up describing someone other than the caller. The
    /// tenant path and instance follow the new principal, exactly as they do
    /// when a context is built.
    ///
    /// Root is never regained: a context that was not root cannot become root
    /// by assuming something, whatever that something is named. It can only be
    /// kept, and only by staying on a root principal.
    ///
    /// Fails past [`MAX_PROVENANCE_DEPTH`].
    #[allow(clippy::result_large_err)]
    pub fn through(&self, principal: WamiArn, via: Transition) -> Result<WamiContext> {
        if self.provenance.len() >= MAX_PROVENANCE_DEPTH {
            return Err(AmiError::InvalidParameter {
                message: format!(
                    "authority has already passed hands {MAX_PROVENANCE_DEPTH} times in this context"
                ),
            });
        }

        let mut next = self.clone();
        next.is_root = self.is_root && principal.is_root_user();
        next.tenant_path = principal.tenant_path.clone();
        next.instance_id = principal.wami_instance_id.clone();

        // Attributes proving something about *who authenticated* do not survive
        // a change of identity. A caller who authenticated with MFA and then
        // assumed a role would otherwise still claim MFA, and a policy
        // requiring it on the role would see a factor belonging to someone who
        // is no longer the caller. Same for the session: one opened for alice
        // describes alice, not what she became.
        //
        // Applying a permission set is not a change of identity — the caller
        // stays who they were — so it keeps both.
        if matches!(
            via,
            Transition::AssumedRole { .. } | Transition::Federated { .. }
        ) {
            next.mfa_present = None;
            next.session_info = None;
        }

        // source_ip and secure_transport describe the request, not the
        // principal, and are true regardless of who holds authority.

        next.provenance.push(Step {
            principal: principal.clone(),
            via,
        });
        next.caller_arn = principal;
        Ok(next)
    }

    /// Get the tenant path
    pub fn tenant_path(&self) -> &TenantPath {
        &self.tenant_path
    }

    /// Get the instance ID
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    /// Get the default region (if set)
    pub fn region(&self) -> Option<&str> {
        self.region.as_deref()
    }

    /// Get session information (if temporary credentials)
    pub fn session_info(&self) -> Option<&SessionInfo> {
        self.session_info.as_ref()
    }

    /// Get the source IP address (if set)
    pub fn source_ip(&self) -> Option<&str> {
        self.source_ip.as_deref()
    }

    /// Check if MFA was used for this request (if known)
    pub fn mfa_present(&self) -> Option<bool> {
        self.mfa_present
    }

    /// Check if the request uses secure transport (if known)
    pub fn secure_transport(&self) -> Option<bool> {
        self.secure_transport
    }

    /// Check if this context can access a specific tenant path
    ///
    /// A context can access:
    /// - Its own tenant
    /// - Any child tenant below it in the hierarchy
    /// - If root user: any tenant in the instance
    pub fn can_access_tenant(&self, target_tenant: &TenantPath) -> bool {
        // Root user can access any tenant
        if self.is_root {
            return true;
        }

        // Check if target tenant is the same or a child of context tenant
        target_tenant.starts_with(self.tenant_path())
    }

    /// Check if the session has expired (for temporary credentials)
    pub fn is_expired(&self) -> bool {
        if let Some(session) = &self.session_info {
            let now = chrono::Utc::now().timestamp();
            return now >= session.expiration;
        }
        false
    }
}

/// Builder for creating a WamiContext
#[derive(Default)]
pub struct WamiContextBuilder {
    tenant_path: Option<TenantPath>,
    instance_id: Option<String>,
    caller_arn: Option<WamiArn>,
    /// `None` means "derive from the caller ARN"; an explicit value always wins.
    is_root: Option<bool>,
    region: Option<String>,
    session_info: Option<SessionInfo>,
    source_ip: Option<String>,
    mfa_present: Option<bool>,
    secure_transport: Option<bool>,
}

impl WamiContextBuilder {
    /// Set the tenant path
    pub fn tenant_path(mut self, tenant_path: TenantPath) -> Self {
        self.tenant_path = Some(tenant_path);
        self
    }

    /// Set the instance ID
    pub fn instance_id(mut self, instance_id: impl Into<String>) -> Self {
        self.instance_id = Some(instance_id.into());
        self
    }

    /// Set the caller ARN
    pub fn caller_arn(mut self, caller_arn: WamiArn) -> Self {
        self.caller_arn = Some(caller_arn);
        self
    }

    /// Set whether the caller is a root user
    ///
    /// Leave it unset to derive it from the caller ARN. An explicit value is
    /// never overridden — in particular `is_root(false)` stays false even for
    /// a root ARN, which is what makes deliberate privilege dropping possible.
    pub fn is_root(mut self, is_root: bool) -> Self {
        self.is_root = Some(is_root);
        self
    }

    /// Set the default region
    pub fn region(mut self, region: impl Into<String>) -> Self {
        self.region = Some(region.into());
        self
    }

    /// Set session information for temporary credentials
    pub fn session_info(mut self, session_info: SessionInfo) -> Self {
        self.session_info = Some(session_info);
        self
    }

    /// Set the source IP address of the request
    pub fn source_ip(mut self, ip: impl Into<String>) -> Self {
        self.source_ip = Some(ip.into());
        self
    }

    /// Set whether MFA was used for authentication
    pub fn mfa_present(mut self, present: bool) -> Self {
        self.mfa_present = Some(present);
        self
    }

    /// Set whether the request uses secure transport (HTTPS)
    pub fn secure_transport(mut self, secure: bool) -> Self {
        self.secure_transport = Some(secure);
        self
    }

    /// Build the WamiContext
    #[allow(clippy::result_large_err)]
    pub fn build(self) -> Result<WamiContext> {
        // The ARN comes first because the other three fields are derived from
        // it. Stating them again is allowed, but only to widen the scope of an
        // operation (cross-tenant, impersonation); leaving them out is the
        // normal case and cannot drift from the caller's identity.
        let caller_arn = self.caller_arn.ok_or_else(|| AmiError::InvalidParameter {
            message: "caller_arn is required".to_string(),
        })?;

        let tenant_path = self
            .tenant_path
            .unwrap_or_else(|| caller_arn.tenant_path.clone());

        let instance_id = self
            .instance_id
            .unwrap_or_else(|| caller_arn.wami_instance_id.clone());

        // Validate that instance_id is not empty
        if instance_id.trim().is_empty() {
            return Err(AmiError::InvalidParameter {
                message: "instance_id cannot be empty".to_string(),
            });
        }

        Ok(WamiContext {
            tenant_path,
            instance_id,
            is_root: self.is_root.unwrap_or_else(|| caller_arn.is_root_user()),
            // The chain starts here rather than at the first `through`, or an
            // audit trail would begin mid-route with no way to tell who came
            // first. A freshly built context is one that just proved itself.
            provenance: vec![Step {
                principal: caller_arn.clone(),
                via: Transition::Authenticated,
            }],
            caller_arn,
            region: self.region,
            session_info: self.session_info,
            source_ip: self.source_ip,
            mfa_present: self.mfa_present,
            secure_transport: self.secure_transport,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_builder() {
        let arn: WamiArn = "arn:wami:iam:12345678/87654321:wami:999888777:user/12345"
            .parse()
            .unwrap();

        let context = WamiContext::builder()
            .instance_id("999888777")
            .tenant_path(TenantPath::new(vec![12345678, 87654321]))
            .caller_arn(arn.clone())
            .is_root(false)
            .region("us-east-1")
            .build()
            .unwrap();

        assert_eq!(context.instance_id(), "999888777");
        assert_eq!(context.tenant_path().to_string(), "12345678/87654321");
        assert_eq!(context.caller_arn(), &arn);
        assert!(!context.is_root());
        assert_eq!(context.region(), Some("us-east-1"));
    }

    #[test]
    fn test_root_context() {
        let arn: WamiArn = "arn:wami:iam:0:wami:999888777:user/root".parse().unwrap();

        let context = WamiContext::builder()
            .instance_id("999888777")
            .tenant_path(TenantPath::single(0))
            .caller_arn(arn)
            .is_root(true)
            .build()
            .unwrap();

        assert!(context.is_root());
        assert_eq!(context.tenant_path().to_string(), "0");
    }

    #[test]
    fn test_can_access_tenant() {
        let arn: WamiArn = "arn:wami:iam:12345678:wami:999888777:user/12345"
            .parse()
            .unwrap();

        let context = WamiContext::builder()
            .instance_id("999888777")
            .tenant_path(TenantPath::single(12345678))
            .caller_arn(arn)
            .is_root(false)
            .build()
            .unwrap();

        // Can access same tenant
        assert!(context.can_access_tenant(&TenantPath::single(12345678)));

        // Can access child tenant
        assert!(context.can_access_tenant(&TenantPath::new(vec![12345678, 87654321])));

        // Cannot access sibling tenant
        assert!(!context.can_access_tenant(&TenantPath::single(99999999)));

        // Cannot access parent tenant (root)
        assert!(!context.can_access_tenant(&TenantPath::single(0)));
    }

    #[test]
    fn test_root_can_access_any_tenant() {
        let arn: WamiArn = "arn:wami:iam:0:wami:999888777:user/root".parse().unwrap();

        let context = WamiContext::builder()
            .instance_id("999888777")
            .tenant_path(TenantPath::single(0))
            .caller_arn(arn)
            .is_root(true)
            .build()
            .unwrap();

        // Root can access any tenant
        assert!(context.can_access_tenant(&TenantPath::single(0)));
        assert!(context.can_access_tenant(&TenantPath::single(12345678)));
        assert!(context.can_access_tenant(&TenantPath::new(vec![12345678, 87654321, 99999999])));
    }

    #[test]
    fn test_session_expiration() {
        let arn: WamiArn = "arn:wami:iam:12345678:wami:999888777:user/12345"
            .parse()
            .unwrap();

        let future_time = chrono::Utc::now().timestamp() + 3600; // 1 hour from now
        let session = SessionInfo {
            session_token: "token123".to_string(),
            expiration: future_time,
            assumed_role_arn: None,
        };

        let context = WamiContext::builder()
            .instance_id("999888777")
            .tenant_path(TenantPath::single(12345678))
            .caller_arn(arn)
            .session_info(session)
            .build()
            .unwrap();

        assert!(!context.is_expired());
    }

    #[test]
    fn test_expired_session() {
        let arn: WamiArn = "arn:wami:iam:12345678:wami:999888777:user/12345"
            .parse()
            .unwrap();

        let past_time = chrono::Utc::now().timestamp() - 3600; // 1 hour ago
        let session = SessionInfo {
            session_token: "token123".to_string(),
            expiration: past_time,
            assumed_role_arn: None,
        };

        let context = WamiContext::builder()
            .instance_id("999888777")
            .tenant_path(TenantPath::single(12345678))
            .caller_arn(arn)
            .session_info(session)
            .build()
            .unwrap();

        assert!(context.is_expired());
    }

    #[test]
    fn test_context_builder_all_fields() {
        let arn: WamiArn = "arn:wami:iam:12345678:wami:999888777:user/12345"
            .parse()
            .unwrap();
        let future_time = chrono::Utc::now().timestamp() + 3600;
        let session = SessionInfo {
            session_token: "token123".to_string(),
            expiration: future_time,
            assumed_role_arn: None,
        };

        let context = WamiContext::builder()
            .instance_id("999888777")
            .tenant_path(TenantPath::single(12345678))
            .caller_arn(arn.clone())
            .is_root(false)
            .region("us-west-2")
            .session_info(session.clone())
            .build()
            .unwrap();

        assert_eq!(context.instance_id(), "999888777");
        assert_eq!(context.caller_arn(), &arn);
        assert_eq!(context.region(), Some("us-west-2"));
        assert_eq!(
            context.session_info().map(|s| s.session_token.as_str()),
            Some("token123")
        );
    }

    #[test]
    fn test_context_without_optional_fields() {
        let arn: WamiArn = "arn:wami:iam:12345678:wami:999888777:user/12345"
            .parse()
            .unwrap();

        let context = WamiContext::builder()
            .instance_id("999888777")
            .tenant_path(TenantPath::single(12345678))
            .caller_arn(arn)
            .is_root(false)
            .build()
            .unwrap();

        assert_eq!(context.region(), None);
        assert!(context.session_info().is_none());
    }

    #[test]
    fn test_caller_arn_is_the_only_required_field() {
        // tenant_path and instance_id are derived, so neither is enough alone.
        let result = WamiContext::builder()
            .tenant_path(TenantPath::single(0))
            .build();
        assert!(result.is_err());

        let result = WamiContext::builder().instance_id("999888777").build();
        assert!(result.is_err());
    }

    /// Helper: an ARN for `user_id` inside `tenant`.
    fn arn_for(tenant: u64, user_id: &str) -> WamiArn {
        WamiArn::builder()
            .service(crate::arn::Service::Iam)
            .tenant_path(TenantPath::single(tenant))
            .wami_instance("999888777")
            .resource("user", user_id)
            .build()
            .unwrap()
    }

    #[test]
    fn test_scope_is_derived_from_caller_arn() {
        let context = WamiContext::builder()
            .caller_arn(arn_for(12345678, "alice"))
            .build()
            .unwrap();

        assert_eq!(context.tenant_path(), &TenantPath::single(12345678));
        assert_eq!(context.instance_id(), "999888777");
    }

    #[test]
    fn test_explicit_scope_still_wins() {
        // Cross-tenant operations are the reason the overrides remain.
        let context = WamiContext::builder()
            .caller_arn(arn_for(12345678, "alice"))
            .tenant_path(TenantPath::single(87654321))
            .instance_id("111222333")
            .build()
            .unwrap();

        assert_eq!(context.tenant_path(), &TenantPath::single(87654321));
        assert_eq!(context.instance_id(), "111222333");
    }

    #[test]
    fn test_root_is_derived_from_root_arn() {
        let context = WamiContext::builder()
            .caller_arn(arn_for(0, "root"))
            .build()
            .unwrap();

        assert!(context.is_root());
    }

    #[test]
    fn test_a_user_named_root_in_another_tenant_is_not_root() {
        // The whole reason is_root_user checks the tenant as well as the name:
        // is_root bypasses every authorization check, so it must not be
        // reachable by naming a resource `root` in a tenant one controls.
        let context = WamiContext::builder()
            .caller_arn(arn_for(12345678, "root"))
            .build()
            .unwrap();

        assert!(!context.is_root());
    }

    #[test]
    fn test_ordinary_user_in_root_tenant_is_not_root() {
        let context = WamiContext::builder()
            .caller_arn(arn_for(0, "alice"))
            .build()
            .unwrap();

        assert!(!context.is_root());
    }

    #[test]
    fn a_built_context_starts_its_chain_at_authentication() {
        // Starting at the first `through` would leave an audit trail beginning
        // mid-route, with nothing saying who came first.
        let context = WamiContext::builder()
            .caller_arn(arn_for(12345678, "alice"))
            .build()
            .unwrap();

        assert_eq!(context.provenance().len(), 1);
        assert_eq!(context.provenance()[0].via(), &Transition::Authenticated);
        assert_eq!(context.provenance()[0].principal(), context.caller_arn());
    }

    #[test]
    fn through_moves_the_caller_and_records_the_move_together() {
        let alice = WamiContext::builder()
            .caller_arn(arn_for(12345678, "alice"))
            .build()
            .unwrap();

        let role = arn_for(12345678, "DataScientist");
        let assumed = alice
            .through(
                role.clone(),
                Transition::AssumedRole {
                    session_name: "session1".to_string(),
                },
            )
            .unwrap();

        assert_eq!(assumed.caller_arn(), &role);
        assert_eq!(assumed.provenance().len(), 2);
        // The invariant that makes the chain worth trusting.
        assert_eq!(
            assumed.provenance().last().unwrap().principal(),
            assumed.caller_arn()
        );
        // And the question #49 wanted answered: who was it before?
        assert_eq!(assumed.provenance()[0].principal().resource_id(), "alice");
    }

    #[test]
    fn the_arn_itself_never_changes_shape() {
        // The whole reason provenance lives here and not in the ARN: a policy
        // matching on the caller must keep matching after a role is assumed.
        let alice_arn = arn_for(12345678, "alice");
        let alice = WamiContext::builder()
            .caller_arn(alice_arn.clone())
            .build()
            .unwrap();

        let assumed = alice
            .through(
                arn_for(12345678, "DataScientist"),
                Transition::AssumedRole {
                    session_name: "s".to_string(),
                },
            )
            .unwrap();

        assert_eq!(assumed.provenance()[0].principal(), &alice_arn);
        assert!(!assumed.caller_arn().to_string().contains("assumed-role"));
        assert!(!assumed.caller_arn().to_string().contains(":iam:policy"));
    }

    #[test]
    fn root_is_never_regained_by_assuming_something() {
        // A principal named `root` in the root tenant is what is_root_user
        // accepts — so this is the exact shape an escalation would take.
        let alice = WamiContext::builder()
            .caller_arn(arn_for(12345678, "alice"))
            .build()
            .unwrap();
        assert!(!alice.is_root());

        let escalated = alice
            .through(arn_for(0, "root"), Transition::Authenticated)
            .unwrap();
        assert!(!escalated.is_root(), "assuming root granted root");
    }

    #[test]
    fn root_is_dropped_when_authority_moves_elsewhere() {
        let root = WamiContext::builder()
            .caller_arn(arn_for(0, "root"))
            .build()
            .unwrap();
        assert!(root.is_root());

        let as_role = root
            .through(
                arn_for(12345678, "DataScientist"),
                Transition::AssumedRole {
                    session_name: "s".to_string(),
                },
            )
            .unwrap();
        assert!(!as_role.is_root());
    }

    #[test]
    fn scope_follows_the_new_principal() {
        // Same rule as build: two sources for one truth can disagree.
        let alice = WamiContext::builder()
            .caller_arn(arn_for(12345678, "alice"))
            .build()
            .unwrap();

        let elsewhere = alice
            .through(arn_for(87654321, "bob"), Transition::Authenticated)
            .unwrap();

        assert_eq!(elsewhere.tenant_path(), &TenantPath::single(87654321));
    }

    #[test]
    fn the_chain_refuses_to_grow_past_its_bound() {
        // Refused, not truncated: a shortened chain would still satisfy any
        // check made against it while no longer describing what happened.
        let mut context = WamiContext::builder()
            .caller_arn(arn_for(12345678, "alice"))
            .build()
            .unwrap();

        // One step is already spent on authentication.
        for i in 1..MAX_PROVENANCE_DEPTH {
            context = context
                .through(
                    arn_for(12345678, &format!("role{i}")),
                    Transition::Authenticated,
                )
                .unwrap();
        }
        assert_eq!(context.provenance().len(), MAX_PROVENANCE_DEPTH);

        let refused = context.through(arn_for(12345678, "one-too-many"), Transition::Authenticated);
        assert!(refused.is_err());
        assert_eq!(context.provenance().len(), MAX_PROVENANCE_DEPTH);
    }

    #[test]
    fn a_context_without_provenance_is_refused_on_the_wire() {
        // build() and through() keep the chain ending on caller_arn.
        // Deserialisation bypasses both, and an empty chain looks entirely
        // normal while provenance().last() returns None to whatever reads it.
        let json = r#"{
            "tenant_path": [12345678],
            "instance_id": "999888777",
            "caller_arn": "arn:wami:iam:12345678:wami:999888777:user/alice",
            "provenance": [],
            "is_root": false,
            "region": null,
            "session_info": null
        }"#;

        assert!(serde_json::from_str::<WamiContext>(json).is_err());
    }

    #[test]
    fn a_chain_ending_on_someone_else_is_refused() {
        // The forgery this guards: claim a route through a privileged role
        // while acting as somebody else entirely.
        let alice = WamiContext::builder()
            .caller_arn(arn_for(12345678, "alice"))
            .build()
            .unwrap();

        let mut tampered: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&alice).unwrap()).unwrap();
        tampered["caller_arn"] =
            serde_json::json!("arn:wami:iam:12345678:wami:999888777:user/mallory");

        let err = serde_json::from_value::<WamiContext>(tampered).unwrap_err();
        assert!(err.to_string().contains("provenance ends on"), "{err}");
    }

    #[test]
    fn an_overlong_chain_is_refused_on_the_wire() {
        // through() refuses to build one; the wire must not be a way around it.
        let mut context = WamiContext::builder()
            .caller_arn(arn_for(12345678, "alice"))
            .build()
            .unwrap();
        for i in 1..MAX_PROVENANCE_DEPTH {
            context = context
                .through(
                    arn_for(12345678, &format!("role{i}")),
                    Transition::Authenticated,
                )
                .unwrap();
        }

        let mut value: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&context).unwrap()).unwrap();
        let extra = value["provenance"][0].clone();
        value["provenance"].as_array_mut().unwrap().push(extra);

        assert!(serde_json::from_value::<WamiContext>(value).is_err());
    }

    #[test]
    fn assuming_a_role_drops_the_mfa_of_whoever_authenticated() {
        // alice proved MFA; DataScientist did not. Carrying the flag across
        // would show a policy a factor belonging to someone who is no longer
        // the caller.
        let alice = WamiContext::builder()
            .caller_arn(arn_for(12345678, "alice"))
            .mfa_present(true)
            .session_info(SessionInfo {
                session_token: "tok".to_string(),
                expiration: 9_999_999_999,
                assumed_role_arn: None,
            })
            .build()
            .unwrap();
        assert_eq!(alice.mfa_present(), Some(true));

        let assumed = alice
            .through(
                arn_for(12345678, "DataScientist"),
                Transition::AssumedRole {
                    session_name: "s".to_string(),
                },
            )
            .unwrap();

        assert_eq!(assumed.mfa_present(), None);
        assert!(assumed.session_info().is_none());
    }

    #[test]
    fn a_permission_set_is_not_a_change_of_identity() {
        // The caller stays who they were, so what they proved still holds.
        let alice = WamiContext::builder()
            .caller_arn(arn_for(12345678, "alice"))
            .mfa_present(true)
            .build()
            .unwrap();

        let scoped = alice
            .through(
                arn_for(12345678, "alice"),
                Transition::PermissionSet {
                    name: "DeveloperAccess".to_string(),
                },
            )
            .unwrap();

        assert_eq!(scoped.mfa_present(), Some(true));
    }

    #[test]
    fn request_attributes_survive_a_transition() {
        // The source address and transport describe the request, not the
        // principal — they are true whoever holds authority.
        let alice = WamiContext::builder()
            .caller_arn(arn_for(12345678, "alice"))
            .source_ip("203.0.113.7")
            .secure_transport(true)
            .build()
            .unwrap();

        let assumed = alice
            .through(
                arn_for(12345678, "role"),
                Transition::AssumedRole {
                    session_name: "s".to_string(),
                },
            )
            .unwrap();

        assert_eq!(assumed.source_ip(), Some("203.0.113.7"));
        assert_eq!(assumed.secure_transport(), Some(true));
    }

    #[test]
    fn deriving_a_context_leaves_the_original_alone() {
        let alice = WamiContext::builder()
            .caller_arn(arn_for(12345678, "alice"))
            .build()
            .unwrap();

        let _ = alice
            .through(arn_for(12345678, "role"), Transition::Authenticated)
            .unwrap();

        assert_eq!(alice.provenance().len(), 1);
        assert_eq!(alice.caller_arn().resource_id(), "alice");
    }

    #[test]
    fn transitions_survive_serialisation() {
        // The chain is only useful if it reaches a log or a policy engine.
        let context = WamiContext::builder()
            .caller_arn(arn_for(12345678, "alice"))
            .build()
            .unwrap()
            .through(
                arn_for(12345678, "DataScientist"),
                Transition::AssumedRole {
                    session_name: "session1".to_string(),
                },
            )
            .unwrap();

        let json = serde_json::to_string(&context).unwrap();
        let back: WamiContext = serde_json::from_str(&json).unwrap();

        assert_eq!(back.provenance(), context.provenance());
        assert_eq!(back.caller_arn(), context.caller_arn());
    }

    #[test]
    fn test_explicit_is_root_false_beats_a_root_arn() {
        // Dropping privileges deliberately has to remain possible.
        let context = WamiContext::builder()
            .caller_arn(arn_for(0, "root"))
            .is_root(false)
            .build()
            .unwrap();

        assert!(!context.is_root());
    }
}
