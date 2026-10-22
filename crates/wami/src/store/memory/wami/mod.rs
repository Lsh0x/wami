//! In-memory WAMI Store
//!
//! This is the main struct for the WAMI store. The actual trait implementations
//! are split across multiple files organized by functionality:
//! - `identity/` - UserStore, GroupStore, RoleStore
//! - `credentials/` - AccessKeyStore, MfaDeviceStore, LoginProfileStore
//! - `policies/` - PolicyStore

use crate::credentials::{AccessKey, LoginProfile, MfaDevice};
use crate::wami::identity::identity_provider::{OidcProvider, SamlProvider};
use crate::wami::identity::{Group, Role, User};
use crate::wami::policies::Policy;
use crate::wami::sso_admin::{
    AccountAssignment, Application, PermissionSet, SsoInstance, TrustedTokenIssuer,
};
use crate::wami::sts::{CallerIdentity, StsSession};
use crate::wami::tenant::{Tenant, TenantId};
use std::collections::HashMap;
use wami_core::arn::ScopedName;

/// In-memory implementation of WAMI store
///
/// This is a pure persistence layer that stores identity resources for ALL tenants
/// across ALL cloud providers. Each resource carries its own tenant_id, account_id,
/// and provider information.
///
/// # Architecture
///
/// The `WamiStore` trait is a composite of multiple sub-traits, each implemented
/// in its own file:
/// - `UserStore` → `memory/identity/user.rs`
/// - `GroupStore` → `memory/identity/group.rs`
/// - `RoleStore` → `memory/identity/role.rs`
/// - `PolicyStore` → `memory/policies/policy.rs` (TODO)
/// - `AccessKeyStore` → `memory/credentials/access_key.rs`
/// - `MfaDeviceStore` → `memory/credentials/mfa_device.rs` (TODO)
/// - `LoginProfileStore` → `memory/credentials/login_profile.rs` (TODO)
#[derive(Debug, Clone, Default)]
pub struct InMemoryWamiStore {
    // Principals, groups and certificates are keyed by ScopedName — the
    // tenant path and the name — never the bare name (wami 005).
    pub(super) users: HashMap<ScopedName, User>,
    pub(super) access_keys: HashMap<String, AccessKey>,
    pub(super) groups: HashMap<ScopedName, Group>,
    pub(super) roles: HashMap<ScopedName, Role>,
    pub(super) policies: HashMap<String, Policy>,
    pub(super) mfa_devices: HashMap<String, MfaDevice>,
    pub(super) login_profiles: HashMap<ScopedName, LoginProfile>,
    pub(super) user_groups: HashMap<ScopedName, Vec<ScopedName>>, // user -> groups
    pub(super) credential_report: Option<crate::wami::reports::credential_report::CredentialReport>,
    pub(super) server_certificates: HashMap<ScopedName, crate::credentials::ServerCertificate>,
    #[allow(dead_code)]
    pub(super) service_specific_credentials:
        HashMap<String, crate::credentials::service_credential::ServiceSpecificCredential>,
    pub(super) service_linked_role_deletion_tasks:
        HashMap<String, crate::wami::identity::service_linked_role::DeletionTaskInfo>,
    #[allow(dead_code)]
    pub(super) signing_certificates:
        HashMap<String, crate::credentials::signing_certificate::SigningCertificate>,
    // STS resources
    pub(super) sessions: HashMap<String, StsSession>,
    pub(super) identities: HashMap<String, CallerIdentity>,
    // Tenant resources
    pub(super) tenants: HashMap<TenantId, Tenant>,
    // SSO Admin resources
    pub(super) sso_instances: HashMap<String, SsoInstance>,
    pub(super) permission_sets: HashMap<String, PermissionSet>,
    pub(super) account_assignments: HashMap<String, AccountAssignment>,
    pub(super) applications: HashMap<String, Application>,
    pub(super) trusted_token_issuers: HashMap<String, TrustedTokenIssuer>,
    // Identity Provider resources
    pub(super) saml_providers: HashMap<String, SamlProvider>,
    pub(super) oidc_providers: HashMap<String, OidcProvider>,
    // Policy attachment resources
    // Managed policy attachments (policy ARN strings)
    pub(super) user_attached_policies: HashMap<ScopedName, Vec<String>>, // user -> [policy_arns]
    pub(super) group_attached_policies: HashMap<ScopedName, Vec<String>>, // group -> [policy_arns]
    pub(super) role_attached_policies: HashMap<ScopedName, Vec<String>>, // role -> [policy_arns]
    // Inline policies (policy_name -> policy_document JSON)
    pub(super) user_inline_policies: HashMap<ScopedName, HashMap<String, String>>, // user -> {policy_name -> document}
    pub(super) group_inline_policies: HashMap<ScopedName, HashMap<String, String>>, // group -> {policy_name -> document}
    pub(super) role_inline_policies: HashMap<ScopedName, HashMap<String, String>>, // role -> {policy_name -> document}
}

impl InMemoryWamiStore {
    /// Create a new empty WAMI store
    pub fn new() -> Self {
        Self::default()
    }
}

// Note: WamiStore is automatically implemented via blanket implementation
// because InMemoryWamiStore implements all required sub-traits in other files:
// - UserStore, GroupStore, RoleStore (identity/)
// - AccessKeyStore, MfaDeviceStore, LoginProfileStore (credentials/)
// - PolicyStore (policies/)
