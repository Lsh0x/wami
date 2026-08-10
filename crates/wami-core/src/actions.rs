//! WAMI Action vocabulary — the complete set of permissions for the obrain ecosystem.
//!
//! Each action follows the `service:Operation` convention (e.g. `"db:Query"`, `"tenant:Create"`).
//! Special wildcards:
//! - `"*"` matches ALL actions
//! - `"service:*"` matches all actions within a service prefix

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;
use std::sync::LazyLock;

// ---------------------------------------------------------------------------
// WamiAction enum
// ---------------------------------------------------------------------------

/// Exhaustive action vocabulary for the obrain ecosystem.
///
/// Actions are organized by service prefix:
/// - `platform:*` — Platform-level administration
/// - `tenant:*` — Tenant hierarchy management
/// - `iam:*` — Identity & access management
/// - `db:*` — Database / knowledge store operations
/// - `chat:*` — Chat and conversation
/// - `persona:*` — Persona management
/// - `room:*` — Room / channel management
/// - `inference:*` — Model and inference operations
/// - `analytics:*` — Analytics and reporting
/// - `integration:*` — External platform integrations
/// - `cognitive:*` — Cognitive layer (brain, memory)
/// - `gdpr:*` — GDPR / data privacy operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WamiAction {
    // -- Wildcards ----------------------------------------------------------
    /// Matches every action (`*`)
    All,
    /// Matches every action within a service prefix (`service:*`)
    ServiceAll(WamiServicePrefix),

    // -- platform -----------------------------------------------------------
    /// Full platform administration
    PlatformAdmin,
    /// View platform settings and stats
    PlatformViewSettings,
    /// Update platform configuration
    PlatformUpdateSettings,
    /// View platform audit logs
    PlatformViewAuditLog,

    // -- tenant -------------------------------------------------------------
    /// Create a new tenant
    TenantCreate,
    /// Configure tenant domain and port
    TenantConfigure,
    /// Manage tenant members (add, remove, ban)
    TenantManageMembers,
    /// Suspend a tenant
    ///
    /// Its opposite is `TenantResume` and not this: cutting access off and
    /// giving it back are not one permission. A tenant is usually suspended
    /// FOR a reason — unpaid, abusive, breached — and whoever may cut it off is
    /// not automatically whoever may decide the reason has passed.
    TenantSuspend,
    /// Lift a suspension
    TenantResume,
    /// List all tenants (platform-level)
    TenantList,

    // -- tenant -------------------------------------------------------------
    /// Read tenant info
    TenantRead,
    /// Update tenant
    TenantUpdate,
    /// Delete tenant
    TenantDelete,
    /// Create sub-tenant
    TenantCreateSubTenant,
    /// Manage users within tenant
    TenantManageUsers,
    /// Manage roles within tenant
    TenantManageRoles,
    /// Manage policies within tenant
    TenantManagePolicies,

    // -- iam ----------------------------------------------------------------
    /// Create IAM user
    IamCreateUser,
    /// Delete IAM user
    IamDeleteUser,
    /// Read IAM user info
    IamReadUser,
    /// Update IAM user
    IamUpdateUser,
    /// List IAM users
    IamListUsers,
    /// Create IAM group
    IamCreateGroup,
    /// Delete IAM group
    IamDeleteGroup,
    /// Manage group membership
    IamManageGroupMembers,
    /// Create IAM role
    IamCreateRole,
    /// Delete IAM role
    IamDeleteRole,
    /// Read IAM role
    IamReadRole,
    /// Assume IAM role
    IamAssumeRole,
    /// Create an IAM policy
    ///
    /// Attaching it is `IamAttachPolicy`, which exists. Saying both here would
    /// make that one grant nothing anybody could not already do.
    IamCreatePolicy,
    /// Delete an IAM policy
    ///
    /// Detaching it is `IamDetachPolicy`, for the same reason.
    IamDeletePolicy,
    /// Read IAM policy
    IamReadPolicy,
    /// Attach policy to user/group/role
    IamAttachPolicy,
    /// Detach policy from user/group/role
    IamDetachPolicy,
    /// Set permissions boundary
    IamSetBoundary,
    /// Manage credentials (access keys, MFA, etc.)
    IamManageCredentials,

    // -- db -----------------------------------------------------------------
    /// Query / read from a knowledge database
    DbQuery,
    /// Write / insert into a knowledge database
    DbWrite,
    /// Delete data from a knowledge database
    DbDelete,
    /// Create a new knowledge database
    DbCreate,
    /// Drop a knowledge database
    DbDrop,
    /// List available databases
    DbList,
    /// Configure database access policies
    DbConfigureAccess,
    /// Import data into a database
    DbImport,
    /// Export data from a database
    DbExport,

    // -- chat ---------------------------------------------------------------
    /// Send a chat message
    ChatSend,
    /// Read chat history
    ChatReadHistory,
    /// Delete a conversation
    ChatDeleteConversation,
    /// Use streaming chat (SSE)
    ChatStream,

    // -- persona ------------------------------------------------------------
    /// Create a persona
    PersonaCreate,
    /// Delete a persona
    PersonaDelete,
    /// Read persona info
    PersonaRead,
    /// Update persona configuration
    PersonaUpdate,
    /// List personas
    PersonaList,
    /// Invoke / use a persona in chat
    PersonaInvoke,

    // -- room ---------------------------------------------------------------
    /// Create a room / channel
    RoomCreate,
    /// Delete a room
    RoomDelete,
    /// Join a room
    RoomJoin,
    /// Read room messages
    RoomRead,
    /// Send message to room
    RoomSend,
    /// Manage room settings
    RoomManage,

    // -- inference ----------------------------------------------------------
    /// List available models
    InferenceListModels,
    /// Invoke a model (generate)
    InferenceInvoke,
    /// Configure model routing
    InferenceConfigureRouter,
    /// View model usage / costs
    InferenceViewUsage,

    // -- analytics ----------------------------------------------------------
    /// View usage analytics
    AnalyticsViewUsage,
    /// View conversation analytics
    AnalyticsViewConversations,
    /// Export analytics reports
    AnalyticsExport,
    /// View user activity
    AnalyticsViewActivity,

    // -- integration --------------------------------------------------------
    /// Create an integration bridge
    IntegrationCreate,
    /// Delete an integration bridge
    IntegrationDelete,
    /// Configure integration settings
    IntegrationConfigure,
    /// List integrations
    IntegrationList,
    /// Receive inbound messages (webhook)
    IntegrationReceive,
    /// Send outbound messages
    IntegrationSend,

    // -- cognitive ----------------------------------------------------------
    /// Read cognitive state (brain, memory)
    CognitiveRead,
    /// Write / update cognitive state
    CognitiveWrite,
    /// Reset cognitive state
    CognitiveReset,

    // -- gdpr ---------------------------------------------------------------
    /// Grant data consent
    GdprGrantConsent,
    /// Revoke data consent
    GdprRevokeConsent,
    /// Export personal data
    GdprExportData,
    /// Erase personal data (right to be forgotten)
    GdprEraseData,
    /// View audit log
    GdprViewAudit,
}

// ---------------------------------------------------------------------------
// Service prefixes
// ---------------------------------------------------------------------------

/// Service prefix for `ServiceAll` wildcard matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WamiServicePrefix {
    Platform,
    Tenant,
    Iam,
    Db,
    Chat,
    Persona,
    Room,
    Inference,
    Analytics,
    Integration,
    Cognitive,
    Gdpr,
}

impl WamiServicePrefix {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Platform => "platform",
            Self::Tenant => "tenant",
            Self::Iam => "iam",
            Self::Db => "db",
            Self::Chat => "chat",
            Self::Persona => "persona",
            Self::Room => "room",
            Self::Inference => "inference",
            Self::Analytics => "analytics",
            Self::Integration => "integration",
            Self::Cognitive => "cognitive",
            Self::Gdpr => "gdpr",
        }
    }

    pub fn all() -> &'static [WamiServicePrefix] {
        &[
            Self::Platform,
            Self::Tenant,
            Self::Iam,
            Self::Db,
            Self::Chat,
            Self::Persona,
            Self::Room,
            Self::Inference,
            Self::Analytics,
            Self::Integration,
            Self::Cognitive,
            Self::Gdpr,
        ]
    }
}

impl FromStr for WamiServicePrefix {
    type Err = ActionParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "platform" => Ok(Self::Platform),
            "tenant" => Ok(Self::Tenant),
            "iam" => Ok(Self::Iam),
            "db" => Ok(Self::Db),
            "chat" => Ok(Self::Chat),
            "persona" => Ok(Self::Persona),
            "room" => Ok(Self::Room),
            "inference" => Ok(Self::Inference),
            "analytics" => Ok(Self::Analytics),
            "integration" => Ok(Self::Integration),
            "cognitive" => Ok(Self::Cognitive),
            "gdpr" => Ok(Self::Gdpr),
            _ => Err(ActionParseError::UnknownPrefix(s.to_string())),
        }
    }
}

impl fmt::Display for WamiServicePrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Display / FromStr — "service:Operation" format
// ---------------------------------------------------------------------------

impl fmt::Display for WamiAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl WamiAction {
    /// String representation in `service:Operation` format.
    pub fn as_str(&self) -> &'static str {
        match self {
            // Wildcards
            Self::All => "*",
            Self::ServiceAll(prefix) => match prefix {
                WamiServicePrefix::Platform => "platform:*",
                WamiServicePrefix::Tenant => "tenant:*",
                WamiServicePrefix::Iam => "iam:*",
                WamiServicePrefix::Db => "db:*",
                WamiServicePrefix::Chat => "chat:*",
                WamiServicePrefix::Persona => "persona:*",
                WamiServicePrefix::Room => "room:*",
                WamiServicePrefix::Inference => "inference:*",
                WamiServicePrefix::Analytics => "analytics:*",
                WamiServicePrefix::Integration => "integration:*",
                WamiServicePrefix::Cognitive => "cognitive:*",
                WamiServicePrefix::Gdpr => "gdpr:*",
            },
            // Platform
            Self::PlatformAdmin => "platform:Admin",
            Self::PlatformViewSettings => "platform:ViewSettings",
            Self::PlatformUpdateSettings => "platform:UpdateSettings",
            Self::PlatformViewAuditLog => "platform:ViewAuditLog",
            Self::TenantCreate => "tenant:Create",
            Self::TenantConfigure => "tenant:Configure",
            Self::TenantManageMembers => "tenant:ManageMembers",
            Self::TenantSuspend => "tenant:Suspend",
            Self::TenantResume => "tenant:Resume",
            Self::TenantList => "tenant:List",
            // Tenant
            Self::TenantRead => "tenant:Read",
            Self::TenantUpdate => "tenant:Update",
            Self::TenantDelete => "tenant:Delete",
            Self::TenantCreateSubTenant => "tenant:CreateSubTenant",
            Self::TenantManageUsers => "tenant:ManageUsers",
            Self::TenantManageRoles => "tenant:ManageRoles",
            Self::TenantManagePolicies => "tenant:ManagePolicies",
            // IAM
            Self::IamCreateUser => "iam:CreateUser",
            Self::IamDeleteUser => "iam:DeleteUser",
            Self::IamReadUser => "iam:ReadUser",
            Self::IamUpdateUser => "iam:UpdateUser",
            Self::IamListUsers => "iam:ListUsers",
            Self::IamCreateGroup => "iam:CreateGroup",
            Self::IamDeleteGroup => "iam:DeleteGroup",
            Self::IamManageGroupMembers => "iam:ManageGroupMembers",
            Self::IamCreateRole => "iam:CreateRole",
            Self::IamDeleteRole => "iam:DeleteRole",
            Self::IamReadRole => "iam:ReadRole",
            Self::IamAssumeRole => "iam:AssumeRole",
            Self::IamCreatePolicy => "iam:CreatePolicy",
            Self::IamDeletePolicy => "iam:DeletePolicy",
            Self::IamReadPolicy => "iam:ReadPolicy",
            Self::IamAttachPolicy => "iam:AttachPolicy",
            Self::IamDetachPolicy => "iam:DetachPolicy",
            Self::IamSetBoundary => "iam:SetBoundary",
            Self::IamManageCredentials => "iam:ManageCredentials",
            // DB
            Self::DbQuery => "db:Query",
            Self::DbWrite => "db:Write",
            Self::DbDelete => "db:Delete",
            Self::DbCreate => "db:Create",
            Self::DbDrop => "db:Drop",
            Self::DbList => "db:List",
            Self::DbConfigureAccess => "db:ConfigureAccess",
            Self::DbImport => "db:Import",
            Self::DbExport => "db:Export",
            // Chat
            Self::ChatSend => "chat:Send",
            Self::ChatReadHistory => "chat:ReadHistory",
            Self::ChatDeleteConversation => "chat:DeleteConversation",
            Self::ChatStream => "chat:Stream",
            // Persona
            Self::PersonaCreate => "persona:Create",
            Self::PersonaDelete => "persona:Delete",
            Self::PersonaRead => "persona:Read",
            Self::PersonaUpdate => "persona:Update",
            Self::PersonaList => "persona:List",
            Self::PersonaInvoke => "persona:Invoke",
            // Room
            Self::RoomCreate => "room:Create",
            Self::RoomDelete => "room:Delete",
            Self::RoomJoin => "room:Join",
            Self::RoomRead => "room:Read",
            Self::RoomSend => "room:Send",
            Self::RoomManage => "room:Manage",
            // Inference
            Self::InferenceListModels => "inference:ListModels",
            Self::InferenceInvoke => "inference:Invoke",
            Self::InferenceConfigureRouter => "inference:ConfigureRouter",
            Self::InferenceViewUsage => "inference:ViewUsage",
            // Analytics
            Self::AnalyticsViewUsage => "analytics:ViewUsage",
            Self::AnalyticsViewConversations => "analytics:ViewConversations",
            Self::AnalyticsExport => "analytics:Export",
            Self::AnalyticsViewActivity => "analytics:ViewActivity",
            // Integration
            Self::IntegrationCreate => "integration:Create",
            Self::IntegrationDelete => "integration:Delete",
            Self::IntegrationConfigure => "integration:Configure",
            Self::IntegrationList => "integration:List",
            Self::IntegrationReceive => "integration:Receive",
            Self::IntegrationSend => "integration:Send",
            // Cognitive
            Self::CognitiveRead => "cognitive:Read",
            Self::CognitiveWrite => "cognitive:Write",
            Self::CognitiveReset => "cognitive:Reset",
            // GDPR
            Self::GdprGrantConsent => "gdpr:GrantConsent",
            Self::GdprRevokeConsent => "gdpr:RevokeConsent",
            Self::GdprExportData => "gdpr:ExportData",
            Self::GdprEraseData => "gdpr:EraseData",
            Self::GdprViewAudit => "gdpr:ViewAudit",
        }
    }

    /// Returns the service prefix for this action.
    pub fn prefix(&self) -> Option<WamiServicePrefix> {
        match self {
            Self::All => None,
            Self::ServiceAll(p) => Some(*p),
            Self::PlatformAdmin
            | Self::PlatformViewSettings
            | Self::PlatformUpdateSettings
            | Self::PlatformViewAuditLog => Some(WamiServicePrefix::Platform),
            Self::TenantCreate
            | Self::TenantConfigure
            | Self::TenantManageMembers
            | Self::TenantSuspend
            | Self::TenantResume
            | Self::TenantList
            | Self::TenantRead
            | Self::TenantUpdate
            | Self::TenantDelete
            | Self::TenantCreateSubTenant
            | Self::TenantManageUsers
            | Self::TenantManageRoles
            | Self::TenantManagePolicies => Some(WamiServicePrefix::Tenant),
            Self::IamCreateUser
            | Self::IamDeleteUser
            | Self::IamReadUser
            | Self::IamUpdateUser
            | Self::IamListUsers
            | Self::IamCreateGroup
            | Self::IamDeleteGroup
            | Self::IamManageGroupMembers
            | Self::IamCreateRole
            | Self::IamDeleteRole
            | Self::IamReadRole
            | Self::IamAssumeRole
            | Self::IamCreatePolicy
            | Self::IamDeletePolicy
            | Self::IamReadPolicy
            | Self::IamAttachPolicy
            | Self::IamDetachPolicy
            | Self::IamSetBoundary
            | Self::IamManageCredentials => Some(WamiServicePrefix::Iam),
            Self::DbQuery
            | Self::DbWrite
            | Self::DbDelete
            | Self::DbCreate
            | Self::DbDrop
            | Self::DbList
            | Self::DbConfigureAccess
            | Self::DbImport
            | Self::DbExport => Some(WamiServicePrefix::Db),
            Self::ChatSend
            | Self::ChatReadHistory
            | Self::ChatDeleteConversation
            | Self::ChatStream => Some(WamiServicePrefix::Chat),
            Self::PersonaCreate
            | Self::PersonaDelete
            | Self::PersonaRead
            | Self::PersonaUpdate
            | Self::PersonaList
            | Self::PersonaInvoke => Some(WamiServicePrefix::Persona),
            Self::RoomCreate
            | Self::RoomDelete
            | Self::RoomJoin
            | Self::RoomRead
            | Self::RoomSend
            | Self::RoomManage => Some(WamiServicePrefix::Room),
            Self::InferenceListModels
            | Self::InferenceInvoke
            | Self::InferenceConfigureRouter
            | Self::InferenceViewUsage => Some(WamiServicePrefix::Inference),
            Self::AnalyticsViewUsage
            | Self::AnalyticsViewConversations
            | Self::AnalyticsExport
            | Self::AnalyticsViewActivity => Some(WamiServicePrefix::Analytics),
            Self::IntegrationCreate
            | Self::IntegrationDelete
            | Self::IntegrationConfigure
            | Self::IntegrationList
            | Self::IntegrationReceive
            | Self::IntegrationSend => Some(WamiServicePrefix::Integration),
            Self::CognitiveRead | Self::CognitiveWrite | Self::CognitiveReset => {
                Some(WamiServicePrefix::Cognitive)
            }
            Self::GdprGrantConsent
            | Self::GdprRevokeConsent
            | Self::GdprExportData
            | Self::GdprEraseData
            | Self::GdprViewAudit => Some(WamiServicePrefix::Gdpr),
        }
    }
}

// ---------------------------------------------------------------------------
// Parse error
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, thiserror::Error)]
pub enum ActionParseError {
    #[error("unknown action: {0}")]
    Unknown(String),
    #[error("unknown service prefix: {0}")]
    UnknownPrefix(String),
    #[error("invalid action format (expected 'service:Operation' or '*'): {0}")]
    InvalidFormat(String),
}

// ---------------------------------------------------------------------------
// FromStr
// ---------------------------------------------------------------------------

impl FromStr for WamiAction {
    type Err = ActionParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Global wildcard
        if s == "*" {
            return Ok(Self::All);
        }

        // Must contain ':'
        let Some((prefix_str, operation)) = s.split_once(':') else {
            return Err(ActionParseError::InvalidFormat(s.to_string()));
        };

        // Service wildcard
        if operation == "*" {
            let prefix = WamiServicePrefix::from_str(prefix_str)?;
            return Ok(Self::ServiceAll(prefix));
        }

        // Exact match
        match (prefix_str, operation) {
            // Platform
            ("platform", "Admin") => Ok(Self::PlatformAdmin),
            ("platform", "ViewSettings") => Ok(Self::PlatformViewSettings),
            ("platform", "UpdateSettings") => Ok(Self::PlatformUpdateSettings),
            ("platform", "ViewAuditLog") => Ok(Self::PlatformViewAuditLog),
            // Tenant
            ("tenant", "Create") => Ok(Self::TenantCreate),
            ("tenant", "Configure") => Ok(Self::TenantConfigure),
            ("tenant", "ManageMembers") => Ok(Self::TenantManageMembers),
            ("tenant", "Suspend") => Ok(Self::TenantSuspend),
            ("tenant", "Resume") => Ok(Self::TenantResume),
            ("tenant", "List") => Ok(Self::TenantList),
            ("tenant", "Read") => Ok(Self::TenantRead),
            ("tenant", "Update") => Ok(Self::TenantUpdate),
            ("tenant", "Delete") => Ok(Self::TenantDelete),
            ("tenant", "CreateSubTenant") => Ok(Self::TenantCreateSubTenant),
            ("tenant", "ManageUsers") => Ok(Self::TenantManageUsers),
            ("tenant", "ManageRoles") => Ok(Self::TenantManageRoles),
            ("tenant", "ManagePolicies") => Ok(Self::TenantManagePolicies),
            // IAM
            ("iam", "CreateUser") => Ok(Self::IamCreateUser),
            ("iam", "DeleteUser") => Ok(Self::IamDeleteUser),
            ("iam", "ReadUser") => Ok(Self::IamReadUser),
            ("iam", "UpdateUser") => Ok(Self::IamUpdateUser),
            ("iam", "ListUsers") => Ok(Self::IamListUsers),
            ("iam", "CreateGroup") => Ok(Self::IamCreateGroup),
            ("iam", "DeleteGroup") => Ok(Self::IamDeleteGroup),
            ("iam", "ManageGroupMembers") => Ok(Self::IamManageGroupMembers),
            ("iam", "CreateRole") => Ok(Self::IamCreateRole),
            ("iam", "DeleteRole") => Ok(Self::IamDeleteRole),
            ("iam", "ReadRole") => Ok(Self::IamReadRole),
            ("iam", "AssumeRole") => Ok(Self::IamAssumeRole),
            ("iam", "CreatePolicy") => Ok(Self::IamCreatePolicy),
            ("iam", "DeletePolicy") => Ok(Self::IamDeletePolicy),
            ("iam", "ReadPolicy") => Ok(Self::IamReadPolicy),
            ("iam", "AttachPolicy") => Ok(Self::IamAttachPolicy),
            ("iam", "DetachPolicy") => Ok(Self::IamDetachPolicy),
            ("iam", "SetBoundary") => Ok(Self::IamSetBoundary),
            ("iam", "ManageCredentials") => Ok(Self::IamManageCredentials),
            // DB
            ("db", "Query") => Ok(Self::DbQuery),
            ("db", "Write") => Ok(Self::DbWrite),
            ("db", "Delete") => Ok(Self::DbDelete),
            ("db", "Create") => Ok(Self::DbCreate),
            ("db", "Drop") => Ok(Self::DbDrop),
            ("db", "List") => Ok(Self::DbList),
            ("db", "ConfigureAccess") => Ok(Self::DbConfigureAccess),
            ("db", "Import") => Ok(Self::DbImport),
            ("db", "Export") => Ok(Self::DbExport),
            // Chat
            ("chat", "Send") => Ok(Self::ChatSend),
            ("chat", "ReadHistory") => Ok(Self::ChatReadHistory),
            ("chat", "DeleteConversation") => Ok(Self::ChatDeleteConversation),
            ("chat", "Stream") => Ok(Self::ChatStream),
            // Persona
            ("persona", "Create") => Ok(Self::PersonaCreate),
            ("persona", "Delete") => Ok(Self::PersonaDelete),
            ("persona", "Read") => Ok(Self::PersonaRead),
            ("persona", "Update") => Ok(Self::PersonaUpdate),
            ("persona", "List") => Ok(Self::PersonaList),
            ("persona", "Invoke") => Ok(Self::PersonaInvoke),
            // Room
            ("room", "Create") => Ok(Self::RoomCreate),
            ("room", "Delete") => Ok(Self::RoomDelete),
            ("room", "Join") => Ok(Self::RoomJoin),
            ("room", "Read") => Ok(Self::RoomRead),
            ("room", "Send") => Ok(Self::RoomSend),
            ("room", "Manage") => Ok(Self::RoomManage),
            // Inference
            ("inference", "ListModels") => Ok(Self::InferenceListModels),
            ("inference", "Invoke") => Ok(Self::InferenceInvoke),
            ("inference", "ConfigureRouter") => Ok(Self::InferenceConfigureRouter),
            ("inference", "ViewUsage") => Ok(Self::InferenceViewUsage),
            // Analytics
            ("analytics", "ViewUsage") => Ok(Self::AnalyticsViewUsage),
            ("analytics", "ViewConversations") => Ok(Self::AnalyticsViewConversations),
            ("analytics", "Export") => Ok(Self::AnalyticsExport),
            ("analytics", "ViewActivity") => Ok(Self::AnalyticsViewActivity),
            // Integration
            ("integration", "Create") => Ok(Self::IntegrationCreate),
            ("integration", "Delete") => Ok(Self::IntegrationDelete),
            ("integration", "Configure") => Ok(Self::IntegrationConfigure),
            ("integration", "List") => Ok(Self::IntegrationList),
            ("integration", "Receive") => Ok(Self::IntegrationReceive),
            ("integration", "Send") => Ok(Self::IntegrationSend),
            // Cognitive
            ("cognitive", "Read") => Ok(Self::CognitiveRead),
            ("cognitive", "Write") => Ok(Self::CognitiveWrite),
            ("cognitive", "Reset") => Ok(Self::CognitiveReset),
            // GDPR
            ("gdpr", "GrantConsent") => Ok(Self::GdprGrantConsent),
            ("gdpr", "RevokeConsent") => Ok(Self::GdprRevokeConsent),
            ("gdpr", "ExportData") => Ok(Self::GdprExportData),
            ("gdpr", "EraseData") => Ok(Self::GdprEraseData),
            ("gdpr", "ViewAudit") => Ok(Self::GdprViewAudit),
            _ => Err(ActionParseError::Unknown(s.to_string())),
        }
    }
}

// ---------------------------------------------------------------------------
// Serde — serialize as string
// ---------------------------------------------------------------------------

impl Serialize for WamiAction {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for WamiAction {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        WamiAction::from_str(&s).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Wildcard matching
// ---------------------------------------------------------------------------

impl WamiAction {
    /// Check whether `self` (a policy action pattern) matches a `requested` action.
    ///
    /// Matching rules:
    /// - `All` (`*`) matches everything
    /// - `ServiceAll(prefix)` (`service:*`) matches any action in that service
    /// - Exact variant matches only itself
    ///
    /// This also supports **string-based** matching for backward compatibility
    /// with existing `Vec<String>` policy statements.
    pub fn matches(&self, requested: &WamiAction) -> bool {
        match self {
            // Global wildcard matches everything
            Self::All => true,
            // Service wildcard matches anything in the same prefix
            Self::ServiceAll(prefix) => requested.prefix() == Some(*prefix),
            // Exact match
            other => other == requested,
        }
    }

    /// Check whether a policy action **string** matches a requested action string.
    ///
    /// This provides backward compatibility with the existing `Vec<String>` in
    /// `PolicyStatement` without requiring a full migration to the enum.
    ///
    /// Supports: `"*"`, `"service:*"`, and exact strings like `"db:Query"`.
    pub fn matches_str(policy_action: &str, requested: &str) -> bool {
        if policy_action == "*" {
            return true;
        }
        if policy_action == requested {
            return true;
        }
        // Prefix wildcard: "iam:*" matches "iam:CreateUser"
        if let Some(prefix) = policy_action.strip_suffix(":*") {
            if let Some(req_prefix) = requested.split_once(':').map(|(p, _)| p) {
                return prefix == req_prefix;
            }
        }
        false
    }
}

// ---------------------------------------------------------------------------
// ActionRegistry — metadata for UI consumption
// ---------------------------------------------------------------------------

/// Metadata about a single action, for UI display and policy builders.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionInfo {
    /// The action string (e.g. `"db:Query"`)
    pub action: String,
    /// Human-readable description
    pub description: String,
    /// Service category (e.g. `"db"`, `"iam"`)
    pub category: String,
}

/// Registry of all known actions with their metadata.
pub struct ActionRegistry;

impl ActionRegistry {
    /// Return all registered actions with their descriptions.
    pub fn list_actions() -> &'static [ActionInfo] {
        &REGISTRY
    }

    /// List actions filtered by service prefix.
    pub fn list_by_prefix(prefix: WamiServicePrefix) -> Vec<&'static ActionInfo> {
        let prefix_str = prefix.as_str();
        REGISTRY
            .iter()
            .filter(|info| info.category == prefix_str)
            .collect()
    }

    /// List all service prefixes.
    pub fn list_prefixes() -> &'static [WamiServicePrefix] {
        WamiServicePrefix::all()
    }
}

// The static registry, built once.
static REGISTRY: LazyLock<Vec<ActionInfo>> = LazyLock::new(|| {
    vec![
        // Platform
        ai("platform:Admin", "Full platform administration", "platform"),
        ai(
            "platform:ViewSettings",
            "View platform settings and stats",
            "platform",
        ),
        ai(
            "platform:UpdateSettings",
            "Update platform configuration",
            "platform",
        ),
        ai(
            "platform:ViewAuditLog",
            "View platform audit logs",
            "platform",
        ),
        // Tenant
        ai("tenant:Create", "Create a new tenant", "tenant"),
        ai(
            "tenant:Configure",
            "Configure tenant domain and port",
            "tenant",
        ),
        ai("tenant:ManageMembers", "Manage tenant members", "tenant"),
        ai("tenant:Suspend", "Suspend a tenant", "tenant"),
        ai("tenant:Resume", "Lift a tenant suspension", "tenant"),
        ai("tenant:List", "List all tenants (platform-level)", "tenant"),
        ai("tenant:Read", "Read tenant info", "tenant"),
        ai("tenant:Update", "Update tenant", "tenant"),
        ai("tenant:Delete", "Delete tenant", "tenant"),
        ai("tenant:CreateSubTenant", "Create sub-tenant", "tenant"),
        ai("tenant:ManageUsers", "Manage users within tenant", "tenant"),
        ai("tenant:ManageRoles", "Manage roles within tenant", "tenant"),
        ai(
            "tenant:ManagePolicies",
            "Manage policies within tenant",
            "tenant",
        ),
        // IAM
        ai("iam:CreateUser", "Create IAM user", "iam"),
        ai("iam:DeleteUser", "Delete IAM user", "iam"),
        ai("iam:ReadUser", "Read IAM user info", "iam"),
        ai("iam:UpdateUser", "Update IAM user", "iam"),
        ai("iam:ListUsers", "List IAM users", "iam"),
        ai("iam:CreateGroup", "Create IAM group", "iam"),
        ai("iam:DeleteGroup", "Delete IAM group", "iam"),
        ai("iam:ManageGroupMembers", "Manage group membership", "iam"),
        ai("iam:CreateRole", "Create IAM role", "iam"),
        ai("iam:DeleteRole", "Delete IAM role", "iam"),
        ai("iam:ReadRole", "Read IAM role", "iam"),
        ai("iam:AssumeRole", "Assume IAM role", "iam"),
        ai("iam:CreatePolicy", "Create IAM policy", "iam"),
        ai("iam:DeletePolicy", "Delete IAM policy", "iam"),
        ai("iam:ReadPolicy", "Read IAM policy", "iam"),
        ai("iam:AttachPolicy", "Attach policy to entity", "iam"),
        ai("iam:DetachPolicy", "Detach policy from entity", "iam"),
        ai("iam:SetBoundary", "Set permissions boundary", "iam"),
        ai("iam:ManageCredentials", "Manage credentials", "iam"),
        // DB
        ai("db:Query", "Query a knowledge database", "db"),
        ai("db:Write", "Write to a knowledge database", "db"),
        ai("db:Delete", "Delete data from database", "db"),
        ai("db:Create", "Create a knowledge database", "db"),
        ai("db:Drop", "Drop a knowledge database", "db"),
        ai("db:List", "List available databases", "db"),
        ai("db:ConfigureAccess", "Configure database access", "db"),
        ai("db:Import", "Import data into database", "db"),
        ai("db:Export", "Export data from database", "db"),
        // Chat
        ai("chat:Send", "Send a chat message", "chat"),
        ai("chat:ReadHistory", "Read chat history", "chat"),
        ai("chat:DeleteConversation", "Delete a conversation", "chat"),
        ai("chat:Stream", "Use streaming chat (SSE)", "chat"),
        // Persona
        ai("persona:Create", "Create a persona", "persona"),
        ai("persona:Delete", "Delete a persona", "persona"),
        ai("persona:Read", "Read persona info", "persona"),
        ai("persona:Update", "Update persona configuration", "persona"),
        ai("persona:List", "List personas", "persona"),
        ai("persona:Invoke", "Invoke a persona in chat", "persona"),
        // Room
        ai("room:Create", "Create a room", "room"),
        ai("room:Delete", "Delete a room", "room"),
        ai("room:Join", "Join a room", "room"),
        ai("room:Read", "Read room messages", "room"),
        ai("room:Send", "Send message to room", "room"),
        ai("room:Manage", "Manage room settings", "room"),
        // Inference
        ai("inference:ListModels", "List available models", "inference"),
        ai("inference:Invoke", "Invoke a model", "inference"),
        ai(
            "inference:ConfigureRouter",
            "Configure model routing",
            "inference",
        ),
        ai("inference:ViewUsage", "View model usage", "inference"),
        // Analytics
        ai("analytics:ViewUsage", "View usage analytics", "analytics"),
        ai(
            "analytics:ViewConversations",
            "View conversation analytics",
            "analytics",
        ),
        ai("analytics:Export", "Export analytics reports", "analytics"),
        ai("analytics:ViewActivity", "View user activity", "analytics"),
        // Integration
        ai(
            "integration:Create",
            "Create integration bridge",
            "integration",
        ),
        ai(
            "integration:Delete",
            "Delete integration bridge",
            "integration",
        ),
        ai(
            "integration:Configure",
            "Configure integration",
            "integration",
        ),
        ai("integration:List", "List integrations", "integration"),
        ai(
            "integration:Receive",
            "Receive inbound messages",
            "integration",
        ),
        ai("integration:Send", "Send outbound messages", "integration"),
        // Cognitive
        ai("cognitive:Read", "Read cognitive state", "cognitive"),
        ai("cognitive:Write", "Write cognitive state", "cognitive"),
        ai("cognitive:Reset", "Reset cognitive state", "cognitive"),
        // GDPR
        ai("gdpr:GrantConsent", "Grant data consent", "gdpr"),
        ai("gdpr:RevokeConsent", "Revoke data consent", "gdpr"),
        ai("gdpr:ExportData", "Export personal data", "gdpr"),
        ai("gdpr:EraseData", "Erase personal data", "gdpr"),
        ai("gdpr:ViewAudit", "View GDPR audit log", "gdpr"),
    ]
});

/// Helper to construct an [`ActionInfo`].
fn ai(action: &str, description: &str, category: &str) -> ActionInfo {
    ActionInfo {
        action: action.to_string(),
        description: description.to_string(),
        category: category.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_roundtrip() {
        let action = WamiAction::DbQuery;
        let json = serde_json::to_string(&action).unwrap();
        assert_eq!(json, r#""db:Query""#);

        let parsed: WamiAction = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, WamiAction::DbQuery);
    }

    #[test]
    fn serde_wildcard_roundtrip() {
        let all = WamiAction::All;
        assert_eq!(serde_json::to_string(&all).unwrap(), r#""*""#);

        let svc = WamiAction::ServiceAll(WamiServicePrefix::Iam);
        assert_eq!(serde_json::to_string(&svc).unwrap(), r#""iam:*""#);

        let parsed: WamiAction = serde_json::from_str(r#""iam:*""#).unwrap();
        assert_eq!(parsed, WamiAction::ServiceAll(WamiServicePrefix::Iam));
    }

    #[test]
    fn from_str_roundtrip_all_actions() {
        // Every action should survive a roundtrip: Display → FromStr
        let actions = vec![
            WamiAction::All,
            WamiAction::ServiceAll(WamiServicePrefix::Db),
            WamiAction::PlatformAdmin,
            WamiAction::TenantCreate,
            WamiAction::TenantRead,
            WamiAction::IamCreateUser,
            WamiAction::DbQuery,
            WamiAction::ChatSend,
            WamiAction::PersonaInvoke,
            WamiAction::RoomCreate,
            WamiAction::InferenceInvoke,
            WamiAction::AnalyticsExport,
            WamiAction::IntegrationCreate,
            WamiAction::CognitiveRead,
            WamiAction::GdprEraseData,
        ];
        for action in actions {
            let s = action.to_string();
            let parsed = WamiAction::from_str(&s).unwrap_or_else(|e| {
                panic!("Failed to parse '{}': {}", s, e);
            });
            assert_eq!(parsed, action, "Roundtrip failed for {}", s);
        }
    }

    #[test]
    fn from_str_errors() {
        assert!(WamiAction::from_str("invalid").is_err());
        assert!(WamiAction::from_str("unknown:Action").is_err());
        assert!(WamiAction::from_str("db:NonExistent").is_err());
        assert!(WamiAction::from_str("").is_err());
    }

    #[test]
    fn wildcard_matching() {
        let all = WamiAction::All;
        let iam_all = WamiAction::ServiceAll(WamiServicePrefix::Iam);
        let create_user = WamiAction::IamCreateUser;
        let db_query = WamiAction::DbQuery;

        // * matches everything
        assert!(all.matches(&create_user));
        assert!(all.matches(&db_query));
        assert!(all.matches(&iam_all));

        // iam:* matches iam:CreateUser but not db:Query
        assert!(iam_all.matches(&create_user));
        assert!(!iam_all.matches(&db_query));

        // Exact match
        assert!(create_user.matches(&create_user));
        assert!(!create_user.matches(&db_query));
    }

    #[test]
    fn matches_str_backward_compat() {
        assert!(WamiAction::matches_str("*", "db:Query"));
        assert!(WamiAction::matches_str("db:*", "db:Query"));
        assert!(WamiAction::matches_str("db:Query", "db:Query"));
        assert!(!WamiAction::matches_str("db:*", "iam:CreateUser"));
        assert!(!WamiAction::matches_str("db:Query", "db:Write"));
    }

    #[test]
    fn prefix_extraction() {
        assert_eq!(WamiAction::All.prefix(), None);
        assert_eq!(
            WamiAction::ServiceAll(WamiServicePrefix::Db).prefix(),
            Some(WamiServicePrefix::Db)
        );
        assert_eq!(WamiAction::DbQuery.prefix(), Some(WamiServicePrefix::Db));
        assert_eq!(
            WamiAction::IamCreateUser.prefix(),
            Some(WamiServicePrefix::Iam)
        );
    }

    #[test]
    fn registry() {
        let all = ActionRegistry::list_actions();
        // We have ~74 concrete actions (excluding wildcards)
        assert!(
            all.len() >= 70,
            "Expected at least 70 actions, got {}",
            all.len()
        );

        let db_actions = ActionRegistry::list_by_prefix(WamiServicePrefix::Db);
        assert_eq!(db_actions.len(), 9);
        assert!(db_actions.iter().all(|a| a.category == "db"));

        let iam_actions = ActionRegistry::list_by_prefix(WamiServicePrefix::Iam);
        assert_eq!(iam_actions.len(), 19);
    }

    // -----------------------------------------------------------------------
    // Exhaustive list of every concrete action variant (no wildcards)
    // -----------------------------------------------------------------------

    fn all_concrete_actions() -> Vec<WamiAction> {
        vec![
            // Platform
            WamiAction::PlatformAdmin,
            WamiAction::PlatformViewSettings,
            WamiAction::PlatformUpdateSettings,
            WamiAction::PlatformViewAuditLog,
            WamiAction::TenantCreate,
            WamiAction::TenantConfigure,
            WamiAction::TenantManageMembers,
            WamiAction::TenantSuspend,
            WamiAction::TenantResume,
            WamiAction::TenantList,
            // Tenant
            WamiAction::TenantRead,
            WamiAction::TenantUpdate,
            WamiAction::TenantDelete,
            WamiAction::TenantCreateSubTenant,
            WamiAction::TenantManageUsers,
            WamiAction::TenantManageRoles,
            WamiAction::TenantManagePolicies,
            // IAM
            WamiAction::IamCreateUser,
            WamiAction::IamDeleteUser,
            WamiAction::IamReadUser,
            WamiAction::IamUpdateUser,
            WamiAction::IamListUsers,
            WamiAction::IamCreateGroup,
            WamiAction::IamDeleteGroup,
            WamiAction::IamManageGroupMembers,
            WamiAction::IamCreateRole,
            WamiAction::IamDeleteRole,
            WamiAction::IamReadRole,
            WamiAction::IamAssumeRole,
            WamiAction::IamCreatePolicy,
            WamiAction::IamDeletePolicy,
            WamiAction::IamReadPolicy,
            WamiAction::IamAttachPolicy,
            WamiAction::IamDetachPolicy,
            WamiAction::IamSetBoundary,
            WamiAction::IamManageCredentials,
            // DB
            WamiAction::DbQuery,
            WamiAction::DbWrite,
            WamiAction::DbDelete,
            WamiAction::DbCreate,
            WamiAction::DbDrop,
            WamiAction::DbList,
            WamiAction::DbConfigureAccess,
            WamiAction::DbImport,
            WamiAction::DbExport,
            // Chat
            WamiAction::ChatSend,
            WamiAction::ChatReadHistory,
            WamiAction::ChatDeleteConversation,
            WamiAction::ChatStream,
            // Persona
            WamiAction::PersonaCreate,
            WamiAction::PersonaDelete,
            WamiAction::PersonaRead,
            WamiAction::PersonaUpdate,
            WamiAction::PersonaList,
            WamiAction::PersonaInvoke,
            // Room
            WamiAction::RoomCreate,
            WamiAction::RoomDelete,
            WamiAction::RoomJoin,
            WamiAction::RoomRead,
            WamiAction::RoomSend,
            WamiAction::RoomManage,
            // Inference
            WamiAction::InferenceListModels,
            WamiAction::InferenceInvoke,
            WamiAction::InferenceConfigureRouter,
            WamiAction::InferenceViewUsage,
            // Analytics
            WamiAction::AnalyticsViewUsage,
            WamiAction::AnalyticsViewConversations,
            WamiAction::AnalyticsExport,
            WamiAction::AnalyticsViewActivity,
            // Integration
            WamiAction::IntegrationCreate,
            WamiAction::IntegrationDelete,
            WamiAction::IntegrationConfigure,
            WamiAction::IntegrationList,
            WamiAction::IntegrationReceive,
            WamiAction::IntegrationSend,
            // Cognitive
            WamiAction::CognitiveRead,
            WamiAction::CognitiveWrite,
            WamiAction::CognitiveReset,
            // GDPR
            WamiAction::GdprGrantConsent,
            WamiAction::GdprRevokeConsent,
            WamiAction::GdprExportData,
            WamiAction::GdprEraseData,
            WamiAction::GdprViewAudit,
        ]
    }

    // -----------------------------------------------------------------------
    // Round-trip: as_str -> from_str for EVERY variant
    // -----------------------------------------------------------------------

    #[test]
    fn roundtrip_every_concrete_action() {
        for action in all_concrete_actions() {
            let s = action.as_str();
            let parsed = WamiAction::from_str(s)
                .unwrap_or_else(|e| panic!("from_str({:?}) failed: {}", s, e));
            assert_eq!(parsed, action, "roundtrip failed for {:?}", s);
        }
    }

    #[test]
    fn roundtrip_all_service_wildcards() {
        for prefix in WamiServicePrefix::all() {
            let action = WamiAction::ServiceAll(*prefix);
            let s = action.as_str();
            assert!(s.ends_with(":*"), "ServiceAll as_str should end with :*");
            let parsed = WamiAction::from_str(s).unwrap();
            assert_eq!(parsed, action);
        }
    }

    #[test]
    fn roundtrip_global_wildcard() {
        assert_eq!(WamiAction::from_str("*").unwrap(), WamiAction::All);
        assert_eq!(WamiAction::All.as_str(), "*");
    }

    // -----------------------------------------------------------------------
    // Display -> FromStr for every variant (exercises Display impl)
    // -----------------------------------------------------------------------

    #[test]
    fn display_fromstr_every_action() {
        for action in all_concrete_actions() {
            let display = action.to_string();
            let parsed: WamiAction = display.parse().unwrap();
            assert_eq!(parsed, action);
        }
        // Wildcards too
        let all_display = WamiAction::All.to_string();
        assert_eq!(all_display, "*");
        assert_eq!(all_display.parse::<WamiAction>().unwrap(), WamiAction::All);

        for prefix in WamiServicePrefix::all() {
            let svc = WamiAction::ServiceAll(*prefix);
            let display = svc.to_string();
            assert_eq!(display.parse::<WamiAction>().unwrap(), svc);
        }
    }

    // -----------------------------------------------------------------------
    // prefix() for EVERY variant
    // -----------------------------------------------------------------------

    #[test]
    fn prefix_every_concrete_action() {
        let expected: Vec<(WamiAction, WamiServicePrefix)> = vec![
            (WamiAction::PlatformAdmin, WamiServicePrefix::Platform),
            (
                WamiAction::PlatformViewSettings,
                WamiServicePrefix::Platform,
            ),
            (
                WamiAction::PlatformUpdateSettings,
                WamiServicePrefix::Platform,
            ),
            (
                WamiAction::PlatformViewAuditLog,
                WamiServicePrefix::Platform,
            ),
            (WamiAction::TenantCreate, WamiServicePrefix::Tenant),
            (WamiAction::TenantConfigure, WamiServicePrefix::Tenant),
            (WamiAction::TenantManageMembers, WamiServicePrefix::Tenant),
            (WamiAction::TenantSuspend, WamiServicePrefix::Tenant),
            (WamiAction::TenantResume, WamiServicePrefix::Tenant),
            (WamiAction::TenantList, WamiServicePrefix::Tenant),
            (WamiAction::TenantRead, WamiServicePrefix::Tenant),
            (WamiAction::TenantUpdate, WamiServicePrefix::Tenant),
            (WamiAction::TenantDelete, WamiServicePrefix::Tenant),
            (WamiAction::TenantCreateSubTenant, WamiServicePrefix::Tenant),
            (WamiAction::TenantManageUsers, WamiServicePrefix::Tenant),
            (WamiAction::TenantManageRoles, WamiServicePrefix::Tenant),
            (WamiAction::TenantManagePolicies, WamiServicePrefix::Tenant),
            (WamiAction::IamCreateUser, WamiServicePrefix::Iam),
            (WamiAction::IamDeleteUser, WamiServicePrefix::Iam),
            (WamiAction::IamReadUser, WamiServicePrefix::Iam),
            (WamiAction::IamUpdateUser, WamiServicePrefix::Iam),
            (WamiAction::IamListUsers, WamiServicePrefix::Iam),
            (WamiAction::IamCreateGroup, WamiServicePrefix::Iam),
            (WamiAction::IamDeleteGroup, WamiServicePrefix::Iam),
            (WamiAction::IamManageGroupMembers, WamiServicePrefix::Iam),
            (WamiAction::IamCreateRole, WamiServicePrefix::Iam),
            (WamiAction::IamDeleteRole, WamiServicePrefix::Iam),
            (WamiAction::IamReadRole, WamiServicePrefix::Iam),
            (WamiAction::IamAssumeRole, WamiServicePrefix::Iam),
            (WamiAction::IamCreatePolicy, WamiServicePrefix::Iam),
            (WamiAction::IamDeletePolicy, WamiServicePrefix::Iam),
            (WamiAction::IamReadPolicy, WamiServicePrefix::Iam),
            (WamiAction::IamAttachPolicy, WamiServicePrefix::Iam),
            (WamiAction::IamDetachPolicy, WamiServicePrefix::Iam),
            (WamiAction::IamSetBoundary, WamiServicePrefix::Iam),
            (WamiAction::IamManageCredentials, WamiServicePrefix::Iam),
            (WamiAction::DbQuery, WamiServicePrefix::Db),
            (WamiAction::DbWrite, WamiServicePrefix::Db),
            (WamiAction::DbDelete, WamiServicePrefix::Db),
            (WamiAction::DbCreate, WamiServicePrefix::Db),
            (WamiAction::DbDrop, WamiServicePrefix::Db),
            (WamiAction::DbList, WamiServicePrefix::Db),
            (WamiAction::DbConfigureAccess, WamiServicePrefix::Db),
            (WamiAction::DbImport, WamiServicePrefix::Db),
            (WamiAction::DbExport, WamiServicePrefix::Db),
            (WamiAction::ChatSend, WamiServicePrefix::Chat),
            (WamiAction::ChatReadHistory, WamiServicePrefix::Chat),
            (WamiAction::ChatDeleteConversation, WamiServicePrefix::Chat),
            (WamiAction::ChatStream, WamiServicePrefix::Chat),
            (WamiAction::PersonaCreate, WamiServicePrefix::Persona),
            (WamiAction::PersonaDelete, WamiServicePrefix::Persona),
            (WamiAction::PersonaRead, WamiServicePrefix::Persona),
            (WamiAction::PersonaUpdate, WamiServicePrefix::Persona),
            (WamiAction::PersonaList, WamiServicePrefix::Persona),
            (WamiAction::PersonaInvoke, WamiServicePrefix::Persona),
            (WamiAction::RoomCreate, WamiServicePrefix::Room),
            (WamiAction::RoomDelete, WamiServicePrefix::Room),
            (WamiAction::RoomJoin, WamiServicePrefix::Room),
            (WamiAction::RoomRead, WamiServicePrefix::Room),
            (WamiAction::RoomSend, WamiServicePrefix::Room),
            (WamiAction::RoomManage, WamiServicePrefix::Room),
            (
                WamiAction::InferenceListModels,
                WamiServicePrefix::Inference,
            ),
            (WamiAction::InferenceInvoke, WamiServicePrefix::Inference),
            (
                WamiAction::InferenceConfigureRouter,
                WamiServicePrefix::Inference,
            ),
            (WamiAction::InferenceViewUsage, WamiServicePrefix::Inference),
            (WamiAction::AnalyticsViewUsage, WamiServicePrefix::Analytics),
            (
                WamiAction::AnalyticsViewConversations,
                WamiServicePrefix::Analytics,
            ),
            (WamiAction::AnalyticsExport, WamiServicePrefix::Analytics),
            (
                WamiAction::AnalyticsViewActivity,
                WamiServicePrefix::Analytics,
            ),
            (
                WamiAction::IntegrationCreate,
                WamiServicePrefix::Integration,
            ),
            (
                WamiAction::IntegrationDelete,
                WamiServicePrefix::Integration,
            ),
            (
                WamiAction::IntegrationConfigure,
                WamiServicePrefix::Integration,
            ),
            (WamiAction::IntegrationList, WamiServicePrefix::Integration),
            (
                WamiAction::IntegrationReceive,
                WamiServicePrefix::Integration,
            ),
            (WamiAction::IntegrationSend, WamiServicePrefix::Integration),
            (WamiAction::CognitiveRead, WamiServicePrefix::Cognitive),
            (WamiAction::CognitiveWrite, WamiServicePrefix::Cognitive),
            (WamiAction::CognitiveReset, WamiServicePrefix::Cognitive),
            (WamiAction::GdprGrantConsent, WamiServicePrefix::Gdpr),
            (WamiAction::GdprRevokeConsent, WamiServicePrefix::Gdpr),
            (WamiAction::GdprExportData, WamiServicePrefix::Gdpr),
            (WamiAction::GdprEraseData, WamiServicePrefix::Gdpr),
            (WamiAction::GdprViewAudit, WamiServicePrefix::Gdpr),
        ];

        for (action, expected_prefix) in &expected {
            assert_eq!(
                action.prefix(),
                Some(*expected_prefix),
                "prefix() wrong for {:?}",
                action
            );
        }
    }

    #[test]
    fn prefix_wildcards() {
        assert_eq!(WamiAction::All.prefix(), None);
        for prefix in WamiServicePrefix::all() {
            assert_eq!(WamiAction::ServiceAll(*prefix).prefix(), Some(*prefix),);
        }
    }

    // -----------------------------------------------------------------------
    // as_str() spot-checks for every service group (exercises all match arms)
    // -----------------------------------------------------------------------

    #[test]
    fn as_str_platform() {
        assert_eq!(WamiAction::PlatformAdmin.as_str(), "platform:Admin");
        assert_eq!(
            WamiAction::PlatformViewSettings.as_str(),
            "platform:ViewSettings"
        );
        assert_eq!(
            WamiAction::PlatformUpdateSettings.as_str(),
            "platform:UpdateSettings"
        );
        assert_eq!(
            WamiAction::PlatformViewAuditLog.as_str(),
            "platform:ViewAuditLog"
        );
    }

    #[test]
    fn as_str_tenant_lifecycle() {
        assert_eq!(WamiAction::TenantCreate.as_str(), "tenant:Create");
        assert_eq!(WamiAction::TenantConfigure.as_str(), "tenant:Configure");
        assert_eq!(
            WamiAction::TenantManageMembers.as_str(),
            "tenant:ManageMembers"
        );
        assert_eq!(WamiAction::TenantSuspend.as_str(), "tenant:Suspend");
        assert_eq!(WamiAction::TenantResume.as_str(), "tenant:Resume");
        assert_eq!(WamiAction::TenantList.as_str(), "tenant:List");
    }

    #[test]
    fn as_str_tenant() {
        assert_eq!(WamiAction::TenantRead.as_str(), "tenant:Read");
        assert_eq!(WamiAction::TenantUpdate.as_str(), "tenant:Update");
        assert_eq!(WamiAction::TenantDelete.as_str(), "tenant:Delete");
        assert_eq!(
            WamiAction::TenantCreateSubTenant.as_str(),
            "tenant:CreateSubTenant"
        );
        assert_eq!(WamiAction::TenantManageUsers.as_str(), "tenant:ManageUsers");
        assert_eq!(WamiAction::TenantManageRoles.as_str(), "tenant:ManageRoles");
        assert_eq!(
            WamiAction::TenantManagePolicies.as_str(),
            "tenant:ManagePolicies"
        );
    }

    #[test]
    fn as_str_iam() {
        assert_eq!(WamiAction::IamCreateUser.as_str(), "iam:CreateUser");
        assert_eq!(WamiAction::IamDeleteUser.as_str(), "iam:DeleteUser");
        assert_eq!(WamiAction::IamReadUser.as_str(), "iam:ReadUser");
        assert_eq!(WamiAction::IamUpdateUser.as_str(), "iam:UpdateUser");
        assert_eq!(WamiAction::IamListUsers.as_str(), "iam:ListUsers");
        assert_eq!(WamiAction::IamCreateGroup.as_str(), "iam:CreateGroup");
        assert_eq!(WamiAction::IamDeleteGroup.as_str(), "iam:DeleteGroup");
        assert_eq!(
            WamiAction::IamManageGroupMembers.as_str(),
            "iam:ManageGroupMembers"
        );
        assert_eq!(WamiAction::IamCreateRole.as_str(), "iam:CreateRole");
        assert_eq!(WamiAction::IamDeleteRole.as_str(), "iam:DeleteRole");
        assert_eq!(WamiAction::IamReadRole.as_str(), "iam:ReadRole");
        assert_eq!(WamiAction::IamAssumeRole.as_str(), "iam:AssumeRole");
        assert_eq!(WamiAction::IamCreatePolicy.as_str(), "iam:CreatePolicy");
        assert_eq!(WamiAction::IamDeletePolicy.as_str(), "iam:DeletePolicy");
        assert_eq!(WamiAction::IamReadPolicy.as_str(), "iam:ReadPolicy");
        assert_eq!(WamiAction::IamAttachPolicy.as_str(), "iam:AttachPolicy");
        assert_eq!(WamiAction::IamDetachPolicy.as_str(), "iam:DetachPolicy");
        assert_eq!(WamiAction::IamSetBoundary.as_str(), "iam:SetBoundary");
        assert_eq!(
            WamiAction::IamManageCredentials.as_str(),
            "iam:ManageCredentials"
        );
    }

    #[test]
    fn as_str_db() {
        assert_eq!(WamiAction::DbQuery.as_str(), "db:Query");
        assert_eq!(WamiAction::DbWrite.as_str(), "db:Write");
        assert_eq!(WamiAction::DbDelete.as_str(), "db:Delete");
        assert_eq!(WamiAction::DbCreate.as_str(), "db:Create");
        assert_eq!(WamiAction::DbDrop.as_str(), "db:Drop");
        assert_eq!(WamiAction::DbList.as_str(), "db:List");
        assert_eq!(WamiAction::DbConfigureAccess.as_str(), "db:ConfigureAccess");
        assert_eq!(WamiAction::DbImport.as_str(), "db:Import");
        assert_eq!(WamiAction::DbExport.as_str(), "db:Export");
    }

    #[test]
    fn as_str_chat() {
        assert_eq!(WamiAction::ChatSend.as_str(), "chat:Send");
        assert_eq!(WamiAction::ChatReadHistory.as_str(), "chat:ReadHistory");
        assert_eq!(
            WamiAction::ChatDeleteConversation.as_str(),
            "chat:DeleteConversation"
        );
        assert_eq!(WamiAction::ChatStream.as_str(), "chat:Stream");
    }

    #[test]
    fn as_str_persona() {
        assert_eq!(WamiAction::PersonaCreate.as_str(), "persona:Create");
        assert_eq!(WamiAction::PersonaDelete.as_str(), "persona:Delete");
        assert_eq!(WamiAction::PersonaRead.as_str(), "persona:Read");
        assert_eq!(WamiAction::PersonaUpdate.as_str(), "persona:Update");
        assert_eq!(WamiAction::PersonaList.as_str(), "persona:List");
        assert_eq!(WamiAction::PersonaInvoke.as_str(), "persona:Invoke");
    }

    #[test]
    fn as_str_room() {
        assert_eq!(WamiAction::RoomCreate.as_str(), "room:Create");
        assert_eq!(WamiAction::RoomDelete.as_str(), "room:Delete");
        assert_eq!(WamiAction::RoomJoin.as_str(), "room:Join");
        assert_eq!(WamiAction::RoomRead.as_str(), "room:Read");
        assert_eq!(WamiAction::RoomSend.as_str(), "room:Send");
        assert_eq!(WamiAction::RoomManage.as_str(), "room:Manage");
    }

    #[test]
    fn as_str_inference() {
        assert_eq!(
            WamiAction::InferenceListModels.as_str(),
            "inference:ListModels"
        );
        assert_eq!(WamiAction::InferenceInvoke.as_str(), "inference:Invoke");
        assert_eq!(
            WamiAction::InferenceConfigureRouter.as_str(),
            "inference:ConfigureRouter"
        );
        assert_eq!(
            WamiAction::InferenceViewUsage.as_str(),
            "inference:ViewUsage"
        );
    }

    #[test]
    fn as_str_analytics() {
        assert_eq!(
            WamiAction::AnalyticsViewUsage.as_str(),
            "analytics:ViewUsage"
        );
        assert_eq!(
            WamiAction::AnalyticsViewConversations.as_str(),
            "analytics:ViewConversations"
        );
        assert_eq!(WamiAction::AnalyticsExport.as_str(), "analytics:Export");
        assert_eq!(
            WamiAction::AnalyticsViewActivity.as_str(),
            "analytics:ViewActivity"
        );
    }

    #[test]
    fn as_str_integration() {
        assert_eq!(WamiAction::IntegrationCreate.as_str(), "integration:Create");
        assert_eq!(WamiAction::IntegrationDelete.as_str(), "integration:Delete");
        assert_eq!(
            WamiAction::IntegrationConfigure.as_str(),
            "integration:Configure"
        );
        assert_eq!(WamiAction::IntegrationList.as_str(), "integration:List");
        assert_eq!(
            WamiAction::IntegrationReceive.as_str(),
            "integration:Receive"
        );
        assert_eq!(WamiAction::IntegrationSend.as_str(), "integration:Send");
    }

    #[test]
    fn as_str_cognitive() {
        assert_eq!(WamiAction::CognitiveRead.as_str(), "cognitive:Read");
        assert_eq!(WamiAction::CognitiveWrite.as_str(), "cognitive:Write");
        assert_eq!(WamiAction::CognitiveReset.as_str(), "cognitive:Reset");
    }

    #[test]
    fn as_str_gdpr() {
        assert_eq!(WamiAction::GdprGrantConsent.as_str(), "gdpr:GrantConsent");
        assert_eq!(WamiAction::GdprRevokeConsent.as_str(), "gdpr:RevokeConsent");
        assert_eq!(WamiAction::GdprExportData.as_str(), "gdpr:ExportData");
        assert_eq!(WamiAction::GdprEraseData.as_str(), "gdpr:EraseData");
        assert_eq!(WamiAction::GdprViewAudit.as_str(), "gdpr:ViewAudit");
    }

    // -----------------------------------------------------------------------
    // ServiceAll as_str for every prefix
    // -----------------------------------------------------------------------

    #[test]
    fn as_str_service_all_every_prefix() {
        assert_eq!(
            WamiAction::ServiceAll(WamiServicePrefix::Platform).as_str(),
            "platform:*"
        );
        assert_eq!(
            WamiAction::ServiceAll(WamiServicePrefix::Tenant).as_str(),
            "tenant:*"
        );
        assert_eq!(
            WamiAction::ServiceAll(WamiServicePrefix::Tenant).as_str(),
            "tenant:*"
        );
        assert_eq!(
            WamiAction::ServiceAll(WamiServicePrefix::Iam).as_str(),
            "iam:*"
        );
        assert_eq!(
            WamiAction::ServiceAll(WamiServicePrefix::Db).as_str(),
            "db:*"
        );
        assert_eq!(
            WamiAction::ServiceAll(WamiServicePrefix::Chat).as_str(),
            "chat:*"
        );
        assert_eq!(
            WamiAction::ServiceAll(WamiServicePrefix::Persona).as_str(),
            "persona:*"
        );
        assert_eq!(
            WamiAction::ServiceAll(WamiServicePrefix::Room).as_str(),
            "room:*"
        );
        assert_eq!(
            WamiAction::ServiceAll(WamiServicePrefix::Inference).as_str(),
            "inference:*"
        );
        assert_eq!(
            WamiAction::ServiceAll(WamiServicePrefix::Analytics).as_str(),
            "analytics:*"
        );
        assert_eq!(
            WamiAction::ServiceAll(WamiServicePrefix::Integration).as_str(),
            "integration:*"
        );
        assert_eq!(
            WamiAction::ServiceAll(WamiServicePrefix::Cognitive).as_str(),
            "cognitive:*"
        );
        assert_eq!(
            WamiAction::ServiceAll(WamiServicePrefix::Gdpr).as_str(),
            "gdpr:*"
        );
    }

    // -----------------------------------------------------------------------
    // Wildcard matching — exhaustive cross-service checks
    // -----------------------------------------------------------------------

    #[test]
    fn matches_all_matches_everything() {
        let all = WamiAction::All;
        for action in all_concrete_actions() {
            assert!(all.matches(&action), "All should match {:?}", action);
        }
        // Also matches wildcards themselves
        for prefix in WamiServicePrefix::all() {
            assert!(all.matches(&WamiAction::ServiceAll(*prefix)));
        }
        assert!(all.matches(&WamiAction::All));
    }

    #[test]
    fn service_all_matches_only_own_prefix() {
        // For every prefix, ServiceAll should match all actions in that prefix
        // and NOT match actions in other prefixes
        let actions = all_concrete_actions();
        for prefix in WamiServicePrefix::all() {
            let svc_all = WamiAction::ServiceAll(*prefix);
            for action in &actions {
                if action.prefix() == Some(*prefix) {
                    assert!(
                        svc_all.matches(action),
                        "{:?} should match {:?}",
                        svc_all,
                        action
                    );
                } else {
                    assert!(
                        !svc_all.matches(action),
                        "{:?} should NOT match {:?}",
                        svc_all,
                        action
                    );
                }
            }
        }
    }

    #[test]
    fn exact_match_only_matches_self() {
        let actions = all_concrete_actions();
        for a in &actions {
            assert!(a.matches(a), "{:?} should match itself", a);
            for b in &actions {
                if a != b {
                    assert!(!a.matches(b), "{:?} should not match {:?}", a, b);
                }
            }
        }
    }

    #[test]
    fn concrete_does_not_match_service_all() {
        // A concrete action should not match a ServiceAll pattern
        let iam_create = WamiAction::IamCreateUser;
        let iam_all = WamiAction::ServiceAll(WamiServicePrefix::Iam);
        assert!(!iam_create.matches(&iam_all));
    }

    // -----------------------------------------------------------------------
    // matches_str — backward compat string matching
    // -----------------------------------------------------------------------

    #[test]
    fn matches_str_star_matches_everything() {
        for action in all_concrete_actions() {
            assert!(WamiAction::matches_str("*", action.as_str()));
        }
    }

    #[test]
    fn matches_str_service_wildcard_every_prefix() {
        let prefixes_and_actions: Vec<(&str, &str, &str)> = vec![
            ("platform:*", "platform:Admin", "tenant:Create"),
            ("platform:*", "platform:Admin", "tenant:Read"),
            ("tenant:*", "tenant:Read", "iam:CreateUser"),
            ("iam:*", "iam:CreateUser", "db:Query"),
            ("db:*", "db:Query", "chat:Send"),
            ("chat:*", "chat:Send", "persona:Create"),
            ("persona:*", "persona:Create", "room:Create"),
            ("room:*", "room:Create", "inference:Invoke"),
            ("inference:*", "inference:Invoke", "analytics:Export"),
            ("analytics:*", "analytics:Export", "integration:Create"),
            ("integration:*", "integration:Create", "cognitive:Read"),
            ("cognitive:*", "cognitive:Read", "gdpr:GrantConsent"),
            ("gdpr:*", "gdpr:GrantConsent", "platform:Admin"),
        ];
        for (pattern, should_match, should_not_match) in prefixes_and_actions {
            assert!(
                WamiAction::matches_str(pattern, should_match),
                "{} should match {}",
                pattern,
                should_match
            );
            assert!(
                !WamiAction::matches_str(pattern, should_not_match),
                "{} should NOT match {}",
                pattern,
                should_not_match
            );
        }
    }

    #[test]
    fn matches_str_exact() {
        assert!(WamiAction::matches_str("iam:CreateUser", "iam:CreateUser"));
        assert!(!WamiAction::matches_str("iam:CreateUser", "iam:DeleteUser"));
    }

    #[test]
    fn matches_str_no_colon_in_requested() {
        // If the requested string has no colon, prefix wildcard should not match
        assert!(!WamiAction::matches_str("iam:*", "noColonHere"));
    }

    #[test]
    fn matches_str_non_matching_patterns() {
        assert!(!WamiAction::matches_str("db:Query", "db:Write"));
        assert!(!WamiAction::matches_str("iam:*", "db:Query"));
        assert!(!WamiAction::matches_str("platform:Admin", "*"));
    }

    // -----------------------------------------------------------------------
    // Edge cases — parse errors
    // -----------------------------------------------------------------------

    #[test]
    fn from_str_empty_string() {
        let err = WamiAction::from_str("").unwrap_err();
        assert!(matches!(err, ActionParseError::InvalidFormat(_)));
    }

    #[test]
    fn from_str_no_colon() {
        let err = WamiAction::from_str("noColon").unwrap_err();
        assert!(matches!(err, ActionParseError::InvalidFormat(_)));
    }

    #[test]
    fn from_str_unknown_prefix() {
        let err = WamiAction::from_str("fake:*").unwrap_err();
        assert!(matches!(err, ActionParseError::UnknownPrefix(_)));
    }

    #[test]
    fn from_str_unknown_operation() {
        let err = WamiAction::from_str("iam:FakeOp").unwrap_err();
        assert!(matches!(err, ActionParseError::Unknown(_)));
    }

    #[test]
    fn from_str_case_sensitive() {
        // Should be case-sensitive: "IAM:CreateUser" is not valid
        assert!(WamiAction::from_str("IAM:CreateUser").is_err());
        assert!(WamiAction::from_str("iam:createuser").is_err());
        assert!(WamiAction::from_str("Iam:CreateUser").is_err());
        assert!(WamiAction::from_str("iam:createUser").is_err());
    }

    #[test]
    fn from_str_valid_prefix_wrong_operation() {
        assert!(WamiAction::from_str("db:NotAnAction").is_err());
        assert!(WamiAction::from_str("chat:NotAnAction").is_err());
        assert!(WamiAction::from_str("room:NotAnAction").is_err());
    }

    // -----------------------------------------------------------------------
    // WamiServicePrefix tests
    // -----------------------------------------------------------------------

    #[test]
    fn service_prefix_as_str_all() {
        assert_eq!(WamiServicePrefix::Platform.as_str(), "platform");
        assert_eq!(WamiServicePrefix::Tenant.as_str(), "tenant");
        assert_eq!(WamiServicePrefix::Iam.as_str(), "iam");
        assert_eq!(WamiServicePrefix::Db.as_str(), "db");
        assert_eq!(WamiServicePrefix::Chat.as_str(), "chat");
        assert_eq!(WamiServicePrefix::Persona.as_str(), "persona");
        assert_eq!(WamiServicePrefix::Room.as_str(), "room");
        assert_eq!(WamiServicePrefix::Inference.as_str(), "inference");
        assert_eq!(WamiServicePrefix::Analytics.as_str(), "analytics");
        assert_eq!(WamiServicePrefix::Integration.as_str(), "integration");
        assert_eq!(WamiServicePrefix::Cognitive.as_str(), "cognitive");
        assert_eq!(WamiServicePrefix::Gdpr.as_str(), "gdpr");
    }

    #[test]
    fn service_prefix_from_str_all() {
        for prefix in WamiServicePrefix::all() {
            let s = prefix.as_str();
            let parsed = WamiServicePrefix::from_str(s).unwrap();
            assert_eq!(parsed, *prefix);
        }
    }

    #[test]
    fn service_prefix_from_str_error() {
        let err = WamiServicePrefix::from_str("nonexistent").unwrap_err();
        assert!(matches!(err, ActionParseError::UnknownPrefix(_)));
    }

    #[test]
    fn service_prefix_display() {
        for prefix in WamiServicePrefix::all() {
            assert_eq!(prefix.to_string(), prefix.as_str());
        }
    }

    #[test]
    fn service_prefix_all_returns_all_12() {
        assert_eq!(WamiServicePrefix::all().len(), 12);
    }

    // -----------------------------------------------------------------------
    // Serde — additional edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn serde_roundtrip_every_action() {
        for action in all_concrete_actions() {
            let json = serde_json::to_string(&action).unwrap();
            let parsed: WamiAction = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, action);
        }
    }

    #[test]
    fn serde_roundtrip_every_service_wildcard() {
        for prefix in WamiServicePrefix::all() {
            let action = WamiAction::ServiceAll(*prefix);
            let json = serde_json::to_string(&action).unwrap();
            let parsed: WamiAction = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, action);
        }
    }

    #[test]
    fn serde_deserialize_invalid() {
        let result: Result<WamiAction, _> = serde_json::from_str(r#""not:valid:action""#);
        assert!(result.is_err());

        let result: Result<WamiAction, _> = serde_json::from_str(r#""garbage""#);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // ActionParseError Display
    // -----------------------------------------------------------------------

    #[test]
    fn action_parse_error_display() {
        let e1 = ActionParseError::Unknown("foo:bar".into());
        assert!(e1.to_string().contains("foo:bar"));

        let e2 = ActionParseError::UnknownPrefix("xyz".into());
        assert!(e2.to_string().contains("xyz"));

        let e3 = ActionParseError::InvalidFormat("nocolon".into());
        assert!(e3.to_string().contains("nocolon"));
    }

    // -----------------------------------------------------------------------
    // ActionRegistry — additional coverage
    // -----------------------------------------------------------------------

    #[test]
    fn registry_list_by_every_prefix() {
        let expected_counts: Vec<(WamiServicePrefix, usize)> = vec![
            (WamiServicePrefix::Platform, 4),
            // Douze : les sept d origine, plus les cinq qui vivaient sous
            // `space` et ne s en distinguaient pas.
            (WamiServicePrefix::Tenant, 13),
            (WamiServicePrefix::Iam, 19),
            (WamiServicePrefix::Db, 9),
            (WamiServicePrefix::Chat, 4),
            (WamiServicePrefix::Persona, 6),
            (WamiServicePrefix::Room, 6),
            (WamiServicePrefix::Inference, 4),
            (WamiServicePrefix::Analytics, 4),
            (WamiServicePrefix::Integration, 6),
            (WamiServicePrefix::Cognitive, 3),
            (WamiServicePrefix::Gdpr, 5),
        ];
        for (prefix, expected) in expected_counts {
            let actions = ActionRegistry::list_by_prefix(prefix);
            assert_eq!(
                actions.len(),
                expected,
                "Wrong count for {:?}: got {}, expected {}",
                prefix,
                actions.len(),
                expected
            );
            for a in &actions {
                assert_eq!(a.category, prefix.as_str());
            }
        }
    }

    #[test]
    fn registry_list_prefixes() {
        let prefixes = ActionRegistry::list_prefixes();
        assert_eq!(prefixes.len(), 12);
    }

    #[test]
    fn registry_total_action_count() {
        let all = ActionRegistry::list_actions();
        // 4+8+7+19+9+4+6+6+4+4+6+3+5 = 85
        assert_eq!(all.len(), 83);
    }
}
