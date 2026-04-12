//! WAMI Action vocabulary — the complete set of permissions for the obrain ecosystem.
//!
//! Each action follows the `service:Operation` convention (e.g. `"db:Query"`, `"space:Create"`).
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
/// - `space:*` — Space lifecycle and configuration
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

    // -- space --------------------------------------------------------------
    /// Create a new Space
    SpaceCreate,
    /// Delete a Space
    SpaceDelete,
    /// Read Space metadata
    SpaceRead,
    /// Update Space settings (branding, visibility, quotas)
    SpaceUpdate,
    /// Configure Space domain and port
    SpaceConfigure,
    /// Manage Space members (add, remove, ban)
    SpaceManageMembers,
    /// Suspend / reactivate a Space
    SpaceSuspend,
    /// List all Spaces (platform-level)
    SpaceList,

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
    /// Create / attach IAM policy
    IamCreatePolicy,
    /// Delete / detach IAM policy
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
    Space,
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
            Self::Space => "space",
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
            Self::Space,
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
            "space" => Ok(Self::Space),
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
                WamiServicePrefix::Space => "space:*",
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
            // Space
            Self::SpaceCreate => "space:Create",
            Self::SpaceDelete => "space:Delete",
            Self::SpaceRead => "space:Read",
            Self::SpaceUpdate => "space:Update",
            Self::SpaceConfigure => "space:Configure",
            Self::SpaceManageMembers => "space:ManageMembers",
            Self::SpaceSuspend => "space:Suspend",
            Self::SpaceList => "space:List",
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
            Self::SpaceCreate
            | Self::SpaceDelete
            | Self::SpaceRead
            | Self::SpaceUpdate
            | Self::SpaceConfigure
            | Self::SpaceManageMembers
            | Self::SpaceSuspend
            | Self::SpaceList => Some(WamiServicePrefix::Space),
            Self::TenantRead
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
            // Space
            ("space", "Create") => Ok(Self::SpaceCreate),
            ("space", "Delete") => Ok(Self::SpaceDelete),
            ("space", "Read") => Ok(Self::SpaceRead),
            ("space", "Update") => Ok(Self::SpaceUpdate),
            ("space", "Configure") => Ok(Self::SpaceConfigure),
            ("space", "ManageMembers") => Ok(Self::SpaceManageMembers),
            ("space", "Suspend") => Ok(Self::SpaceSuspend),
            ("space", "List") => Ok(Self::SpaceList),
            // Tenant
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
            Self::ServiceAll(prefix) => {
                requested.prefix().map_or(false, |rp| rp == *prefix)
            }
            // Exact match
            other => other == requested,
        }
    }

    /// Check whether a policy action **string** matches a requested action string.
    ///
    /// This provides backward compatibility with the existing `Vec<String>` in
    /// [`PolicyStatement`] without requiring a full migration to the enum.
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
        ai("platform:ViewSettings", "View platform settings and stats", "platform"),
        ai("platform:UpdateSettings", "Update platform configuration", "platform"),
        ai("platform:ViewAuditLog", "View platform audit logs", "platform"),
        // Space
        ai("space:Create", "Create a new Space", "space"),
        ai("space:Delete", "Delete a Space", "space"),
        ai("space:Read", "Read Space metadata", "space"),
        ai("space:Update", "Update Space settings", "space"),
        ai("space:Configure", "Configure Space domain and port", "space"),
        ai("space:ManageMembers", "Manage Space members", "space"),
        ai("space:Suspend", "Suspend / reactivate a Space", "space"),
        ai("space:List", "List all Spaces", "space"),
        // Tenant
        ai("tenant:Read", "Read tenant info", "tenant"),
        ai("tenant:Update", "Update tenant", "tenant"),
        ai("tenant:Delete", "Delete tenant", "tenant"),
        ai("tenant:CreateSubTenant", "Create sub-tenant", "tenant"),
        ai("tenant:ManageUsers", "Manage users within tenant", "tenant"),
        ai("tenant:ManageRoles", "Manage roles within tenant", "tenant"),
        ai("tenant:ManagePolicies", "Manage policies within tenant", "tenant"),
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
        ai("inference:ConfigureRouter", "Configure model routing", "inference"),
        ai("inference:ViewUsage", "View model usage", "inference"),
        // Analytics
        ai("analytics:ViewUsage", "View usage analytics", "analytics"),
        ai("analytics:ViewConversations", "View conversation analytics", "analytics"),
        ai("analytics:Export", "Export analytics reports", "analytics"),
        ai("analytics:ViewActivity", "View user activity", "analytics"),
        // Integration
        ai("integration:Create", "Create integration bridge", "integration"),
        ai("integration:Delete", "Delete integration bridge", "integration"),
        ai("integration:Configure", "Configure integration", "integration"),
        ai("integration:List", "List integrations", "integration"),
        ai("integration:Receive", "Receive inbound messages", "integration"),
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
            WamiAction::SpaceCreate,
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
        assert!(all.len() >= 70, "Expected at least 70 actions, got {}", all.len());

        let db_actions = ActionRegistry::list_by_prefix(WamiServicePrefix::Db);
        assert_eq!(db_actions.len(), 9);
        assert!(db_actions.iter().all(|a| a.category == "db"));

        let iam_actions = ActionRegistry::list_by_prefix(WamiServicePrefix::Iam);
        assert_eq!(iam_actions.len(), 19);
    }
}
