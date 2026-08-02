use thiserror::Error;

#[derive(Error, Debug)]
pub enum AmiError {
    /// A provider rejected an operation.
    ///
    /// Replaces the AwsSdk, StsSdk and SsoAdminSdk variants removed in 0.14.
    /// Those named SDK error types in their signature, so every consumer
    /// compiled three AWS SDKs to hold three variants this workspace never
    /// constructed once. Carrying the provider name and its message keeps the
    /// information without keeping the dependency:
    ///
    /// ```ignore
    /// client.get_user().send().await.map_err(|e| AmiError::Provider {
    ///     provider: "aws".to_string(),
    ///     message: e.to_string(),
    /// })?
    /// ```
    #[error("{provider} error: {message}")]
    Provider {
        /// Which provider refused.
        provider: String,
        /// What it said.
        message: String,
    },

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Invalid parameter: {message}")]
    InvalidParameter { message: String },

    #[error("Operation not supported: {operation}")]
    OperationNotSupported { operation: String },

    #[error("Resource not found: {resource}")]
    ResourceNotFound { resource: String },

    #[error("Permission denied: {reason}")]
    PermissionDenied { reason: String },

    #[error("Access denied: {message}")]
    AccessDenied { message: String },

    #[error("Resource limit exceeded: {resource_type} limit is {limit}")]
    ResourceLimitExceeded { resource_type: String, limit: usize },

    #[error("Resource already exists: {resource}")]
    ResourceExists { resource: String },

    #[error("Store error: {0}")]
    StoreError(String),

    /// A policy document could not be parsed, so no decision can be made from it.
    ///
    /// Deliberately an error and not a denial. A denial means "the rules
    /// forbid this"; an unreadable policy means "the rules cannot be read" —
    /// and the caller must be able to tell those apart, because the first is a
    /// 403 the user can act on and the second is a corrupt store that should
    /// page someone. Folding it into `AccessDenied` would hide a broken policy
    /// store behind what looks like an ordinary permission failure.
    #[error("policy cannot be read ({policy}): {message}")]
    UnreadablePolicy {
        /// Which policy failed to parse, so an operator knows what to fix.
        policy: String,
        /// What the parser objected to.
        message: String,
    },
}

pub type Result<T> = std::result::Result<T, AmiError>;

// Re-export helper functions and traits
pub mod helpers;
pub use helpers::OptionExt;

// Re-export AmiError helper methods through the enum itself
// The helper methods are implemented as extension methods on AmiError
