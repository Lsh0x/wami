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
    ///
    /// When several documents cannot be read, one error names them all, in
    /// the authorizer's canonical order: each field lists the documents'
    /// values joined by `"; "`. The message names the statement (`Sid`, else
    /// `#` and its index) and what the policy's author wrote — never a value.
    #[error("policy cannot be read ({policy}): {message}")]
    UnreadablePolicy {
        /// Which policy failed to parse, so an operator knows what to fix.
        policy: String,
        /// What the parser objected to.
        message: String,
    },

    /// A statement's condition could not be evaluated, so no decision can be
    /// made from the policy that carries it.
    ///
    /// Deliberately an error and not a `false`. A false condition means "the
    /// statement does not apply here"; an unreadable one means "whether it
    /// applies cannot be known" — and answering that as `false` made the
    /// statement vanish, so a `Deny` carrying it stopped denying. As with
    /// [`AmiError::UnreadablePolicy`], it is not folded into `AccessDenied`
    /// either: the policy is broken, and the operator must be told which one.
    ///
    /// What still reaches evaluation after the parse check is the request
    /// side — a value the operator cannot compare, such as an `aws:SourceIp`
    /// that is no address, or a custom key holding a number under
    /// `StringEquals` — or a document that did not go through
    /// `parse_policy_doc`. Every statement whose action and resource match is
    /// read before any verdict, so a `Deny` that holds does not hide one.
    ///
    /// Several such statements are named in one error, in order, each field
    /// listing the values joined by `"; "` (`policy` and `statement` pair up
    /// by position). The message names kinds and positions, never the
    /// request's values.
    #[error("condition cannot be read ({policy}, statement {statement}): {message}")]
    UnreadableCondition {
        /// Which policy holds the statement.
        policy: String,
        /// The statement: its `Sid`, else `#` and its index in the document.
        statement: String,
        /// What the evaluation objected to.
        message: String,
    },
}

pub type Result<T> = std::result::Result<T, AmiError>;

// Re-export helper functions and traits
pub mod helpers;
pub use helpers::OptionExt;

// Re-export AmiError helper methods through the enum itself
// The helper methods are implemented as extension methods on AmiError
