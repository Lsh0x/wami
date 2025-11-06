//! Error Helper Functions
//!
//! Provides convenient helper functions for creating common error types.

use crate::error::{AmiError, Result};

/// Helper functions for creating common AmiError variants
impl AmiError {
    /// Create a "Resource not found" error with a formatted message
    ///
    /// # Example
    ///
    /// ```rust
    /// use wami_core::error::AmiError;
    ///
    /// let error = AmiError::resource_not_found("User", "alice");
    /// assert!(error.to_string().contains("User: alice"));
    /// ```
    pub fn resource_not_found(resource_type: &str, resource_id: &str) -> Self {
        AmiError::ResourceNotFound {
            resource: format!("{}: {}", resource_type, resource_id),
        }
    }

    /// Create a "Permission denied" error with action and resource context
    ///
    /// # Example
    ///
    /// ```rust
    /// use wami_core::error::AmiError;
    ///
    /// let error = AmiError::permission_denied("delete", "User: alice");
    /// assert!(error.to_string().contains("Cannot delete"));
    /// ```
    pub fn permission_denied(action: &str, resource: &str) -> Self {
        AmiError::PermissionDenied {
            reason: format!("Cannot {} on {}", action, resource),
        }
    }

    /// Create an "Access denied" error with a detailed message
    ///
    /// # Example
    ///
    /// ```rust
    /// use wami_core::error::AmiError;
    ///
    /// let error = AmiError::access_denied("User alice does not have permission to delete users");
    /// ```
    pub fn access_denied(message: impl Into<String>) -> Self {
        AmiError::AccessDenied {
            message: message.into(),
        }
    }

    /// Create an "Invalid parameter" error
    ///
    /// # Example
    ///
    /// ```rust
    /// use wami_core::error::AmiError;
    ///
    /// let error = AmiError::invalid_parameter("User name cannot be empty");
    /// ```
    pub fn invalid_parameter(message: impl Into<String>) -> Self {
        AmiError::InvalidParameter {
            message: message.into(),
        }
    }

    /// Create a "Resource already exists" error
    ///
    /// # Example
    ///
    /// ```rust
    /// use wami_core::error::AmiError;
    ///
    /// let error = AmiError::resource_exists("User: alice");
    /// ```
    pub fn resource_exists(resource: impl Into<String>) -> Self {
        AmiError::ResourceExists {
            resource: resource.into(),
        }
    }

    /// Create a "Resource limit exceeded" error
    ///
    /// # Example
    ///
    /// ```rust
    /// use wami_core::error::AmiError;
    ///
    /// let error = AmiError::resource_limit_exceeded("AccessKey", 2);
    /// ```
    pub fn resource_limit_exceeded(resource_type: &str, limit: usize) -> Self {
        AmiError::ResourceLimitExceeded {
            resource_type: resource_type.to_string(),
            limit,
        }
    }

    /// Create an "Operation not supported" error
    ///
    /// # Example
    ///
    /// ```rust
    /// use wami_core::error::AmiError;
    ///
    /// let error = AmiError::operation_not_supported("batch_delete");
    /// ```
    pub fn operation_not_supported(operation: impl Into<String>) -> Self {
        AmiError::OperationNotSupported {
            operation: operation.into(),
        }
    }
}

/// Extension trait for Option to provide convenient error handling
///
/// # Example
///
/// ```rust
/// use wami_core::error::{Result, OptionExt};
///
/// fn example() -> Result<String> {
///     let user: Option<String> = Some("alice".to_string());
///     let result = user.or_not_found("User", "alice")?;
///     Ok(result)
/// }
/// ```
#[allow(clippy::result_large_err)]
pub trait OptionExt<T> {
    /// Convert None to a ResourceNotFound error
    fn or_not_found(self, resource_type: &str, resource_id: &str) -> Result<T>;
}

impl<T> OptionExt<T> for Option<T> {
    fn or_not_found(self, resource_type: &str, resource_id: &str) -> Result<T> {
        self.ok_or_else(|| AmiError::resource_not_found(resource_type, resource_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_not_found() {
        let error = AmiError::resource_not_found("User", "alice");
        assert!(matches!(error, AmiError::ResourceNotFound { .. }));
        assert!(error.to_string().contains("User: alice"));
    }

    #[test]
    fn test_permission_denied() {
        let error = AmiError::permission_denied("delete", "User: alice");
        assert!(matches!(error, AmiError::PermissionDenied { .. }));
        assert!(error.to_string().contains("Cannot delete"));
    }

    #[test]
    fn test_or_not_found_some() {
        let option: Option<String> = Some("value".to_string());
        let result = option.or_not_found("Resource", "id");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "value");
    }

    #[test]
    fn test_or_not_found_none() {
        let option: Option<String> = None;
        let result = option.or_not_found("User", "alice");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AmiError::ResourceNotFound { .. }
        ));
    }
}
