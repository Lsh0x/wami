//! Permissions Boundary Request and Response Types

use crate::arn::ScopedName;
use serde::{Deserialize, Serialize};

/// Type of principal for permissions boundary operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrincipalType {
    /// IAM User
    User,
    /// IAM Role
    Role,
}

/// Request to attach a permissions boundary to a user or role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PutPermissionsBoundaryRequest {
    /// Type of principal (User or Role)
    pub principal_type: PrincipalType,
    /// The user or role — its tenant and its name (wami 005)
    pub principal: ScopedName,
    /// ARN of the policy to use as the permissions boundary
    pub permissions_boundary: String,
}

/// Request to remove a permissions boundary from a user or role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletePermissionsBoundaryRequest {
    /// Type of principal (User or Role)
    pub principal_type: PrincipalType,
    /// The user or role — its tenant and its name (wami 005)
    pub principal: ScopedName,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tenant every test of this module works in.
    fn tenant() -> wami_core::arn::TenantPath {
        wami_core::arn::TenantPath::single(12345678)
    }

    /// `name`'s key in that tenant.
    fn key(name: impl AsRef<str>) -> wami_core::arn::ScopedName {
        wami_core::arn::ScopedName::new(tenant(), name.as_ref())
    }

    #[test]
    fn test_put_request_creation() {
        let request = PutPermissionsBoundaryRequest {
            principal_type: PrincipalType::User,
            principal: key("alice"),
            permissions_boundary: "arn:aws:iam::123456789012:policy/boundary".to_string(),
        };

        assert_eq!(request.principal_type, PrincipalType::User);
        assert_eq!(request.principal.name(), "alice");
    }

    #[test]
    fn test_delete_request_creation() {
        let request = DeletePermissionsBoundaryRequest {
            principal_type: PrincipalType::Role,
            principal: key("admin-role"),
        };

        assert_eq!(request.principal_type, PrincipalType::Role);
        assert_eq!(request.principal.name(), "admin-role");
    }

    #[test]
    fn test_principal_type_equality() {
        assert_eq!(PrincipalType::User, PrincipalType::User);
        assert_eq!(PrincipalType::Role, PrincipalType::Role);
        assert_ne!(PrincipalType::User, PrincipalType::Role);
    }
}
