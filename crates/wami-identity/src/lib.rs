//! Identity domain models, builders, and operations.

pub mod identity;

pub use identity::{
    group::{self, Group, GroupBuilder},
    identity_provider::{self, IdentityProvider, IdentityProviderBuilder},
    role::{self, Role, RoleBuilder},
    root_user::RootUser,
    service_linked_role::{
        self, DeletionTaskFailureReason, DeletionTaskInfo, DeletionTaskStatus, ServiceLinkedRole,
    },
    user::{self, User, UserBuilder},
};
