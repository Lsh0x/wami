//! LoginProfile Resource Module
//!
//! This module provides self-contained handling of IAM login profile resources.

pub mod builder;
pub mod model;
// pub mod operations; // TODO: Fix field mismatches in tests
pub mod requests;

pub use builder::{add_provider_to_login_profile, build_login_profile, update_login_profile};
pub use model::LoginProfile;
// Operations moved to service layer
// pub use operations::LoginProfileOperations;
pub use requests::{CreateLoginProfileRequest, GetLoginProfileRequest, UpdateLoginProfileRequest};
