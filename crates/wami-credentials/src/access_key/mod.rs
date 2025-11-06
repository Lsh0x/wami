//! AccessKey Resource Module
//!
//! This module provides self-contained handling of IAM access key resources.

pub mod builder;
pub mod model;
// pub mod operations; // TODO: Fix field mismatches in tests
pub mod requests;

pub use builder::{add_provider_to_access_key, build_access_key, update_access_key_status};
pub use model::{AccessKey, AccessKeyLastUsed};
pub use requests::{
    CreateAccessKeyRequest, ListAccessKeysRequest, ListAccessKeysResponse, UpdateAccessKeyRequest,
};
