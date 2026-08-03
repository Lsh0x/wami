//! Signing Certificate Resource Module
//!
//! This module provides self-contained handling of IAM signing certificate resources.

pub mod builder;
pub mod model;
// pub mod operations; // TODO: Fix model ref
pub mod requests;

pub use builder::build_signing_certificate;
pub use model::*;
pub use requests::*;
