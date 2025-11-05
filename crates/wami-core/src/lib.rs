//! Core primitives shared across the WAMI workspace.

pub mod arn;
pub mod context;
pub mod error;
pub mod types;

pub use context::{SessionInfo, WamiContext, WamiContextBuilder};
pub use error::{AmiError, OptionExt, Result};
pub use types::*;
