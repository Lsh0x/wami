//! Core primitives shared across the WAMI workspace.

pub mod actions;
pub mod arn;
pub mod context;
pub mod error;
pub mod traits;
pub mod types;

pub use actions::{ActionInfo, ActionParseError, ActionRegistry, WamiAction, WamiServicePrefix};
pub use context::{
    SessionInfo, Step, Transition, WamiContext, WamiContextBuilder, MAX_PROVENANCE_DEPTH,
};
pub use error::{AmiError, OptionExt, Result};
pub use types::*;
