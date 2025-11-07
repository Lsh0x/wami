//! IAM Policy management

pub mod attachment;
pub mod evaluation;
pub mod inline;
pub mod policy;

// Re-export condition types for convenience
pub use wami_condition::{
    ConditionBlock, ConditionContext, ConditionError, ConditionOperator, ConditionValue,
    evaluate_condition_block, get_context_value, parse_condition_block,
};

// Re-export types for convenience
pub use attachment::*;
pub use inline::*;
pub use policy::{Policy, PolicyBuilder};

