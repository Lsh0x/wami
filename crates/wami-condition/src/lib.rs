//! wami-condition crate
//!
//! This crate provides policy condition key evaluation used by WAMI.

// Re-export core error module so paths like `crate::error::AmiError` resolve
pub use wami_core::error;

// Public modules
pub mod context;
pub mod evaluator;
pub mod keys;
pub mod operators;

#[cfg(test)]
mod tests;

pub use context::ConditionContext;
pub use evaluator::{evaluate_condition_block, ConditionError};
pub use keys::get_context_value;
pub use operators::ConditionOperator;

use serde_json::Value;
use std::collections::HashMap;

/// A condition block is a map of operator names to key-value pairs
pub type ConditionBlock = HashMap<String, HashMap<String, ConditionValue>>;

/// A condition value can be a string, number, boolean, or array of strings
#[derive(Debug, Clone, PartialEq)]
pub enum ConditionValue {
    String(String),
    Number(f64),
    Boolean(bool),
    Array(Vec<String>),
}

impl ConditionValue {
    pub fn as_string(&self) -> Result<String, ConditionError> {
        match self {
            ConditionValue::String(s) => Ok(s.clone()),
            ConditionValue::Number(n) => Ok(n.to_string()),
            ConditionValue::Boolean(b) => Ok(b.to_string()),
            ConditionValue::Array(_) => Err(ConditionError::TypeMismatch {
                expected: "String".to_string(),
                actual: "Array".to_string(),
            }),
        }
    }

    pub fn as_number(&self) -> Result<f64, ConditionError> {
        match self {
            ConditionValue::Number(n) => Ok(*n),
            ConditionValue::String(s) => s.parse().map_err(|_| ConditionError::TypeMismatch {
                expected: "Number".to_string(),
                actual: "String".to_string(),
            }),
            _ => Err(ConditionError::TypeMismatch {
                expected: "Number".to_string(),
                actual: format!("{:?}", self),
            }),
        }
    }

    pub fn as_boolean(&self) -> Result<bool, ConditionError> {
        match self {
            ConditionValue::Boolean(b) => Ok(*b),
            ConditionValue::String(s) => match s.as_str() {
                "true" => Ok(true),
                "false" => Ok(false),
                _ => Err(ConditionError::InvalidBooleanValue(s.clone())),
            },
            _ => Err(ConditionError::TypeMismatch {
                expected: "Boolean".to_string(),
                actual: format!("{:?}", self),
            }),
        }
    }

    pub fn as_array(&self) -> Result<&Vec<String>, ConditionError> {
        match self {
            ConditionValue::Array(arr) => Ok(arr),
            _ => Err(ConditionError::TypeMismatch {
                expected: "Array".to_string(),
                actual: format!("{:?}", self),
            }),
        }
    }
}

impl From<Value> for ConditionValue {
    fn from(value: Value) -> Self {
        match value {
            Value::String(s) => ConditionValue::String(s),
            Value::Number(n) => ConditionValue::Number(n.as_f64().unwrap_or(0.0)),
            Value::Bool(b) => ConditionValue::Boolean(b),
            Value::Array(arr) => {
                let strings: Vec<String> = arr
                    .into_iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
                ConditionValue::Array(strings)
            }
            Value::Null => ConditionValue::String("".to_string()),
            Value::Object(_) => ConditionValue::String("".to_string()), // Invalid, but handle gracefully
        }
    }
}

// Provide the expected namespace used by tests and downstream code:
// `crate::wami::policies::condition::...`
pub mod wami {
    pub mod policies {
        pub mod condition {
            // Re-export modules and symbols so callers can use
            // `crate::wami::policies::condition::{evaluator::..., ConditionContext, ...}`
            pub use crate::{
                context, evaluate_condition_block, evaluator, get_context_value, keys, operators,
                ConditionBlock, ConditionContext, ConditionOperator, ConditionValue,
            };
        }
    }
}
