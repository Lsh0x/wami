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
mod validate;

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
    /// The variant's name — what an error says in place of the value, so a
    /// request value or a policy value never reaches a log (wami 001).
    pub fn kind(&self) -> &'static str {
        match self {
            ConditionValue::String(_) => "String",
            ConditionValue::Number(_) => "Number",
            ConditionValue::Boolean(_) => "Boolean",
            ConditionValue::Array(_) => "Array",
        }
    }

    fn mismatch(&self, expected: &str) -> ConditionError {
        ConditionError::TypeMismatch {
            expected: expected.to_string(),
            actual: self.kind().to_string(),
        }
    }

    /// The value as text: a string, or a number or boolean written out.
    ///
    /// # Errors
    ///
    /// [`ConditionError::TypeMismatch`] for a list.
    pub fn as_string(&self) -> Result<String, ConditionError> {
        match self {
            ConditionValue::String(s) => Ok(s.clone()),
            ConditionValue::Number(n) => Ok(n.to_string()),
            ConditionValue::Boolean(b) => Ok(b.to_string()),
            ConditionValue::Array(_) => Err(self.mismatch("String")),
        }
    }

    /// The value as a finite number.
    ///
    /// Parse reads a policy's numbers through this very function, so what it
    /// refuses is refused at parse too. `"NaN"` and `"inf"` are refused: they
    /// read as `f64`, and a comparison with them is never met.
    ///
    /// # Errors
    ///
    /// [`ConditionError::TypeMismatch`] for anything else.
    pub fn as_number(&self) -> Result<f64, ConditionError> {
        match self {
            ConditionValue::Number(n) if n.is_finite() => Ok(*n),
            ConditionValue::String(s) => s
                .parse::<f64>()
                .ok()
                .filter(|n| n.is_finite())
                .ok_or_else(|| self.mismatch("a finite Number")),
            _ => Err(self.mismatch("a finite Number")),
        }
    }

    /// The value as a boolean: `true`/`false`, as such or as a string.
    ///
    /// # Errors
    ///
    /// [`ConditionError::InvalidBooleanValue`] for any other string,
    /// [`ConditionError::TypeMismatch`] for a number or a list.
    pub fn as_boolean(&self) -> Result<bool, ConditionError> {
        match self {
            ConditionValue::Boolean(b) => Ok(*b),
            ConditionValue::String(s) => match s.as_str() {
                "true" => Ok(true),
                "false" => Ok(false),
                _ => Err(ConditionError::InvalidBooleanValue),
            },
            _ => Err(self.mismatch("Boolean")),
        }
    }

    /// The value as a list of strings.
    ///
    /// # Errors
    ///
    /// [`ConditionError::TypeMismatch`] for a scalar.
    pub fn as_array(&self) -> Result<&Vec<String>, ConditionError> {
        match self {
            ConditionValue::Array(arr) => Ok(arr),
            _ => Err(self.mismatch("Array")),
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
