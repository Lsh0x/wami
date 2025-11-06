//! Condition Evaluator
//!
//! Evaluates condition blocks against a context.

use super::{
    get_context_value, ConditionBlock, ConditionContext, ConditionOperator, ConditionValue,
};
use serde_json::Value;
use std::collections::HashMap;
use std::str::FromStr;

/// Error types for condition evaluation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConditionError {
    UnknownOperator(String),
    TypeMismatch { expected: String, actual: String },
    InvalidBooleanValue(String),
    InvalidDate { value: String, error: String },
    MissingContextKey(String),
    InvalidConditionStructure(String),
}

impl std::fmt::Display for ConditionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConditionError::UnknownOperator(op) => write!(f, "Unknown operator: {}", op),
            ConditionError::TypeMismatch { expected, actual } => {
                write!(f, "Type mismatch: expected {}, got {}", expected, actual)
            }
            ConditionError::InvalidBooleanValue(val) => {
                write!(
                    f,
                    "Invalid boolean value: {} (must be 'true' or 'false')",
                    val
                )
            }
            ConditionError::InvalidDate { value, error } => {
                write!(f, "Invalid date value: {} - {}", value, error)
            }
            ConditionError::MissingContextKey(key) => {
                write!(f, "Missing context key: {}", key)
            }
            ConditionError::InvalidConditionStructure(msg) => {
                write!(f, "Invalid condition structure: {}", msg)
            }
        }
    }
}

impl std::error::Error for ConditionError {}

impl From<ConditionError> for crate::error::AmiError {
    fn from(err: ConditionError) -> Self {
        crate::error::AmiError::InvalidParameter {
            message: err.to_string(),
        }
    }
}

/// Evaluate a condition block
///
/// A condition block evaluates to `true` if ALL operator blocks evaluate to `true` (AND logic).
pub fn evaluate_condition_block(
    block: &ConditionBlock,
    context: &ConditionContext,
) -> Result<bool, ConditionError> {
    // Empty block passes (no conditions to check)
    if block.is_empty() {
        return Ok(true);
    }

    // All operator blocks must pass (AND logic across operators)
    for (operator_name, key_value_map) in block {
        let operator = ConditionOperator::from_str(operator_name)?;
        if !evaluate_operator_block(operator, key_value_map, context)? {
            return Ok(false); // One operator block fails = entire condition fails
        }
    }

    Ok(true) // All operator blocks passed
}

/// Evaluate an operator block
///
/// An operator block evaluates to `true` if ALL key-value pairs evaluate to `true` (AND logic).
fn evaluate_operator_block(
    operator: ConditionOperator,
    key_value_map: &HashMap<String, ConditionValue>,
    context: &ConditionContext,
) -> Result<bool, ConditionError> {
    // Empty operator block passes
    if key_value_map.is_empty() {
        return Ok(true);
    }

    // All key-value pairs must pass (AND logic within operator)
    for (key, expected_value) in key_value_map {
        let actual_value = get_context_value(key, context)
            .map_err(|e| ConditionError::MissingContextKey(format!("{}: {}", key, e)))?;
        if !super::operators::evaluate_operator(operator, actual_value, expected_value)? {
            return Ok(false); // One key fails = operator block fails
        }
    }

    Ok(true) // All keys passed
}

/// Parse a condition block from JSON Value
pub fn parse_condition_block(value: &Value) -> Result<ConditionBlock, ConditionError> {
    let obj = value.as_object().ok_or_else(|| {
        ConditionError::InvalidConditionStructure("Condition must be an object".to_string())
    })?;

    let mut block = ConditionBlock::new();

    for (operator_name, key_value_obj) in obj {
        let key_value_map = key_value_obj.as_object().ok_or_else(|| {
            ConditionError::InvalidConditionStructure(format!(
                "Operator '{}' value must be an object",
                operator_name
            ))
        })?;

        let mut key_values = HashMap::new();
        for (key, value) in key_value_map {
            let condition_value = ConditionValue::from(value.clone());
            key_values.insert(key.clone(), condition_value);
        }

        block.insert(operator_name.clone(), key_values);
    }

    Ok(block)
}
