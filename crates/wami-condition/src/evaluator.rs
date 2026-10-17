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
    TypeMismatch {
        expected: String,
        actual: String,
    },
    InvalidBooleanValue(String),
    InvalidDate {
        value: String,
        error: String,
    },
    MissingContextKey(String),
    InvalidConditionStructure(String),
    /// A value its operator cannot read, refused when the condition is parsed.
    ///
    /// It names where the value sits — operator, key, and the element when the
    /// value is a list — and what the operator reads, but never the value
    /// itself: a caller logging the error must not echo policy text it has
    /// not checked.
    InvalidConditionValue {
        /// The operator as written in the condition.
        operator: String,
        /// The condition key the value is compared with.
        key: String,
        /// The offending element's index, when the value is a list.
        position: Option<usize>,
        /// What the operator reads.
        expected: String,
    },
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
            ConditionError::InvalidConditionValue {
                operator,
                key,
                position,
                expected,
            } => {
                write!(f, "Invalid value for {operator} on key {key}")?;
                if let Some(index) = position {
                    write!(f, " at element {index}")?;
                }
                write!(f, ": expected {expected}")
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
        // An error is not a `false`: answering it as one made the statement
        // vanish, and a vanished Deny is a fail-open. `parse_condition_block`
        // refuses every policy-side value an operator cannot read, so what
        // still errs here is the CONTEXT side — a key whose value the operator
        // cannot compare (`NumericLessThan` on `aws:username`) — or a block
        // built by hand without going through parse.
        if !super::operators::evaluate_operator(operator, actual_value, expected_value)? {
            return Ok(false);
        }
    }

    Ok(true) // All keys passed
}

/// Parse a condition block from JSON Value
///
/// Refuses, rather than defers to evaluation, everything evaluation could not
/// read: a block that is not an object, an operator nobody defined, and a
/// value its operator cannot compare (the table in `validate.rs`). Each used to
/// evaluate to `false`, which made the statement carrying it vanish.
///
/// # Errors
///
/// [`ConditionError::InvalidConditionStructure`] for the shape,
/// [`ConditionError::UnknownOperator`] for a misspelt operator, and
/// [`ConditionError::InvalidConditionValue`] for a value its operator cannot
/// read — including a list where the operator reads one value (wami 002).
pub fn parse_condition_block(value: &Value) -> Result<ConditionBlock, ConditionError> {
    let obj = value.as_object().ok_or_else(|| {
        ConditionError::InvalidConditionStructure("Condition must be an object".to_string())
    })?;

    let mut block = ConditionBlock::new();

    for (operator_name, key_value_obj) in obj {
        let operator = ConditionOperator::from_str(operator_name)?;
        let key_value_map = key_value_obj.as_object().ok_or_else(|| {
            ConditionError::InvalidConditionStructure(format!(
                "Operator '{}' value must be an object",
                operator_name
            ))
        })?;

        let mut key_values = HashMap::new();
        for (key, value) in key_value_map {
            crate::validate::check_value(operator_name, operator, key, value)?;
            let condition_value = ConditionValue::from(value.clone());
            key_values.insert(key.clone(), condition_value);
        }

        block.insert(operator_name.clone(), key_values);
    }

    Ok(block)
}
