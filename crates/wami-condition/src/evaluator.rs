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
///
/// An error names what the policy's author wrote and must fix — the operator,
/// the key, the position of an element — and the KIND of a value, never the
/// value itself, neither the policy's nor the request's: a caller logging the
/// error must not echo text it has not checked (wami 001).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConditionError {
    UnknownOperator(String),
    TypeMismatch {
        expected: String,
        actual: String,
    },
    /// A string that is neither `true` nor `false` where a boolean is read.
    InvalidBooleanValue,
    /// A string that is not an RFC 3339 date where a date is read.
    InvalidDate {
        /// What the date parser objected to — never the input.
        error: String,
    },
    MissingContextKey(String),
    InvalidConditionStructure(String),
    /// A value its operator cannot read, refused when the condition is parsed.
    ///
    /// It names where the value sits — operator, key, and the element when the
    /// value is a list — and what the operator reads, but never the value
    /// itself.
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
    /// An operator no key can feed: the `ForAllValues`/`ForAnyValue` forms of
    /// `Numeric*`, `Date*` and `IpAddress` compare a LIST of numbers, dates or
    /// addresses, and no declared key holds one (`keys::KeyType` has no such
    /// type; custom keys are compared as strings). Refused at parse rather
    /// than kept as a path no parsed policy reaches (wami 001).
    OperatorWithoutKey {
        /// The operator as written in the condition.
        operator: String,
    },
    /// An operator that cannot compare the type of the key it is given — a
    /// string operator on the Boolean `aws:SecureTransport`, a numeric one on
    /// a key nobody declared (compared as a string). Refused at parse: it used
    /// to evaluate to `false`, so a Deny carrying it vanished.
    OperatorKeyMismatch {
        /// The operator as written in the condition.
        operator: String,
        /// The condition key.
        key: String,
        /// The key's declared type, or that it is undeclared.
        key_type: String,
    },
}

impl std::fmt::Display for ConditionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConditionError::UnknownOperator(op) => write!(f, "Unknown operator: {}", op),
            ConditionError::TypeMismatch { expected, actual } => {
                write!(f, "Type mismatch: expected {}, got {}", expected, actual)
            }
            ConditionError::InvalidBooleanValue => {
                write!(f, "Invalid boolean value: must be 'true' or 'false'")
            }
            ConditionError::InvalidDate { error } => {
                write!(f, "Invalid date value: {error}")
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
            ConditionError::OperatorWithoutKey { operator } => write!(
                f,
                "{operator} cannot be used: no key of that kind holds a list"
            ),
            ConditionError::OperatorKeyMismatch {
                operator,
                key,
                key_type,
            } => write!(
                f,
                "{operator} cannot compare key {key}, which is {key_type}"
            ),
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
///
/// Parts are read in sorted order (operators, then keys); a false part does
/// not stop the reading; the first part that cannot be compared stops the
/// evaluation with its error. So a part that cannot be compared is an error
/// even when another part is false, and the answer is deterministic (wami 001,
/// read everything before deciding). It used to stop at the first FALSE part,
/// in `HashMap` order: one request was refused on one parse and decided on the
/// next.
///
/// # Errors
///
/// The first error in that order, from an unknown operator or a comparison
/// that cannot be made.
pub fn evaluate_condition_block(
    block: &ConditionBlock,
    context: &ConditionContext,
) -> Result<bool, ConditionError> {
    let mut operators: Vec<_> = block.iter().collect();
    operators.sort_by_key(|(name, _)| *name);
    let mut holds = true;
    for (operator_name, key_value_map) in operators {
        let operator = ConditionOperator::from_str(operator_name)?;
        holds &= evaluate_operator_block(operator, key_value_map, context)?;
    }
    Ok(holds)
}

/// Evaluate an operator block
///
/// An operator block evaluates to `true` if ALL key-value pairs evaluate to
/// `true` (AND logic) — keys read in sorted order, a false one not stopping
/// the reading, the first that cannot be compared stopping it with its error.
fn evaluate_operator_block(
    operator: ConditionOperator,
    key_value_map: &HashMap<String, ConditionValue>,
    context: &ConditionContext,
) -> Result<bool, ConditionError> {
    let mut keys: Vec<_> = key_value_map.iter().collect();
    keys.sort_by_key(|(key, _)| *key);
    let mut holds = true;
    for (key, expected_value) in keys {
        let actual_value = get_context_value(key, context)
            .map_err(|e| ConditionError::MissingContextKey(format!("{}: {}", key, e)))?;
        // An error is not a `false`: answering it as one made the statement
        // vanish, and a vanished Deny is a fail-open. `parse_condition_block`
        // refuses every policy-side value an operator cannot read and every
        // operator its key's declared type rules out, so what still errs here
        // is the CONTEXT side — a custom key holding a value of another type,
        // an `aws:SourceIp` that is no address — or a block built by hand
        // without going through parse.
        holds &= super::operators::evaluate_operator(operator, actual_value, expected_value)?;
    }
    Ok(holds)
}

/// Parse a condition block from JSON Value
///
/// Refuses, rather than defers to evaluation, everything evaluation could not
/// read: a block that is not an object, an operator nobody defined, an
/// operator that cannot compare its key's declared type, and a value its
/// operator cannot compare (the table in `validate.rs`). Each used to evaluate
/// to `false`, which made the statement carrying it vanish.
///
/// # Errors
///
/// [`ConditionError::InvalidConditionStructure`] for the shape,
/// [`ConditionError::UnknownOperator`] for a misspelt operator,
/// [`ConditionError::OperatorKeyMismatch`] for an operator its key rules out, and
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
