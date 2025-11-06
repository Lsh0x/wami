//! Condition Operators
//!
//! Implements all condition operators for policy evaluation.

use super::{ConditionError, ConditionValue};
use std::str::FromStr;

/// Condition operator types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionOperator {
    // String operators
    StringEquals,
    StringNotEquals,
    StringLike,
    StringNotLike,
    StringEqualsIgnoreCase,
    StringNotEqualsIgnoreCase,
    StringEqualsIfExists,
    StringNotEqualsIfExists,
    StringLikeIfExists,
    StringNotLikeIfExists,

    // Numeric operators
    NumericEquals,
    NumericNotEquals,
    NumericLessThan,
    NumericLessThanEquals,
    NumericGreaterThan,
    NumericGreaterThanEquals,
    NumericEqualsIfExists,
    NumericNotEqualsIfExists,
    NumericLessThanIfExists,
    NumericLessThanEqualsIfExists,
    NumericGreaterThanIfExists,
    NumericGreaterThanEqualsIfExists,

    // Date operators
    DateEquals,
    DateNotEquals,
    DateLessThan,
    DateLessThanEquals,
    DateGreaterThan,
    DateGreaterThanEquals,
    DateEqualsIfExists,
    DateNotEqualsIfExists,
    DateLessThanIfExists,
    DateLessThanEqualsIfExists,
    DateGreaterThanIfExists,
    DateGreaterThanEqualsIfExists,

    // IP address operators
    IpAddress,
    NotIpAddress,
    IpAddressIfExists,
    NotIpAddressIfExists,

    // ARN operators
    ArnEquals,
    ArnNotEquals,
    ArnLike,
    ArnNotLike,
    ArnEqualsIfExists,
    ArnNotEqualsIfExists,
    ArnLikeIfExists,
    ArnNotLikeIfExists,

    // Boolean operators
    Bool,
    BoolIfExists,

    // Binary operators
    BinaryEquals,
    BinaryEqualsIfExists,

    // Null operators
    Null,
    NullIfExists,

    // Set operators (ForAllValues)
    ForAllValuesStringEquals,
    ForAllValuesStringNotEquals,
    ForAllValuesStringLike,
    ForAllValuesStringNotLike,
    ForAllValuesArnEquals,
    ForAllValuesArnLike,
    ForAllValuesNumericLessThan,
    ForAllValuesNumericGreaterThan,
    ForAllValuesIpAddress,
    ForAllValuesDateLessThan,
    ForAllValuesDateGreaterThan,

    // Set operators (ForAnyValue)
    ForAnyValueStringEquals,
    ForAnyValueStringNotEquals,
    ForAnyValueStringLike,
    ForAnyValueStringNotLike,
    ForAnyValueArnEquals,
    ForAnyValueArnLike,
    ForAnyValueNumericLessThan,
    ForAnyValueNumericGreaterThan,
    ForAnyValueIpAddress,
    ForAnyValueDateLessThan,
    ForAnyValueDateGreaterThan,
}

impl FromStr for ConditionOperator {
    type Err = ConditionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "StringEquals" => Ok(ConditionOperator::StringEquals),
            "StringNotEquals" => Ok(ConditionOperator::StringNotEquals),
            "StringLike" => Ok(ConditionOperator::StringLike),
            "StringNotLike" => Ok(ConditionOperator::StringNotLike),
            "StringEqualsIgnoreCase" => Ok(ConditionOperator::StringEqualsIgnoreCase),
            "StringNotEqualsIgnoreCase" => Ok(ConditionOperator::StringNotEqualsIgnoreCase),
            "StringEqualsIfExists" => Ok(ConditionOperator::StringEqualsIfExists),
            "StringNotEqualsIfExists" => Ok(ConditionOperator::StringNotEqualsIfExists),
            "StringLikeIfExists" => Ok(ConditionOperator::StringLikeIfExists),
            "StringNotLikeIfExists" => Ok(ConditionOperator::StringNotLikeIfExists),

            "NumericEquals" => Ok(ConditionOperator::NumericEquals),
            "NumericNotEquals" => Ok(ConditionOperator::NumericNotEquals),
            "NumericLessThan" => Ok(ConditionOperator::NumericLessThan),
            "NumericLessThanEquals" => Ok(ConditionOperator::NumericLessThanEquals),
            "NumericGreaterThan" => Ok(ConditionOperator::NumericGreaterThan),
            "NumericGreaterThanEquals" => Ok(ConditionOperator::NumericGreaterThanEquals),
            "NumericEqualsIfExists" => Ok(ConditionOperator::NumericEqualsIfExists),
            "NumericNotEqualsIfExists" => Ok(ConditionOperator::NumericNotEqualsIfExists),
            "NumericLessThanIfExists" => Ok(ConditionOperator::NumericLessThanIfExists),
            "NumericLessThanEqualsIfExists" => Ok(ConditionOperator::NumericLessThanEqualsIfExists),
            "NumericGreaterThanIfExists" => Ok(ConditionOperator::NumericGreaterThanIfExists),
            "NumericGreaterThanEqualsIfExists" => {
                Ok(ConditionOperator::NumericGreaterThanEqualsIfExists)
            }

            "DateEquals" => Ok(ConditionOperator::DateEquals),
            "DateNotEquals" => Ok(ConditionOperator::DateNotEquals),
            "DateLessThan" => Ok(ConditionOperator::DateLessThan),
            "DateLessThanEquals" => Ok(ConditionOperator::DateLessThanEquals),
            "DateGreaterThan" => Ok(ConditionOperator::DateGreaterThan),
            "DateGreaterThanEquals" => Ok(ConditionOperator::DateGreaterThanEquals),
            "DateEqualsIfExists" => Ok(ConditionOperator::DateEqualsIfExists),
            "DateNotEqualsIfExists" => Ok(ConditionOperator::DateNotEqualsIfExists),
            "DateLessThanIfExists" => Ok(ConditionOperator::DateLessThanIfExists),
            "DateLessThanEqualsIfExists" => Ok(ConditionOperator::DateLessThanEqualsIfExists),
            "DateGreaterThanIfExists" => Ok(ConditionOperator::DateGreaterThanIfExists),
            "DateGreaterThanEqualsIfExists" => Ok(ConditionOperator::DateGreaterThanEqualsIfExists),

            "IpAddress" => Ok(ConditionOperator::IpAddress),
            "NotIpAddress" => Ok(ConditionOperator::NotIpAddress),
            "IpAddressIfExists" => Ok(ConditionOperator::IpAddressIfExists),
            "NotIpAddressIfExists" => Ok(ConditionOperator::NotIpAddressIfExists),

            "ArnEquals" => Ok(ConditionOperator::ArnEquals),
            "ArnNotEquals" => Ok(ConditionOperator::ArnNotEquals),
            "ArnLike" => Ok(ConditionOperator::ArnLike),
            "ArnNotLike" => Ok(ConditionOperator::ArnNotLike),
            "ArnEqualsIfExists" => Ok(ConditionOperator::ArnEqualsIfExists),
            "ArnNotEqualsIfExists" => Ok(ConditionOperator::ArnNotEqualsIfExists),
            "ArnLikeIfExists" => Ok(ConditionOperator::ArnLikeIfExists),
            "ArnNotLikeIfExists" => Ok(ConditionOperator::ArnNotLikeIfExists),

            "Bool" => Ok(ConditionOperator::Bool),
            "BoolIfExists" => Ok(ConditionOperator::BoolIfExists),

            "BinaryEquals" => Ok(ConditionOperator::BinaryEquals),
            "BinaryEqualsIfExists" => Ok(ConditionOperator::BinaryEqualsIfExists),

            "Null" => Ok(ConditionOperator::Null),
            "NullIfExists" => Ok(ConditionOperator::NullIfExists),

            "ForAllValues:StringEquals" => Ok(ConditionOperator::ForAllValuesStringEquals),
            "ForAllValues:StringNotEquals" => Ok(ConditionOperator::ForAllValuesStringNotEquals),
            "ForAllValues:StringLike" => Ok(ConditionOperator::ForAllValuesStringLike),
            "ForAllValues:StringNotLike" => Ok(ConditionOperator::ForAllValuesStringNotLike),
            "ForAllValues:ArnEquals" => Ok(ConditionOperator::ForAllValuesArnEquals),
            "ForAllValues:ArnLike" => Ok(ConditionOperator::ForAllValuesArnLike),
            "ForAllValues:NumericLessThan" => Ok(ConditionOperator::ForAllValuesNumericLessThan),
            "ForAllValues:NumericGreaterThan" => {
                Ok(ConditionOperator::ForAllValuesNumericGreaterThan)
            }
            "ForAllValues:IpAddress" => Ok(ConditionOperator::ForAllValuesIpAddress),
            "ForAllValues:DateLessThan" => Ok(ConditionOperator::ForAllValuesDateLessThan),
            "ForAllValues:DateGreaterThan" => Ok(ConditionOperator::ForAllValuesDateGreaterThan),

            "ForAnyValue:StringEquals" => Ok(ConditionOperator::ForAnyValueStringEquals),
            "ForAnyValue:StringNotEquals" => Ok(ConditionOperator::ForAnyValueStringNotEquals),
            "ForAnyValue:StringLike" => Ok(ConditionOperator::ForAnyValueStringLike),
            "ForAnyValue:StringNotLike" => Ok(ConditionOperator::ForAnyValueStringNotLike),
            "ForAnyValue:ArnEquals" => Ok(ConditionOperator::ForAnyValueArnEquals),
            "ForAnyValue:ArnLike" => Ok(ConditionOperator::ForAnyValueArnLike),
            "ForAnyValue:NumericLessThan" => Ok(ConditionOperator::ForAnyValueNumericLessThan),
            "ForAnyValue:NumericGreaterThan" => {
                Ok(ConditionOperator::ForAnyValueNumericGreaterThan)
            }
            "ForAnyValue:IpAddress" => Ok(ConditionOperator::ForAnyValueIpAddress),
            "ForAnyValue:DateLessThan" => Ok(ConditionOperator::ForAnyValueDateLessThan),
            "ForAnyValue:DateGreaterThan" => Ok(ConditionOperator::ForAnyValueDateGreaterThan),

            _ => Err(ConditionError::UnknownOperator(s.to_string())),
        }
    }
}

/// Evaluate a condition operator
pub fn evaluate_operator(
    operator: ConditionOperator,
    actual: Option<ConditionValue>,
    expected: &ConditionValue,
) -> Result<bool, ConditionError> {
    match operator {
        // String operators
        ConditionOperator::StringEquals => evaluate_string_equals(actual, expected),
        ConditionOperator::StringNotEquals => evaluate_string_equals(actual, expected).map(|r| !r),
        ConditionOperator::StringLike => evaluate_string_like(actual, expected),
        ConditionOperator::StringNotLike => evaluate_string_like(actual, expected).map(|r| !r),
        ConditionOperator::StringEqualsIgnoreCase => {
            evaluate_string_equals_ignore_case(actual, expected)
        }
        ConditionOperator::StringNotEqualsIgnoreCase => {
            evaluate_string_equals_ignore_case(actual, expected).map(|r| !r)
        }
        ConditionOperator::StringEqualsIfExists => {
            evaluate_if_exists(actual, |a| evaluate_string_equals(Some(a), expected))
        }
        ConditionOperator::StringNotEqualsIfExists => evaluate_if_exists(actual, |a| {
            evaluate_string_equals(Some(a), expected).map(|r| !r)
        }),
        ConditionOperator::StringLikeIfExists => {
            evaluate_if_exists(actual, |a| evaluate_string_like(Some(a), expected))
        }
        ConditionOperator::StringNotLikeIfExists => evaluate_if_exists(actual, |a| {
            evaluate_string_like(Some(a), expected).map(|r| !r)
        }),

        // Numeric operators
        ConditionOperator::NumericEquals => evaluate_numeric_equals(actual, expected),
        ConditionOperator::NumericNotEquals => {
            evaluate_numeric_equals(actual, expected).map(|r| !r)
        }
        ConditionOperator::NumericLessThan => evaluate_numeric_less_than(actual, expected),
        ConditionOperator::NumericLessThanEquals => {
            evaluate_numeric_less_than_equals(actual, expected)
        }
        ConditionOperator::NumericGreaterThan => evaluate_numeric_greater_than(actual, expected),
        ConditionOperator::NumericGreaterThanEquals => {
            evaluate_numeric_greater_than_equals(actual, expected)
        }
        ConditionOperator::NumericEqualsIfExists => {
            evaluate_if_exists(actual, |a| evaluate_numeric_equals(Some(a), expected))
        }
        ConditionOperator::NumericNotEqualsIfExists => evaluate_if_exists(actual, |a| {
            evaluate_numeric_equals(Some(a), expected).map(|r| !r)
        }),
        ConditionOperator::NumericLessThanIfExists => {
            evaluate_if_exists(actual, |a| evaluate_numeric_less_than(Some(a), expected))
        }
        ConditionOperator::NumericLessThanEqualsIfExists => evaluate_if_exists(actual, |a| {
            evaluate_numeric_less_than_equals(Some(a), expected)
        }),
        ConditionOperator::NumericGreaterThanIfExists => {
            evaluate_if_exists(actual, |a| evaluate_numeric_greater_than(Some(a), expected))
        }
        ConditionOperator::NumericGreaterThanEqualsIfExists => evaluate_if_exists(actual, |a| {
            evaluate_numeric_greater_than_equals(Some(a), expected)
        }),

        // Date operators
        ConditionOperator::DateEquals => evaluate_date_equals(actual, expected),
        ConditionOperator::DateNotEquals => evaluate_date_equals(actual, expected).map(|r| !r),
        ConditionOperator::DateLessThan => evaluate_date_less_than(actual, expected),
        ConditionOperator::DateLessThanEquals => evaluate_date_less_than_equals(actual, expected),
        ConditionOperator::DateGreaterThan => evaluate_date_greater_than(actual, expected),
        ConditionOperator::DateGreaterThanEquals => {
            evaluate_date_greater_than_equals(actual, expected)
        }
        ConditionOperator::DateEqualsIfExists => {
            evaluate_if_exists(actual, |a| evaluate_date_equals(Some(a), expected))
        }
        ConditionOperator::DateNotEqualsIfExists => evaluate_if_exists(actual, |a| {
            evaluate_date_equals(Some(a), expected).map(|r| !r)
        }),
        ConditionOperator::DateLessThanIfExists => {
            evaluate_if_exists(actual, |a| evaluate_date_less_than(Some(a), expected))
        }
        ConditionOperator::DateLessThanEqualsIfExists => evaluate_if_exists(actual, |a| {
            evaluate_date_less_than_equals(Some(a), expected)
        }),
        ConditionOperator::DateGreaterThanIfExists => {
            evaluate_if_exists(actual, |a| evaluate_date_greater_than(Some(a), expected))
        }
        ConditionOperator::DateGreaterThanEqualsIfExists => evaluate_if_exists(actual, |a| {
            evaluate_date_greater_than_equals(Some(a), expected)
        }),

        // IP address operators
        ConditionOperator::IpAddress => evaluate_ip_address(actual, expected),
        ConditionOperator::NotIpAddress => evaluate_ip_address(actual, expected).map(|r| !r),
        ConditionOperator::IpAddressIfExists => {
            evaluate_if_exists(actual, |a| evaluate_ip_address(Some(a), expected))
        }
        ConditionOperator::NotIpAddressIfExists => evaluate_if_exists(actual, |a| {
            evaluate_ip_address(Some(a), expected).map(|r| !r)
        }),

        // ARN operators
        ConditionOperator::ArnEquals => evaluate_arn_equals(actual, expected),
        ConditionOperator::ArnNotEquals => evaluate_arn_equals(actual, expected).map(|r| !r),
        ConditionOperator::ArnLike => evaluate_arn_like(actual, expected),
        ConditionOperator::ArnNotLike => evaluate_arn_like(actual, expected).map(|r| !r),
        ConditionOperator::ArnEqualsIfExists => {
            evaluate_if_exists(actual, |a| evaluate_arn_equals(Some(a), expected))
        }
        ConditionOperator::ArnNotEqualsIfExists => evaluate_if_exists(actual, |a| {
            evaluate_arn_equals(Some(a), expected).map(|r| !r)
        }),
        ConditionOperator::ArnLikeIfExists => {
            evaluate_if_exists(actual, |a| evaluate_arn_like(Some(a), expected))
        }
        ConditionOperator::ArnNotLikeIfExists => {
            evaluate_if_exists(actual, |a| evaluate_arn_like(Some(a), expected).map(|r| !r))
        }

        // Boolean operators
        ConditionOperator::Bool => evaluate_bool(actual, expected),
        ConditionOperator::BoolIfExists => {
            evaluate_if_exists(actual, |a| evaluate_bool(Some(a), expected))
        }

        // Binary operators
        ConditionOperator::BinaryEquals => evaluate_binary_equals(actual, expected),
        ConditionOperator::BinaryEqualsIfExists => {
            evaluate_if_exists(actual, |a| evaluate_binary_equals(Some(a), expected))
        }

        // Null operators
        ConditionOperator::Null => evaluate_null(actual, expected),
        ConditionOperator::NullIfExists => {
            evaluate_if_exists(actual, |a| evaluate_null(Some(a), expected))
        }

        // Set operators - ForAllValues
        ConditionOperator::ForAllValuesStringEquals => {
            evaluate_for_all_values_string_equals(actual, expected)
        }
        ConditionOperator::ForAllValuesStringNotEquals => {
            evaluate_for_all_values_string_equals(actual, expected).map(|r| !r)
        }
        ConditionOperator::ForAllValuesStringLike => {
            evaluate_for_all_values_string_like(actual, expected)
        }
        ConditionOperator::ForAllValuesStringNotLike => {
            evaluate_for_all_values_string_like(actual, expected).map(|r| !r)
        }
        ConditionOperator::ForAllValuesArnEquals => {
            evaluate_for_all_values_arn_equals(actual, expected)
        }
        ConditionOperator::ForAllValuesArnLike => {
            evaluate_for_all_values_arn_like(actual, expected)
        }
        ConditionOperator::ForAllValuesNumericLessThan => {
            evaluate_for_all_values_numeric_less_than(actual, expected)
        }
        ConditionOperator::ForAllValuesNumericGreaterThan => {
            evaluate_for_all_values_numeric_greater_than(actual, expected)
        }
        ConditionOperator::ForAllValuesIpAddress => {
            evaluate_for_all_values_ip_address(actual, expected)
        }
        ConditionOperator::ForAllValuesDateLessThan => {
            evaluate_for_all_values_date_less_than(actual, expected)
        }
        ConditionOperator::ForAllValuesDateGreaterThan => {
            evaluate_for_all_values_date_greater_than(actual, expected)
        }

        // Set operators - ForAnyValue
        ConditionOperator::ForAnyValueStringEquals => {
            evaluate_for_any_value_string_equals(actual, expected)
        }
        ConditionOperator::ForAnyValueStringNotEquals => {
            evaluate_for_any_value_string_equals(actual, expected).map(|r| !r)
        }
        ConditionOperator::ForAnyValueStringLike => {
            evaluate_for_any_value_string_like(actual, expected)
        }
        ConditionOperator::ForAnyValueStringNotLike => {
            evaluate_for_any_value_string_like(actual, expected).map(|r| !r)
        }
        ConditionOperator::ForAnyValueArnEquals => {
            evaluate_for_any_value_arn_equals(actual, expected)
        }
        ConditionOperator::ForAnyValueArnLike => evaluate_for_any_value_arn_like(actual, expected),
        ConditionOperator::ForAnyValueNumericLessThan => {
            evaluate_for_any_value_numeric_less_than(actual, expected)
        }
        ConditionOperator::ForAnyValueNumericGreaterThan => {
            evaluate_for_any_value_numeric_greater_than(actual, expected)
        }
        ConditionOperator::ForAnyValueIpAddress => {
            evaluate_for_any_value_ip_address(actual, expected)
        }
        ConditionOperator::ForAnyValueDateLessThan => {
            evaluate_for_any_value_date_less_than(actual, expected)
        }
        ConditionOperator::ForAnyValueDateGreaterThan => {
            evaluate_for_any_value_date_greater_than(actual, expected)
        }
    }
}

// Helper: Evaluate IfExists behavior
fn evaluate_if_exists<F>(
    actual: Option<ConditionValue>,
    evaluator: F,
) -> Result<bool, ConditionError>
where
    F: FnOnce(ConditionValue) -> Result<bool, ConditionError>,
{
    match actual {
        Some(value) => evaluator(value),
        None => Ok(true), // IfExists: missing value passes
    }
}

// String operator implementations
fn evaluate_string_equals(
    actual: Option<ConditionValue>,
    expected: &ConditionValue,
) -> Result<bool, ConditionError> {
    match actual {
        Some(ConditionValue::String(actual_str)) => {
            let expected_str = expected.as_string()?;
            Ok(actual_str == expected_str)
        }
        None => Ok(false), // Missing value = no match
        _ => Ok(false),    // Type mismatch = no match
    }
}

fn evaluate_string_equals_ignore_case(
    actual: Option<ConditionValue>,
    expected: &ConditionValue,
) -> Result<bool, ConditionError> {
    match actual {
        Some(ConditionValue::String(actual_str)) => {
            let expected_str = expected.as_string()?;
            Ok(actual_str.eq_ignore_ascii_case(&expected_str))
        }
        None => Ok(false),
        _ => Ok(false),
    }
}

fn evaluate_string_like(
    actual: Option<ConditionValue>,
    expected: &ConditionValue,
) -> Result<bool, ConditionError> {
    match actual {
        Some(ConditionValue::String(actual_str)) => {
            let pattern = expected.as_string()?;
            Ok(matches_wildcard_pattern(&actual_str, &pattern))
        }
        None => Ok(false),
        _ => Ok(false),
    }
}

// Wildcard pattern matching (* and ?)
fn matches_wildcard_pattern(value: &str, pattern: &str) -> bool {
    // Simple wildcard matching: * matches any sequence, ? matches single character
    // This is a simplified implementation - AWS uses more complex matching
    if pattern == "*" {
        return true;
    }

    // Convert pattern to regex-like matching
    let mut value_chars = value.chars();
    let mut pattern_chars = pattern.chars();

    while let Some(pc) = pattern_chars.next() {
        match pc {
            '*' => {
                // Match zero or more characters
                // Try matching rest of pattern against remaining value
                let remaining_pattern: String = pattern_chars.collect();
                if remaining_pattern.is_empty() {
                    return true; // * at end matches everything
                }
                // Try matching remaining pattern at each position
                while let Some(_) = value_chars.next() {
                    let remaining_value: String = value_chars.as_str().chars().collect();
                    if matches_wildcard_pattern(&remaining_value, &remaining_pattern) {
                        return true;
                    }
                }
                return false;
            }
            '?' => {
                // Match single character
                if value_chars.next().is_none() {
                    return false;
                }
            }
            _ => {
                // Match exact character
                if value_chars.next() != Some(pc) {
                    return false;
                }
            }
        }
    }

    // Pattern exhausted - value must also be exhausted
    value_chars.next().is_none()
}

// Numeric operator implementations
fn evaluate_numeric_equals(
    actual: Option<ConditionValue>,
    expected: &ConditionValue,
) -> Result<bool, ConditionError> {
    match actual {
        Some(actual_val) => {
            let actual_num = actual_val.as_number()?;
            let expected_num = expected.as_number()?;
            Ok((actual_num - expected_num).abs() < f64::EPSILON)
        }
        None => Ok(false),
    }
}

fn evaluate_numeric_less_than(
    actual: Option<ConditionValue>,
    expected: &ConditionValue,
) -> Result<bool, ConditionError> {
    match actual {
        Some(actual_val) => {
            let actual_num = actual_val.as_number()?;
            let expected_num = expected.as_number()?;
            Ok(actual_num < expected_num)
        }
        None => Ok(false),
    }
}

fn evaluate_numeric_less_than_equals(
    actual: Option<ConditionValue>,
    expected: &ConditionValue,
) -> Result<bool, ConditionError> {
    match actual {
        Some(actual_val) => {
            let actual_num = actual_val.as_number()?;
            let expected_num = expected.as_number()?;
            Ok(actual_num <= expected_num)
        }
        None => Ok(false),
    }
}

fn evaluate_numeric_greater_than(
    actual: Option<ConditionValue>,
    expected: &ConditionValue,
) -> Result<bool, ConditionError> {
    match actual {
        Some(actual_val) => {
            let actual_num = actual_val.as_number()?;
            let expected_num = expected.as_number()?;
            Ok(actual_num > expected_num)
        }
        None => Ok(false),
    }
}

fn evaluate_numeric_greater_than_equals(
    actual: Option<ConditionValue>,
    expected: &ConditionValue,
) -> Result<bool, ConditionError> {
    match actual {
        Some(actual_val) => {
            let actual_num = actual_val.as_number()?;
            let expected_num = expected.as_number()?;
            Ok(actual_num >= expected_num)
        }
        None => Ok(false),
    }
}

// Date operator implementations
fn evaluate_date_equals(
    actual: Option<ConditionValue>,
    expected: &ConditionValue,
) -> Result<bool, ConditionError> {
    match actual {
        Some(ConditionValue::String(actual_str)) => {
            let expected_str = expected.as_string()?;
            let actual_time = parse_rfc3339(&actual_str)?;
            let expected_time = parse_rfc3339(&expected_str)?;
            Ok(actual_time == expected_time)
        }
        None => Ok(false),
        _ => Ok(false),
    }
}

fn evaluate_date_less_than(
    actual: Option<ConditionValue>,
    expected: &ConditionValue,
) -> Result<bool, ConditionError> {
    match actual {
        Some(ConditionValue::String(actual_str)) => {
            let expected_str = expected.as_string()?;
            let actual_time = parse_rfc3339(&actual_str)?;
            let expected_time = parse_rfc3339(&expected_str)?;
            Ok(actual_time < expected_time)
        }
        None => Ok(false),
        _ => Ok(false),
    }
}

fn evaluate_date_less_than_equals(
    actual: Option<ConditionValue>,
    expected: &ConditionValue,
) -> Result<bool, ConditionError> {
    match actual {
        Some(ConditionValue::String(actual_str)) => {
            let expected_str = expected.as_string()?;
            let actual_time = parse_rfc3339(&actual_str)?;
            let expected_time = parse_rfc3339(&expected_str)?;
            Ok(actual_time <= expected_time)
        }
        None => Ok(false),
        _ => Ok(false),
    }
}

fn evaluate_date_greater_than(
    actual: Option<ConditionValue>,
    expected: &ConditionValue,
) -> Result<bool, ConditionError> {
    match actual {
        Some(ConditionValue::String(actual_str)) => {
            let expected_str = expected.as_string()?;
            let actual_time = parse_rfc3339(&actual_str)?;
            let expected_time = parse_rfc3339(&expected_str)?;
            Ok(actual_time > expected_time)
        }
        None => Ok(false),
        _ => Ok(false),
    }
}

fn evaluate_date_greater_than_equals(
    actual: Option<ConditionValue>,
    expected: &ConditionValue,
) -> Result<bool, ConditionError> {
    match actual {
        Some(ConditionValue::String(actual_str)) => {
            let expected_str = expected.as_string()?;
            let actual_time = parse_rfc3339(&actual_str)?;
            let expected_time = parse_rfc3339(&expected_str)?;
            Ok(actual_time >= expected_time)
        }
        None => Ok(false),
        _ => Ok(false),
    }
}

fn parse_rfc3339(s: &str) -> Result<chrono::DateTime<chrono::Utc>, ConditionError> {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .map_err(|e| ConditionError::InvalidDate {
            value: s.to_string(),
            error: e.to_string(),
        })
}

// IP address operator implementations
fn evaluate_ip_address(
    actual: Option<ConditionValue>,
    expected: &ConditionValue,
) -> Result<bool, ConditionError> {
    match actual {
        Some(ConditionValue::String(actual_ip)) => {
            // Handle both single IP/CIDR and array of IPs/CIDRs
            match expected {
                ConditionValue::String(expected_ip_cidr) => {
                    Ok(ip_matches_cidr(&actual_ip, expected_ip_cidr))
                }
                ConditionValue::Array(expected_ips) => {
                    // At least one CIDR must match
                    Ok(expected_ips
                        .iter()
                        .any(|cidr| ip_matches_cidr(&actual_ip, cidr)))
                }
                _ => Ok(false),
            }
        }
        None => Ok(false),
        _ => Ok(false),
    }
}

fn ip_matches_cidr(ip: &str, cidr: &str) -> bool {
    // Simple CIDR matching - for production, use a proper IP/CIDR library
    if ip == cidr {
        return true; // Exact match
    }

    // Parse CIDR notation (e.g., "203.0.113.0/24")
    if let Some((network, prefix_len_str)) = cidr.split_once('/') {
        if let Ok(prefix_len) = prefix_len_str.parse::<u8>() {
            // For IPv4
            if let (Some(ip_addr), Some(net_addr)) = (parse_ipv4(ip), parse_ipv4(network)) {
                return ip_in_cidr_v4(ip_addr, net_addr, prefix_len);
            }
            // For IPv6 (simplified - basic prefix matching)
            if ip.contains(':') && cidr.contains(':') {
                // Basic IPv6 CIDR matching - check if IP starts with network prefix
                // This is simplified - proper IPv6 CIDR would need full parsing
                if let Some((network_part, _)) = cidr.split_once('/') {
                    // For /32 prefix, check first 32 bits (8 hex groups of 4 chars each)
                    // Simplified: check if IP starts with network part
                    if prefix_len <= 128 {
                        // For now, do prefix string matching (simplified)
                        // Proper implementation would parse IPv6 addresses and masks
                        return ip.starts_with(network_part) || ip == network;
                    }
                }
                return ip == network; // Fallback to exact match
            }
        }
    }

    false
}

fn parse_ipv4(ip: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut bytes = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        bytes[i] = part.parse().ok()?;
    }
    Some(bytes)
}

fn ip_in_cidr_v4(ip: [u8; 4], network: [u8; 4], prefix_len: u8) -> bool {
    if prefix_len > 32 {
        return false;
    }
    let mask_bits = prefix_len;
    let full_bytes = (mask_bits / 8) as usize;
    let remaining_bits = mask_bits % 8;

    // Check full bytes
    for i in 0..full_bytes {
        if ip[i] != network[i] {
            return false;
        }
    }

    // Check remaining bits
    if remaining_bits > 0 && full_bytes < 4 {
        let mask = !((1u8 << (8 - remaining_bits)) - 1);
        if (ip[full_bytes] & mask) != (network[full_bytes] & mask) {
            return false;
        }
    }

    true
}

// ARN operator implementations
fn evaluate_arn_equals(
    actual: Option<ConditionValue>,
    expected: &ConditionValue,
) -> Result<bool, ConditionError> {
    match actual {
        Some(ConditionValue::String(actual_arn)) => {
            let expected_arn = expected.as_string()?;
            Ok(actual_arn == expected_arn)
        }
        None => Ok(false),
        _ => Ok(false),
    }
}

fn evaluate_arn_like(
    actual: Option<ConditionValue>,
    expected: &ConditionValue,
) -> Result<bool, ConditionError> {
    match actual {
        Some(ConditionValue::String(actual_arn)) => {
            let pattern = expected.as_string()?;
            Ok(matches_wildcard_pattern(&actual_arn, &pattern))
        }
        None => Ok(false),
        _ => Ok(false),
    }
}

// Boolean operator implementations
fn evaluate_bool(
    actual: Option<ConditionValue>,
    expected: &ConditionValue,
) -> Result<bool, ConditionError> {
    match actual {
        Some(actual_val) => {
            let actual_bool = actual_val.as_boolean()?;
            let expected_bool = expected.as_boolean()?;
            Ok(actual_bool == expected_bool)
        }
        None => Ok(false),
    }
}

// Binary operator implementations
fn evaluate_binary_equals(
    actual: Option<ConditionValue>,
    expected: &ConditionValue,
) -> Result<bool, ConditionError> {
    match actual {
        Some(ConditionValue::String(actual_base64)) => {
            let expected_base64 = expected.as_string()?;
            // Decode and compare (simplified - would use base64 crate in production)
            Ok(actual_base64 == expected_base64)
        }
        None => Ok(false),
        _ => Ok(false),
    }
}

// Null operator implementations
fn evaluate_null(
    actual: Option<ConditionValue>,
    expected: &ConditionValue,
) -> Result<bool, ConditionError> {
    let expected_bool = expected.as_boolean()?;
    let is_null = actual.is_none();
    Ok(is_null == expected_bool)
}

// Set operator implementations - ForAllValues
fn evaluate_for_all_values_string_equals(
    actual: Option<ConditionValue>,
    expected: &ConditionValue,
) -> Result<bool, ConditionError> {
    match actual {
        Some(ConditionValue::Array(actual_values)) => {
            if actual_values.is_empty() {
                return Ok(true); // Vacuous truth - empty request passes
            }
            let expected_array = expected.as_array()?;
            // All values in actual must match at least one in expected
            Ok(actual_values.iter().all(|actual_val| {
                expected_array
                    .iter()
                    .any(|expected_val| actual_val == expected_val)
            }))
        }
        Some(ConditionValue::String(actual_val)) => {
            // Single value treated as array of one
            let expected_array = expected.as_array()?;
            Ok(expected_array.contains(&actual_val))
        }
        None => Ok(true), // Vacuous truth
        _ => Ok(false),
    }
}

fn evaluate_for_all_values_string_like(
    actual: Option<ConditionValue>,
    expected: &ConditionValue,
) -> Result<bool, ConditionError> {
    match actual {
        Some(ConditionValue::Array(actual_values)) => {
            if actual_values.is_empty() {
                return Ok(true);
            }
            let expected_array = expected.as_array()?;
            Ok(actual_values.iter().all(|actual_val| {
                expected_array
                    .iter()
                    .any(|expected_pattern| matches_wildcard_pattern(actual_val, expected_pattern))
            }))
        }
        Some(ConditionValue::String(actual_val)) => {
            let expected_array = expected.as_array()?;
            Ok(expected_array
                .iter()
                .any(|pattern| matches_wildcard_pattern(&actual_val, pattern)))
        }
        None => Ok(true),
        _ => Ok(false),
    }
}

fn evaluate_for_all_values_arn_equals(
    actual: Option<ConditionValue>,
    expected: &ConditionValue,
) -> Result<bool, ConditionError> {
    evaluate_for_all_values_string_equals(actual, expected)
}

fn evaluate_for_all_values_arn_like(
    actual: Option<ConditionValue>,
    expected: &ConditionValue,
) -> Result<bool, ConditionError> {
    evaluate_for_all_values_string_like(actual, expected)
}

fn evaluate_for_all_values_numeric_less_than(
    actual: Option<ConditionValue>,
    expected: &ConditionValue,
) -> Result<bool, ConditionError> {
    match actual {
        Some(ConditionValue::Array(actual_values)) => {
            if actual_values.is_empty() {
                return Ok(true);
            }
            let expected_num = expected.as_number()?;
            Ok(actual_values.iter().all(|actual_str| {
                if let Ok(actual_num) = actual_str.parse::<f64>() {
                    actual_num < expected_num
                } else {
                    false
                }
            }))
        }
        Some(ConditionValue::String(actual_str)) => {
            let actual_num =
                actual_str
                    .parse::<f64>()
                    .map_err(|_| ConditionError::TypeMismatch {
                        expected: "Number".to_string(),
                        actual: "String".to_string(),
                    })?;
            let expected_num = expected.as_number()?;
            Ok(actual_num < expected_num)
        }
        None => Ok(true),
        _ => Ok(false),
    }
}

fn evaluate_for_all_values_numeric_greater_than(
    actual: Option<ConditionValue>,
    expected: &ConditionValue,
) -> Result<bool, ConditionError> {
    match actual {
        Some(ConditionValue::Array(actual_values)) => {
            if actual_values.is_empty() {
                return Ok(true);
            }
            let expected_num = expected.as_number()?;
            Ok(actual_values.iter().all(|actual_str| {
                if let Ok(actual_num) = actual_str.parse::<f64>() {
                    actual_num > expected_num
                } else {
                    false
                }
            }))
        }
        Some(ConditionValue::String(actual_str)) => {
            let actual_num =
                actual_str
                    .parse::<f64>()
                    .map_err(|_| ConditionError::TypeMismatch {
                        expected: "Number".to_string(),
                        actual: "String".to_string(),
                    })?;
            let expected_num = expected.as_number()?;
            Ok(actual_num > expected_num)
        }
        None => Ok(true),
        _ => Ok(false),
    }
}

fn evaluate_for_all_values_ip_address(
    actual: Option<ConditionValue>,
    expected: &ConditionValue,
) -> Result<bool, ConditionError> {
    match actual {
        Some(ConditionValue::Array(actual_ips)) => {
            if actual_ips.is_empty() {
                return Ok(true);
            }
            let expected_array = expected.as_array()?;
            Ok(actual_ips.iter().all(|actual_ip| {
                expected_array
                    .iter()
                    .any(|expected_cidr| ip_matches_cidr(actual_ip, expected_cidr))
            }))
        }
        Some(ConditionValue::String(actual_ip)) => {
            let expected_array = expected.as_array()?;
            Ok(expected_array
                .iter()
                .any(|cidr| ip_matches_cidr(&actual_ip, cidr)))
        }
        None => Ok(true),
        _ => Ok(false),
    }
}

fn evaluate_for_all_values_date_less_than(
    actual: Option<ConditionValue>,
    expected: &ConditionValue,
) -> Result<bool, ConditionError> {
    match actual {
        Some(ConditionValue::Array(actual_dates)) => {
            if actual_dates.is_empty() {
                return Ok(true);
            }
            let expected_time = parse_rfc3339(&expected.as_string()?)?;
            Ok(actual_dates.iter().all(|actual_date_str| {
                parse_rfc3339(actual_date_str)
                    .map(|actual_time| actual_time < expected_time)
                    .unwrap_or(false)
            }))
        }
        Some(ConditionValue::String(actual_date_str)) => {
            let actual_time = parse_rfc3339(&actual_date_str)?;
            let expected_time = parse_rfc3339(&expected.as_string()?)?;
            Ok(actual_time < expected_time)
        }
        None => Ok(true),
        _ => Ok(false),
    }
}

fn evaluate_for_all_values_date_greater_than(
    actual: Option<ConditionValue>,
    expected: &ConditionValue,
) -> Result<bool, ConditionError> {
    match actual {
        Some(ConditionValue::Array(actual_dates)) => {
            if actual_dates.is_empty() {
                return Ok(true);
            }
            let expected_time = parse_rfc3339(&expected.as_string()?)?;
            Ok(actual_dates.iter().all(|actual_date_str| {
                parse_rfc3339(actual_date_str)
                    .map(|actual_time| actual_time > expected_time)
                    .unwrap_or(false)
            }))
        }
        Some(ConditionValue::String(actual_date_str)) => {
            let actual_time = parse_rfc3339(&actual_date_str)?;
            let expected_time = parse_rfc3339(&expected.as_string()?)?;
            Ok(actual_time > expected_time)
        }
        None => Ok(true),
        _ => Ok(false),
    }
}

// Set operator implementations - ForAnyValue
fn evaluate_for_any_value_string_equals(
    actual: Option<ConditionValue>,
    expected: &ConditionValue,
) -> Result<bool, ConditionError> {
    match actual {
        Some(ConditionValue::Array(actual_values)) => {
            if actual_values.is_empty() {
                return Ok(false); // Empty request = no values match
            }
            let expected_array = expected.as_array()?;
            // At least one value in actual must match at least one in expected
            Ok(actual_values.iter().any(|actual_val| {
                expected_array
                    .iter()
                    .any(|expected_val| actual_val == expected_val)
            }))
        }
        Some(ConditionValue::String(actual_val)) => {
            let expected_array = expected.as_array()?;
            Ok(expected_array.contains(&actual_val))
        }
        None => Ok(false), // No value to match
        _ => Ok(false),
    }
}

fn evaluate_for_any_value_string_like(
    actual: Option<ConditionValue>,
    expected: &ConditionValue,
) -> Result<bool, ConditionError> {
    match actual {
        Some(ConditionValue::Array(actual_values)) => {
            if actual_values.is_empty() {
                return Ok(false);
            }
            let expected_array = expected.as_array()?;
            Ok(actual_values.iter().any(|actual_val| {
                expected_array
                    .iter()
                    .any(|expected_pattern| matches_wildcard_pattern(actual_val, expected_pattern))
            }))
        }
        Some(ConditionValue::String(actual_val)) => {
            let expected_array = expected.as_array()?;
            Ok(expected_array
                .iter()
                .any(|pattern| matches_wildcard_pattern(&actual_val, pattern)))
        }
        None => Ok(false),
        _ => Ok(false),
    }
}

fn evaluate_for_any_value_arn_equals(
    actual: Option<ConditionValue>,
    expected: &ConditionValue,
) -> Result<bool, ConditionError> {
    evaluate_for_any_value_string_equals(actual, expected)
}

fn evaluate_for_any_value_arn_like(
    actual: Option<ConditionValue>,
    expected: &ConditionValue,
) -> Result<bool, ConditionError> {
    evaluate_for_any_value_string_like(actual, expected)
}

fn evaluate_for_any_value_numeric_less_than(
    actual: Option<ConditionValue>,
    expected: &ConditionValue,
) -> Result<bool, ConditionError> {
    match actual {
        Some(ConditionValue::Array(actual_values)) => {
            if actual_values.is_empty() {
                return Ok(false);
            }
            let expected_num = expected.as_number()?;
            Ok(actual_values.iter().any(|actual_str| {
                if let Ok(actual_num) = actual_str.parse::<f64>() {
                    actual_num < expected_num
                } else {
                    false
                }
            }))
        }
        Some(ConditionValue::String(actual_str)) => {
            let actual_num =
                actual_str
                    .parse::<f64>()
                    .map_err(|_| ConditionError::TypeMismatch {
                        expected: "Number".to_string(),
                        actual: "String".to_string(),
                    })?;
            let expected_num = expected.as_number()?;
            Ok(actual_num < expected_num)
        }
        None => Ok(false),
        _ => Ok(false),
    }
}

fn evaluate_for_any_value_numeric_greater_than(
    actual: Option<ConditionValue>,
    expected: &ConditionValue,
) -> Result<bool, ConditionError> {
    match actual {
        Some(ConditionValue::Array(actual_values)) => {
            if actual_values.is_empty() {
                return Ok(false);
            }
            let expected_num = expected.as_number()?;
            Ok(actual_values.iter().any(|actual_str| {
                if let Ok(actual_num) = actual_str.parse::<f64>() {
                    actual_num > expected_num
                } else {
                    false
                }
            }))
        }
        Some(ConditionValue::String(actual_str)) => {
            let actual_num =
                actual_str
                    .parse::<f64>()
                    .map_err(|_| ConditionError::TypeMismatch {
                        expected: "Number".to_string(),
                        actual: "String".to_string(),
                    })?;
            let expected_num = expected.as_number()?;
            Ok(actual_num > expected_num)
        }
        None => Ok(false),
        _ => Ok(false),
    }
}

fn evaluate_for_any_value_ip_address(
    actual: Option<ConditionValue>,
    expected: &ConditionValue,
) -> Result<bool, ConditionError> {
    match actual {
        Some(ConditionValue::Array(actual_ips)) => {
            if actual_ips.is_empty() {
                return Ok(false);
            }
            let expected_array = expected.as_array()?;
            Ok(actual_ips.iter().any(|actual_ip| {
                expected_array
                    .iter()
                    .any(|expected_cidr| ip_matches_cidr(actual_ip, expected_cidr))
            }))
        }
        Some(ConditionValue::String(actual_ip)) => {
            let expected_array = expected.as_array()?;
            Ok(expected_array
                .iter()
                .any(|cidr| ip_matches_cidr(&actual_ip, cidr)))
        }
        None => Ok(false),
        _ => Ok(false),
    }
}

fn evaluate_for_any_value_date_less_than(
    actual: Option<ConditionValue>,
    expected: &ConditionValue,
) -> Result<bool, ConditionError> {
    match actual {
        Some(ConditionValue::Array(actual_dates)) => {
            if actual_dates.is_empty() {
                return Ok(false);
            }
            let expected_time = parse_rfc3339(&expected.as_string()?)?;
            Ok(actual_dates.iter().any(|actual_date_str| {
                parse_rfc3339(actual_date_str)
                    .map(|actual_time| actual_time < expected_time)
                    .unwrap_or(false)
            }))
        }
        Some(ConditionValue::String(actual_date_str)) => {
            let actual_time = parse_rfc3339(&actual_date_str)?;
            let expected_time = parse_rfc3339(&expected.as_string()?)?;
            Ok(actual_time < expected_time)
        }
        None => Ok(false),
        _ => Ok(false),
    }
}

fn evaluate_for_any_value_date_greater_than(
    actual: Option<ConditionValue>,
    expected: &ConditionValue,
) -> Result<bool, ConditionError> {
    match actual {
        Some(ConditionValue::Array(actual_dates)) => {
            if actual_dates.is_empty() {
                return Ok(false);
            }
            let expected_time = parse_rfc3339(&expected.as_string()?)?;
            Ok(actual_dates.iter().any(|actual_date_str| {
                parse_rfc3339(actual_date_str)
                    .map(|actual_time| actual_time > expected_time)
                    .unwrap_or(false)
            }))
        }
        Some(ConditionValue::String(actual_date_str)) => {
            let actual_time = parse_rfc3339(&actual_date_str)?;
            let expected_time = parse_rfc3339(&expected.as_string()?)?;
            Ok(actual_time > expected_time)
        }
        None => Ok(false),
        _ => Ok(false),
    }
}
