//! What each operator can read, checked when a condition is parsed.
//!
//! A value an operator cannot read used to reach evaluation, fail there, and be
//! answered `false` — so a `Deny` carrying it stopped applying and any `Allow`
//! in reach won. Refusing it here makes the refusal deterministic: it happens
//! whatever the request, before any context is consulted.
//!
//! Every accepted form is derived from the evaluator in [`crate::operators`],
//! so that parse refuses exactly what evaluation could not have read:
//!
//! | shape | evaluator | accepted |
//! | --- | --- | --- |
//! | text | `ConditionValue::as_string` | a string, number or boolean |
//! | number | `ConditionValue::as_number` | a number, or a string that parses as `f64` |
//! | date | `parse_rfc3339` over `as_string` | an RFC 3339 string |
//! | boolean | `ConditionValue::as_boolean` | `true`/`false`, as JSON or as a string |
//! | address | `ip_matches_cidr` | an IPv4/IPv6 address, or one with a prefix (≤ 32 / ≤ 128) |
//!
//! A list is accepted only where the evaluator reads one: the `IpAddress`
//! family (`String` or `Array`), and the string, ARN and address forms of
//! `ForAllValues`/`ForAnyValue`, which read nothing but a list (`as_array`).
//! A list element must be a string, because `ConditionValue::from` keeps only
//! the strings of a JSON array and drops the rest without a word.

use std::net::Ipv6Addr;

use serde_json::Value;

use crate::operators::{parse_ipv4, parse_rfc3339};
use crate::{ConditionError, ConditionOperator};

/// The kind of value an operator compares against.
#[derive(Clone, Copy)]
enum Kind {
    Text,
    Number,
    Date,
    Boolean,
    Address,
}

/// How many values an operator reads.
#[derive(Clone, Copy)]
enum Arity {
    /// One value; a list is refused (its evaluator cannot read one).
    One,
    /// One value or a list of them.
    OneOrList,
    /// A list only (its evaluator calls `as_array`).
    List,
}

fn shape(operator: ConditionOperator) -> (Kind, Arity) {
    use ConditionOperator as O;
    match operator {
        O::StringEquals
        | O::StringNotEquals
        | O::StringLike
        | O::StringNotLike
        | O::StringEqualsIgnoreCase
        | O::StringNotEqualsIgnoreCase
        | O::StringEqualsIfExists
        | O::StringNotEqualsIfExists
        | O::StringLikeIfExists
        | O::StringNotLikeIfExists
        | O::ArnEquals
        | O::ArnNotEquals
        | O::ArnLike
        | O::ArnNotLike
        | O::ArnEqualsIfExists
        | O::ArnNotEqualsIfExists
        | O::ArnLikeIfExists
        | O::ArnNotLikeIfExists
        | O::BinaryEquals
        | O::BinaryEqualsIfExists => (Kind::Text, Arity::One),
        O::NumericEquals
        | O::NumericNotEquals
        | O::NumericLessThan
        | O::NumericLessThanEquals
        | O::NumericGreaterThan
        | O::NumericGreaterThanEquals
        | O::NumericEqualsIfExists
        | O::NumericNotEqualsIfExists
        | O::NumericLessThanIfExists
        | O::NumericLessThanEqualsIfExists
        | O::NumericGreaterThanIfExists
        | O::NumericGreaterThanEqualsIfExists
        | O::ForAllValuesNumericLessThan
        | O::ForAllValuesNumericGreaterThan
        | O::ForAnyValueNumericLessThan
        | O::ForAnyValueNumericGreaterThan => (Kind::Number, Arity::One),
        O::DateEquals
        | O::DateNotEquals
        | O::DateLessThan
        | O::DateLessThanEquals
        | O::DateGreaterThan
        | O::DateGreaterThanEquals
        | O::DateEqualsIfExists
        | O::DateNotEqualsIfExists
        | O::DateLessThanIfExists
        | O::DateLessThanEqualsIfExists
        | O::DateGreaterThanIfExists
        | O::DateGreaterThanEqualsIfExists
        | O::ForAllValuesDateLessThan
        | O::ForAllValuesDateGreaterThan
        | O::ForAnyValueDateLessThan
        | O::ForAnyValueDateGreaterThan => (Kind::Date, Arity::One),
        O::Bool | O::BoolIfExists | O::Null | O::NullIfExists => (Kind::Boolean, Arity::One),
        O::IpAddress | O::NotIpAddress | O::IpAddressIfExists | O::NotIpAddressIfExists => {
            (Kind::Address, Arity::OneOrList)
        }
        O::ForAllValuesIpAddress | O::ForAnyValueIpAddress => (Kind::Address, Arity::List),
        O::ForAllValuesStringEquals
        | O::ForAllValuesStringNotEquals
        | O::ForAllValuesStringLike
        | O::ForAllValuesStringNotLike
        | O::ForAllValuesArnEquals
        | O::ForAllValuesArnLike
        | O::ForAnyValueStringEquals
        | O::ForAnyValueStringNotEquals
        | O::ForAnyValueStringLike
        | O::ForAnyValueStringNotLike
        | O::ForAnyValueArnEquals
        | O::ForAnyValueArnLike => (Kind::Text, Arity::List),
    }
}

impl Kind {
    fn describe(self) -> &'static str {
        match self {
            Kind::Text => "a string, number or boolean",
            Kind::Number => "a number",
            Kind::Date => "an RFC 3339 date",
            Kind::Boolean => "true or false",
            Kind::Address => "an IP address or CIDR",
        }
    }

    /// Whether `value` is one the evaluator for this kind can read.
    ///
    /// `in_list` narrows every kind to strings: a JSON array is converted by
    /// keeping its strings only, so anything else would vanish.
    fn accepts(self, value: &Value, in_list: bool) -> bool {
        if in_list && !value.is_string() {
            return false;
        }
        match (self, value) {
            (Kind::Text, Value::String(_) | Value::Number(_) | Value::Bool(_)) => true,
            (Kind::Number, Value::Number(_)) => true,
            (Kind::Number, Value::String(s)) => s.parse::<f64>().is_ok(),
            (Kind::Date, Value::String(s)) => parse_rfc3339(s).is_ok(),
            (Kind::Boolean, Value::Bool(_)) => true,
            (Kind::Boolean, Value::String(s)) => s == "true" || s == "false",
            (Kind::Address, Value::String(s)) => is_address_or_cidr(s),
            _ => false,
        }
    }
}

/// What `ip_matches_cidr` can ever match: an address alone, or a network with
/// a prefix it does not ignore (a v4 prefix above 32 never matches anything).
fn is_address_or_cidr(s: &str) -> bool {
    let is_v4 = |a: &str| parse_ipv4(a).is_some();
    let is_v6 = |a: &str| a.parse::<Ipv6Addr>().is_ok();
    match s.split_once('/') {
        None => is_v4(s) || is_v6(s),
        Some((network, prefix)) => match prefix.parse::<u8>() {
            Ok(p) if is_v4(network) => p <= 32,
            Ok(p) if is_v6(network) => p <= 128,
            _ => false,
        },
    }
}

/// Refuse a value `operator` could not read, naming the operator, the key and,
/// for a list, the element — never the value itself.
pub(crate) fn check_value(
    operator_name: &str,
    operator: ConditionOperator,
    key: &str,
    value: &Value,
) -> Result<(), ConditionError> {
    let (kind, arity) = shape(operator);
    let refuse = |position: Option<usize>, expected: String| {
        Err(ConditionError::InvalidConditionValue {
            operator: operator_name.to_string(),
            key: key.to_string(),
            position,
            expected,
        })
    };
    match (value, arity) {
        (Value::Array(_), Arity::One) => refuse(
            None,
            format!(
                "{} — a list is not accepted by {operator_name} (wami 002 will read it as OR)",
                kind.describe()
            ),
        ),
        (Value::Array(items), Arity::OneOrList | Arity::List) => {
            match items.iter().position(|item| !kind.accepts(item, true)) {
                Some(index) => refuse(Some(index), format!("{} as a string", kind.describe())),
                None => Ok(()),
            }
        }
        (_, Arity::List) => refuse(
            None,
            format!(
                "a list of {} — {operator_name} reads only a list",
                kind.describe()
            ),
        ),
        (_, Arity::One | Arity::OneOrList) if kind.accepts(value, false) => Ok(()),
        _ => refuse(None, kind.describe().to_string()),
    }
}
