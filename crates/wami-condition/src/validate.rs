//! What each operator can read, checked when a condition is parsed.
//!
//! A value an operator cannot read used to reach evaluation, fail there, and be
//! answered `false` — so a `Deny` carrying it stopped applying and any `Allow`
//! in reach won. Refusing it here makes the refusal deterministic: it happens
//! whatever the request, before any context is consulted.
//!
//! Two checks, both against what evaluation does:
//!
//! - **the key**: an operator compares one type of key — a string operator
//!   cannot compare the Boolean `aws:SecureTransport`, a numeric one a key
//!   nobody declared (it is compared as a string). The declared types are
//!   `keys::key_type`, the same table `get_context_value` reads from.
//! - **the value**: read through the evaluator's OWN parsers — never a copy of
//!   them, so the two cannot drift apart:
//!
//! | shape | parser called | accepted |
//! | --- | --- | --- |
//! | text | `ConditionValue::as_string` | a string, number or boolean |
//! | number | `ConditionValue::as_number` | a finite number, or a string that reads as one |
//! | date | `parse_rfc3339` over `as_string` | an RFC 3339 string |
//! | boolean | `ConditionValue::as_boolean` | `true`/`false`, as JSON or as a string |
//! | address | `operators::check_ip_or_cidr` | an IPv4/IPv6 address, or one with a prefix (≤ 32 / ≤ 128) |
//!
//! A list is accepted only where the evaluator reads one: the `IpAddress`
//! family (`String` or `Array`), and the string and ARN forms of
//! `ForAllValues`/`ForAnyValue`, which read nothing but a list (`as_array`).
//! Their numeric, date and address forms are refused outright: no key holds
//! a list of those (`without_key`).
//! An empty list is refused there (`NotIpAddress []` was always true). A list
//! element must be a string, because `ConditionValue::from` keeps only the
//! strings of a JSON array and drops the rest without a word.

use serde_json::Value;

use crate::keys::{key_type, KeyType};
use crate::operators::{check_ip_or_cidr, parse_rfc3339};
use crate::{ConditionError, ConditionOperator, ConditionValue};

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
            Kind::Number => "a finite number",
            Kind::Date => "an RFC 3339 date",
            Kind::Boolean => "true or false",
            Kind::Address => "an IP address or CIDR",
        }
    }

    /// Whether `value` is one the evaluator for this kind can read — asked
    /// of the evaluator's own parsers.
    ///
    /// `in_list` narrows every kind to strings: a JSON array is converted by
    /// keeping its strings only, so anything else would vanish. A null or an
    /// object is no value anybody wrote: `ConditionValue::from` would turn it
    /// into `""` without a word.
    fn accepts(self, value: &Value, in_list: bool) -> bool {
        if (in_list && !value.is_string()) || value.is_null() || value.is_object() {
            return false;
        }
        let value = ConditionValue::from(value.clone());
        match self {
            Kind::Text => value.as_string().is_ok(),
            Kind::Number => value.as_number().is_ok(),
            Kind::Date => value
                .as_string()
                .and_then(|s| parse_rfc3339(&s).map(|_| ()))
                .is_ok(),
            Kind::Boolean => value.as_boolean().is_ok(),
            Kind::Address => value
                .as_string()
                .and_then(|s| check_ip_or_cidr(&s, None))
                .is_ok(),
        }
    }
}

/// Whether `operator` can compare a key of type `key_type` (`None`: a key
/// nobody declared, compared as a string). The `IfExists` forms follow their
/// base operator; `Null` asks only whether the key is there, so it takes any.
fn compares(operator: ConditionOperator, key_type: Option<KeyType>) -> bool {
    use KeyType as K;
    let (kind, arity) = shape(operator);
    let textual = matches!(key_type, None | Some(K::String | K::Arn));
    match (kind, arity) {
        _ if is_null(operator) => true,
        (Kind::Text, Arity::List) => textual || key_type == Some(K::StringList),
        (Kind::Text, _) => textual,
        (Kind::Number, _) => key_type == Some(K::Number),
        (Kind::Date, _) => key_type == Some(K::Date),
        (Kind::Boolean, _) => key_type == Some(K::Boolean),
        (Kind::Address, _) => key_type == Some(K::Ip),
    }
}

/// The set operators no key can feed, by the name a policy writes: they
/// compare a list of numbers, dates or addresses, and the key table has no
/// such list — its one list type, `KeyType::StringList`, holds strings
/// (`aws:TagKeys`). A key of that kind would need a new `KeyType`, which is
/// where this list is revisited.
pub(crate) fn without_key(operator: ConditionOperator) -> Option<&'static str> {
    use ConditionOperator as O;
    Some(match operator {
        O::ForAllValuesNumericLessThan => "ForAllValues:NumericLessThan",
        O::ForAllValuesNumericGreaterThan => "ForAllValues:NumericGreaterThan",
        O::ForAllValuesDateLessThan => "ForAllValues:DateLessThan",
        O::ForAllValuesDateGreaterThan => "ForAllValues:DateGreaterThan",
        O::ForAllValuesIpAddress => "ForAllValues:IpAddress",
        O::ForAnyValueNumericLessThan => "ForAnyValue:NumericLessThan",
        O::ForAnyValueNumericGreaterThan => "ForAnyValue:NumericGreaterThan",
        O::ForAnyValueDateLessThan => "ForAnyValue:DateLessThan",
        O::ForAnyValueDateGreaterThan => "ForAnyValue:DateGreaterThan",
        O::ForAnyValueIpAddress => "ForAnyValue:IpAddress",
        _ => return None,
    })
}

fn is_null(operator: ConditionOperator) -> bool {
    matches!(
        operator,
        ConditionOperator::Null | ConditionOperator::NullIfExists
    )
}

/// Refuse a key `operator` cannot compare, or a value it could not read, naming
/// the operator, the key and, for a list, the element — never the value.
pub(crate) fn check_value(
    operator_name: &str,
    operator: ConditionOperator,
    key: &str,
    value: &Value,
) -> Result<(), ConditionError> {
    if let Some(name) = without_key(operator) {
        return Err(ConditionError::OperatorWithoutKey {
            operator: name.to_string(),
        });
    }
    let declared = key_type(key);
    if !compares(operator, declared) {
        return Err(ConditionError::OperatorKeyMismatch {
            operator: operator_name.to_string(),
            key: key.to_string(),
            key_type: declared.map_or_else(
                || "not a declared key, so compared as a string".to_string(),
                |t| format!("{} key", t.describe()),
            ),
        });
    }
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
        (Value::Array(items), Arity::OneOrList | Arity::List) if items.is_empty() => refuse(
            None,
            format!("at least one {} — an empty list", kind.describe()),
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
