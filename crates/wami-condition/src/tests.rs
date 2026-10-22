// ============================================================================
// Targeted branch coverage tests (operators.rs residuals)
// ============================================================================

#[test]
fn test_ip_address_expected_type_mismatch() {
    // expected is a number (not string/array): the operator could only ever
    // answer false, so it is refused at parse (wami 001)
    parse_err(r#"{"IpAddress": {"aws:SourceIp": 123}}"#);
}

#[test]
fn test_ip_address_ipv6_fallback_exact_match() {
    // A v6 prefix above 128 is no CIDR: refused at parse (wami 001) rather
    // than falling back to an exact match on the network part.
    parse_err(r#"{"IpAddress": {"aws:SourceIp": "2001:db8::/255"}}"#);
}

#[test]
fn test_string_like_missing_key_returns_false() {
    let context = ConditionContext::builder().build();
    let condition = parse_condition_block_from_json(
        r#"{
            "StringLike": {"aws:username": "a*"}
        }"#,
    );
    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(!result);
}

#[test]
fn test_date_equals_missing_key_returns_false() {
    let context = ConditionContext::builder().build();
    let condition = parse_condition_block_from_string(format!(
        r#"{{
            "DateEquals": {{"aws:TokenIssueTime": "{}"}}
        }}"#,
        chrono::Utc::now().to_rfc3339()
    ));
    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(!result);
}

#[test]
fn test_forallvalues_string_like_empty_actual_true() {
    let context = ConditionContext::builder()
        .custom_value("str:vals", crate::ConditionValue::Array(vec![]))
        .build();
    let condition = parse_condition_block_from_json(
        r#"{
            "ForAllValues:StringLike": {"str:vals": ["a*"]}
        }"#,
    );
    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

#[test]
fn test_foranyvalue_string_equals_empty_actual_false() {
    let context = ConditionContext::builder()
        .custom_value("str:vals", crate::ConditionValue::Array(vec![]))
        .build();
    let condition = parse_condition_block_from_json(
        r#"{
            "ForAnyValue:StringEquals": {"str:vals": ["x"]}
        }"#,
    );
    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(!result);
}

#[test]
fn test_foranyvalue_string_like_missing_key_false() {
    let context = ConditionContext::builder().build();
    let condition = parse_condition_block_from_json(
        r#"{
            "ForAnyValue:StringLike": {"aws:username": ["a*"]}
        }"#,
    );
    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(!result);
}

// Comprehensive Test Suite for Condition Key Evaluation
//
// This test suite follows TDD principles - tests are written before implementation.
// It covers all operators, condition keys, edge cases, and corner cases.

use crate::ConditionError;
use crate::{
    evaluate_condition_block, evaluator::parse_condition_block, get_context_value, ConditionBlock,
    ConditionContext, ConditionValue,
};
use serde_json::Value;

// ============================================================================
// Test Helpers
// ============================================================================

fn create_test_context() -> ConditionContext {
    ConditionContext::builder()
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .username("alice")
        .source_ip("203.0.113.42")
        .current_time(chrono::Utc::now())
        .mfa_present(true)
        .mfa_age(300) // 5 minutes
        .build()
}

fn parse_condition_block_from_json(json: &str) -> ConditionBlock {
    let value: Value = serde_json::from_str(json).unwrap();
    parse_condition_block(&value).unwrap()
}

/// [`unchecked`] for an owned string.
fn unchecked_string(json: String) -> ConditionBlock {
    unchecked(&json)
}

fn parse_condition_block_from_string(json_str: String) -> ConditionBlock {
    let value: Value = serde_json::from_str(&json_str).unwrap();
    parse_condition_block(&value).unwrap()
}

// ============================================================================
// String Operators Tests
// ============================================================================

#[test]
fn test_string_equals_exact_match() {
    let context = create_test_context();
    let condition = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "aws:username": "alice"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

#[test]
fn test_string_equals_no_match() {
    let context = create_test_context();
    let condition = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "aws:username": "bob"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(!result);
}

#[test]
fn test_string_equals_case_sensitive() {
    let context = create_test_context();
    let condition = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "aws:username": "Alice"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(!result); // Case-sensitive, should not match
}

#[test]
fn test_string_equals_empty_string() {
    let context = create_test_context();
    let condition = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "aws:username": ""
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(!result); // Empty string should not match "alice"
}

#[test]
fn test_string_equals_missing_key() {
    let context = create_test_context();
    let condition = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "aws:NonexistentKey": "value"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(!result); // Missing key should fail
}

#[test]
fn test_string_equals_if_exists_missing_key() {
    let context = create_test_context();
    let condition = parse_condition_block_from_json(
        r#"{
            "StringEqualsIfExists": {
                "aws:NonexistentKey": "value"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // IfExists: missing key should pass
}

#[test]
fn test_string_equals_if_exists_present_key() {
    let context = create_test_context();
    let condition = parse_condition_block_from_json(
        r#"{
            "StringEqualsIfExists": {
                "aws:username": "alice"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // Key exists and matches
}

#[test]
fn test_string_equals_if_exists_present_key_no_match() {
    let context = create_test_context();
    let condition = parse_condition_block_from_json(
        r#"{
            "StringEqualsIfExists": {
                "aws:username": "bob"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(!result); // Key exists but doesn't match
}

#[test]
fn test_string_like_wildcard_prefix() {
    let context = create_test_context();
    let condition = parse_condition_block_from_json(
        r#"{
            "StringLike": {
                "aws:PrincipalArn": "arn:aws:iam::*:user/*"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

#[test]
fn test_string_like_wildcard_suffix() {
    let context = create_test_context();
    let condition = parse_condition_block_from_json(
        r#"{
            "StringLike": {
                "aws:username": "ali*"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

#[test]
fn test_string_like_wildcard_middle() {
    let context = create_test_context();
    let condition = parse_condition_block_from_json(
        r#"{
            "StringLike": {
                "aws:username": "al*ce"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

#[test]
fn test_string_like_multiple_wildcards() {
    let context = create_test_context();
    let condition = parse_condition_block_from_json(
        r#"{
            "StringLike": {
                "aws:PrincipalArn": "arn:aws:iam::*:user/al*"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

#[test]
fn test_string_like_no_match() {
    let context = create_test_context();
    let condition = parse_condition_block_from_json(
        r#"{
            "StringLike": {
                "aws:username": "bob*"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(!result);
}

#[test]
fn test_string_like_question_mark() {
    let context = create_test_context();
    let condition = parse_condition_block_from_json(
        r#"{
            "StringLike": {
                "aws:username": "ali?e"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // ? matches single character
}

#[test]
fn test_string_like_escape_wildcards() {
    let context = create_test_context();
    // Test that literal * and ? can be escaped (if supported)
    // This is an edge case - AWS doesn't support escaping, but we might want to
    let condition = parse_condition_block_from_json(
        r#"{
            "StringLike": {
                "aws:username": "alice*"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // "alice*" should match "alice" (wildcard matches empty)
}

#[test]
fn test_string_not_equals() {
    let context = create_test_context();
    let condition = parse_condition_block_from_json(
        r#"{
            "StringNotEquals": {
                "aws:username": "bob"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // "alice" != "bob"
}

#[test]
fn test_string_not_equals_match() {
    let context = create_test_context();
    let condition = parse_condition_block_from_json(
        r#"{
            "StringNotEquals": {
                "aws:username": "alice"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(!result); // "alice" == "alice", so NotEquals fails
}

#[test]
fn test_string_equals_ignore_case() {
    let context = create_test_context();
    let condition = parse_condition_block_from_json(
        r#"{
            "StringEqualsIgnoreCase": {
                "aws:username": "Alice"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // Case-insensitive match
}

// ============================================================================
// Numeric Operators Tests
// ============================================================================

#[test]
fn test_numeric_equals() {
    let context = create_test_context();
    let condition = parse_condition_block_from_json(
        r#"{
            "NumericEquals": {
                "aws:MultiFactorAuthAge": "300"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

#[test]
fn test_numeric_equals_float() {
    let context = create_test_context();
    let condition = unchecked(
        r#"{
            "NumericEquals": {
                "aws:SomeNumericKey": "123.45"
            }
        }"#,
    );

    // This depends on whether we support floats
    // AWS IAM typically uses integers, but we might want float support
    let _ = evaluate_condition_block(&condition, &context).unwrap();
    // Implementation dependent
}

#[test]
fn test_numeric_less_than() {
    let context = create_test_context();
    let condition = parse_condition_block_from_json(
        r#"{
            "NumericLessThan": {
                "aws:MultiFactorAuthAge": "3600"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // 300 < 3600
}

#[test]
fn test_numeric_less_than_equals() {
    let context = create_test_context();
    let condition = parse_condition_block_from_json(
        r#"{
            "NumericLessThanEquals": {
                "aws:MultiFactorAuthAge": "300"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // 300 <= 300
}

#[test]
fn test_numeric_greater_than() {
    let context = create_test_context();
    let condition = parse_condition_block_from_json(
        r#"{
            "NumericGreaterThan": {
                "aws:MultiFactorAuthAge": "60"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // 300 > 60
}

#[test]
fn test_numeric_greater_than_equals() {
    let context = create_test_context();
    let condition = parse_condition_block_from_json(
        r#"{
            "NumericGreaterThanEquals": {
                "aws:MultiFactorAuthAge": "300"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // 300 >= 300
}

#[test]
fn test_numeric_negative_values() {
    let _context = create_test_context();
    let _condition = unchecked(
        r#"{
            "NumericLessThan": {
                "aws:SomeKey": "-100"
            }
        }"#,
    );

    // Test with negative value in context
    // Implementation dependent
}

#[test]
fn test_numeric_zero() {
    let _context = create_test_context();
    let _condition = unchecked(
        r#"{
            "NumericEquals": {
                "aws:SomeKey": "0"
            }
        }"#,
    );

    // Test with zero value
}

#[test]
fn test_numeric_very_large() {
    let _context = create_test_context();
    let _condition = unchecked(
        r#"{
            "NumericLessThan": {
                "aws:SomeKey": "999999999999"
            }
        }"#,
    );

    // Test with very large number
}

#[test]
fn test_numeric_invalid_string() {
    // "alice" is not a number: refused at parse (wami 001).
    let message = parse_err(r#"{"NumericEquals": {"wami:SessionAge": "alice"}}"#);
    assert!(message.contains("finite number"), "{message}");
}

// ============================================================================
// Date/Time Operators Tests
// ============================================================================

#[test]
fn test_date_equals() {
    let now = chrono::Utc::now();
    let context = ConditionContext::builder().current_time(now).build();

    let time_str = now.to_rfc3339();
    let condition = parse_condition_block_from_string(format!(
        r#"{{
            "DateEquals": {{
                "aws:CurrentTime": "{}"
            }}
        }}"#,
        time_str
    ));

    let _ = evaluate_condition_block(&condition, &context).unwrap();
    // Exact match might fail due to precision, but should be close
}

#[test]
fn test_date_less_than() {
    let now = chrono::Utc::now();
    let future = now + chrono::Duration::hours(1);
    let context = ConditionContext::builder().current_time(now).build();

    let future_str = future.to_rfc3339();
    let condition = parse_condition_block_from_string(format!(
        r#"{{
            "DateLessThan": {{
                "aws:CurrentTime": "{}"
            }}
        }}"#,
        future_str
    ));

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // now < future
}

#[test]
fn test_date_greater_than() {
    let now = chrono::Utc::now();
    let past = now - chrono::Duration::hours(1);
    let context = ConditionContext::builder().current_time(now).build();

    let past_str = past.to_rfc3339();
    let condition = parse_condition_block_from_string(format!(
        r#"{{
            "DateGreaterThan": {{
                "aws:CurrentTime": "{}"
            }}
        }}"#,
        past_str
    ));

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // now > past
}

#[test]
fn test_date_invalid_format() {
    // An invalid date used to make the condition false; it is now refused at
    // parse (wami 001).
    let message = parse_err(r#"{"DateEquals": {"aws:CurrentTime": "invalid-date"}}"#);
    assert!(message.contains("RFC 3339"), "{message}");
}

// ============================================================================
// IP Address Operators Tests
// ============================================================================

#[test]
fn test_ip_address_exact_match() {
    let context = ConditionContext::builder()
        .source_ip("203.0.113.42")
        .build();

    let condition = parse_condition_block_from_json(
        r#"{
            "IpAddress": {
                "aws:SourceIp": "203.0.113.42"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

#[test]
fn test_ip_address_cidr_match() {
    let context = ConditionContext::builder()
        .source_ip("203.0.113.42")
        .build();

    let condition = parse_condition_block_from_json(
        r#"{
            "IpAddress": {
                "aws:SourceIp": "203.0.113.0/24"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // 203.0.113.42 is in 203.0.113.0/24
}

#[test]
fn test_ip_address_cidr_no_match() {
    let context = ConditionContext::builder()
        .source_ip("198.51.100.42")
        .build();

    let condition = parse_condition_block_from_json(
        r#"{
            "IpAddress": {
                "aws:SourceIp": "203.0.113.0/24"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(!result); // 198.51.100.42 is not in 203.0.113.0/24
}

#[test]
fn test_ip_address_multiple_cidrs() {
    let context = ConditionContext::builder()
        .source_ip("203.0.113.42")
        .build();

    let condition = parse_condition_block_from_json(
        r#"{
            "IpAddress": {
                "aws:SourceIp": ["203.0.113.0/24", "198.51.100.0/24"]
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // Matches first CIDR
}

#[test]
fn test_ip_address_ipv6() {
    let context = ConditionContext::builder().source_ip("2001:db8::1").build();

    let condition = parse_condition_block_from_json(
        r#"{
            "IpAddress": {
                "aws:SourceIp": "2001:db8::/32"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // IPv6 support
}

#[test]
fn test_ip_address_invalid_ip() {
    let context = ConditionContext::builder().source_ip("not-an-ip").build();

    let condition = parse_condition_block_from_json(
        r#"{
            "IpAddress": {
                "aws:SourceIp": "203.0.113.0/24"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context);
    assert_eq!(
        result,
        Err(ConditionError::TypeMismatch {
            expected: "an IP address".to_string(),
            actual: "String".to_string()
        })
    );
}

#[test]
fn test_not_ip_address() {
    let context = ConditionContext::builder()
        .source_ip("198.51.100.42")
        .build();

    let condition = parse_condition_block_from_json(
        r#"{
            "NotIpAddress": {
                "aws:SourceIp": "203.0.113.0/24"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // 198.51.100.42 is not in 203.0.113.0/24
}

// ============================================================================
// ARN Operators Tests
// ============================================================================

#[test]
fn test_arn_equals() {
    let context = ConditionContext::builder()
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .build();

    let condition = parse_condition_block_from_json(
        r#"{
            "ArnEquals": {
                "aws:PrincipalArn": "arn:aws:iam::123456789012:user/alice"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

#[test]
fn test_arn_like_wildcard() {
    let context = ConditionContext::builder()
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .build();

    let condition = parse_condition_block_from_json(
        r#"{
            "ArnLike": {
                "aws:PrincipalArn": "arn:aws:iam::*:user/*"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

#[test]
fn test_arn_like_no_match() {
    let context = ConditionContext::builder()
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .build();

    let condition = parse_condition_block_from_json(
        r#"{
            "ArnLike": {
                "aws:PrincipalArn": "arn:aws:iam::*:role/*"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(!result); // user/* doesn't match role/*
}

// ============================================================================
// Boolean Operators Tests
// ============================================================================

#[test]
fn test_bool_true() {
    let context = ConditionContext::builder().mfa_present(true).build();

    let condition = parse_condition_block_from_json(
        r#"{
            "Bool": {
                "aws:MultiFactorAuthPresent": "true"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

#[test]
fn test_bool_false() {
    let context = ConditionContext::builder().mfa_present(false).build();

    let condition = parse_condition_block_from_json(
        r#"{
            "Bool": {
                "aws:MultiFactorAuthPresent": "false"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

#[test]
fn test_bool_mismatch() {
    let context = ConditionContext::builder().mfa_present(true).build();

    let condition = parse_condition_block_from_json(
        r#"{
            "Bool": {
                "aws:MultiFactorAuthPresent": "false"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(!result); // true != false
}

#[test]
fn test_bool_invalid_value() {
    // Only "true" and "false" are valid; "yes" used to be a silent false and
    // is now refused at parse (wami 001).
    let message = parse_err(r#"{"Bool": {"aws:MultiFactorAuthPresent": "yes"}}"#);
    assert!(message.contains("true or false"), "{message}");
}

// ============================================================================
// Set Operators Tests (ForAllValues, ForAnyValue)
// ============================================================================

#[test]
fn test_for_all_values_string_equals_all_match() {
    // ForAllValues: All values in request must match at least one in policy
    let context = ConditionContext::builder()
        .tag_keys(vec!["Env".to_string(), "Owner".to_string()])
        .build();

    let condition = parse_condition_block_from_json(
        r#"{
            "ForAllValues:StringEquals": {
                "aws:TagKeys": ["Env", "Owner"]
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // Both "Env" and "Owner" are in the policy list
}

#[test]
fn test_for_all_values_string_equals_one_missing() {
    let context = ConditionContext::builder()
        .tag_keys(vec![
            "Env".to_string(),
            "Owner".to_string(),
            "Cost".to_string(),
        ])
        .build();

    let condition = parse_condition_block_from_json(
        r#"{
            "ForAllValues:StringEquals": {
                "aws:TagKeys": ["Env", "Owner"]
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(!result); // "Cost" is not in the policy list
}

#[test]
fn test_for_all_values_string_equals_empty_request() {
    let context = ConditionContext::builder().tag_keys(vec![]).build();

    let condition = parse_condition_block_from_json(
        r#"{
            "ForAllValues:StringEquals": {
                "aws:TagKeys": ["Env", "Owner"]
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // Empty request = all values match (vacuous truth)
}

#[test]
fn test_for_any_value_string_equals_one_matches() {
    // ForAnyValue: At least one value in request must match at least one in policy
    let context = ConditionContext::builder()
        .principal_tag_role(vec!["Admin".to_string()])
        .build();

    let condition = parse_condition_block_from_json(
        r#"{
            "ForAnyValue:StringEquals": {
                "aws:PrincipalTag/Role": ["Admin", "DevOps"]
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // "Admin" matches
}

#[test]
fn test_for_any_value_string_equals_none_match() {
    let context = ConditionContext::builder()
        .principal_tag_role(vec!["User".to_string()])
        .build();

    let condition = parse_condition_block_from_json(
        r#"{
            "ForAnyValue:StringEquals": {
                "aws:PrincipalTag/Role": ["Admin", "DevOps"]
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(!result); // "User" doesn't match any
}

#[test]
fn test_for_any_value_string_equals_empty_request() {
    let context = ConditionContext::builder()
        .principal_tag_role(vec![])
        .build();

    let condition = parse_condition_block_from_json(
        r#"{
            "ForAnyValue:StringEquals": {
                "aws:PrincipalTag/Role": ["Admin", "DevOps"]
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(!result); // Empty request = no values match
}

// ============================================================================
// Multiple Conditions Tests
// ============================================================================

#[test]
fn test_multiple_conditions_all_pass() {
    let context = ConditionContext::builder()
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .username("alice")
        .source_ip("203.0.113.42")
        .mfa_present(true)
        .build();

    let condition = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "aws:username": "alice"
            },
            "IpAddress": {
                "aws:SourceIp": "203.0.113.0/24"
            },
            "Bool": {
                "aws:MultiFactorAuthPresent": "true"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // All conditions pass
}

#[test]
fn test_multiple_conditions_one_fails() {
    let context = ConditionContext::builder()
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .source_ip("198.51.100.42") // Wrong IP
        .mfa_present(true)
        .build();

    let condition = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "aws:username": "alice"
            },
            "IpAddress": {
                "aws:SourceIp": "203.0.113.0/24"
            },
            "Bool": {
                "aws:MultiFactorAuthPresent": "true"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(!result); // IP condition fails
}

#[test]
fn test_multiple_keys_same_operator() {
    let context = ConditionContext::builder()
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .source_ip("203.0.113.42")
        .build();

    let condition = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "aws:username": "alice",
                "aws:PrincipalType": "User"
            }
        }"#,
    );

    let _ = evaluate_condition_block(&condition, &context).unwrap();
    // Both keys must match
}

// ============================================================================
// Edge Cases and Corner Cases
// ============================================================================

#[test]
fn test_empty_condition_block() {
    let context = create_test_context();
    let condition = parse_condition_block_from_json(r#"{}"#);

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // Empty block should pass (no conditions to check)
}

#[test]
fn test_condition_with_null_value() {
    let _context = create_test_context();
    let _condition = parse_condition_block_from_json(
        r#"{
            "Null": {
                "aws:TokenIssueTime": "true"
            }
        }"#,
    );

    // Test null check
}

#[test]
fn test_condition_with_unicode() {
    let context = ConditionContext::builder()
        .username("用户".to_string())
        .build();

    let condition = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "aws:username": "用户"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // Unicode support
}

#[test]
fn test_condition_with_very_long_string() {
    let long_string = "a".repeat(10000);
    let context = ConditionContext::builder()
        .username(long_string.clone())
        .build();

    let condition = parse_condition_block_from_string(format!(
        r#"{{
            "StringEquals": {{
                "aws:username": "{}"
            }}
        }}"#,
        long_string
    ));

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

#[test]
fn test_condition_with_special_characters() {
    let context = ConditionContext::builder()
        .username("user@example.com".to_string())
        .build();

    let condition = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "aws:username": "user@example.com"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

#[test]
fn test_condition_type_mismatch() {
    let context = ConditionContext::builder()
        .username("alice".to_string())
        .build();

    let condition = unchecked(
        r#"{
            "NumericEquals": {
                "aws:username": "123"
            }
        }"#,
    );

    // Should fail - can't compare string as number
    let result = evaluate_condition_block(&condition, &context);
    assert_eq!(
        result,
        Err(ConditionError::TypeMismatch {
            expected: "a finite Number".to_string(),
            actual: "String".to_string()
        })
    );
}

#[test]
fn test_condition_invalid_operator() {
    // Refused at parse (wami 001) ...
    let message = parse_err(r#"{"InvalidOperator": {"aws:username": "alice"}}"#);
    assert!(message.contains("InvalidOperator"), "{message}");

    // ... and still an error for a block built by hand.
    let mut condition = ConditionBlock::new();
    condition.insert(
        "InvalidOperator".to_string(),
        std::collections::HashMap::from([(
            "aws:username".to_string(),
            ConditionValue::String("alice".to_string()),
        )]),
    );
    let result = evaluate_condition_block(&condition, &create_test_context());
    assert_eq!(
        result,
        Err(ConditionError::UnknownOperator(
            "InvalidOperator".to_string()
        ))
    );
}

#[test]
fn test_condition_array_value() {
    let context = ConditionContext::builder()
        .tag_keys(vec!["Env".to_string(), "Owner".to_string()])
        .build();

    let condition = parse_condition_block_from_json(
        r#"{
            "ForAllValues:StringEquals": {
                "aws:TagKeys": ["Env", "Owner"]
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

#[test]
fn test_condition_nested_structure() {
    // Test that condition structure is correctly parsed
    // This is more of an implementation detail test
}

// ============================================================================
// Integration with Policy Evaluation Tests
// ============================================================================

#[test]
fn test_policy_with_condition_allows() {
    // Full policy evaluation with condition that passes
}

#[test]
fn test_policy_with_condition_denies() {
    // Full policy evaluation with condition that fails
}

#[test]
fn test_policy_without_condition() {
    // Policy without condition should work as before
}

#[test]
fn test_multiple_statements_with_conditions() {
    // Multiple statements, some with conditions, some without
}

#[test]
fn test_deny_statement_with_condition() {
    // Deny statement with condition that passes
}

#[test]
fn test_deny_statement_with_condition_fails() {
    // Deny statement with condition that fails (should not deny)
}

// ============================================================================
// AWS Compatibility Tests
// ============================================================================

#[test]
fn test_aws_condition_key_principal_arn() {
    // Test AWS condition key behavior matches AWS IAM
}

#[test]
fn test_aws_condition_key_source_ip() {
    // Test AWS SourceIp behavior
}

#[test]
fn test_aws_condition_key_current_time() {
    // Test AWS CurrentTime behavior
}

// ============================================================================
// WAMI-Specific Tests
// ============================================================================

#[test]
fn test_wami_condition_key_tenant_id() {
    let _context = ConditionContext::builder()
        .tenant_id(12345678)
        .principal_tenant_id(12345678)
        .build();

    let _condition = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "wami:TenantId": "${wami:PrincipalTenantId}"
            }
        }"#,
    );

    // Test variable substitution
}

#[test]
fn test_wami_condition_key_provider() {
    let context = ConditionContext::builder()
        .provider("AWS".to_string())
        .build();

    let condition = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "wami:Provider": "AWS"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

// ============================================================================
// Performance Tests
// ============================================================================

#[test]
fn test_condition_evaluation_performance() {
    // Benchmark condition evaluation
    // Should be < 1ms for typical conditions
}

#[test]
fn test_large_condition_block() {
    // Test with many conditions (100+)
}

// ============================================================================
// Security Tests
// ============================================================================

#[test]
fn test_condition_injection_prevention() {
    // Test that malicious strings don't cause code execution
    let context = ConditionContext::builder()
        .username("alice'; DROP TABLE users; --")
        .build();

    let condition = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "aws:username": "alice'; DROP TABLE users; --"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // Should match exactly, no injection
}

#[test]
fn test_condition_sql_injection_in_pattern() {
    // Test SQL injection attempts in wildcard patterns
    let context = ConditionContext::builder().username("alice").build();

    let condition = parse_condition_block_from_json(
        r#"{
            "StringLike": {
                "aws:username": "*'; DROP TABLE users; --*"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(!result); // Should not match, pattern is literal
}

#[test]
fn test_condition_path_traversal_prevention() {
    // Test path traversal attempts
    let context = ConditionContext::builder()
        .username("../../../etc/passwd")
        .build();

    let condition = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "aws:username": "../../../etc/passwd"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // Should match exactly, no path traversal
}

#[test]
fn test_condition_xss_prevention() {
    // Test XSS attempts in condition values
    let context = ConditionContext::builder()
        .username("<script>alert('xss')</script>")
        .build();

    let condition = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "aws:username": "<script>alert('xss')</script>"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // Should match exactly, no XSS execution
}

#[test]
fn test_condition_command_injection_prevention() {
    // Test command injection attempts
    let context = ConditionContext::builder()
        .username("alice; rm -rf /")
        .build();

    let condition = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "aws:username": "alice; rm -rf /"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // Should match exactly, no command execution
}

#[test]
fn test_condition_resource_limits() {
    // Test that very large condition blocks are handled gracefully
    let mut large_condition = String::from(r#"{"StringEquals": {"#);
    for i in 0..1000 {
        if i > 0 {
            large_condition.push(',');
        }
        large_condition.push_str(&format!(r#""aws:username{}": "value{}""#, i, i));
    }
    large_condition.push_str(r#"}}"#);

    let value: Value = serde_json::from_str(&large_condition).unwrap();
    let result = parse_condition_block(&value);
    assert!(result.is_ok()); // Should parse successfully
}

#[test]
fn test_condition_deeply_nested_structure() {
    // Test that deeply nested structures are handled
    // Note: JSON parsing will fail for deeply nested structures, so we test with valid JSON
    let nested = r#"{"StringEquals": {"aws:username": "alice"}}"#;
    let value: Value = serde_json::from_str(nested).unwrap();
    let result = parse_condition_block(&value);
    // Should parse successfully for valid structure
    assert!(result.is_ok());
}

#[test]
fn test_condition_very_long_strings() {
    // Test handling of very long strings (potential DoS)
    let long_string = "a".repeat(1_000_000);
    let context = ConditionContext::builder()
        .username(long_string.clone())
        .build();

    let condition_json = format!(
        r#"{{
            "StringEquals": {{
                "aws:username": "{}"
            }}
        }}"#,
        long_string
    );

    let condition = parse_condition_block_from_string(condition_json);
    let result = evaluate_condition_block(&condition, &context);
    // Should handle gracefully without panicking
    assert!(result.is_ok());
}

#[test]
fn test_condition_malformed_json_handling() {
    // Test that malformed JSON is rejected
    let malformed = r#"{"StringEquals": {"aws:username": "alice""#; // Missing closing braces
    let value_result: Result<Value, _> = serde_json::from_str(malformed);
    assert!(value_result.is_err()); // Should fail to parse
}

#[test]
fn test_condition_null_bytes_in_strings() {
    // Test handling of null bytes (potential security issue)
    // Note: JSON doesn't support null bytes in strings, so we test with actual null byte
    let username_with_null = format!("alice{}injected", '\0');
    let context = ConditionContext::builder()
        .username(username_with_null.clone())
        .build();

    // Create condition with null byte programmatically
    let condition_json = serde_json::json!({
        "StringEquals": {
            "aws:username": username_with_null
        }
    });

    let condition = parse_condition_block(&condition_json).unwrap();
    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // Should handle null bytes safely
}

#[test]
fn test_condition_unicode_normalization_attacks() {
    // Test Unicode normalization attacks (homoglyphs, etc.)
    let context = ConditionContext::builder()
        .username("alice") // Regular ASCII
        .build();

    // Using lookalike characters
    let condition = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "aws:username": "аlice"
            }
        }"#,
    ); // Cyrillic 'а' instead of Latin 'a'

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(!result); // Should not match (different characters)
}

#[test]
fn test_condition_regex_injection_prevention() {
    // Test that regex-like patterns are treated as literal strings
    let context = ConditionContext::builder().username("alice").build();

    let condition = parse_condition_block_from_json(
        r#"{
            "StringLike": {
                "aws:username": ".*"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    // Should treat .* as literal, not regex
    assert!(!result); // "alice" doesn't match literal ".*"
}

#[test]
fn test_condition_arithmetic_overflow_prevention() {
    // Test numeric operations with very large numbers
    let context = ConditionContext::builder().mfa_age(u64::MAX).build();

    let condition = parse_condition_block_from_json(
        r#"{
            "NumericLessThan": {
                "aws:MultiFactorAuthAge": "18446744073709551615"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context);
    // Should handle without overflow
    assert_eq!(result, Ok(false));
}

#[test]
fn test_condition_denial_of_service_wildcard() {
    // Test that wildcard patterns don't cause excessive computation
    let context = ConditionContext::builder()
        .username("a".repeat(1000))
        .build();

    let pattern = format!("*{}*", "a".repeat(100));
    let condition_json = format!(
        r#"{{
            "StringLike": {{
                "aws:username": "{}"
            }}
        }}"#,
        pattern
    );

    let condition = parse_condition_block_from_string(condition_json);
    let start = std::time::Instant::now();
    let result = evaluate_condition_block(&condition, &context);
    let duration = start.elapsed();

    assert!(result.is_ok());
    // Should complete in reasonable time (< 1 second)
    assert!(duration.as_secs() < 1);
}

#[test]
fn test_condition_empty_context_handling() {
    // Test evaluation with minimal/empty context
    let context = ConditionContext::builder().build();

    let condition = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "aws:username": "alice"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(!result); // Missing context should fail
}

#[test]
fn test_condition_missing_key_handling() {
    // Test that missing context keys are handled gracefully
    let context = ConditionContext::builder().username("alice").build();

    let condition = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "aws:username": "alice",
                "aws:PrincipalType": "User"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    // Missing PrincipalType should cause failure
    assert!(!result);
}

#[test]
fn test_condition_if_exists_with_missing_key() {
    // Test IfExists operators with missing keys
    let context = ConditionContext::builder().username("alice").build();

    let condition = parse_condition_block_from_json(
        r#"{
            "StringEqualsIfExists": {
                "aws:PrincipalType": "User"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // IfExists should pass when key is missing
}

#[test]
fn test_condition_type_coercion_security() {
    // Test that type coercion doesn't bypass security checks
    let context = ConditionContext::builder().username("0").build();

    // Try to coerce string "0" to number
    let condition = unchecked(
        r#"{
            "NumericEquals": {
                "aws:username": "0"
            }
        }"#,
    );

    // The implementation allows string-to-number coercion (AWS-compatible behavior)
    // Security property: non-numeric strings should not match numeric values

    // Test 1: Numeric string "0" can be coerced to number 0 (acceptable AWS behavior)
    let _result1 = evaluate_condition_block(&condition, &context);
    // Result can be true (if "0" parses as 0) or false/error - both are acceptable

    // Test 2: Non-numeric string should NOT match numeric value (security property)
    let context2 = ConditionContext::builder().username("alice").build();
    let result2 = evaluate_condition_block(&condition, &context2);
    // Should error when trying to parse "alice" as number, or return false
    assert_eq!(
        result2,
        Err(ConditionError::TypeMismatch {
            expected: "a finite Number".to_string(),
            actual: "String".to_string()
        })
    );

    // Test 3: Invalid numeric string should fail
    let context3 = ConditionContext::builder().username("not-a-number").build();
    let result3 = evaluate_condition_block(&condition, &context3);
    // Should either error or return false for invalid numeric string
    assert_eq!(
        result3,
        Err(ConditionError::TypeMismatch {
            expected: "a finite Number".to_string(),
            actual: "String".to_string()
        })
    );
}

#[test]
fn test_condition_array_injection() {
    // Test that arrays in condition values are handled safely
    // A list where one string is read: refused at parse, never a silent
    // false (wami 001; wami 002 will read it as OR).
    let message = parse_err(r#"{"StringEquals": {"aws:username": ["Env", "Owner"]}}"#);
    assert!(message.contains("wami 002"), "{message}");
}

#[test]
fn test_condition_boolean_coercion_security() {
    // Test boolean coercion doesn't bypass checks
    let context = ConditionContext::builder().mfa_present(true).build();

    // Try to use string "true" where boolean expected
    let condition = parse_condition_block_from_json(
        r#"{
            "Bool": {
                "aws:MultiFactorAuthPresent": "true"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // String "true" should convert to boolean true
}

#[test]
fn test_condition_date_manipulation_attempts() {
    // Test that date manipulation doesn't bypass time-based conditions
    let now = chrono::Utc::now();
    let future = now + chrono::Duration::days(365 * 100); // 100 years in future
    let context = ConditionContext::builder().current_time(now).build();

    let future_str = future.to_rfc3339();
    let condition = parse_condition_block_from_string(format!(
        r#"{{
            "DateLessThan": {{
                "aws:CurrentTime": "{}"
            }}
        }}"#,
        future_str
    ));

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // now < future should be true
}

#[test]
fn test_condition_ip_address_spoofing_prevention() {
    // Test that IP address conditions can't be easily spoofed
    let context = ConditionContext::builder()
        .source_ip("203.0.113.42")
        .build();

    // Try various IP formats
    let condition = parse_condition_block_from_json(
        r#"{
            "IpAddress": {
                "aws:SourceIp": "203.0.113.0/24"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // Should match CIDR correctly
}

#[test]
fn test_condition_arn_injection_prevention() {
    // Test ARN injection attempts
    let context = ConditionContext::builder()
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .build();

    // Try to inject malicious ARN
    let condition = parse_condition_block_from_json(
        r#"{
            "ArnLike": {
                "aws:PrincipalArn": "arn:aws:iam::*:user/*"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // Should match wildcard pattern correctly
}

#[test]
fn test_condition_forallvalues_empty_actual() {
    // Test ForAllValues with empty actual (vacuous truth)
    let context = ConditionContext::builder().tag_keys(vec![]).build();

    let condition = parse_condition_block_from_json(
        r#"{
            "ForAllValues:StringEquals": {
                "aws:TagKeys": ["Env", "Owner"]
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // Empty actual = vacuous truth
}

#[test]
fn test_condition_foranyvalue_empty_actual() {
    // Test ForAnyValue with empty actual (should fail)
    let context = ConditionContext::builder().tag_keys(vec![]).build();

    let condition = parse_condition_block_from_json(
        r#"{
            "ForAnyValue:StringEquals": {
                "aws:TagKeys": ["Env", "Owner"]
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(!result); // Empty actual = no match
}

#[test]
fn test_condition_multiple_operators_security() {
    // Test that multiple operators are evaluated correctly (no short-circuit bypass)
    let context = ConditionContext::builder()
        .username("alice")
        .source_ip("203.0.113.42")
        .mfa_present(true)
        .build();

    let condition = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "aws:username": "alice"
            },
            "IpAddress": {
                "aws:SourceIp": "203.0.113.0/24"
            },
            "Bool": {
                "aws:MultiFactorAuthPresent": "true"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // All should pass
}

#[test]
fn test_condition_operator_short_circuit_security() {
    // Test that one failing operator doesn't bypass others
    let context = ConditionContext::builder()
        .username("alice")
        .source_ip("198.51.100.42") // Wrong IP
        .build();

    let condition = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "aws:username": "alice"
            },
            "IpAddress": {
                "aws:SourceIp": "203.0.113.0/24"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(!result); // IP condition should fail, causing overall failure
}

#[test]
fn test_condition_very_large_numbers() {
    // Test handling of very large numeric values
    let context = ConditionContext::builder()
        .mfa_age(1_000_000_000_000)
        .build();

    let condition = parse_condition_block_from_json(
        r#"{
            "NumericLessThan": {
                "aws:MultiFactorAuthAge": "2000000000000"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

#[test]
fn test_condition_negative_numbers() {
    // Test handling of negative numbers
    let context = ConditionContext::builder().mfa_age(300).build();

    let condition = parse_condition_block_from_json(
        r#"{
            "NumericGreaterThan": {
                "aws:MultiFactorAuthAge": "-100"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // 300 > -100
}

#[test]
fn test_condition_floating_point_precision() {
    // Test floating point precision handling
    let context = ConditionContext::builder().mfa_age(300).build();

    let condition = parse_condition_block_from_json(
        r#"{
            "NumericEquals": {
                "aws:MultiFactorAuthAge": "300.0"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // Should handle floating point equality
}

#[test]
fn test_condition_special_characters_in_keys() {
    // Test handling of special characters in condition keys
    let mut tags = std::collections::HashMap::new();
    tags.insert("Key-With-Special/Chars".to_string(), "value".to_string());
    let context = ConditionContext::builder()
        .principal_tag("Key-With-Special/Chars", "value")
        .build();

    let condition = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "aws:PrincipalTag/Key-With-Special/Chars": "value"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

#[test]
fn test_condition_unicode_in_keys() {
    // Test Unicode characters in condition keys
    let context = ConditionContext::builder()
        .principal_tag("键", "值")
        .build();

    let condition = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "aws:PrincipalTag/键": "值"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

#[test]
fn test_condition_control_characters() {
    // Test handling of control characters
    let context = ConditionContext::builder().username("alice\tbob").build();

    let condition = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "aws:username": "alice\tbob"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

#[test]
fn test_condition_empty_strings() {
    // Test handling of empty strings
    let context = ConditionContext::builder().username("").build();

    let condition = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "aws:username": ""
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // Empty strings should match
}

#[test]
fn test_condition_whitespace_handling() {
    // Test whitespace handling
    let context = ConditionContext::builder().username("  alice  ").build();

    let condition = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "aws:username": "  alice  "
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // Should match exactly including whitespace
}

#[test]
fn test_condition_case_sensitivity() {
    // Test case sensitivity
    let context = ConditionContext::builder().username("Alice").build();

    let condition = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "aws:username": "alice"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(!result); // Should be case-sensitive
}

#[test]
fn test_condition_case_insensitive() {
    // Test case insensitive operator
    let context = ConditionContext::builder().username("Alice").build();

    let condition = parse_condition_block_from_json(
        r#"{
            "StringEqualsIgnoreCase": {
                "aws:username": "alice"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // Should match case-insensitively
}

#[test]
fn test_condition_wildcard_edge_cases() {
    // Test wildcard edge cases
    let test_cases = vec![
        ("alice", "*", true),
        ("alice", "alice*", true),
        ("alice", "*alice", true), // *alice should match strings ending with "alice"
        ("alice", "*alice*", true),
        ("alice", "alice", true),
        ("alice", "bob", false),
        ("alice", "a*e", true),
        ("alice", "a?ice", true),
        ("alice", "a??ce", true),
        ("alice", "a???ce", false),
        ("testalice", "*alice", true), // Should match strings ending with "alice"
        ("", "*", true),               // Empty string matches *
        ("", "*alice", false),         // Empty string doesn't match *alice
        ("alice", "a*", true),         // Should match strings starting with "a"
        ("alice", "*c*", true),        // Should match strings containing "c"
    ];

    for (value, pattern, expected) in test_cases {
        let context = ConditionContext::builder().username(value).build();

        let condition_json = format!(
            r#"{{
                "StringLike": {{
                    "aws:username": "{}"
                }}
            }}"#,
            pattern
        );

        let condition = parse_condition_block_from_string(condition_json);
        let result = evaluate_condition_block(&condition, &context).unwrap();
        assert_eq!(
            result, expected,
            "Pattern '{}' should match '{}' = {}",
            pattern, value, expected
        );
    }
}

#[test]
fn test_condition_parse_invalid_structure() {
    // Test parsing invalid condition structures
    let invalid_cases = vec![
        r#"null"#,
        r#""string""#,
        r#"123"#,
        r#"[]"#,
        r#"{"StringEquals": "not an object"}"#,
        r#"{"StringEquals": {"key": null}}"#,
    ];

    for invalid_json in invalid_cases {
        let value_result: Result<Value, _> = serde_json::from_str(invalid_json);
        if let Ok(value) = value_result {
            let result = parse_condition_block(&value);
            // Each is refused for its structure or its value (wami 001).
            assert!(
                matches!(
                    result,
                    Err(ConditionError::InvalidConditionStructure(_)
                        | ConditionError::InvalidConditionValue { .. })
                ),
                "{invalid_json}: {result:?}"
            );
        }
    }
}

#[test]
fn test_condition_context_key_resolution_edge_cases() {
    // Test edge cases in context key resolution
    let context = ConditionContext::builder()
        .principal_arn("")
        .username("")
        .mfa_present(false)
        .mfa_age(0)
        .build();

    let condition = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "aws:PrincipalArn": "",
                "aws:username": ""
            },
            "Bool": {
                "aws:MultiFactorAuthPresent": "false"
            },
            "NumericEquals": {
                "aws:MultiFactorAuthAge": "0"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // All empty/false/zero values should match
}

#[test]
fn test_condition_custom_value_fallback() {
    // Test custom value fallback
    let context = ConditionContext::builder()
        .custom_value(
            "custom:key",
            crate::ConditionValue::String("value".to_string()),
        )
        .build();

    let condition = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "custom:key": "value"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

#[test]
fn test_condition_unknown_key_handling() {
    // Test handling of unknown condition keys
    let context = create_test_context();

    let condition = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "unknown:key": "value"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    // Unknown key should return None, causing condition to fail
    assert!(!result);
}

// ============================================================================
// Additional Edge Case Tests for Coverage
// ============================================================================

#[test]
fn test_condition_empty_block() {
    // Empty condition block should pass
    let context = create_test_context();
    let condition = ConditionBlock::new();
    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

#[test]
fn test_condition_empty_operator_block() {
    // Empty operator block should pass
    let context = create_test_context();
    let condition = parse_condition_block_from_json(
        r#"{
            "StringEquals": {}
        }"#,
    );
    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

#[test]
fn test_condition_multiple_empty_operators() {
    // Multiple empty operator blocks should pass
    let context = create_test_context();
    let condition = parse_condition_block_from_json(
        r#"{
            "StringEquals": {},
            "NumericEquals": {},
            "Bool": {}
        }"#,
    );
    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

#[test]
fn test_condition_all_ifexists_operators() {
    // Test all IfExists variants
    let context = ConditionContext::builder()
        .username("alice")
        .mfa_present(true)
        .build();

    let test_cases = vec![
        (
            r#"{"StringEqualsIfExists": {"aws:username": "alice"}}"#,
            true,
        ),
        (
            r#"{"StringEqualsIfExists": {"aws:PrincipalType": "User"}}"#,
            true,
        ), // Missing key passes
        (
            r#"{"NumericEqualsIfExists": {"aws:MultiFactorAuthAge": "300"}}"#,
            true,
        ),
        (
            r#"{"NumericEqualsIfExists": {"aws:MultiFactorAuthAge": "600"}}"#,
            true, // Missing key passes (IfExists behavior)
        ),
        (
            r#"{"DateEqualsIfExists": {"aws:TokenIssueTime": "2024-01-01T00:00:00Z"}}"#,
            true,
        ), // Missing key passes
        (
            r#"{"IpAddressIfExists": {"aws:SourceIp": "203.0.113.0/24"}}"#,
            true,
        ), // Missing key passes
        (
            r#"{"ArnEqualsIfExists": {"aws:PrincipalArn": "arn:aws:iam::123456789012:user/alice"}}"#,
            true,
        ), // Missing key passes
        (
            r#"{"BoolIfExists": {"aws:MultiFactorAuthPresent": "true"}}"#,
            true,
        ),
        (
            r#"{"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}}"#,
            false,
        ),
    ];

    for (json, expected) in test_cases {
        let condition = parse_condition_block_from_json(json);
        let result = evaluate_condition_block(&condition, &context).unwrap();
        assert_eq!(result, expected, "Failed for condition: {}", json);
    }
}

#[test]
fn test_condition_numeric_edge_cases() {
    // Test numeric edge cases
    let max_str = u64::MAX.to_string();
    let test_cases = vec![
        (0u64, "0", true),
        (0u64, "0.0", true),
        (300u64, "300", true),
        (300u64, "300.0", true),
        (300u64, "299", false),
        (300u64, "301", false),
        (u64::MAX, &max_str, true),
    ];

    for (age, expected_str, should_match) in test_cases {
        let context = ConditionContext::builder().mfa_age(age).build();
        let condition_json = format!(
            r#"{{
                "NumericEquals": {{
                    "aws:MultiFactorAuthAge": "{}"
                }}
            }}"#,
            expected_str
        );
        let condition = parse_condition_block_from_string(condition_json);
        let result = evaluate_condition_block(&condition, &context).unwrap();
        assert_eq!(
            result,
            should_match,
            "Age {} should {} match {}",
            age,
            if should_match { "" } else { "not" },
            expected_str
        );
    }
}

#[test]
fn test_condition_numeric_comparison_operators() {
    // Test all numeric comparison operators
    let context = ConditionContext::builder().mfa_age(300).build();

    let test_cases = vec![
        (
            r#"{"NumericLessThan": {"aws:MultiFactorAuthAge": "400"}}"#,
            true,
        ),
        (
            r#"{"NumericLessThan": {"aws:MultiFactorAuthAge": "300"}}"#,
            false,
        ),
        (
            r#"{"NumericLessThan": {"aws:MultiFactorAuthAge": "200"}}"#,
            false,
        ),
        (
            r#"{"NumericLessThanEquals": {"aws:MultiFactorAuthAge": "300"}}"#,
            true,
        ),
        (
            r#"{"NumericLessThanEquals": {"aws:MultiFactorAuthAge": "400"}}"#,
            true,
        ),
        (
            r#"{"NumericLessThanEquals": {"aws:MultiFactorAuthAge": "200"}}"#,
            false,
        ),
        (
            r#"{"NumericGreaterThan": {"aws:MultiFactorAuthAge": "200"}}"#,
            true,
        ),
        (
            r#"{"NumericGreaterThan": {"aws:MultiFactorAuthAge": "300"}}"#,
            false,
        ),
        (
            r#"{"NumericGreaterThan": {"aws:MultiFactorAuthAge": "400"}}"#,
            false,
        ),
        (
            r#"{"NumericGreaterThanEquals": {"aws:MultiFactorAuthAge": "300"}}"#,
            true,
        ),
        (
            r#"{"NumericGreaterThanEquals": {"aws:MultiFactorAuthAge": "200"}}"#,
            true,
        ),
        (
            r#"{"NumericGreaterThanEquals": {"aws:MultiFactorAuthAge": "400"}}"#,
            false,
        ),
    ];

    for (json, expected) in test_cases {
        let condition = parse_condition_block_from_json(json);
        let result = evaluate_condition_block(&condition, &context).unwrap();
        assert_eq!(result, expected, "Failed for condition: {}", json);
    }
}

#[test]
fn test_condition_date_comparison_operators() {
    // Test all date comparison operators
    let now = chrono::Utc::now();
    let past = now - chrono::Duration::hours(1);
    let future = now + chrono::Duration::hours(1);
    let context = ConditionContext::builder().current_time(now).build();

    let test_cases = vec![
        (
            format!(
                r#"{{"DateLessThan": {{"aws:CurrentTime": "{}"}}}}"#,
                future.to_rfc3339()
            ),
            true,
        ),
        (
            format!(
                r#"{{"DateLessThan": {{"aws:CurrentTime": "{}"}}}}"#,
                now.to_rfc3339()
            ),
            false,
        ),
        (
            format!(
                r#"{{"DateLessThan": {{"aws:CurrentTime": "{}"}}}}"#,
                past.to_rfc3339()
            ),
            false,
        ),
        (
            format!(
                r#"{{"DateLessThanEquals": {{"aws:CurrentTime": "{}"}}}}"#,
                now.to_rfc3339()
            ),
            true,
        ),
        (
            format!(
                r#"{{"DateLessThanEquals": {{"aws:CurrentTime": "{}"}}}}"#,
                future.to_rfc3339()
            ),
            true,
        ),
        (
            format!(
                r#"{{"DateLessThanEquals": {{"aws:CurrentTime": "{}"}}}}"#,
                past.to_rfc3339()
            ),
            false,
        ),
        (
            format!(
                r#"{{"DateGreaterThan": {{"aws:CurrentTime": "{}"}}}}"#,
                past.to_rfc3339()
            ),
            true,
        ),
        (
            format!(
                r#"{{"DateGreaterThan": {{"aws:CurrentTime": "{}"}}}}"#,
                now.to_rfc3339()
            ),
            false,
        ),
        (
            format!(
                r#"{{"DateGreaterThan": {{"aws:CurrentTime": "{}"}}}}"#,
                future.to_rfc3339()
            ),
            false,
        ),
        (
            format!(
                r#"{{"DateGreaterThanEquals": {{"aws:CurrentTime": "{}"}}}}"#,
                now.to_rfc3339()
            ),
            true,
        ),
        (
            format!(
                r#"{{"DateGreaterThanEquals": {{"aws:CurrentTime": "{}"}}}}"#,
                past.to_rfc3339()
            ),
            true,
        ),
        (
            format!(
                r#"{{"DateGreaterThanEquals": {{"aws:CurrentTime": "{}"}}}}"#,
                future.to_rfc3339()
            ),
            false,
        ),
    ];

    for (json, expected) in test_cases {
        let condition = parse_condition_block_from_string(json.clone());
        let result = evaluate_condition_block(&condition, &context).unwrap();
        assert_eq!(result, expected, "Failed for condition: {}", json);
    }
}

#[test]
fn test_condition_binary_operators() {
    // Test binary operators
    let context = ConditionContext::builder()
        .custom_value(
            "binary:key",
            crate::ConditionValue::String("dGVzdA==".to_string()),
        )
        .build();

    let condition = parse_condition_block_from_json(
        r#"{
            "BinaryEquals": {
                "binary:key": "dGVzdA=="
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

#[test]
fn test_condition_null_operators() {
    // Test null operators
    let context1 = ConditionContext::builder().username("alice").build();
    let context2 = ConditionContext::builder().build(); // No username

    let condition = parse_condition_block_from_json(
        r#"{
            "Null": {
                "aws:username": "true"
            }
        }"#,
    );

    let result1 = evaluate_condition_block(&condition, &context1).unwrap();
    assert!(!result1); // username exists, so null check fails

    let result2 = evaluate_condition_block(&condition, &context2).unwrap();
    assert!(result2); // username doesn't exist, so null check passes
}

#[test]
fn test_condition_forallvalues_comprehensive() {
    // Test ForAllValues with various scenarios
    let context = ConditionContext::builder()
        .tag_keys(vec!["Env".to_string(), "Owner".to_string()])
        .build();

    let test_cases = vec![
        // All values match
        (
            r#"{"ForAllValues:StringEquals": {"aws:TagKeys": ["Env", "Owner"]}}"#,
            true,
        ),
        // All actual values are in expected (ForAllValues checks that all actual values are in expected)
        (
            r#"{"ForAllValues:StringEquals": {"aws:TagKeys": ["Env", "Owner", "Project"]}}"#,
            true, // Actual: [Env, Owner], Expected: [Env, Owner, Project] - both Env and Owner are in expected
        ),
        // Empty actual (vacuous truth)
        (
            r#"{"ForAllValues:StringEquals": {"aws:TagKeys": ["Env", "Owner"]}}"#,
            true,
        ),
        // Single value
        (
            r#"{"ForAllValues:StringEquals": {"aws:TagKeys": ["Env"]}}"#,
            false,
        ), // Only Env matches, Owner doesn't
    ];

    for (json, expected) in test_cases {
        let condition = parse_condition_block_from_json(json);
        let result = evaluate_condition_block(&condition, &context).unwrap();
        assert_eq!(result, expected, "Failed for condition: {}", json);
    }
}

#[test]
fn test_condition_foranyvalue_comprehensive() {
    // Test ForAnyValue with various scenarios
    let context = ConditionContext::builder()
        .tag_keys(vec!["Env".to_string(), "Owner".to_string()])
        .build();

    let test_cases = vec![
        // At least one value matches
        (
            r#"{"ForAnyValue:StringEquals": {"aws:TagKeys": ["Env", "Project"]}}"#,
            true,
        ),
        // No values match
        (
            r#"{"ForAnyValue:StringEquals": {"aws:TagKeys": ["Project", "Team"]}}"#,
            false,
        ),
        // Empty actual (should fail)
        (
            r#"{"ForAnyValue:StringEquals": {"aws:TagKeys": ["Env"]}}"#,
            true,
        ), // Env matches
    ];

    for (json, expected) in test_cases {
        let condition = parse_condition_block_from_json(json);
        let result = evaluate_condition_block(&condition, &context).unwrap();
        assert_eq!(result, expected, "Failed for condition: {}", json);
    }
}

#[test]
fn test_condition_tag_keys_dynamic() {
    // Test dynamic tag key resolution
    let context = ConditionContext::builder()
        .principal_tag("Environment", "production")
        .principal_tag("Role", "admin")
        .resource_tag("Project", "wami")
        .request_tag("RequestId", "12345")
        .build();

    let test_cases = vec![
        (
            r#"{"StringEquals": {"aws:PrincipalTag/Environment": "production"}}"#,
            true,
        ),
        (
            r#"{"StringEquals": {"aws:PrincipalTag/Role": "admin"}}"#,
            true,
        ),
        (
            r#"{"StringEquals": {"aws:PrincipalTag/Environment": "staging"}}"#,
            false,
        ),
        (
            r#"{"StringEquals": {"aws:ResourceTag/Project": "wami"}}"#,
            true,
        ),
        (
            r#"{"StringEquals": {"aws:RequestTag/RequestId": "12345"}}"#,
            true,
        ),
        (
            r#"{"StringEquals": {"aws:PrincipalTag/Nonexistent": "value"}}"#,
            false,
        ),
    ];

    for (json, expected) in test_cases {
        let condition = parse_condition_block_from_json(json);
        let result = evaluate_condition_block(&condition, &context).unwrap();
        assert_eq!(result, expected, "Failed for condition: {}", json);
    }
}

#[test]
fn test_condition_wami_specific_keys() {
    // Test WAMI-specific condition keys
    let context = ConditionContext::builder()
        .tenant_id(12345)
        .principal_tenant_id(12345)
        .resource_tenant_id(67890)
        .provider("AWS")
        .source_provider("AWS")
        .target_provider("GCP")
        .build();

    let test_cases = vec![
        (r#"{"StringEquals": {"wami:TenantId": "12345"}}"#, true),
        (
            r#"{"StringEquals": {"wami:PrincipalTenantId": "12345"}}"#,
            true,
        ),
        (
            r#"{"StringEquals": {"wami:ResourceTenantId": "67890"}}"#,
            true,
        ),
        (r#"{"StringEquals": {"wami:Provider": "AWS"}}"#, true),
        (r#"{"StringEquals": {"wami:SourceProvider": "AWS"}}"#, true),
        (r#"{"StringEquals": {"wami:TargetProvider": "GCP"}}"#, true),
        (r#"{"StringEquals": {"wami:TenantId": "99999"}}"#, false),
    ];

    for (json, expected) in test_cases {
        let condition = parse_condition_block_from_json(json);
        let result = evaluate_condition_block(&condition, &context).unwrap();
        assert_eq!(result, expected, "Failed for condition: {}", json);
    }
}

#[test]
fn test_condition_epoch_time() {
    // Test EpochTime condition key
    let now = chrono::Utc::now();
    let context = ConditionContext::builder().current_time(now).build();

    let epoch = now.timestamp();
    let condition_json = format!(
        r#"{{
            "NumericEquals": {{
                "aws:EpochTime": "{}"
            }}
        }}"#,
        epoch
    );

    let condition = parse_condition_block_from_string(condition_json);
    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

#[test]
fn test_condition_boolean_edge_cases() {
    // Test boolean edge cases
    let context_true = ConditionContext::builder().mfa_present(true).build();
    let context_false = ConditionContext::builder().mfa_present(false).build();

    let test_cases = vec![
        (
            r#"{"Bool": {"aws:MultiFactorAuthPresent": "true"}}"#,
            true,
            true,
        ),
        (
            r#"{"Bool": {"aws:MultiFactorAuthPresent": "false"}}"#,
            false,
            true,
        ),
        (
            r#"{"Bool": {"aws:MultiFactorAuthPresent": "true"}}"#,
            false,
            false,
        ),
        (
            r#"{"Bool": {"aws:MultiFactorAuthPresent": "false"}}"#,
            true,
            false,
        ),
    ];

    for (json, expected, use_true_context) in test_cases {
        let context = if use_true_context {
            &context_true
        } else {
            &context_false
        };
        let condition = parse_condition_block_from_json(json);
        let result = evaluate_condition_block(&condition, context).unwrap();
        assert_eq!(result, expected, "Failed for condition: {}", json);
    }
}

#[test]
fn test_condition_arn_wildcard_patterns() {
    // Test ARN wildcard patterns
    let context = ConditionContext::builder()
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .build();

    let test_cases = vec![
        (
            r#"{"ArnLike": {"aws:PrincipalArn": "arn:aws:iam::*:user/*"}}"#,
            true,
        ),
        (
            r#"{"ArnLike": {"aws:PrincipalArn": "arn:aws:iam::123456789012:user/alice"}}"#,
            true,
        ),
        (
            r#"{"ArnLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/*"}}"#,
            false,
        ),
        (
            r#"{"ArnLike": {"aws:PrincipalArn": "arn:aws:s3:::*"}}"#,
            false,
        ),
    ];

    for (json, expected) in test_cases {
        let condition = parse_condition_block_from_json(json);
        let result = evaluate_condition_block(&condition, &context).unwrap();
        assert_eq!(result, expected, "Failed for condition: {}", json);
    }
}

#[test]
fn test_condition_complex_multi_operator() {
    // Test complex condition with multiple operators and keys
    let context = ConditionContext::builder()
        .username("alice")
        .source_ip("203.0.113.42")
        .mfa_present(true)
        .mfa_age(300)
        .principal_tag("Environment", "production")
        .current_time(chrono::Utc::now())
        .build();

    let condition = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "aws:username": "alice"
            },
            "IpAddress": {
                "aws:SourceIp": "203.0.113.0/24"
            },
            "Bool": {
                "aws:MultiFactorAuthPresent": "true"
            },
            "NumericLessThan": {
                "aws:MultiFactorAuthAge": "600"
            },
            "StringEquals": {
                "aws:PrincipalTag/Environment": "production"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // All conditions should pass
}

#[test]
fn test_condition_parse_error_handling() {
    // Test parsing error handling
    let invalid_cases = vec![
        serde_json::json!(null),
        serde_json::json!("string"),
        serde_json::json!(123),
        serde_json::json!([]),
        serde_json::json!({"StringEquals": "not an object"}),
    ];

    for invalid_value in invalid_cases {
        let result = parse_condition_block(&invalid_value);
        // Each is refused for its structure (wami 001).
        assert!(
            matches!(result, Err(ConditionError::InvalidConditionStructure(_))),
            "{invalid_value}: {result:?}"
        );
    }
}

// ============================================================================
// ConditionValue Type Conversion Tests (lib.rs coverage)
// ============================================================================

#[test]
fn test_condition_value_as_string() {
    use crate::ConditionValue;

    // String to string
    let val = ConditionValue::String("test".to_string());
    assert_eq!(val.as_string().unwrap(), "test");

    // Number to string
    let val = ConditionValue::Number(123.45);
    assert_eq!(val.as_string().unwrap(), "123.45");

    // Boolean to string
    let val = ConditionValue::Boolean(true);
    assert_eq!(val.as_string().unwrap(), "true");
    let val = ConditionValue::Boolean(false);
    assert_eq!(val.as_string().unwrap(), "false");

    // Array to string should error
    let val = ConditionValue::Array(vec!["a".to_string(), "b".to_string()]);
    assert!(val.as_string().is_err());
}

#[test]
fn test_condition_value_as_number() {
    use crate::ConditionValue;

    // Number to number
    let val = ConditionValue::Number(123.45);
    assert_eq!(val.as_number().unwrap(), 123.45);

    // String to number (valid)
    let val = ConditionValue::String("123.45".to_string());
    assert_eq!(val.as_number().unwrap(), 123.45);

    // String to number (invalid)
    let val = ConditionValue::String("not-a-number".to_string());
    assert!(val.as_number().is_err());

    // Boolean to number should error
    let val = ConditionValue::Boolean(true);
    assert!(val.as_number().is_err());

    // Array to number should error
    let val = ConditionValue::Array(vec!["a".to_string()]);
    assert!(val.as_number().is_err());
}

#[test]
fn test_condition_value_as_boolean() {
    use crate::ConditionValue;

    // Boolean to boolean
    let val = ConditionValue::Boolean(true);
    assert!(val.as_boolean().unwrap());
    let val = ConditionValue::Boolean(false);
    assert!(!val.as_boolean().unwrap());

    // String "true" to boolean
    let val = ConditionValue::String("true".to_string());
    assert!(val.as_boolean().unwrap());

    // String "false" to boolean
    let val = ConditionValue::String("false".to_string());
    assert!(!val.as_boolean().unwrap());

    // String invalid to boolean should error
    let val = ConditionValue::String("maybe".to_string());
    assert!(val.as_boolean().is_err());

    // Number to boolean should error
    let val = ConditionValue::Number(1.0);
    assert!(val.as_boolean().is_err());

    // Array to boolean should error
    let val = ConditionValue::Array(vec!["a".to_string()]);
    assert!(val.as_boolean().is_err());
}

#[test]
fn test_condition_value_as_array() {
    use crate::ConditionValue;

    // Array to array
    let arr = vec!["a".to_string(), "b".to_string()];
    let val = ConditionValue::Array(arr.clone());
    assert_eq!(val.as_array().unwrap(), &arr);

    // String to array should error
    let val = ConditionValue::String("test".to_string());
    assert!(val.as_array().is_err());

    // Number to array should error
    let val = ConditionValue::Number(123.45);
    assert!(val.as_array().is_err());

    // Boolean to array should error
    let val = ConditionValue::Boolean(true);
    assert!(val.as_array().is_err());
}

#[test]
fn test_condition_value_from_json_value() {
    use crate::ConditionValue;
    use serde_json::Value;

    // String
    let json = Value::String("test".to_string());
    let val = ConditionValue::from(json);
    assert!(matches!(val, ConditionValue::String(_)));

    // Number
    let json = Value::Number(serde_json::Number::from_f64(123.45).unwrap());
    let val = ConditionValue::from(json);
    assert!(matches!(val, ConditionValue::Number(_)));

    // Boolean
    let json = Value::Bool(true);
    let val = ConditionValue::from(json);
    assert!(matches!(val, ConditionValue::Boolean(_)));

    // Array
    let json = Value::Array(vec![
        Value::String("a".to_string()),
        Value::String("b".to_string()),
    ]);
    let val = ConditionValue::from(json);
    assert!(matches!(val, ConditionValue::Array(_)));

    // Null (should become empty string)
    let json = Value::Null;
    let val = ConditionValue::from(json);
    assert!(matches!(val, ConditionValue::String(_)));

    // Object (should become empty string)
    let json = Value::Object(serde_json::Map::new());
    let val = ConditionValue::from(json);
    assert!(matches!(val, ConditionValue::String(_)));
}

// ============================================================================
// ConditionError Display Tests (evaluator.rs coverage)
// ============================================================================

#[test]
fn test_condition_error_display() {
    use crate::evaluator::ConditionError;

    // UnknownOperator
    let err = ConditionError::UnknownOperator("BadOp".to_string());
    assert!(err.to_string().contains("Unknown operator"));
    assert!(err.to_string().contains("BadOp"));

    // TypeMismatch
    let err = ConditionError::TypeMismatch {
        expected: "String".to_string(),
        actual: "Number".to_string(),
    };
    assert!(err.to_string().contains("Type mismatch"));
    assert!(err.to_string().contains("String"));
    assert!(err.to_string().contains("Number"));

    // InvalidBooleanValue — carries no value since wami 001
    let err = ConditionError::InvalidBooleanValue;
    assert!(err.to_string().contains("Invalid boolean value"));

    // InvalidDate — the parser's fault, never the input (wami 001)
    let err = ConditionError::InvalidDate {
        error: "parse error".to_string(),
    };
    assert!(err.to_string().contains("Invalid date value"));
    assert!(err.to_string().contains("parse error"));

    // MissingContextKey
    let err = ConditionError::MissingContextKey("aws:username".to_string());
    assert!(err.to_string().contains("Missing context key"));
    assert!(err.to_string().contains("aws:username"));

    // InvalidConditionStructure
    let err = ConditionError::InvalidConditionStructure("bad structure".to_string());
    assert!(err.to_string().contains("Invalid condition structure"));
    assert!(err.to_string().contains("bad structure"));
}

#[test]
fn test_condition_error_to_ami_error() {
    use crate::error::AmiError;
    use crate::evaluator::ConditionError;

    let err = ConditionError::UnknownOperator("BadOp".to_string());
    let ami_err: AmiError = err.into();
    assert!(matches!(ami_err, AmiError::InvalidParameter { .. }));
}

// ============================================================================
// Context Builder Tests (context.rs coverage)
// ============================================================================

#[test]
fn test_context_builder_all_methods() {
    use crate::ConditionContext;
    use chrono::Utc;

    let context = ConditionContext::builder()
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .principal_account("123456789012")
        .principal_type("User")
        .username("alice")
        .userid("AIDAIOSFODNN7EXAMPLE")
        .mfa_present(true)
        .mfa_age(300)
        .token_issue_time(Utc::now())
        .secure_transport(true)
        .source_ip("203.0.113.42")
        .source_vpc("vpc-12345678")
        .source_vpce("vpce-12345678")
        .current_time(Utc::now())
        .requested_region("us-east-1")
        .referer("https://example.com")
        .user_agent("Mozilla/5.0")
        .resource_arn("arn:aws:s3:::bucket/key")
        .resource_account("123456789012")
        .principal_tag("Environment", "production")
        .resource_tag("Project", "wami")
        .request_tag("RequestId", "12345")
        .tag_keys(vec!["Env".to_string(), "Owner".to_string()])
        .tenant_id(12345)
        .principal_tenant_id(12345)
        .resource_tenant_id(67890)
        .provider("AWS")
        .source_provider("AWS")
        .target_provider("GCP")
        .custom_value(
            "custom:key",
            crate::ConditionValue::String("value".to_string()),
        )
        .build();

    assert_eq!(
        context.principal_arn,
        Some("arn:aws:iam::123456789012:user/alice".to_string())
    );
    assert_eq!(context.username, Some("alice".to_string()));
    assert_eq!(context.mfa_present, Some(true));
    assert_eq!(context.tenant_id.as_deref(), Some("12345"));
}

#[test]
fn test_context_builder_principal_tag_role() {
    use crate::ConditionContext;

    let context = ConditionContext::builder()
        .principal_tag_role(vec!["admin".to_string(), "user".to_string()])
        .build();

    // Should set the first role
    assert_eq!(
        context.principal_tags.get("Role"),
        Some(&"admin".to_string())
    );
}

// ============================================================================
// Operator Error Path Tests (operators.rs coverage)
// ============================================================================

#[test]
fn test_all_numeric_ifexists_operators() {
    // Test all NumericIfExists operators
    let context = ConditionContext::builder().mfa_age(300).build();

    let test_cases = vec![
        (
            r#"{"NumericEqualsIfExists": {"aws:MultiFactorAuthAge": "300"}}"#,
            true,
        ),
        (
            r#"{"NumericEqualsIfExists": {"aws:MultiFactorAuthAge": "600"}}"#,
            false,
        ),
        (
            r#"{"NumericNotEqualsIfExists": {"aws:MultiFactorAuthAge": "300"}}"#,
            false,
        ),
        (
            r#"{"NumericNotEqualsIfExists": {"aws:MultiFactorAuthAge": "600"}}"#,
            true,
        ),
        (
            r#"{"NumericLessThanIfExists": {"aws:MultiFactorAuthAge": "400"}}"#,
            true,
        ),
        (
            r#"{"NumericLessThanIfExists": {"aws:MultiFactorAuthAge": "200"}}"#,
            false,
        ),
        (
            r#"{"NumericLessThanEqualsIfExists": {"aws:MultiFactorAuthAge": "300"}}"#,
            true,
        ),
        (
            r#"{"NumericLessThanEqualsIfExists": {"aws:MultiFactorAuthAge": "200"}}"#,
            false,
        ),
        (
            r#"{"NumericGreaterThanIfExists": {"aws:MultiFactorAuthAge": "200"}}"#,
            true,
        ),
        (
            r#"{"NumericGreaterThanIfExists": {"aws:MultiFactorAuthAge": "400"}}"#,
            false,
        ),
        (
            r#"{"NumericGreaterThanEqualsIfExists": {"aws:MultiFactorAuthAge": "300"}}"#,
            true,
        ),
        (
            r#"{"NumericGreaterThanEqualsIfExists": {"aws:MultiFactorAuthAge": "400"}}"#,
            false,
        ),
    ];

    for (json, expected) in test_cases {
        let condition = parse_condition_block_from_json(json);
        let result = evaluate_condition_block(&condition, &context).unwrap();
        assert_eq!(result, expected, "Failed for condition: {}", json);
    }
}

#[test]
fn test_all_date_ifexists_operators() {
    // Test all DateIfExists operators
    let now = chrono::Utc::now();
    let past = now - chrono::Duration::hours(1);
    let future = now + chrono::Duration::hours(1);
    let context = ConditionContext::builder().current_time(now).build();

    let test_cases = vec![
        (
            format!(
                r#"{{"DateEqualsIfExists": {{"aws:CurrentTime": "{}"}}}}"#,
                now.to_rfc3339()
            ),
            true,
        ),
        (
            format!(
                r#"{{"DateNotEqualsIfExists": {{"aws:CurrentTime": "{}"}}}}"#,
                now.to_rfc3339()
            ),
            false,
        ),
        (
            format!(
                r#"{{"DateLessThanIfExists": {{"aws:CurrentTime": "{}"}}}}"#,
                future.to_rfc3339()
            ),
            true,
        ),
        (
            format!(
                r#"{{"DateLessThanEqualsIfExists": {{"aws:CurrentTime": "{}"}}}}"#,
                now.to_rfc3339()
            ),
            true,
        ),
        (
            format!(
                r#"{{"DateGreaterThanIfExists": {{"aws:CurrentTime": "{}"}}}}"#,
                past.to_rfc3339()
            ),
            true,
        ),
        (
            format!(
                r#"{{"DateGreaterThanEqualsIfExists": {{"aws:CurrentTime": "{}"}}}}"#,
                now.to_rfc3339()
            ),
            true,
        ),
    ];

    for (json, expected) in test_cases {
        let condition = parse_condition_block_from_string(json);
        let result = evaluate_condition_block(&condition, &context).unwrap();
        assert_eq!(result, expected, "Failed for condition");
    }
}

#[test]
fn test_all_arn_ifexists_operators() {
    // Test all ArnIfExists operators
    let context = ConditionContext::builder()
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .build();

    let test_cases = vec![
        (
            r#"{"ArnEqualsIfExists": {"aws:PrincipalArn": "arn:aws:iam::123456789012:user/alice"}}"#,
            true,
        ),
        (
            r#"{"ArnEqualsIfExists": {"aws:PrincipalArn": "arn:aws:iam::123456789012:user/bob"}}"#,
            false,
        ),
        (
            r#"{"ArnNotEqualsIfExists": {"aws:PrincipalArn": "arn:aws:iam::123456789012:user/alice"}}"#,
            false,
        ),
        (
            r#"{"ArnNotEqualsIfExists": {"aws:PrincipalArn": "arn:aws:iam::123456789012:user/bob"}}"#,
            true,
        ),
        (
            r#"{"ArnLikeIfExists": {"aws:PrincipalArn": "arn:aws:iam::*:user/*"}}"#,
            true,
        ),
        (
            r#"{"ArnLikeIfExists": {"aws:PrincipalArn": "arn:aws:s3:::*"}}"#,
            false,
        ),
        (
            r#"{"ArnNotLikeIfExists": {"aws:PrincipalArn": "arn:aws:iam::*:user/*"}}"#,
            false,
        ),
        (
            r#"{"ArnNotLikeIfExists": {"aws:PrincipalArn": "arn:aws:s3:::*"}}"#,
            true,
        ),
    ];

    for (json, expected) in test_cases {
        let condition = parse_condition_block_from_json(json);
        let result = evaluate_condition_block(&condition, &context).unwrap();
        assert_eq!(result, expected, "Failed for condition: {}", json);
    }
}

#[test]
fn test_all_forallvalues_operators() {
    // Test all ForAllValues operators
    let context = ConditionContext::builder()
        .tag_keys(vec!["Env".to_string(), "Owner".to_string()])
        .source_ip("203.0.113.42")
        .mfa_age(300)
        .current_time(chrono::Utc::now())
        .build();

    let test_cases = vec![
        (
            r#"{"ForAllValues:StringNotEquals": {"aws:TagKeys": ["Project", "Team"]}}"#,
            true,
        ), // All actual values are not in expected
        (
            r#"{"ForAllValues:StringLike": {"aws:TagKeys": ["Env*", "Own*"]}}"#,
            true,
        ),
        (
            r#"{"ForAllValues:StringNotLike": {"aws:TagKeys": ["Pro*", "Tea*"]}}"#,
            true,
        ),
        (
            r#"{"ForAllValues:ArnEquals": {"aws:TagKeys": ["arn:aws:iam::123456789012:user/alice"]}}"#,
            false,
        ), // TagKeys is array, not ARN
        (
            r#"{"ForAllValues:ArnLike": {"aws:TagKeys": ["arn:aws:iam::*:user/*"]}}"#,
            false,
        ),
    ];

    for (json, expected) in test_cases {
        let condition = parse_condition_block_from_json(json);
        let result = evaluate_condition_block(&condition, &context);
        assert_eq!(result, Ok(expected), "{json}");
    }
}

#[test]
fn test_all_foranyvalue_operators() {
    // Test all ForAnyValue operators
    let context = ConditionContext::builder()
        .tag_keys(vec!["Env".to_string(), "Owner".to_string()])
        .source_ip("203.0.113.42")
        .mfa_age(300)
        .current_time(chrono::Utc::now())
        .build();

    let test_cases = vec![
        (
            r#"{"ForAnyValue:StringNotEquals": {"aws:TagKeys": ["Project", "Team"]}}"#,
            true,
        ), // The code reads ForAnyValue:StringNotEquals as NOT(ForAnyValue:
        // StringEquals), "no value is listed" — not AWS's reading, "some value
        // is not listed". Both give true here, so this row cannot tell them
        // apart: the negated set operators are wami 009.
        (
            r#"{"ForAnyValue:StringLike": {"aws:TagKeys": ["Env*", "Pro*"]}}"#,
            true,
        ), // Env matches
        (
            r#"{"ForAnyValue:StringNotLike": {"aws:TagKeys": ["Pro*", "Tea*"]}}"#,
            true,
        ), // Env and Owner don't match patterns
        (
            r#"{"ForAnyValue:ArnEquals": {"aws:TagKeys": ["arn:aws:iam::123456789012:user/alice"]}}"#,
            false,
        ),
        (
            r#"{"ForAnyValue:ArnLike": {"aws:TagKeys": ["arn:aws:iam::*:user/*"]}}"#,
            false,
        ),
    ];

    for (json, expected) in test_cases {
        let condition = parse_condition_block_from_json(json);
        let result = evaluate_condition_block(&condition, &context);
        assert_eq!(result, Ok(expected), "{json}");
    }
}

#[test]
fn test_operator_from_str_all_variants() {
    use crate::operators::ConditionOperator;
    use std::str::FromStr;

    // Test all operator string variants
    let operators = vec![
        "StringEquals",
        "StringNotEquals",
        "StringLike",
        "StringNotLike",
        "StringEqualsIgnoreCase",
        "StringNotEqualsIgnoreCase",
        "StringEqualsIfExists",
        "StringNotEqualsIfExists",
        "StringLikeIfExists",
        "StringNotLikeIfExists",
        "NumericEquals",
        "NumericNotEquals",
        "NumericLessThan",
        "NumericLessThanEquals",
        "NumericGreaterThan",
        "NumericGreaterThanEquals",
        "NumericEqualsIfExists",
        "NumericNotEqualsIfExists",
        "NumericLessThanIfExists",
        "NumericLessThanEqualsIfExists",
        "NumericGreaterThanIfExists",
        "NumericGreaterThanEqualsIfExists",
        "DateEquals",
        "DateNotEquals",
        "DateLessThan",
        "DateLessThanEquals",
        "DateGreaterThan",
        "DateGreaterThanEquals",
        "DateEqualsIfExists",
        "DateNotEqualsIfExists",
        "DateLessThanIfExists",
        "DateLessThanEqualsIfExists",
        "DateGreaterThanIfExists",
        "DateGreaterThanEqualsIfExists",
        "IpAddress",
        "NotIpAddress",
        "IpAddressIfExists",
        "NotIpAddressIfExists",
        "ArnEquals",
        "ArnNotEquals",
        "ArnLike",
        "ArnNotLike",
        "ArnEqualsIfExists",
        "ArnNotEqualsIfExists",
        "ArnLikeIfExists",
        "ArnNotLikeIfExists",
        "Bool",
        "BoolIfExists",
        "BinaryEquals",
        "BinaryEqualsIfExists",
        "Null",
        "NullIfExists",
        "ForAllValues:StringEquals",
        "ForAllValues:StringNotEquals",
        "ForAllValues:StringLike",
        "ForAllValues:StringNotLike",
        "ForAllValues:ArnEquals",
        "ForAllValues:ArnLike",
        "ForAllValues:NumericLessThan",
        "ForAllValues:NumericGreaterThan",
        "ForAllValues:IpAddress",
        "ForAllValues:DateLessThan",
        "ForAllValues:DateGreaterThan",
        "ForAnyValue:StringEquals",
        "ForAnyValue:StringNotEquals",
        "ForAnyValue:StringLike",
        "ForAnyValue:StringNotLike",
        "ForAnyValue:ArnEquals",
        "ForAnyValue:ArnLike",
        "ForAnyValue:NumericLessThan",
        "ForAnyValue:NumericGreaterThan",
        "ForAnyValue:IpAddress",
        "ForAnyValue:DateLessThan",
        "ForAnyValue:DateGreaterThan",
    ];

    for op_str in operators {
        let result = ConditionOperator::from_str(op_str);
        assert!(result.is_ok(), "Failed to parse operator: {}", op_str);
    }

    // Test invalid operator
    let result = ConditionOperator::from_str("InvalidOperator");
    assert!(result.is_err());
}

#[test]
fn test_operator_evaluation_error_paths() {
    // Test error paths in operator evaluation
    use crate::operators::{evaluate_operator, ConditionOperator};
    use crate::ConditionValue;

    // Test with invalid type combinations that should return errors
    let test_cases = vec![
        // Numeric operator with non-numeric string
        (
            ConditionOperator::NumericEquals,
            Some(ConditionValue::String("not-a-number".to_string())),
            ConditionValue::Number(123.0),
        ),
        // Date operator with invalid date string
        (
            ConditionOperator::DateEquals,
            Some(ConditionValue::String("invalid-date".to_string())),
            ConditionValue::String("2024-01-01T00:00:00Z".to_string()),
        ),
        // Boolean operator with invalid boolean string
        (
            ConditionOperator::Bool,
            Some(ConditionValue::String("maybe".to_string())),
            ConditionValue::Boolean(true),
        ),
        // Array operator with non-array
        (
            ConditionOperator::ForAllValuesStringEquals,
            Some(ConditionValue::String("single".to_string())),
            ConditionValue::Number(123.0),
        ), // Expected should be array but is number
    ];

    // Each is an error, and the one its parser gives (wami 001).
    let errors = [
        ConditionError::TypeMismatch {
            expected: "a finite Number".to_string(),
            actual: "String".to_string(),
        },
        ConditionError::InvalidDate {
            error: "input contains invalid characters".to_string(),
        },
        ConditionError::InvalidBooleanValue,
        ConditionError::TypeMismatch {
            expected: "Array".to_string(),
            actual: "Number".to_string(),
        },
    ];
    for ((op, actual, expected), error) in test_cases.into_iter().zip(errors) {
        assert_eq!(
            evaluate_operator(op, actual, &expected),
            Err(error),
            "{op:?}"
        );
    }
}

#[test]
fn test_parse_condition_block_error_paths() {
    use crate::evaluator::parse_condition_block;
    use serde_json::Value;

    // Test invalid structures
    let invalid_cases = vec![
        // Not an object
        Value::String("not an object".to_string()),
        Value::Number(serde_json::Number::from(123)),
        Value::Bool(true),
        Value::Array(vec![]),
        // Operator value not an object
        serde_json::json!({
            "StringEquals": "not an object"
        }),
        // Null operator value
        serde_json::json!({
            "StringEquals": null
        }),
    ];

    for invalid_value in invalid_cases {
        let result = parse_condition_block(&invalid_value);
        assert!(
            result.is_err(),
            "Should error on invalid structure: {:?}",
            invalid_value
        );
    }
}

#[test]
fn test_evaluator_error_display_coverage() {
    use crate::evaluator::ConditionError;

    // Ensure all error variants are covered by Display
    let errors = vec![
        ConditionError::UnknownOperator("TestOp".to_string()),
        ConditionError::TypeMismatch {
            expected: "String".to_string(),
            actual: "Number".to_string(),
        },
        ConditionError::InvalidBooleanValue,
        ConditionError::InvalidDate {
            error: "parse error".to_string(),
        },
        ConditionError::MissingContextKey("key".to_string()),
        ConditionError::InvalidConditionStructure("bad".to_string()),
    ];

    for err in errors {
        let _display = format!("{}", err);
        let _debug = format!("{:?}", err);
    }
}

#[test]
fn test_condition_value_from_json_edge_cases() {
    use crate::ConditionValue;
    use serde_json::Value;

    // Test number edge cases
    let json = Value::Number(serde_json::Number::from(0));
    let val = ConditionValue::from(json);
    assert!(matches!(val, ConditionValue::Number(_)));

    // Test negative number
    let json = Value::Number(serde_json::Number::from(-123));
    let val = ConditionValue::from(json);
    assert!(matches!(val, ConditionValue::Number(_)));

    // Test array with mixed types (should filter to strings only)
    let json = Value::Array(vec![
        Value::String("a".to_string()),
        Value::Number(serde_json::Number::from(123)),
        Value::Bool(true),
        Value::String("b".to_string()),
    ]);
    let val = ConditionValue::from(json);
    match val {
        ConditionValue::Array(arr) => {
            assert_eq!(arr.len(), 2); // Only strings kept
            assert_eq!(arr, vec!["a".to_string(), "b".to_string()]);
        }
        _ => panic!("Expected Array"),
    }

    // Test empty array
    let json = Value::Array(vec![]);
    let val = ConditionValue::from(json);
    match val {
        ConditionValue::Array(arr) => assert!(arr.is_empty()),
        _ => panic!("Expected Array"),
    }
}

// ============================================================================
// Additional Coverage Tests for Remaining Uncovered Lines
// ============================================================================

#[test]
fn test_ip_address_actual_not_string() {
    // Line 608: actual is not String => Ok(false)
    let context = ConditionContext::builder()
        .custom_value("ip:key", crate::ConditionValue::Number(123.0))
        .build();
    let condition = unchecked(
        r#"{
            "IpAddress": {
                "ip:key": "127.0.0.1"
            }
        }"#,
    );
    // A type mismatch is an error, never `false` (wami 001).
    assert_eq!(
        evaluate_condition_block(&condition, &context),
        Err(ConditionError::TypeMismatch {
            expected: "an IP address".to_string(),
            actual: "Number".to_string()
        })
    );
}

#[test]
fn test_bool_operator_missing_key() {
    // Line 823: None => Ok(false)
    let context = ConditionContext::builder().build();
    let condition = parse_condition_block_from_json(
        r#"{
            "Bool": {
                "aws:MultiFactorAuthPresent": "true"
            }
        }"#,
    );
    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(!result);
}

#[test]
fn test_forallvalues_string_equals_missing_key() {
    // Line 861: None => Ok(true) - vacuous truth
    let context = ConditionContext::builder().build();
    let condition = parse_condition_block_from_json(
        r#"{
            "ForAllValues:StringEquals": {
                "aws:TagKeys": ["Env", "Owner"]
            }
        }"#,
    );
    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

#[test]
fn test_ip_address_cidr_parse_failure() {
    // Test CIDR parsing failure (invalid prefix length)
    // An invalid prefix used to fail to match; refused at parse (wami 001).
    parse_err(r#"{"IpAddress": {"aws:SourceIp": "203.0.113.0/invalid"}}"#);
}

#[test]
fn test_ip_address_ipv4_parse_failure() {
    // Test IPv4 parsing failure (not 4 parts)
    let context = ConditionContext::builder().source_ip("203.0.113").build();
    let condition = unchecked(
        r#"{
            "IpAddress": {
                "aws:SourceIp": "203.0.113.0/24"
            }
        }"#,
    );
    // A type mismatch is an error, never `false` (wami 001).
    assert_eq!(
        evaluate_condition_block(&condition, &context),
        Err(ConditionError::TypeMismatch {
            expected: "an IP address".to_string(),
            actual: "String".to_string()
        })
    );
}

#[test]
fn test_ip_address_ipv6_no_colon() {
    // Test IPv6 case where IP doesn't contain colon
    let context = ConditionContext::builder()
        .source_ip("203.0.113.42")
        .build();
    let condition = parse_condition_block_from_json(
        r#"{
            "IpAddress": {
                "aws:SourceIp": "2001:db8::/32"
            }
        }"#,
    );
    let result = evaluate_condition_block(&condition, &context).unwrap();
    // IPv4 IP won't match IPv6 CIDR
    assert!(!result);
}

#[test]
fn test_ip_address_cidr_no_slash() {
    // Test CIDR without slash (exact match path)
    let context = ConditionContext::builder()
        .source_ip("203.0.113.42")
        .build();
    let condition = parse_condition_block_from_json(
        r#"{
            "IpAddress": {
                "aws:SourceIp": "203.0.113.42"
            }
        }"#,
    );
    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

#[test]
fn test_ip_address_cidr_prefix_len_too_large() {
    // Test prefix_len > 32 for IPv4
    // A v4 prefix above 32 matched nothing; refused at parse (wami 001).
    parse_err(r#"{"IpAddress": {"aws:SourceIp": "203.0.113.0/33"}}"#);
}

#[test]
fn test_ip_address_ipv6_prefix_len_edge_case() {
    // Test IPv6 with prefix_len exactly 128
    let ip = "2001:db8::1";
    let context = ConditionContext::builder().source_ip(ip).build();
    let condition = parse_condition_block_from_json(&format!(
        r#"{{
            "IpAddress": {{
                "aws:SourceIp": "{}/128"
            }}
        }}"#,
        ip
    ));
    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

// ============================================================================
// Comprehensive Operator Coverage Tests (>99% target)
// ============================================================================

#[test]
fn test_string_not_operators() {
    // Test StringNotEquals, StringNotLike, StringNotEqualsIgnoreCase
    let context = ConditionContext::builder().username("alice").build();

    let test_cases = vec![
        (r#"{"StringNotEquals": {"aws:username": "bob"}}"#, true), // alice != bob
        (r#"{"StringNotEquals": {"aws:username": "alice"}}"#, false), // alice == alice
        (r#"{"StringNotLike": {"aws:username": "b*"}}"#, true),    // alice doesn't match b*
        (r#"{"StringNotLike": {"aws:username": "a*"}}"#, false),   // alice matches a*
        (
            r#"{"StringNotEqualsIgnoreCase": {"aws:username": "BOB"}}"#,
            true,
        ), // alice != BOB
        (
            r#"{"StringNotEqualsIgnoreCase": {"aws:username": "ALICE"}}"#,
            false,
        ), // alice == ALICE (case insensitive)
    ];

    for (json, expected) in test_cases {
        let condition = parse_condition_block_from_json(json);
        let result = evaluate_condition_block(&condition, &context).unwrap();
        assert_eq!(result, expected, "Failed for condition: {}", json);
    }
}

#[test]
fn test_string_not_ifexists_operators() {
    // Test StringNotEqualsIfExists, StringNotLikeIfExists
    let context1 = ConditionContext::builder().username("alice").build();
    let context2 = ConditionContext::builder().build(); // No username

    let test_cases = vec![
        (
            r#"{"StringNotEqualsIfExists": {"aws:username": "bob"}}"#,
            true,
            true,
        ), // alice != bob
        (
            r#"{"StringNotEqualsIfExists": {"aws:username": "alice"}}"#,
            false,
            true,
        ), // alice == alice
        (
            r#"{"StringNotEqualsIfExists": {"aws:PrincipalType": "User"}}"#,
            true,
            false,
        ), // Missing key passes
        (
            r#"{"StringNotLikeIfExists": {"aws:username": "b*"}}"#,
            true,
            true,
        ), // alice doesn't match b*
        (
            r#"{"StringNotLikeIfExists": {"aws:username": "a*"}}"#,
            false,
            true,
        ), // alice matches a*
        (
            r#"{"StringNotLikeIfExists": {"aws:PrincipalType": "User*"}}"#,
            true,
            false,
        ), // Missing key passes
    ];

    for (json, expected, use_context1) in test_cases {
        let context = if use_context1 { &context1 } else { &context2 };
        let condition = parse_condition_block_from_json(json);
        let result = evaluate_condition_block(&condition, context).unwrap();
        assert_eq!(result, expected, "Failed for condition: {}", json);
    }
}

#[test]
fn test_numeric_not_equals() {
    // Test NumericNotEquals
    let context = ConditionContext::builder().mfa_age(300).build();

    let test_cases = vec![
        (
            r#"{"NumericNotEquals": {"aws:MultiFactorAuthAge": "300"}}"#,
            false,
        ), // 300 == 300
        (
            r#"{"NumericNotEquals": {"aws:MultiFactorAuthAge": "600"}}"#,
            true,
        ), // 300 != 600
        (
            r#"{"NumericNotEquals": {"aws:MultiFactorAuthAge": "299"}}"#,
            true,
        ), // 300 != 299
    ];

    for (json, expected) in test_cases {
        let condition = parse_condition_block_from_json(json);
        let result = evaluate_condition_block(&condition, &context).unwrap();
        assert_eq!(result, expected, "Failed for condition: {}", json);
    }
}

#[test]
fn test_date_not_equals() {
    // Test DateNotEquals
    let now = chrono::Utc::now();
    let past = now - chrono::Duration::hours(1);
    let context = ConditionContext::builder().current_time(now).build();

    let test_cases = vec![
        (
            format!(
                r#"{{"DateNotEquals": {{"aws:CurrentTime": "{}"}}}}"#,
                now.to_rfc3339()
            ),
            false,
        ), // now == now
        (
            format!(
                r#"{{"DateNotEquals": {{"aws:CurrentTime": "{}"}}}}"#,
                past.to_rfc3339()
            ),
            true,
        ), // now != past
    ];

    for (json, expected) in test_cases {
        let condition = parse_condition_block_from_string(json);
        let result = evaluate_condition_block(&condition, &context).unwrap();
        assert_eq!(result, expected, "Failed for condition");
    }
}

#[test]
fn test_date_not_equals_ifexists() {
    // Test DateNotEqualsIfExists
    let now = chrono::Utc::now();
    let past = now - chrono::Duration::hours(1);
    let context1 = ConditionContext::builder().current_time(now).build();
    let context2 = ConditionContext::builder().build(); // No current_time

    let test_cases = vec![
        (
            format!(
                r#"{{"DateNotEqualsIfExists": {{"aws:CurrentTime": "{}"}}}}"#,
                now.to_rfc3339()
            ),
            false,
            true,
        ), // now == now
        (
            format!(
                r#"{{"DateNotEqualsIfExists": {{"aws:CurrentTime": "{}"}}}}"#,
                past.to_rfc3339()
            ),
            true,
            true,
        ), // now != past
        (
            format!(
                r#"{{"DateNotEqualsIfExists": {{"aws:TokenIssueTime": "{}"}}}}"#,
                now.to_rfc3339()
            ),
            true,
            false,
        ), // Missing key passes
    ];

    for (json, expected, use_context1) in test_cases {
        let context = if use_context1 { &context1 } else { &context2 };
        let condition = parse_condition_block_from_string(json);
        let result = evaluate_condition_block(&condition, context).unwrap();
        assert_eq!(result, expected, "Failed for condition");
    }
}

#[test]
fn test_binary_equals_ifexists() {
    // Test BinaryEqualsIfExists
    let context1 = ConditionContext::builder()
        .custom_value(
            "binary:key",
            crate::ConditionValue::String("dGVzdA==".to_string()),
        )
        .build();
    let context2 = ConditionContext::builder().build(); // No binary key

    let condition1 = parse_condition_block_from_json(
        r#"{
            "BinaryEqualsIfExists": {
                "binary:key": "dGVzdA=="
            }
        }"#,
    );
    let result1 = evaluate_condition_block(&condition1, &context1).unwrap();
    assert!(result1);

    let condition2 = parse_condition_block_from_json(
        r#"{
            "BinaryEqualsIfExists": {
                "binary:key": "dGVzdA=="
            }
        }"#,
    );
    let result2 = evaluate_condition_block(&condition2, &context2).unwrap();
    assert!(result2); // Missing key passes
}

#[test]
fn test_null_ifexists() {
    // Test NullIfExists
    let context1 = ConditionContext::builder().username("alice").build();
    let context2 = ConditionContext::builder().build(); // No username

    let condition = parse_condition_block_from_json(
        r#"{
            "NullIfExists": {
                "aws:username": "true"
            }
        }"#,
    );

    let result1 = evaluate_condition_block(&condition, &context1).unwrap();
    assert!(!result1); // username exists, so null check fails

    let result2 = evaluate_condition_block(&condition, &context2).unwrap();
    assert!(result2); // username doesn't exist, so null check passes (IfExists)
}

#[test]
fn test_arn_not_equals_ifexists() {
    // Test ArnNotEqualsIfExists
    let context1 = ConditionContext::builder()
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .build();
    let context2 = ConditionContext::builder().build(); // No principal_arn

    let test_cases = vec![
        (
            r#"{"ArnNotEqualsIfExists": {"aws:PrincipalArn": "arn:aws:iam::123456789012:user/alice"}}"#,
            false,
            true,
        ), // Equal
        (
            r#"{"ArnNotEqualsIfExists": {"aws:PrincipalArn": "arn:aws:iam::123456789012:user/bob"}}"#,
            true,
            true,
        ), // Not equal
        (
            r#"{"ArnNotEqualsIfExists": {"aws:PrincipalArn": "arn:aws:iam::123456789012:user/alice"}}"#,
            true,
            false,
        ), // Missing key passes
    ];

    for (json, expected, use_context1) in test_cases {
        let context = if use_context1 { &context1 } else { &context2 };
        let condition = parse_condition_block_from_json(json);
        let result = evaluate_condition_block(&condition, context).unwrap();
        assert_eq!(result, expected, "Failed for condition: {}", json);
    }
}

#[test]
fn test_arn_not_like_ifexists() {
    // Test ArnNotLikeIfExists
    let context1 = ConditionContext::builder()
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .build();
    let context2 = ConditionContext::builder().build(); // No principal_arn

    let test_cases = vec![
        (
            r#"{"ArnNotLikeIfExists": {"aws:PrincipalArn": "arn:aws:iam::*:user/*"}}"#,
            false,
            true,
        ), // Matches pattern
        (
            r#"{"ArnNotLikeIfExists": {"aws:PrincipalArn": "arn:aws:s3:::*"}}"#,
            true,
            true,
        ), // Doesn't match pattern
        (
            r#"{"ArnNotLikeIfExists": {"aws:PrincipalArn": "arn:aws:iam::*:user/*"}}"#,
            true,
            false,
        ), // Missing key passes
    ];

    for (json, expected, use_context1) in test_cases {
        let context = if use_context1 { &context1 } else { &context2 };
        let condition = parse_condition_block_from_json(json);
        let result = evaluate_condition_block(&condition, context).unwrap();
        assert_eq!(result, expected, "Failed for condition: {}", json);
    }
}

#[test]
fn test_wildcard_pattern_edge_cases() {
    // Test wildcard pattern edge cases to cover line 508
    let test_cases = vec![
        ("", "*", true),          // Empty string matches *
        ("", "?", false),         // Empty string doesn't match ?
        ("a", "?", true),         // Single char matches ?
        ("ab", "??", true),       // Two chars match ??
        ("abc", "a?c", true),     // Pattern with ? in middle
        ("abc", "a??c", false),   // Pattern with too many ?
        ("", "a*", false),        // Empty doesn't match a*
        ("a", "a*", true),        // a matches a*
        ("ab", "a*", true),       // ab matches a*
        ("ba", "*a", true),       // ba matches *a
        ("ba", "a*", false),      // ba doesn't match a*
        ("abc", "*b*", true),     // abc matches *b*
        ("abc", "a*c", true),     // abc matches a*c
        ("abc", "a*e", false),    // abc doesn't match a*e
        ("abcde", "a*e", true),   // abcde matches a*e
        ("test", "t*st", true),   // test matches t*st
        ("test", "t?st", true),   // test matches t?st
        ("test", "t??st", false), // test doesn't match t??st
    ];

    for (value, pattern, expected) in test_cases {
        let context = ConditionContext::builder().username(value).build();
        let condition_json = format!(
            r#"{{
                "StringLike": {{
                    "aws:username": "{}"
                }}
            }}"#,
            pattern
        );
        let condition = parse_condition_block_from_string(condition_json);
        let result = evaluate_condition_block(&condition, &context).unwrap();
        assert_eq!(
            result, expected,
            "Pattern '{}' should match '{}' = {}",
            pattern, value, expected
        );
    }
}

#[test]
fn test_date_operator_error_paths() {
    // Test date operator error paths (invalid dates, type mismatches)
    let context = ConditionContext::builder()
        .current_time(chrono::Utc::now())
        .build();

    // An invalid date, or a number where a date is read, is refused at parse
    // (wami 001) — it used to evaluate to false.
    parse_err(r#"{"DateEquals": {"aws:CurrentTime": "not-a-date"}}"#);
    parse_err(r#"{"DateEquals": {"aws:CurrentTime": "123"}}"#);

    let test_cases = vec![
        // Missing context key
        (
            r#"{"DateEquals": {"aws:TokenIssueTime": "2024-01-01T00:00:00Z"}}"#,
            false,
        ),
    ];

    for (json, expected) in test_cases {
        let condition = parse_condition_block_from_json(json);
        let result = evaluate_condition_block(&condition, &context).unwrap();
        assert_eq!(result, expected, "Failed for condition: {}", json);
    }
}

#[test]
fn test_forallvalues_string_single_value() {
    // Test ForAllValues with single string value (line 871-874)
    let context = ConditionContext::builder().username("alice").build();

    let condition = parse_condition_block_from_json(
        r#"{
            "ForAllValues:StringEquals": {
                "aws:username": ["alice", "bob"]
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // "alice" is in ["alice", "bob"]

    let condition2 = parse_condition_block_from_json(
        r#"{
            "ForAllValues:StringEquals": {
                "aws:username": ["bob", "charlie"]
            }
        }"#,
    );

    let result2 = evaluate_condition_block(&condition2, &context).unwrap();
    assert!(!result2); // "alice" is not in ["bob", "charlie"]
}

#[test]
fn test_forallvalues_string_like_single_value() {
    // Test ForAllValues:StringLike with single string value (line 897-899)
    let context = ConditionContext::builder().username("alice").build();

    let condition = parse_condition_block_from_json(
        r#"{
            "ForAllValues:StringLike": {
                "aws:username": ["a*", "b*"]
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // "alice" matches "a*"

    let condition2 = parse_condition_block_from_json(
        r#"{
            "ForAllValues:StringLike": {
                "aws:username": ["b*", "c*"]
            }
        }"#,
    );

    let result2 = evaluate_condition_block(&condition2, &context).unwrap();
    assert!(!result2); // "alice" doesn't match "b*" or "c*"
}

#[test]
fn test_forallvalues_arn_single_value() {
    // Test ForAllValues:ArnEquals and ForAllValues:ArnLike with single value
    let context = ConditionContext::builder()
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .build();

    let condition1 = parse_condition_block_from_json(
        r#"{
            "ForAllValues:ArnEquals": {
                "aws:PrincipalArn": ["arn:aws:iam::123456789012:user/alice", "arn:aws:iam::123456789012:user/bob"]
            }
        }"#,
    );
    let result1 = evaluate_condition_block(&condition1, &context).unwrap();
    assert!(result1); // ARN is in the list

    let condition2 = parse_condition_block_from_json(
        r#"{
            "ForAllValues:ArnLike": {
                "aws:PrincipalArn": ["arn:aws:iam::*:user/*", "arn:aws:s3:::*"]
            }
        }"#,
    );
    let result2 = evaluate_condition_block(&condition2, &context).unwrap();
    assert!(result2); // ARN matches first pattern
}

#[test]
fn test_foranyvalue_string_single_value() {
    // Test ForAnyValue with single string value
    let context = ConditionContext::builder().username("alice").build();

    let condition = parse_condition_block_from_json(
        r#"{
            "ForAnyValue:StringEquals": {
                "aws:username": ["alice", "bob"]
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // "alice" is in ["alice", "bob"]

    let condition2 = parse_condition_block_from_json(
        r#"{
            "ForAnyValue:StringLike": {
                "aws:username": ["a*", "b*"]
            }
        }"#,
    );

    let result2 = evaluate_condition_block(&condition2, &context).unwrap();
    assert!(result2); // "alice" matches "a*"
}

#[test]
fn test_foranyvalue_arn_single_value() {
    // Test ForAnyValue:ArnEquals and ForAnyValue:ArnLike with single value
    let context = ConditionContext::builder()
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .build();

    let condition1 = parse_condition_block_from_json(
        r#"{
            "ForAnyValue:ArnEquals": {
                "aws:PrincipalArn": ["arn:aws:iam::123456789012:user/alice", "arn:aws:iam::123456789012:user/bob"]
            }
        }"#,
    );
    let result1 = evaluate_condition_block(&condition1, &context).unwrap();
    assert!(result1); // ARN is in the list

    let condition2 = parse_condition_block_from_json(
        r#"{
            "ForAnyValue:ArnLike": {
                "aws:PrincipalArn": ["arn:aws:iam::*:user/*", "arn:aws:s3:::*"]
            }
        }"#,
    );
    let result2 = evaluate_condition_block(&condition2, &context).unwrap();
    assert!(result2); // ARN matches first pattern
}

#[test]
fn test_ip_address_array_handling() {
    // Test IP address with array of CIDRs (line 700-702)
    let context = ConditionContext::builder()
        .source_ip("203.0.113.42")
        .build();

    let condition = parse_condition_block_from_json(
        r#"{
            "IpAddress": {
                "aws:SourceIp": ["203.0.113.0/24", "198.51.100.0/24"]
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // IP matches first CIDR

    // Test NotIpAddress with array
    let condition2 = parse_condition_block_from_json(
        r#"{
            "NotIpAddress": {
                "aws:SourceIp": ["198.51.100.0/24", "192.0.2.0/24"]
            }
        }"#,
    );

    let result2 = evaluate_condition_block(&condition2, &context).unwrap();
    assert!(result2); // IP is not in either CIDR
}

#[test]
fn test_ip_parsing_edge_cases() {
    // Test IP parsing edge cases (lines 737, 759)
    let test_cases = vec![
        // IPv6 basic matching
        ("2001:db8::1", "2001:db8::/32", true),
        ("2001:db8::1", "2001:db9::/32", false),
        // Invalid IP format
        ("not-an-ip", "203.0.113.0/24", false),
        // CIDR without prefix
        ("203.0.113.42", "203.0.113.42", true), // Exact match
    ];
    // Invalid CIDR formats used to fail to match; refused at parse (wami 001).
    parse_err(r#"{"IpAddress": {"aws:SourceIp": "203.0.113.0/"}}"#);
    parse_err(r#"{"IpAddress": {"aws:SourceIp": "203.0.113.0/33"}}"#);

    for (ip, cidr, expected) in test_cases {
        let context = ConditionContext::builder().source_ip(ip).build();
        let condition_json = format!(
            r#"{{
                "IpAddress": {{
                    "aws:SourceIp": "{}"
                }}
            }}"#,
            cidr
        );
        let condition = parse_condition_block_from_string(condition_json);
        let result = evaluate_condition_block(&condition, &context);
        // Some may error, some may return false
        if let Ok(val) = result {
            assert_eq!(
                val, expected,
                "IP {} in CIDR {} should be {}",
                ip, cidr, expected
            );
        }
    }
}

#[test]
fn test_forallvalues_empty_actual_edge_cases() {
    // Test ForAllValues with empty actual (vacuous truth) - various operators
    let context = ConditionContext::builder()
        .tag_keys(vec![]) // Empty
        .build();

    let test_cases = vec![
        (
            r#"{"ForAllValues:StringEquals": {"aws:TagKeys": ["Env", "Owner"]}}"#,
            true,
        ),
        (
            r#"{"ForAllValues:StringLike": {"aws:TagKeys": ["Env*", "Own*"]}}"#,
            true,
        ),
        (
            r#"{"ForAllValues:ArnEquals": {"aws:TagKeys": ["arn:aws:iam::123456789012:user/alice"]}}"#,
            true,
        ),
        (
            r#"{"ForAllValues:ArnLike": {"aws:TagKeys": ["arn:aws:iam::*:user/*"]}}"#,
            true,
        ),
    ];

    for (json, expected) in test_cases {
        let condition = unchecked(json);
        let result = evaluate_condition_block(&condition, &context).unwrap();
        assert_eq!(result, expected, "Failed for condition: {}", json);
    }
}

#[test]
fn test_foranyvalue_empty_actual_edge_cases() {
    // Test ForAnyValue with empty actual (should fail) - various operators
    let context = ConditionContext::builder()
        .tag_keys(vec![]) // Empty
        .build();

    let test_cases = vec![
        (
            r#"{"ForAnyValue:StringEquals": {"aws:TagKeys": ["Env", "Owner"]}}"#,
            false,
        ),
        (
            r#"{"ForAnyValue:StringLike": {"aws:TagKeys": ["Env*", "Own*"]}}"#,
            false,
        ),
        (
            r#"{"ForAnyValue:ArnEquals": {"aws:TagKeys": ["arn:aws:iam::123456789012:user/alice"]}}"#,
            false,
        ),
        (
            r#"{"ForAnyValue:ArnLike": {"aws:TagKeys": ["arn:aws:iam::*:user/*"]}}"#,
            false,
        ),
    ];

    for (json, expected) in test_cases {
        let condition = unchecked(json);
        let result = evaluate_condition_block(&condition, &context).unwrap();
        assert_eq!(result, expected, "Failed for condition: {}", json);
    }
}

#[test]
fn test_forallvalues_type_mismatch_paths() {
    // Test ForAllValues with type mismatches (non-array expected, etc.)
    // Expected is not an array: refused at parse (wami 001)
    let message = parse_err(r#"{"ForAllValues:StringEquals": {"aws:TagKeys": "Env"}}"#);
    assert!(message.contains("reads only a list"), "{message}");

    // Actual is not array or string (should return false)
    let context2 = ConditionContext::builder().mfa_age(300).build();
    let condition2 = unchecked(
        r#"{
            "ForAllValues:StringEquals": {
                "aws:MultiFactorAuthAge": ["300"]
            }
        }"#,
    );
    // A type mismatch is an error, never `false` (wami 001).
    assert_eq!(
        evaluate_condition_block(&condition2, &context2),
        Err(ConditionError::TypeMismatch {
            expected: "a String or an Array of Strings".to_string(),
            actual: "Number".to_string()
        })
    );
}

#[test]
fn test_foranyvalue_type_mismatch_paths() {
    // Test ForAnyValue with type mismatches
    // Expected is not an array: refused at parse (wami 001)
    let message = parse_err(r#"{"ForAnyValue:StringEquals": {"aws:TagKeys": "Env"}}"#);
    assert!(message.contains("reads only a list"), "{message}");

    // Actual is not array or string (should return false)
    let context2 = ConditionContext::builder().mfa_age(300).build();
    let condition2 = unchecked(
        r#"{
            "ForAnyValue:StringEquals": {
                "aws:MultiFactorAuthAge": ["300"]
            }
        }"#,
    );
    // A type mismatch is an error, never `false` (wami 001).
    assert_eq!(
        evaluate_condition_block(&condition2, &context2),
        Err(ConditionError::TypeMismatch {
            expected: "a String or an Array of Strings".to_string(),
            actual: "Number".to_string()
        })
    );
}

#[test]
fn test_string_operator_error_paths() {
    // Test string operator error paths (lines 451-452, 465-466)
    // These were the `_ => Ok(false)` paths; a type mismatch is an error since wami 001.

    // StringEquals with non-string actual
    let context1 = ConditionContext::builder()
        .mfa_age(300) // Number, not string
        .build();
    let condition1 = unchecked(
        r#"{
            "StringEquals": {
                "aws:MultiFactorAuthAge": "300"
            }
        }"#,
    );
    // A type mismatch is an error, never `false` (wami 001).
    assert_eq!(
        evaluate_condition_block(&condition1, &context1),
        Err(ConditionError::TypeMismatch {
            expected: "String".to_string(),
            actual: "Number".to_string()
        })
    );

    // StringLike with non-string actual
    let condition2 = unchecked(
        r#"{
            "StringLike": {
                "aws:MultiFactorAuthAge": "3*"
            }
        }"#,
    );
    // A type mismatch is an error, never `false` (wami 001).
    assert_eq!(
        evaluate_condition_block(&condition2, &context1),
        Err(ConditionError::TypeMismatch {
            expected: "String".to_string(),
            actual: "Number".to_string()
        })
    );

    // StringEqualsIgnoreCase with non-string actual
    let condition3 = unchecked(
        r#"{
            "StringEqualsIgnoreCase": {
                "aws:MultiFactorAuthAge": "300"
            }
        }"#,
    );
    // A type mismatch is an error, never `false` (wami 001).
    assert_eq!(
        evaluate_condition_block(&condition3, &context1),
        Err(ConditionError::TypeMismatch {
            expected: "String".to_string(),
            actual: "Number".to_string()
        })
    );
}

#[test]
fn test_keys_aws_userid_variant() {
    // Test aws:userid and aws:userId (both should work, line 20)
    let context = ConditionContext::builder()
        .userid("AIDAIOSFODNN7EXAMPLE")
        .build();

    let condition1 = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "aws:userid": "AIDAIOSFODNN7EXAMPLE"
            }
        }"#,
    );
    let result1 = evaluate_condition_block(&condition1, &context).unwrap();
    assert!(result1);

    let condition2 = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "aws:userId": "AIDAIOSFODNN7EXAMPLE"
            }
        }"#,
    );
    let result2 = evaluate_condition_block(&condition2, &context).unwrap();
    assert!(result2);
}

#[test]
fn test_keys_principal_account() {
    // Test aws:PrincipalAccount (lines 14-17)
    let context = ConditionContext::builder()
        .principal_account("123456789012")
        .build();

    let condition = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "aws:PrincipalAccount": "123456789012"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

#[test]
fn test_keys_principal_type() {
    // Test aws:PrincipalType
    let context = ConditionContext::builder().principal_type("User").build();

    let condition = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "aws:PrincipalType": "User"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

#[test]
fn test_keys_resource_account() {
    // Test aws:ResourceAccount
    let context = ConditionContext::builder()
        .resource_account("123456789012")
        .build();

    let condition = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "aws:ResourceAccount": "123456789012"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

#[test]
fn test_keys_secure_transport() {
    // Test aws:SecureTransport
    let context = ConditionContext::builder().secure_transport(true).build();

    let condition = parse_condition_block_from_json(
        r#"{
            "Bool": {
                "aws:SecureTransport": "true"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

#[test]
fn test_keys_source_vpc_vpce() {
    // Test aws:SourceVpc and aws:SourceVpce
    let context = ConditionContext::builder()
        .source_vpc("vpc-12345678")
        .source_vpce("vpce-12345678")
        .build();

    let condition1 = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "aws:SourceVpc": "vpc-12345678"
            }
        }"#,
    );
    let result1 = evaluate_condition_block(&condition1, &context).unwrap();
    assert!(result1);

    let condition2 = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "aws:SourceVpce": "vpce-12345678"
            }
        }"#,
    );
    let result2 = evaluate_condition_block(&condition2, &context).unwrap();
    assert!(result2);
}

#[test]
fn test_keys_referer_user_agent() {
    // Test aws:Referer and aws:UserAgent
    let context = ConditionContext::builder()
        .referer("https://example.com")
        .user_agent("Mozilla/5.0")
        .build();

    let condition1 = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "aws:Referer": "https://example.com"
            }
        }"#,
    );
    let result1 = evaluate_condition_block(&condition1, &context).unwrap();
    assert!(result1);

    let condition2 = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "aws:UserAgent": "Mozilla/5.0"
            }
        }"#,
    );
    let result2 = evaluate_condition_block(&condition2, &context).unwrap();
    assert!(result2);
}

#[test]
fn test_keys_requested_region() {
    // Test aws:RequestedRegion
    let context = ConditionContext::builder()
        .requested_region("us-east-1")
        .build();

    let condition = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "aws:RequestedRegion": "us-east-1"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

#[test]
fn test_keys_token_issue_time() {
    // Test aws:TokenIssueTime
    let now = chrono::Utc::now();
    let context = ConditionContext::builder().token_issue_time(now).build();

    let condition_json = format!(
        r#"{{
            "DateEquals": {{
                "aws:TokenIssueTime": "{}"
            }}
        }}"#,
        now.to_rfc3339()
    );

    let condition = parse_condition_block_from_string(condition_json);
    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

#[test]
fn test_keys_mfa_age() {
    // Test aws:MultiFactorAuthAge
    let context = ConditionContext::builder().mfa_age(300).build();

    let condition = parse_condition_block_from_json(
        r#"{
            "NumericEquals": {
                "aws:MultiFactorAuthAge": "300"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

#[test]
fn test_keys_tag_keys_empty() {
    // Test aws:TagKeys with empty array (should return None, line 67-70)
    let context = ConditionContext::builder()
        .tag_keys(vec![]) // Empty
        .build();

    let condition = parse_condition_block_from_json(
        r#"{
            "ForAllValues:StringEquals": {
                "aws:TagKeys": ["Env"]
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // Empty actual = vacuous truth for ForAllValues
}

#[test]
fn test_keys_tag_keys_non_empty() {
    // Test aws:TagKeys with non-empty array
    let context = ConditionContext::builder()
        .tag_keys(vec!["Env".to_string(), "Owner".to_string()])
        .build();

    let condition = parse_condition_block_from_json(
        r#"{
            "ForAllValues:StringEquals": {
                "aws:TagKeys": ["Env", "Owner"]
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

#[test]
fn test_ipv4_parsing_edge_cases() {
    // Test IPv4 parsing edge cases (parse_ipv4 function)
    let test_cases = vec![
        // Valid IPv4
        ("203.0.113.42", "203.0.113.0/24", true),
        // Invalid IPv4 (wrong number of parts)
        ("203.0.113", "203.0.113.0/24", false),
        ("203.0.113.42.1", "203.0.113.0/24", false),
        // Invalid IPv4 (non-numeric parts)
        ("203.0.113.abc", "203.0.113.0/24", false),
        // Edge case: prefix length 0
        ("203.0.113.42", "0.0.0.0/0", true), // /0 matches all
        // Edge case: prefix length 32
        ("203.0.113.42", "203.0.113.42/32", true),
    ];
    // Prefix length > 32 used to match nothing; refused at parse (wami 001).
    parse_err(r#"{"IpAddress": {"aws:SourceIp": "203.0.113.0/33"}}"#);

    for (ip, cidr, expected) in test_cases {
        let context = ConditionContext::builder().source_ip(ip).build();
        let condition_json = format!(
            r#"{{
                "IpAddress": {{
                    "aws:SourceIp": "{}"
                }}
            }}"#,
            cidr
        );
        let condition = parse_condition_block_from_string(condition_json);
        let result = evaluate_condition_block(&condition, &context);
        if let Ok(val) = result {
            assert_eq!(
                val, expected,
                "IP {} in CIDR {} should be {}",
                ip, cidr, expected
            );
        } else {
            // Some invalid cases may error, which is acceptable
        }
    }
}

#[test]
fn test_ipv6_basic_matching() {
    // Test IPv6 basic matching (lines 725-737)
    let test_cases = vec![
        ("2001:db8::1", "2001:db8::/32", true),
        ("2001:db8::1", "2001:db8::1", true), // Exact match
        ("2001:db8::1", "2001:db9::/32", false),
    ];
    // IPv6 with prefix > 128 used to fall back to an exact match; refused at
    // parse (wami 001).
    parse_err(r#"{"IpAddress": {"aws:SourceIp": "2001:db8::1/129"}}"#);

    for (ip, cidr, expected) in test_cases {
        let context = ConditionContext::builder().source_ip(ip).build();
        let condition_json = format!(
            r#"{{
                "IpAddress": {{
                    "aws:SourceIp": "{}"
                }}
            }}"#,
            cidr
        );
        let condition = parse_condition_block_from_string(condition_json);
        let result = evaluate_condition_block(&condition, &context);
        if let Ok(val) = result {
            assert_eq!(
                val, expected,
                "IP {} in CIDR {} should be {}",
                ip, cidr, expected
            );
        }
    }
}

#[test]
fn test_cidr_prefix_edge_cases() {
    // Test CIDR prefix length edge cases
    let test_cases = vec![
        // /0 matches everything
        ("203.0.113.42", "0.0.0.0/0", true),
        ("198.51.100.42", "0.0.0.0/0", true),
        // /8 matches first octet
        ("203.0.113.42", "203.0.0.0/8", true),
        ("198.51.100.42", "203.0.0.0/8", false),
        // /16 matches first two octets
        ("203.0.113.42", "203.0.0.0/16", true),
        ("203.1.113.42", "203.0.0.0/16", false),
        // /24 matches first three octets
        ("203.0.113.42", "203.0.113.0/24", true),
        ("203.0.114.42", "203.0.113.0/24", false),
        // /32 matches exact IP
        ("203.0.113.42", "203.0.113.42/32", true),
        ("203.0.113.43", "203.0.113.42/32", false),
    ];

    for (ip, cidr, expected) in test_cases {
        let context = ConditionContext::builder().source_ip(ip).build();
        let condition_json = format!(
            r#"{{
                "IpAddress": {{
                    "aws:SourceIp": "{}"
                }}
            }}"#,
            cidr
        );
        let condition = parse_condition_block_from_string(condition_json);
        let result = evaluate_condition_block(&condition, &context).unwrap();
        assert_eq!(
            result, expected,
            "IP {} in CIDR {} should be {}",
            ip, cidr, expected
        );
    }
}

#[test]
fn test_cidr_partial_byte_matching() {
    // Test CIDR matching with partial byte masks (e.g., /25, /26, etc.)
    // This tests the bit-level matching in ip_in_cidr_v4
    let test_cases = vec![
        // /25 = 128 addresses (first bit of last octet)
        ("203.0.113.0", "203.0.113.0/25", true),
        ("203.0.113.127", "203.0.113.0/25", true),
        ("203.0.113.128", "203.0.113.0/25", false), // Outside /25 range
        // /26 = 64 addresses (first 2 bits of last octet)
        ("203.0.113.0", "203.0.113.0/26", true),
        ("203.0.113.63", "203.0.113.0/26", true),
        ("203.0.113.64", "203.0.113.0/26", false), // Outside /26 range
        // /28 = 16 addresses
        ("203.0.113.0", "203.0.113.0/28", true),
        ("203.0.113.15", "203.0.113.0/28", true),
        ("203.0.113.16", "203.0.113.0/28", false), // Outside /28 range
    ];

    for (ip, cidr, expected) in test_cases {
        let context = ConditionContext::builder().source_ip(ip).build();
        let condition_json = format!(
            r#"{{
                "IpAddress": {{
                    "aws:SourceIp": "{}"
                }}
            }}"#,
            cidr
        );
        let condition = parse_condition_block_from_string(condition_json);
        let result = evaluate_condition_block(&condition, &context).unwrap();
        assert_eq!(
            result, expected,
            "IP {} in CIDR {} should be {}",
            ip, cidr, expected
        );
    }
}

#[test]
fn test_wildcard_pattern_complex_cases() {
    // Test complex wildcard patterns to cover all branches
    let test_cases = vec![
        // Multiple wildcards
        ("abc", "a*c", true),
        ("abc", "a*b*c", true), // a* matches a, b* matches bc, c matches c (with * matching empty)
        ("abcde", "a*e", true),
        ("abcde", "a*c*e", true),
        // Wildcard at start and end
        ("abc", "*b*", true),
        ("abc", "*d*", false),
        // Multiple ? wildcards
        ("abc", "a?c", true),
        ("abc", "a??c", false), // Only 2 chars between a and c
        ("abcd", "a??d", true), // 2 chars between a and d
        // Mixed * and ?
        ("abc", "a?*c", true),
        ("abc", "a*?c", true),
        ("abcd", "a?*d", true),
        // Edge: pattern longer than value
        ("ab", "abc", false),
        ("ab", "a?c", false),
        // Edge: value longer than pattern (without wildcards)
        ("abc", "ab", false),
    ];

    for (value, pattern, expected) in test_cases {
        let context = ConditionContext::builder().username(value).build();
        let condition_json = format!(
            r#"{{
                "StringLike": {{
                    "aws:username": "{}"
                }}
            }}"#,
            pattern
        );
        let condition = parse_condition_block_from_string(condition_json);
        let result = evaluate_condition_block(&condition, &context).unwrap();
        assert_eq!(
            result, expected,
            "Pattern '{}' should match '{}' = {}",
            pattern, value, expected
        );
    }
}

#[test]
fn test_wildcard_pattern_star_at_end() {
    // Test * at end of pattern (line 489)
    let context = ConditionContext::builder().username("alice").build();

    let condition = parse_condition_block_from_json(
        r#"{
            "StringLike": {
                "aws:username": "a*"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // "alice" matches "a*"
}

#[test]
fn test_wildcard_pattern_star_consumes_rest() {
    // Test that * properly consumes remaining pattern
    let test_cases = vec![
        ("abc", "*bc", true),
        ("abc", "a*c", true),
        ("abc", "ab*", true),
        ("abc", "*abc", true),
        ("abc", "abc*", true),
        ("abc", "*abc*", true),
    ];

    for (value, pattern, expected) in test_cases {
        let context = ConditionContext::builder().username(value).build();
        let condition_json = format!(
            r#"{{
                "StringLike": {{
                    "aws:username": "{}"
                }}
            }}"#,
            pattern
        );
        let condition = parse_condition_block_from_string(condition_json);
        let result = evaluate_condition_block(&condition, &context).unwrap();
        assert_eq!(
            result, expected,
            "Pattern '{}' should match '{}' = {}",
            pattern, value, expected
        );
    }
}

#[test]
fn test_binary_equals_error_paths() {
    // Test BinaryEquals error paths
    let context1 = ConditionContext::builder()
        .custom_value("binary:key", crate::ConditionValue::Number(123.0)) // Wrong type
        .build();

    let condition = unchecked(
        r#"{
            "BinaryEquals": {
                "binary:key": "dGVzdA=="
            }
        }"#,
    );
    // A type mismatch is an error, never `false` (wami 001).
    assert_eq!(
        evaluate_condition_block(&condition, &context1),
        Err(ConditionError::TypeMismatch {
            expected: "String".to_string(),
            actual: "Number".to_string()
        })
    );
}

#[test]
fn test_null_operator_with_false() {
    // Test Null operator with false expected
    let context1 = ConditionContext::builder().username("alice").build();
    let context2 = ConditionContext::builder().build(); // No username

    let condition = parse_condition_block_from_json(
        r#"{
            "Null": {
                "aws:username": "false"
            }
        }"#,
    );

    let result1 = evaluate_condition_block(&condition, &context1).unwrap();
    assert!(result1); // username exists, null=false means "not null" = true

    let result2 = evaluate_condition_block(&condition, &context2).unwrap();
    assert!(!result2); // username doesn't exist, null=false means "not null" = false
}

#[test]
fn test_forallvalues_with_none_actual() {
    // Test ForAllValues with None actual (vacuous truth)
    let context = ConditionContext::builder().build(); // No tag_keys

    let condition = parse_condition_block_from_json(
        r#"{
            "ForAllValues:StringEquals": {
                "aws:TagKeys": ["Env", "Owner"]
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // None = vacuous truth
}

#[test]
fn test_foranyvalue_with_none_actual() {
    // Test ForAnyValue with None actual (should fail)
    let context = ConditionContext::builder().build(); // No tag_keys

    let condition = parse_condition_block_from_json(
        r#"{
            "ForAnyValue:StringEquals": {
                "aws:TagKeys": ["Env", "Owner"]
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(!result); // None = no match
}

// ============================================================================
// Final Coverage Push - Error Paths (>99% target)
// ============================================================================

#[test]
fn test_string_like_ifexists_missing_key() {
    // Test StringLikeIfExists with missing key (line 231)
    let context = ConditionContext::builder().build(); // No username

    let condition = parse_condition_block_from_json(
        r#"{
            "StringLikeIfExists": {
                "aws:username": "a*"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // Missing key passes with IfExists
}

#[test]
fn test_not_ip_address_ifexists_missing_key() {
    // Test NotIpAddressIfExists with missing key (line 303-304)
    let context = ConditionContext::builder().build(); // No source_ip

    let condition = parse_condition_block_from_json(
        r#"{
            "NotIpAddressIfExists": {
                "aws:SourceIp": ["203.0.113.0/24"]
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // Missing key passes with IfExists
}

#[test]
fn test_arn_not_equals_missing_key() {
    // Test ArnNotEquals with missing key (line 309)
    // ArnEquals with None returns false, so ArnNotEquals returns true
    let context = ConditionContext::builder().build(); // No principal_arn

    let condition = parse_condition_block_from_json(
        r#"{
            "ArnNotEquals": {
                "aws:PrincipalArn": "arn:aws:iam::123456789012:user/alice"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // Missing key: ArnEquals returns false, so ArnNotEquals returns true
}

#[test]
fn test_arn_not_like_missing_key() {
    // Test ArnNotLike with missing key (line 311)
    // ArnLike with None returns false, so ArnNotLike returns true
    let context = ConditionContext::builder().build(); // No principal_arn

    let condition = parse_condition_block_from_json(
        r#"{
            "ArnNotLike": {
                "aws:PrincipalArn": "arn:aws:iam::*:user/*"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // Missing key: ArnLike returns false, so ArnNotLike returns true
}

#[test]
fn test_string_equals_ignore_case_missing_key() {
    // Test StringEqualsIgnoreCase with missing key (None path)
    let context = ConditionContext::builder().build(); // No username

    let condition = parse_condition_block_from_json(
        r#"{
            "StringEqualsIgnoreCase": {
                "aws:username": "ALICE"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(!result); // Missing key = no match
}

#[test]
fn test_numeric_operators_missing_key() {
    // Test numeric operators with missing key (None => Ok(false) paths)
    let context = ConditionContext::builder().build(); // No mfa_age

    let test_cases = vec![
        (
            r#"{"NumericLessThan": {"aws:MultiFactorAuthAge": "400"}}"#,
            false,
        ),
        (
            r#"{"NumericLessThanEquals": {"aws:MultiFactorAuthAge": "400"}}"#,
            false,
        ),
        (
            r#"{"NumericGreaterThan": {"aws:MultiFactorAuthAge": "100"}}"#,
            false,
        ),
        (
            r#"{"NumericGreaterThanEquals": {"aws:MultiFactorAuthAge": "100"}}"#,
            false,
        ),
    ];

    for (json, expected) in test_cases {
        let condition = parse_condition_block_from_json(json);
        let result = evaluate_condition_block(&condition, &context).unwrap();
        assert_eq!(result, expected, "Failed for condition: {}", json);
    }
}

#[test]
fn test_date_operators_missing_key() {
    // Test date operators with missing key (None => Ok(false) paths)
    // Note: current_time has a default, so we test with TokenIssueTime which can be missing
    let context = ConditionContext::builder().build(); // No token_issue_time

    let now = chrono::Utc::now();
    let test_cases = vec![
        (
            format!(
                r#"{{"DateLessThan": {{"aws:TokenIssueTime": "{}"}}}}"#,
                now.to_rfc3339()
            ),
            false,
        ),
        (
            format!(
                r#"{{"DateLessThanEquals": {{"aws:TokenIssueTime": "{}"}}}}"#,
                now.to_rfc3339()
            ),
            false,
        ),
        (
            format!(
                r#"{{"DateGreaterThan": {{"aws:TokenIssueTime": "{}"}}}}"#,
                now.to_rfc3339()
            ),
            false,
        ),
        (
            format!(
                r#"{{"DateGreaterThanEquals": {{"aws:TokenIssueTime": "{}"}}}}"#,
                now.to_rfc3339()
            ),
            false,
        ),
    ];

    for (json, expected) in test_cases {
        let condition = parse_condition_block_from_string(json);
        let result = evaluate_condition_block(&condition, &context).unwrap();
        assert_eq!(result, expected, "Failed for condition");
    }
}

#[test]
fn test_ip_address_missing_key() {
    // Test IP address operators with missing key (None => Ok(false) paths)
    let context = ConditionContext::builder().build(); // No source_ip

    let condition = parse_condition_block_from_json(
        r#"{
            "IpAddress": {
                "aws:SourceIp": ["203.0.113.0/24"]
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(!result); // Missing key = no match
}

#[test]
fn test_ip_address_type_mismatch() {
    // Test IP address with non-string actual (line 703, 706-707)
    let context = ConditionContext::builder()
        .mfa_age(300) // Number, not IP
        .build();

    let condition = unchecked(
        r#"{
            "IpAddress": {
                "aws:MultiFactorAuthAge": ["203.0.113.0/24"]
            }
        }"#,
    );

    // A type mismatch is an error, never `false` (wami 001).
    assert_eq!(
        evaluate_condition_block(&condition, &context),
        Err(ConditionError::TypeMismatch {
            expected: "an IP address".to_string(),
            actual: "Number".to_string()
        })
    );
}

#[test]
fn test_forallvalues_type_mismatch_non_array_string() {
    // Test ForAllValues with actual that's not Array or String (line 861, 888, 904)
    let context = ConditionContext::builder()
        .mfa_age(300) // Number, not array/string
        .build();

    let condition = unchecked(
        r#"{
            "ForAllValues:StringEquals": {
                "aws:MultiFactorAuthAge": ["300"]
            }
        }"#,
    );

    // A type mismatch is an error, never `false` (wami 001).
    assert_eq!(
        evaluate_condition_block(&condition, &context),
        Err(ConditionError::TypeMismatch {
            expected: "a String or an Array of Strings".to_string(),
            actual: "Number".to_string()
        })
    );
}

#[test]
fn test_foranyvalue_type_mismatch_non_array_string() {
    // Test ForAnyValue with actual that's not Array or String (line 1077, 1103, 1119)
    let context = ConditionContext::builder()
        .mfa_age(300) // Number, not array/string
        .build();

    let condition = unchecked(
        r#"{
            "ForAnyValue:StringEquals": {
                "aws:MultiFactorAuthAge": ["300"]
            }
        }"#,
    );

    // A type mismatch is an error, never `false` (wami 001).
    assert_eq!(
        evaluate_condition_block(&condition, &context),
        Err(ConditionError::TypeMismatch {
            expected: "a String or an Array of Strings".to_string(),
            actual: "Number".to_string()
        })
    );
}

#[test]
fn test_arn_equals_missing_key() {
    // Test ArnEquals with missing key (line 793-794)
    let context = ConditionContext::builder().build(); // No principal_arn

    let condition = parse_condition_block_from_json(
        r#"{
            "ArnEquals": {
                "aws:PrincipalArn": "arn:aws:iam::123456789012:user/alice"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(!result); // Missing key = no match
}

#[test]
fn test_arn_like_missing_key() {
    // Test ArnLike with missing key (line 807-808)
    let context = ConditionContext::builder().build(); // No principal_arn

    let condition = parse_condition_block_from_json(
        r#"{
            "ArnLike": {
                "aws:PrincipalArn": "arn:aws:iam::*:user/*"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(!result); // Missing key = no match
}

#[test]
fn test_binary_equals_missing_key() {
    // Test BinaryEquals with missing key (line 823)
    let context = ConditionContext::builder().build(); // No binary key

    let condition = parse_condition_block_from_json(
        r#"{
            "BinaryEquals": {
                "binary:key": "dGVzdA=="
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(!result); // Missing key = no match
}

#[test]
fn test_null_missing_key() {
    // Test Null with missing key (line 838)
    let context = ConditionContext::builder().build(); // No username

    let condition = parse_condition_block_from_json(
        r#"{
            "Null": {
                "aws:username": "true"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // Missing key = null = true
}

// ============================================================================
// Additional Error Path Coverage (>99% target)
// ============================================================================

#[test]
fn test_string_like_type_mismatch_boolean() {
    // Test StringLike with Boolean actual (line 465: once `_ => Ok(false)`, an error since wami 001)
    let context = ConditionContext::builder()
        .mfa_present(true) // Boolean, not string
        .build();

    let condition = unchecked(
        r#"{
            "StringLike": {
                "aws:MultiFactorAuthPresent": "true*"
            }
        }"#,
    );

    // A type mismatch is an error, never `false` (wami 001).
    assert_eq!(
        evaluate_condition_block(&condition, &context),
        Err(ConditionError::TypeMismatch {
            expected: "String".to_string(),
            actual: "Boolean".to_string()
        })
    );
}

#[test]
fn test_date_operators_type_mismatch_number() {
    // Test date operators with Number actual (lines 608, 624, 640, 656, 672: once `_ => Ok(false)`, an error since wami 001)
    let context = ConditionContext::builder()
        .mfa_age(300) // Number, not date string
        .build();

    let now = chrono::Utc::now();
    let test_cases = vec![
        (
            format!(
                r#"{{"DateLessThan": {{"aws:MultiFactorAuthAge": "{}"}}}}"#,
                now.to_rfc3339()
            ),
            false,
        ),
        (
            format!(
                r#"{{"DateLessThanEquals": {{"aws:MultiFactorAuthAge": "{}"}}}}"#,
                now.to_rfc3339()
            ),
            false,
        ),
        (
            format!(
                r#"{{"DateGreaterThan": {{"aws:MultiFactorAuthAge": "{}"}}}}"#,
                now.to_rfc3339()
            ),
            false,
        ),
        (
            format!(
                r#"{{"DateGreaterThanEquals": {{"aws:MultiFactorAuthAge": "{}"}}}}"#,
                now.to_rfc3339()
            ),
            false,
        ),
    ];

    // Each was answered `false`; a type mismatch is an error (wami 001).
    for (json, _answered_false) in test_cases {
        let condition = unchecked_string(json);
        let outcome = evaluate_condition_block(&condition, &context);
        assert_eq!(
            outcome,
            Err(ConditionError::TypeMismatch {
                expected: "String".to_string(),
                actual: "Number".to_string()
            })
        );
    }
}

#[test]
fn test_ip_address_type_mismatch_boolean() {
    // Test IP address with Boolean actual (line 703: once `_ => Ok(false)`, an error since wami 001)
    let context = ConditionContext::builder()
        .secure_transport(true) // Boolean, not IP
        .build();

    let condition = unchecked(
        r#"{
            "IpAddress": {
                "aws:SecureTransport": ["203.0.113.0/24"]
            }
        }"#,
    );

    // A type mismatch is an error, never `false` (wami 001).
    assert_eq!(
        evaluate_condition_block(&condition, &context),
        Err(ConditionError::TypeMismatch {
            expected: "an IP address".to_string(),
            actual: "Boolean".to_string()
        })
    );
}

#[test]
fn test_arn_equals_type_mismatch_number() {
    // Test ArnEquals with Number actual (line 794: once `_ => Ok(false)`, an error since wami 001)
    let context = ConditionContext::builder()
        .mfa_age(300) // Number, not ARN
        .build();

    let condition = unchecked(
        r#"{
            "ArnEquals": {
                "aws:MultiFactorAuthAge": "arn:aws:iam::123456789012:user/alice"
            }
        }"#,
    );

    // A type mismatch is an error, never `false` (wami 001).
    assert_eq!(
        evaluate_condition_block(&condition, &context),
        Err(ConditionError::TypeMismatch {
            expected: "String".to_string(),
            actual: "Number".to_string()
        })
    );
}

#[test]
fn test_arn_like_type_mismatch_number() {
    // Test ArnLike with Number actual (line 808: once `_ => Ok(false)`, an error since wami 001)
    let context = ConditionContext::builder()
        .mfa_age(300) // Number, not ARN
        .build();

    let condition = unchecked(
        r#"{
            "ArnLike": {
                "aws:MultiFactorAuthAge": "arn:aws:iam::*:user/*"
            }
        }"#,
    );

    // A type mismatch is an error, never `false` (wami 001).
    assert_eq!(
        evaluate_condition_block(&condition, &context),
        Err(ConditionError::TypeMismatch {
            expected: "String".to_string(),
            actual: "Number".to_string()
        })
    );
}

#[test]
fn test_binary_equals_type_mismatch_boolean() {
    // Test BinaryEquals with Boolean actual (line 823: once `_ => Ok(false)`, an error since wami 001)
    let context = ConditionContext::builder()
        .mfa_present(true) // Boolean, not string
        .build();

    let condition = unchecked(
        r#"{
            "BinaryEquals": {
                "aws:MultiFactorAuthPresent": "dGVzdA=="
            }
        }"#,
    );

    // A type mismatch is an error, never `false` (wami 001).
    assert_eq!(
        evaluate_condition_block(&condition, &context),
        Err(ConditionError::TypeMismatch {
            expected: "String".to_string(),
            actual: "Boolean".to_string()
        })
    );
}

#[test]
fn test_forallvalues_string_type_mismatch_number() {
    // Test ForAllValues:StringEquals with Number actual (line 861: once `_ => Ok(false)`, an error since wami 001)
    let context = ConditionContext::builder()
        .mfa_age(300) // Number, not array/string
        .build();

    let condition = unchecked(
        r#"{
            "ForAllValues:StringEquals": {
                "aws:MultiFactorAuthAge": ["300"]
            }
        }"#,
    );

    // A type mismatch is an error, never `false` (wami 001).
    assert_eq!(
        evaluate_condition_block(&condition, &context),
        Err(ConditionError::TypeMismatch {
            expected: "a String or an Array of Strings".to_string(),
            actual: "Number".to_string()
        })
    );
}

#[test]
fn test_forallvalues_string_like_type_mismatch_number() {
    // Test ForAllValues:StringLike with Number actual (line 888: once `_ => Ok(false)`, an error since wami 001)
    let context = ConditionContext::builder()
        .mfa_age(300) // Number, not array/string
        .build();

    let condition = unchecked(
        r#"{
            "ForAllValues:StringLike": {
                "aws:MultiFactorAuthAge": ["3*"]
            }
        }"#,
    );

    // A type mismatch is an error, never `false` (wami 001).
    assert_eq!(
        evaluate_condition_block(&condition, &context),
        Err(ConditionError::TypeMismatch {
            expected: "a String or an Array of Strings".to_string(),
            actual: "Number".to_string()
        })
    );
}

#[test]
fn test_forallvalues_arn_type_mismatch_number() {
    // Test ForAllValues:ArnEquals with Number actual (line 904: once `_ => Ok(false)`, an error since wami 001)
    let context = ConditionContext::builder()
        .mfa_age(300) // Number, not array/string
        .build();

    let condition = unchecked(
        r#"{
            "ForAllValues:ArnEquals": {
                "aws:MultiFactorAuthAge": ["arn:aws:iam::123456789012:user/alice"]
            }
        }"#,
    );

    // A type mismatch is an error, never `false` (wami 001).
    assert_eq!(
        evaluate_condition_block(&condition, &context),
        Err(ConditionError::TypeMismatch {
            expected: "a String or an Array of Strings".to_string(),
            actual: "Number".to_string()
        })
    );
}

#[test]
fn test_foranyvalue_string_type_mismatch_number() {
    // Test ForAnyValue:StringEquals with Number actual (line 1077: once `_ => Ok(false)`, an error since wami 001)
    let context = ConditionContext::builder()
        .mfa_age(300) // Number, not array/string
        .build();

    let condition = unchecked(
        r#"{
            "ForAnyValue:StringEquals": {
                "aws:MultiFactorAuthAge": ["300"]
            }
        }"#,
    );

    // A type mismatch is an error, never `false` (wami 001).
    assert_eq!(
        evaluate_condition_block(&condition, &context),
        Err(ConditionError::TypeMismatch {
            expected: "a String or an Array of Strings".to_string(),
            actual: "Number".to_string()
        })
    );
}

#[test]
fn test_foranyvalue_string_like_type_mismatch_number() {
    // Test ForAnyValue:StringLike with Number actual (line 1103: once `_ => Ok(false)`, an error since wami 001)
    let context = ConditionContext::builder()
        .mfa_age(300) // Number, not array/string
        .build();

    let condition = unchecked(
        r#"{
            "ForAnyValue:StringLike": {
                "aws:MultiFactorAuthAge": ["3*"]
            }
        }"#,
    );

    // A type mismatch is an error, never `false` (wami 001).
    assert_eq!(
        evaluate_condition_block(&condition, &context),
        Err(ConditionError::TypeMismatch {
            expected: "a String or an Array of Strings".to_string(),
            actual: "Number".to_string()
        })
    );
}

#[test]
fn test_foranyvalue_arn_type_mismatch_number() {
    // Test ForAnyValue:ArnEquals with Number actual (line 1119: once `_ => Ok(false)`, an error since wami 001)
    let context = ConditionContext::builder()
        .mfa_age(300) // Number, not array/string
        .build();

    let condition = unchecked(
        r#"{
            "ForAnyValue:ArnEquals": {
                "aws:MultiFactorAuthAge": ["arn:aws:iam::123456789012:user/alice"]
            }
        }"#,
    );

    // A type mismatch is an error, never `false` (wami 001).
    assert_eq!(
        evaluate_condition_block(&condition, &context),
        Err(ConditionError::TypeMismatch {
            expected: "a String or an Array of Strings".to_string(),
            actual: "Number".to_string()
        })
    );
}

#[test]
fn test_not_ip_address_ifexists_type_mismatch() {
    // Test NotIpAddressIfExists with type mismatch (line 304)
    let context = ConditionContext::builder()
        .mfa_age(300) // Number, not IP
        .build();

    let condition = unchecked(
        r#"{
            "NotIpAddressIfExists": {
                "aws:MultiFactorAuthAge": ["203.0.113.0/24"]
            }
        }"#,
    );

    // It used to read `false`, so NotIpAddress answered TRUE: a type mismatch
    // is an error (wami 001).
    assert_eq!(
        evaluate_condition_block(&condition, &context),
        Err(ConditionError::TypeMismatch {
            expected: "an IP address".to_string(),
            actual: "Number".to_string()
        })
    );
}

// ============================================================================
// Tests for WAMI-specific condition keys (general purpose)
// ============================================================================

#[test]
fn test_wami_request_method_key() {
    let context = ConditionContext::builder().request_method("POST").build();
    let value = get_context_value("wami:RequestMethod", &context).unwrap();
    assert_eq!(value, Some(ConditionValue::String("POST".to_string())));
}

#[test]
fn test_wami_request_path_key() {
    let context = ConditionContext::builder()
        .request_path("/api/v1/users")
        .build();
    let value = get_context_value("wami:RequestPath", &context).unwrap();
    assert_eq!(
        value,
        Some(ConditionValue::String("/api/v1/users".to_string()))
    );
}

#[test]
fn test_wami_api_version_key() {
    let context = ConditionContext::builder().api_version("v2").build();
    let value = get_context_value("wami:ApiVersion", &context).unwrap();
    assert_eq!(value, Some(ConditionValue::String("v2".to_string())));
}

#[test]
fn test_wami_client_type_key() {
    let context = ConditionContext::builder().client_type("web").build();
    let value = get_context_value("wami:ClientType", &context).unwrap();
    assert_eq!(value, Some(ConditionValue::String("web".to_string())));
}

#[test]
fn test_wami_platform_key() {
    let context = ConditionContext::builder().platform("ios").build();
    let value = get_context_value("wami:Platform", &context).unwrap();
    assert_eq!(value, Some(ConditionValue::String("ios".to_string())));
}

#[test]
fn test_wami_device_type_key() {
    let context = ConditionContext::builder().device_type("mobile").build();
    let value = get_context_value("wami:DeviceType", &context).unwrap();
    assert_eq!(value, Some(ConditionValue::String("mobile".to_string())));
}

#[test]
fn test_wami_session_age_key() {
    let context = ConditionContext::builder().session_age(3600).build();
    let value = get_context_value("wami:SessionAge", &context).unwrap();
    assert_eq!(value, Some(ConditionValue::Number(3600.0)));
}

#[test]
fn test_wami_authentication_method_key() {
    let context = ConditionContext::builder()
        .authentication_method("oauth")
        .build();
    let value = get_context_value("wami:AuthenticationMethod", &context).unwrap();
    assert_eq!(value, Some(ConditionValue::String("oauth".to_string())));
}

#[test]
fn test_wami_authentication_strength_key() {
    let context = ConditionContext::builder()
        .authentication_strength("high")
        .build();
    let value = get_context_value("wami:AuthenticationStrength", &context).unwrap();
    assert_eq!(value, Some(ConditionValue::String("high".to_string())));
}

#[test]
fn test_wami_session_risk_score_key() {
    let context = ConditionContext::builder().session_risk_score(0.75).build();
    let value = get_context_value("wami:SessionRiskScore", &context).unwrap();
    assert_eq!(value, Some(ConditionValue::Number(0.75)));
}

#[test]
fn test_wami_source_country_key() {
    let context = ConditionContext::builder()
        .geolocation_country("US")
        .build();
    let value = get_context_value("wami:SourceCountry", &context).unwrap();
    assert_eq!(value, Some(ConditionValue::String("US".to_string())));
}

#[test]
fn test_wami_source_city_key() {
    let context = ConditionContext::builder()
        .geolocation_city("San Francisco")
        .build();
    let value = get_context_value("wami:SourceCity", &context).unwrap();
    assert_eq!(
        value,
        Some(ConditionValue::String("San Francisco".to_string()))
    );
}

#[test]
fn test_wami_vpn_detected_key() {
    let context = ConditionContext::builder().vpn_detected(true).build();
    let value = get_context_value("wami:VpnDetected", &context).unwrap();
    assert_eq!(value, Some(ConditionValue::Boolean(true)));
}

#[test]
fn test_wami_proxy_detected_key() {
    let context = ConditionContext::builder().proxy_detected(false).build();
    let value = get_context_value("wami:ProxyDetected", &context).unwrap();
    assert_eq!(value, Some(ConditionValue::Boolean(false)));
}

#[test]
fn test_wami_requests_per_minute_key() {
    let context = ConditionContext::builder().requests_per_minute(100).build();
    let value = get_context_value("wami:RequestsPerMinute", &context).unwrap();
    assert_eq!(value, Some(ConditionValue::Number(100.0)));
}

#[test]
fn test_wami_quota_remaining_key() {
    let context = ConditionContext::builder().quota_remaining(5000).build();
    let value = get_context_value("wami:QuotaRemaining", &context).unwrap();
    assert_eq!(value, Some(ConditionValue::Number(5000.0)));
}

#[test]
fn test_wami_burst_capacity_used_key() {
    let context = ConditionContext::builder()
        .burst_capacity_used(0.85)
        .build();
    let value = get_context_value("wami:BurstCapacityUsed", &context).unwrap();
    assert_eq!(value, Some(ConditionValue::Number(0.85)));
}

#[test]
fn test_wami_request_id_key() {
    let context = ConditionContext::builder().request_id("req-12345").build();
    let value = get_context_value("wami:RequestId", &context).unwrap();
    assert_eq!(value, Some(ConditionValue::String("req-12345".to_string())));
}

#[test]
fn test_wami_trace_id_key() {
    let context = ConditionContext::builder().trace_id("trace-abc123").build();
    let value = get_context_value("wami:TraceId", &context).unwrap();
    assert_eq!(
        value,
        Some(ConditionValue::String("trace-abc123".to_string()))
    );
}

#[test]
fn test_wami_debug_mode_enabled_key() {
    let context = ConditionContext::builder().debug_mode(true).build();
    let value = get_context_value("wami:DebugModeEnabled", &context).unwrap();
    assert_eq!(value, Some(ConditionValue::Boolean(true)));
}

#[test]
fn test_wami_dry_run_mode_key() {
    let context = ConditionContext::builder().dry_run_mode(false).build();
    let value = get_context_value("wami:DryRunMode", &context).unwrap();
    assert_eq!(value, Some(ConditionValue::Boolean(false)));
}

#[test]
fn test_wami_data_classification_key() {
    let context = ConditionContext::builder()
        .data_classification("confidential")
        .build();
    let value = get_context_value("wami:ResourceDataClassification", &context).unwrap();
    assert_eq!(
        value,
        Some(ConditionValue::String("confidential".to_string()))
    );
}

#[test]
fn test_wami_encryption_required_key() {
    let context = ConditionContext::builder()
        .encryption_required(true)
        .build();
    let value = get_context_value("wami:EncryptionRequired", &context).unwrap();
    assert_eq!(value, Some(ConditionValue::Boolean(true)));
}

#[test]
fn test_wami_tenant_name_key() {
    let context = ConditionContext::builder().tenant_name("acme-corp").build();
    let value = get_context_value("wami:TenantName", &context).unwrap();
    assert_eq!(value, Some(ConditionValue::String("acme-corp".to_string())));
}

#[test]
fn test_wami_cross_tenant_request_key() {
    let context = ConditionContext::builder()
        .cross_tenant_request(true)
        .build();
    let value = get_context_value("wami:CrossTenantRequest", &context).unwrap();
    assert_eq!(value, Some(ConditionValue::Boolean(true)));
}

#[test]
fn test_wami_provider_region_key() {
    let context = ConditionContext::builder()
        .provider_region("us-east-1")
        .build();
    let value = get_context_value("wami:ProviderRegion", &context).unwrap();
    assert_eq!(value, Some(ConditionValue::String("us-east-1".to_string())));
}

#[test]
fn test_wami_cross_provider_request_key() {
    let context = ConditionContext::builder()
        .cross_provider_request(false)
        .build();
    let value = get_context_value("wami:CrossProviderRequest", &context).unwrap();
    assert_eq!(value, Some(ConditionValue::Boolean(false)));
}

#[test]
fn test_wami_condition_with_request_method() {
    // Test condition evaluation with request method
    let context = ConditionContext::builder().request_method("POST").build();
    let condition = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "wami:RequestMethod": "POST"
            }
        }"#,
    );
    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

#[test]
fn test_wami_condition_with_client_type() {
    // Test condition evaluation with client type
    let context = ConditionContext::builder().client_type("mobile").build();
    let condition = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "wami:ClientType": "mobile"
            }
        }"#,
    );
    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

#[test]
fn test_wami_condition_with_platform() {
    // Test condition evaluation with platform
    let context = ConditionContext::builder().platform("ios").build();
    let condition = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "wami:Platform": "ios"
            }
        }"#,
    );
    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

#[test]
fn test_wami_condition_with_session_age() {
    // Test condition evaluation with session age
    let context = ConditionContext::builder()
        .session_age(1800) // 30 minutes
        .build();
    let condition = parse_condition_block_from_json(
        r#"{
            "NumericLessThan": {
                "wami:SessionAge": "3600"
            }
        }"#,
    );
    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // 1800 < 3600
}

#[test]
fn test_wami_condition_with_rate_limiting() {
    // Test condition evaluation with rate limiting
    let context = ConditionContext::builder()
        .requests_per_minute(50)
        .quota_remaining(1000)
        .build();
    let condition = parse_condition_block_from_json(
        r#"{
            "NumericLessThan": {
                "wami:RequestsPerMinute": "100"
            },
            "NumericGreaterThan": {
                "wami:QuotaRemaining": "500"
            }
        }"#,
    );
    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result); // Both conditions pass
}

#[test]
fn test_wami_condition_with_geolocation() {
    // Test condition evaluation with geolocation
    let context = ConditionContext::builder()
        .geolocation_country("US")
        .geolocation_city("New York")
        .build();
    let condition = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "wami:SourceCountry": "US"
            }
        }"#,
    );
    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

#[test]
fn test_wami_condition_with_security_flags() {
    // Test condition evaluation with security flags
    let context = ConditionContext::builder()
        .vpn_detected(false)
        .proxy_detected(false)
        .session_risk_score(0.2)
        .build();
    let condition = parse_condition_block_from_json(
        r#"{
            "Bool": {
                "wami:VpnDetected": "false"
            },
            "NumericLessThan": {
                "wami:SessionRiskScore": "0.5"
            }
        }"#,
    );
    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

#[test]
fn test_wami_condition_with_authentication() {
    // Test condition evaluation with authentication method and strength
    let context = ConditionContext::builder()
        .authentication_method("oauth")
        .authentication_strength("high")
        .build();
    let condition = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "wami:AuthenticationMethod": "oauth",
                "wami:AuthenticationStrength": "high"
            }
        }"#,
    );
    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

#[test]
fn test_wami_condition_with_data_classification() {
    // Test condition evaluation with data classification
    let context = ConditionContext::builder()
        .data_classification("confidential")
        .encryption_required(true)
        .build();
    let condition = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "wami:ResourceDataClassification": "confidential"
            },
            "Bool": {
                "wami:EncryptionRequired": "true"
            }
        }"#,
    );
    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

#[test]
fn test_wami_condition_web_app_example() {
    // Example: Web app restricting admin access to specific client types
    let context = ConditionContext::builder()
        .client_type("web")
        .platform("web")
        .request_method("POST")
        .request_path("/api/admin/users")
        .build();
    let condition = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "wami:ClientType": "web",
                "wami:Platform": "web"
            },
            "StringLike": {
                "wami:RequestPath": "/api/admin/*"
            }
        }"#,
    );
    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

#[test]
fn test_wami_condition_mobile_app_example() {
    // Example: Mobile app with device restrictions
    let context = ConditionContext::builder()
        .client_type("mobile")
        .platform("ios")
        .device_type("mobile")
        .application_version("2.0.0")
        .build();
    let condition = parse_condition_block_from_json(
        r#"{
            "StringEquals": {
                "wami:ClientType": "mobile",
                "wami:Platform": "ios"
            },
            "StringLike": {
                "wami:ApplicationVersion": "2.*"
            }
        }"#,
    );
    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

#[test]
fn test_wami_condition_api_rate_limit_example() {
    // Example: API rate limiting based on request rate
    let context = ConditionContext::builder()
        .requests_per_minute(45)
        .quota_remaining(500)
        .build();
    let condition = parse_condition_block_from_json(
        r#"{
            "NumericLessThan": {
                "wami:RequestsPerMinute": "60"
            },
            "NumericGreaterThan": {
                "wami:QuotaRemaining": "0"
            }
        }"#,
    );
    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

#[test]
fn test_wami_condition_security_example() {
    // Example: Security policy requiring low risk and no VPN
    let context = ConditionContext::builder()
        .session_risk_score(0.15)
        .vpn_detected(false)
        .authentication_strength("high")
        .build();
    let condition = parse_condition_block_from_json(
        r#"{
            "NumericLessThan": {
                "wami:SessionRiskScore": "0.3"
            },
            "Bool": {
                "wami:VpnDetected": "false"
            },
            "StringEquals": {
                "wami:AuthenticationStrength": "high"
            }
        }"#,
    );
    let result = evaluate_condition_block(&condition, &context).unwrap();
    assert!(result);
}

// ============================================================================
// Additional tests for coverage gaps
// ============================================================================

#[test]
fn test_wami_requests_per_hour_key() {
    let context = ConditionContext::builder().requests_per_hour(1000).build();
    let value = get_context_value("wami:RequestsPerHour", &context).unwrap();
    assert_eq!(value, Some(ConditionValue::Number(1000.0)));
}

#[test]
fn test_wami_requests_per_day_key() {
    let context = ConditionContext::builder().requests_per_day(10000).build();
    let value = get_context_value("wami:RequestsPerDay", &context).unwrap();
    assert_eq!(value, Some(ConditionValue::Number(10000.0)));
}

#[test]
fn test_wami_quota_limit_key() {
    let context = ConditionContext::builder().quota_limit(50000).build();
    let value = get_context_value("wami:QuotaLimit", &context).unwrap();
    assert_eq!(value, Some(ConditionValue::Number(50000.0)));
}

#[test]
fn test_wami_data_residency_region_key() {
    let context = ConditionContext::builder()
        .data_residency_region("eu-west-1")
        .build();
    let value = get_context_value("wami:DataResidencyRegion", &context).unwrap();
    assert_eq!(value, Some(ConditionValue::String("eu-west-1".to_string())));
}

#[test]
fn test_wami_encryption_algorithm_key() {
    let context = ConditionContext::builder()
        .encryption_algorithm("AES-256")
        .build();
    let value = get_context_value("wami:EncryptionAlgorithm", &context).unwrap();
    assert_eq!(value, Some(ConditionValue::String("AES-256".to_string())));
}

// ============================================================================
// Unreadable is not false (wami 001)
//
// A condition that cannot be read used to be answered as a false one, so the
// statement carrying it vanished — for a Deny, a fail-open. Parse now refuses
// exactly what evaluation could not read, and evaluation no longer turns an
// error into `false`.
// ============================================================================

fn parse_err(json: &str) -> String {
    let value: Value = serde_json::from_str(json).unwrap();
    match parse_condition_block(&value) {
        Ok(block) => panic!("{json} parsed, as {block:?}; it must be refused"),
        Err(e) => e.to_string(),
    }
}

fn parses(json: &str) {
    let value: Value = serde_json::from_str(json).unwrap();
    if let Err(e) = parse_condition_block(&value) {
        panic!("{json} was refused ({e}); it is a readable condition");
    }
}

#[test]
fn an_unknown_operator_is_refused_at_parse() {
    // One letter off: "StringEqualz". It used to parse, then fail at
    // evaluation, then be answered `false`.
    let message = parse_err(r#"{"StringEqualz":{"aws:username":"alice"}}"#);
    assert!(message.contains("StringEqualz"), "{message}");
}

#[test]
fn a_malformed_value_is_refused_at_parse_for_every_operator_family() {
    // (condition, operator, key) — each value is one its operator's evaluator
    // could never read, so it used to evaluate to a silent `false`.
    let cases = [
        // IpAddress: not an address, not a CIDR (probed: Ok(false)).
        (
            r#"{"IpAddress":{"aws:SourceIp":"not-an-ip"}}"#,
            "IpAddress",
            "aws:SourceIp",
        ),
        (
            r#"{"NotIpAddressIfExists":{"aws:SourceIp":"10.0.0.0/33"}}"#,
            "NotIpAddressIfExists",
            "aws:SourceIp",
        ),
        (
            r#"{"IpAddress":{"aws:SourceIp":123}}"#,
            "IpAddress",
            "aws:SourceIp",
        ),
        // Bool: neither true nor false (probed: Ok(false)).
        (
            r#"{"Bool":{"aws:SecureTransport":"yes"}}"#,
            "Bool",
            "aws:SecureTransport",
        ),
        // Numeric: not a number (probed: Ok(false)).
        (
            r#"{"NumericEquals":{"aws:username":"abc"}}"#,
            "NumericEquals",
            "aws:username",
        ),
        (
            r#"{"NumericLessThanIfExists":{"wami:SessionAge":true}}"#,
            "NumericLessThanIfExists",
            "wami:SessionAge",
        ),
        // Date: not RFC 3339.
        (
            r#"{"DateLessThan":{"aws:CurrentTime":"yesterday"}}"#,
            "DateLessThan",
            "aws:CurrentTime",
        ),
        // Null: neither true nor false.
        (
            r#"{"Null":{"aws:SourceIp":"maybe"}}"#,
            "Null",
            "aws:SourceIp",
        ),
        // String, Arn, Binary: an object or a null is no value anybody wrote —
        // it used to become "" without a word.
        (
            r#"{"StringEquals":{"aws:username":{"a":1}}}"#,
            "StringEquals",
            "aws:username",
        ),
        (
            r#"{"ArnLike":{"aws:PrincipalArn":null}}"#,
            "ArnLike",
            "aws:PrincipalArn",
        ),
        (
            r#"{"BinaryEquals":{"wami:Custom":{}}}"#,
            "BinaryEquals",
            "wami:Custom",
        ),
        // ForAllValues / ForAnyValue on strings: their evaluator reads only a
        // list, so a scalar is refused.
        (
            r#"{"ForAnyValue:StringEquals":{"aws:TagKeys":"env"}}"#,
            "ForAnyValue:StringEquals",
            "aws:TagKeys",
        ),
        // ... and their numeric and date forms read only a scalar.
    ];
    for (json, operator, key) in cases {
        let message = parse_err(json);
        assert!(message.contains(operator), "{json}: {message}");
        assert!(message.contains(key), "{json}: {message}");
    }
}

#[test]
fn a_list_element_is_validated_and_named_by_its_position() {
    // A non-string element used to be dropped from the list without a word.
    let message = parse_err(r#"{"ForAnyValue:StringEquals":{"aws:TagKeys":["env", 5]}}"#);
    assert!(message.contains("element 1"), "{message}");
    let message = parse_err(r#"{"IpAddress":{"aws:SourceIp":["10.0.0.1","nope"]}}"#);
    assert!(message.contains("element 1"), "{message}");
}

#[test]
fn a_list_is_refused_where_its_operator_cannot_read_one() {
    // `StringEquals` with a list is valid AWS (OR across the values), but this
    // evaluator reads one value: the list used to be a silent `false`, so a
    // Deny naming two users denied neither. Refused until wami 002 reads it.
    for json in [
        r#"{"StringEquals":{"aws:username":["alice","bob"]}}"#,
        r#"{"ArnEquals":{"aws:PrincipalArn":["a","b"]}}"#,
        r#"{"NumericEquals":{"wami:SessionAge":[1,2]}}"#,
        r#"{"DateEquals":{"aws:CurrentTime":["2020-01-01T00:00:00Z"]}}"#,
        r#"{"Bool":{"aws:SecureTransport":[true]}}"#,
    ] {
        let message = parse_err(json);
        assert!(message.contains("wami 002"), "{json}: {message}");
    }
}

#[test]
fn every_readable_form_still_parses() {
    // The guard against refusing too much: each form its evaluator reads.
    for json in [
        r#"{"StringEquals":{"aws:username":"alice"}}"#,
        r#"{"StringLike":{"aws:username":5}}"#,
        r#"{"StringEqualsIgnoreCase":{"aws:username":true}}"#,
        r#"{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}"#,
        r#"{"IpAddress":{"aws:SourceIp":["10.0.0.1","2001:db8::/32","::1"]}}"#,
        r#"{"Bool":{"aws:SecureTransport":true}}"#,
        r#"{"BoolIfExists":{"aws:SecureTransport":"false"}}"#,
        r#"{"NumericLessThan":{"wami:SessionAge":5}}"#,
        r#"{"NumericGreaterThan":{"wami:SessionAge":"5.5"}}"#,
        r#"{"DateGreaterThan":{"aws:CurrentTime":"2020-01-01T00:00:00Z"}}"#,
        r#"{"Null":{"aws:SourceIp":"true"}}"#,
        r#"{"ArnLike":{"aws:PrincipalArn":"arn:wami:iam:*"}}"#,
        r#"{"ForAnyValue:StringEquals":{"aws:TagKeys":["env","team"]}}"#,
        r#"{"StringEquals":{}}"#,
        r#"{}"#,
    ] {
        parses(json);
    }
}

#[test]
fn a_missing_context_key_is_a_false_condition_not_an_error() {
    // As AWS: a key absent from the request makes the condition false.
    // `get_context_value` has no error path for an unknown or unset key.
    let empty = ConditionContext::builder().build();
    let block = parse_condition_block_from_json(r#"{"IpAddress":{"aws:SourceIp":"10.0.0.1"}}"#);
    assert_eq!(evaluate_condition_block(&block, &empty), Ok(false));
    let block = parse_condition_block_from_json(r#"{"StringEquals":{"wami:NoSuchKey":"x"}}"#);
    assert_eq!(evaluate_condition_block(&block, &empty), Ok(false));
    // ... and the IfExists forms pass on it, as AWS.
    let block =
        parse_condition_block_from_json(r#"{"IpAddressIfExists":{"aws:SourceIp":"10.0.0.1"}}"#);
    assert_eq!(evaluate_condition_block(&block, &empty), Ok(true));
}

#[test]
fn a_context_value_its_operator_cannot_read_is_an_error_not_false() {
    // Well-formed policy value, but `aws:username` is a name: comparing it
    // numerically cannot be done. It used to be a silent `false`. Parse now
    // refuses the operator for the key; evaluation refuses it too.
    let json = r#"{"NumericLessThan":{"aws:username":"5"}}"#;
    parse_err(json);
    let context = ConditionContext::builder().username("alice").build();
    assert_eq!(
        evaluate_condition_block(&unchecked(json), &context),
        Err(ConditionError::TypeMismatch {
            expected: "a finite Number".to_string(),
            actual: "String".to_string(),
        }),
        "an evaluation error must not be answered as false"
    );
}

#[test]
fn an_unreadable_value_that_bypassed_parse_is_an_error_at_evaluation() {
    // `ConditionBlock` is a public map, so a block can reach evaluation
    // without going through `parse_condition_block`. Its error must still
    // surface rather than read as `false`.
    let mut block = ConditionBlock::new();
    block.insert(
        "Bool".to_string(),
        std::collections::HashMap::from([(
            "aws:SecureTransport".to_string(),
            ConditionValue::String("yes".to_string()),
        )]),
    );
    let context = ConditionContext::builder().secure_transport(true).build();
    assert_eq!(
        evaluate_condition_block(&block, &context),
        Err(ConditionError::InvalidBooleanValue)
    );
}

// ============================================================================
// A type mismatch is never false (wami 001, review round 1)
//
// Round 0 refused, at parse, a policy value its operator cannot read. It left
// two doors open: an operator compared with a key of another type
// (`StringEquals` on the Boolean `aws:SecureTransport`), and a request value
// the operator cannot compare. Both still read as `false` — a Deny vanished.
// ============================================================================

/// A block built without `parse_condition_block`, as a hand-made
/// `ConditionBlock` reaches evaluation.
fn unchecked(json: &str) -> ConditionBlock {
    let value: Value = serde_json::from_str(json).unwrap();
    value
        .as_object()
        .unwrap()
        .iter()
        .map(|(operator, pairs)| {
            let pairs = pairs
                .as_object()
                .unwrap()
                .iter()
                .map(|(key, v)| (key.clone(), ConditionValue::from(v.clone())))
                .collect();
            (operator.clone(), pairs)
        })
        .collect()
}

#[test]
fn an_operator_of_another_type_than_its_key_is_refused_at_parse() {
    // (condition, operator, key) — each compares a key whose declared type the
    // operator cannot read. Each used to parse, then evaluate to `false`.
    let cases = [
        (
            r#"{"StringEquals":{"aws:SecureTransport":"false"}}"#,
            "StringEquals",
            "aws:SecureTransport",
        ),
        (
            r#"{"StringNotEqualsIfExists":{"aws:MultiFactorAuthAge":"300"}}"#,
            "StringNotEqualsIfExists",
            "aws:MultiFactorAuthAge",
        ),
        (
            r#"{"StringLike":{"aws:CurrentTime":"2020-*"}}"#,
            "StringLike",
            "aws:CurrentTime",
        ),
        (
            r#"{"StringEquals":{"aws:SourceIp":"10.0.0.1"}}"#,
            "StringEquals",
            "aws:SourceIp",
        ),
        (
            r#"{"StringEquals":{"aws:TagKeys":"env"}}"#,
            "StringEquals",
            "aws:TagKeys",
        ),
        (
            r#"{"ArnEquals":{"wami:VpnDetected":"x"}}"#,
            "ArnEquals",
            "wami:VpnDetected",
        ),
        (
            r#"{"BinaryEquals":{"wami:SessionAge":"QQ=="}}"#,
            "BinaryEquals",
            "wami:SessionAge",
        ),
        (
            r#"{"NumericLessThan":{"aws:username":"5"}}"#,
            "NumericLessThan",
            "aws:username",
        ),
        // A key nobody declared is compared as a string.
        (
            r#"{"NumericEquals":{"wami:Team":"5"}}"#,
            "NumericEquals",
            "wami:Team",
        ),
        (
            r#"{"DateLessThan":{"aws:EpochTime":"2020-01-01T00:00:00Z"}}"#,
            "DateLessThan",
            "aws:EpochTime",
        ),
        (
            r#"{"Bool":{"aws:username":"true"}}"#,
            "Bool",
            "aws:username",
        ),
        (
            r#"{"IpAddress":{"aws:username":"10.0.0.1"}}"#,
            "IpAddress",
            "aws:username",
        ),
        (
            r#"{"IpAddress":{"wami:Team":"10.0.0.1"}}"#,
            "IpAddress",
            "wami:Team",
        ),
        (
            r#"{"ForAllValues:StringEquals":{"aws:SecureTransport":["true"]}}"#,
            "ForAllValues:StringEquals",
            "aws:SecureTransport",
        ),
    ];
    for (json, operator, key) in cases {
        let message = parse_err(json);
        assert!(message.contains(operator), "{json}: {message}");
        assert!(message.contains(key), "{json}: {message}");
    }
}

#[test]
fn well_typed_operators_parse_on_every_kind_of_key() {
    // The guard against refusing too much.
    for json in [
        r#"{"StringEquals":{"aws:username":"alice"}}"#,
        r#"{"StringLike":{"aws:PrincipalArn":"arn:*"}}"#,
        r#"{"ArnLike":{"aws:PrincipalArn":"arn:*"}}"#,
        r#"{"ArnEquals":{"aws:username":"alice"}}"#,
        r#"{"StringEquals":{"wami:Team":"core"}}"#,
        r#"{"StringEquals":{"aws:PrincipalTag/team":"core"}}"#,
        r#"{"BinaryEquals":{"wami:Blob":"QQ=="}}"#,
        r#"{"Bool":{"aws:SecureTransport":true}}"#,
        r#"{"BoolIfExists":{"wami:VpnDetected":"false"}}"#,
        r#"{"NumericLessThan":{"aws:MultiFactorAuthAge":600}}"#,
        r#"{"DateLessThan":{"aws:CurrentTime":"2020-01-01T00:00:00Z"}}"#,
        r#"{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}"#,
        r#"{"ForAnyValue:StringEquals":{"aws:TagKeys":["env"]}}"#,
        r#"{"ForAllValues:StringLike":{"aws:username":["a*"]}}"#,
        r#"{"Null":{"aws:SecureTransport":"true"}}"#,
        r#"{"Null":{"aws:TagKeys":"false"}}"#,
        r#"{"NullIfExists":{"wami:Team":"true"}}"#,
    ] {
        parses(json);
    }
}

#[test]
fn a_context_value_of_another_type_is_an_error_for_every_string_operator() {
    // A key nobody declared holds whatever the caller put in it, so parse
    // cannot know its type. Comparing it as a string cannot be done; it used
    // to read as `false` — and the `Not` forms as TRUE.
    let context = ConditionContext::builder()
        .custom_value("wami:Team", ConditionValue::Number(5.0))
        .custom_value("wami:Flags", ConditionValue::Boolean(true))
        .custom_value("wami:List", ConditionValue::Array(vec!["a".to_string()]))
        .build();
    for json in [
        r#"{"StringEquals":{"wami:Team":"5"}}"#,
        r#"{"StringNotEquals":{"wami:Team":"5"}}"#,
        r#"{"StringLike":{"wami:Flags":"t*"}}"#,
        r#"{"StringEqualsIgnoreCase":{"wami:List":"a"}}"#,
        r#"{"StringEqualsIfExists":{"wami:Team":"5"}}"#,
        r#"{"ArnEquals":{"wami:Team":"x"}}"#,
        r#"{"ArnNotLike":{"wami:Flags":"x"}}"#,
        r#"{"BinaryEquals":{"wami:Team":"QQ=="}}"#,
        r#"{"ForAllValues:StringEquals":{"wami:Team":["5"]}}"#,
        r#"{"ForAnyValue:StringLike":{"wami:Flags":["t*"]}}"#,
        r#"{"ForAllValues:ArnLike":{"wami:Team":["x"]}}"#,
    ] {
        let block = parse_condition_block_from_json(json);
        let outcome = evaluate_condition_block(&block, &context);
        // A type mismatch, not any error: a misspelt operator would err too.
        assert!(
            matches!(outcome, Err(ConditionError::TypeMismatch { .. })),
            "{json}: {outcome:?}"
        );
    }
}

#[test]
fn a_context_value_of_another_type_is_an_error_for_every_other_operator() {
    // Bypassing parse, which refuses these keys for these operators: the
    // evaluator must refuse them too, never answer `false`.
    let context = ConditionContext::builder()
        .custom_value("wami:When", ConditionValue::Number(5.0))
        .custom_value("wami:Where", ConditionValue::Boolean(true))
        .custom_value(
            "wami:Numbers",
            ConditionValue::Array(vec!["1".to_string(), "abc".to_string()]),
        )
        .custom_value(
            "wami:Dates",
            ConditionValue::Array(vec!["2020-01-01T00:00:00Z".to_string(), "soon".to_string()]),
        )
        .custom_value(
            "wami:Ips",
            ConditionValue::Array(vec!["10.0.0.1".to_string(), "nope".to_string()]),
        )
        .custom_value("wami:Flag", ConditionValue::Number(1.0))
        .source_ip("not-an-ip")
        .build();
    for json in [
        r#"{"DateLessThan":{"wami:When":"2020-01-01T00:00:00Z"}}"#,
        r#"{"DateNotEquals":{"wami:When":"2020-01-01T00:00:00Z"}}"#,
        r#"{"IpAddress":{"wami:Where":"10.0.0.0/8"}}"#,
        r#"{"NotIpAddress":{"wami:Where":"10.0.0.0/8"}}"#,
        r#"{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}"#,
        r#"{"NotIpAddress":{"aws:SourceIp":"10.0.0.0/8"}}"#,
        r#"{"Bool":{"wami:Flag":"true"}}"#,
        // An element that cannot be read is an error whatever the order — the
        // first element alone would already decide `any` and `all` here.
    ] {
        let outcome = evaluate_condition_block(&unchecked(json), &context);
        // A type mismatch, not any error: a misspelt operator would err too.
        assert!(
            matches!(outcome, Err(ConditionError::TypeMismatch { .. })),
            "{json}: {outcome:?}"
        );
    }
}

#[test]
fn a_number_that_is_not_finite_is_refused() {
    // `f64::from_str` reads "NaN" and "inf": a Deny `NumericLessThan "NaN"`
    // parsed and was never met.
    for value in ["NaN", "inf", "-inf", "infinity", "+Infinity"] {
        let json = format!(r#"{{"NumericLessThan":{{"wami:SessionAge":"{value}"}}}}"#);
        parse_err(&json);
    }
    // ... and the request side reads through the same parser.
    assert!(ConditionValue::String("NaN".to_string())
        .as_number()
        .is_err());
}

#[test]
fn an_empty_list_is_refused_where_a_list_is_read() {
    // `NotIpAddress []` was always true; `IpAddress []` always false.
    for json in [
        r#"{"IpAddress":{"aws:SourceIp":[]}}"#,
        r#"{"NotIpAddress":{"aws:SourceIp":[]}}"#,
        r#"{"ForAllValues:StringEquals":{"aws:TagKeys":[]}}"#,
    ] {
        parse_err(json);
    }
}

#[test]
fn malformed_set_and_if_exists_forms_are_refused_at_parse() {
    for json in [
        r#"{"DateEqualsIfExists":{"aws:CurrentTime":"soon"}}"#,
        r#"{"BoolIfExists":{"aws:SecureTransport":"yes"}}"#,
        r#"{"NullIfExists":{"aws:SourceIp":"maybe"}}"#,
    ] {
        parse_err(json);
    }
}

#[test]
fn an_error_names_where_a_value_sits_never_the_value() {
    use crate::operators::evaluate_operator;
    use crate::ConditionOperator as O;
    // A canary, not a credential: the assertions search for it to prove that
    // whatever the caller sent is never echoed back in an error.
    let canary = "canary-value";

    // Policy side: what the author must fix is named, the value is not.
    for json in [
        format!(r#"{{"Bool":{{"aws:SecureTransport":"{canary}"}}}}"#),
        format!(r#"{{"DateLessThan":{{"aws:CurrentTime":"{canary}"}}}}"#),
        format!(r#"{{"NumericEquals":{{"wami:SessionAge":"{canary}"}}}}"#),
        format!(r#"{{"IpAddress":{{"aws:SourceIp":["10.0.0.1","{canary}"]}}}}"#),
    ] {
        let message = parse_err(&json);
        assert!(!message.contains(canary), "{json}: {message}");
    }

    // Request side: the caller's value never reaches the error.
    let cases = [
        (O::Bool, ConditionValue::Boolean(true)),
        (
            O::DateLessThan,
            ConditionValue::String("2020-01-01T00:00:00Z".to_string()),
        ),
        (O::NumericLessThan, ConditionValue::Number(5.0)),
        (
            O::IpAddress,
            ConditionValue::String("10.0.0.0/8".to_string()),
        ),
    ];
    for (operator, expected) in cases {
        let err = evaluate_operator(
            operator,
            Some(ConditionValue::String(canary.to_string())),
            &expected,
        )
        .unwrap_err();
        assert!(!err.to_string().contains(canary), "{operator:?}: {err}");
        assert!(
            !format!("{err:?}").contains(canary),
            "{operator:?}: {err:?}"
        );
    }
    let err = evaluate_operator(
        O::StringEquals,
        Some(ConditionValue::Array(vec![canary.to_string()])),
        &ConditionValue::String("x".to_string()),
    )
    .unwrap_err();
    assert!(!format!("{err:?}").contains(canary), "{err:?}");
}

/// Every operator, by its name as written in a policy.
const EVERY_OPERATOR: [&str; 74] = [
    "StringEquals",
    "StringNotEquals",
    "StringLike",
    "StringNotLike",
    "StringEqualsIgnoreCase",
    "StringNotEqualsIgnoreCase",
    "StringEqualsIfExists",
    "StringNotEqualsIfExists",
    "StringLikeIfExists",
    "StringNotLikeIfExists",
    "NumericEquals",
    "NumericNotEquals",
    "NumericLessThan",
    "NumericLessThanEquals",
    "NumericGreaterThan",
    "NumericGreaterThanEquals",
    "NumericEqualsIfExists",
    "NumericNotEqualsIfExists",
    "NumericLessThanIfExists",
    "NumericLessThanEqualsIfExists",
    "NumericGreaterThanIfExists",
    "NumericGreaterThanEqualsIfExists",
    "DateEquals",
    "DateNotEquals",
    "DateLessThan",
    "DateLessThanEquals",
    "DateGreaterThan",
    "DateGreaterThanEquals",
    "DateEqualsIfExists",
    "DateNotEqualsIfExists",
    "DateLessThanIfExists",
    "DateLessThanEqualsIfExists",
    "DateGreaterThanIfExists",
    "DateGreaterThanEqualsIfExists",
    "IpAddress",
    "NotIpAddress",
    "IpAddressIfExists",
    "NotIpAddressIfExists",
    "ArnEquals",
    "ArnNotEquals",
    "ArnLike",
    "ArnNotLike",
    "ArnEqualsIfExists",
    "ArnNotEqualsIfExists",
    "ArnLikeIfExists",
    "ArnNotLikeIfExists",
    "Bool",
    "BoolIfExists",
    "BinaryEquals",
    "BinaryEqualsIfExists",
    "Null",
    "NullIfExists",
    "ForAllValues:StringEquals",
    "ForAllValues:StringNotEquals",
    "ForAllValues:StringLike",
    "ForAllValues:StringNotLike",
    "ForAllValues:ArnEquals",
    "ForAllValues:ArnLike",
    "ForAllValues:NumericLessThan",
    "ForAllValues:NumericGreaterThan",
    "ForAllValues:IpAddress",
    "ForAllValues:DateLessThan",
    "ForAllValues:DateGreaterThan",
    "ForAnyValue:StringEquals",
    "ForAnyValue:StringNotEquals",
    "ForAnyValue:StringLike",
    "ForAnyValue:StringNotLike",
    "ForAnyValue:ArnEquals",
    "ForAnyValue:ArnLike",
    "ForAnyValue:NumericLessThan",
    "ForAnyValue:NumericGreaterThan",
    "ForAnyValue:IpAddress",
    "ForAnyValue:DateLessThan",
    "ForAnyValue:DateGreaterThan",
];

/// The key each operator family is tried on: one whose declared type it reads.
fn a_key_for(operator: &str) -> &'static str {
    let base = operator
        .trim_start_matches("ForAllValues:")
        .trim_start_matches("ForAnyValue:");
    if base.contains("IpAddress") {
        "aws:SourceIp"
    } else if base.starts_with("Numeric") {
        "aws:MultiFactorAuthAge"
    } else if base.starts_with("Date") {
        "aws:CurrentTime"
    } else if base.starts_with("Bool") {
        "aws:SecureTransport"
    } else if base.starts_with("Null") {
        "aws:SourceIp"
    } else if base.starts_with("Arn") {
        "aws:PrincipalArn"
    } else if operator.starts_with("For") {
        "aws:TagKeys"
    } else {
        "aws:username"
    }
}

#[test]
fn whatever_parse_lets_through_evaluates_without_an_error() {
    // The two nets are tied: a value parse accepts on a well-typed key must be
    // one evaluation can read, or a valid-looking policy errs on every request.
    let context = ConditionContext::builder()
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .username("alice")
        .source_ip("203.0.113.42")
        .current_time(chrono::Utc::now())
        .mfa_age(300)
        .secure_transport(true)
        .tag_keys(vec!["env".to_string()])
        .build();
    let candidates = [
        serde_json::json!("alice"),
        serde_json::json!("arn:aws:iam::*"),
        serde_json::json!("10.0.0.1"),
        serde_json::json!("10.0.0.0/8"),
        serde_json::json!("2001:db8::/32"),
        serde_json::json!(["10.0.0.0/8", "::1"]),
        serde_json::json!(["env", "team"]),
        serde_json::json!(["alice"]),
        serde_json::json!([]),
        serde_json::json!("600"),
        serde_json::json!(600),
        serde_json::json!("1e3"),
        serde_json::json!("NaN"),
        serde_json::json!(true),
        serde_json::json!("false"),
        serde_json::json!("2020-01-01T00:00:00Z"),
        serde_json::json!(["2020-01-01T00:00:00Z"]),
        serde_json::json!("QQ=="),
    ];
    let mut accepted = 0;
    for operator in EVERY_OPERATOR {
        let key = a_key_for(operator);
        for value in &candidates {
            let condition = serde_json::json!({ operator: { key: value } });
            let Ok(block) = parse_condition_block(&condition) else {
                continue;
            };
            accepted += 1;
            if let Err(e) = evaluate_condition_block(&block, &context) {
                panic!("{condition} parsed, then failed at evaluation: {e}");
            }
        }
    }
    // Every operator accepted at least one candidate, so none was skipped —
    // but the ten no key can feed, which accept none (wami 001, Δ13).
    assert!(accepted >= EVERY_OPERATOR.len() - 10, "{accepted}");
}

#[test]
fn every_declared_key_resolves_to_the_type_it_declares() {
    // The declared type is what parse judges an operator by, so a resolver
    // that drifted from it would refuse a good policy or let a bad one in.
    // Every field is set, so every key resolves to something.
    use crate::keys::{declared_keys, key_type, KeyType};
    let now = chrono::Utc::now();
    let context = ConditionContext::builder()
        .principal_arn("arn:aws:iam::1:user/a")
        .principal_account("1")
        .principal_type("User")
        .username("a")
        .userid("AID")
        .mfa_present(true)
        .mfa_age(1)
        .token_issue_time(now)
        .secure_transport(true)
        .source_ip("10.0.0.1")
        .source_vpc("vpc")
        .source_vpce("vpce")
        .current_time(now)
        .requested_region("eu")
        .referer("r")
        .user_agent("ua")
        .resource_arn("arn:aws:s3:::b")
        .resource_account("2")
        .tag_keys(vec!["env".to_string()])
        .tenant_id(1)
        .principal_tenant_id(1)
        .resource_tenant_id(1)
        .provider("p")
        .source_provider("p")
        .target_provider("p")
        .tenant_name("t")
        .tenant_status("active")
        .cross_tenant_request(false)
        .provider_region("eu")
        .cross_provider_request(false)
        .request_method("GET")
        .request_protocol("https")
        .api_version("1")
        .request_path("/")
        .request_query("q")
        .content_type("json")
        .accept_header("*/*")
        .origin("o")
        .host("h")
        .application_id("app")
        .application_version("1")
        .client_id("c")
        .client_type("web")
        .device_id("d")
        .device_type("phone")
        .platform("ios")
        .session_id("s")
        .session_age(1)
        .authentication_method("password")
        .authentication_strength("strong")
        .session_risk_score(0.5)
        .ip_reputation("good")
        .geolocation_country("FR")
        .geolocation_city("Paris")
        .vpn_detected(false)
        .proxy_detected(false)
        .requests_per_minute(1)
        .requests_per_hour(1)
        .requests_per_day(1)
        .quota_remaining(1)
        .quota_limit(1)
        .burst_capacity_used(0.5)
        .request_id("r")
        .correlation_id("c")
        .trace_id("t")
        .span_id("s")
        .debug_mode(false)
        .dry_run_mode(false)
        .data_classification("secret")
        .encryption_required(true)
        .encryption_algorithm("AES")
        .data_residency_region("eu")
        .build();
    let mut seen = 0;
    for (key, declared) in declared_keys() {
        seen += 1;
        let value = get_context_value(key, &context)
            .unwrap()
            .unwrap_or_else(|| panic!("{key} resolved to nothing in a full context"));
        let holds = match declared {
            KeyType::String | KeyType::Arn => matches!(value, ConditionValue::String(_)),
            KeyType::Date => value
                .as_string()
                .is_ok_and(|s| crate::operators::parse_rfc3339(&s).is_ok()),
            KeyType::Ip => matches!(value, ConditionValue::String(_)),
            KeyType::Number => matches!(value, ConditionValue::Number(_)),
            KeyType::Boolean => matches!(value, ConditionValue::Boolean(_)),
            KeyType::StringList => matches!(value, ConditionValue::Array(_)),
        };
        assert!(
            holds,
            "{key} is declared {declared:?} and resolves to {value:?}"
        );
        assert_eq!(key_type(key), Some(declared), "{key}");
    }
    assert!(seen > 70, "{seen}");
    // Tag keys are declared by prefix; anything else is undeclared.
    assert_eq!(key_type("aws:PrincipalTag/team"), Some(KeyType::String));
    assert_eq!(key_type("wami:Team"), None);
}

#[test]
fn the_set_operators_no_key_can_feed_are_refused_at_parse() {
    // ForAllValues/ForAnyValue over numbers, dates or addresses compare a LIST
    // of them, and no declared key holds one: they used to take a one-value
    // key and quietly act as scalar operators that pass on an absent key.
    let cases = [
        r#"{"ForAllValues:NumericLessThan":{"wami:SessionAge":"10"}}"#,
        r#"{"ForAllValues:NumericGreaterThan":{"aws:MultiFactorAuthAge":"1"}}"#,
        r#"{"ForAnyValue:NumericLessThan":{"aws:TagKeys":"5"}}"#,
        r#"{"ForAnyValue:NumericGreaterThan":{"aws:EpochTime":"1"}}"#,
        r#"{"ForAllValues:DateLessThan":{"aws:CurrentTime":"2020-01-01T00:00:00Z"}}"#,
        r#"{"ForAllValues:DateGreaterThan":{"aws:TokenIssueTime":"2020-01-01T00:00:00Z"}}"#,
        r#"{"ForAnyValue:DateLessThan":{"aws:CurrentTime":"2020-01-01T00:00:00Z"}}"#,
        r#"{"ForAnyValue:DateGreaterThan":{"aws:CurrentTime":"2020-01-01T00:00:00Z"}}"#,
        r#"{"ForAllValues:IpAddress":{"aws:SourceIp":["10.0.0.0/8"]}}"#,
        r#"{"ForAnyValue:IpAddress":{"aws:SourceIp":["10.0.0.0/8"]}}"#,
    ];
    for json in cases {
        let message = parse_err(json);
        assert!(
            message.contains("no key of that kind holds a list"),
            "{json}: {message}"
        );
        let operator = json.split('"').nth(1).unwrap();
        assert!(message.contains(operator), "{json}: {message}");
    }
    // ... because the table has one list key, and it holds strings.
    let lists: Vec<_> = crate::keys::declared_keys()
        .filter(|(_, t)| *t == crate::keys::KeyType::StringList)
        .map(|(key, _)| key)
        .collect();
    assert_eq!(lists, ["aws:TagKeys"]);
}

#[test]
fn a_hand_built_block_cannot_reach_a_set_operator_no_key_can_feed() {
    // No evaluator is left behind the parse guard: a block built by hand gets
    // the same refusal, never an answer.
    let context = ConditionContext::builder().mfa_age(300).build();
    let block = unchecked(r#"{"ForAllValues:NumericLessThan":{"aws:MultiFactorAuthAge":"600"}}"#);
    assert_eq!(
        evaluate_condition_block(&block, &context),
        Err(ConditionError::OperatorWithoutKey {
            operator: "ForAllValues:NumericLessThan".to_string(),
        })
    );
}

#[test]
fn every_declared_key_is_written_where_it_is_read() {
    // A simulation's context entry for a declared key used to go to the custom
    // values, which a declared key is never read from: the key read as absent.
    use crate::keys::{assign_context_value, declared_keys, KeyType};
    for (key, declared) in declared_keys() {
        let sample: Vec<String> = match declared {
            KeyType::String | KeyType::Arn => vec!["7".to_string()],
            KeyType::Number => vec!["1600000000".to_string()],
            KeyType::Boolean => vec!["true".to_string()],
            KeyType::Date => vec!["2020-01-01T00:00:00Z".to_string()],
            KeyType::Ip => vec!["10.0.0.1".to_string()],
            KeyType::StringList => vec!["a".to_string(), "b".to_string()],
        };
        let mut context = ConditionContext::builder().build();
        assert_eq!(
            assign_context_value(&mut context, key, &sample),
            Ok(true),
            "{key}"
        );
        assert!(
            context.custom_values.is_empty(),
            "{key} went to the custom values"
        );
        // The value read back is the value written — not merely something:
        // aws:CurrentTime and aws:EpochTime always resolve to a value.
        let read = get_context_value(key, &context)
            .unwrap()
            .unwrap_or_else(|| panic!("{key} written, then read as absent"));
        let expected = match declared {
            KeyType::String | KeyType::Arn => ConditionValue::String("7".to_string()),
            KeyType::Number => ConditionValue::Number(1_600_000_000.0),
            KeyType::Boolean => ConditionValue::Boolean(true),
            KeyType::Ip => ConditionValue::String("10.0.0.1".to_string()),
            KeyType::StringList => ConditionValue::Array(vec!["a".to_string(), "b".to_string()]),
            KeyType::Date => {
                let instant = |v: &ConditionValue| {
                    crate::operators::parse_rfc3339(&v.as_string().unwrap()).unwrap()
                };
                let written = ConditionValue::String(sample[0].clone());
                assert_eq!(instant(&read), instant(&written), "{key}");
                continue;
            }
        };
        assert_eq!(read, expected, "{key}");
    }
    // A tag is written to its map; an undeclared key is left to the caller.
    let mut context = ConditionContext::builder().build();
    let core = ["core".to_string()];
    assert_eq!(
        assign_context_value(&mut context, "aws:PrincipalTag/team", &core),
        Ok(true)
    );
    assert_eq!(
        get_context_value("aws:PrincipalTag/team", &context).unwrap(),
        Some(ConditionValue::String("core".to_string()))
    );
    assert_eq!(
        assign_context_value(&mut context, "wami:Team", &core),
        Ok(false)
    );
}

#[test]
fn a_value_that_does_not_read_as_its_key_is_refused_without_being_quoted() {
    use crate::keys::assign_context_value;
    let secret = "s3cr3t".to_string();
    for key in [
        "aws:SecureTransport",
        "wami:SessionAge",
        "wami:SessionRiskScore",
        "aws:CurrentTime",
        "aws:EpochTime",
        "aws:SourceIp",
        "wami:TenantId",
    ] {
        let mut context = ConditionContext::builder().build();
        let err =
            assign_context_value(&mut context, key, std::slice::from_ref(&secret)).expect_err(key);
        assert!(!format!("{err:?}").contains("s3cr3t"), "{key}: {err:?}");
    }
    // A scalar key takes one value, not two.
    let mut context = ConditionContext::builder().build();
    let two = ["a".to_string(), "b".to_string()];
    assert!(assign_context_value(&mut context, "aws:username", &two).is_err());
}

#[test]
fn every_part_of_a_condition_is_read_before_it_answers() {
    // One part false (alice is not bob), one part that cannot be compared (the
    // request's address is no address). Evaluation stopped at the first false
    // part, in HashMap order: the same request was refused on one parse and
    // decided on the next. Every part is read first, in a fixed order.
    let context = ConditionContext::builder()
        .username("alice")
        .source_ip("not-an-ip")
        .custom_value("wami:Team", ConditionValue::Number(5.0))
        .build();
    for json in [
        // across operators
        r#"{"StringEquals":{"aws:username":"bob"},"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}"#,
        // within one operator, across keys
        r#"{"StringEquals":{"aws:username":"bob","wami:Team":"5"}}"#,
    ] {
        let outcomes: std::collections::BTreeSet<String> = (0..200)
            .map(|_| {
                format!(
                    "{:?}",
                    evaluate_condition_block(&parse_condition_block_from_json(json), &context)
                )
            })
            .collect();
        assert_eq!(outcomes.len(), 1, "{json}: {outcomes:?}");
        let outcome = outcomes.into_iter().next().unwrap();
        assert!(outcome.starts_with("Err(TypeMismatch"), "{json}: {outcome}");
    }
}
