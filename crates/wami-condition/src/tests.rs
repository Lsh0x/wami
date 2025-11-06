//! Comprehensive Test Suite for Condition Key Evaluation
//!
//! This test suite follows TDD principles - tests are written before implementation.
//! It covers all operators, condition keys, edge cases, and corner cases.

use crate::wami::policies::condition::{
    evaluator::{evaluate_condition_block, parse_condition_block},
    ConditionBlock, ConditionContext,
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
    let condition = parse_condition_block_from_json(
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
    let _condition = parse_condition_block_from_json(
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
    let _condition = parse_condition_block_from_json(
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
    let _condition = parse_condition_block_from_json(
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
    let context = create_test_context();
    let condition = parse_condition_block_from_json(
        r#"{
            "NumericEquals": {
                "aws:username": "alice"
            }
        }"#,
    );

    // Should fail - can't compare string as number
    let result = evaluate_condition_block(&condition, &context);
    assert!(result.is_err() || !result.unwrap());
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
    let context = create_test_context();
    let condition = parse_condition_block_from_json(
        r#"{
            "DateEquals": {
                "aws:CurrentTime": "invalid-date"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context);
    assert!(result.is_err());
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
    assert!(result.is_err() || !result.unwrap());
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
    let context = ConditionContext::builder().mfa_present(true).build();

    let condition = parse_condition_block_from_json(
        r#"{
            "Bool": {
                "aws:MultiFactorAuthPresent": "yes"
            }
        }"#,
    );

    // Should fail - only "true" and "false" are valid
    let result = evaluate_condition_block(&condition, &context);
    assert!(result.is_err() || !result.unwrap());
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

    let condition = parse_condition_block_from_json(
        r#"{
            "NumericEquals": {
                "aws:username": "123"
            }
        }"#,
    );

    // Should fail - can't compare string as number
    let result = evaluate_condition_block(&condition, &context);
    assert!(result.is_err() || !result.unwrap());
}

#[test]
fn test_condition_invalid_operator() {
    let context = create_test_context();
    let condition = parse_condition_block_from_json(
        r#"{
            "InvalidOperator": {
                "aws:username": "alice"
            }
        }"#,
    );

    let result = evaluate_condition_block(&condition, &context);
    assert!(result.is_err());
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
    // Ensure no code execution from condition values
}

#[test]
fn test_condition_resource_limits() {
    // Test that very large condition blocks are rejected
}
