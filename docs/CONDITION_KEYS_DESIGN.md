# Policy Condition Keys - Design Document

## Overview

This document describes the design and architecture for implementing policy condition key evaluation in WAMI. Condition keys enable fine-grained access control by evaluating contextual information about requests (IP address, time, MFA status, tenant, etc.).

## Architecture

### Core Components

```
┌─────────────────────────────────────────────────────────────┐
│                    Policy Evaluation                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   Action     │  │   Resource   │  │  Condition   │     │
│  │  Matching    │  │   Matching   │  │  Evaluation │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│                          │                    │             │
│                          └────────┬───────────┘             │
│                                   │                         │
│                          ┌────────▼──────────┐              │
│                          │  Final Decision   │              │
│                          │  (Allow/Deny)    │              │
│                          └───────────────────┘              │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ uses
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              Condition Evaluation Engine                     │
│  ┌──────────────────────────────────────────────────────┐  │
│  │         ConditionEvaluator                           │  │
│  │  - evaluate_condition_block()                        │  │
│  │  - evaluate_operator()                               │  │
│  │  - get_context_value()                                │  │
│  └──────────────────────────────────────────────────────┘  │
│                              │                              │
│                              │ uses                          │
│  ┌───────────────────────────┼───────────────────────────┐  │
│  │                           │                           │  │
│  ▼                           ▼                           ▼  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │   Operators  │  │  Condition   │  │   Context    │  │
│  │   Module     │  │    Keys       │  │   Module     │  │
│  │              │  │   Module      │  │              │  │
│  │ - String     │  │ - AWS Keys    │  │ - Context    │  │
│  │ - Numeric    │  │ - WAMI Keys   │  │   Builder    │  │
│  │ - Date       │  │ - Key Resolver│  │ - Value      │  │
│  │ - IP         │  │               │  │   Extraction │  │
│  │ - ARN        │  │               │  │              │  │
│  │ - Boolean    │  │               │  │              │  │
│  │ - Set Ops    │  │               │  │              │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Data Structures

### Condition Block Structure

A condition block in a policy statement has this JSON structure:
```json
{
  "Condition": {
    "StringEquals": {
      "aws:username": "alice"
    },
    "IpAddress": {
      "aws:SourceIp": ["203.0.113.0/24", "198.51.100.0/24"]
    },
    "NumericLessThan": {
      "aws:MultiFactorAuthAge": "3600"
    }
  }
}
```

### Internal Representation

```rust
// Condition block: Map<Operator, Map<Key, Value>>
pub type ConditionBlock = HashMap<String, HashMap<String, ConditionValue>>;

// Condition value can be string, number, boolean, or array
#[derive(Debug, Clone, PartialEq)]
pub enum ConditionValue {
    String(String),
    Number(f64),
    Boolean(bool),
    Array(Vec<String>),
}

// Context for evaluation
pub struct ConditionContext {
    // Request context
    principal_arn: Option<String>,
    source_ip: Option<String>,
    current_time: DateTime<Utc>,
    
    // WAMI-specific
    tenant_id: Option<u64>,
    provider: Option<String>,
    
    // Extensible map for additional keys
    custom_values: HashMap<String, ConditionValue>,
}
```

## Evaluation Logic

### Condition Block Evaluation

A condition block evaluates to `true` if **ALL** operator blocks** evaluate to `true (AND logic across operators).

```rust
fn evaluate_condition_block(
    block: &ConditionBlock,
    context: &ConditionContext,
) -> Result<bool, ConditionError> {
    // All operator blocks must pass (AND logic)
    for (operator_name, key_value_map) in block {
        let operator = ConditionOperator::from_str(operator_name)?;
        if !evaluate_operator_block(operator, key_value_map, context)? {
            return Ok(false); // One operator block fails = entire condition fails
        }
    }
    Ok(true) // All operator blocks passed
}
```

### Operator Block Evaluation

An operator block evaluates to `true` if **ALL** key-value pairs evaluate to `true` (AND logic within operator).

```rust
fn evaluate_operator_block(
    operator: ConditionOperator,
    key_value_map: &HashMap<String, ConditionValue>,
    context: &ConditionContext,
) -> Result<bool, ConditionError> {
    // All key-value pairs must pass (AND logic)
    for (key, expected_value) in key_value_map {
        let actual_value = get_context_value(key, context)?;
        if !evaluate_operator(operator, actual_value, expected_value)? {
            return Ok(false); // One key fails = operator block fails
        }
    }
    Ok(true) // All keys passed
}
```

### Operator Evaluation

Each operator evaluates a single key-value pair:

```rust
fn evaluate_operator(
    operator: ConditionOperator,
    actual: Option<ConditionValue>,
    expected: &ConditionValue,
) -> Result<bool, ConditionError> {
    match operator {
        ConditionOperator::StringEquals => {
            // Exact string match
            match actual {
                Some(ConditionValue::String(actual_str)) => {
                    Ok(actual_str == expected.as_string()?)
                }
                None => Ok(false), // Missing value = no match
                _ => Ok(false), // Type mismatch = no match
            }
        }
        ConditionOperator::StringEqualsIfExists => {
            // If key exists, must match; if missing, passes
            match actual {
                Some(ConditionValue::String(actual_str)) => {
                    Ok(actual_str == expected.as_string()?)
                }
                None => Ok(true), // Missing value = passes (IfExists behavior)
                _ => Ok(false),
            }
        }
        ConditionOperator::StringLike => {
            // Wildcard pattern matching
            // ... implementation
        }
        // ... other operators
    }
}
```

## Condition Keys

### Key Resolution

Condition keys are resolved from the context:

```rust
fn get_context_value(key: &str, context: &ConditionContext) -> Result<Option<ConditionValue>, ConditionError> {
    match key {
        // AWS keys
        "aws:PrincipalArn" => Ok(context.principal_arn.clone().map(ConditionValue::String)),
        "aws:SourceIp" => Ok(context.source_ip.clone().map(ConditionValue::String)),
        "aws:CurrentTime" => Ok(Some(ConditionValue::String(context.current_time.to_rfc3339()))),
        "aws:MultiFactorAuthPresent" => Ok(context.mfa_present.map(ConditionValue::Boolean)),
        
        // WAMI keys
        "wami:TenantId" => Ok(context.tenant_id.map(|id| ConditionValue::String(id.to_string()))),
        "wami:Provider" => Ok(context.provider.clone().map(ConditionValue::String)),
        
        // Dynamic keys (with placeholders)
        key if key.starts_with("aws:PrincipalTag/") => {
            let tag_key = &key["aws:PrincipalTag/".len()..];
            Ok(context.principal_tags.get(tag_key).cloned())
        }
        
        // Fallback to custom values
        _ => Ok(context.custom_values.get(key).cloned()),
    }
}
```

## Operators

### String Operators

1. **StringEquals**: Exact string match
2. **StringNotEquals**: Exact string mismatch
3. **StringLike**: Wildcard pattern match (`*`, `?`)
4. **StringNotLike**: Wildcard pattern mismatch
5. **StringEqualsIgnoreCase**: Case-insensitive exact match
6. **StringNotEqualsIgnoreCase**: Case-insensitive exact mismatch
7. **StringEqualsIfExists**: StringEquals if key exists, passes if missing
8. **StringNotEqualsIfExists**: StringNotEquals if key exists, passes if missing
9. **StringLikeIfExists**: StringLike if key exists, passes if missing
10. **StringNotLikeIfExists**: StringNotLike if key exists, passes if missing

### Numeric Operators

1. **NumericEquals**: Exact numeric match
2. **NumericNotEquals**: Exact numeric mismatch
3. **NumericLessThan**: Less than comparison
4. **NumericLessThanEquals**: Less than or equal
5. **NumericGreaterThan**: Greater than comparison
6. **NumericGreaterThanEquals**: Greater than or equal
7. **IfExists variants**: All 6 operators have IfExists variants

### Date/Time Operators

1. **DateEquals**: Exact date/time match (ISO 8601)
2. **DateNotEquals**: Exact date/time mismatch
3. **DateLessThan**: Before date/time
4. **DateLessThanEquals**: Before or equal
5. **DateGreaterThan**: After date/time
6. **DateGreaterThanEquals**: After or equal
7. **IfExists variants**: All 6 operators have IfExists variants

### IP Address Operators

1. **IpAddress**: IP matches CIDR block or exact IP
2. **NotIpAddress**: IP does not match CIDR block or exact IP
3. **IpAddressIfExists**: IpAddress if key exists, passes if missing
4. **NotIpAddressIfExists**: NotIpAddress if key exists, passes if missing

### ARN Operators

1. **ArnEquals**: Exact ARN match
2. **ArnNotEquals**: Exact ARN mismatch
3. **ArnLike**: ARN pattern match (wildcards)
4. **ArnNotLike**: ARN pattern mismatch
5. **IfExists variants**: All 4 operators have IfExists variants

### Boolean Operators

1. **Bool**: Boolean value match (true/false as strings)
2. **BoolIfExists**: Bool if key exists, passes if missing

### Binary Operators

1. **BinaryEquals**: Base64-encoded binary match
2. **BinaryEqualsIfExists**: BinaryEquals if key exists, passes if missing

### Null Operators

1. **Null**: Check if value is null (true/false as strings)
2. **NullIfExists**: Null if key exists, passes if missing

### Set Operators

#### ForAllValues (AND logic)
- All values in the request must match at least one value in the policy
- Example: `ForAllValues:StringEquals` with `aws:TagKeys: ["Env", "Owner"]` means the request must have BOTH "Env" AND "Owner" tags

#### ForAnyValue (OR logic)
- At least one value in the request must match at least one value in the policy
- Example: `ForAnyValue:StringEquals` with `aws:PrincipalTag/Role: ["Admin", "DevOps"]` means the principal must have EITHER "Admin" OR "DevOps" tag

## Integration with Policy Evaluation

### Current Flow (without conditions)
```
1. Check if action matches
2. Check if resource matches
3. If both match → apply effect (Allow/Deny)
```

### New Flow (with conditions)
```
1. Check if action matches
2. Check if resource matches
3. If both match:
   a. If condition exists:
      - Evaluate condition block
      - If condition passes → apply effect
      - If condition fails → implicit deny (statement doesn't apply)
   b. If no condition → apply effect directly
```

## Error Handling

### Missing Context Values

- **Without IfExists**: Missing value → condition fails → statement doesn't apply
- **With IfExists**: Missing value → condition passes → statement can apply

### Invalid Operators

- Unknown operator → return error
- Type mismatch → condition fails

### Invalid Keys

- Unknown key → return error (or treat as missing if IfExists)

## Performance Considerations

1. **Lazy Evaluation**: Only evaluate conditions when action and resource match
2. **Caching**: Cache parsed condition blocks
3. **Early Exit**: Fail fast on first failing condition
4. **Optimization**: Pre-compile wildcard patterns

## Security Considerations

1. **Input Validation**: Validate all condition keys and values
2. **Type Safety**: Strict type checking for operators
3. **No Code Execution**: Never evaluate user input as code
4. **Resource Limits**: Limit condition block size and complexity

## Testing Strategy

### Unit Tests
- Each operator with various inputs
- Edge cases (empty strings, null values, type mismatches)
- IfExists behavior
- Set operators (ForAllValues, ForAnyValue)

### Integration Tests
- Full policy evaluation with conditions
- Multiple conditions in one statement
- Conditions across multiple statements
- Deny precedence with conditions

### AWS Compatibility Tests
- Validate against AWS IAM policy simulator behavior
- Test all AWS condition keys
- Test all AWS operators

### Performance Tests
- Benchmark condition evaluation
- Test with large condition blocks
- Test with many conditions

## Implementation Phases

### Phase 1: Core Infrastructure
- Condition block parsing
- Basic operator evaluation (StringEquals, NumericEquals, Bool)
- Context structure
- Integration with policy evaluation

### Phase 2: AWS Operators
- All string operators
- All numeric operators
- All date operators
- IP address operators
- ARN operators
- Set operators

### Phase 3: AWS Condition Keys
- Principal keys
- Authentication keys
- Network keys
- Request context keys
- Resource keys
- Time keys

### Phase 4: WAMI Extensions
- WAMI-specific keys
- Custom operators
- Advanced features

### Phase 5: Testing & Documentation
- Comprehensive test suite
- Documentation
- Examples
- Migration guide

