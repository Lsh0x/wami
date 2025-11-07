# Policy Condition Keys - User Guide

## Overview

Policy condition keys enable fine-grained access control by evaluating contextual information about requests. Conditions allow you to restrict access based on IP address, time, MFA status, tenant isolation, and more.

## Quick Start

### Basic Example: IP Address Restriction

```rust
use wami::service::policies::evaluation::{EvaluationService, SimulateCustomPolicyRequest, ContextEntry};
use wami::store::memory::InMemoryWamiStore;
use std::sync::{Arc, RwLock};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
    let service = EvaluationService::new(store, "123456789012".to_string());

    // Policy that allows S3 access only from specific IP range
    let policy = r#"{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "*",
            "Condition": {
                "IpAddress": {
                    "aws:SourceIp": "203.0.113.0/24"
                }
            }
        }]
    }"#;

    // Simulate request from allowed IP
    let request = SimulateCustomPolicyRequest {
        policy_input_list: vec![policy.to_string()],
        action_names: vec!["s3:GetObject".to_string()],
        resource_arns: None,
        context_entries: Some(vec![ContextEntry {
            context_key_name: "aws:SourceIp".to_string(),
            context_key_values: vec!["203.0.113.42".to_string()],
            context_key_type: "String".to_string(),
        }]),
    };

    let response = service.simulate_custom_policy(request).await?;
    assert_eq!(response.evaluation_results[0].eval_decision, "allowed");

    // Simulate request from blocked IP
    let request = SimulateCustomPolicyRequest {
        policy_input_list: vec![policy.to_string()],
        action_names: vec!["s3:GetObject".to_string()],
        resource_arns: None,
        context_entries: Some(vec![ContextEntry {
            context_key_name: "aws:SourceIp".to_string(),
            context_key_values: vec!["198.51.100.42".to_string()],
            context_key_type: "String".to_string(),
        }]),
    };

    let response = service.simulate_custom_policy(request).await?;
    assert_eq!(response.evaluation_results[0].eval_decision, "implicitDeny");

    Ok(())
}
```

## Common Use Cases

### 1. Time-Based Access Control

Restrict access to business hours only:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "s3:*",
    "Resource": "*",
    "Condition": {
      "DateGreaterThan": {
        "aws:CurrentTime": "2024-01-01T09:00:00Z"
      },
      "DateLessThan": {
        "aws:CurrentTime": "2024-01-01T17:00:00Z"
      }
    }
  }]
}
```

**Usage:**
```rust
let request = SimulateCustomPolicyRequest {
    policy_input_list: vec![policy.to_string()],
    action_names: vec!["s3:GetObject".to_string()],
    resource_arns: None,
    context_entries: Some(vec![ContextEntry {
        context_key_name: "aws:CurrentTime".to_string(),
        context_key_values: vec!["2024-01-01T12:00:00Z".to_string()],
        context_key_type: "String".to_string(),
    }]),
};
```

### 2. MFA Requirement

Require MFA for sensitive operations:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "*"
    },
    {
      "Effect": "Deny",
      "Action": "s3:DeleteObject",
      "Resource": "*",
      "Condition": {
        "Bool": {
          "aws:MultiFactorAuthPresent": "false"
        }
      }
    }
  ]
}
```

**Usage:**
```rust
let request = SimulateCustomPolicyRequest {
    policy_input_list: vec![policy.to_string()],
    action_names: vec!["s3:DeleteObject".to_string()],
    resource_arns: None,
    context_entries: Some(vec![ContextEntry {
        context_key_name: "aws:MultiFactorAuthPresent".to_string(),
        context_key_values: vec!["false".to_string()],
        context_key_type: "Boolean".to_string(),
    }]),
};
// Result: denied (MFA not present)
```

### 3. Tenant Isolation

Ensure users can only access resources in their own tenant:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "s3:*",
    "Resource": "*",
    "Condition": {
      "StringEquals": {
        "wami:TenantId": "${wami:PrincipalTenantId}"
      }
    }
  }]
}
```

**Usage:**
```rust
let request = SimulateCustomPolicyRequest {
    policy_input_list: vec![policy.to_string()],
    action_names: vec!["s3:GetObject".to_string()],
    resource_arns: None,
    context_entries: Some(vec![
        ContextEntry {
            context_key_name: "wami:PrincipalTenantId".to_string(),
            context_key_values: vec!["12345".to_string()],
            context_key_type: "String".to_string(),
        },
        ContextEntry {
            context_key_name: "wami:TenantId".to_string(),
            context_key_values: vec!["12345".to_string()],
            context_key_type: "String".to_string(),
        },
    ]),
};
```

### 4. Multi-Cloud Provider Restriction

Restrict actions to specific cloud providers:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "s3:*",
    "Resource": "*",
    "Condition": {
      "StringEquals": {
        "wami:Provider": "aws"
      }
    }
  }]
}
```

### 5. Combining Multiple Conditions

Require multiple conditions to be satisfied:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "iam:*",
    "Resource": "*",
    "Condition": {
      "Bool": {
        "aws:MultiFactorAuthPresent": "true"
      },
      "IpAddress": {
        "aws:SourceIp": ["10.0.0.0/8", "172.16.0.0/12"]
      },
      "DateGreaterThan": {
        "aws:CurrentTime": "2024-01-01T09:00:00Z"
      }
    }
  }]
}
```

**Note:** All conditions must pass (AND logic). If any condition fails, the statement doesn't match.

### 6. Conditional Deny with Allow

Allow by default but deny specific cases:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:*",
      "Resource": "*"
    },
    {
      "Effect": "Deny",
      "Action": "s3:DeleteObject",
      "Resource": "*",
      "Condition": {
        "IpAddress": {
          "aws:SourceIp": "198.51.100.0/24"
        }
      }
    }
  ]
}
```

**Behavior:** 
- Requests from `198.51.100.0/24` → `denied` (explicit deny wins)
- Requests from other IPs → `allowed`

## Available Condition Keys

### AWS Global Keys

#### Principal & Identity
- `aws:PrincipalArn` - ARN of the principal making the request
- `aws:PrincipalAccount` - Account ID of the principal
- `aws:PrincipalType` - Type of principal (User, Role, etc.)
- `aws:username` - Username of the principal
- `aws:userid` - User ID of the principal
- `aws:PrincipalTag/${TagKey}` - Tag on the principal

#### Authentication
- `aws:MultiFactorAuthPresent` - Whether MFA is present (true/false)
- `aws:MultiFactorAuthAge` - Age of MFA in seconds
- `aws:TokenIssueTime` - When temporary credentials were issued

#### Network & Transport
- `aws:SourceIp` - Source IP address (supports CIDR notation)
- `aws:SourceVpc` - VPC ID of the source
- `aws:SourceVpce` - VPC endpoint ID
- `aws:SecureTransport` - Whether request uses HTTPS (true/false)

#### Request Context
- `aws:CurrentTime` - Current time (ISO 8601 format)
- `aws:EpochTime` - Current time as Unix timestamp
- `aws:RequestedRegion` - AWS region of the request
- `aws:Referer` - HTTP referer header
- `aws:UserAgent` - User agent string

#### Resource
- `aws:ResourceArn` - ARN of the resource being accessed
- `aws:ResourceAccount` - Account ID of the resource
- `aws:ResourceTag/${TagKey}` - Tag on the resource

#### Tags
- `aws:TagKeys` - List of tag keys in the request
- `aws:RequestTag/${TagKey}` - Tag being set in the request

### WAMI-Specific Keys

#### Multi-Tenant
- `wami:TenantId` - Current tenant ID
- `wami:PrincipalTenantId` - Tenant ID of the principal
- `wami:ResourceTenantId` - Tenant ID of the resource

#### Multi-Cloud
- `wami:Provider` - Cloud provider (aws, gcp, azure, custom)
- `wami:SourceProvider` - Source cloud provider
- `wami:TargetProvider` - Target cloud provider

## Available Operators

### String Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `StringEquals` | Exact string match | `"aws:username": "alice"` |
| `StringNotEquals` | Exact string mismatch | `"aws:username": "admin"` |
| `StringLike` | Wildcard pattern match | `"aws:PrincipalArn": "arn:aws:iam::*:role/Admin*"` |
| `StringNotLike` | Wildcard pattern mismatch | `"aws:PrincipalArn": "arn:aws:iam::*:user/*"` |
| `StringEqualsIgnoreCase` | Case-insensitive match | `"aws:username": "ALICE"` |
| `StringEqualsIfExists` | Match if key exists, pass if missing | `"aws:PrincipalTag/Env": "prod"` |

### Numeric Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `NumericEquals` | Exact numeric match | `"aws:MultiFactorAuthAge": "3600"` |
| `NumericLessThan` | Less than | `"aws:MultiFactorAuthAge": "3600"` (MFA < 1 hour old) |
| `NumericGreaterThan` | Greater than | `"wami:RequestsPerHour": "1000"` |
| `NumericLessThanEquals` | Less than or equal | `"aws:MultiFactorAuthAge": "7200"` |
| `NumericGreaterThanEquals` | Greater than or equal | `"wami:QuotaRemaining": "100"` |

### Date/Time Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `DateEquals` | Exact date/time match | `"aws:CurrentTime": "2024-01-01T12:00:00Z"` |
| `DateLessThan` | Before date/time | `"aws:CurrentTime": "2024-01-01T17:00:00Z"` (before 5 PM) |
| `DateGreaterThan` | After date/time | `"aws:CurrentTime": "2024-01-01T09:00:00Z"` (after 9 AM) |
| `DateLessThanEquals` | Before or equal | `"aws:TokenIssueTime": "2024-01-01T00:00:00Z"` |
| `DateGreaterThanEquals` | After or equal | `"aws:CurrentTime": "2024-01-01T00:00:00Z"` |

### IP Address Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `IpAddress` | IP matches CIDR block | `"aws:SourceIp": "203.0.113.0/24"` |
| `NotIpAddress` | IP does not match CIDR | `"aws:SourceIp": "198.51.100.0/24"` |

### ARN Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `ArnEquals` | Exact ARN match | `"aws:ResourceArn": "arn:aws:s3:::mybucket"` |
| `ArnLike` | ARN pattern match | `"aws:ResourceArn": "arn:aws:s3:::mybucket/*"` |
| `ArnNotEquals` | Exact ARN mismatch | `"aws:ResourceArn": "arn:aws:s3:::otherbucket"` |
| `ArnNotLike` | ARN pattern mismatch | `"aws:ResourceArn": "arn:aws:s3:::restricted/*"` |

### Boolean Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `Bool` | Boolean value match | `"aws:SecureTransport": "true"` |
| `BoolIfExists` | Boolean if key exists | `"aws:MultiFactorAuthPresent": "true"` |

### Set Operators

#### ForAllValues (AND logic)
All values in the request must match at least one value in the policy.

```json
{
  "ForAllValues:StringEquals": {
    "aws:TagKeys": ["Env", "Owner", "Project"]
  }
}
```
**Meaning:** Request must have ALL tags: Env AND Owner AND Project

#### ForAnyValue (OR logic)
At least one value in the request must match at least one value in the policy.

```json
{
  "ForAnyValue:StringEquals": {
    "aws:PrincipalTag/Role": ["Admin", "DevOps", "Security"]
  }
}
```
**Meaning:** Principal must have EITHER Admin OR DevOps OR Security role

## Condition Evaluation Logic

### AND Logic Across Operators

When multiple operators are specified, ALL must pass:

```json
{
  "Condition": {
    "IpAddress": { "aws:SourceIp": "10.0.0.0/8" },
    "Bool": { "aws:MultiFactorAuthPresent": "true" },
    "DateGreaterThan": { "aws:CurrentTime": "2024-01-01T09:00:00Z" }
  }
}
```

**Result:** All three conditions must be true for the statement to match.

### AND Logic Within Operator

When multiple keys are specified in one operator, ALL must pass:

```json
{
  "StringEquals": {
    "aws:username": "alice",
    "wami:TenantId": "12345"
  }
}
```

**Result:** Both username must be "alice" AND tenant must be "12345".

### IfExists Behavior

`IfExists` operators pass if the key is missing:

```json
{
  "StringEqualsIfExists": {
    "aws:PrincipalTag/Department": "Engineering"
  }
}
```

- If `aws:PrincipalTag/Department` exists → must equal "Engineering"
- If `aws:PrincipalTag/Department` is missing → condition passes

## Integration Example

### Using Condition Evaluation in Policy Simulation

```rust
use wami::service::policies::evaluation::{
    EvaluationService, SimulateCustomPolicyRequest, ContextEntry,
};
use wami::store::memory::InMemoryWamiStore;
use std::sync::{Arc, RwLock};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
    let service = EvaluationService::new(store, "123456789012".to_string());

    // Policy with multiple conditions
    let policy = r#"{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "*",
            "Condition": {
                "IpAddress": {
                    "aws:SourceIp": "203.0.113.0/24"
                },
                "Bool": {
                    "aws:SecureTransport": "true"
                },
                "DateGreaterThan": {
                    "aws:CurrentTime": "2024-01-01T09:00:00Z"
                }
            }
        }]
    }"#;

    // Build context entries
    let context_entries = vec![
        ContextEntry {
            context_key_name: "aws:SourceIp".to_string(),
            context_key_values: vec!["203.0.113.42".to_string()],
            context_key_type: "String".to_string(),
        },
        ContextEntry {
            context_key_name: "aws:SecureTransport".to_string(),
            context_key_values: vec!["true".to_string()],
            context_key_type: "Boolean".to_string(),
        },
        ContextEntry {
            context_key_name: "aws:CurrentTime".to_string(),
            context_key_values: vec!["2024-01-01T12:00:00Z".to_string()],
            context_key_type: "String".to_string(),
        },
    ];

    let request = SimulateCustomPolicyRequest {
        policy_input_list: vec![policy.to_string()],
        action_names: vec!["s3:GetObject".to_string()],
        resource_arns: None,
        context_entries: Some(context_entries),
    };

    let response = service.simulate_custom_policy(request).await?;
    
    match response.evaluation_results[0].eval_decision.as_str() {
        "allowed" => println!("✅ Access granted"),
        "denied" => println!("❌ Access denied (explicit deny)"),
        "implicitDeny" => println!("⚠️  Access denied (no matching statement)"),
        _ => println!("❓ Unknown decision"),
    }

    Ok(())
}
```

## Best Practices

### 1. Use Explicit Deny for Security

Always use explicit Deny statements for security-critical restrictions:

```json
{
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:*",
      "Resource": "*"
    },
    {
      "Effect": "Deny",
      "Action": "s3:DeleteObject",
      "Resource": "*",
      "Condition": {
        "Bool": {
          "aws:MultiFactorAuthPresent": "false"
        }
      }
    }
  ]
}
```

### 2. Combine Conditions for Defense in Depth

Use multiple conditions to add layers of security:

```json
{
  "Condition": {
    "IpAddress": { "aws:SourceIp": "10.0.0.0/8" },
    "Bool": { "aws:MultiFactorAuthPresent": "true" },
    "NumericLessThan": { "aws:MultiFactorAuthAge": "3600" }
  }
}
```

### 3. Use IfExists for Optional Checks

Use `IfExists` operators when conditions are optional:

```json
{
  "StringEqualsIfExists": {
    "aws:PrincipalTag/Environment": "production"
  }
}
```

This allows the policy to work even if the tag doesn't exist.

### 4. Tenant Isolation

Always enforce tenant isolation in multi-tenant scenarios:

```json
{
  "StringEquals": {
    "wami:TenantId": "${wami:PrincipalTenantId}"
  }
}
```

### 5. Time-Based Restrictions

Use date conditions for time-sensitive access:

```json
{
  "DateGreaterThan": { "aws:CurrentTime": "2024-01-01T09:00:00Z" },
  "DateLessThan": { "aws:CurrentTime": "2024-01-01T17:00:00Z" }
}
```

## Troubleshooting

### Condition Not Matching

If a condition isn't matching as expected:

1. **Check context entries**: Ensure all required context keys are provided
2. **Verify operator syntax**: Use correct operator names (case-sensitive)
3. **Check value types**: Ensure context values match expected types (String, Numeric, Boolean)
4. **Review AND logic**: Remember all conditions must pass

### Common Issues

**Issue:** Condition always fails
- **Solution:** Check if context key exists and has correct value type

**Issue:** IfExists condition fails when key is missing
- **Solution:** Use `IfExists` variant (e.g., `StringEqualsIfExists`)

**Issue:** Date condition not working
- **Solution:** Ensure dates are in RFC3339 format: `2024-01-01T12:00:00Z`

**Issue:** IP address condition not matching
- **Solution:** Use CIDR notation: `203.0.113.0/24` not `203.0.113.*`

## See Also

- [Condition Keys Design Document](CONDITION_KEYS_DESIGN.md) - Detailed architecture
- [Condition Keys Implementation](CONDITION_KEYS_IMPLEMENTATION.md) - Implementation details
- [API Reference](API_REFERENCE.md) - Full API documentation
- [Policy Evaluation Service](../crates/wami/src/service/policies/evaluation.rs) - Source code

