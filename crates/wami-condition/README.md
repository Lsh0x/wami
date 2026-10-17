# wami-condition

IAM policy **condition key** evaluation — the `Condition` block of a policy
statement, decided against a request context.

[![crates.io](https://img.shields.io/crates/v/wami-condition.svg)](https://crates.io/crates/wami-condition)
[![docs.rs](https://docs.rs/wami-condition/badge.svg)](https://docs.rs/wami-condition)

Extracted from [`wami`](https://crates.io/crates/wami), which uses it to decide
whether a statement applies. It is published separately because deciding a
condition block is a self-contained problem: you can use it against your own
policy documents without adopting an identity model.

```toml
[dependencies]
wami-condition = "0.16"
```

## What it evaluates

A condition block maps an operator to the keys it constrains:

```json
{
  "StringEquals":   { "aws:PrincipalAccount": "123456789012" },
  "Bool":           { "aws:SecureTransport": "true" },
  "DateLessThan":   { "aws:CurrentTime": "2026-12-31T23:59:59Z" }
}
```

`evaluate_condition_block` answers whether the whole block holds for a given
[`ConditionContext`]. Every operator family from the AWS condition grammar is
implemented — `String*`, `Numeric*`, `Date*`, `Bool`, `IpAddress`, `Arn*`,
`Binary*` — each with its `Not` and `IfExists` variants, and `ForAllValues` /
`ForAnyValue` set qualifiers.

## The part that is easy to get wrong

`IfExists` is not "optional". `StringEqualsIfExists` passes when the key is
**absent**, and is only checked when the key is present — which means adding
`IfExists` to a `Deny` can turn a rule that blocked something into one that
permits it. The distinction is implemented, and tested.

Likewise an absent key under a plain operator makes the condition **false**,
not true — as in AWS, a key the request does not carry is not met.

An **unreadable** condition is not a false one. An operator nobody defined
(`StringEqualz`), a value its operator cannot read (an `IpAddress` that is no
address, a `Bool` that is neither `true` nor `false`, a list where the operator
reads one value) is refused by `parse_condition_block`, and an evaluation that
cannot be carried out — a context value the operator cannot compare — is an
`Err` from `evaluate_condition_block`, never a `false`. Answered as `false`,
it made the statement carrying it vanish: for a `Deny`, the rule meant to block
an action stopped applying.

## Context keys

The `aws:` keys are recognised natively — `PrincipalArn`, `PrincipalAccount`,
`PrincipalType`, `CurrentTime`, `EpochTime`, `SecureTransport`,
`MultiFactorAuthPresent`, `MultiFactorAuthAge`, `RequestedRegion`,
`ResourceArn`, `ResourceAccount`, `Referer` and more. Any key the table does
not name falls through to `ConditionContext::custom_values`, so your own keys
work by putting them there — no registration step.

## License

MIT. See [LICENSE](https://github.com/Lsh0x/wami/blob/main/LICENSE).

[`ConditionContext`]: https://docs.rs/wami-condition/latest/wami_condition/context/struct.ConditionContext.html
