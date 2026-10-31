# Issue #008: `wami-scope` — policies compiled into what a query may reach

**Status**: 🟡 In progress — built and merged: `wami-scope` (compile, fence, narrowing, lints), `wami-scope-gql`, `wami-scope-tests` (the sharing world on a real store, the port, the suite, Grafeo), `AuthorizationService::documents`; remain: `wami-scope-sql` with `tests/sqlite.rs`, the services' call sites, the yuga allowlist, three wami issues named below  
**Priority**: High  
**Type**: Feature Enhancement  
**Assignee**: TBD  
**Created**: 2026-10-30  
**Labels**: `enhancement`, `policy-engine`, `multi-tenant`, `wami-feature`  
**Design**: studio, project `wami`, conversation `wami-008-scope` (design-discussion; diagram #2, the sharing world, v13)

## Summary

A storage-agnostic crate, `wami-scope`, that compiles a principal's policies
for one action into a `Scope`: the ARN patterns the principal may reach, the
patterns denied, and whether a statement could not be folded. One small
translator per backend turns a scope into that store's own query. The
evaluator keeps deciding on every row; the scope only narrows what the store
reads.

## Current State

Three anatta services already do this, each by hand and each incompletely:

- anatta-studio `app/src/rights/filter.rs`: grants compiled into SQL (a byte
  range on the motif's literal prefix plus `wami_match`, wami's glob
  registered in SQLite), rows re-checked by `decide`, a property test that the
  filter's rows equal the rows `decide` allows. SQLite only. Deny and
  Condition refused at boot.
- gitsense and sippa `crates/rights/filter.rs`: `ArnFilter` as a value (role
  motifs, token motifs) with `prefixes()` for adapters and `retain` for the
  re-check. No adapter calls `prefixes()`. Gitsense D35 names "a query takes a
  scope" and has no type for it.
- sippa's yuga retriever runs top-k before any right is applied: a principal
  who may read few entries gets empty pages.
- wami's `policy_evaluator` is forward only: Deny over Allow, Conditions,
  `*` and `**`, `${tenant}` `${principal}` `${service}`. Nothing answers
  "which ARN patterns may this principal reach for this action".

## Problem Statement

Shared resources (a public source read by many tenants, a lesson visible to
some members, a project readable by a subset) need every list, search and
traversal to hit only what the caller may reach, before the store answers.
Post-hoc filtering is wrong twice: a top-k search loses hits a scoped caller
should have seen, and every service rewrites the compile step, so `*`, `**`
and Deny end up read three different ways.

## Proposed Solution

### Layer 1: `wami-scope` (this workspace)

```rust
pub struct Scope {
    pub allow: Vec<Pattern>,
    pub deny: Vec<Pattern>,
    /// A matching statement the compiler could not fold (a Condition), or a
    /// permissions boundary the caller did not compile: the re-check does
    /// real work.
    pub residual: bool,
    /// The action compiled for: its service is the fence's service axis.
    pub action: String,
    /// The fence, when fenced: exact trees a row must also match.
    pub fence: Vec<Pattern>,
}

impl Scope {
    pub fn compile(policies: &[PolicyDocument], action: &str, ctx: &MatchContext) -> Result<Scope, ScopeError>;
    /// The service's fence: the tenant roots it gives (the caller's, the
    /// public space it opens) and their descendants, in the action's
    /// service — a conjunction `matches` requires and `lower` ands. A
    /// fenced scope may exclude what the bare evaluator allows: its oracle
    /// is the evaluator and the fence. It mirrors what the services'
    /// `decide` refuses before any document; never assumed by the library.
    pub fn fenced(&self, tenants: &[&str]) -> Scope;
    /// The evaluator's own glob and substitution (wami_core::arn::matching).
    pub fn matches(&self, arn: &str) -> bool;
    /// Lowered to exact, prefix, and, or, not: what every store renders.
    pub fn lower(&self) -> Predicate;
    pub fn prefixes(&self) -> Vec<&str>;
    pub fn is_empty(&self) -> bool;
}

/// The scopes of one query, by bound name (a GQL variable, a SQL alias),
/// each under the action reading it stands for; `bind` a returned name,
/// `test` a name only tested (EXISTS, count, ORDER BY); `admit(row)` is the
/// re-check a returned row cannot skip. Nothing in it is a traversal or a
/// syntax.
pub struct Narrowing { /* bindings */ }

impl Pattern {
    /// Literal service and tenant (or `${service}`, `${tenant}`, or a
    /// tenant followed by `/*`), `*` inside a segment, `**` only as a
    /// trailing `/**`: the subset a store translates exactly. Services check
    /// their role documents against it at boot.
    pub fn compilable(motif: &str) -> Result<(), NotCompilable>;
}
```

`AuthorizationService::documents(context)` (wami) hands out the documents
the evaluator reads for a caller — identity documents in reading order, the
boundary apart, root flagged — so a scope is compiled from exactly what a
row is then judged on.

`wami-scope-tests` (unpublished) holds the world, the oracle and the suite:
a cloud account's shape (buckets, directories, functions, topics, keys;
users, groups, roles, sessions, a boundary; shares as trees across tenants)
loaded into a real `InMemoryWamiStore`, the oracle `authorize` itself, a
port (`Store::load`, `run(shape, narrowing)`, seven shapes without a
syntax), an in-memory reference, and the suite — the table by hand, every
principal × shape bare and fenced, tightness, the leak detectors (an unbound
child, a count, an ORDER BY, an EXISTS under a loose scope), random policies
and random shapes. `tests/grafeo.rs` runs it on Grafeo; a SQL store will be
`tests/sqlite.rs`.

### Layer 2: one translator per backend, each its own crate

- `wami-scope-sql` (this workspace): `Scope` to a clause over an `arn`
  column and its params. `arn = ?` for a literal; `(arn >= ? AND arn < ? AND
  wami_match(?, arn))` for a pattern, `OR arn = <path>` for a trailing `/**`;
  deny patterns as `AND NOT`; `0` when empty. SQLite now, Postgres later with
  the same output.
- `wami-scope-gql` (this workspace, 2026-10-31: the user chose wami over a
  repository of its own or anatta): `Scope` to a GQL `WHERE` fragment and its
  parameters — `=` for a literal, `STARTS WITH` for a prefix, both for a
  trailing `/**`; a deny pushed down only when exact; `scope.matches` on each
  row, since GQL has no user-defined function for the glob; `narrowing_filter`
  renders a whole query's bindings, parameters prefixed per name. Checked
  against Grafeo in `wami-scope-tests` (out of the default members: Grafeo
  0.6 needs Rust 1.99, above the MSRV).
- yuga translator (in anatta, in the search adapters): an id allowlist built
  from the store's ARN index before top-k, else oversampling with the scope
  as filter.
- In-memory stores: `scope.matches` on each item.

None of the translators depends on another. wami never depends on a
database.

### The invariant

A scope may over-include. It may never exclude a row `decide` would allow.
A pattern a translator cannot express widens to its prefix and lets the
re-check pay. Every row a store returns still goes through `decide`.

## Implementation Plan

1. ✅ `wami-scope`: `Scope`, `Pattern`, `compile`, `fenced`, `lower`,
   `Narrowing`, `compilable`; `wami-scope-gql`; `wami-scope-tests` with the
   suite on Grafeo; `AuthorizationService::documents`.
2. `wami-scope-sql`, ported from studio's `filter.rs`, run by the suite as
   `tests/sqlite.rs`. Studio's `filter.rs` becomes a call.
3. sippa: yuga id allowlist before top-k; `rights/filter.rs` becomes a call;
   the `Narrowing` on every graph query, `admit` then `decide` on each row.
4. gitsense: the same on the `GraphStore` adapter; D35's scope as a set of
   (database, patterns).
5. wami, found while building the world (each its own issue): a session's
   `${tenant}` and `${principal}` resolve from the assumer's key, not the
   role's (a role meant for outsiders names its tenant literally today); the
   trust policy is not evaluated at `AssumeRole`; the evaluator lets a policy
   name any tenant's ARN (one side of AWS's two) — the fence on the
   evaluator's side.

## Testing Strategy

- The harness, run by every translator.
- Per translator: an empty scope yields an empty query; a Deny removes a row
  the Allow covered; a Condition sets `residual` and never drops a row; a
  pattern outside the compilable subset is refused by `compilable` and, if it
  reaches a translator anyway, widens to its prefix.
- `matches` agrees with `policy_evaluator` on every pattern of the matching
  module's tests.

## Success Criteria

- studio, gitsense and sippa have no hand-written compile step left.
- A scoped principal's search in sippa returns its hits, not empty pages.
- One reading of `*`, `**`, Deny and variables across the ecosystem,
  enforced by the harness.

## Dependencies

- `wami_core::arn::matching` (glob, substitution) is the only matching code.
- anatta-auth later serves a member's policies; the compile runs in the
  service from what it fetched, no call site moves.

## Risks & Mitigations

- A translator under-approximates: the harness fails; the invariant is the
  test, not a comment.
- Conditions that depend on request context cannot be pushed down: they set
  `residual`, the re-check decides, and the scope stays the Allow patterns.
- Scope size on wide policies: prefixes are few per role; measured on
  studio's SQL today.
