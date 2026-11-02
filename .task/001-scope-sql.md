# 001 — SQL scope translator

status: complete
rank: 9
branch: task/001-scope-sql
source: issue #008, policy-scope
studio: project pzwxzjvxjygg, conversation c2xr04apyrpf

## Request

2026-11-02: Build `wami-scope-sql` in wami, test policy-to-SQL narrowing and isolation, then measure and integrate it in Studio where it improves conversation opening.

## Summary

Render `wami_scope::Predicate` and `Narrowing` into parameterized SQLite SQL over ARN columns. SQL may over-include but must never exclude an evaluator-allowed row. Callers must still run `decide` on returned rows. The Studio path additionally needs a direct `reference → message → conversation` join to remove repeated thread lookup.

## Design

TARGET: `Scope::lower` → `wami-scope-sql` → SQLite WHERE over named ARN columns → returned rows → `decide`. Each bound query alias has its own predicate. Exact and prefix tests use SQLite binary string semantics; every value is bound. The query's tenant/project joins remain explicit store constraints.

## Log

- 2026-11-02: SQL-only Studio replay found 4.98 s median in current reference walk, 0.13 ms for a direct join prototype. Existing issue #008 and D47 define the translator and re-check invariant.
- 2026-11-02: Added SQL translator, five SQLite tests, the shared evaluator suite on SQLite, and 64 random shape/principal/fence cases. `cargo test --workspace` and targeted Clippy pass.
- 2026-11-02: Registered the new `0.1.0` crate for release; no existing crate version changed. PR #156.
