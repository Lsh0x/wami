# wami-scope

A principal's policies, compiled into what a query may reach.

wami's evaluator answers "may this principal do this action on this ARN?".
A list, a search or a graph traversal needs the reverse — "which ARNs may this
principal reach for this action?" — *before* the store answers, or a top-k
search loses the hits a narrowly scoped caller should have seen, and every
service rewrites the compile step its own way.

```rust
let scope = Scope::compile(&policies, "atlas:ReadItem", &match_context)?;
scope.allow      // the patterns an Allow names, variables resolved
scope.deny       // the patterns a Deny names
scope.residual   // a conditioned statement: the re-check does real work
scope.prefixes() // what an index can narrow on
scope.matches(arn) // the re-check, with the evaluator's own glob
scope.lower()    // a Predicate: exact, prefix, and, or, not — what any store filters on
```

The lowering is what every store shares: a glob becomes its literal prefix
(including too much), a deny is kept only when exact, nothing granted becomes
nothing. It is done here, once, with its proof. One translator per store only
renders the predicate in that store's syntax: `wami-scope-gql` (a GQL `WHERE`
fragment and its parameters), `wami-scope-sql` (`LIKE 'p%'`), a search
engine's clause. None depends on a database; wami never does.

## The invariant

**A scope may over-include. It may never exclude a row the evaluator would
allow.** A conditioned `Allow` is kept, a conditioned `Deny` dropped (pushing
it down would exclude a row the evaluator allows when its condition is false),
and `residual` says so. A pattern a store cannot express exactly widens to its
literal prefix. Every row a store returns still goes through `decide`.

The `harness` feature ships the test that holds the lowering to it — a world
of tenants, principals and resources, the evaluator as oracle, random
policies, `check_translator` — and a translator's own tests prove their
rendering equal to `Predicate::keeps`.
