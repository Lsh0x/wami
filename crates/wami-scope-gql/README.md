# wami-scope-gql

A [`wami-scope`](../wami-scope) predicate rendered as a GQL `WHERE` fragment
and its parameters, for a graph store (Grafeo, or any GQL engine) to narrow
what it reads before the evaluator re-checks every row.

```rust
let scope = Scope::compile(&policies, "atlas:ReadItem", &ctx)?;
let f = arn_filter(&scope, "n", "arn", "s")?;   // render(&scope.lower(), …)
// f.text   = "(((n.arn STARTS WITH $s0) OR (n.arn = $s1)) AND (NOT (n.arn = $s2)))"
// f.params = [("s0", "arn:wami:atlas:100:wami:1:archive/"), ("s1", …), ("s2", …)]
let query = format!("MATCH (n:Thing) WHERE {} RETURN n.arn", f.text);
// run it with f.params bound, then keep the rows scope.matches(arn) keeps.
```

The lowering (a glob to its prefix, a deny kept only when exact, nothing
granted to nothing) is `Scope::lower`'s, proved once in `wami-scope`. This
crate renders the predicate: `=`, `STARTS WITH`, `AND`, `OR`, `NOT`, `true`,
`false`, every node parenthesised, every value a parameter. Its tests prove
the rendering equal to `Predicate::keeps`.

No database dependency. The tests against a real graph store (tenants,
principals, projects, the wami-scope harness) are in
`wami-scope-grafeo-tests`, which needs a newer toolchain than wami's MSRV.
