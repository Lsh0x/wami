# wami-scope-sql

Renders a `wami-scope` predicate into a parameterized SQLite `WHERE` fragment.
Every returned resource must still be judged with the evaluator's `decide`.

Each alias in a multi-resource query gets its own scope. The service remains
responsible for tenant and container joins.
