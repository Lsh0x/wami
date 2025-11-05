# wami (crate)

Crate-level README for the internal `wami` workspace member. This crate
implements the service, store, and API façade that backs the public
`wami` crate at the workspace root.

## Highlights

- Re-exports identity, credential, policy, STS, tenant, and SSO Admin modules.
- Provides service layer implementations backed by trait-oriented stores.
- Offers compatibility helpers for users migrating from the monolithic layout.

## Development

This crate is not published directly to crates.io—the top-level `wami` crate is
published instead. Developers working inside the workspace should depend on the
root crate; this directory exists to keep the workspace organized.

## Tests

Run all unit tests from the workspace root:

```bash
cargo test
```

## License

Licensed under MIT. See [`../../LICENSE`](../../LICENSE) for details.
