//! Nothing but tests: `tests/store.rs` runs `wami-scope-gql`'s fragment
//! against a real graph store, Grafeo, loaded with the harness's world —
//! tenants, principals, maps and their layers, an archive, memos and places.
//!
//! Out of the workspace's default members (Grafeo 0.6 needs Rust 1.99, above
//! wami's MSRV): `cargo test -p wami-scope-grafeo-tests` on stable.

#![forbid(unsafe_code)]
