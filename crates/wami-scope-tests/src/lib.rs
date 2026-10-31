//! The world, the oracle and the suite every translator of `wami-scope`
//! runs (wami 008). Tests only, never published.
//!
//! [`world`] is a cloud account's shape loaded into a real wami store —
//! tenants, buckets and their directories, functions, topics, keys; users,
//! groups, roles, sessions, a permissions boundary; shares as trees across
//! tenants. [`oracle`] is `authorize` on that store, the only definition of
//! "allowed", and the scope compiled from exactly the documents it reads.
//! [`port`] is what a store implements: load the world, run a [`port::Shape`]
//! under a [`wami_scope::Narrowing`]. [`reference`](crate::reference) gives every shape its
//! meaning in memory. [`suite`] holds a store to the invariant on every
//! principal, every shape, bare and fenced, and proves it would see a leak.
//! [`arbitrary`] draws random policies and ARNs for the property tests.
//!
//! # The invariant
//!
//! A bare scope **may over-include, never exclude** a row `authorize`
//! allows; once its rows are admitted ([`wami_scope::Narrowing::admit`]) and
//! judged, exactly those. A fenced scope is held to `authorize` **and** the
//! fence. Where every pattern is in the compilable subset, the store's rows
//! are exactly the allowed rows before any re-check: narrow before answer.
//!
//! # The contract on the rows
//!
//! The evaluator judges the ARN as `WamiArn` displays it once parsed; the
//! scope and every store judge the row's text. They agree on canonical rows
//! only (`…:100:…`, never `…:0100:…`); [`suite::canonical`] refuses a
//! universe outside the contract.
//!
//! A store runs the suite from its own tests, with this crate among its
//! dev-dependencies:
//!
//! ```rust,ignore
//! let world = World::standard().await;
//! let mut store = MyStore::new();
//! store.load(&world);
//! suite::run_all(&world, &store).await;
//! ```

pub mod arbitrary;
pub mod oracle;
pub mod port;
pub mod reference;
pub mod suite;
pub mod world;
