//! A principal's policies, compiled into what a query may reach (wami 008).
//!
//! The evaluator answers one question: may this principal do this action on
//! this ARN? A list, a search or a graph traversal asks the reverse one —
//! which ARNs may this principal reach for this action? — and asks it
//! *before* the store answers, or a top-k search loses the hits a narrowly
//! scoped caller should have seen.
//!
//! [`Scope::compile`] folds the policies for one action into the allow and
//! deny patterns they name, resolved with the caller's `${tenant}`,
//! `${principal}` and `${service}`. [`Scope::lower`] turns them into a
//! [`Predicate`] — exact, prefix, and, or, not — the one lowering every store
//! shares; a translator (one crate per store: `wami-scope-gql`,
//! `wami-scope-sql`) only renders it in that store's syntax. The evaluator
//! keeps deciding on every row; the scope only narrows what the store reads.
//!
//! # The invariant
//!
//! **A scope may over-include. It may never exclude a row the evaluator would
//! allow.** A statement the compiler cannot fold — a condition, whose truth
//! depends on the request — sets [`Scope::residual`]: an `Allow` under a
//! condition is kept (it may hold), a `Deny` under a condition is dropped (it
//! may not), and the re-check pays. `wami-scope-tests` holds every translator
//! to it: a world, the evaluator as oracle, a suite every store runs.
//!
//! # Example
//!
//! ```
//! use wami_core::arn::matching::MatchContext;
//! use wami_core::types::{PolicyDocument, PolicyStatement};
//! use wami_scope::Scope;
//!
//! let policy = PolicyDocument {
//!     version: "2012-10-17".into(),
//!     statement: vec![
//!         PolicyStatement {
//!             sid: None,
//!             effect: "Allow".into(),
//!             action: vec!["atlas:Read*".into()],
//!             resource: vec!["arn:wami:atlas:${tenant}:wami:*:archive/**".into()],
//!             condition: None,
//!         },
//!         PolicyStatement {
//!             sid: None,
//!             effect: "Deny".into(),
//!             action: vec!["atlas:*".into()],
//!             resource: vec!["arn:wami:atlas:${tenant}:wami:1:archive/house/note/secret".into()],
//!             condition: None,
//!         },
//!     ],
//! };
//! let ctx = MatchContext { tenant: Some("100".into()), ..MatchContext::default() };
//! let scope = Scope::compile(&[policy], "atlas:ReadItem", &ctx).unwrap();
//!
//! assert!(scope.matches("arn:wami:atlas:100:wami:1:archive/house/recipe/soup"));
//! assert!(!scope.matches("arn:wami:atlas:100:wami:1:archive/house/note/secret"), "deny wins");
//! assert!(!scope.matches("arn:wami:atlas:200:wami:1:archive/house/recipe/soup"), "another tenant");
//! assert_eq!(scope.prefixes(), ["arn:wami:atlas:100:wami:"]);
//! assert!(!scope.residual);
//!
//! let lowered = scope.lower(); // what a store filters on, before the re-check
//! assert!(lowered.keeps("arn:wami:atlas:100:wami:1:archive/house/recipe/soup"));
//! assert!(!lowered.keeps("arn:wami:atlas:100:wami:1:archive/house/note/secret"), "an exact deny");
//! assert!(!lowered.keeps("arn:wami:atlas:200:wami:1:archive/house/recipe/soup"));
//! ```

#![forbid(unsafe_code)]

mod narrowing;
mod pattern;
mod predicate;
mod scope;

pub use narrowing::{Binding, Narrowing, NarrowingError};
pub use pattern::{NotCompilable, Pattern};
pub use predicate::Predicate;
pub use scope::{Scope, ScopeError};
