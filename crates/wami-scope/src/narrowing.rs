//! A query that binds several resources, each judged under its own action:
//! one scope per bound name, and the re-check a row cannot skip.
//!
//! A GQL variable, a SQL alias, a search engine's ARN field: every store has
//! a *name* that holds an ARN in a query, and a query holds several. Each is
//! judged under the action that reading it stands for (`s3:ListBucket` on
//! the bucket, `s3:GetObject` on the object), so each gets its own
//! [`Scope`]. Nothing here is a traversal, an edge or a syntax: a translator
//! renders every binding as its store names it, and a service that forgot to
//! bind a name it returns or tests has no scope for it — which the suite
//! catches, and which [`Narrowing::admit`] refuses.

use std::fmt;

use crate::{Predicate, Scope};

/// One bound name of a query and the scope it is judged under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    /// The name as the query binds it (a variable, an alias).
    pub name: String,
    /// The scope of the action reading it stands for.
    pub scope: Scope,
    /// Whether the query returns it (then [`Narrowing::admit`] re-checks
    /// it) or only tests it (`EXISTS`, `count`, `ORDER BY`: nothing comes
    /// back to re-check, so only a tight scope keeps it from leaking).
    pub returned: bool,
}

/// The scopes of one query, by bound name, and the re-check of its rows.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Narrowing {
    bindings: Vec<Binding>,
}

/// Why a binding is refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NarrowingError {
    /// A name bound twice: two scopes for one place would be a choice nobody
    /// made.
    #[error("{0:?} is bound twice")]
    DuplicateBinding(String),
}

impl Narrowing {
    /// No binding yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Binds `name`, a name the query returns, to `scope`.
    ///
    /// # Errors
    ///
    /// [`NarrowingError::DuplicateBinding`] when `name` is already bound.
    pub fn bind(self, name: &str, scope: Scope) -> Result<Self, NarrowingError> {
        self.add(name, scope, true)
    }

    /// Binds `name`, a name the query only tests (`EXISTS`, `count`,
    /// `ORDER BY`) and never returns, to `scope`: the store filters it, and
    /// nothing comes back to re-check. A service uses it with a tight scope,
    /// or accepts that a residual one may let an existence show.
    ///
    /// # Errors
    ///
    /// [`NarrowingError::DuplicateBinding`] when `name` is already bound.
    pub fn test(self, name: &str, scope: Scope) -> Result<Self, NarrowingError> {
        self.add(name, scope, false)
    }

    fn add(mut self, name: &str, scope: Scope, returned: bool) -> Result<Self, NarrowingError> {
        if self.bindings.iter().any(|b| b.name == name) {
            return Err(NarrowingError::DuplicateBinding(name.into()));
        }
        self.bindings.push(Binding {
            name: name.into(),
            scope,
            returned,
        });
        Ok(self)
    }

    /// The bindings, in binding order.
    #[must_use]
    pub fn bindings(&self) -> &[Binding] {
        &self.bindings
    }

    /// Each binding's scope lowered: what a translator renders, name by name.
    #[must_use]
    pub fn lowered(&self) -> Vec<(&str, Predicate)> {
        self.bindings
            .iter()
            .map(|b| (b.name.as_str(), b.scope.lower()))
            .collect()
    }

    /// Whether the scopes alone would decide every row (no binding residual
    /// or fenced): then a row the store keeps and [`Narrowing::admit`]
    /// accepts is exactly a row the evaluator allows.
    #[must_use]
    pub fn is_exact(&self) -> bool {
        self.bindings
            .iter()
            .all(|b| !b.scope.residual && b.scope.fence.is_empty())
    }

    /// The re-check: whether `row` — the ARN each returned name holds in one
    /// row the store returned — passes every returned binding's scope. A
    /// returned name the row does not carry fails it: a store that did not
    /// return what the query bound returned a row nobody can judge. A tested
    /// name is not looked for.
    #[must_use]
    pub fn admit(&self, row: &[(&str, &str)]) -> bool {
        self.bindings.iter().filter(|b| b.returned).all(|b| {
            row.iter()
                .find(|(name, _)| *name == b.name)
                .is_some_and(|(_, arn)| b.scope.matches(arn))
        })
    }
}

impl fmt::Display for Narrowing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<&str> = self.bindings.iter().map(|b| b.name.as_str()).collect();
        write!(f, "narrowing on {}", names.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wami_core::arn::matching::MatchContext;
    use wami_core::types::{PolicyDocument, PolicyStatement};

    fn scope(action: &str, resource: &str) -> Scope {
        let document = PolicyDocument {
            version: "2012-10-17".into(),
            statement: vec![PolicyStatement {
                sid: None,
                effect: "Allow".into(),
                action: vec![action.into()],
                resource: vec![resource.into()],
                condition: None,
            }],
        };
        let ctx = MatchContext {
            tenant: Some("100".into()),
            ..MatchContext::default()
        };
        Scope::compile(&[document], action, &ctx).unwrap()
    }

    #[test]
    fn every_bound_name_is_judged_and_a_missing_one_fails_the_row() {
        let n = Narrowing::new()
            .bind(
                "b",
                scope("s3:ListBucket", "arn:wami:s3:${tenant}:wami:*:bucket/atlas"),
            )
            .unwrap()
            .bind(
                "o",
                scope(
                    "s3:GetObject",
                    "arn:wami:s3:${tenant}:wami:*:bucket/atlas/conv/c1/**",
                ),
            )
            .unwrap();
        let bucket = "arn:wami:s3:100:wami:1:bucket/atlas";
        let shared = "arn:wami:s3:100:wami:1:bucket/atlas/conv/c1/thread/t1/msg/1";
        let private = "arn:wami:s3:100:wami:1:bucket/atlas/conv/c2/thread/t1/msg/1";
        assert!(n.admit(&[("b", bucket), ("o", shared)]));
        assert!(
            !n.admit(&[("b", bucket), ("o", private)]),
            "the object's scope, not the bucket's"
        );
        assert!(
            !n.admit(&[("b", bucket)]),
            "a bound name the row does not carry"
        );
        assert!(
            n.admit(&[("o", shared), ("b", bucket), ("x", "whatever")]),
            "order and extras do not matter"
        );
        assert_eq!(n.lowered().len(), 2);
        assert!(n.is_exact());
        assert_eq!(n.to_string(), "narrowing on b, o");
    }

    #[test]
    fn a_name_bound_twice_is_refused() {
        let got = Narrowing::new()
            .bind("n", scope("s3:GetObject", "*"))
            .unwrap()
            .bind("n", scope("s3:ListBucket", "*"));
        assert_eq!(got, Err(NarrowingError::DuplicateBinding("n".into())));
    }

    #[test]
    fn a_fenced_or_residual_binding_is_not_exact() {
        let n = Narrowing::new()
            .bind("n", scope("s3:GetObject", "*").fenced(&["100"]))
            .unwrap();
        assert!(!n.is_exact());
        assert!(n.admit(&[("n", "arn:wami:s3:100:wami:1:bucket/atlas")]));
        assert!(!n.admit(&[("n", "arn:wami:s3:200:wami:1:bucket/atlas")]));
    }
}
