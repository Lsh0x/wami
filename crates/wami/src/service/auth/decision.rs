//! What an authorization decision was, and what decided it.
//!
//! `authorize` used to return `bool`. A verdict cannot be audited and cannot be
//! explained: a log line needs to name the statement that decided, and a denied
//! user needs to be told what they lack. Neither is recoverable from `true` /
//! `false`.
//!
//! The effect is carried by the variant rather than a separate field, so
//! combinations the domain forbids — an `Allow` justified by a missing
//! permissions boundary, say — cannot be constructed at all.

use std::fmt;
use std::ops::Deref;

/// A list that cannot be empty.
///
/// [`Decision`] is public API, so "this list always has at least one element"
/// is worth making unrepresentable rather than documenting. Small enough to own
/// outright — it would be a poor trade to take a dependency for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonEmpty<T>(Vec<T>);

impl<T> NonEmpty<T> {
    /// Wrap `items`, or return them untouched if there is nothing to wrap.
    ///
    /// The rejected input is handed back rather than dropped: callers that hit
    /// the empty case usually need the allocation to build an error.
    pub fn new(items: Vec<T>) -> Result<Self, Vec<T>> {
        if items.is_empty() {
            Err(items)
        } else {
            Ok(Self(items))
        }
    }

    /// A list of exactly one.
    pub fn one(item: T) -> Self {
        Self(vec![item])
    }

    /// The first element. Total, by construction.
    pub fn first(&self) -> &T {
        &self.0[0]
    }

    /// Give up the guarantee and take the elements.
    pub fn into_vec(self) -> Vec<T> {
        self.0
    }
}

impl<T> Deref for NonEmpty<T> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        &self.0
    }
}

impl<T> IntoIterator for NonEmpty<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a, T> IntoIterator for &'a NonEmpty<T> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

/// Where a statement came from.
///
/// The declaration order is load-bearing: it is the collection order of
/// [`AuthorizationService::authorize`], and the derived [`Ord`] is what makes
/// the reported sources deterministic regardless of what order the store
/// happened to return rows in.
///
/// [`AuthorizationService::authorize`]: crate::service::auth::AuthorizationService::authorize
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum PolicySource {
    /// A managed policy attached to the user.
    UserManaged {
        /// The policy's ARN.
        arn: String,
    },
    /// A policy inlined on the user.
    UserInline {
        /// The policy's name.
        name: String,
    },
    /// A managed policy attached to one of the user's groups.
    GroupManaged {
        /// The group holding the attachment.
        group: String,
        /// The policy's ARN.
        arn: String,
    },
    /// A policy inlined on one of the user's groups.
    GroupInline {
        /// The group holding the policy.
        group: String,
        /// The policy's name.
        name: String,
    },
    /// A managed policy attached to the assumed role.
    RoleManaged {
        /// The assumed role.
        role: String,
        /// The policy's ARN.
        arn: String,
    },
    /// A policy inlined on the assumed role.
    RoleInline {
        /// The assumed role.
        role: String,
        /// The policy's name.
        name: String,
    },
    /// The permissions boundary itself.
    ///
    /// Not a source of permissions — a ceiling on them. It appears here so
    /// [`AmiError::UnreadablePolicy`] can say *which* document failed to parse,
    /// the boundary being read on a different path from the identity policies.
    ///
    /// [`AmiError::UnreadablePolicy`]: wami_core::error::AmiError::UnreadablePolicy
    PermissionsBoundary {
        /// The boundary policy's ARN.
        arn: String,
    },
}

impl fmt::Display for PolicySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UserManaged { arn } => write!(f, "user managed policy {arn}"),
            Self::UserInline { name } => write!(f, "user inline policy {name}"),
            Self::GroupManaged { group, arn } => {
                write!(f, "managed policy {arn} of group {group}")
            }
            Self::GroupInline { group, name } => {
                write!(f, "inline policy {name} of group {group}")
            }
            Self::RoleManaged { role, arn } => write!(f, "managed policy {arn} of role {role}"),
            Self::RoleInline { role, name } => write!(f, "inline policy {name} of role {role}"),
            Self::PermissionsBoundary { arn } => write!(f, "permissions boundary {arn}"),
        }
    }
}

/// The statement that decided, and the policy it came from.
///
/// One per contributing source — the *decisive* statement of that document, not
/// every statement it contains: evaluation stops at the first match within a
/// document, deny before allow.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct StatementRef {
    /// Which policy this statement lives in.
    pub policy: PolicySource,
    /// The statement's `Sid`, when the author supplied one.
    pub sid: Option<String>,
    /// Position in the document.
    ///
    /// A fallback for statements with no `Sid`, and deliberately not a stable
    /// identifier: rewriting a policy renumbers it. Fine for reproducing a
    /// decision now, not for pinning one in a durable log.
    pub index: usize,
}

impl fmt::Display for StatementRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.sid {
            Some(sid) => write!(f, "statement `{sid}` of {}", self.policy),
            None => write!(f, "statement #{} of {}", self.index, self.policy),
        }
    }
}

/// Why access was granted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowReason {
    /// The caller is root, so no policy was consulted at all.
    ///
    /// Root bypasses the permissions boundary too, as it does in AWS.
    RootBypass,
    /// Statements that allowed the action, in collection order.
    Statements(NonEmpty<StatementRef>),
}

/// Why access was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyReason {
    /// Nothing matched.
    ///
    /// An implicit denial: there is no statement to name, because none applied.
    /// The permissions boundary is not consulted on this path — it can only
    /// narrow permissions, never grant them, so with nothing to narrow it
    /// cannot change the outcome.
    NoMatch,
    /// Statements that explicitly denied the action, in collection order.
    Statements(NonEmpty<StatementRef>),
    /// The identity policies allowed it and the permissions boundary did not.
    BoundaryRestricted {
        /// The boundary that cut the action off.
        arn: String,
        /// What would otherwise have allowed it.
        allowed_by: NonEmpty<StatementRef>,
        /// Explicit denials inside the boundary.
        ///
        /// Empty means the boundary simply does not cover the action — the fix
        /// is to widen it. Non-empty means it refuses the action outright — the
        /// fix is to remove those statements. Opposite remedies, so the
        /// distinction has to survive into the log.
        denied_by: Vec<StatementRef>,
    },
    /// The user references a permissions boundary that the store does not hold.
    ///
    /// Fails closed: a ceiling that cannot be read cannot be honoured.
    BoundaryMissing {
        /// The ARN that resolved to nothing.
        arn: String,
    },
}

/// An authorization decision, and what produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The action is permitted.
    Allow(AllowReason),
    /// The action is refused.
    Deny(DenyReason),
}

impl Decision {
    /// Whether the action is permitted.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow(_))
    }
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow(AllowReason::RootBypass) => write!(f, "allowed: caller is root"),
            Self::Allow(AllowReason::Statements(refs)) => {
                write!(f, "allowed by {}", refs.first())
            }
            Self::Deny(DenyReason::NoMatch) => {
                write!(f, "denied: no statement matches this action and resource")
            }
            Self::Deny(DenyReason::Statements(refs)) => write!(f, "denied by {}", refs.first()),
            Self::Deny(DenyReason::BoundaryRestricted { arn, denied_by, .. }) => {
                match denied_by.first() {
                    Some(statement) => write!(
                        f,
                        "denied by {statement}: permissions boundary {arn} refuses this action"
                    ),
                    None => write!(
                        f,
                        "denied: permissions boundary {arn} does not cover this action"
                    ),
                }
            }
            Self::Deny(DenyReason::BoundaryMissing { arn }) => {
                write!(f, "denied: permissions boundary {arn} was not found")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn statement(policy: PolicySource, sid: Option<&str>) -> StatementRef {
        StatementRef {
            policy,
            sid: sid.map(str::to_string),
            index: 0,
        }
    }

    #[test]
    fn an_empty_list_cannot_become_non_empty() {
        assert!(NonEmpty::<u8>::new(vec![]).is_err());
        assert_eq!(NonEmpty::new(vec![1, 2]).unwrap().first(), &1);
    }

    #[test]
    fn sources_sort_in_evaluation_order_not_store_order() {
        // The whole point of the canonical sort: the store guarantees no
        // ordering, so two backends returning the same policies in different
        // orders must still produce the same audit line.
        let mut shuffled = vec![
            PolicySource::RoleInline {
                role: "r".into(),
                name: "n".into(),
            },
            PolicySource::UserManaged { arn: "a".into() },
            PolicySource::GroupInline {
                group: "g".into(),
                name: "n".into(),
            },
            PolicySource::UserInline { name: "n".into() },
        ];
        shuffled.sort();

        assert_eq!(
            shuffled,
            vec![
                PolicySource::UserManaged { arn: "a".into() },
                PolicySource::UserInline { name: "n".into() },
                PolicySource::GroupInline {
                    group: "g".into(),
                    name: "n".into()
                },
                PolicySource::RoleInline {
                    role: "r".into(),
                    name: "n".into()
                },
            ]
        );
    }

    #[test]
    fn a_denied_user_is_told_what_to_fix() {
        // The two boundary cases call for opposite remedies, so they must not
        // read the same.
        let allowed = NonEmpty::one(statement(
            PolicySource::UserManaged { arn: "p".into() },
            Some("AllowAll"),
        ));

        let uncovered = Decision::Deny(DenyReason::BoundaryRestricted {
            arn: "b".into(),
            allowed_by: allowed.clone(),
            denied_by: vec![],
        });
        assert!(uncovered.to_string().contains("does not cover"));

        let refused = Decision::Deny(DenyReason::BoundaryRestricted {
            arn: "b".into(),
            allowed_by: allowed,
            denied_by: vec![statement(
                PolicySource::PermissionsBoundary { arn: "b".into() },
                Some("DenyWrites"),
            )],
        });
        assert!(refused.to_string().contains("DenyWrites"));
        assert!(refused.to_string().contains("refuses this action"));
    }

    #[test]
    fn a_statement_without_a_sid_falls_back_to_its_index() {
        let named = statement(PolicySource::UserInline { name: "p".into() }, Some("Sid1"));
        assert!(named.to_string().contains("`Sid1`"));

        let anonymous = StatementRef {
            policy: PolicySource::UserInline { name: "p".into() },
            sid: None,
            index: 3,
        };
        assert!(anonymous.to_string().contains("#3"));
    }
}
