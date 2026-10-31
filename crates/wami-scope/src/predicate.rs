//! The scope lowered to what any store can filter on: a small predicate over
//! the ARN's text, built once here, rendered by each translator.
//!
//! What SQL, GQL and a search engine share is the lowering, not the syntax:
//! a glob becomes its literal prefix (including too much); a deny is kept
//! only when it is exact, else ignored; a scope granting nothing becomes
//! nothing. The proof that the lowering never excludes a row the evaluator
//! allows lives with it, once ([`Predicate::keeps`] against the harness); a
//! translator only renders — `arn LIKE 'p%'`, `n.arn STARTS WITH $p`, a
//! clause of a search engine — and proves its rendering equal to `keeps`.

use crate::{Pattern, Scope};

/// A test on an ARN's text, as every store can run it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Predicate {
    /// Every row.
    All,
    /// No row.
    None,
    /// The row whose ARN is exactly this.
    Exact(String),
    /// The rows whose ARN starts with this.
    Prefix(String),
    /// Every operand holds.
    And(Vec<Predicate>),
    /// Some operand holds.
    Or(Vec<Predicate>),
    /// The operand does not hold.
    Not(Box<Predicate>),
}

impl Predicate {
    /// Whether `text` passes: the reference every rendering is held to.
    #[must_use]
    pub fn keeps(&self, text: &str) -> bool {
        match self {
            Self::All => true,
            Self::None => false,
            Self::Exact(arn) => text == arn,
            Self::Prefix(prefix) => text.starts_with(prefix),
            Self::And(all) => all.iter().all(|p| p.keeps(text)),
            Self::Or(any) => any.iter().any(|p| p.keeps(text)),
            Self::Not(p) => !p.keeps(text),
        }
    }

    /// An allow pattern, including too much: itself when literal; the
    /// prefix and the bare path for `<literal>/**`; its literal prefix
    /// otherwise (everything, when it starts with a wildcard).
    fn allow(pattern: &Pattern) -> Self {
        if pattern.is_literal() {
            return Self::Exact(pattern.as_str().to_string());
        }
        if let Some(tree) = pattern.trailing_tree() {
            return Self::Or(vec![
                Self::Prefix(format!("{tree}/")),
                Self::Exact(tree.to_string()),
            ]);
        }
        match pattern.prefix() {
            "" => Self::All,
            prefix => Self::Prefix(prefix.to_string()),
        }
    }

    /// A deny pattern, only when it is exact: a literal, or `<literal>/**`.
    /// A wildcard deny widened to its prefix would exclude rows the
    /// evaluator allows, so it is left to the re-check.
    fn deny(pattern: &Pattern) -> Option<Self> {
        if pattern.is_literal() {
            return Some(Self::Exact(pattern.as_str().to_string()));
        }
        pattern.trailing_tree().map(|tree| {
            Self::Or(vec![
                Self::Prefix(format!("{tree}/")),
                Self::Exact(tree.to_string()),
            ])
        })
    }

    /// `Or` of one is itself; of none, nothing.
    fn any(mut operands: Vec<Self>) -> Self {
        match operands.len() {
            0 => Self::None,
            1 => operands.remove(0),
            _ => Self::Or(operands),
        }
    }
}

impl Scope {
    /// The scope lowered to a [`Predicate`]: **including too much, never
    /// excluding**. Nothing granted is [`Predicate::None`]; else the allow
    /// patterns, each widened to what a store can test exactly, or-ed; then
    /// `AND` the fence when there is one (exact trees, [`Scope::fenced`]);
    /// then `AND NOT` each deny that is exact. A conditioned `Allow` is already in
    /// `allow` and a conditioned `Deny` already out of `deny`
    /// ([`Scope::compile`]), so a residual scope lowers like any other, and
    /// [`Scope::residual`] tells the caller the re-check decides.
    #[must_use]
    pub fn lower(&self) -> Predicate {
        if self.is_empty() {
            return Predicate::None;
        }
        let allowed = Predicate::any(self.allow.iter().map(Predicate::allow).collect());
        let mut all = vec![allowed];
        if !self.fence.is_empty() {
            all.push(Predicate::any(
                self.fence.iter().map(Predicate::allow).collect(),
            ));
        }
        all.extend(
            self.deny
                .iter()
                .filter_map(Predicate::deny)
                .map(|exact| Predicate::Not(Box::new(exact))),
        );
        if all.len() == 1 {
            return all.remove(0);
        }
        Predicate::And(all)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(text: &str) -> Pattern {
        Pattern::resolved(text.into())
    }

    fn scope(allow: &[&str], deny: &[&str]) -> Scope {
        Scope {
            allow: allow.iter().map(|p| pattern(p)).collect(),
            deny: deny.iter().map(|p| pattern(p)).collect(),
            residual: false,
            action: "atlas:ReadItem".into(),
            fence: Vec::new(),
        }
    }

    #[test]
    fn a_literal_is_exact_a_wildcard_its_prefix_a_tree_both() {
        let literal = "arn:wami:a:1:wami:1:key/k1";
        assert_eq!(
            scope(&[literal], &[]).lower(),
            Predicate::Exact(literal.into())
        );
        assert_eq!(
            scope(&["arn:wami:a:1:wami:*:archive/*/note/*"], &[]).lower(),
            Predicate::Prefix("arn:wami:a:1:wami:".into())
        );
        assert_eq!(
            scope(&["arn:wami:a:1:wami:1:realm/main/**"], &[]).lower(),
            Predicate::Or(vec![
                Predicate::Prefix("arn:wami:a:1:wami:1:realm/main/".into()),
                Predicate::Exact("arn:wami:a:1:wami:1:realm/main".into()),
            ])
        );
        assert_eq!(scope(&["*"], &[]).lower(), Predicate::All);
        assert_eq!(scope(&["**"], &[]).lower(), Predicate::All);
    }

    #[test]
    fn nothing_granted_is_none_whatever_is_denied() {
        assert_eq!(scope(&[], &[]).lower(), Predicate::None);
        assert_eq!(
            scope(&[], &["arn:wami:a:1:wami:1:key/k1"]).lower(),
            Predicate::None
        );
    }

    #[test]
    fn an_exact_deny_is_kept_a_wildcard_deny_dropped() {
        let allow = "arn:wami:a:1:wami:1:archive/**";
        let exact = "arn:wami:a:1:wami:1:archive/house/note/secret";
        let lowered = scope(&[allow], &[exact]).lower();
        let Predicate::And(parts) = &lowered else {
            panic!("{lowered:?}")
        };
        assert_eq!(parts.len(), 2);
        assert_eq!(
            parts[1],
            Predicate::Not(Box::new(Predicate::Exact(exact.into())))
        );
        assert!(lowered.keeps("arn:wami:a:1:wami:1:archive/house/recipe/soup"));
        assert!(!lowered.keeps(exact));

        let widened = scope(&[allow], &["arn:wami:a:1:wami:1:archive/*/note/*"]).lower();
        assert!(
            !matches!(widened, Predicate::And(_)),
            "left to the re-check: {widened:?}"
        );
        assert!(widened.keeps(exact), "included too much, never excluded");

        let tree = scope(&[allow], &["arn:wami:a:1:wami:1:archive/house/**"]).lower();
        assert!(!tree.keeps("arn:wami:a:1:wami:1:archive/house"));
        assert!(!tree.keeps(exact));
        assert!(tree.keeps("arn:wami:a:1:wami:1:archive/guild/recipe/stew"));
    }

    #[test]
    fn several_allows_are_or_ed_before_the_denies() {
        let lowered = scope(
            &["arn:wami:a:1:wami:1:key/k1", "arn:wami:a:1:wami:1:key/k2"],
            &["arn:wami:a:1:wami:1:key/k2"],
        )
        .lower();
        assert!(lowered.keeps("arn:wami:a:1:wami:1:key/k1"));
        assert!(!lowered.keeps("arn:wami:a:1:wami:1:key/k2"));
        assert!(!lowered.keeps("arn:wami:a:1:wami:1:key/k3"));
    }

    #[test]
    fn a_fence_is_anded_between_the_allows_and_the_denies() {
        let fenced = scope(&["*"], &["arn:wami:atlas:1:wami:1:key/k1"]).fenced(&["1"]);
        let Predicate::And(parts) = fenced.lower() else {
            panic!()
        };
        assert_eq!(parts.len(), 3, "allow, fence, deny");
        assert_eq!(parts[0], Predicate::All);
        assert_eq!(
            parts[1],
            Predicate::Or(vec![
                Predicate::Prefix("arn:wami:atlas:1:wami:".into()),
                Predicate::Or(vec![
                    Predicate::Prefix("arn:wami:atlas:1/".into()),
                    Predicate::Exact("arn:wami:atlas:1".into()),
                ]),
            ])
        );
        assert!(fenced.lower().keeps("arn:wami:atlas:1:wami:1:key/k2"));
        assert!(!fenced.lower().keeps("arn:wami:atlas:1:wami:1:key/k1"));
        assert!(!fenced.lower().keeps("arn:wami:atlas:2:wami:1:key/k2"));
    }
}
