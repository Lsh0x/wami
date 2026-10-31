//! One resolved resource pattern, and the subset of patterns a store can
//! translate exactly.

use std::fmt;

use wami_core::arn::matching::glob_match;

/// A resource pattern of a policy statement, its variables resolved: the
/// text the evaluator's glob matches against (`*` within a segment, `**`
/// across segments, a trailing `/**` also matching the bare path).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Pattern(String);

/// Why a pattern is outside the subset a store can translate exactly.
///
/// A translator handed such a pattern widens it to its literal prefix (an
/// over-approximation the re-check pays for) or refuses it; a service checks
/// its role documents against the subset at boot, so the widening is a
/// choice, never a surprise.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NotCompilable {
    /// Not an ARN pattern at all: fewer than six `:`-separated parts, or not
    /// `arn:wami:…`.
    #[error("{0:?} is not an ARN pattern")]
    NotAnArn(String),
    /// The service part holds a wildcard: `arn:wami:*:…` widens to every
    /// service's rows, the whole store.
    #[error("{0:?}: the service part must be literal (or `${{service}}`)")]
    ServiceWildcard(String),
    /// The tenant part holds a wildcard: nothing a tenant-prefixed index can
    /// narrow. `<tenant>/*` — a tenant's direct descendants — is allowed.
    #[error(
        "{0:?}: the tenant part must be literal (or `${{tenant}}`, or either followed by `/*`)"
    )]
    TenantWildcard(String),
    /// `**` anywhere but as a trailing `/**`.
    #[error("{0:?}: `**` is only translated as a trailing `/**`")]
    InnerDoubleStar(String),
    /// A `${var}` the context did not resolve: the pattern matches nothing.
    #[error("{0:?}: an unresolved variable matches nothing")]
    UnresolvedVariable(String),
}

impl Pattern {
    /// A pattern whose variables are already resolved.
    pub(crate) fn resolved(text: String) -> Self {
        Self(text)
    }

    /// The pattern's text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether `arn` matches: the evaluator's own glob, never a copy.
    #[must_use]
    pub fn matches(&self, arn: &str) -> bool {
        glob_match(&self.0, arn)
    }

    /// The literal text before the first `*`: what an index can narrow on
    /// (`STARTS WITH`, a byte range). The whole text for a literal pattern,
    /// empty when the pattern starts with a wildcard.
    #[must_use]
    pub fn prefix(&self) -> &str {
        self.0.find('*').map_or(&self.0, |at| &self.0[..at])
    }

    /// Whether the pattern holds no wildcard: an index matches it with `=`.
    #[must_use]
    pub fn is_literal(&self) -> bool {
        !self.0.contains('*')
    }

    /// The path a trailing `/**` also matches without it, when the pattern is
    /// exactly `<literal>/**`: `a/b/**` matches `a/b/c` and `a/b`. `None` for
    /// any other shape — a store then expresses the pattern only by its
    /// prefix, and the re-check does the rest.
    #[must_use]
    pub fn trailing_tree(&self) -> Option<&str> {
        let base = self.0.strip_suffix("/**")?;
        (!base.contains('*')).then_some(base)
    }

    /// Whether `motif` is in the subset a store can translate exactly: a
    /// literal service part (or `${service}`), a literal tenant part (or
    /// `${tenant}`, or either followed by `/*` for the direct descendants),
    /// `*` within a segment, `**` only as a trailing `/**`, every variable
    /// resolved.
    ///
    /// Checked on a raw motif (variables not yet resolved) as a service does
    /// on its role documents at boot, or on a resolved pattern.
    ///
    /// # Errors
    ///
    /// The first [`NotCompilable`] reason, in the order above.
    pub fn compilable(motif: &str) -> Result<(), NotCompilable> {
        let parts: Vec<&str> = motif.split(':').collect();
        if parts.len() < 6 || parts[0] != "arn" || parts[1] != "wami" {
            return Err(NotCompilable::NotAnArn(motif.into()));
        }
        if parts[2].contains('*') {
            return Err(NotCompilable::ServiceWildcard(motif.into()));
        }
        let descendants = parts[3].strip_suffix("/*").unwrap_or(parts[3]);
        if descendants.contains('*') {
            return Err(NotCompilable::TenantWildcard(motif.into()));
        }
        let body = motif.strip_suffix("/**").unwrap_or(motif);
        if body.contains("**") {
            return Err(NotCompilable::InnerDoubleStar(motif.into()));
        }
        let unresolved = motif
            .split("${")
            .skip(1)
            .filter_map(|rest| rest.split('}').next())
            .any(|var| !matches!(var, "tenant" | "principal" | "service"));
        if unresolved {
            return Err(NotCompilable::UnresolvedVariable(motif.into()));
        }
        Ok(())
    }
}

impl fmt::Display for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(text: &str) -> Pattern {
        Pattern::resolved(text.into())
    }

    #[test]
    fn the_prefix_is_the_text_before_the_first_star() {
        assert_eq!(
            pattern("arn:wami:a:1:wami:*:x/*").prefix(),
            "arn:wami:a:1:wami:"
        );
        assert_eq!(
            pattern("arn:wami:a:1:wami:1:x/y").prefix(),
            "arn:wami:a:1:wami:1:x/y"
        );
        assert_eq!(pattern("*").prefix(), "");
        assert!(pattern("arn:wami:a:1:wami:1:x/y").is_literal());
        assert!(!pattern("arn:wami:a:1:wami:*:x/y").is_literal());
    }

    #[test]
    fn a_trailing_tree_is_a_literal_base_and_nothing_else() {
        assert_eq!(pattern("a/b/**").trailing_tree(), Some("a/b"));
        assert_eq!(
            pattern("a/*/**").trailing_tree(),
            None,
            "a star in the base"
        );
        assert_eq!(pattern("a/b/**/c").trailing_tree(), None, "not trailing");
        assert_eq!(pattern("a/b").trailing_tree(), None, "no tree");
        assert_eq!(pattern("a/b**").trailing_tree(), None, "no slash before");
    }

    #[test]
    fn the_compilable_subset_is_what_the_issue_names() {
        let ok = [
            "arn:wami:atlas:${tenant}:wami:*:archive/**",
            "arn:wami:atlas:100:wami:1:realm/main/map/*/layer/*",
            "arn:wami:atlas:100/7:wami:*:key/k1",
            "arn:wami:${service}:${tenant}:wami:*:memo/${principal}",
            "arn:wami:s3:${tenant}/*:wami:*:bucket/**",
            "arn:wami:s3:100/*:wami:*:bucket/**",
        ];
        for motif in ok {
            assert_eq!(Pattern::compilable(motif), Ok(()), "{motif}");
        }
        let refused = [
            ("*", NotCompilable::NotAnArn("*".into())),
            ("**", NotCompilable::NotAnArn("**".into())),
            (
                "arn:aws:s3:::bucket",
                NotCompilable::NotAnArn("arn:aws:s3:::bucket".into()),
            ),
            (
                "arn:wami:atlas:*:wami:*:archive/**",
                NotCompilable::TenantWildcard("arn:wami:atlas:*:wami:*:archive/**".into()),
            ),
            (
                "arn:wami:atlas:1*:wami:*:archive/**",
                NotCompilable::TenantWildcard("arn:wami:atlas:1*:wami:*:archive/**".into()),
            ),
            (
                "arn:wami:atlas:100/**:wami:*:archive/**",
                NotCompilable::TenantWildcard("arn:wami:atlas:100/**:wami:*:archive/**".into()),
            ),
            (
                "arn:wami:*:100:wami:*:archive/**",
                NotCompilable::ServiceWildcard("arn:wami:*:100:wami:*:archive/**".into()),
            ),
            (
                "arn:wami:s*:${tenant}:wami:*:bucket/**",
                NotCompilable::ServiceWildcard("arn:wami:s*:${tenant}:wami:*:bucket/**".into()),
            ),
            (
                "arn:wami:atlas:100:wami:*:**/note/*",
                NotCompilable::InnerDoubleStar("arn:wami:atlas:100:wami:*:**/note/*".into()),
            ),
            (
                "arn:wami:atlas:100:wami:*:**",
                NotCompilable::InnerDoubleStar("arn:wami:atlas:100:wami:*:**".into()),
            ),
            (
                "arn:wami:atlas:100:wami:*:${owner}/**",
                NotCompilable::UnresolvedVariable("arn:wami:atlas:100:wami:*:${owner}/**".into()),
            ),
        ];
        for (motif, error) in refused {
            assert_eq!(Pattern::compilable(motif), Err(error), "{motif}");
        }
    }
}
