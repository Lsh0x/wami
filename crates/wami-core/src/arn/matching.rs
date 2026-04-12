//! ARN Pattern Matching with Variable Substitution and Double-Star Globbing
//!
//! This module provides enhanced pattern matching for WAMI ARN policy evaluation:
//!
//! - **Variable substitution**: `${tenant}`, `${principal}`, `${service}` resolved
//!   at evaluation time from a [`MatchContext`].
//! - **Double-star (`**`)**: matches zero or more path segments (separated by `/`).
//! - **Single-star (`*`)**: matches any characters within a single segment.
//!
//! # Examples
//!
//! ```
//! use wami_core::arn::matching::{MatchContext, matches_arn_pattern};
//!
//! let ctx = MatchContext {
//!     tenant: Some("12345678".into()),
//!     principal: Some("user/alice".into()),
//!     service: Some("iam".into()),
//! };
//!
//! // Variable substitution
//! assert!(matches_arn_pattern(
//!     "arn:wami:iam:${tenant}:wami:*:user/*",
//!     "arn:wami:iam:12345678:wami:999:user/alice",
//!     &ctx,
//! ));
//!
//! // Double-star matches multi-segment paths
//! assert!(matches_arn_pattern(
//!     "arn:wami:hub:12345678:wami:*:space/le-zinc/**",
//!     "arn:wami:hub:12345678:wami:999:space/le-zinc/db/menu",
//!     &ctx,
//! ));
//! ```

use std::collections::HashMap;

/// Context for variable resolution during ARN pattern matching.
#[derive(Debug, Clone, Default)]
pub struct MatchContext {
    /// The caller's tenant ID (resolves `${tenant}`)
    pub tenant: Option<String>,
    /// The caller's principal (resolves `${principal}`)
    pub principal: Option<String>,
    /// The service name (resolves `${service}`)
    pub service: Option<String>,
}

impl MatchContext {
    /// Create a new empty context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a variable map for substitution.
    fn to_vars(&self) -> HashMap<&str, &str> {
        let mut vars = HashMap::new();
        if let Some(ref t) = self.tenant {
            vars.insert("tenant", t.as_str());
        }
        if let Some(ref p) = self.principal {
            vars.insert("principal", p.as_str());
        }
        if let Some(ref s) = self.service {
            vars.insert("service", s.as_str());
        }
        vars
    }
}

/// Build a [`MatchContext`] from a [`WamiContext`].
#[cfg(feature = "context")]
impl From<&crate::context::WamiContext> for MatchContext {
    fn from(ctx: &crate::context::WamiContext) -> Self {
        Self {
            tenant: Some(ctx.tenant_path().as_string()),
            principal: Some(ctx.caller_arn().resource.resource_id.clone()),
            service: Some(ctx.caller_arn().service.to_string()),
        }
    }
}

/// Substitute `${var}` references in a pattern string.
///
/// Unknown variables are left as-is (no match will occur against a literal `${xxx}`).
fn substitute_variables(pattern: &str, vars: &HashMap<&str, &str>) -> String {
    let mut result = String::with_capacity(pattern.len());
    let mut chars = pattern.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '$' && chars.peek() == Some(&'{') {
            chars.next(); // consume '{'
            let mut var_name = String::new();
            for vc in chars.by_ref() {
                if vc == '}' {
                    break;
                }
                var_name.push(vc);
            }
            if let Some(&val) = vars.get(var_name.as_str()) {
                result.push_str(val);
            } else {
                // Unknown variable — leave literal (will fail match)
                result.push_str("${");
                result.push_str(&var_name);
                result.push('}');
            }
        } else {
            result.push(c);
        }
    }

    result
}

/// Match an ARN string against a pattern with variable substitution and globbing.
///
/// # Pattern Syntax
///
/// - `*` — matches any characters within a single path segment (no `/`)
/// - `**` — matches zero or more path segments including `/`
/// - `${tenant}` — substituted from context
/// - `${principal}` — substituted from context
/// - `${service}` — substituted from context
///
/// # Arguments
///
/// - `pattern` — the policy resource pattern (e.g., `arn:wami:iam:${tenant}:wami:*:space/**`)
/// - `text` — the concrete ARN string to match against
/// - `ctx` — context for variable substitution
pub fn matches_arn_pattern(pattern: &str, text: &str, ctx: &MatchContext) -> bool {
    // Step 1: substitute variables
    let vars = ctx.to_vars();
    let resolved = substitute_variables(pattern, &vars);

    // Step 2: match with glob support
    glob_match(&resolved, text)
}

/// Match a resource pattern against a resource string (no variable substitution).
///
/// This is the raw glob matcher supporting `*` and `**`.
///
/// `*` matches any characters except `/`.
/// `**` matches zero or more path segments (including `/`).
/// A trailing `/**` also matches the path without the trailing `/` (e.g.,
/// `a/b/**` matches both `a/b` and `a/b/c/d`).
pub fn glob_match(pattern: &str, text: &str) -> bool {
    // Fast paths
    if pattern == "*" || pattern == "**" {
        return true;
    }
    if pattern == text {
        return true;
    }
    if !pattern.contains('*') {
        return pattern == text;
    }

    if glob_match_recursive(pattern.as_bytes(), text.as_bytes()) {
        return true;
    }

    // Special case: pattern ends with `/**` — also match without the trailing segment.
    // e.g., `space/le-zinc/**` should match `space/le-zinc`.
    if let Some(prefix) = pattern.strip_suffix("/**") {
        return text == prefix || glob_match_recursive(prefix.as_bytes(), text.as_bytes());
    }

    false
}

/// Iterative glob matching with `*` (single-segment) and `**` (multi-segment).
///
/// `*` matches any characters except `/`.
/// `**` matches any characters including `/` (zero or more segments).
fn glob_match_recursive(pattern: &[u8], text: &[u8]) -> bool {
    let mut pi = 0usize;
    let mut ti = 0usize;

    // Backtracking point for last `**`
    let mut dstar_pi: i64 = -1;
    let mut dstar_ti: i64 = -1;

    // Backtracking point for last single `*`
    let mut star_pi: i64 = -1;
    let mut star_ti: i64 = -1;

    while ti < text.len() || pi < pattern.len() {
        if pi < pattern.len() {
            // Check for `**`
            if pi + 1 < pattern.len() && pattern[pi] == b'*' && pattern[pi + 1] == b'*' {
                dstar_pi = pi as i64;
                dstar_ti = ti as i64;
                pi += 2;
                // Skip trailing `/` after `**`
                if pi < pattern.len() && pattern[pi] == b'/' {
                    pi += 1;
                }
                // Reset single-star backtracking
                star_pi = -1;
                star_ti = -1;
                continue;
            }

            // Check for single `*`
            if pattern[pi] == b'*' {
                star_pi = pi as i64;
                star_ti = ti as i64;
                pi += 1;
                continue;
            }

            // Literal match
            if ti < text.len() && pattern[pi] == text[ti] {
                pi += 1;
                ti += 1;
                continue;
            }
        }

        // Backtrack to single `*` (matches any char except `/`)
        if star_pi >= 0 {
            let st = star_ti as usize;
            if st < text.len() && text[st] != b'/' {
                star_ti += 1;
                ti = star_ti as usize;
                pi = star_pi as usize + 1;
                continue;
            }
            // Single * can't cross `/`, fall through to ** backtrack
            star_pi = -1;
            star_ti = -1;
        }

        // Backtrack to `**` (matches anything including `/`)
        if dstar_pi >= 0 {
            dstar_ti += 1;
            let st = dstar_ti as usize;
            if st <= text.len() {
                ti = st;
                pi = dstar_pi as usize + 2;
                if pi < pattern.len() && pattern[pi] == b'/' {
                    pi += 1;
                }
                // Reset single-star backtracking
                star_pi = -1;
                star_ti = -1;
                continue;
            }
        }

        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Variable Substitution ─────────────────────────────────

    #[test]
    fn test_substitute_tenant() {
        let vars: HashMap<&str, &str> = [("tenant", "12345678")].into();
        assert_eq!(
            substitute_variables("arn:wami:iam:${tenant}:wami:*:user/*", &vars),
            "arn:wami:iam:12345678:wami:*:user/*"
        );
    }

    #[test]
    fn test_substitute_multiple_vars() {
        let vars: HashMap<&str, &str> =
            [("tenant", "12345678"), ("service", "iam")].into();
        assert_eq!(
            substitute_variables("arn:wami:${service}:${tenant}:wami:*:user/*", &vars),
            "arn:wami:iam:12345678:wami:*:user/*"
        );
    }

    #[test]
    fn test_substitute_unknown_var_left_as_is() {
        let vars: HashMap<&str, &str> = HashMap::new();
        assert_eq!(
            substitute_variables("arn:wami:iam:${unknown}:wami:*:user/*", &vars),
            "arn:wami:iam:${unknown}:wami:*:user/*"
        );
    }

    #[test]
    fn test_substitute_no_vars() {
        let vars: HashMap<&str, &str> = HashMap::new();
        assert_eq!(
            substitute_variables("arn:wami:iam:*:user/*", &vars),
            "arn:wami:iam:*:user/*"
        );
    }

    // ── Single Star Matching ──────────────────────────────────

    #[test]
    fn test_glob_exact_match() {
        assert!(glob_match("hello", "hello"));
        assert!(!glob_match("hello", "world"));
    }

    #[test]
    fn test_glob_star_all() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", ""));
    }

    #[test]
    fn test_glob_single_star_within_segment() {
        // * matches within a segment (no /)
        assert!(glob_match("user/*", "user/alice"));
        assert!(glob_match("user/*", "user/bob"));
        assert!(glob_match("*/alice", "user/alice"));
    }

    #[test]
    fn test_glob_single_star_does_not_cross_slash() {
        // * should NOT match across /
        assert!(!glob_match("space/*/db", "space/le-zinc/sub/db"));
        assert!(glob_match("space/*/db", "space/le-zinc/db"));
    }

    #[test]
    fn test_glob_star_prefix_suffix() {
        assert!(glob_match("iam:*", "iam:GetUser"));
        assert!(glob_match("iam:Get*", "iam:GetUser"));
        assert!(!glob_match("iam:Delete*", "iam:GetUser"));
    }

    // ── Double Star Matching ──────────────────────────────────

    #[test]
    fn test_glob_double_star_matches_everything() {
        assert!(glob_match("**", "anything/with/slashes"));
        assert!(glob_match("**", ""));
    }

    #[test]
    fn test_glob_double_star_multi_segment() {
        assert!(glob_match("space/le-zinc/**", "space/le-zinc/db/menu"));
        assert!(glob_match("space/le-zinc/**", "space/le-zinc/db/menu/items"));
        assert!(glob_match("space/le-zinc/**", "space/le-zinc"));
        assert!(!glob_match("space/le-zinc/**", "space/other/db"));
    }

    #[test]
    fn test_glob_double_star_in_middle() {
        assert!(glob_match("arn:wami:**/user/*", "arn:wami:iam:12345678:wami:999:user/alice"));
        assert!(glob_match("a/**/z", "a/b/c/d/z"));
        assert!(glob_match("a/**/z", "a/z"));
    }

    #[test]
    fn test_glob_double_star_at_start() {
        assert!(glob_match("**/user/alice", "arn:wami:iam:123:wami:999:user/alice"));
    }

    // ── Full ARN Pattern Matching ─────────────────────────────

    #[test]
    fn test_arn_pattern_with_variables() {
        let ctx = MatchContext {
            tenant: Some("12345678".into()),
            principal: Some("alice".into()),
            service: Some("iam".into()),
        };

        assert!(matches_arn_pattern(
            "arn:wami:iam:${tenant}:wami:*:user/*",
            "arn:wami:iam:12345678:wami:999:user/alice",
            &ctx,
        ));
    }

    #[test]
    fn test_arn_pattern_tenant_mismatch() {
        let ctx = MatchContext {
            tenant: Some("99999999".into()),
            ..Default::default()
        };

        assert!(!matches_arn_pattern(
            "arn:wami:iam:${tenant}:wami:*:user/*",
            "arn:wami:iam:12345678:wami:999:user/alice",
            &ctx,
        ));
    }

    #[test]
    fn test_arn_pattern_double_star_space_scoping() {
        let ctx = MatchContext {
            tenant: Some("12345678".into()),
            ..Default::default()
        };

        // Space-scoped policy: allow all resources under le-zinc
        let pattern = "arn:wami:hub:${tenant}:wami:*:space/le-zinc/**";

        assert!(matches_arn_pattern(
            pattern,
            "arn:wami:hub:12345678:wami:999:space/le-zinc/db/menu",
            &ctx,
        ));

        assert!(matches_arn_pattern(
            pattern,
            "arn:wami:hub:12345678:wami:999:space/le-zinc/persona/chef",
            &ctx,
        ));

        assert!(!matches_arn_pattern(
            pattern,
            "arn:wami:hub:12345678:wami:999:space/other-space/db/menu",
            &ctx,
        ));
    }

    #[test]
    fn test_arn_pattern_no_context() {
        let ctx = MatchContext::default();

        // Without variables, pattern matching still works
        assert!(matches_arn_pattern(
            "arn:wami:iam:*:wami:*:user/*",
            "arn:wami:iam:12345678:wami:999:user/alice",
            &ctx,
        ));
    }

    #[test]
    fn test_arn_pattern_wildcard_all() {
        let ctx = MatchContext::default();
        assert!(matches_arn_pattern("*", "anything", &ctx));
    }

    #[test]
    fn test_arn_pattern_exact_match() {
        let ctx = MatchContext::default();
        assert!(matches_arn_pattern(
            "arn:wami:iam:12345678:wami:999:user/alice",
            "arn:wami:iam:12345678:wami:999:user/alice",
            &ctx,
        ));
    }

    // ── Edge Cases ────────────────────────────────────────────

    #[test]
    fn test_glob_empty_pattern_empty_text() {
        assert!(glob_match("", ""));
    }

    #[test]
    fn test_glob_empty_pattern_nonempty_text() {
        assert!(!glob_match("", "something"));
    }

    #[test]
    fn test_glob_consecutive_stars() {
        // *** should behave like **
        assert!(glob_match("a/**/*", "a/b/c"));
    }

    #[test]
    fn test_glob_star_at_colon_boundary() {
        // ARN segments separated by : — * still matches within a segment
        assert!(glob_match(
            "arn:wami:iam:*:wami:*:user/alice",
            "arn:wami:iam:12345678:wami:999:user/alice"
        ));
    }

    #[test]
    fn test_backward_compat_existing_patterns() {
        // Ensure existing * patterns from authorization.rs still work
        assert!(glob_match(
            "arn:wami:iam:*:user/*",
            "arn:wami:iam:12345678:wami:999:user/alice"
        ));
        assert!(glob_match("*.example.com", "api.example.com"));
        assert!(glob_match("test-*-prod", "test-api-prod"));
        assert!(!glob_match(
            "arn:*:role/*",
            "arn:wami:iam:12345678:wami:999:user/alice"
        ));
    }
}
