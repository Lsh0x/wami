//! A [`Predicate`] rendered as a GQL `WHERE` fragment (wami 008).
//!
//! The lowering — a glob to its prefix, a deny kept only when exact, nothing
//! granted to nothing — is [`Scope::lower`]'s, done once in `wami-scope` with
//! its proof. This crate only renders the predicate in GQL (ISO/IEC 39075):
//! `=` for [`Predicate::Exact`], `STARTS WITH` for [`Predicate::Prefix`],
//! `AND`, `OR`, `NOT`, `true` and `false`, every node parenthesised. Every
//! value travels as a parameter, never in the text: the fragment is safe
//! whatever an ARN holds, and a store plans it like any other.
//!
//! ```
//! use wami_core::arn::matching::MatchContext;
//! use wami_core::types::{PolicyDocument, PolicyStatement};
//! use wami_scope::Scope;
//! use wami_scope_gql::arn_filter;
//!
//! let policy = PolicyDocument {
//!     version: "2012-10-17".into(),
//!     statement: vec![PolicyStatement {
//!         sid: None,
//!         effect: "Allow".into(),
//!         action: vec!["atlas:ReadItem".into()],
//!         resource: vec!["arn:wami:atlas:${tenant}:wami:*:archive/**".into()],
//!         condition: None,
//!     }],
//! };
//! let ctx = MatchContext { tenant: Some("100".into()), ..MatchContext::default() };
//! let scope = Scope::compile(&[policy], "atlas:ReadItem", &ctx).unwrap();
//! let fragment = arn_filter(&scope, "n", "arn", "s").unwrap();
//!
//! assert_eq!(fragment.text, "(n.arn STARTS WITH $s0)");
//! assert_eq!(fragment.params[0], ("s0".to_string(), "arn:wami:atlas:100:wami:".to_string()));
//! // MATCH (n:Thing) WHERE <fragment.text> RETURN n.arn — then scope.matches on each row.
//! ```

#![forbid(unsafe_code)]

use wami_scope::{Narrowing, Predicate, Scope};

/// A `WHERE` fragment and the parameters it names, to splice into a query.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Fragment {
    /// The boolean expression, parenthesised, naming `$<param>`s only.
    pub text: String,
    /// Each parameter's name (without `$`) and value, in order of first use.
    pub params: Vec<(String, String)>,
}

/// Why a fragment could not be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FragmentError {
    /// A name spliced into the text is not an identifier (`[A-Za-z_][A-Za-z0-9_]*`):
    /// refused rather than written into a query.
    #[error("{what} {name:?} is not an identifier")]
    NotAnIdentifier {
        /// `variable`, `property` or `parameter prefix`.
        what: &'static str,
        /// The text refused.
        name: String,
    },
}

fn is_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn identifier(what: &'static str, name: &str) -> Result<(), FragmentError> {
    if is_identifier(name) {
        Ok(())
    } else {
        Err(FragmentError::NotAnIdentifier {
            what,
            name: name.into(),
        })
    }
}

/// Renders a predicate on `<variable>.<property>`, its values as `$<prefix><n>`.
struct Renderer<'a> {
    target: String,
    prefix: &'a str,
    params: Vec<(String, String)>,
}

impl Renderer<'_> {
    fn param(&mut self, value: &str) -> String {
        let name = format!("{}{}", self.prefix, self.params.len());
        self.params.push((name.clone(), value.to_string()));
        format!("${name}")
    }

    /// Every operand parenthesised, so the text reads without knowing GQL's
    /// precedence.
    fn render(&mut self, predicate: &Predicate) -> String {
        match predicate {
            Predicate::All => "true".into(),
            Predicate::None => "false".into(),
            Predicate::Exact(arn) => {
                let p = self.param(arn);
                format!("{} = {p}", self.target)
            }
            Predicate::Prefix(prefix) => {
                let p = self.param(prefix);
                format!("{} STARTS WITH {p}", self.target)
            }
            Predicate::And(all) => self.join(all, " AND "),
            Predicate::Or(any) => self.join(any, " OR "),
            Predicate::Not(p) => format!("NOT ({})", self.render(p)),
        }
    }

    fn join(&mut self, operands: &[Predicate], with: &str) -> String {
        let parts: Vec<String> = operands
            .iter()
            .map(|p| format!("({})", self.render(p)))
            .collect();
        parts.join(with)
    }
}

/// `predicate` as a fragment on `<variable>.<property>` (the node variable
/// and the property holding the ARN), its parameters named `<param_prefix>0`,
/// `<param_prefix>1`…
///
/// # Errors
///
/// [`FragmentError::NotAnIdentifier`] when a name to splice into the text is
/// not one.
pub fn render(
    predicate: &Predicate,
    variable: &str,
    property: &str,
    param_prefix: &str,
) -> Result<Fragment, FragmentError> {
    identifier("variable", variable)?;
    identifier("property", property)?;
    identifier("parameter prefix", param_prefix)?;
    let mut renderer = Renderer {
        target: format!("{variable}.{property}"),
        prefix: param_prefix,
        params: Vec::new(),
    };
    let text = format!("({})", renderer.render(predicate));
    Ok(Fragment {
        text,
        params: renderer.params,
    })
}

/// The fragment of a whole query: every binding of `narrowing` rendered on
/// `<name>.<property>`, and-ed, its parameters named
/// `<param_prefix>_<name>_<n>` so two bindings never share one. A narrowing
/// with no binding keeps every row (`(true)`): the service bound nothing,
/// and [`Narrowing::admit`] will refuse what it returns.
///
/// # Errors
///
/// As [`render`], for each binding's name and the prefix.
pub fn narrowing_filter(
    narrowing: &Narrowing,
    property: &str,
    param_prefix: &str,
) -> Result<Fragment, FragmentError> {
    let mut texts = Vec::new();
    let mut params = Vec::new();
    for (name, predicate) in narrowing.lowered() {
        let prefix = format!("{param_prefix}_{name}_");
        let fragment = render(&predicate, name, property, &prefix)?;
        texts.push(fragment.text);
        params.extend(fragment.params);
    }
    let text = if texts.is_empty() {
        "(true)".to_string()
    } else {
        format!("({})", texts.join(" AND "))
    };
    Ok(Fragment { text, params })
}

/// The fragment keeping what `scope` may reach: [`Scope::lower`] rendered.
///
/// # Errors
///
/// As [`render`].
pub fn arn_filter(
    scope: &Scope,
    variable: &str,
    property: &str,
    param_prefix: &str,
) -> Result<Fragment, FragmentError> {
    render(&scope.lower(), variable, property, param_prefix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_checked_before_anything_is_written() {
        assert!(is_identifier("n") && is_identifier("_arn") && is_identifier("p9"));
        assert!(!is_identifier("") && !is_identifier("9p") && !is_identifier("n.arn"));
        assert!(!is_identifier("n) OR true OR (") && !is_identifier("$p"));
        assert_eq!(
            render(&Predicate::All, "n) OR (true", "arn", "s"),
            Err(FragmentError::NotAnIdentifier {
                what: "variable",
                name: "n) OR (true".into()
            })
        );
        assert!(render(&Predicate::All, "n", "arn", "0s").is_err());
    }

    #[test]
    fn each_node_renders_in_gql() {
        let p = Predicate::And(vec![
            Predicate::Or(vec![
                Predicate::Prefix("a/".into()),
                Predicate::Exact("a".into()),
            ]),
            Predicate::Not(Box::new(Predicate::Exact("a/x".into()))),
        ]);
        let f = render(&p, "n", "arn", "s").unwrap();
        assert_eq!(
            f.text,
            "(((n.arn STARTS WITH $s0) OR (n.arn = $s1)) AND (NOT (n.arn = $s2)))"
        );
        assert_eq!(f.params.len(), 3);
        assert_eq!(
            render(&Predicate::None, "n", "arn", "s").unwrap().text,
            "(false)"
        );
        assert_eq!(
            render(&Predicate::All, "n", "arn", "s").unwrap().text,
            "(true)"
        );
    }

    #[test]
    fn a_narrowing_renders_one_fragment_per_binding_with_its_own_parameters() {
        let n = Narrowing::new()
            .bind("b", scope_on("arn:wami:s3:100:wami:1:bucket/atlas"))
            .unwrap()
            .bind(
                "o",
                scope_on("arn:wami:s3:100:wami:1:bucket/atlas/conv/c1/**"),
            )
            .unwrap();
        let f = narrowing_filter(&n, "arn", "s").unwrap();
        assert_eq!(
            f.text,
            "((b.arn = $s_b_0) AND ((o.arn STARTS WITH $s_o_0) OR (o.arn = $s_o_1)))"
        );
        let names: Vec<&str> = f.params.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["s_b_0", "s_o_0", "s_o_1"]);
        assert_eq!(
            narrowing_filter(&Narrowing::new(), "arn", "s")
                .unwrap()
                .text,
            "(true)"
        );
        assert!(matches!(
            narrowing_filter(
                &Narrowing::new().bind("b.x", scope_on("*")).unwrap(),
                "arn",
                "s"
            ),
            Err(FragmentError::NotAnIdentifier {
                what: "variable",
                ..
            })
        ));
    }

    fn scope_on(resource: &str) -> Scope {
        use wami_core::arn::matching::MatchContext;
        use wami_core::types::{PolicyDocument, PolicyStatement};
        let document = PolicyDocument {
            version: "2012-10-17".into(),
            statement: vec![PolicyStatement {
                sid: None,
                effect: "Allow".into(),
                action: vec!["s3:*".into()],
                resource: vec![resource.into()],
                condition: None,
            }],
        };
        Scope::compile(&[document], "s3:GetObject", &MatchContext::default()).unwrap()
    }
}
