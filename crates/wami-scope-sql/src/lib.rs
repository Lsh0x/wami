//! Render a [`wami_scope::Predicate`] as a parameterized SQLite `WHERE` clause.
//!
//! [`Scope::lower`](wami_scope::Scope::lower) owns the authorization lowering:
//! this crate only renders it. A store must still run the evaluator's `decide`
//! on every returned resource, especially for residual conditions and policies
//! whose patterns are wider than their SQL prefix.

#![forbid(unsafe_code)]

use wami_scope::{Narrowing, Predicate, Scope};

/// A boolean SQLite expression and its named, bound text parameters.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Fragment {
    /// The parenthesized expression, with no policy values interpolated.
    pub text: String,
    /// Parameter names including `:` and their values, in first-use order.
    pub params: Vec<(String, String)>,
}

/// An invalid SQL identifier supplied by the caller.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FragmentError {
    /// Aliases, column names and parameter prefixes must be simple identifiers.
    #[error("{what} {name:?} is not an identifier")]
    NotAnIdentifier {
        /// The identifier's role.
        what: &'static str,
        /// The invalid value.
        name: String,
    },
}

fn identifier(what: &'static str, name: &str) -> Result<(), FragmentError> {
    let mut chars = name.chars();
    if chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        Ok(())
    } else {
        Err(FragmentError::NotAnIdentifier {
            what,
            name: name.into(),
        })
    }
}

/// The exclusive upper bound of an ASCII prefix under SQLite binary ordering.
/// A non-ASCII prefix uses `substr` instead, so UTF-8 cannot be cut in half.
fn prefix_upper(prefix: &str) -> Option<String> {
    if !prefix.is_ascii() {
        return None;
    }
    let mut bytes = prefix.as_bytes().to_vec();
    let at = bytes.iter().rposition(|byte| *byte < 127)?;
    bytes[at] += 1;
    bytes.truncate(at + 1);
    String::from_utf8(bytes).ok()
}

struct Renderer<'a> {
    target: String,
    prefix: &'a str,
    params: Vec<(String, String)>,
}

impl Renderer<'_> {
    fn param(&mut self, value: &str) -> String {
        let name = format!(":{}{}", self.prefix, self.params.len());
        self.params.push((name.clone(), value.into()));
        name
    }

    fn render(&mut self, predicate: &Predicate) -> String {
        match predicate {
            Predicate::All => "1".into(),
            Predicate::None => "0".into(),
            Predicate::Exact(arn) => {
                let param = self.param(arn);
                format!("{} COLLATE BINARY = {param}", self.target)
            }
            Predicate::Prefix(prefix) => self.render_prefix(prefix),
            Predicate::And(all) => self.join(all, " AND ", "1"),
            Predicate::Or(any) => self.join(any, " OR ", "0"),
            Predicate::Not(p) => format!("NOT ({})", self.render(p)),
        }
    }

    fn render_prefix(&mut self, prefix: &str) -> String {
        let lower = self.param(prefix);
        if let Some(upper) = prefix_upper(prefix) {
            let upper = self.param(&upper);
            format!(
                "{} COLLATE BINARY >= {lower} AND {} COLLATE BINARY < {upper}",
                self.target, self.target
            )
        } else {
            format!(
                "substr({}, 1, length({lower})) COLLATE BINARY = {lower}",
                self.target
            )
        }
    }

    fn join(&mut self, operands: &[Predicate], separator: &str, empty: &str) -> String {
        if operands.is_empty() {
            return empty.into();
        }
        operands
            .iter()
            .map(|p| format!("({})", self.render(p)))
            .collect::<Vec<_>>()
            .join(separator)
    }
}

/// Render a predicate against `<alias>.<column>` with named parameters.
///
/// # Errors
///
/// Any identifier that could alter the SQL syntax is refused.
pub fn render(
    predicate: &Predicate,
    alias: &str,
    column: &str,
    param_prefix: &str,
) -> Result<Fragment, FragmentError> {
    identifier("alias", alias)?;
    identifier("column", column)?;
    identifier("parameter prefix", param_prefix)?;
    let mut renderer = Renderer {
        target: format!("{alias}.{column}"),
        prefix: param_prefix,
        params: Vec::new(),
    };
    let text = format!("({})", renderer.render(predicate));
    Ok(Fragment {
        text,
        params: renderer.params,
    })
}

/// Render a scope's lowered predicate for one ARN column.
///
/// # Errors
///
/// As [`render`].
pub fn arn_filter(
    scope: &Scope,
    alias: &str,
    column: &str,
    param_prefix: &str,
) -> Result<Fragment, FragmentError> {
    render(&scope.lower(), alias, column, param_prefix)
}

/// Render every bound alias in a multi-resource query.
///
/// An empty narrowing returns `(1)`; the caller must bind every resource
/// used or returned by the query and still evaluate returned rows.
///
/// # Errors
///
/// As [`render`], for each binding.
pub fn narrowing_filter(
    narrowing: &Narrowing,
    column: &str,
    param_prefix: &str,
) -> Result<Fragment, FragmentError> {
    identifier("parameter prefix", param_prefix)?;
    let mut parts = Vec::new();
    let mut params = Vec::new();
    for (alias, predicate) in narrowing.lowered() {
        let prefix = format!("{param_prefix}_{alias}_");
        let fragment = render(&predicate, alias, column, &prefix)?;
        parts.push(fragment.text);
        params.extend(fragment.params);
    }
    let text = if parts.is_empty() {
        "(1)".into()
    } else {
        format!("({})", parts.join(" AND "))
    };
    Ok(Fragment { text, params })
}
