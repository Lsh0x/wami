//! Concrete descendant construction, independent of authorization.
use super::{ArnParseError, WamiArn};

impl WamiArn {
    /// Append one concrete `resource_type/key` pair without changing this ARN.
    ///
    /// Service, tenant hierarchy, instance and cloud mapping are preserved.
    /// Each new component must contain only ASCII letters, digits, `-`, `_`,
    /// or `.`, and cannot be empty, `.` or `..`. This does not grant access;
    /// callers still evaluate policies for the resulting resource.
    /// Unlike [`super::ArnBuilder::resource`], this appends rather than replaces.
    ///
    /// # Errors
    /// Returns an error for an invalid component, a wildcard/control character
    /// anywhere in the parent, or a parent that cannot round-trip unchanged.
    ///
    /// # Examples
    /// ```
    /// use wami_core::arn::WamiArn;
    /// let project: WamiArn = "arn:wami:gitsense:42:wami:anatta:project/p".parse()?;
    /// let repo = project.child("source", "github.com")?
    ///     .child("owner", "anatta-rs")?.child("repo", "gitsense")?;
    /// assert_eq!(repo.resource_id(), "p/source/github.com/owner/anatta-rs/repo/gitsense");
    /// assert_eq!(project.resource_id(), "p");
    /// # Ok::<(), wami_core::arn::ArnParseError>(())
    /// ```
    pub fn child(&self, resource_type: &str, key: &str) -> Result<Self, ArnParseError> {
        component(resource_type)?;
        component(key)?;
        // Public fields and the general builder allow unchecked values. Do not
        // treat a WamiArn value as proof of a concrete canonical parent.
        let text = self.to_string();
        if self.service.as_str().is_empty()
            || text.chars().any(|c| c == '*' || c == '?' || c.is_control())
            || text.parse::<WamiArn>()? != *self
        {
            return Err(ArnParseError::InvalidComponent(
                "child requires a concrete round-trippable parent".into(),
            ));
        }
        let mut child = self.clone();
        child.resource.resource_id.push('/');
        child.resource.resource_id.push_str(resource_type);
        child.resource.resource_id.push('/');
        child.resource.resource_id.push_str(key);
        Ok(child)
    }
}

fn component(value: &str) -> Result<(), ArnParseError> {
    if value.is_empty()
        || matches!(value, "." | "..")
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
    {
        return Err(ArnParseError::InvalidComponent(
            "child requires a concrete single component (ASCII letters, digits, -_.)".into(),
        ));
    }
    Ok(())
}
