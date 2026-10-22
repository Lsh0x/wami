//! The key a principal, a group or a certificate is stored and addressed by.

use super::types::TenantPath;
use serde::{Deserialize, Serialize};
use std::fmt;

/// A name, and the tenant it is unique in.
///
/// A name alone identifies nothing: two tenants may each hold an `alice`, and a
/// store keyed by the bare name hands one tenant's record to the other — or
/// lets the second create overwrite the first. Every store method that
/// addresses a principal, a group or a certificate takes this instead.
///
/// It is a type rather than two `&str` because a swapped pair compiles. It is
/// not an ARN either: a stored record's ARN carries its stable id (a UUID) as
/// the resource, so an ARN-keyed store would key by id, not by the name a
/// request carries.
///
/// The tenant is the record's full [`TenantPath`], never its leaf: `5/7` and
/// `6/7` are different tenants with the same leaf.
///
/// There is deliberately no constructor from a [`WamiArn`](super::WamiArn):
/// the resource id of a stored principal's ARN is its id, and reading it as a
/// name is how a lookup came to find nothing, or someone else.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ScopedName {
    tenant: TenantPath,
    name: String,
}

impl ScopedName {
    /// The key of `name` in `tenant`.
    pub fn new(tenant: TenantPath, name: impl Into<String>) -> Self {
        Self {
            tenant,
            name: name.into(),
        }
    }

    /// The tenant the name is unique in.
    pub fn tenant(&self) -> &TenantPath {
        &self.tenant
    }

    /// The name, unique within [`ScopedName::tenant`] only.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The same tenant under another name — what a rename produces.
    #[must_use]
    pub fn renamed(&self, name: impl Into<String>) -> Self {
        Self::new(self.tenant.clone(), name)
    }
}

/// `5/7:alice` — the tenant path, a colon, the name. For messages only: there
/// is no parser back, because nothing should rebuild a key from text.
impl fmt::Display for ScopedName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.tenant, self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_name_in_two_tenants_is_two_keys() {
        let a = ScopedName::new(TenantPath::new(vec![5, 7]), "alice");
        let b = ScopedName::new(TenantPath::new(vec![6, 7]), "alice");
        assert_ne!(a, b);
    }

    #[test]
    fn a_rename_keeps_the_tenant() {
        let a = ScopedName::new(TenantPath::new(vec![5, 7]), "alice");
        let r = a.renamed("alicia");
        assert_eq!(r.tenant(), a.tenant());
        assert_eq!(r.name(), "alicia");
    }

    #[test]
    fn it_round_trips_through_serde() {
        let a = ScopedName::new(TenantPath::new(vec![0, 7]), "root");
        let json = serde_json::to_string(&a).unwrap();
        assert_eq!(json, r#"{"tenant":"0/7","name":"root"}"#);
        assert_eq!(serde_json::from_str::<ScopedName>(&json).unwrap(), a);
    }

    #[test]
    fn it_displays_tenant_then_name() {
        let a = ScopedName::new(TenantPath::new(vec![5, 7]), "alice");
        assert_eq!(a.to_string(), "5/7:alice");
    }
}
