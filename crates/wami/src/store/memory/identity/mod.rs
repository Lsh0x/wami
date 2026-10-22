//! Identity Sub-Trait Implementations
//!
//! Implements all identity-related stores for InMemoryWamiStore.

pub mod group;
pub mod identity_provider;
pub mod role;
pub mod service_linked_role;
pub mod user;

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use wami_core::arn::ScopedName;
use wami_core::error::{AmiError, Result};

/// Insert `record` under `key`, refusing a key or an id already held.
///
/// Never an overwrite: a create that replaced the existing record would let
/// anyone able to create a principal rewrite whoever held that name.
pub(super) fn insert_new<T: Clone>(
    map: &mut HashMap<ScopedName, T>,
    key: ScopedName,
    record: T,
    id_of: impl Fn(&T) -> &str,
    what: &str,
) -> Result<T> {
    if map.contains_key(&key) {
        return Err(AmiError::ResourceExists {
            resource: format!("{what} {key}"),
        });
    }
    let id = id_of(&record);
    if map.values().any(|held| id_of(held) == id) {
        return Err(AmiError::ResourceExists {
            resource: format!("{what} with id {id}"),
        });
    }
    map.insert(key, record.clone());
    Ok(record)
}

/// Replace the record whose id is `record`'s, moving it to `key`.
///
/// Returns the key it was stored under before, so a rename can carry what
/// hangs off the old key along with it.
pub(super) fn replace_by_id<T: Clone>(
    map: &mut HashMap<ScopedName, T>,
    key: ScopedName,
    record: T,
    id_of: impl Fn(&T) -> &str,
    what: &str,
) -> Result<(ScopedName, T)> {
    let id = id_of(&record).to_string();
    let old = map
        .iter()
        .find(|(_, held)| id_of(held) == id)
        .map(|(k, _)| k.clone())
        .ok_or_else(|| AmiError::ResourceNotFound {
            resource: format!("{what} with id {id}"),
        })?;
    if old != key && map.contains_key(&key) {
        return Err(AmiError::ResourceExists {
            resource: format!("{what} {key}"),
        });
    }
    map.remove(&old);
    map.insert(key, record.clone());
    Ok((old, record))
}

/// Move the entry under `from` to `to`, if any — what a rename does to the
/// tables keyed by a principal. Left behind, the next holder of the old name
/// would inherit it.
pub(super) fn move_key<V>(map: &mut HashMap<ScopedName, V>, from: &ScopedName, to: &ScopedName) {
    if from != to {
        if let Some(value) = map.remove(from) {
            map.insert(to.clone(), value);
        }
    }
}

/// Keep the records whose path starts with `prefix` (the caller has already
/// kept one tenant's), sort them
/// by `name_of`, then paginate — the shared shape of the list methods.
pub(super) fn page<T>(
    mut items: Vec<T>,
    path_prefix: Option<&str>,
    path_of: impl Fn(&T) -> &str,
    name_of: impl Fn(&T) -> &str,
    pagination: Option<&wami_core::types::PaginationParams>,
) -> (Vec<T>, bool, Option<String>) {
    if let Some(prefix) = path_prefix {
        // An empty prefix matches only empty paths, not every path.
        if prefix.is_empty() {
            items.retain(|item| path_of(item).is_empty());
        } else {
            items.retain(|item| path_of(item).starts_with(prefix));
        }
    }
    items.sort_by(|a, b| name_of(a).cmp(name_of(b)));

    let mut is_truncated = false;
    let mut marker = None;
    if let Some(max_items) = pagination.and_then(|p| p.max_items) {
        if max_items > 0 && items.len() > max_items as usize {
            items.truncate(max_items as usize);
            is_truncated = true;
            marker = items.last().map(|last| name_of(last).to_string());
        } else if max_items == 0 {
            // max_items = 0 returns nothing, and says whether there was more.
            is_truncated = !items.is_empty();
            items.clear();
        }
    }
    (items, is_truncated, marker)
}
