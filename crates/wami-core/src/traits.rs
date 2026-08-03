//! Domain-agnostic traits shared across the workspace.
//!
//! These live in `wami-core` rather than a crate of their own because they are
//! 37 lines with no dependencies of their own, and a separate crate for them
//! would have to be published for anyone to depend on `wami` at all. See #129.
//!
//! [`Service`] and [`ServiceRegistry`] are what `wami_macros::Service` and
//! `wami_macros::register_services!` expand to, so a crate using those macros
//! needs `wami-core` in scope — the macros name it absolutely, as `::wami_core`.

use crate::error::Result;
use std::sync::Arc;

/// Generic CRUD trait for backing stores.
#[allow(clippy::result_large_err)]
pub trait Store<T>: Send + Sync {
    /// Insert or update a model in the store.
    fn insert(&self, model: T) -> Result<()>;

    /// Retrieve a model by identifier.
    fn get(&self, id: &str) -> Result<Option<T>>;

    /// Delete a model by identifier.
    fn delete(&self, id: &str) -> Result<()>;
}

/// Abstraction over high-level services exposed by the platform.
pub trait Service: Send + Sync {
    type Request;
    type Response;
    type Error;

    fn handle(&self, req: Self::Request) -> std::result::Result<Self::Response, Self::Error>;
}

/// Dependency-injection mechanism for resolving services at runtime.
pub trait ServiceRegistry: Send + Sync {
    fn register<S>(&mut self, name: &str, service: Arc<S>)
    where
        S: Service + 'static;

    fn get<S>(&self, name: &str) -> Option<Arc<S>>
    where
        S: Service + 'static;
}
