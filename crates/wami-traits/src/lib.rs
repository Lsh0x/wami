//! Domain-agnostic trait definitions shared across WAMI crates.

use std::sync::Arc;
use wami_core::error::Result;

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
