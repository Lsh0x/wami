//! Service registry implementation for the WAMI workspace.

use std::any::Any;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use wami_traits::ServiceRegistry;

/// Thread-safe registry that stores services by string identifier.
pub struct Registry {
    inner: RwLock<HashMap<String, Arc<dyn Any + Send + Sync>>>,
}

impl Registry {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: RwLock::new(HashMap::with_capacity(capacity)),
        }
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceRegistry for Registry {
    fn register<S>(&mut self, name: &str, service: Arc<S>)
    where
        S: wami_traits::Service + 'static,
    {
        let mut guard = self.inner.write().expect("registry poisoned");
        guard.insert(name.to_string(), service as Arc<dyn Any + Send + Sync>);
    }

    fn get<S>(&self, name: &str) -> Option<Arc<S>>
    where
        S: wami_traits::Service + 'static,
    {
        let guard = self.inner.read().ok()?;
        guard.get(name).cloned()?.downcast::<S>().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wami_core::error::AmiError;
    use wami_traits::Service;

    #[derive(Default)]
    struct EchoService;

    impl Service for EchoService {
        type Request = String;
        type Response = String;
        type Error = AmiError;

        fn handle(&self, req: Self::Request) -> std::result::Result<Self::Response, Self::Error> {
            Ok(req)
        }
    }

    #[test]
    fn register_and_retrieve_service() {
        let mut registry = Registry::default();
        registry.register("echo", Arc::new(EchoService));

        let service = registry
            .get::<EchoService>("echo")
            .expect("service missing");
        let result = service.handle("hello".to_string()).unwrap();
        assert_eq!(result, "hello");
    }

    #[test]
    fn returns_none_for_unknown_service() {
        let registry = Registry::default();
        assert!(registry.get::<EchoService>("missing").is_none());
    }
}
