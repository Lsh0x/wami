//! Service registry implementation for the WAMI workspace.

use std::any::Any;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use wami_core::traits::ServiceRegistry;

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
        S: wami_core::traits::Service + 'static,
    {
        let mut guard = self.inner.write().expect("registry poisoned");
        guard.insert(name.to_string(), service as Arc<dyn Any + Send + Sync>);
    }

    fn get<S>(&self, name: &str) -> Option<Arc<S>>
    where
        S: wami_core::traits::Service + 'static,
    {
        let guard = self.inner.read().ok()?;
        guard.get(name).cloned()?.downcast::<S>().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wami_core::error::AmiError;
    use wami_core::traits::Service;

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

#[cfg(test)]
mod macro_hygiene {
    //! The macros name their traits absolutely, so a caller needs nothing in
    //! scope but the dependency itself.
    //!
    //! Before #129 they emitted a bare `wami_traits::Service`, which resolved
    //! in the *caller's* scope: the macro silently required a dependency it
    //! never mentioned, and shadowing the name locally would have redirected
    //! the generated `impl` somewhere else entirely. Both are checked here.

    use ::wami_core::error::AmiError;

    /// A module named `wami_core` that is not the crate. If the macro emitted
    /// a relative path, expansion inside this scope would resolve to it.
    mod wami_core {}

    #[derive(Default)]
    struct Delegate;

    impl ::wami_core::traits::Service for Delegate {
        type Request = u8;
        type Response = u8;
        type Error = AmiError;

        fn handle(&self, req: u8) -> Result<u8, AmiError> {
            Ok(req)
        }
    }

    #[derive(Default, wami_macros::Service)]
    #[service(delegate = inner, request = u8, response = u8)]
    struct Shadowed {
        inner: Delegate,
    }

    #[test]
    fn a_local_name_collision_does_not_capture_the_generated_impl() {
        use ::wami_core::traits::Service as _;
        let s = Shadowed::default();
        assert_eq!(s.handle(7).unwrap(), 7);
        // Referenced so the empty module is not flagged as dead code.
        let _ = std::mem::size_of::<Shadowed>();
    }
}
