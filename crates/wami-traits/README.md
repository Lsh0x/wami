# wami-traits

Domain-agnostic trait definitions shared across the WAMI workspace. These
interfaces define the contracts implemented by storage, services, and the
service registry.

## Features

- **Store Traits** – `Store<T>` and specialized interfaces used by credential,
  identity, policy, and reporting components.
- **Service Trait** – Common abstraction for service request/response handlers.
- **Service Registry** – Trait-based dependency injection mechanism for
  registering and resolving services at runtime.

## Usage

```toml
[dependencies]
wami-traits = { path = "../wami-traits" }
```

```rust
use std::sync::Arc;
use wami_traits::{Service, ServiceRegistry, Store};

struct MemoryStore;

impl Store<String> for MemoryStore {
    fn insert(&self, value: String) -> wami_core::error::Result<()> {
        println!("Inserted {}", value);
        Ok(())
    }

    fn get(&self, _id: &str) -> wami_core::error::Result<Option<String>> {
        Ok(None)
    }

    fn delete(&self, _id: &str) -> wami_core::error::Result<()> {
        Ok(())
    }
}

struct EchoService;

impl Service for EchoService {
    type Request = String;
    type Response = String;
    type Error = wami_core::error::AmiError;

    fn handle(&self, req: Self::Request) -> Result<Self::Response, Self::Error> {
        Ok(req)
    }
}

fn register_service(registry: &mut dyn ServiceRegistry) {
    registry.register("echo", Arc::new(EchoService));
}
```

## License

Licensed under MIT. See [`../LICENSE`](../../LICENSE) for details.


