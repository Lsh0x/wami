# wami-service

Service registry and orchestration utilities for the WAMI workspace. This crate
implements a dynamic registry capable of storing heterogenous services behind a
trait-object interface.

## Features

- **Service Registry** – Thread-safe registry (`Registry`) that stores services
  by name and supports type-safe retrieval.
- **Dynamic Dispatch** – Leverages `Any` + `Arc` to downcast services on demand.
- **Testing Utilities** – Includes example services and registry tests.

## Usage

```toml
[dependencies]
wami-service = { path = "../wami-service" }
wami-traits = { path = "../wami-traits" }
```

```rust
use std::sync::Arc;
use wami_service::Registry;
use wami_traits::{Service, ServiceRegistry};

#[derive(Default)]
struct EchoService;

impl Service for EchoService {
    type Request = String;
    type Response = String;
    type Error = wami_core::error::AmiError;

    fn handle(&self, req: Self::Request) -> Result<Self::Response, Self::Error> {
        Ok(req)
    }
}

let mut registry = Registry::default();
registry.register("echo", Arc::new(EchoService::default()));

let service = registry.get::<EchoService>("echo").unwrap();
assert_eq!(service.handle("hello".into()).unwrap(), "hello");
```

## License

Licensed under MIT. See [`../LICENSE`](../../LICENSE) for details.


