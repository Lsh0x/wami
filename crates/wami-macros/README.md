# wami-macros

Procedural macros that power the WAMI workspace. These macros reduce boilerplate
for service implementations and service registration.

## Macros

- `#[derive(Service)]` – Derive the `wami_traits::Service` trait for a struct.
- `#[service]` – Attribute macro that generates standard service boilerplate
  (constructor, store helpers) with support for composite trait bounds and an
  optional `generate_new = false` flag.
- `register_services!` – Function-like macro that registers multiple services
  in a registry at once.

## Usage

```toml
[dependencies]
wami-macros = { path = "../wami-macros" }
```

```rust
use std::sync::{Arc, RwLock};
use wami_macros::service;
use wami_traits::Service;

pub trait UserServiceStore: wami::store::traits::UserStore {}
impl<T> UserServiceStore for T where T: wami::store::traits::UserStore {}

#[service(store_trait = "crate::UserServiceStore")]
pub struct UserService<S> {
    store: Arc<RwLock<S>>,
}

impl<S: UserServiceStore> UserService<S> {
    pub async fn get_user(&self, user_name: &str) -> wami::Result<Option<wami::identity::User>> {
        self.read_store().get_user(user_name).await
    }
}
```

## Development

The macros use `syn`, `quote`, and `proc-macro2`. Run the macro unit tests with:

```bash
cargo test -p wami-macros
```

## License

Licensed under MIT. See [`../LICENSE`](../../LICENSE) for details.



