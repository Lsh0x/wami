use wami_macros::credential_module;

#[credential_module(
    resource = "access-key",
    shared = {
        //! AccessKey Resource Module
        //!
        //! This module provides self-contained handling of IAM access key resources.
    },
    model = "model.rs",
    builder = "builder.rs",
    requests = "requests.rs",
    exports = {
        pub use model::{AccessKey, AccessKeyLastUsed};
        pub use requests::{
            CreateAccessKeyRequest,
            ListAccessKeysRequest,
            ListAccessKeysResponse,
            UpdateAccessKeyRequest,
        };
    }
)]
pub mod access_key;
