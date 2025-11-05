use wami_macros::store_trait;

#[store_trait(
    trait = AccessKeyStore,
    shared = {
        //! Access Key Store Trait
        //!
        //! Focused trait for access key storage operations
        use crate::error::Result;
        use crate::types::PaginationParams;
        use crate::wami::credentials::AccessKey;
    },
    methods = {
        /// Create a new access key
        async fn create_access_key(&mut self, access_key: AccessKey) -> Result<AccessKey>;

        /// Get an access key by ID
        async fn get_access_key(&self, access_key_id: &str) -> Result<Option<AccessKey>>;

        /// Update an access key
        async fn update_access_key(&mut self, access_key: AccessKey) -> Result<AccessKey>;

        /// Delete an access key
        async fn delete_access_key(&mut self, access_key_id: &str) -> Result<()>;

        /// List access keys for a user
        async fn list_access_keys(
            &self,
            user_name: &str,
            pagination: Option<&PaginationParams>,
        ) -> Result<(Vec<AccessKey>, bool, Option<String>)>;
    }
)]
pub mod access_key_store;
