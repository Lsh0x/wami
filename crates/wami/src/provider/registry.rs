//! Provider registry implementation for WAMI.
//!
//! This module offers a lightweight registry for `CloudProvider` implementations.
//! Providers are stored by name and retrieved as shared references, enabling the
//! application to switch between providers at runtime or support multi-cloud
//! scenarios.

use std::collections::HashMap;
use std::sync::Arc;

use crate::provider::CloudProvider;

/// In-memory registry for cloud providers.
#[derive(Default, Debug)]
pub struct ProviderRegistry {
    providers: HashMap<String, Arc<dyn CloudProvider>>,
}

impl ProviderRegistry {
    /// Creates an empty provider registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a provider registry with a pre-allocated capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            providers: HashMap::with_capacity(capacity),
        }
    }

    /// Registers a provider under the specified name.
    ///
    /// If a provider with the same name already exists, it will be replaced.
    pub fn register(&mut self, name: impl Into<String>, provider: Arc<dyn CloudProvider>) {
        self.providers.insert(name.into(), provider);
    }

    /// Convenience method to register a boxed provider by converting it to an `Arc`.
    pub fn register_boxed(&mut self, name: impl Into<String>, provider: Box<dyn CloudProvider>) {
        self.register(name, Arc::from(provider));
    }

    /// Returns the provider registered under `name`, if any.
    pub fn get(&self, name: &str) -> Option<Arc<dyn CloudProvider>> {
        self.providers.get(name).cloned()
    }

    /// Lists the registered provider names in unspecified order.
    pub fn list_names(&self) -> Vec<String> {
        self.providers.keys().cloned().collect()
    }

    /// Returns `true` if the registry currently has no providers.
    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }

    /// Returns the number of registered providers.
    pub fn len(&self) -> usize {
        self.providers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use wami_core::error::Result;

    #[derive(Debug)]
    struct DummyProvider;

    impl CloudProvider for DummyProvider {
        fn name(&self) -> &str {
            "dummy"
        }

        fn generate_resource_identifier(
            &self,
            _resource_type: crate::provider::ResourceType,
            _account_id: &str,
            _path: &str,
            name: &str,
        ) -> String {
            name.to_string()
        }

        fn generate_resource_id(&self, _resource_type: crate::provider::ResourceType) -> String {
            "id".to_string()
        }

        fn resource_limits(&self) -> &crate::provider::ResourceLimits {
            static LIMITS: crate::provider::ResourceLimits = crate::provider::ResourceLimits {
                max_access_keys_per_user: 2,
                max_signing_certificates_per_user: 2,
                max_service_credentials_per_user_per_service: 2,
                max_tags_per_resource: 50,
                max_mfa_devices_per_user: 8,
                session_duration_min: 3600,
                session_duration_max: 43200,
            };
            &LIMITS
        }

        fn validate_service_name(&self, _service: &str) -> Result<()> {
            Ok(())
        }

        fn validate_path(&self, _path: &str) -> Result<()> {
            Ok(())
        }

        fn generate_service_linked_role_name(
            &self,
            service_name: &str,
            _custom_suffix: Option<&str>,
        ) -> String {
            service_name.to_string()
        }

        fn generate_service_linked_role_path(&self, _service_name: &str) -> String {
            String::new()
        }
    }

    #[test]
    fn register_and_get_provider() {
        let mut registry = ProviderRegistry::new();
        let provider = Arc::new(DummyProvider);
        registry.register("dummy", provider.clone());

        let fetched = registry.get("dummy").expect("provider not found");
        assert_eq!(fetched.name(), "dummy");
        assert_eq!(
            fetched.generate_resource_identifier(
                crate::provider::ResourceType::User,
                "",
                "",
                "alice"
            ),
            "alice"
        );
    }

    #[test]
    fn list_names_returns_registered_providers() {
        let mut registry = ProviderRegistry::new();
        registry.register("one", Arc::new(DummyProvider));
        registry.register("two", Arc::new(DummyProvider));

        let mut names = registry.list_names();
        names.sort();
        assert_eq!(names, vec!["one".to_string(), "two".to_string()]);
        assert_eq!(registry.len(), 2);
    }

    #[test]
    fn register_boxed_provider() {
        let mut registry = ProviderRegistry::new();
        registry.register_boxed("dummy", Box::new(DummyProvider));
        assert!(registry.get("dummy").is_some());
    }
}
