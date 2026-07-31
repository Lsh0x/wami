//! In-Memory Identity Provider Store Implementation

use crate::store::memory::InMemoryWamiStore;
use crate::store::traits::IdentityProviderStore;
use crate::wami::identity::identity_provider::{OidcProvider, SamlProvider};
use async_trait::async_trait;
use wami_core::error::{AmiError, Result};
use wami_core::types::{PaginationParams, Tag};

#[async_trait]
impl IdentityProviderStore for InMemoryWamiStore {
    // ===========================
    // SAML Provider Operations
    // ===========================

    async fn create_saml_provider(&mut self, provider: SamlProvider) -> Result<SamlProvider> {
        if self.saml_providers.contains_key(&provider.arn) {
            return Err(AmiError::ResourceExists {
                resource: format!("SamlProvider: {}", provider.arn),
            });
        }

        self.saml_providers
            .insert(provider.arn.clone(), provider.clone());
        Ok(provider)
    }

    async fn get_saml_provider(&self, arn: &str) -> Result<Option<SamlProvider>> {
        Ok(self.saml_providers.get(arn).cloned())
    }

    async fn update_saml_provider(&mut self, provider: SamlProvider) -> Result<SamlProvider> {
        if !self.saml_providers.contains_key(&provider.arn) {
            return Err(AmiError::ResourceNotFound {
                resource: format!("SamlProvider: {}", provider.arn),
            });
        }

        self.saml_providers
            .insert(provider.arn.clone(), provider.clone());
        Ok(provider)
    }

    async fn delete_saml_provider(&mut self, arn: &str) -> Result<()> {
        if self.saml_providers.remove(arn).is_none() {
            return Err(AmiError::ResourceNotFound {
                resource: format!("SamlProvider: {}", arn),
            });
        }
        Ok(())
    }

    async fn list_saml_providers(
        &self,
        pagination: Option<&PaginationParams>,
    ) -> Result<(Vec<SamlProvider>, bool, Option<String>)> {
        let mut providers: Vec<SamlProvider> = self.saml_providers.values().cloned().collect();

        // Sort by create_date for consistent pagination
        providers.sort_by_key(|a| a.create_date);

        // Apply pagination
        let (start_index, max_items) = if let Some(params) = pagination {
            let start = params
                .marker
                .as_ref()
                .and_then(|m| providers.iter().position(|p| p.arn == *m))
                .map(|pos| pos + 1)
                .unwrap_or(0);
            (start, params.max_items.unwrap_or(100) as usize)
        } else {
            (0, 100)
        };

        let end_index = std::cmp::min(start_index + max_items, providers.len());
        let paginated = providers[start_index..end_index].to_vec();
        let is_truncated = end_index < providers.len();
        let next_marker = if is_truncated {
            paginated.last().map(|p| p.arn.clone())
        } else {
            None
        };

        Ok((paginated, is_truncated, next_marker))
    }

    // ===========================
    // OIDC Provider Operations
    // ===========================

    async fn create_oidc_provider(&mut self, provider: OidcProvider) -> Result<OidcProvider> {
        if self.oidc_providers.contains_key(&provider.arn) {
            return Err(AmiError::ResourceExists {
                resource: format!("OidcProvider: {}", provider.arn),
            });
        }

        self.oidc_providers
            .insert(provider.arn.clone(), provider.clone());
        Ok(provider)
    }

    async fn get_oidc_provider(&self, arn: &str) -> Result<Option<OidcProvider>> {
        Ok(self.oidc_providers.get(arn).cloned())
    }

    async fn update_oidc_provider(&mut self, provider: OidcProvider) -> Result<OidcProvider> {
        if !self.oidc_providers.contains_key(&provider.arn) {
            return Err(AmiError::ResourceNotFound {
                resource: format!("OidcProvider: {}", provider.arn),
            });
        }

        self.oidc_providers
            .insert(provider.arn.clone(), provider.clone());
        Ok(provider)
    }

    async fn delete_oidc_provider(&mut self, arn: &str) -> Result<()> {
        if self.oidc_providers.remove(arn).is_none() {
            return Err(AmiError::ResourceNotFound {
                resource: format!("OidcProvider: {}", arn),
            });
        }
        Ok(())
    }

    async fn list_oidc_providers(
        &self,
        pagination: Option<&PaginationParams>,
    ) -> Result<(Vec<OidcProvider>, bool, Option<String>)> {
        let mut providers: Vec<OidcProvider> = self.oidc_providers.values().cloned().collect();

        // Sort by create_date for consistent pagination
        providers.sort_by_key(|a| a.create_date);

        // Apply pagination
        let (start_index, max_items) = if let Some(params) = pagination {
            let start = params
                .marker
                .as_ref()
                .and_then(|m| providers.iter().position(|p| p.arn == *m))
                .map(|pos| pos + 1)
                .unwrap_or(0);
            (start, params.max_items.unwrap_or(100) as usize)
        } else {
            (0, 100)
        };

        let end_index = std::cmp::min(start_index + max_items, providers.len());
        let paginated = providers[start_index..end_index].to_vec();
        let is_truncated = end_index < providers.len();
        let next_marker = if is_truncated {
            paginated.last().map(|p| p.arn.clone())
        } else {
            None
        };

        Ok((paginated, is_truncated, next_marker))
    }

    // ===========================
    // Tagging Operations
    // ===========================

    async fn tag_identity_provider(&mut self, arn: &str, tags: Vec<Tag>) -> Result<()> {
        // Check SAML providers first
        if let Some(mut provider) = self.saml_providers.get(arn).cloned() {
            for tag in tags {
                provider.tags.retain(|t| t.key != tag.key);
                provider.tags.push(tag);
            }
            self.saml_providers.insert(arn.to_string(), provider);
            return Ok(());
        }

        // Then check OIDC providers
        if let Some(mut provider) = self.oidc_providers.get(arn).cloned() {
            for tag in tags {
                provider.tags.retain(|t| t.key != tag.key);
                provider.tags.push(tag);
            }
            self.oidc_providers.insert(arn.to_string(), provider);
            return Ok(());
        }

        Err(AmiError::ResourceNotFound {
            resource: format!("IdentityProvider: {}", arn),
        })
    }

    async fn list_identity_provider_tags(&self, arn: &str) -> Result<Vec<Tag>> {
        // Check SAML providers first
        if let Some(provider) = self.saml_providers.get(arn) {
            return Ok(provider.tags.clone());
        }

        // Then check OIDC providers
        if let Some(provider) = self.oidc_providers.get(arn) {
            return Ok(provider.tags.clone());
        }

        Err(AmiError::ResourceNotFound {
            resource: format!("IdentityProvider: {}", arn),
        })
    }

    async fn untag_identity_provider(&mut self, arn: &str, tag_keys: Vec<String>) -> Result<()> {
        // Check SAML providers first
        if let Some(mut provider) = self.saml_providers.get(arn).cloned() {
            provider.tags.retain(|t| !tag_keys.contains(&t.key));
            self.saml_providers.insert(arn.to_string(), provider);
            return Ok(());
        }

        // Then check OIDC providers
        if let Some(mut provider) = self.oidc_providers.get(arn).cloned() {
            provider.tags.retain(|t| !tag_keys.contains(&t.key));
            self.oidc_providers.insert(arn.to_string(), provider);
            return Ok(());
        }

        Err(AmiError::ResourceNotFound {
            resource: format!("IdentityProvider: {}", arn),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arn::{TenantPath, WamiArn};
    use crate::context::WamiContext;
    use crate::wami::identity::identity_provider::builder;
    use chrono::{Duration, TimeZone, Utc};
    use wami_core::types::PaginationParams;

    fn test_context() -> WamiContext {
        WamiContext::builder()
            .instance_id("123456789012")
            .tenant_path(TenantPath::single(0))
            .caller_arn(
                WamiArn::builder()
                    .service(crate::arn::Service::Iam)
                    .tenant_path(TenantPath::single(0))
                    .wami_instance("123456789012")
                    .resource("user", "test-user")
                    .build()
                    .unwrap(),
            )
            .is_root(false)
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn test_saml_provider_crud() {
        let mut store = InMemoryWamiStore::default();
        let context = test_context();

        let saml = builder::build_saml_provider(
            "TestProvider".to_string(),
            "<EntityDescriptor />".to_string(),
            &context,
        )
        .unwrap();

        // Create
        let created = store.create_saml_provider(saml.clone()).await.unwrap();
        assert_eq!(created.saml_provider_name, "TestProvider");

        // Get
        let retrieved = store.get_saml_provider(&created.arn).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().arn, created.arn);

        // Update
        let mut updated = created.clone();
        updated.saml_metadata_document = "new metadata".to_string();
        let updated_result = store.update_saml_provider(updated).await.unwrap();
        assert_eq!(updated_result.saml_metadata_document, "new metadata");

        // Delete
        store.delete_saml_provider(&created.arn).await.unwrap();
        assert!(store
            .get_saml_provider(&created.arn)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn test_oidc_provider_crud() {
        let mut store = InMemoryWamiStore::default();
        let context = test_context();

        let oidc = builder::build_oidc_provider(
            "https://accounts.google.com".to_string(),
            vec!["client-id".to_string()],
            vec!["0123456789abcdef0123456789abcdef01234567".to_string()],
            &context,
        )
        .unwrap();

        // Create
        let created = store.create_oidc_provider(oidc.clone()).await.unwrap();
        assert_eq!(created.url, "https://accounts.google.com");

        // Get
        let retrieved = store.get_oidc_provider(&created.arn).await.unwrap();
        assert!(retrieved.is_some());

        // Update
        let mut updated = created.clone();
        updated.client_id_list.push("new-client".to_string());
        let updated_result = store.update_oidc_provider(updated).await.unwrap();
        assert_eq!(updated_result.client_id_list.len(), 2);

        // Delete
        store.delete_oidc_provider(&created.arn).await.unwrap();
        assert!(store
            .get_oidc_provider(&created.arn)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn test_tagging_operations() {
        let mut store = InMemoryWamiStore::default();
        let context = test_context();

        let saml = builder::build_saml_provider(
            "TagTest".to_string(),
            "<EntityDescriptor />".to_string(),
            &context,
        )
        .unwrap();

        let created = store.create_saml_provider(saml).await.unwrap();

        // Tag
        let tags = vec![Tag {
            key: "Environment".to_string(),
            value: "Production".to_string(),
        }];
        store
            .tag_identity_provider(&created.arn, tags.clone())
            .await
            .unwrap();

        // List tags
        let listed_tags = store
            .list_identity_provider_tags(&created.arn)
            .await
            .unwrap();
        assert_eq!(listed_tags.len(), 1);
        assert_eq!(listed_tags[0].key, "Environment");

        // Untag
        store
            .untag_identity_provider(&created.arn, vec!["Environment".to_string()])
            .await
            .unwrap();

        let listed_after_untag = store
            .list_identity_provider_tags(&created.arn)
            .await
            .unwrap();
        assert_eq!(listed_after_untag.len(), 0);
    }

    #[tokio::test]
    async fn test_list_saml_providers_pagination() {
        let mut store = InMemoryWamiStore::default();
        let context = test_context();
        let base_time = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();

        let mut providers = [
            builder::build_saml_provider("ProviderA".to_string(), "<A />".to_string(), &context)
                .unwrap(),
            builder::build_saml_provider("ProviderB".to_string(), "<B />".to_string(), &context)
                .unwrap(),
            builder::build_saml_provider("ProviderC".to_string(), "<C />".to_string(), &context)
                .unwrap(),
        ];

        for (idx, provider) in providers.iter_mut().enumerate() {
            provider.create_date = base_time + Duration::seconds(idx as i64 * 10);
            store.create_saml_provider(provider.clone()).await.unwrap();
        }

        let pagination = PaginationParams {
            max_items: Some(2),
            marker: None,
        };

        let (page_one, truncated, marker) =
            store.list_saml_providers(Some(&pagination)).await.unwrap();

        assert_eq!(page_one.len(), 2);
        assert!(truncated);
        let marker = marker.expect("expected pagination marker");
        assert_eq!(marker, page_one.last().unwrap().arn);

        let pagination_next = PaginationParams {
            max_items: Some(2),
            marker: Some(marker.clone()),
        };

        let (page_two, truncated_two, marker_two) = store
            .list_saml_providers(Some(&pagination_next))
            .await
            .unwrap();

        assert_eq!(page_two.len(), 1);
        assert!(!truncated_two);
        assert!(marker_two.is_none());
        assert!(page_two[0].create_date > page_one[0].create_date);
    }

    #[tokio::test]
    async fn test_list_oidc_providers_pagination() {
        let mut store = InMemoryWamiStore::default();
        let context = test_context();
        let base_time = Utc.with_ymd_and_hms(2025, 2, 2, 0, 0, 0).unwrap();

        let mut providers = [
            builder::build_oidc_provider(
                "https://idp-a.example.com".to_string(),
                vec!["client-a".to_string()],
                vec!["0123456789abcdef0123456789abcdef01234567".to_string()],
                &context,
            )
            .unwrap(),
            builder::build_oidc_provider(
                "https://idp-b.example.com".to_string(),
                vec!["client-b".to_string()],
                vec!["abcdef0123456789abcdef0123456789abcdef01".to_string()],
                &context,
            )
            .unwrap(),
            builder::build_oidc_provider(
                "https://idp-c.example.com".to_string(),
                vec!["client-c".to_string()],
                vec!["fedcba9876543210fedcba9876543210fedcba98".to_string()],
                &context,
            )
            .unwrap(),
        ];

        for (idx, provider) in providers.iter_mut().enumerate() {
            provider.create_date = base_time + Duration::seconds(idx as i64 * 5);
            store.create_oidc_provider(provider.clone()).await.unwrap();
        }

        let pagination = PaginationParams {
            max_items: Some(2),
            marker: None,
        };

        let (page_one, truncated, marker) =
            store.list_oidc_providers(Some(&pagination)).await.unwrap();

        assert_eq!(page_one.len(), 2);
        assert!(truncated);
        let marker = marker.expect("expected pagination marker");
        assert_eq!(marker, page_one.last().unwrap().arn);

        let pagination_next = PaginationParams {
            max_items: Some(2),
            marker: Some(marker.clone()),
        };

        let (page_two, truncated_two, marker_two) = store
            .list_oidc_providers(Some(&pagination_next))
            .await
            .unwrap();

        assert_eq!(page_two.len(), 1);
        assert!(!truncated_two);
        assert!(marker_two.is_none());
        assert!(page_two[0].create_date > page_one[0].create_date);
    }

    #[tokio::test]
    async fn test_identity_provider_error_paths() {
        let mut store = InMemoryWamiStore::default();
        let context = test_context();

        let saml = builder::build_saml_provider(
            "Duplicate".to_string(),
            "<EntityDescriptor/>".to_string(),
            &context,
        )
        .unwrap();

        store.create_saml_provider(saml.clone()).await.unwrap();
        let create_err = store.create_saml_provider(saml.clone()).await.unwrap_err();
        assert!(matches!(create_err, AmiError::ResourceExists { .. }));

        let missing_saml = builder::build_saml_provider(
            "Missing".to_string(),
            "<EntityDescriptor/>".to_string(),
            &context,
        )
        .unwrap();
        let update_err = store.update_saml_provider(missing_saml).await.unwrap_err();
        assert!(matches!(update_err, AmiError::ResourceNotFound { .. }));

        let delete_err = store
            .delete_saml_provider("arn:aws:iam::123456789012:saml-provider/Unknown")
            .await
            .unwrap_err();
        assert!(matches!(delete_err, AmiError::ResourceNotFound { .. }));

        let oidc = builder::build_oidc_provider(
            "https://duplicate.example.com".to_string(),
            vec!["client".to_string()],
            vec!["0123456789abcdef0123456789abcdef01234567".to_string()],
            &context,
        )
        .unwrap();

        store.create_oidc_provider(oidc.clone()).await.unwrap();
        let create_err = store.create_oidc_provider(oidc.clone()).await.unwrap_err();
        assert!(matches!(create_err, AmiError::ResourceExists { .. }));

        let missing_oidc = builder::build_oidc_provider(
            "https://missing.example.com".to_string(),
            vec!["missing-client".to_string()],
            vec!["abcdef0123456789abcdef0123456789abcdef01".to_string()],
            &context,
        )
        .unwrap();
        let update_err = store.update_oidc_provider(missing_oidc).await.unwrap_err();
        assert!(matches!(update_err, AmiError::ResourceNotFound { .. }));

        let delete_err = store
            .delete_oidc_provider("arn:aws:iam::123456789012:oidc-provider/unknown")
            .await
            .unwrap_err();
        assert!(matches!(delete_err, AmiError::ResourceNotFound { .. }));
    }

    #[tokio::test]
    async fn test_identity_provider_tagging_errors() {
        let mut store = InMemoryWamiStore::default();
        let missing_arn = "arn:aws:iam::123456789012:saml-provider/DoesNotExist";

        let err = store
            .tag_identity_provider(
                missing_arn,
                vec![Tag {
                    key: "Environment".to_string(),
                    value: "Dev".to_string(),
                }],
            )
            .await
            .unwrap_err();
        assert!(matches!(err, AmiError::ResourceNotFound { .. }));

        let err = store
            .list_identity_provider_tags(missing_arn)
            .await
            .unwrap_err();
        assert!(matches!(err, AmiError::ResourceNotFound { .. }));

        let err = store
            .untag_identity_provider(missing_arn, vec!["Environment".to_string()])
            .await
            .unwrap_err();
        assert!(matches!(err, AmiError::ResourceNotFound { .. }));
    }
}
