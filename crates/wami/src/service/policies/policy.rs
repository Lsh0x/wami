//! Policy Service
//!
//! Orchestrates policy management operations.

use crate::service::auth::authorizer::{
    guard, guard_by_id, guard_tenant, iam_arn, Authorizer, Found,
};
use crate::store::traits::PolicyStore;
use crate::wami::policies::policy::{
    builder as policy_builder, CreatePolicyRequest, ListPoliciesRequest, Policy,
    UpdatePolicyRequest,
};
use std::sync::Arc;
use tokio::sync::RwLock;
use wami_core::actions::WamiAction;
use wami_core::arn::ScopedName;
use wami_core::context::WamiContext;
use wami_core::error::Result;

/// Service for managing IAM policies
///
/// Provides high-level operations for policy management.
/// Optionally holds an [`Authorizer`] for authorization guards on every method.
#[wami_macros::service(
    store_trait = "crate::store::traits::PolicyStore",
    generate_new = false
)]
pub struct PolicyService<S> {
    store: Arc<RwLock<S>>,
    authz: Option<Arc<dyn Authorizer>>,
}

impl<S: PolicyStore> PolicyService<S> {
    /// Create a new PolicyService without authorization guards (backward compatible).
    pub fn new(store: Arc<RwLock<S>>) -> Self {
        Self { store, authz: None }
    }

    /// Create a new PolicyService with an authorization guard.
    pub fn with_authorizer(store: Arc<RwLock<S>>, authz: Arc<dyn Authorizer>) -> Self {
        Self {
            store,
            authz: Some(authz),
        }
    }

    /// Create a new policy
    pub async fn create_policy(
        &self,
        context: &WamiContext,
        request: CreatePolicyRequest,
    ) -> Result<Policy> {
        // Judged in the tenant the request names, never the caller's.
        let target = ScopedName::new(request.tenant.clone(), request.policy_name.clone());
        guard(
            self.authz.as_ref(),
            context,
            WamiAction::IamCreatePolicy,
            "policy",
            &target,
        )
        .await?;

        // Refused at write for what the read refuses (wami 001).
        crate::service::policies::inline::refuse_unreadable(
            &request.policy_document,
            &format!("managed policy {}", request.policy_name),
        )?;

        // Use wami builder to create policy (includes tags)
        let policy = policy_builder::build_policy(
            request.policy_name,
            request.policy_document,
            request.path,
            request.description,
            request.tags,
            &request.tenant,
            context,
        )?;

        // Store it
        self.write_store().await.create_policy(policy).await
    }

    /// Get a policy by ARN
    pub async fn get_policy(
        &self,
        context: &WamiContext,
        policy_arn: &str,
    ) -> Result<Option<Policy>> {
        self.read_judged(context, WamiAction::IamReadPolicy, policy_arn)
            .await
    }

    /// Read the policy stored under `policy_arn`, then judge `action` on it in
    /// ITS tenant — the one its `wami_arn` records. The ARN names no tenant
    /// (wami 011), so the policy is read before it can be judged; an absent
    /// ARN and a denied one are one refusal (A1). The resource stays
    /// `policy/<the ARN>` as it was (wami 007 decides its id).
    async fn read_judged(
        &self,
        context: &WamiContext,
        action: WamiAction,
        policy_arn: &str,
    ) -> Result<Option<Policy>> {
        let policy = self.read_store().await.get_policy(policy_arn).await?;
        let stored = policy.as_ref().map(|p| Found {
            instance: p.wami_arn.wami_instance_id.clone(),
            owner: iam_arn(context, &p.wami_arn.tenant_path, "policy", policy_arn),
            itself: None,
        });
        guard_by_id(
            self.authz.as_ref(),
            context,
            action,
            "policy",
            policy_arn,
            stored,
        )
        .await?;
        Ok(policy)
    }

    /// Update a policy
    pub async fn update_policy(
        &self,
        context: &WamiContext,
        request: UpdatePolicyRequest,
    ) -> Result<Policy> {
        let policy = self
            .read_judged(context, WamiAction::IamCreatePolicy, &request.policy_arn)
            .await?
            .ok_or_else(|| crate::error::AmiError::ResourceNotFound {
                resource: format!("Policy: {}", request.policy_arn),
            })?;

        // Apply updates using builder function
        let updated_policy =
            policy_builder::update_policy(policy, request.description, request.default_version_id);

        // Store updated policy
        self.store.write().await.update_policy(updated_policy).await
    }

    /// Delete a policy
    pub async fn delete_policy(&self, context: &WamiContext, policy_arn: &str) -> Result<()> {
        self.read_judged(context, WamiAction::IamDeletePolicy, policy_arn)
            .await?;
        self.write_store().await.delete_policy(policy_arn).await
    }

    /// List policies with optional filtering
    pub async fn list_policies(
        &self,
        context: &WamiContext,
        request: ListPoliciesRequest,
    ) -> Result<(Vec<Policy>, bool, Option<String>)> {
        guard_tenant(
            self.authz.as_ref(),
            context,
            WamiAction::IamReadPolicy,
            "policy",
            &request.tenant,
        )
        .await?;
        self.store
            .read()
            .await
            .list_policies(
                &request.tenant,
                request.scope.as_deref(),
                request.pagination.as_ref(),
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::auth::decision::{Decision, DenyReason};
    use crate::store::memory::InMemoryWamiStore;
    use wami_core::arn::{TenantPath, WamiArn};

    /// The tenant every test of this module works in.
    fn tenant() -> wami_core::arn::TenantPath {
        wami_core::arn::TenantPath::single(12345678)
    }

    fn setup_service() -> PolicyService<InMemoryWamiStore> {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        PolicyService::new(store)
    }

    fn test_context() -> WamiContext {
        let arn: WamiArn = "arn:wami:.*:12345678:wami:123456789012:user/test"
            .parse()
            .unwrap();
        WamiContext::builder()
            .instance_id("123456789012")
            .tenant_path(TenantPath::single(12345678))
            .caller_arn(arn)
            .is_root(false)
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn test_create_and_get_policy() {
        let service = setup_service();
        let context = test_context();

        let policy_doc = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}"#;
        let request = CreatePolicyRequest {
            tenant: tenant(),
            policy_name: "S3FullAccess".to_string(),
            policy_document: policy_doc.to_string(),
            path: Some("/service/".to_string()),
            description: Some("Full S3 access policy".to_string()),
            tags: None,
        };

        let policy = service.create_policy(&context, request).await.unwrap();
        assert_eq!(policy.policy_name, "S3FullAccess");
        assert_eq!(policy.path, "/service/");
        assert_eq!(
            policy.description,
            Some("Full S3 access policy".to_string())
        );

        let retrieved = service.get_policy(&context, &policy.arn).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().policy_name, "S3FullAccess");
    }

    #[tokio::test]
    async fn test_update_policy() {
        let service = setup_service();
        let context = test_context();

        // Create policy
        let policy_doc = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:*","Resource":"*"}]}"#;
        let create_request = CreatePolicyRequest {
            tenant: tenant(),
            policy_name: "EC2FullAccess".to_string(),
            policy_document: policy_doc.to_string(),
            path: Some("/".to_string()),
            description: Some("Original description".to_string()),
            tags: None,
        };
        let policy = service
            .create_policy(&context, create_request)
            .await
            .unwrap();

        // Update policy
        let update_request = UpdatePolicyRequest {
            policy_arn: policy.arn.clone(),
            description: Some("Updated description".to_string()),
            default_version_id: Some("v2".to_string()),
        };
        let updated = service
            .update_policy(&context, update_request)
            .await
            .unwrap();
        assert_eq!(updated.description, Some("Updated description".to_string()));
        assert_eq!(updated.default_version_id, "v2");
    }

    #[tokio::test]
    async fn test_delete_policy() {
        let service = setup_service();
        let context = test_context();

        let policy_doc = r#"{"Version":"2012-10-17","Statement":[]}"#;
        let request = CreatePolicyRequest {
            tenant: tenant(),
            policy_name: "TempPolicy".to_string(),
            policy_document: policy_doc.to_string(),
            path: None,
            description: None,
            tags: None,
        };
        let policy = service.create_policy(&context, request).await.unwrap();

        service.delete_policy(&context, &policy.arn).await.unwrap();

        let retrieved = service.get_policy(&context, &policy.arn).await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_list_policies() {
        let service = setup_service();
        let context = test_context();

        // Create multiple policies
        for i in 0..3 {
            let policy_doc = r#"{"Version":"2012-10-17","Statement":[]}"#;
            let request = CreatePolicyRequest {
                tenant: tenant(),
                policy_name: format!("Policy{}", i),
                policy_document: policy_doc.to_string(),
                path: Some("/test/".to_string()),
                description: None,
                tags: None,
            };
            service.create_policy(&context, request).await.unwrap();
        }

        let list_request = ListPoliciesRequest {
            tenant: tenant(),
            scope: None,
            only_attached: None,
            path_prefix: Some("/test/".to_string()),
            pagination: None,
        };
        let (policies, _, _) = service.list_policies(&context, list_request).await.unwrap();
        assert_eq!(policies.len(), 3);
    }

    // ========== Error Path Tests ==========

    #[tokio::test]
    async fn test_update_policy_nonexistent() {
        let service = setup_service();
        let context = test_context();

        let request = UpdatePolicyRequest {
            policy_arn: "arn:aws:iam::123456789012:policy/Nonexistent".to_string(),
            description: None,
            default_version_id: None,
        };

        let result = service.update_policy(&context, request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_policy_nonexistent() {
        let service = setup_service();
        let context = test_context();

        let result = service
            .get_policy(&context, "arn:aws:iam::123456789012:policy/Nonexistent")
            .await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_delete_policy_nonexistent() {
        let service = setup_service();
        let context = test_context();

        // Delete is idempotent - succeeds even if policy doesn't exist
        let result = service
            .delete_policy(&context, "arn:aws:iam::123456789012:policy/Nonexistent")
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_list_policies_empty_result() {
        let service = setup_service();
        let context = test_context();

        let request = ListPoliciesRequest {
            tenant: tenant(),
            scope: None,
            only_attached: None,
            path_prefix: Some("/nonexistent/".to_string()),
            pagination: None,
        };

        let (policies, _, _) = service.list_policies(&context, request).await.unwrap();
        assert_eq!(policies.len(), 0);
    }

    #[tokio::test]
    async fn test_list_policies_with_path_prefix() {
        let service = setup_service();
        let context = test_context();
        // A document the read accepts: one without "Statement" is refused at
        // create since wami 001, as the authorizer refuses it at read.
        let policy_doc = r#"{"Version":"2012-10-17","Statement":[]}"#.to_string();

        // Create policies with different paths
        for (name, path) in [
            ("Policy1", "/admin/"),
            ("Policy2", "/user/"),
            ("Policy3", "/admin/"),
        ] {
            let request = CreatePolicyRequest {
                tenant: tenant(),
                policy_name: name.to_string(),
                policy_document: policy_doc.clone(),
                path: Some(path.to_string()),
                description: None,
                tags: None,
            };
            service.create_policy(&context, request).await.unwrap();
        }

        // Note: list_policies service method doesn't currently filter by path_prefix
        // It only uses scope and pagination. This test verifies all policies are returned.
        let request = ListPoliciesRequest {
            tenant: tenant(),
            scope: None,
            only_attached: None,
            path_prefix: Some("/admin/".to_string()),
            pagination: None,
        };

        let (policies, _, _) = service.list_policies(&context, request).await.unwrap();
        // All 3 policies are returned (path_prefix filtering not implemented in service layer)
        assert_eq!(policies.len(), 3);
    }

    // ========== Authorization Guard Tests ==========

    use crate::service::auth::authorizer::Authorizer;
    use async_trait::async_trait;

    struct DenyAllAuthorizer;

    #[async_trait]
    impl Authorizer for DenyAllAuthorizer {
        async fn authorize(
            &self,
            _context: &WamiContext,
            _action: &str,
            _resource_arn: &WamiArn,
        ) -> wami_core::error::Result<Decision> {
            Ok(Decision::Deny(DenyReason::NoMatch))
        }
    }

    #[tokio::test]
    async fn test_guard_create_policy_denied() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let service = PolicyService::with_authorizer(store, Arc::new(DenyAllAuthorizer));
        let context = test_context();

        let request = CreatePolicyRequest {
            tenant: tenant(),
            policy_name: "TestPolicy".to_string(),
            policy_document: r#"{"Version":"2012-10-17","Statement":[]}"#.to_string(),
            path: None,
            description: None,
            tags: None,
        };

        let result = service.create_policy(&context, request).await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn test_guard_get_policy_denied() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let service = PolicyService::with_authorizer(store, Arc::new(DenyAllAuthorizer));
        let context = test_context();

        let result = service
            .get_policy(&context, "arn:aws:iam::123456789012:policy/TestPolicy")
            .await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn test_guard_update_policy_denied() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let service = PolicyService::with_authorizer(store, Arc::new(DenyAllAuthorizer));
        let context = test_context();

        let request = UpdatePolicyRequest {
            policy_arn: "arn:aws:iam::123456789012:policy/TestPolicy".to_string(),
            description: Some("Updated".to_string()),
            default_version_id: None,
        };

        let result = service.update_policy(&context, request).await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn test_guard_delete_policy_denied() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let service = PolicyService::with_authorizer(store, Arc::new(DenyAllAuthorizer));
        let context = test_context();

        let result = service
            .delete_policy(&context, "arn:aws:iam::123456789012:policy/TestPolicy")
            .await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn test_guard_list_policies_denied() {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        let service = PolicyService::with_authorizer(store, Arc::new(DenyAllAuthorizer));
        let context = test_context();

        let request = ListPoliciesRequest {
            tenant: tenant(),
            scope: None,
            only_attached: None,
            path_prefix: None,
            pagination: None,
        };

        let result = service.list_policies(&context, request).await;
        assert!(matches!(
            result,
            Err(wami_core::error::AmiError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn a_managed_policy_the_read_would_refuse_is_refused_at_create() {
        // wami 001, review round 2: the read refuses it, so the write must.
        let service = setup_service();
        let context = test_context();
        for (sid, document) in [
            (
                "Typo",
                r#"{"Version":"2012-10-17","Statement":[{"Sid":"Typo","Effect":"Deny","Action":["iam:*"],"Resource":["*"],"Condition":{"StringEqualz":{"aws:username":"alice"}}}]}"#,
            ),
            (
                "NoDelete",
                r#"{"Version":"2012-10-17","Statement":[{"Sid":"NoDelete","Effect":"Dney","Action":["iam:*"],"Resource":["*"]}]}"#,
            ),
        ] {
            let err = service
                .create_policy(
                    &context,
                    CreatePolicyRequest {
                        tenant: tenant(),
                        policy_name: "P".to_string(),
                        policy_document: document.to_string(),
                        path: None,
                        description: None,
                        tags: None,
                    },
                )
                .await
                .expect_err("a document the read refuses must be refused at create");
            let crate::error::AmiError::InvalidParameter { message } = &err else {
                panic!("expected InvalidParameter, got {err:?}");
            };
            assert!(message.contains(&format!("statement {sid}")), "{message}");
        }
    }
}
