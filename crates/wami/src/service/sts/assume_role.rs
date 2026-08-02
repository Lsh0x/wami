//! STS Assume Role Service
//!
//! Orchestrates role assumption operations.

use crate::store::traits::{RoleStore, SessionStore};
use crate::wami::sts::assume_role::{AssumeRoleRequest, AssumeRoleResponse, AssumedRoleUser};
use crate::wami::sts::session::SessionStatus;
use crate::wami::sts::{Credentials, StsSession};
use chrono::{Duration, Utc};
use std::sync::Arc;
use tokio::sync::RwLock;
use wami_core::arn::{Service, WamiArn};
use wami_core::context::WamiContext;
use wami_core::error::{AmiError, Result};

#[cfg(feature = "sts-jwt")]
use crate::wami::sts::jwt;
#[cfg(feature = "sts-jwt")]
use crate::wami::sts::jwt::KeyManager;

pub trait AssumeRoleServiceStore: SessionStore + RoleStore {}
impl<T> AssumeRoleServiceStore for T where T: SessionStore + RoleStore {}

/// Service for assuming IAM roles
///
/// Provides high-level operations for role assumption and temporary credentials.
#[wami_macros::service(store_trait = "crate::service::sts::assume_role::AssumeRoleServiceStore")]
pub struct AssumeRoleService<S> {
    store: Arc<RwLock<S>>,
}

impl<S: AssumeRoleServiceStore> AssumeRoleService<S> {
    /// Assume an IAM role
    ///
    /// Returns temporary credentials for the assumed role.
    pub async fn assume_role(
        &self,
        context: &WamiContext,
        request: AssumeRoleRequest,
        principal_arn: &str,
    ) -> Result<AssumeRoleResponse> {
        self.assume_role_inner(context, request, principal_arn)
            .await
    }

    /// Assume an IAM role with optional JWT signing.
    ///
    /// When a `KeyManager` is provided, the returned credentials will include
    /// a signed JWT (`signed_token`) that can be verified offline.
    #[cfg(feature = "sts-jwt")]
    pub async fn assume_role_with_signing(
        &self,
        context: &WamiContext,
        request: AssumeRoleRequest,
        principal_arn: &str,
        key_manager: Option<&KeyManager>,
    ) -> Result<AssumeRoleResponse> {
        let mut response = self
            .assume_role_inner(context, request, principal_arn)
            .await?;
        if let Some(km) = key_manager {
            let claims_ctx = jwt::StsClaimsContext {
                principal_arn: principal_arn.to_string(),
                issuer: "wami-sts".to_string(),
                audience: "wami".to_string(),
                scoped_actions: vec![],
                scoped_resources: vec![],
            };
            let claims = jwt::build_sts_claims(&response.credentials, &claims_ctx);
            response.credentials.signed_token = km.sign_claims(&claims).ok();
        }
        Ok(response)
    }

    /// Core assume-role logic (no JWT signing).
    async fn assume_role_inner(
        &self,
        context: &WamiContext,
        request: AssumeRoleRequest,
        principal_arn: &str,
    ) -> Result<AssumeRoleResponse> {
        // Validate request
        request.validate()?;

        // Verify role exists - try parsing as WAMI ARN first
        let role = if let Ok(wami_arn) = request.role_arn.parse::<crate::arn::WamiArn>() {
            if wami_arn.resource.resource_type == "role" {
                // Search for role by matching wami_arn
                let store_guard = self.read_store().await;
                let (roles, _, _) = store_guard.list_roles(None, None).await?;
                roles
                    .into_iter()
                    .find(|r| r.wami_arn.to_string() == request.role_arn)
                    .ok_or_else(|| AmiError::ResourceNotFound {
                        resource: format!("Role: {}", request.role_arn),
                    })?
            } else {
                return Err(AmiError::InvalidParameter {
                    message: format!("ARN is not a role: {}", request.role_arn),
                });
            }
        } else {
            // Fall back to AWS format
            let role_name = self.extract_role_name_from_arn(&request.role_arn)?;
            self.store
                .read()
                .await
                .get_role(&role_name)
                .await?
                .ok_or_else(|| AmiError::ResourceNotFound {
                    resource: format!("Role: {}", role_name),
                })?
        };

        // Determine session duration (default: 1 hour, max: role's max session duration or 12 hours)
        let max_duration = role.max_session_duration.unwrap_or(43200);
        let duration_seconds = request.duration_seconds.unwrap_or(3600).min(max_duration);
        let expiration = Utc::now() + Duration::seconds(duration_seconds as i64);

        // Generate credentials
        let access_key_id = format!(
            "AKIA{}",
            uuid::Uuid::new_v4()
                .to_string()
                .replace('-', "")
                .chars()
                .take(16)
                .collect::<String>()
        );
        let secret_access_key = format!(
            "SECRET{}",
            uuid::Uuid::new_v4().to_string().replace('-', "")
        );
        let session_token = format!("TOKEN{}", uuid::Uuid::new_v4().to_string().replace('-', ""));

        let session_arn = format!(
            "arn:aws:sts::{}:assumed-role/{}/{}",
            context.instance_id(),
            role.role_name,
            request.role_session_name
        );

        // Build WAMI ARN for credentials using context
        let wami_arn = WamiArn::builder()
            .service(Service::Sts)
            .tenant_path(context.tenant_path().clone())
            .wami_instance(context.instance_id())
            .resource(
                "session",
                format!("{}/{}", role.role_name, request.role_session_name),
            )
            .build()?;

        let credentials = Credentials {
            access_key_id: access_key_id.clone(),
            secret_access_key: secret_access_key.clone(),
            session_token: session_token.clone(),
            expiration,
            arn: session_arn.clone(),
            wami_arn: wami_arn.clone(),
            providers: vec![],
            tenant_id: None,
            signed_token: None,
        };

        // Create assumed role user
        let assumed_role_id = format!(
            "AROA{}",
            uuid::Uuid::new_v4()
                .to_string()
                .replace('-', "")
                .chars()
                .take(17)
                .collect::<String>()
        );
        let assumed_role_user = AssumedRoleUser {
            assumed_role_id,
            arn: session_arn.clone(),
        };

        // Create and store session
        let session = StsSession {
            session_token: session_token.clone(),
            access_key_id,
            secret_access_key,
            expiration,
            status: SessionStatus::Active,
            assumed_role_arn: Some(request.role_arn.clone()),
            federated_user_name: None,
            principal_arn: Some(principal_arn.to_string()),
            arn: session_arn,
            wami_arn,
            providers: vec![],
            tenant_id: None,
            created_at: Utc::now(),
            last_used: None,
        };

        self.write_store().await.create_session(session).await?;

        Ok(AssumeRoleResponse {
            credentials,
            assumed_role_user,
        })
    }

    // Helper methods

    fn extract_role_name_from_arn(&self, arn: &str) -> Result<String> {
        // Try parsing as WAMI ARN first
        if let Ok(wami_arn) = arn.parse::<crate::arn::WamiArn>() {
            if wami_arn.resource.resource_type == "role" {
                return Ok(wami_arn.resource.resource_id);
            }
        }

        // Fall back to AWS format: arn:aws:iam::123456789012:role/RoleName
        let parts: Vec<&str> = arn.split(':').collect();
        if parts.len() < 6 {
            return Err(AmiError::InvalidParameter {
                message: format!("Invalid role ARN: {}", arn),
            });
        }

        let resource_part = parts[5]; // "role/RoleName"
        let resource_parts: Vec<&str> = resource_part.split('/').collect();

        if resource_parts.len() < 2 {
            return Err(AmiError::InvalidParameter {
                message: format!("Invalid role ARN format: {}", arn),
            });
        }

        Ok(resource_parts[1..].join("/"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::memory::InMemoryWamiStore;
    use crate::wami::identity::role::builder::build_role;
    use wami_core::arn::{TenantPath, WamiArn};
    use wami_core::context::WamiContext;

    fn setup_service() -> AssumeRoleService<InMemoryWamiStore> {
        let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
        AssumeRoleService::new(store)
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
    async fn test_assume_role() {
        let service = setup_service();
        let context = test_context();

        // Create a role
        let trust_policy = r#"{"Version":"2012-10-17","Statement":[]}"#;
        let role = build_role(
            "TestRole".to_string(),
            trust_policy.to_string(),
            Some("/".to_string()),
            None,
            None,
            &context,
        )
        .unwrap();

        let role_arn = role.wami_arn.to_string();

        service.store.write().await.create_role(role).await.unwrap();

        // Assume the role
        let request = AssumeRoleRequest {
            role_arn,
            role_session_name: "test-session".to_string(),
            duration_seconds: Some(3600),
            external_id: None,
            policy: None,
        };

        let response = service
            .assume_role(&context, request, "arn:aws:iam::123456789012:user/alice")
            .await
            .unwrap();

        assert!(!response.credentials.access_key_id.is_empty());
        assert!(!response.credentials.session_token.is_empty());
        assert!(response.assumed_role_user.arn.contains("assumed-role"));
        assert!(response.assumed_role_user.arn.contains("TestRole"));
    }

    #[tokio::test]
    async fn test_assume_role_nonexistent() {
        let service = setup_service();

        let request = AssumeRoleRequest {
            role_arn: "arn:wami:.*:12345678:wami:123456789012:role/nonexistent".to_string(),
            role_session_name: "test-session".to_string(),
            duration_seconds: Some(3600),
            external_id: None,
            policy: None,
        };

        let context = test_context();
        let result = service
            .assume_role(&context, request, "arn:aws:iam::123456789012:user/alice")
            .await;

        assert!(result.is_err());
        assert!(matches!(result, Err(AmiError::ResourceNotFound { .. })));
    }

    #[tokio::test]
    async fn test_assume_role_with_aws_format_arn() {
        // An ARN that does not parse as a WAMI ARN takes the AWS fallback path,
        // which looks the role up by the name pulled out of the ARN.
        let service = setup_service();
        let context = test_context();

        let role = build_role(
            "LegacyRole".to_string(),
            r#"{"Version":"2012-10-17","Statement":[]}"#.to_string(),
            Some("/".to_string()),
            None,
            None,
            &context,
        )
        .unwrap();
        service.store.write().await.create_role(role).await.unwrap();

        let response = service
            .assume_role(
                &context,
                AssumeRoleRequest {
                    role_arn: "arn:aws:iam::123456789012:role/LegacyRole".to_string(),
                    role_session_name: "legacy-session".to_string(),
                    duration_seconds: Some(3600),
                    external_id: None,
                    policy: None,
                },
                "arn:aws:iam::123456789012:user/alice",
            )
            .await
            .unwrap();

        assert!(response.assumed_role_user.arn.contains("LegacyRole"));
    }

    #[tokio::test]
    async fn test_assume_role_with_aws_format_arn_unknown_role() {
        let service = setup_service();
        let context = test_context();

        let result = service
            .assume_role(
                &context,
                AssumeRoleRequest {
                    role_arn: "arn:aws:iam::123456789012:role/Missing".to_string(),
                    role_session_name: "legacy-session".to_string(),
                    duration_seconds: Some(3600),
                    external_id: None,
                    policy: None,
                },
                "arn:aws:iam::123456789012:user/alice",
            )
            .await;

        assert!(matches!(result, Err(AmiError::ResourceNotFound { .. })));
    }

    #[tokio::test]
    async fn test_assume_role_with_external_id() {
        let service = setup_service();
        let context = test_context();

        // Create a role
        let trust_policy = r#"{"Version":"2012-10-17","Statement":[]}"#;
        let role = build_role(
            "CrossAccountRole".to_string(),
            trust_policy.to_string(),
            Some("/".to_string()),
            None,
            None,
            &context,
        )
        .unwrap();

        let role_arn = role.wami_arn.to_string();

        service.store.write().await.create_role(role).await.unwrap();

        // Assume with external ID
        let request = AssumeRoleRequest {
            role_arn,
            role_session_name: "cross-account-session".to_string(),
            duration_seconds: Some(7200),
            external_id: Some("unique-external-id-12345".to_string()),
            policy: None,
        };

        let response = service
            .assume_role(
                &context,
                request,
                "arn:aws:iam::999999999999:user/external-user",
            )
            .await
            .unwrap();

        assert!(response.credentials.expiration > Utc::now());
    }

    #[tokio::test]
    async fn test_assume_role_creates_session() {
        let service = setup_service();
        let context = test_context();

        // Create a role
        let trust_policy = r#"{"Version":"2012-10-17","Statement":[]}"#;
        let role = build_role(
            "SessionRole".to_string(),
            trust_policy.to_string(),
            Some("/".to_string()),
            None,
            None,
            &context,
        )
        .unwrap();

        let role_arn = role.wami_arn.to_string();

        service.store.write().await.create_role(role).await.unwrap();

        // Assume the role
        let request = AssumeRoleRequest {
            role_arn,
            role_session_name: "check-session".to_string(),
            duration_seconds: Some(3600),
            external_id: None,
            policy: None,
        };

        let response = service
            .assume_role(&context, request, "arn:aws:iam::123456789012:user/bob")
            .await
            .unwrap();

        // Verify session was created
        let sessions = service
            .store
            .read()
            .await
            .list_sessions(None)
            .await
            .unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(
            sessions[0].session_token,
            response.credentials.session_token
        );
        assert!(sessions[0].assumed_role_arn.is_some());
    }

    #[tokio::test]
    async fn test_extract_role_name_from_arn() {
        let service = setup_service();

        let name = service
            .extract_role_name_from_arn("arn:aws:iam::123456789012:role/MyRole")
            .unwrap();
        assert_eq!(name, "MyRole");

        let name_with_path = service
            .extract_role_name_from_arn("arn:aws:iam::123456789012:role/path/to/MyRole")
            .unwrap();
        assert_eq!(name_with_path, "path/to/MyRole");
    }

    #[cfg(feature = "sts-jwt")]
    #[tokio::test]
    async fn test_assume_role_with_jwt_signing() {
        use crate::wami::sts::jwt::KeyManager;

        let service = setup_service();
        let context = test_context();

        // Create a role
        let trust_policy = r#"{"Version":"2012-10-17","Statement":[]}"#;
        let role = build_role(
            "JwtRole".to_string(),
            trust_policy.to_string(),
            Some("/".to_string()),
            None,
            None,
            &context,
        )
        .unwrap();

        let role_arn = role.wami_arn.to_string();
        service.store.write().await.create_role(role).await.unwrap();

        let km = KeyManager::generate();
        let request = AssumeRoleRequest {
            role_arn,
            role_session_name: "jwt-session".to_string(),
            duration_seconds: Some(3600),
            external_id: None,
            policy: None,
        };

        let response = service
            .assume_role_with_signing(
                &context,
                request,
                "arn:aws:iam::123456789012:user/alice",
                Some(&km),
            )
            .await
            .unwrap();

        // Verify signed_token is present and valid
        let signed_token = response
            .credentials
            .signed_token
            .as_ref()
            .expect("signed_token should be present");
        let claims = km
            .verify_token(signed_token, "wami")
            .expect("token should be verifiable");
        assert_eq!(claims.sub, "arn:aws:iam::123456789012:user/alice");
        assert_eq!(claims.iss, "wami-sts");
        assert_eq!(claims.aud, "wami");
    }
}
