//! Instance Bootstrap - Initialize WAMI instances with root user and credentials
//!
//! This module handles the secure initialization of a WAMI instance, including:
//! - Creating the root user
//! - Generating root access keys
//! - Securely hashing the secret key
//! - Returning credentials for initial authentication
//!
//! # Security Model
//!
//! **CRITICAL:** Root users MUST have access keys to authenticate. Without this,
//! anyone could brute force instance IDs and gain unauthorized root access.
//!
//! # Example
//!
//! ```rust,no_run
//! use wami::{InstanceBootstrap, store::memory::InMemoryWamiStore};
//! use std::sync::Arc;
//! use tokio::sync::RwLock;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
//!     
//!     // Initialize a new WAMI instance
//!     let creds = InstanceBootstrap::initialize_instance(
//!         store.clone(),
//!         "999888777",  // instance_id
//!     ).await?;
//!     
//!     println!("Root Access Key: {}", creds.access_key_id);
//!     println!("Root Secret Key: {}", creds.secret_access_key);
//!     println!("⚠️  SAVE THESE CREDENTIALS - They cannot be retrieved later!");
//!     
//!     // Now you can authenticate as root
//!     use wami::AuthenticationService;
//!     let auth_service = AuthenticationService::new(store.clone());
//!     let context = auth_service
//!         .authenticate(&creds.access_key_id, &creds.secret_access_key)
//!         .await?;
//!     
//!     assert!(context.is_root());
//!     
//!     Ok(())
//! }
//! ```

use crate::arn::{Service, TenantPath, WamiArn};
use crate::credentials::AccessKey;
use crate::error::{AmiError, Result};
use crate::service::auth::authentication::hash_secret;
use crate::store::traits::{AccessKeyStore, PolicyStore, RoleStore, UserStore};
use crate::wami::identity::role::builder as role_builder;
use crate::wami::identity::root_user::{ROOT_TENANT_ID, ROOT_USER_ID, ROOT_USER_NAME};
use crate::wami::identity::User;
use crate::wami::policies::policy::builder as policy_builder;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use wami_core::PolicyDocument;

/// Root user credentials returned after instance initialization
///
/// **CRITICAL SECURITY:** These credentials are shown ONCE during initialization.
/// They cannot be retrieved later. Save them securely!
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootCredentials {
    /// The access key ID (public identifier)
    pub access_key_id: String,

    /// The secret access key (private, like a password)
    ///
    /// **SECURITY:** This is shown in plaintext ONLY during initialization.
    /// It is stored as a bcrypt hash and cannot be retrieved later.
    pub secret_access_key: String,

    /// The instance ID this root user belongs to
    pub instance_id: String,

    /// The root user ARN
    pub user_arn: String,
}

/// One role to create at bootstrap, with the policy it carries.
///
/// The two documents are named rather than positional on purpose. Both are
/// policy JSON and both parse, so a pair passed the wrong way round is accepted
/// everywhere and produces a role anybody may assume, carrying whatever the
/// trust policy happened to say. Named fields make that mistake unwritable
/// rather than merely unlikely.
#[derive(Debug, Clone, Copy)]
pub struct RoleSeed<'a> {
    /// Role name, as it will be referred to — `platform-admin`, `reader`.
    pub name: &'a str,

    /// IAM path, `/` if you have no use for one.
    pub path: &'a str,

    /// Shown wherever the role is listed.
    ///
    /// Say what it reaches, not what it is meant for. A description that
    /// disagrees with its document is worse than an absent one: it is read, and
    /// believed, by whoever is deciding whether to grant it.
    pub description: &'a str,

    /// Who may assume the role.
    pub assume_role_policy: &'a str,

    /// Name of the managed policy created and attached.
    pub policy_name: &'a str,

    /// What the role may do, once assumed.
    pub policy_document: &'a str,
}

/// Instance Bootstrap - Initialize WAMI instances
pub struct InstanceBootstrap;

impl InstanceBootstrap {
    /// Initialize a new WAMI instance with root user and credentials
    ///
    /// This creates:
    /// 1. A root user with ARN: `arn:wami:iam:0:wami:{instance_id}:user/root`
    /// 2. An access key pair for the root user
    /// 3. Securely hashed secret (bcrypt)
    ///
    /// # Security
    ///
    /// - Access key secret is hashed with bcrypt before storage
    /// - Secret is returned in plaintext ONLY during this initialization
    /// - Secrets cannot be retrieved later (by design)
    /// - Root access requires these credentials (prevents brute force attacks)
    ///
    /// # Arguments
    ///
    /// * `store` - The store to persist the root user and credentials
    /// * `instance_id` - Unique identifier for this WAMI instance
    ///
    /// # Returns
    ///
    /// `RootCredentials` containing the access key ID and secret key.
    /// **CRITICAL:** Save these credentials securely - they cannot be retrieved later!
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use wami::{InstanceBootstrap, store::memory::InMemoryWamiStore};
    /// use std::sync::Arc;
    /// use tokio::sync::RwLock;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let store = Arc::new(RwLock::new(InMemoryWamiStore::default()));
    ///     
    ///     let creds = InstanceBootstrap::initialize_instance(
    ///         store,
    ///         "999888777",
    ///     ).await?;
    ///     
    ///     // MUST save these - they're shown only once!
    ///     println!("Access Key: {}", creds.access_key_id);
    ///     println!("Secret Key: {}", creds.secret_access_key);
    ///     
    ///     Ok(())
    /// }
    /// ```
    pub async fn initialize_instance<S>(
        store: Arc<RwLock<S>>,
        instance_id: impl Into<String>,
    ) -> Result<RootCredentials>
    where
        S: UserStore + AccessKeyStore + Send + Sync,
    {
        let instance_id = instance_id.into();

        // Validate instance_id
        if instance_id.trim().is_empty() {
            return Err(AmiError::InvalidParameter {
                message: "instance_id cannot be empty".to_string(),
            });
        }

        let now = Utc::now();

        // Build root user ARN
        let wami_arn = WamiArn::builder()
            .service(Service::Iam)
            .tenant_path(TenantPath::single(ROOT_TENANT_ID))
            .wami_instance(&instance_id)
            .resource("user", ROOT_USER_ID)
            .build()?;

        // Create root user
        let root_user = User {
            user_name: ROOT_USER_NAME.to_string(),
            user_id: ROOT_USER_ID.to_string(),
            wami_arn: wami_arn.clone(),
            arn: format!("arn:aws:iam::{}:user/root", instance_id),
            path: "/".to_string(),
            create_date: now,
            password_last_used: None,
            permissions_boundary: None,
            tags: vec![],
            providers: vec![],
            tenant_id: None,
        };

        // Generate access key credentials
        let access_key_id = Self::generate_access_key_id();
        let secret_access_key = Self::generate_secret_access_key();

        // Hash the secret for storage (NEVER store plaintext)
        let secret_hash = hash_secret(&secret_access_key)?;

        // Create access key ARN
        let access_key_arn = WamiArn::builder()
            .service(Service::Iam)
            .tenant_path(TenantPath::single(ROOT_TENANT_ID))
            .wami_instance(&instance_id)
            .resource("access-key", &access_key_id)
            .build()?;

        // Create access key
        let access_key = AccessKey {
            user_name: ROOT_USER_NAME.to_string(),
            access_key_id: access_key_id.clone(),
            status: "Active".to_string(),
            create_date: now,
            secret_access_key: Some(secret_hash), // Stored as hash!
            wami_arn: access_key_arn,
            providers: vec![],
        };

        // Store root user
        let mut store_guard = store.write().await;
        store_guard.create_user(root_user.clone()).await?;

        // Store access key
        store_guard.create_access_key(access_key).await?;

        // Return credentials (secret in plaintext - ONLY TIME IT'S VISIBLE!)
        Ok(RootCredentials {
            access_key_id,
            secret_access_key, // Plaintext - save this!
            instance_id,
            user_arn: wami_arn.to_string(),
        })
    }

    /// Generate a secure access key ID
    ///
    /// Format: AKIA + 16 uppercase alphanumeric characters (AWS-compatible)
    fn generate_access_key_id() -> String {
        use rand::Rng;
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let mut rng = rand::thread_rng();

        let random: String = (0..16)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect();

        format!("AKIA{}", random)
    }

    /// Generate a secure secret access key
    ///
    /// Format: 40 character alphanumeric + special chars (AWS-compatible)
    fn generate_secret_access_key() -> String {
        use rand::Rng;
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut rng = rand::thread_rng();

        (0..40)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }

    /// Create the given roles, each with the policy it carries, as root.
    ///
    /// This library builds the ARNs, the root context and the ordering — create
    /// the policy, create the role, attach one to the other. It supplies no
    /// content: which roles an instance should have, and what they may reach,
    /// belongs to whoever runs it, and a general IAM library has no way to know.
    ///
    /// Until v0.17 there was no parameter. `initialize_instance` wrote three
    /// roles of its own unconditionally, so every instance that booted held a
    /// `platform-admin` granting `*` on `*` that its operator had never asked
    /// for and could not decline. One of those documents also named an action
    /// that does not exist, unnoticed for as long as it shipped, because nothing
    /// reads a seeded document back.
    ///
    /// Each document is parsed before anything is written, and a malformed one
    /// refuses the whole call rather than leaving half a set of roles behind.
    /// Their *contents* are not judged: an action this build has never heard of
    /// is a valid document, because a vocabulary belongs to whoever declares it.
    ///
    /// ```no_run
    /// # use wami::{InstanceBootstrap, RoleSeed};
    /// # async fn f<S: wami::store::traits::RoleStore + wami::store::traits::PolicyStore + Send + Sync>(
    /// #     store: std::sync::Arc<tokio::sync::RwLock<S>>) -> Result<(), Box<dyn std::error::Error>> {
    /// InstanceBootstrap::seed_roles(store, "999888777", &[RoleSeed {
    ///     name: "reader",
    ///     path: "/",
    ///     description: "Reads users and roles, on every resource",
    ///     assume_role_policy: r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"wami.local"},"Action":"sts:AssumeRole"}]}"#,
    ///     policy_name: "ReaderPolicy",
    ///     policy_document: r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:ReadUser","iam:ReadRole"],"Resource":["*"]}]}"#,
    /// }]).await?;
    /// # Ok(()) }
    /// ```
    pub async fn seed_roles<S>(
        store: Arc<RwLock<S>>,
        instance_id: &str,
        roles: &[RoleSeed<'_>],
    ) -> Result<()>
    where
        S: RoleStore + PolicyStore + Send + Sync,
    {
        use crate::wami::identity::root_user::ROOT_TENANT_ID;

        // Every document is checked before the first one is stored. Validating
        // as we go would leave a caller who passed four roles and one typo with
        // three roles created and no way to tell from the error which.
        for role in roles {
            serde_json::from_str::<PolicyDocument>(role.policy_document).map_err(|e| {
                AmiError::InvalidParameter {
                    message: format!("role {}: policy_document is not a policy: {e}", role.name),
                }
            })?;

            // Only that it is JSON. A trust policy carries `Principal` and no
            // `Resource`, and this library models no type for one — `PolicyDocument`
            // rejects it outright, which is how this check was written the first
            // time and how the test above caught it. Claiming a stronger guarantee
            // than the crate can back would be the same fault as the description
            // that said "scoped" over a document saying `Resource: ["*"]`.
            serde_json::from_str::<serde_json::Value>(role.assume_role_policy).map_err(|e| {
                AmiError::InvalidParameter {
                    message: format!("role {}: assume_role_policy is not JSON: {e}", role.name),
                }
            })?;
        }

        // Root, because at bootstrap there is nobody else yet to authorise this.
        let root_arn = WamiArn::builder()
            .service(Service::Iam)
            .tenant_path(TenantPath::single(ROOT_TENANT_ID))
            .wami_instance(instance_id)
            .resource("user", ROOT_USER_ID)
            .build()?;

        let ctx = crate::context::WamiContext::builder()
            .instance_id(instance_id)
            .tenant_path(TenantPath::single(ROOT_TENANT_ID))
            .caller_arn(root_arn)
            .is_root(true)
            .build()?;

        let mut store_guard = store.write().await;
        let store = &mut *store_guard;

        for role in roles {
            let policy = policy_builder::build_policy(
                role.policy_name.to_string(),
                role.policy_document.to_string(),
                Some(role.path.to_string()),
                Some(role.description.to_string()),
                None,
                &ctx,
            )?;
            let policy_arn = policy.arn.clone();
            store.create_policy(policy).await?;

            let built = role_builder::build_role(
                role.name.to_string(),
                role.assume_role_policy.to_string(),
                Some(role.path.to_string()),
                Some(role.description.to_string()),
                None,
                &ctx,
            )?;
            store.create_role(built).await?;
            store.attach_role_policy(role.name, &policy_arn).await?;
        }

        Ok(())
    }

    /// Check if an instance is already initialized (has a root user)
    pub async fn is_initialized<S>(store: Arc<RwLock<S>>, instance_id: &str) -> Result<bool>
    where
        S: UserStore + Send + Sync,
    {
        let store_guard = store.read().await;
        let root_user = store_guard.get_user(ROOT_USER_NAME).await?;

        // Check if root user exists and belongs to this instance
        Ok(root_user
            .map(|u| u.wami_arn.wami_instance_id == instance_id)
            .unwrap_or(false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::auth::AuthenticationService;
    use crate::store::memory::InMemoryWamiStore;

    #[tokio::test]
    async fn test_initialize_instance() {
        let store = Arc::new(tokio::sync::RwLock::new(InMemoryWamiStore::default()));

        let creds = InstanceBootstrap::initialize_instance(store.clone(), "999888777")
            .await
            .unwrap();

        // Verify credentials structure
        assert!(creds.access_key_id.starts_with("AKIA"));
        assert_eq!(creds.access_key_id.len(), 20);
        assert_eq!(creds.secret_access_key.len(), 40);
        assert_eq!(creds.instance_id, "999888777");

        // Verify root user was created
        let user = store
            .read()
            .await
            .get_user(ROOT_USER_NAME)
            .await
            .unwrap()
            .expect("Root user should exist");

        assert_eq!(user.user_name, ROOT_USER_NAME);
        assert_eq!(user.wami_arn.wami_instance_id, "999888777");

        // Verify access key was created
        let key = store
            .read()
            .await
            .get_access_key(&creds.access_key_id)
            .await
            .unwrap()
            .expect("Access key should exist");

        assert_eq!(key.user_name, ROOT_USER_NAME);
        assert_eq!(key.status, "Active");
    }

    #[tokio::test]
    async fn test_root_authentication() {
        let store = Arc::new(tokio::sync::RwLock::new(InMemoryWamiStore::default()));

        // Initialize instance
        let creds = InstanceBootstrap::initialize_instance(store.clone(), "999888777")
            .await
            .unwrap();

        // Authenticate as root
        let auth_service = AuthenticationService::new(store.clone());
        let context = auth_service
            .authenticate(&creds.access_key_id, &creds.secret_access_key)
            .await
            .unwrap();

        // Verify root context
        assert!(context.is_root());
        assert_eq!(context.instance_id(), "999888777");
        assert_eq!(context.tenant_path().as_string(), "0"); // Root tenant ID is 0
    }

    #[tokio::test]
    async fn test_cannot_authenticate_with_wrong_secret() {
        let store = Arc::new(tokio::sync::RwLock::new(InMemoryWamiStore::default()));

        let creds = InstanceBootstrap::initialize_instance(store.clone(), "999888777")
            .await
            .unwrap();

        // Try to authenticate with wrong secret
        let auth_service = AuthenticationService::new(store.clone());
        let result = auth_service
            .authenticate(&creds.access_key_id, "wrong_secret")
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_is_initialized() {
        let store = Arc::new(tokio::sync::RwLock::new(InMemoryWamiStore::default()));

        // Not initialized yet
        let initialized = InstanceBootstrap::is_initialized(store.clone(), "999888777")
            .await
            .unwrap();
        assert!(!initialized);

        // Initialize
        InstanceBootstrap::initialize_instance(store.clone(), "999888777")
            .await
            .unwrap();

        // Now initialized
        let initialized = InstanceBootstrap::is_initialized(store.clone(), "999888777")
            .await
            .unwrap();
        assert!(initialized);
    }

    #[test]
    fn test_generate_access_key_id() {
        let key_id = InstanceBootstrap::generate_access_key_id();

        assert!(key_id.starts_with("AKIA"));
        assert_eq!(key_id.len(), 20);
        assert!(key_id.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn test_generate_secret_access_key() {
        let secret = InstanceBootstrap::generate_secret_access_key();

        assert_eq!(secret.len(), 40);
        // Should be base64-like characters
        assert!(secret
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/'));
    }

    /// Two documents that parse, so nothing downstream can tell them apart.
    fn seed<'a>(name: &'a str, policy_document: &'a str) -> RoleSeed<'a> {
        RoleSeed {
            name,
            path: "/",
            description: "Reads users and roles, on every resource",
            assume_role_policy: r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"wami.local"},"Action":"sts:AssumeRole"}]}"#,
            policy_name: "SeedPolicy",
            policy_document,
        }
    }

    const READS: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:ReadUser","iam:ReadRole"],"Resource":["*"]}]}"#;

    /// The regression this whole change exists for.
    ///
    /// Before it, booting an instance also wrote three roles and three policies
    /// nobody had asked for, one of them granting `*` on `*`. Asserting that the
    /// store holds them is what the old test did, and it passed for as long as
    /// the behaviour was wrong — so what is asserted here is the absence.
    #[tokio::test]
    async fn test_initialize_instance_writes_no_policy() {
        use crate::store::traits::{PolicyStore, RoleStore};

        let store = Arc::new(tokio::sync::RwLock::new(InMemoryWamiStore::default()));

        InstanceBootstrap::initialize_instance(store.clone(), "999888777")
            .await
            .unwrap();

        let s = store.read().await;
        assert!(
            s.list_roles(None, None).await.unwrap().0.is_empty(),
            "initialize_instance created a role nobody asked for"
        );
        assert!(
            s.list_policies(None, None).await.unwrap().0.is_empty(),
            "initialize_instance created a policy nobody asked for"
        );
    }

    #[tokio::test]
    async fn test_seed_roles_creates_what_it_was_given() {
        use crate::store::traits::{PolicyStore, RoleStore};

        let store = Arc::new(tokio::sync::RwLock::new(InMemoryWamiStore::default()));
        InstanceBootstrap::initialize_instance(store.clone(), "999888777")
            .await
            .unwrap();

        InstanceBootstrap::seed_roles(store.clone(), "999888777", &[seed("reader", READS)])
            .await
            .unwrap();

        let s = store.read().await;
        let role = s.get_role("reader").await.unwrap();
        assert!(role.is_some(), "the role that was passed should exist");

        let attached = s.list_attached_role_policies("reader").await.unwrap();
        assert_eq!(attached.len(), 1, "its policy should be attached to it");

        let policy = s.get_policy(&attached[0]).await.unwrap().unwrap();
        assert_eq!(
            policy.policy_document, READS,
            "the document stored should be the document given, untouched"
        );

        assert_eq!(
            s.list_roles(None, None).await.unwrap().0.len(),
            1,
            "and nothing else should have appeared beside it"
        );
    }

    /// A caller who passes four roles and one typo should get four roles or
    /// none, never the three that happened to come before the bad one.
    #[tokio::test]
    async fn test_seed_roles_writes_nothing_when_a_document_is_malformed() {
        use crate::store::traits::RoleStore;

        let store = Arc::new(tokio::sync::RwLock::new(InMemoryWamiStore::default()));
        InstanceBootstrap::initialize_instance(store.clone(), "999888777")
            .await
            .unwrap();

        let outcome = InstanceBootstrap::seed_roles(
            store.clone(),
            "999888777",
            &[seed("good", READS), seed("bad", "{not json")],
        )
        .await;

        assert!(outcome.is_err(), "a malformed document should be refused");
        assert!(
            store.read().await.get_role("good").await.unwrap().is_none(),
            "the roles before the bad one should not have been written"
        );
    }

    /// An action this build has never heard of is a valid document.
    ///
    /// A vocabulary belongs to whoever declares it, and refusing here would put
    /// this library in the position of knowing every consumer's verbs — which
    /// is how it came to ship `chat:` and `space:` in the first place.
    #[tokio::test]
    async fn test_seed_roles_does_not_judge_the_vocabulary() {
        let store = Arc::new(tokio::sync::RwLock::new(InMemoryWamiStore::default()));
        InstanceBootstrap::initialize_instance(store.clone(), "999888777")
            .await
            .unwrap();

        let theirs = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["mermaid:PublishDiagram"],"Resource":["*"]}]}"#;

        InstanceBootstrap::seed_roles(store.clone(), "999888777", &[seed("publisher", theirs)])
            .await
            .expect("a caller's own action should be storable");
    }
}
