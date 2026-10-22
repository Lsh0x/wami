//! Credentials Service Module
//!
//! Services for managing IAM credentials (access keys, MFA devices, login profiles, certificates).

pub mod access_key;
pub mod login_profile;
pub mod mfa_device;
pub mod server_certificate;
pub mod service_credential;
pub mod signing_certificate;

pub use access_key::AccessKeyService;
pub use login_profile::LoginProfileService;
pub use mfa_device::MfaDeviceService;
pub use server_certificate::ServerCertificateService;
pub use service_credential::ServiceCredentialService;
pub use signing_certificate::SigningCertificateService;

use crate::service::auth::authorizer::confirm;
use crate::store::traits::UserStore;
use wami_core::arn::ScopedName;
use wami_core::context::WamiContext;
use wami_core::error::{AmiError, Result};

/// The key of the user a credential is minted for, read from the store
/// after the guard allowed `requested` (wami 005, D5).
///
/// A credential takes its owner's key and tenant from the owner's RECORD:
/// never from the caller, and never minted for a user that is not there.
///
/// # Errors
///
/// [`AmiError::ResourceNotFound`] when no user is stored under `requested`;
/// [`AmiError::AccessDenied`] when the store returns another record.
pub(crate) async fn read_owner<S: UserStore>(
    store: &S,
    context: &WamiContext,
    requested: &ScopedName,
) -> Result<ScopedName> {
    let owner = store
        .get_user(requested)
        .await?
        .ok_or_else(|| AmiError::ResourceNotFound {
            resource: format!("User: {requested}"),
        })?;
    let key = owner.key();
    confirm(
        context,
        "user",
        requested,
        &key,
        &owner.wami_arn.wami_instance_id,
    )?;
    Ok(key)
}
