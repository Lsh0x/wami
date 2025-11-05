//! Credential management: access keys, MFA devices, login profiles, and certificates.

pub mod access_key;
pub mod login_profile;
pub mod mfa_device;
pub mod server_certificate;
pub mod service_credential;
pub mod signing_certificate;

pub use access_key::{
    add_provider_to_access_key, build_access_key, update_access_key_status, AccessKey,
    AccessKeyLastUsed,
};
pub use login_profile::{
    add_provider_to_login_profile, build_login_profile, update_login_profile, LoginProfile,
};
pub use mfa_device::{add_provider_to_mfa_device, build_mfa_device, MfaDevice};
pub use server_certificate::{
    build_server_certificate, ServerCertificate, ServerCertificateMetadata,
};
pub use service_credential::ServiceSpecificCredential;
pub use signing_certificate::{build_signing_certificate, SigningCertificate};
