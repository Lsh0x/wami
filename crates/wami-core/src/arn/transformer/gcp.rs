use super::{ArnTransformer, ProviderArnInfo};
use crate::arn::types::{Service, WamiArn};
use crate::error::{AmiError, Result};

/// GCP ARN transformer.
///
/// Converts between WAMI ARNs and GCP resource name format:
/// `//iam.googleapis.com/projects/{project_id}/serviceAccounts/{resource_id}`
///
/// Note: GCP uses "resource names" rather than ARNs, but we use a simplified
/// ARN-like format for consistency.
pub struct GcpArnTransformer;

impl ArnTransformer for GcpArnTransformer {
    fn to_provider_arn(&self, arn: &WamiArn) -> Result<String> {
        let cloud_mapping =
            arn.cloud_mapping
                .as_ref()
                .ok_or_else(|| AmiError::InvalidParameter {
                    message: "ARN is not cloud-synced".to_string(),
                })?;

        if cloud_mapping.provider != "gcp" {
            return Err(AmiError::InvalidParameter {
                message: format!(
                    "ARN provider is '{}', expected 'gcp'",
                    cloud_mapping.provider
                ),
            });
        }

        // Map WAMI service to GCP service
        let gcp_service = match &arn.service {
            Service::Iam => "iam.googleapis.com",
            Service::SsoAdmin => "cloudidentity.googleapis.com",
            Service::Custom(s) => s.as_str(),
            _ => "iam.googleapis.com", // Default to IAM
        };

        // GCP format - optionally include location if regional
        let base = format!(
            "//{}/projects/{}/{}s/{}",
            gcp_service,
            cloud_mapping.account_id,
            arn.resource.resource_type,
            arn.resource.resource_id
        );

        // If regional, could append location, but GCP format varies by service
        // For simplicity, we keep the basic format
        Ok(base)
    }

    fn from_provider_arn(&self, provider_arn: &str) -> Result<ProviderArnInfo> {
        // Parse GCP resource name format
        // //iam.googleapis.com/projects/{project_id}/{resource_type}s/{resource_id}

        if !provider_arn.starts_with("//") {
            return Err(AmiError::InvalidParameter {
                message: "Invalid GCP resource name: expected '//' prefix".to_string(),
            });
        }

        let parts: Vec<&str> = provider_arn[2..].split('/').collect();

        if parts.len() < 4 {
            return Err(AmiError::InvalidParameter {
                message: format!(
                    "Invalid GCP resource name format: expected at least 4 parts, got {}",
                    parts.len()
                ),
            });
        }

        let service = parts[0].to_string();

        if parts[1] != "projects" {
            return Err(AmiError::InvalidParameter {
                message: format!(
                    "Invalid GCP resource name: expected 'projects', got '{}'",
                    parts[1]
                ),
            });
        }

        let account_id = parts[2].to_string();

        // Resource type (remove trailing 's' if present)
        let mut resource_type = parts[3].to_string();
        if resource_type.ends_with('s') {
            resource_type.pop();
        }

        let resource_id = parts[4..].join("/");

        Ok(ProviderArnInfo {
            provider: "gcp".to_string(),
            account_id,
            service,
            resource_type,
            resource_id,
            region: None, // GCP uses locations in a different format
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arn::{Service, WamiArn};
    #[test]
    fn test_gcp_transformer() {
        let arn = WamiArn::builder()
            .service(Service::Iam)
            .tenant(12345678)
            .wami_instance("999888777")
            .cloud_provider("gcp", "554433221")
            .resource("serviceAccount", "77557755")
            .build()
            .unwrap();

        let transformer = GcpArnTransformer;
        let gcp_arn = transformer.to_provider_arn(&arn).unwrap();
        assert_eq!(
            gcp_arn,
            "//iam.googleapis.com/projects/554433221/serviceAccounts/77557755"
        );
    }

    #[test]
    fn test_gcp_transformer_error_cases() {
        let transformer = GcpArnTransformer;

        // Not cloud synced
        let arn = WamiArn::builder()
            .service(Service::Iam)
            .tenant(12345678)
            .wami_instance("999888777")
            .resource("user", "alice")
            .build()
            .unwrap();

        let result = transformer.to_provider_arn(&arn);
        assert!(result.is_err());

        // Wrong provider
        let arn = WamiArn::builder()
            .service(Service::Iam)
            .tenant(12345678)
            .wami_instance("999888777")
            .cloud_provider("aws", "123456")
            .resource("user", "alice")
            .build()
            .unwrap();

        let result = transformer.to_provider_arn(&arn);
        assert!(result.is_err());
    }
}
