use super::{ArnTransformer, ProviderArnInfo};
use crate::arn::types::{Service, WamiArn};
use crate::error::{AmiError, Result};

/// Scaleway ARN transformer.
///
/// Converts between WAMI ARNs and Scaleway resource format:
/// `scw:{organization_id}:{service}:{resource_type}/{resource_id}`
pub struct ScalewayArnTransformer;

impl ArnTransformer for ScalewayArnTransformer {
    fn to_provider_arn(&self, arn: &WamiArn) -> Result<String> {
        let cloud_mapping =
            arn.cloud_mapping
                .as_ref()
                .ok_or_else(|| AmiError::InvalidParameter {
                    message: "ARN is not cloud-synced".to_string(),
                })?;

        if cloud_mapping.provider != "scaleway" {
            return Err(AmiError::InvalidParameter {
                message: format!(
                    "ARN provider is '{}', expected 'scaleway'",
                    cloud_mapping.provider
                ),
            });
        }

        let service = match &arn.service {
            Service::Iam => "iam",
            Service::SsoAdmin => "sso",
            Service::Custom(s) => s.as_str(),
            _ => "iam",
        };

        Ok(format!(
            "scw:{}:{}:{}/{}",
            cloud_mapping.account_id, service, arn.resource.resource_type, arn.resource.resource_id
        ))
    }

    fn from_provider_arn(&self, provider_arn: &str) -> Result<ProviderArnInfo> {
        let parts: Vec<&str> = provider_arn.split(':').collect();

        if parts.len() < 4 {
            return Err(AmiError::InvalidParameter {
                message: format!(
                    "Invalid Scaleway resource format: expected at least 4 parts, got {}",
                    parts.len()
                ),
            });
        }

        if parts[0] != "scw" {
            return Err(AmiError::InvalidParameter {
                message: format!(
                    "Invalid Scaleway resource prefix: expected 'scw', got '{}'",
                    parts[0]
                ),
            });
        }

        let account_id = parts[1].to_string();
        let service = parts[2].to_string();

        let resource_part = parts[3..].join(":");
        let resource_parts: Vec<&str> = resource_part.split('/').collect();

        if resource_parts.len() < 2 {
            return Err(AmiError::InvalidParameter {
                message: format!(
                    "Invalid Scaleway resource format: expected 'type/id', got '{}'",
                    resource_part
                ),
            });
        }

        let resource_type = resource_parts[0].to_string();
        let resource_id = resource_parts[1..].join("/");

        Ok(ProviderArnInfo {
            provider: "scaleway".to_string(),
            account_id,
            service,
            resource_type,
            resource_id,
            region: None, // Scaleway regions handled separately
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arn::{Service, WamiArn};
    #[test]
    fn test_scaleway_transformer() {
        let arn = WamiArn::builder()
            .service(Service::Iam)
            .tenant(12345678)
            .wami_instance("999888777")
            .cloud_provider("scaleway", "112233445")
            .resource("user", "77557755")
            .build()
            .unwrap();

        let transformer = ScalewayArnTransformer;
        let scw_arn = transformer.to_provider_arn(&arn).unwrap();
        assert_eq!(scw_arn, "scw:112233445:iam:user/77557755");

        let info = transformer.from_provider_arn(&scw_arn).unwrap();
        assert_eq!(info.provider, "scaleway");
        assert_eq!(info.account_id, "112233445");
        assert_eq!(info.service, "iam");
        assert_eq!(info.resource_type, "user");
        assert_eq!(info.resource_id, "77557755");
    }

    #[test]
    fn test_scaleway_transformer_error_cases() {
        let transformer = ScalewayArnTransformer;

        // Invalid format
        let result = transformer.from_provider_arn("invalid");
        assert!(result.is_err());

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
    }
}
