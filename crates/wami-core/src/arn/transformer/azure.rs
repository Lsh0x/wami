use super::{ArnTransformer, ProviderArnInfo};
use crate::arn::types::{Service, WamiArn};
use crate::error::{AmiError, Result};

/// Azure ARN transformer.
///
/// Converts between WAMI ARNs and Azure resource ID format:
/// `/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.{service}/{resource_type}/{resource_id}`
pub struct AzureArnTransformer;

impl ArnTransformer for AzureArnTransformer {
    fn to_provider_arn(&self, arn: &WamiArn) -> Result<String> {
        let cloud_mapping =
            arn.cloud_mapping
                .as_ref()
                .ok_or_else(|| AmiError::InvalidParameter {
                    message: "ARN is not cloud-synced".to_string(),
                })?;

        if cloud_mapping.provider != "azure" {
            return Err(AmiError::InvalidParameter {
                message: format!(
                    "ARN provider is '{}', expected 'azure'",
                    cloud_mapping.provider
                ),
            });
        }

        // Map WAMI service to Azure namespace
        let azure_namespace = match &arn.service {
            Service::Iam => "Microsoft.Authorization",
            Service::SsoAdmin => "Microsoft.AzureActiveDirectory",
            Service::Custom(s) => s.as_str(),
            _ => "Microsoft.Authorization",
        };

        // For Azure, account_id is subscription_id
        // We use a default resource group "wami-resources"
        Ok(format!(
            "/subscriptions/{}/resourceGroups/wami-resources/providers/{}/{}/{}",
            cloud_mapping.account_id,
            azure_namespace,
            arn.resource.resource_type,
            arn.resource.resource_id
        ))
    }

    fn from_provider_arn(&self, provider_arn: &str) -> Result<ProviderArnInfo> {
        // Parse Azure resource ID format
        let parts: Vec<&str> = provider_arn.split('/').collect();

        if parts.len() < 9 || !parts[0].is_empty() {
            return Err(AmiError::InvalidParameter {
                message: "Invalid Azure resource ID format".to_string(),
            });
        }

        if parts[1] != "subscriptions" {
            return Err(AmiError::InvalidParameter {
                message: format!(
                    "Invalid Azure resource ID: expected 'subscriptions', got '{}'",
                    parts[1]
                ),
            });
        }

        let account_id = parts[2].to_string();
        let service = parts[5].to_string(); // providers/{namespace}
        let resource_type = parts[6].to_string();
        let resource_id = parts[7..].join("/");

        Ok(ProviderArnInfo {
            provider: "azure".to_string(),
            account_id,
            service,
            resource_type,
            resource_id,
            region: None, // Azure uses locations in resource groups
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arn::{Service, WamiArn};
    #[test]
    fn test_azure_transformer() {
        let arn = WamiArn::builder()
            .service(Service::Iam)
            .tenant(12345678)
            .wami_instance("999888777")
            .cloud_provider("azure", "sub-12345")
            .resource("user", "77557755")
            .build()
            .unwrap();

        let transformer = AzureArnTransformer;
        let azure_arn = transformer.to_provider_arn(&arn).unwrap();
        assert_eq!(
            azure_arn,
            "/subscriptions/sub-12345/resourceGroups/wami-resources/providers/Microsoft.Authorization/user/77557755"
        );
    }

    #[test]
    fn test_azure_transformer_error_cases() {
        let transformer = AzureArnTransformer;

        // Invalid Azure resource ID format
        let result = transformer.from_provider_arn("/invalid");
        assert!(result.is_err());

        // Missing required parts
        let result = transformer.from_provider_arn("/subscriptions/123");
        assert!(result.is_err());
    }
}
