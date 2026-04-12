use keychain::{KeyBackend, KeychainError, ResolvedKey};
use serde::Deserialize;
use std::collections::HashMap;

/// AWS KMS backend for keychain.
///
/// URI formats:
/// - `aws-kms://arn:aws:kms:us-east-1:123456:key/key-id`
/// - `aws-kms://alias/my-key?region=us-east-1`
/// - `aws-kms://key-id?region=us-east-1`
///
/// Uses the KMS GenerateDataKey API via HTTP REST to generate a 256-bit
/// data encryption key. The plaintext key is returned as `material`; the
/// encrypted (wrapped) copy is stored in metadata as `ciphertext_blob`.
///
/// # Authentication
///
/// For local development with LocalStack, set `AWS_KMS_ENDPOINT` to override
/// the endpoint (e.g. `http://localhost:4566`). LocalStack does not require
/// request signing.
///
/// TODO: Implement SigV4 request signing for real AWS endpoints.
/// For now this backend works with endpoint override (LocalStack) or
/// any proxy that does not require SigV4 signing.
pub struct AwsKmsBackend {
    region: String,
    endpoint: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GenerateDataKeyResponse {
    plaintext: String,
    ciphertext_blob: String,
    key_id: String,
}

impl AwsKmsBackend {
    pub fn new(region: &str) -> Self {
        Self {
            region: region.to_string(),
            endpoint: None,
        }
    }

    /// Create with an explicit endpoint override (e.g. for LocalStack).
    pub fn with_endpoint(region: &str, endpoint: &str) -> Self {
        Self {
            region: region.to_string(),
            endpoint: Some(endpoint.trim_end_matches('/').to_string()),
        }
    }

    /// Create from environment variables.
    ///
    /// - `AWS_REGION` or `AWS_DEFAULT_REGION` (required)
    /// - `AWS_KMS_ENDPOINT` (optional, for LocalStack)
    pub fn from_env() -> Result<Self, KeychainError> {
        let region = std::env::var("AWS_REGION")
            .or_else(|_| std::env::var("AWS_DEFAULT_REGION"))
            .map_err(|_| KeychainError::Backend("AWS_REGION or AWS_DEFAULT_REGION not set".into()))?;

        let endpoint = std::env::var("AWS_KMS_ENDPOINT").ok();

        Ok(Self {
            region,
            endpoint,
        })
    }

    fn base_url(&self) -> String {
        match &self.endpoint {
            Some(ep) => ep.clone(),
            None => format!("https://kms.{}.amazonaws.com", self.region),
        }
    }

    /// Parse the path portion of the URI to extract key_id and optional region override.
    /// Supports:
    ///   - `arn:aws:kms:us-east-1:123456:key/key-id`
    ///   - `key-id?region=us-west-2`
    ///   - `alias/my-key?region=us-west-2`
    fn parse_path(&self, path: &str) -> (String, Option<String>) {
        if let Some(idx) = path.find('?') {
            let key_id = &path[..idx];
            let query = &path[idx + 1..];
            let mut region_override = None;
            for param in query.split('&') {
                if let Some(val) = param.strip_prefix("region=") {
                    region_override = Some(val.to_string());
                }
            }
            (key_id.to_string(), region_override)
        } else {
            (path.to_string(), None)
        }
    }
}

impl KeyBackend for AwsKmsBackend {
    fn scheme(&self) -> &str {
        "aws-kms"
    }

    fn resolve(&self, path: &str) -> Result<ResolvedKey, KeychainError> {
        let (key_id, region_override) = self.parse_path(path);

        // Build the endpoint URL, respecting region override
        let url = match (&self.endpoint, &region_override) {
            (Some(ep), _) => ep.clone(),
            (None, Some(r)) => format!("https://kms.{}.amazonaws.com", r),
            (None, None) => self.base_url(),
        };

        let body = serde_json::json!({
            "KeyId": key_id,
            "KeySpec": "AES_256"
        });

        // TODO: Add SigV4 signing for real AWS endpoints.
        // LocalStack and local proxies work without signing.
        let resp = ureq::post(&url)
            .set("Content-Type", "application/x-amz-json-1.1")
            .set("X-Amz-Target", "TrentService.GenerateDataKey")
            .send_json(&body)
            .map_err(|e| match e {
                ureq::Error::Status(code, resp) => {
                    let body = resp.into_string().unwrap_or_default();
                    KeychainError::Backend(format!(
                        "AWS KMS GenerateDataKey failed (HTTP {}): {}",
                        code, body
                    ))
                }
                _ => KeychainError::Backend(format!("AWS KMS request failed: {}", e)),
            })?;

        let kms_resp: GenerateDataKeyResponse = resp
            .into_json()
            .map_err(|e| KeychainError::Backend(format!("Failed to parse KMS response: {}", e)))?;

        use base64::Engine;
        let plaintext = base64::engine::general_purpose::STANDARD
            .decode(&kms_resp.plaintext)
            .map_err(|e| KeychainError::Backend(format!("Failed to decode plaintext: {}", e)))?;

        let mut metadata = HashMap::new();
        metadata.insert("ciphertext_blob".to_string(), kms_resp.ciphertext_blob);
        metadata.insert("key_id".to_string(), kms_resp.key_id);
        metadata.insert(
            "region".to_string(),
            region_override.unwrap_or_else(|| self.region.clone()),
        );

        Ok(ResolvedKey {
            uri: format!("aws-kms://{}", path),
            material: plaintext,
            metadata,
        })
    }
}
