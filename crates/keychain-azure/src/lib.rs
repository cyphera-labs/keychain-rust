use keychain::{KeyBackend, KeychainError, ResolvedKey};
use serde::Deserialize;
use std::collections::HashMap;

/// Azure Key Vault backend for keychain.
///
/// URI format: `azure-kv://vault-name/keys/key-name`
///
/// Generates a random 256-bit data encryption key, wraps it using the
/// Azure Key Vault wrapKey operation (RSA-OAEP), and returns the plaintext
/// as `material`. The wrapped key is stored in metadata as `wrapped_key`.
///
/// # Authentication
///
/// Set `AZURE_ACCESS_TOKEN` with an OAuth2 bearer token, or
/// `AZURE_KV_ENDPOINT` to override the base URL for local testing.
pub struct AzureKeyVaultBackend {
    endpoint_override: Option<String>,
}

#[derive(Deserialize)]
struct WrapKeyResponse {
    kid: Option<String>,
    value: String,
}

impl AzureKeyVaultBackend {
    pub fn new() -> Self {
        Self {
            endpoint_override: None,
        }
    }

    /// Create with an explicit endpoint override for local testing.
    pub fn with_endpoint(endpoint: &str) -> Self {
        Self {
            endpoint_override: Some(endpoint.trim_end_matches('/').to_string()),
        }
    }

    /// Create from environment variables.
    ///
    /// - `AZURE_ACCESS_TOKEN` (required unless using endpoint override)
    /// - `AZURE_KV_ENDPOINT` (optional, for local testing)
    pub fn from_env() -> Result<Self, KeychainError> {
        let endpoint_override = std::env::var("AZURE_KV_ENDPOINT").ok();
        Ok(Self { endpoint_override })
    }

    fn get_token() -> Result<String, KeychainError> {
        std::env::var("AZURE_ACCESS_TOKEN")
            .map_err(|_| KeychainError::Backend("AZURE_ACCESS_TOKEN not set".into()))
    }

    /// Parse the URI path into (vault_name, key_name).
    /// Path format: `vault-name/keys/key-name`
    fn parse_path(path: &str) -> Result<(String, String), KeychainError> {
        // Expected: "vault-name/keys/key-name"
        let parts: Vec<&str> = path.splitn(3, '/').collect();
        if parts.len() != 3 || parts[1] != "keys" {
            return Err(KeychainError::InvalidUri(format!(
                "expected 'vault-name/keys/key-name', got '{}'",
                path
            )));
        }
        Ok((parts[0].to_string(), parts[2].to_string()))
    }
}

impl Default for AzureKeyVaultBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyBackend for AzureKeyVaultBackend {
    fn scheme(&self) -> &str {
        "azure-kv"
    }

    fn resolve(&self, path: &str) -> Result<ResolvedKey, KeychainError> {
        let token = Self::get_token()?;
        let (vault_name, key_name) = Self::parse_path(path)?;

        // Generate a random 32-byte DEK
        use rand::RngCore;
        let mut plaintext = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut plaintext);

        // Base64url-encode the plaintext for the wrapKey request (Azure uses base64url without padding)
        use base64::Engine;
        let plaintext_b64url =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&plaintext);

        let url = match &self.endpoint_override {
            Some(ep) => format!("{}/keys/{}/wrapkey?api-version=7.4", ep, key_name),
            None => format!(
                "https://{}.vault.azure.net/keys/{}/wrapkey?api-version=7.4",
                vault_name, key_name
            ),
        };

        let body = serde_json::json!({
            "alg": "RSA-OAEP",
            "value": plaintext_b64url
        });

        let resp = ureq::post(&url)
            .set("Authorization", &format!("Bearer {}", token))
            .set("Content-Type", "application/json")
            .send_json(&body)
            .map_err(|e| match e {
                ureq::Error::Status(code, resp) => {
                    let body = resp.into_string().unwrap_or_default();
                    KeychainError::Backend(format!(
                        "Azure Key Vault wrapKey failed (HTTP {}): {}",
                        code, body
                    ))
                }
                _ => KeychainError::Backend(format!("Azure Key Vault request failed: {}", e)),
            })?;

        let wrap_resp: WrapKeyResponse = resp
            .into_json()
            .map_err(|e| {
                KeychainError::Backend(format!("Failed to parse Azure KV response: {}", e))
            })?;

        let mut metadata = HashMap::new();
        metadata.insert("wrapped_key".to_string(), wrap_resp.value);
        metadata.insert("algorithm".to_string(), "RSA-OAEP".to_string());
        if let Some(kid) = wrap_resp.kid {
            metadata.insert("kid".to_string(), kid);
        }
        metadata.insert("vault_name".to_string(), vault_name);
        metadata.insert("key_name".to_string(), key_name);

        Ok(ResolvedKey {
            uri: format!("azure-kv://{}", path),
            material: plaintext,
            metadata,
        })
    }
}
