use keychain::{KeyBackend, KeychainError, ResolvedKey, decode_key};
use serde::Deserialize;

/// HashiCorp Vault KV v2 backend for keychain.
///
/// URI format: `vault://path/to/secret`
///
/// Authenticates via VAULT_ADDR and VAULT_TOKEN env vars.
pub struct VaultKvBackend {
    address: String,
    token: String,
    mount: String,
}

#[derive(Deserialize)]
struct VaultResponse {
    data: VaultResponseData,
}

#[derive(Deserialize)]
struct VaultResponseData {
    data: std::collections::HashMap<String, serde_json::Value>,
}

impl VaultKvBackend {
    pub fn new(address: &str, token: &str, mount: &str) -> Self {
        Self {
            address: address.trim_end_matches('/').to_string(),
            token: token.to_string(),
            mount: mount.to_string(),
        }
    }

    pub fn from_env() -> Result<Self, KeychainError> {
        let address = std::env::var("VAULT_ADDR")
            .map_err(|_| KeychainError::Backend("VAULT_ADDR not set".into()))?;
        let token = std::env::var("VAULT_TOKEN")
            .map_err(|_| KeychainError::Backend("VAULT_TOKEN not set".into()))?;
        Ok(Self::new(&address, &token, "secret"))
    }
}

impl KeyBackend for VaultKvBackend {
    fn scheme(&self) -> &str { "vault" }

    fn resolve(&self, path: &str) -> Result<ResolvedKey, KeychainError> {
        let url = format!("{}/v1/{}/data/{}", self.address, self.mount, path);

        let resp = ureq::get(&url)
            .header("X-Vault-Token", &self.token)
            .call()
            .map_err(|e| KeychainError::Backend(format!("Vault request failed: {}", e)))?;

        if resp.status() == 404 {
            return Err(KeychainError::NotFound(format!("vault://{}", path)));
        }

        let body = resp.into_body().read_to_string()
            .map_err(|e| KeychainError::Backend(format!("Failed to read Vault response: {}", e)))?;
        let vault_resp: VaultResponse = serde_json::from_str(&body)
            .map_err(|e| KeychainError::Backend(format!("Failed to parse Vault response: {}", e)))?;

        let material_str = vault_resp.data.data.get("material")
            .and_then(|v| v.as_str())
            .ok_or_else(|| KeychainError::Backend(format!("Vault secret '{}' missing 'material' field", path)))?;

        let material = decode_key(material_str.as_bytes(), Some("hex"))
            .map_err(|e| KeychainError::Backend(format!("Failed to decode material: {}", e)))?;

        Ok(ResolvedKey {
            uri: format!("vault://{}", path),
            material,
            metadata: std::collections::HashMap::new(),
        })
    }
}
