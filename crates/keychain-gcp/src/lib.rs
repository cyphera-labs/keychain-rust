use keychain::{KeyBackend, KeychainError, ResolvedKey};
use serde::Deserialize;
use std::collections::HashMap;

/// GCP Cloud KMS backend for keychain.
///
/// URI format: `gcp-kms://projects/PROJECT/locations/LOC/keyRings/RING/cryptoKeys/KEY`
///
/// Generates a random 256-bit data encryption key, encrypts it with the
/// specified Cloud KMS key, and returns the plaintext as `material`. The
/// ciphertext (wrapped key) is stored in metadata as `ciphertext`.
///
/// # Authentication
///
/// Set `GOOGLE_ACCESS_TOKEN` with an OAuth2 bearer token, or
/// `GCP_KMS_ENDPOINT` to override the endpoint for local testing
/// (e.g. with a Cloud KMS emulator).
pub struct GcpKmsBackend {
    endpoint: Option<String>,
}

#[derive(Deserialize)]
struct EncryptResponse {
    ciphertext: String,
    name: Option<String>,
}

impl GcpKmsBackend {
    pub fn new() -> Self {
        Self { endpoint: None }
    }

    /// Create with an explicit endpoint override for local testing.
    pub fn with_endpoint(endpoint: &str) -> Self {
        Self {
            endpoint: Some(endpoint.trim_end_matches('/').to_string()),
        }
    }

    /// Create from environment variables.
    ///
    /// - `GOOGLE_ACCESS_TOKEN` (required unless using endpoint override)
    /// - `GCP_KMS_ENDPOINT` (optional, for emulators)
    pub fn from_env() -> Result<Self, KeychainError> {
        let endpoint = std::env::var("GCP_KMS_ENDPOINT").ok();
        // Token is checked at resolve time, not at construction
        Ok(Self { endpoint })
    }

    fn base_url(&self) -> String {
        match &self.endpoint {
            Some(ep) => ep.clone(),
            None => "https://cloudkms.googleapis.com".to_string(),
        }
    }

    fn get_token() -> Result<String, KeychainError> {
        std::env::var("GOOGLE_ACCESS_TOKEN")
            .map_err(|_| KeychainError::Backend("GOOGLE_ACCESS_TOKEN not set".into()))
    }
}

impl Default for GcpKmsBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyBackend for GcpKmsBackend {
    fn scheme(&self) -> &str {
        "gcp-kms"
    }

    fn resolve(&self, path: &str) -> Result<ResolvedKey, KeychainError> {
        // path = "projects/P/locations/L/keyRings/R/cryptoKeys/K"
        let token = Self::get_token()?;

        // Generate a random 32-byte DEK
        use rand::RngCore;
        let mut plaintext = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut plaintext);

        // Base64-encode the plaintext for the encrypt request
        use base64::Engine;
        let plaintext_b64 = base64::engine::general_purpose::STANDARD.encode(&plaintext);

        let url = format!("{}/v1/{}:encrypt", self.base_url(), path);
        let body = serde_json::json!({
            "plaintext": plaintext_b64
        });

        let resp = ureq::post(&url)
            .set("Authorization", &format!("Bearer {}", token))
            .set("Content-Type", "application/json")
            .send_json(&body)
            .map_err(|e| match e {
                ureq::Error::Status(code, resp) => {
                    let body = resp.into_string().unwrap_or_default();
                    KeychainError::Backend(format!(
                        "GCP KMS encrypt failed (HTTP {}): {}",
                        code, body
                    ))
                }
                _ => KeychainError::Backend(format!("GCP KMS request failed: {}", e)),
            })?;

        let encrypt_resp: EncryptResponse = resp
            .into_json()
            .map_err(|e| KeychainError::Backend(format!("Failed to parse GCP KMS response: {}", e)))?;

        let mut metadata = HashMap::new();
        metadata.insert("ciphertext".to_string(), encrypt_resp.ciphertext);
        if let Some(name) = encrypt_resp.name {
            metadata.insert("key_name".to_string(), name);
        }

        Ok(ResolvedKey {
            uri: format!("gcp-kms://{}", path),
            material: plaintext,
            metadata,
        })
    }
}
