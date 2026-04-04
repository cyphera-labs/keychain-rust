use keychain::{KeyBackend, KeychainError, ResolvedKey};

/// GCP Cloud KMS backend for keychain.
///
/// URI format: `gcp-kms://projects/PROJECT/locations/LOC/keyRings/RING/cryptoKeys/KEY`
pub struct GcpKmsBackend;

impl GcpKmsBackend {
    pub fn new() -> Self { Self }
}

impl Default for GcpKmsBackend {
    fn default() -> Self { Self::new() }
}

impl KeyBackend for GcpKmsBackend {
    fn scheme(&self) -> &str { "gcp-kms" }

    fn resolve(&self, path: &str) -> Result<ResolvedKey, KeychainError> {
        let _ = path;
        Err(KeychainError::Backend("GCP KMS backend not yet implemented".into()))
    }
}
