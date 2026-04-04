use keychain::{KeyBackend, KeychainError, ResolvedKey};

/// Azure Key Vault backend for keychain.
///
/// URI format: `azure-kv://vault-name/keys/key-name`
pub struct AzureKeyVaultBackend;

impl AzureKeyVaultBackend {
    pub fn new() -> Self { Self }
}

impl Default for AzureKeyVaultBackend {
    fn default() -> Self { Self::new() }
}

impl KeyBackend for AzureKeyVaultBackend {
    fn scheme(&self) -> &str { "azure-kv" }

    fn resolve(&self, path: &str) -> Result<ResolvedKey, KeychainError> {
        let _ = path;
        Err(KeychainError::Backend("Azure Key Vault backend not yet implemented".into()))
    }
}
