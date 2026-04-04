use keychain::{KeyBackend, KeychainError, ResolvedKey};

/// HashiCorp Vault Transit backend for keychain.
///
/// URI format: `vault://mount/keys/key-name`
///
/// Authenticates via VAULT_ADDR and VAULT_TOKEN env vars.
pub struct VaultTransitBackend {
    _address: String,
}

impl VaultTransitBackend {
    pub fn new(address: &str) -> Self {
        Self {
            _address: address.to_string(),
        }
    }

    pub fn from_env() -> Result<Self, KeychainError> {
        let address = std::env::var("VAULT_ADDR")
            .map_err(|_| KeychainError::Backend("VAULT_ADDR not set".into()))?;
        Ok(Self::new(&address))
    }
}

impl KeyBackend for VaultTransitBackend {
    fn scheme(&self) -> &str { "vault" }

    fn resolve(&self, path: &str) -> Result<ResolvedKey, KeychainError> {
        let _ = path;
        Err(KeychainError::Backend("Vault Transit backend not yet implemented".into()))
    }
}
