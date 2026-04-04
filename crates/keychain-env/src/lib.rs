use keychain::{KeyBackend, KeychainError, ResolvedKey, decode_key};
use std::collections::HashMap;

/// Resolves keys from environment variables.
///
/// URI format: `env://VAR_NAME`
///
/// Supports encoding hints via suffix:
/// - `env://MY_KEY` — raw UTF-8 bytes
/// - `env://MY_KEY?hex` — hex-decoded
/// - `env://MY_KEY?base64` — base64-decoded
pub struct EnvBackend;

impl EnvBackend {
    pub fn new() -> Self {
        Self
    }
}

impl Default for EnvBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyBackend for EnvBackend {
    fn scheme(&self) -> &str {
        "env"
    }

    fn resolve(&self, path: &str) -> Result<ResolvedKey, KeychainError> {
        // Parse optional encoding hint: VAR_NAME?hex or VAR_NAME?base64
        let (var_name, encoding) = if let Some(idx) = path.find('?') {
            (&path[..idx], Some(&path[idx + 1..]))
        } else {
            (path, None)
        };

        let value = std::env::var(var_name).map_err(|_| {
            KeychainError::NotFound(format!("env var '{var_name}' not set"))
        })?;

        let material = decode_key(value.as_bytes(), encoding)?;

        Ok(ResolvedKey {
            uri: format!("env://{path}"),
            material,
            metadata: HashMap::from([
                ("source".into(), "env".into()),
                ("var".into(), var_name.to_string()),
            ]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_env_raw() {
        std::env::set_var("KEYCHAIN_TEST_RAW", "my-secret-key");
        let backend = EnvBackend::new();
        let key = backend.resolve("KEYCHAIN_TEST_RAW").unwrap();
        assert_eq!(key.material, b"my-secret-key");
        std::env::remove_var("KEYCHAIN_TEST_RAW");
    }

    #[test]
    fn test_resolve_env_hex() {
        std::env::set_var("KEYCHAIN_TEST_HEX", "deadbeef01020304");
        let backend = EnvBackend::new();
        let key = backend.resolve("KEYCHAIN_TEST_HEX?hex").unwrap();
        assert_eq!(key.material, vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04]);
        std::env::remove_var("KEYCHAIN_TEST_HEX");
    }

    #[test]
    fn test_resolve_env_base64() {
        std::env::set_var("KEYCHAIN_TEST_B64", "AQIDBA==");
        let backend = EnvBackend::new();
        let key = backend.resolve("KEYCHAIN_TEST_B64?base64").unwrap();
        assert_eq!(key.material, vec![1, 2, 3, 4]);
        std::env::remove_var("KEYCHAIN_TEST_B64");
    }

    #[test]
    fn test_missing_var() {
        let backend = EnvBackend::new();
        let result = backend.resolve("KEYCHAIN_DEFINITELY_DOES_NOT_EXIST");
        assert!(result.is_err());
    }
}
