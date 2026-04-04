use thiserror::Error;
use std::collections::HashMap;

#[derive(Error, Debug)]
pub enum KeychainError {
    #[error("no backend registered for scheme '{0}'")]
    UnknownScheme(String),
    #[error("key not found: {0}")]
    NotFound(String),
    #[error("invalid URI: {0}")]
    InvalidUri(String),
    #[error("backend error: {0}")]
    Backend(String),
    #[error("invalid key encoding: {0}")]
    Encoding(String),
}

/// Resolved key material
#[derive(Debug, Clone)]
pub struct ResolvedKey {
    pub uri: String,
    pub material: Vec<u8>,
    pub metadata: HashMap<String, String>,
}

/// Trait for key backends. Each backend handles one URI scheme.
pub trait KeyBackend: Send + Sync {
    /// The URI scheme this backend handles (e.g., "env", "file", "aws-kms")
    fn scheme(&self) -> &str;

    /// Resolve a URI to key material.
    /// The `path` is everything after `scheme://`
    fn resolve(&self, path: &str) -> Result<ResolvedKey, KeychainError>;
}

/// Universal key store. Register backends, resolve URIs.
pub struct KeyStore {
    backends: HashMap<String, Box<dyn KeyBackend>>,
}

impl KeyStore {
    pub fn new() -> Self {
        Self {
            backends: HashMap::new(),
        }
    }

    /// Register a backend for a URI scheme
    pub fn register(mut self, backend: Box<dyn KeyBackend>) -> Self {
        let scheme = backend.scheme().to_string();
        self.backends.insert(scheme, backend);
        self
    }

    /// Resolve a URI to key material.
    ///
    /// URI format: `scheme://path`
    ///
    /// Examples:
    /// - `env://MY_SECRET_KEY`
    /// - `file://./keys/dev.key`
    /// - `file://./keys/dev.hex` (hex-encoded)
    /// - `aws-kms://arn:aws:kms:us-east-1:123:key/abc`
    /// - `vault://transit/keys/my-key`
    /// - `gcp-kms://projects/p/locations/l/keyRings/r/cryptoKeys/k`
    /// - `azure-kv://my-vault/keys/my-key`
    pub fn resolve(&self, uri: &str) -> Result<ResolvedKey, KeychainError> {
        let (scheme, path) = parse_uri(uri)?;

        let backend = self.backends.get(&scheme).ok_or_else(|| {
            KeychainError::UnknownScheme(scheme.clone())
        })?;

        backend.resolve(&path)
    }

    /// List registered schemes
    pub fn schemes(&self) -> Vec<&str> {
        self.backends.keys().map(|s| s.as_str()).collect()
    }
}

impl Default for KeyStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse a URI into scheme and path
fn parse_uri(uri: &str) -> Result<(String, String), KeychainError> {
    let parts: Vec<&str> = uri.splitn(2, "://").collect();
    if parts.len() != 2 {
        return Err(KeychainError::InvalidUri(format!(
            "expected 'scheme://path', got '{uri}'"
        )));
    }
    Ok((parts[0].to_string(), parts[1].to_string()))
}

/// Decode key material from common encodings.
/// Detects format from content or file extension.
pub fn decode_key(data: &[u8], hint: Option<&str>) -> Result<Vec<u8>, KeychainError> {
    match hint {
        Some("hex") => {
            let s = std::str::from_utf8(data)
                .map_err(|e| KeychainError::Encoding(e.to_string()))?
                .trim();
            hex::decode(s).map_err(|e| KeychainError::Encoding(e.to_string()))
        }
        Some("base64") | Some("b64") => {
            use base64::Engine;
            let s = std::str::from_utf8(data)
                .map_err(|e| KeychainError::Encoding(e.to_string()))?
                .trim();
            base64::engine::general_purpose::STANDARD
                .decode(s)
                .map_err(|e| KeychainError::Encoding(e.to_string()))
        }
        _ => {
            // Raw bytes
            Ok(data.to_vec())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Dummy backend for testing
    struct DummyBackend;

    impl KeyBackend for DummyBackend {
        fn scheme(&self) -> &str { "dummy" }
        fn resolve(&self, path: &str) -> Result<ResolvedKey, KeychainError> {
            Ok(ResolvedKey {
                uri: format!("dummy://{path}"),
                material: vec![0xAB; 32],
                metadata: HashMap::new(),
            })
        }
    }

    #[test]
    fn test_parse_uri() {
        let (scheme, path) = parse_uri("env://MY_KEY").unwrap();
        assert_eq!(scheme, "env");
        assert_eq!(path, "MY_KEY");
    }

    #[test]
    fn test_parse_uri_with_slashes() {
        let (scheme, path) = parse_uri("aws-kms://arn:aws:kms:us-east-1:123:key/abc").unwrap();
        assert_eq!(scheme, "aws-kms");
        assert_eq!(path, "arn:aws:kms:us-east-1:123:key/abc");
    }

    #[test]
    fn test_invalid_uri() {
        assert!(parse_uri("noscheme").is_err());
    }

    #[test]
    fn test_register_and_resolve() {
        let store = KeyStore::new()
            .register(Box::new(DummyBackend));

        let key = store.resolve("dummy://my-key").unwrap();
        assert_eq!(key.material.len(), 32);
        assert_eq!(key.uri, "dummy://my-key");
    }

    #[test]
    fn test_unknown_scheme() {
        let store = KeyStore::new();
        assert!(store.resolve("nope://key").is_err());
    }

    #[test]
    fn test_decode_hex() {
        let key = decode_key(b"0102030405060708", Some("hex")).unwrap();
        assert_eq!(key, vec![1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn test_decode_base64() {
        let key = decode_key(b"AQIDBA==", Some("base64")).unwrap();
        assert_eq!(key, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_decode_raw() {
        let raw = vec![1, 2, 3, 4];
        let key = decode_key(&raw, None).unwrap();
        assert_eq!(key, raw);
    }
}
