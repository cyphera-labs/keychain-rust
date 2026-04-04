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

/// Universal key store. Register backends, resolve URIs or named aliases.
pub struct KeyStore {
    backends: HashMap<String, Box<dyn KeyBackend>>,
    aliases: HashMap<String, String>,
}

impl KeyStore {
    pub fn new() -> Self {
        Self {
            backends: HashMap::new(),
            aliases: HashMap::new(),
        }
    }

    /// Register a backend for a URI scheme
    pub fn register(mut self, backend: Box<dyn KeyBackend>) -> Self {
        let scheme = backend.scheme().to_string();
        self.backends.insert(scheme, backend);
        self
    }

    /// Register a named alias that maps to a URI.
    ///
    /// ```ignore
    /// store.alias("customer-east", "aws-kms://arn:aws:kms:us-east-1:123:key/ssn");
    /// store.resolve("customer-east")?; // resolves via AWS KMS
    /// ```
    pub fn alias(mut self, name: &str, uri: &str) -> Self {
        self.aliases.insert(name.to_string(), uri.to_string());
        self
    }

    /// Load aliases from a HashMap (e.g., parsed from YAML/JSON)
    pub fn aliases(mut self, map: HashMap<String, String>) -> Self {
        self.aliases.extend(map);
        self
    }

    /// Resolve a name or URI to key material.
    ///
    /// If the input contains `://`, it's treated as a URI.
    /// Otherwise, it's looked up as an alias first.
    ///
    /// Examples:
    /// - `"customer-east"` → alias lookup → `"aws-kms://..."` → AWS KMS
    /// - `"env://MY_KEY"` → direct URI → env backend
    pub fn resolve(&self, name_or_uri: &str) -> Result<ResolvedKey, KeychainError> {
        // If it looks like a URI, resolve directly
        let uri = if name_or_uri.contains("://") {
            name_or_uri.to_string()
        } else {
            // Look up alias
            self.aliases.get(name_or_uri)
                .cloned()
                .ok_or_else(|| KeychainError::NotFound(
                    format!("no alias or URI found for '{name_or_uri}'")
                ))?
        };

        let (scheme, path) = parse_uri(&uri)?;

        let backend = self.backends.get(&scheme).ok_or_else(|| {
            KeychainError::UnknownScheme(scheme.clone())
        })?;

        backend.resolve(&path)
    }

    /// List registered schemes
    pub fn schemes(&self) -> Vec<&str> {
        self.backends.keys().map(|s| s.as_str()).collect()
    }

    /// List registered aliases
    pub fn alias_names(&self) -> Vec<&str> {
        self.aliases.keys().map(|s| s.as_str()).collect()
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
    fn test_alias_resolves_to_backend() {
        let store = KeyStore::new()
            .register(Box::new(DummyBackend))
            .alias("my-key", "dummy://actual-key-path");

        let key = store.resolve("my-key").unwrap();
        assert_eq!(key.material.len(), 32);
        assert_eq!(key.uri, "dummy://actual-key-path");
    }

    #[test]
    fn test_alias_not_found() {
        let store = KeyStore::new()
            .register(Box::new(DummyBackend));

        // No alias registered, and it doesn't look like a URI
        assert!(store.resolve("nonexistent").is_err());
    }

    #[test]
    fn test_uri_bypasses_alias() {
        let store = KeyStore::new()
            .register(Box::new(DummyBackend))
            .alias("my-key", "dummy://aliased-path");

        // Direct URI should bypass alias lookup
        let key = store.resolve("dummy://direct-path").unwrap();
        assert_eq!(key.uri, "dummy://direct-path");
    }

    #[test]
    fn test_multiple_aliases() {
        let store = KeyStore::new()
            .register(Box::new(DummyBackend))
            .alias("east", "dummy://us-east-key")
            .alias("west", "dummy://us-west-key")
            .alias("eu", "dummy://eu-key");

        assert!(store.resolve("east").is_ok());
        assert!(store.resolve("west").is_ok());
        assert!(store.resolve("eu").is_ok());
        assert_eq!(store.alias_names().len(), 3);
    }

    #[test]
    fn test_aliases_from_hashmap() {
        let mut map = HashMap::new();
        map.insert("prod".to_string(), "dummy://prod-key".to_string());
        map.insert("staging".to_string(), "dummy://staging-key".to_string());

        let store = KeyStore::new()
            .register(Box::new(DummyBackend))
            .aliases(map);

        assert!(store.resolve("prod").is_ok());
        assert!(store.resolve("staging").is_ok());
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
