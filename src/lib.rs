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

/// Resolved key material + settings
#[derive(Debug, Clone)]
pub struct ResolvedKey {
    pub uri: String,
    pub material: Vec<u8>,
    pub metadata: HashMap<String, String>,
}

/// Full key configuration — URI + all settings needed for use
#[derive(Debug, Clone)]
pub struct KeyConfig {
    pub uri: String,
    pub tweak: Option<Vec<u8>>,
    pub algorithm: Option<String>,
    pub version: Option<u32>,
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

/// Resolved key with full settings from the key config
#[derive(Debug, Clone)]
pub struct FullResolvedKey {
    pub name: String,
    pub uri: String,
    pub material: Vec<u8>,
    pub tweak: Option<Vec<u8>>,
    pub algorithm: Option<String>,
    pub version: Option<u32>,
    pub metadata: HashMap<String, String>,
}

/// Universal key store. Register backends, resolve URIs or named key configs.
pub struct KeyStore {
    backends: HashMap<String, Box<dyn KeyBackend>>,
    aliases: HashMap<String, String>,
    configs: HashMap<String, KeyConfig>,
}

impl KeyStore {
    pub fn new() -> Self {
        Self {
            backends: HashMap::new(),
            aliases: HashMap::new(),
            configs: HashMap::new(),
        }
    }

    /// Register a backend for a URI scheme
    pub fn register(mut self, backend: Box<dyn KeyBackend>) -> Self {
        let scheme = backend.scheme().to_string();
        self.backends.insert(scheme, backend);
        self
    }

    /// Register a simple alias: name → URI (no extra settings)
    ///
    /// ```ignore
    /// store.alias("customer-east", "aws-kms://arn:aws:kms:us-east-1:123:key/ssn");
    /// ```
    pub fn alias(mut self, name: &str, uri: &str) -> Self {
        self.aliases.insert(name.to_string(), uri.to_string());
        self
    }

    /// Load simple aliases from a HashMap
    pub fn aliases(mut self, map: HashMap<String, String>) -> Self {
        self.aliases.extend(map);
        self
    }

    /// Register a full key config: name → URI + tweak + algorithm + version + metadata
    ///
    /// ```ignore
    /// store.key("prod-east", KeyConfig {
    ///     uri: "aws-kms://arn:aws:kms:us-east-1:123:key/ssn".into(),
    ///     tweak: Some(hex::decode("d8e7920afa330a73").unwrap()),
    ///     algorithm: Some("aes-256".into()),
    ///     version: Some(2),
    ///     metadata: HashMap::new(),
    /// });
    /// ```
    pub fn key(mut self, name: &str, config: KeyConfig) -> Self {
        self.configs.insert(name.to_string(), config);
        self
    }

    /// Load multiple key configs
    pub fn keys(mut self, configs: HashMap<String, KeyConfig>) -> Self {
        self.configs.extend(configs);
        self
    }

    /// Resolve a name or URI to key material (simple — no key config settings)
    pub fn resolve(&self, name_or_uri: &str) -> Result<ResolvedKey, KeychainError> {
        let uri = self.resolve_uri(name_or_uri)?;
        let (scheme, path) = parse_uri(&uri)?;
        let backend = self.backends.get(&scheme).ok_or_else(|| {
            KeychainError::UnknownScheme(scheme.clone())
        })?;
        backend.resolve(&path)
    }

    /// Resolve a name to key material + full settings from key config.
    /// Falls back to simple alias or direct URI if no config found.
    pub fn resolve_full(&self, name_or_uri: &str) -> Result<FullResolvedKey, KeychainError> {
        // Check key configs first
        if let Some(config) = self.configs.get(name_or_uri) {
            let (scheme, path) = parse_uri(&config.uri)?;
            let backend = self.backends.get(&scheme).ok_or_else(|| {
                KeychainError::UnknownScheme(scheme.clone())
            })?;
            let resolved = backend.resolve(&path)?;

            return Ok(FullResolvedKey {
                name: name_or_uri.to_string(),
                uri: config.uri.clone(),
                material: resolved.material,
                tweak: config.tweak.clone(),
                algorithm: config.algorithm.clone(),
                version: config.version,
                metadata: {
                    let mut m = resolved.metadata;
                    m.extend(config.metadata.clone());
                    m
                },
            });
        }

        // Fall back to simple resolve
        let uri = self.resolve_uri(name_or_uri)?;
        let (scheme, path) = parse_uri(&uri)?;
        let backend = self.backends.get(&scheme).ok_or_else(|| {
            KeychainError::UnknownScheme(scheme.clone())
        })?;
        let resolved = backend.resolve(&path)?;

        Ok(FullResolvedKey {
            name: name_or_uri.to_string(),
            uri,
            material: resolved.material,
            tweak: None,
            algorithm: None,
            version: None,
            metadata: resolved.metadata,
        })
    }

    /// List registered schemes
    pub fn schemes(&self) -> Vec<&str> {
        self.backends.keys().map(|s| s.as_str()).collect()
    }

    /// List registered aliases
    pub fn alias_names(&self) -> Vec<&str> {
        self.aliases.keys().map(|s| s.as_str()).collect()
    }

    /// List registered key configs
    pub fn key_names(&self) -> Vec<&str> {
        self.configs.keys().map(|s| s.as_str()).collect()
    }

    // ── Internal ────────────────────────────────────────────────────────

    fn resolve_uri(&self, name_or_uri: &str) -> Result<String, KeychainError> {
        if name_or_uri.contains("://") {
            Ok(name_or_uri.to_string())
        } else if let Some(config) = self.configs.get(name_or_uri) {
            Ok(config.uri.clone())
        } else if let Some(uri) = self.aliases.get(name_or_uri) {
            Ok(uri.clone())
        } else {
            Err(KeychainError::NotFound(
                format!("no key config, alias, or URI found for '{name_or_uri}'")
            ))
        }
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

// ── Module declarations ─────────────────────────────────────────────────

pub mod env;
pub mod file;

#[cfg(feature = "aws")]
pub mod aws;

#[cfg(feature = "gcp")]
pub mod gcp;

#[cfg(feature = "azure")]
pub mod azure;

#[cfg(feature = "vault")]
pub mod vault;

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
    fn test_key_config_full_resolve() {
        let store = KeyStore::new()
            .register(Box::new(DummyBackend))
            .key("prod-east", KeyConfig {
                uri: "dummy://east-key".into(),
                tweak: Some(vec![0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73]),
                algorithm: Some("aes-256".into()),
                version: Some(2),
                metadata: HashMap::from([("region".into(), "us-east-1".into())]),
            });

        let key = store.resolve_full("prod-east").unwrap();
        assert_eq!(key.name, "prod-east");
        assert_eq!(key.material.len(), 32);
        assert_eq!(key.tweak, Some(vec![0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73]));
        assert_eq!(key.algorithm, Some("aes-256".into()));
        assert_eq!(key.version, Some(2));
        assert_eq!(key.metadata.get("region"), Some(&"us-east-1".to_string()));
    }

    #[test]
    fn test_key_config_fallback_to_alias() {
        let store = KeyStore::new()
            .register(Box::new(DummyBackend))
            .alias("simple", "dummy://simple-key");

        // No key config for "simple", but there's an alias
        let key = store.resolve_full("simple").unwrap();
        assert_eq!(key.name, "simple");
        assert!(key.tweak.is_none()); // no config, no tweak
        assert!(key.algorithm.is_none());
    }

    #[test]
    fn test_key_config_takes_priority_over_alias() {
        let store = KeyStore::new()
            .register(Box::new(DummyBackend))
            .alias("mykey", "dummy://alias-path")
            .key("mykey", KeyConfig {
                uri: "dummy://config-path".into(),
                tweak: Some(vec![1, 2, 3, 4, 5, 6, 7, 8]),
                algorithm: None,
                version: None,
                metadata: HashMap::new(),
            });

        // Key config should win over alias
        let key = store.resolve_full("mykey").unwrap();
        assert_eq!(key.uri, "dummy://config-path");
        assert!(key.tweak.is_some());
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
