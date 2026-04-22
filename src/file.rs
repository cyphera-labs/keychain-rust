use crate::{KeyBackend, KeychainError, ResolvedKey, decode_key};
use std::collections::HashMap;

/// Resolves keys from files on disk.
///
/// URI format: `file://path/to/key`
///
/// Encoding detected from file extension:
/// - `.key`, `.bin` — raw bytes
/// - `.hex` — hex-encoded
/// - `.b64`, `.base64` — base64-encoded
///
/// Or override with query param: `file://path/to/key?hex`
pub struct FileBackend;

impl FileBackend {
    pub fn new() -> Self {
        Self
    }
}

impl Default for FileBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyBackend for FileBackend {
    fn scheme(&self) -> &str {
        "file"
    }

    fn resolve(&self, path: &str) -> Result<ResolvedKey, KeychainError> {
        // Parse optional encoding override: path?hex
        let (file_path, encoding_override) = if let Some(idx) = path.find('?') {
            (&path[..idx], Some(&path[idx + 1..]))
        } else {
            (path, None)
        };

        let data = std::fs::read(file_path).map_err(|e| {
            KeychainError::NotFound(format!("failed to read '{file_path}': {e}"))
        })?;

        // Determine encoding: explicit override > file extension > raw
        let encoding = encoding_override.or_else(|| {
            if file_path.ends_with(".hex") {
                Some("hex")
            } else if file_path.ends_with(".b64") || file_path.ends_with(".base64") {
                Some("base64")
            } else {
                None
            }
        });

        let material = decode_key(&data, encoding)?;

        Ok(ResolvedKey {
            uri: format!("file://{path}"),
            material,
            metadata: HashMap::from([
                ("source".into(), "file".into()),
                ("path".into(), file_path.to_string()),
            ]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_resolve_raw_file() {
        let dir = std::env::temp_dir().join("keychain_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.key");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(&[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();

        let backend = FileBackend::new();
        let key = backend.resolve(path.to_str().unwrap()).unwrap();
        assert_eq!(key.material, vec![0xDE, 0xAD, 0xBE, 0xEF]);

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_resolve_hex_file() {
        let dir = std::env::temp_dir().join("keychain_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.hex");
        std::fs::write(&path, "deadbeef01020304").unwrap();

        let backend = FileBackend::new();
        let key = backend.resolve(path.to_str().unwrap()).unwrap();
        assert_eq!(key.material, vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04]);

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_resolve_base64_file() {
        let dir = std::env::temp_dir().join("keychain_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.b64");
        std::fs::write(&path, "AQIDBA==").unwrap();

        let backend = FileBackend::new();
        let key = backend.resolve(path.to_str().unwrap()).unwrap();
        assert_eq!(key.material, vec![1, 2, 3, 4]);

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_missing_file() {
        let backend = FileBackend::new();
        assert!(backend.resolve("/tmp/keychain_definitely_not_here.key").is_err());
    }

    #[test]
    fn test_encoding_override() {
        let dir = std::env::temp_dir().join("keychain_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test_override.txt");
        std::fs::write(&path, "deadbeef").unwrap();

        let backend = FileBackend::new();
        let uri = format!("{}?hex", path.to_str().unwrap());
        let key = backend.resolve(&uri).unwrap();
        assert_eq!(key.material, vec![0xDE, 0xAD, 0xBE, 0xEF]);

        std::fs::remove_file(path).ok();
    }
}
