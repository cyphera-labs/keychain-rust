# keychain

Universal key resolution. One API, every key store.

```rust
use keychain::KeyStore;
use keychain_env::EnvBackend;
use keychain_file::FileBackend;

let store = KeyStore::new()
    .register(Box::new(EnvBackend::new()))
    .register(Box::new(FileBackend::new()));

// Resolve from environment variable
let key = store.resolve("env://MY_SECRET_KEY")?;

// Resolve from file (auto-detects hex/base64 from extension)
let key = store.resolve("file://./keys/production.hex")?;

// Resolve from AWS KMS
let key = store.resolve("aws-kms://arn:aws:kms:us-east-1:123:key/abc")?;

// Resolve from HashiCorp Vault
let key = store.resolve("vault://transit/keys/my-key")?;
```

## Backends

| Crate | Scheme | Status |
|-------|--------|--------|
| `keychain-env` | `env://` | Working |
| `keychain-file` | `file://` | Working |
| `keychain-aws` | `aws-kms://` | Scaffolded |
| `keychain-gcp` | `gcp-kms://` | Scaffolded |
| `keychain-azure` | `azure-kv://` | Scaffolded |
| `keychain-vault` | `vault://` | Scaffolded |

## Encoding

Keys can be stored in different formats. Keychain auto-detects or accepts hints:

- Raw bytes (default)
- Hex: `env://MY_KEY?hex` or `.hex` file extension
- Base64: `env://MY_KEY?base64` or `.b64` file extension

## Custom Backends

```rust
use keychain::{KeyBackend, KeychainError, ResolvedKey};

struct MyBackend;

impl KeyBackend for MyBackend {
    fn scheme(&self) -> &str { "my-store" }

    fn resolve(&self, path: &str) -> Result<ResolvedKey, KeychainError> {
        // fetch key material from your store
        todo!()
    }
}

let store = KeyStore::new()
    .register(Box::new(MyBackend));

store.resolve("my-store://key-name")?;
```

## License

Apache 2.0
