use keychain::{KeyBackend, KeychainError, ResolvedKey};
use std::collections::HashMap;

/// AWS KMS backend for keychain.
///
/// URI format: `aws-kms://key-arn-or-alias`
///
/// Uses AWS KMS Decrypt to unwrap data encryption keys.
/// Authenticates via standard AWS credential chain
/// (env vars, IAM role, instance profile, etc.)
pub struct AwsKmsBackend {
    _region: String,
}

impl AwsKmsBackend {
    pub fn new(region: &str) -> Self {
        Self {
            _region: region.to_string(),
        }
    }
}

impl KeyBackend for AwsKmsBackend {
    fn scheme(&self) -> &str {
        "aws-kms"
    }

    fn resolve(&self, path: &str) -> Result<ResolvedKey, KeychainError> {
        // TODO: call aws-sdk-kms to decrypt/generate data key
        // let client = aws_sdk_kms::Client::new(&config);
        // let resp = client.decrypt().key_id(path).ciphertext_blob(wrapped_key).send().await?;
        let _ = path;
        Err(KeychainError::Backend("AWS KMS backend not yet implemented — add aws-sdk-kms dependency".into()))
    }
}
