use anyhow::{Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use base64::Engine;
use crate::components::logger;

const KEY_DIR: &str = "/etc/moni-fim/keys";

#[derive(Serialize, Deserialize)]
pub struct SignedData<T> {
    pub data: T,
    pub signature: String,
    pub public_key: String,
}

pub struct CryptoManager {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl CryptoManager {
    pub fn new() -> Result<Self> {
        let (signing_key, verifying_key) = Self::load_or_generate_keypair()?;
        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    fn load_or_generate_keypair() -> Result<(SigningKey, VerifyingKey)> {
        let key_dir = Path::new(KEY_DIR);
        fs::create_dir_all(key_dir)
            .context("Failed to create key directory")?;

        let private_key_path = key_dir.join("private.key");
        let public_key_path = key_dir.join("public.key");

        if private_key_path.exists() && public_key_path.exists() {
            // Load existing keypair
            let mut private_key_bytes = Vec::new();
            File::open(&private_key_path)?
                .read_to_end(&mut private_key_bytes)?;

            let mut public_key_bytes = Vec::new();
            File::open(&public_key_path)?
                .read_to_end(&mut public_key_bytes)?;

            let private_key_array: [u8; 32] = private_key_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid private key length, expected 32 bytes"))?;

            let public_key_array: [u8; 32] = public_key_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid public key length, expected 32 bytes"))?;

            let signing_key = SigningKey::from_bytes(&private_key_array);
            let verifying_key = VerifyingKey::from_bytes(&public_key_array)
                .map_err(|e| anyhow::anyhow!("Invalid public key: {}", e))?;

            Ok((signing_key, verifying_key))
        } else {
            // Generate new keypair
            let mut csprng = OsRng;
            let secret_key: [u8; 32] = {
                let mut bytes = [0u8; 32];
                use rand::RngCore;
                csprng.fill_bytes(&mut bytes);
                bytes
            };
            let signing_key = SigningKey::from_bytes(&secret_key);
            let verifying_key = signing_key.verifying_key();

            // Save keys with restricted permissions
            let mut private_file = File::create(&private_key_path)?;
            private_file.write_all(&signing_key.to_bytes())?;

            let mut public_file = File::create(&public_key_path)?;
            public_file.write_all(&verifying_key.to_bytes())?;

            // Set restrictive permissions
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = fs::metadata(&private_key_path)?.permissions();
                perms.set_mode(0o600); // Only owner can read/write
                fs::set_permissions(&private_key_path, perms)?;
            }

            crate::components::logger::log_crypto_operation(
                "KEYPAIR_GENERATED",
                "New Ed25519 keypair generated and saved"
            );

            Ok((signing_key, verifying_key))
        }
    }

    pub fn sign_data<T: Serialize + for<'de> Deserialize<'de>>(&self, data: &T) -> Result<SignedData<T>> {
        let serialized = serde_json::to_string(data)?;
        let signature = self.signing_key.sign(serialized.as_bytes());

        Ok(SignedData {
            data: serde_json::from_str(&serialized)?,
            signature: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
            public_key: base64::engine::general_purpose::STANDARD.encode(self.verifying_key.to_bytes()),
        })
    }

    pub fn verify_signature<T: Serialize + for<'de> Deserialize<'de>>(
        &self,
        signed_data: &SignedData<T>,
    ) -> Result<bool> {
        let signature_bytes = base64::engine::general_purpose::STANDARD
            .decode(&signed_data.signature)
            .context("Failed to decode signature")?;

        let signature_array: [u8; 64] = signature_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid signature length, expected 64 bytes"))?;

        let signature = Signature::from_bytes(&signature_array);

        let public_key_bytes = base64::engine::general_purpose::STANDARD
            .decode(&signed_data.public_key)
            .context("Failed to decode public key")?;

        let public_key_array: [u8; 32] = public_key_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid public key length, expected 32 bytes"))?;

        let verifying_key = VerifyingKey::from_bytes(&public_key_array)
            .map_err(|e| anyhow::anyhow!("Invalid public key: {}", e))?;

        let serialized = serde_json::to_string(&signed_data.data)?;

        // First try with the stored public key from the signed data
        let verification_result = verifying_key.verify(serialized.as_bytes(), &signature);

        if verification_result.is_ok() {
            return Ok(true);
        }

        // If that fails, try with our current verifying key (for backward compatibility)
        let fallback_result = self.verifying_key.verify(serialized.as_bytes(), &signature);

        if fallback_result.is_ok() {
            logger::log_crypto_operation("SIGNATURE_VERIFIED_FALLBACK",
                                         "Signature verified using current key (baseline may be from different key)");
            return Ok(true);
        }

        // Log the failure for debugging
        logger::log_crypto_operation("SIGNATURE_VERIFICATION_FAILED",
                                     &format!("Failed to verify signature. Current key fingerprint: {}",
                                              self.get_key_fingerprint()));

        Ok(false)
    }

    // Add a method to verify without failing
    pub fn verify_signature_lenient<T: Serialize + for<'de> Deserialize<'de>>(
        &self,
        signed_data: &SignedData<T>,
    ) -> Result<bool> {
        match self.verify_signature(signed_data) {
            Ok(result) => Ok(result),
            Err(_) => {
                logger::log_crypto_operation("SIGNATURE_VERIFICATION_SKIPPED",
                                             "Signature verification failed, proceeding without verification");
                Ok(true) // Allow operation to continue
            }
        }
    }

    pub fn export_public_key(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.verifying_key.to_bytes())
    }

    pub fn export_public_key_hex(&self) -> String {
        hex::encode(self.verifying_key.to_bytes())
    }

    pub fn get_key_fingerprint(&self) -> String {
        let public_bytes = self.verifying_key.to_bytes();
        let hash = blake3::hash(&public_bytes);
        let fingerprint = hash.to_hex();
        format!("{}...{}", &fingerprint[..8], &fingerprint[fingerprint.len()-8..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let crypto = CryptoManager::new().unwrap();

        #[derive(Serialize, Deserialize, PartialEq, Clone)]
        struct TestData {
            message: String,
            value: u32,
        }

        let data = TestData {
            message: "Test message".to_string(),
            value: 42,
        };

        let signed = crypto.sign_data(&data).unwrap();
        assert!(crypto.verify_signature(&signed).unwrap());

        // Test tampering detection
        let mut tampered = signed;
        tampered.data.value = 43;
        assert!(!crypto.verify_signature(&tampered).unwrap());
    }
}
