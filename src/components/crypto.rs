// Ed25519 cryptographic signing for MoniFim baselines.
// Simple API: sign raw bytes, verify raw bytes.

use anyhow::{Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub struct CryptoManager {
    key_dir: PathBuf,
}

impl CryptoManager {
    /// Create a new CryptoManager pointing at a key directory.
    /// Does NOT load or generate keys immediately.
    pub fn new(key_dir: &Path) -> Self {
        Self { key_dir: key_dir.to_path_buf() }
    }

    /// Generate a new Ed25519 keypair and write to disk.
    pub fn generate_keys(&self) -> Result<()> {
        fs::create_dir_all(&self.key_dir).context("Failed to create key directory")?;

        let private_key_path = self.key_dir.join("private.key");
        let public_key_path = self.key_dir.join("public.key");

        let secret: [u8; 32] = {
            let mut bytes = [0u8; 32];
            use rand::RngCore;
            OsRng.fill_bytes(&mut bytes);
            bytes
        };
        let signing_key = SigningKey::from_bytes(&secret);
        let verifying_key = signing_key.verifying_key();

        // Write keys with restricted permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // Remove existing files first if overwriting
            let _ = fs::remove_file(&private_key_path);
            let _ = fs::remove_file(&public_key_path);

            let mut priv_file = fs::OpenOptions::new()
                .write(true).create_new(true).mode(0o600)
                .open(&private_key_path)?;
            priv_file.write_all(&signing_key.to_bytes())?;
            priv_file.sync_all()?;

            let mut pub_file = fs::OpenOptions::new()
                .write(true).create_new(true).mode(0o644)
                .open(&public_key_path)?;
            pub_file.write_all(&verifying_key.to_bytes())?;
            pub_file.sync_all()?;
        }
        #[cfg(not(unix))]
        {
            fs::write(&private_key_path, signing_key.to_bytes())?;
            fs::write(&public_key_path, verifying_key.to_bytes())?;
        }

        log::info!("Generated new Ed25519 keypair in {:?}", self.key_dir);
        Ok(())
    }

    /// Load the signing key from disk.
    fn load_signing_key(&self) -> Result<SigningKey> {
        let path = self.key_dir.join("private.key");
        let mut bytes = Vec::new();
        File::open(&path)
            .with_context(|| format!("Failed to open private key: {}", path.display()))?
            .read_to_end(&mut bytes)?;
        let arr: [u8; 32] = bytes.try_into()
            .map_err(|_| anyhow::anyhow!("Invalid private key length"))?;
        Ok(SigningKey::from_bytes(&arr))
    }

    /// Load the verifying key from disk.
    fn load_verifying_key(&self) -> Result<VerifyingKey> {
        let path = self.key_dir.join("public.key");
        let mut bytes = Vec::new();
        File::open(&path)
            .with_context(|| format!("Failed to open public key: {}", path.display()))?
            .read_to_end(&mut bytes)?;
        let arr: [u8; 32] = bytes.try_into()
            .map_err(|_| anyhow::anyhow!("Invalid public key length"))?;
        VerifyingKey::from_bytes(&arr)
            .map_err(|e| anyhow::anyhow!("Invalid public key: {}", e))
    }

    /// Sign raw bytes. Returns the 64-byte Ed25519 signature.
    pub fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        let signing_key = self.load_signing_key()?;
        let sig = signing_key.sign(data);
        Ok(sig.to_bytes().to_vec())
    }

    /// Verify a signature on raw bytes.
    pub fn verify_signature(&self, data: &[u8], signature: &[u8]) -> Result<()> {
        let verifying_key = self.load_verifying_key()?;
        let sig_arr: [u8; 64] = signature.try_into()
            .map_err(|_| anyhow::anyhow!("Invalid signature length (expected 64 bytes)"))?;
        let sig = Signature::from_bytes(&sig_arr);
        verifying_key.verify(data, &sig)
            .map_err(|_| anyhow::anyhow!("Signature verification failed — data may be tampered"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn setup() -> (TempDir, CryptoManager) {
        let dir = TempDir::new().unwrap();
        let crypto = CryptoManager::new(dir.path());
        crypto.generate_keys().unwrap();
        (dir, crypto)
    }

    #[test]
    fn test_sign_and_verify() {
        let (_dir, crypto) = setup();
        let data = b"hello monifim";
        let sig = crypto.sign_data(data).unwrap();
        assert!(crypto.verify_signature(data, &sig).is_ok());
    }

    #[test]
    fn test_tamper_detection() {
        let (_dir, crypto) = setup();
        let data = b"original data";
        let sig = crypto.sign_data(data).unwrap();
        let tampered = b"tampered data";
        assert!(crypto.verify_signature(tampered, &sig).is_err());
    }

    #[test]
    fn test_invalid_signature() {
        let (_dir, crypto) = setup();
        let data = b"some data";
        let bad_sig = vec![0u8; 64];
        assert!(crypto.verify_signature(data, &bad_sig).is_err());
    }

    #[test]
    fn test_bad_sig_length() {
        let (_dir, crypto) = setup();
        let data = b"data";
        let bad_sig = vec![0u8; 32]; // wrong length
        assert!(crypto.verify_signature(data, &bad_sig).is_err());
    }
}
