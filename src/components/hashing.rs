// Hashing engine for MoniFim.
// Supports BLAKE3 (default), SHA-256, and MD5 (deprecated).

use crate::components::config::HashAlgorithm;
use anyhow::{Context, Result};
use std::fs::File;
use std::io::Read;
use std::path::Path;

const BUFFER_SIZE: usize = 65536;

/// Hash a file with the given algorithm.
pub fn hash_file(path: &Path, algorithm: HashAlgorithm) -> Result<String> {
    let mut file = File::open(path)
        .with_context(|| format!("Cannot open file for hashing: {:?}", path))?;
    let mut buffer = [0u8; BUFFER_SIZE];

    match algorithm {
        HashAlgorithm::Blake3 => {
            let mut hasher = blake3::Hasher::new();
            loop {
                let bytes_read = file.read(&mut buffer)?;
                if bytes_read == 0 { break; }
                hasher.update(&buffer[..bytes_read]);
            }
            Ok(hasher.finalize().to_hex().to_string())
        }
        HashAlgorithm::Sha256 => {
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            loop {
                let bytes_read = file.read(&mut buffer)?;
                if bytes_read == 0 { break; }
                hasher.update(&buffer[..bytes_read]);
            }
            Ok(format!("{:x}", hasher.finalize()))
        }
        HashAlgorithm::Md5 => {
            use md5::{Md5, Digest};
            let mut hasher = Md5::new();
            loop {
                let bytes_read = file.read(&mut buffer)?;
                if bytes_read == 0 { break; }
                hasher.update(&buffer[..bytes_read]);
            }
            Ok(format!("{:x}", hasher.finalize()))
        }
    }
}

/// Quick hash of in-memory data.
pub fn quick_hash(data: &[u8], algorithm: HashAlgorithm) -> String {
    match algorithm {
        HashAlgorithm::Blake3 => blake3::hash(data).to_hex().to_string(),
        HashAlgorithm::Sha256 => {
            use sha2::{Sha256, Digest};
            format!("{:x}", Sha256::digest(data))
        }
        HashAlgorithm::Md5 => {
            use md5::{Md5, Digest};
            format!("{:x}", Md5::digest(data))
        }
    }
}
