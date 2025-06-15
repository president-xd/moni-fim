use crate::components::config::HashAlgorithm;
use anyhow::{Context, Result};
use blake3::Hasher as Blake3Hasher;
use md5::{Digest as Md5Digest, Md5};
use sha2::{Digest as Sha2Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const BUFFER_SIZE: usize = 1024 * 1024; // 1MB buffer for better performance

pub struct HashProgress {
    pub bytes_processed: Arc<AtomicU64>,
    pub total_bytes: u64,
}

impl HashProgress {
    pub fn new(total_bytes: u64) -> Self {
        Self {
            bytes_processed: Arc::new(AtomicU64::new(0)),
            total_bytes,
        }
    }

    pub fn update(&self, bytes: u64) {
        self.bytes_processed.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn percentage(&self) -> f64 {
        if self.total_bytes == 0 {
            100.0
        } else {
            let processed = self.bytes_processed.load(Ordering::Relaxed);
            (processed as f64 / self.total_bytes as f64) * 100.0
        }
    }
}

pub fn hash_file(path: &Path, algorithm: &HashAlgorithm) -> Result<String> {
    let file = File::open(path)
        .with_context(|| format!("Failed to open file: {:?}", path))?;

    let metadata = file.metadata()
        .with_context(|| format!("Failed to get metadata for: {:?}", path))?;

    let file_size = metadata.len();
    let mut reader = BufReader::with_capacity(BUFFER_SIZE, file);
    let mut buffer = vec![0; BUFFER_SIZE];

    match algorithm {
        HashAlgorithm::Blake3 => {
            let mut hasher = Blake3Hasher::new();
            loop {
                let n = reader.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buffer[..n]);
            }
            Ok(hasher.finalize().to_hex().to_string())
        }
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            loop {
                let n = reader.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                Sha2Digest::update(&mut hasher, &buffer[..n]);
            }
            Ok(format!("{:x}", hasher.finalize()))
        }
        HashAlgorithm::Md5 => {
            let mut hasher = Md5::new();
            loop {
                let n = reader.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                Md5Digest::update(&mut hasher, &buffer[..n]);
            }
            Ok(format!("{:x}", hasher.finalize()))
        }
    }
}

pub fn hash_file_with_progress(
    path: &Path,
    algorithm: &HashAlgorithm,
    progress: Option<&HashProgress>,
) -> Result<String> {
    let file = File::open(path)
        .with_context(|| format!("Failed to open file: {:?}", path))?;

    let mut reader = BufReader::with_capacity(BUFFER_SIZE, file);
    let mut buffer = vec![0; BUFFER_SIZE];

    match algorithm {
        HashAlgorithm::Blake3 => {
            let mut hasher = Blake3Hasher::new();
            let mut total_read = 0u64;

            loop {
                let n = reader.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buffer[..n]);
                total_read += n as u64;

                if let Some(p) = progress {
                    p.update(n as u64);
                }
            }

            Ok(hasher.finalize().to_hex().to_string())
        }
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            let mut total_read = 0u64;

            loop {
                let n = reader.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                Sha2Digest::update(&mut hasher, &buffer[..n]);
                total_read += n as u64;

                if let Some(p) = progress {
                    p.update(n as u64);
                }
            }

            Ok(format!("{:x}", hasher.finalize()))
        }
        HashAlgorithm::Md5 => {
            let mut hasher = Md5::new();
            let mut total_read = 0u64;

            loop {
                let n = reader.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                Md5Digest::update(&mut hasher, &buffer[..n]);
                total_read += n as u64;

                if let Some(p) = progress {
                    p.update(n as u64);
                }
            }

            Ok(format!("{:x}", hasher.finalize()))
        }
    }
}

pub fn quick_hash(data: &[u8], algorithm: &HashAlgorithm) -> String {
    match algorithm {
        HashAlgorithm::Blake3 => {
            blake3::hash(data).to_hex().to_string()
        }
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            Sha2Digest::update(&mut hasher, data);
            format!("{:x}", hasher.finalize())
        }
        HashAlgorithm::Md5 => {
            let mut hasher = Md5::new();
            Md5Digest::update(&mut hasher, data);
            format!("{:x}", hasher.finalize())
        }
    }
}

pub fn verify_hash(path: &Path, expected_hash: &str, algorithm: &HashAlgorithm) -> Result<bool> {
    let actual_hash = hash_file(path, algorithm)?;
    Ok(actual_hash == expected_hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::NamedTempFile;

    #[test]
    fn test_hash_algorithms() {
        let data = b"Hello, World!";
        let mut temp_file = NamedTempFile::new().unwrap();
        fs::write(temp_file.path(), data).unwrap();

        // Test BLAKE3
        let blake3_hash = hash_file(temp_file.path(), &HashAlgorithm::Blake3).unwrap();
        assert!(!blake3_hash.is_empty());

        // Test SHA256
        let sha256_hash = hash_file(temp_file.path(), &HashAlgorithm::Sha256).unwrap();
        assert_eq!(sha256_hash.len(), 64); // SHA256 produces 64 hex characters

        // Test MD5
        let md5_hash = hash_file(temp_file.path(), &HashAlgorithm::Md5).unwrap();
        assert_eq!(md5_hash.len(), 32); // MD5 produces 32 hex characters
    }

    #[test]
    fn test_quick_hash() {
        let data = b"Test data";

        let blake3 = quick_hash(data, &HashAlgorithm::Blake3);
        let sha256 = quick_hash(data, &HashAlgorithm::Sha256);
        let md5 = quick_hash(data, &HashAlgorithm::Md5);

        assert!(!blake3.is_empty());
        assert_eq!(sha256.len(), 64);
        assert_eq!(md5.len(), 32);
    }
}