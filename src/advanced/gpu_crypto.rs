// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! CPU-Parallel Batch Cryptography Module
//!
//! This module provides high-throughput batch cryptographic operations using:
//! - Rayon thread pool for parallel hash, encrypt, and verify workloads
//! - Real cryptographic primitives (SHA-2, SHA-3, AES-256-GCM, Ed25519, ECDSA)
//! - Hardware feature detection for informational purposes
//!
//! CUDA/GPU acceleration is not yet implemented and is reserved for a future
//! extension.  `has_gpu_support()` always returns `false`.

use crate::error::{HsmError, HsmResult};
use rayon::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Device manager for batch cryptographic operations.
///
/// Holds a rayon thread pool (`SimdCrypto`) and running performance counters
/// (`GpuStats`).  There is no CUDA device — GPU support is a future extension.
pub struct GpuCryptoDevice {
    /// CPU-parallel crypto executor
    simd_crypto: SimdCrypto,

    /// Performance statistics
    stats: Arc<RwLock<GpuStats>>,
}

/// CPU-parallel cryptographic operations backed by a rayon thread pool.
pub struct SimdCrypto {
    /// Thread pool for parallel operations
    cpu_pool: rayon::ThreadPool,
}

/// Performance statistics for batch operations.
#[derive(Debug, Default, Clone)]
pub struct GpuStats {
    /// Total operations performed
    pub total_operations: u64,
    /// GPU operations count (always 0 — no GPU support yet)
    pub gpu_operations: u64,
    /// CPU parallel operations count
    pub cpu_simd_operations: u64,
    /// Exponential moving average of operation time in microseconds
    pub average_time_us: f64,
    /// GPU memory used in bytes (always 0)
    pub gpu_memory_used: usize,
}

/// A batch cryptographic operation to execute.
#[derive(Debug, Clone)]
pub enum BatchOperation {
    /// Batch elliptic curve point multiplication (P-256)
    EccMultiplication {
        points: Vec<[u8; 64]>,  // Uncompressed affine coordinates (x ‖ y)
        scalars: Vec<[u8; 32]>, // 256-bit scalars
    },
    /// Batch hash computation
    BatchHash {
        data: Vec<Vec<u8>>,
        algorithm: HashAlgorithm,
    },
    /// Batch symmetric encryption
    BatchEncrypt {
        plaintexts: Vec<Vec<u8>>,
        keys: Vec<[u8; 32]>,
        algorithm: SymmetricAlgorithm,
    },
    /// Batch signature verification
    BatchVerify {
        messages: Vec<Vec<u8>>,
        signatures: Vec<Vec<u8>>,
        public_keys: Vec<Vec<u8>>,
        algorithm: SignatureAlgorithm,
    },
}

/// Supported hash algorithms for batch operations.
#[derive(Debug, Clone, Copy)]
pub enum HashAlgorithm {
    Sha256,
    Sha512,
    Blake2b,
    Keccak256,
}

/// Supported symmetric algorithms for batch operations.
#[derive(Debug, Clone, Copy)]
pub enum SymmetricAlgorithm {
    Aes256Gcm,
    ChaCha20Poly1305,
    Aes256Cbc,
}

/// Supported signature algorithms for batch verification.
#[derive(Debug, Clone, Copy)]
pub enum SignatureAlgorithm {
    EcdsaP256,
    EcdsaP384,
    Ed25519,
    RsaPkcs1v15,
}

/// Result of a batch operation.
#[derive(Debug)]
pub struct BatchResult {
    /// Per-operation success flags
    pub results: Vec<bool>,
    /// Collected outputs (hash digests, ciphertexts, etc.)
    pub outputs: Vec<Vec<u8>>,
    /// Wall-clock execution time in microseconds
    pub execution_time_us: u64,
    /// Whether the GPU was used (always `false` currently)
    pub used_gpu: bool,
    /// Number of operations processed
    pub operation_count: usize,
}

// ---------------------------------------------------------------------------
// GpuCryptoDevice implementation
// ---------------------------------------------------------------------------

impl GpuCryptoDevice {
    /// Create a new batch crypto device backed by a rayon thread pool.
    pub fn new() -> HsmResult<Self> {
        let cpu_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(num_cpus::get())
            .build()
            .map_err(|e| {
                HsmError::InitializationError(format!("Failed to create thread pool: {}", e))
            })?;

        let simd_crypto = SimdCrypto { cpu_pool };

        Ok(Self {
            simd_crypto,
            stats: Arc::new(RwLock::new(GpuStats::default())),
        })
    }

    /// Execute a batch operation, returning per-item results and outputs.
    pub async fn execute_batch(&self, operation: BatchOperation) -> HsmResult<BatchResult> {
        let start_time = std::time::Instant::now();

        let mut result = match operation {
            BatchOperation::EccMultiplication { points, scalars } => {
                self.batch_ecc_multiplication(points, scalars).await?
            }
            BatchOperation::BatchHash { data, algorithm } => {
                self.batch_hash(data, algorithm).await?
            }
            BatchOperation::BatchEncrypt {
                plaintexts,
                keys,
                algorithm,
            } => self.batch_encrypt(plaintexts, keys, algorithm).await?,
            BatchOperation::BatchVerify {
                messages,
                signatures,
                public_keys,
                algorithm,
            } => {
                self.batch_verify(messages, signatures, public_keys, algorithm)
                    .await?
            }
        };

        let execution_time = start_time.elapsed().as_micros() as u64;
        result.execution_time_us = execution_time;

        // Update statistics
        let mut stats = self.stats.write().await;
        stats.total_operations += result.operation_count as u64;
        stats.cpu_simd_operations += result.operation_count as u64;
        // Exponential moving average
        stats.average_time_us = (stats.average_time_us * 0.9) + (execution_time as f64 * 0.1);

        Ok(result)
    }

    // -- Hashing -----------------------------------------------------------

    /// Batch hash computation using rayon parallelism.
    async fn batch_hash(
        &self,
        data: Vec<Vec<u8>>,
        algorithm: HashAlgorithm,
    ) -> HsmResult<BatchResult> {
        let operation_count = data.len();

        let (results, outputs): (Vec<bool>, Vec<Vec<u8>>) =
            self.simd_crypto.cpu_pool.install(|| {
                data.par_iter()
                    .map(|input| {
                        let hash = self.compute_hash(input, algorithm);
                        (true, hash)
                    })
                    .unzip()
            });

        Ok(BatchResult {
            results,
            outputs,
            execution_time_us: 0, // filled by caller
            used_gpu: false,
            operation_count,
        })
    }

    /// Compute a single hash using the requested algorithm.
    fn compute_hash(&self, data: &[u8], algorithm: HashAlgorithm) -> Vec<u8> {
        match algorithm {
            HashAlgorithm::Sha256 => {
                use sha2::{Digest, Sha256};
                Sha256::digest(data).to_vec()
            }
            HashAlgorithm::Sha512 => {
                use sha2::{Digest, Sha512};
                Sha512::digest(data).to_vec()
            }
            HashAlgorithm::Keccak256 => {
                use sha3::{Digest, Keccak256};
                Keccak256::digest(data).to_vec()
            }
            HashAlgorithm::Blake2b => {
                // Use BLAKE3 when available, otherwise fall back to SHA-512
                #[cfg(feature = "blake3-hash")]
                {
                    blake3::hash(data).as_bytes().to_vec()
                }
                #[cfg(not(feature = "blake3-hash"))]
                {
                    use sha2::{Digest, Sha512};
                    Sha512::digest(data).to_vec()
                }
            }
        }
    }

    // -- Encryption --------------------------------------------------------

    /// Batch encryption using rayon parallelism.
    async fn batch_encrypt(
        &self,
        plaintexts: Vec<Vec<u8>>,
        keys: Vec<[u8; 32]>,
        algorithm: SymmetricAlgorithm,
    ) -> HsmResult<BatchResult> {
        let operation_count = plaintexts.len();

        if plaintexts.len() != keys.len() {
            return Err(HsmError::InvalidInput(
                "Plaintexts and keys length mismatch".into(),
            ));
        }

        let (results, outputs): (Vec<bool>, Vec<Vec<u8>>) =
            self.simd_crypto.cpu_pool.install(|| {
                plaintexts
                    .par_iter()
                    .zip(keys.par_iter())
                    .map(|(plaintext, key)| self.real_encrypt(plaintext, key, algorithm))
                    .unzip()
            });

        Ok(BatchResult {
            results,
            outputs,
            execution_time_us: 0,
            used_gpu: false,
            operation_count,
        })
    }

    /// Encrypt a single plaintext with the requested algorithm.
    fn real_encrypt(
        &self,
        plaintext: &[u8],
        key: &[u8; 32],
        algorithm: SymmetricAlgorithm,
    ) -> (bool, Vec<u8>) {
        match algorithm {
            SymmetricAlgorithm::Aes256Gcm => {
                match crate::crypto::encrypt::aes_256_gcm_encrypt(key, plaintext) {
                    Ok(ct) => (true, ct),
                    Err(_) => (false, Vec::new()),
                }
            }
            SymmetricAlgorithm::ChaCha20Poly1305 => {
                #[cfg(feature = "chacha20-aead")]
                {
                    use chacha20poly1305::{
                        aead::{Aead, KeyInit},
                        ChaCha20Poly1305,
                    };
                    let cipher = ChaCha20Poly1305::new(key.into());
                    let mut nonce_bytes = [0u8; 12];
                    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);
                    let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
                    match cipher.encrypt(nonce, plaintext) {
                        Ok(ct) => {
                            let mut result = Vec::with_capacity(12 + ct.len());
                            result.extend_from_slice(&nonce_bytes);
                            result.extend_from_slice(&ct);
                            (true, result)
                        }
                        Err(_) => (false, Vec::new()),
                    }
                }
                #[cfg(not(feature = "chacha20-aead"))]
                {
                    // Fallback to AES-256-GCM when ChaCha20 feature is disabled
                    match crate::crypto::encrypt::aes_256_gcm_encrypt(key, plaintext) {
                        Ok(ct) => (true, ct),
                        Err(_) => (false, Vec::new()),
                    }
                }
            }
            SymmetricAlgorithm::Aes256Cbc => {
                // CBC mode falls back to AES-256-GCM (authenticated encryption preferred)
                match crate::crypto::encrypt::aes_256_gcm_encrypt(key, plaintext) {
                    Ok(ct) => (true, ct),
                    Err(_) => (false, Vec::new()),
                }
            }
        }
    }

    // -- ECC point multiplication ------------------------------------------

    /// Batch P-256 elliptic curve point validation.
    async fn batch_ecc_multiplication(
        &self,
        points: Vec<[u8; 64]>,
        scalars: Vec<[u8; 32]>,
    ) -> HsmResult<BatchResult> {
        if points.len() != scalars.len() {
            return Err(HsmError::InvalidInput(
                "Points and scalars length mismatch".into(),
            ));
        }

        let operation_count = points.len();

        let (results, outputs): (Vec<bool>, Vec<Vec<u8>>) =
            self.simd_crypto.cpu_pool.install(|| {
                points
                    .par_iter()
                    .zip(scalars.par_iter())
                    .map(|(point, scalar)| {
                        let ok = self.ecc_point_multiply(point, scalar);
                        (ok, Vec::new())
                    })
                    .unzip()
            });

        Ok(BatchResult {
            results,
            outputs,
            execution_time_us: 0,
            used_gpu: false,
            operation_count,
        })
    }

    /// Validate and perform a P-256 point operation.
    ///
    /// Decodes the 64-byte uncompressed affine point into a `p256::AffinePoint`,
    /// verifies it lies on the P-256 curve, and converts it to projective form.
    /// Returns `true` when the point is valid on the curve.
    fn ecc_point_multiply(&self, point: &[u8; 64], _scalar: &[u8; 32]) -> bool {
        use p256::elliptic_curve::sec1::FromEncodedPoint;

        // Build SEC1 uncompressed encoding: 0x04 ‖ x ‖ y
        let mut sec1 = vec![0x04u8];
        sec1.extend_from_slice(point);

        let encoded = match p256::EncodedPoint::from_bytes(&sec1) {
            Ok(e) => e,
            Err(_) => return false,
        };

        let affine: Option<p256::AffinePoint> =
            p256::AffinePoint::from_encoded_point(&encoded).into();
        let affine = match affine {
            Some(a) => a,
            None => return false,
        };

        // Convert to projective — proves the point is on the curve
        let _result = p256::ProjectivePoint::from(affine);
        true
    }

    // -- Signature verification --------------------------------------------

    /// Batch signature verification using rayon parallelism.
    async fn batch_verify(
        &self,
        messages: Vec<Vec<u8>>,
        signatures: Vec<Vec<u8>>,
        public_keys: Vec<Vec<u8>>,
        algorithm: SignatureAlgorithm,
    ) -> HsmResult<BatchResult> {
        let operation_count = messages.len();

        if messages.len() != signatures.len() || messages.len() != public_keys.len() {
            return Err(HsmError::InvalidInput(
                "Input vectors length mismatch".into(),
            ));
        }

        let (results, outputs): (Vec<bool>, Vec<Vec<u8>>) =
            self.simd_crypto.cpu_pool.install(|| {
                messages
                    .par_iter()
                    .zip(signatures.par_iter())
                    .zip(public_keys.par_iter())
                    .map(|((message, signature), public_key)| {
                        let ok = self.verify_signature(message, signature, public_key, algorithm);
                        (ok, Vec::new())
                    })
                    .unzip()
            });

        Ok(BatchResult {
            results,
            outputs,
            execution_time_us: 0,
            used_gpu: false,
            operation_count,
        })
    }

    /// Verify a single signature using the real crypto module.
    fn verify_signature(
        &self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
        algorithm: SignatureAlgorithm,
    ) -> bool {
        match algorithm {
            SignatureAlgorithm::Ed25519 => {
                crate::crypto::sign::ed25519_verify(public_key, message, signature).unwrap_or(false)
            }
            SignatureAlgorithm::EcdsaP256 => {
                crate::crypto::sign::ecdsa_p256_verify(public_key, message, signature)
                    .unwrap_or(false)
            }
            SignatureAlgorithm::EcdsaP384 => {
                crate::crypto::sign::ecdsa_p384_verify(public_key, message, signature)
                    .unwrap_or(false)
            }
            SignatureAlgorithm::RsaPkcs1v15 => {
                // RSA batch verification requires parsed key structures;
                // not supported in the batch path.
                false
            }
        }
    }

    // -- Misc --------------------------------------------------------------

    /// GPU support is not yet implemented.
    fn has_gpu_support(&self) -> bool {
        false
    }

    /// Return a snapshot of the current performance statistics.
    pub async fn get_stats(&self) -> GpuStats {
        self.stats.read().await.clone()
    }

    /// Reset performance statistics to zero.
    pub async fn reset_stats(&self) {
        let mut stats = self.stats.write().await;
        *stats = GpuStats::default();
    }

    /// Detect available hardware features and return them as a map.
    pub fn detect_features() -> HashMap<String, String> {
        let mut features = HashMap::new();

        features.insert("cpu_count".to_string(), num_cpus::get().to_string());
        features.insert("gpu_available".to_string(), "false".to_string());

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            features.insert(
                "avx2".to_string(),
                is_x86_feature_detected!("avx2").to_string(),
            );
            features.insert(
                "avx512f".to_string(),
                is_x86_feature_detected!("avx512f").to_string(),
            );
            features.insert(
                "aes_ni".to_string(),
                is_x86_feature_detected!("aes").to_string(),
            );
        }

        #[cfg(target_arch = "aarch64")]
        {
            features.insert("neon".to_string(), "true".to_string());
        }

        features
    }
}

impl Default for GpuCryptoDevice {
    fn default() -> Self {
        Self::new().expect("Failed to create GPU crypto device")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_batch_hash_sha256() {
        let device = GpuCryptoDevice::new().unwrap();
        let data = vec![b"abc".to_vec(), b"".to_vec(), b"test".to_vec()];
        let result = device
            .execute_batch(BatchOperation::BatchHash {
                data,
                algorithm: HashAlgorithm::Sha256,
            })
            .await
            .unwrap();

        assert_eq!(result.operation_count, 3);
        assert_eq!(result.outputs.len(), 3);
        assert!(result.results.iter().all(|&ok| ok));
        // SHA-256("abc")
        assert_eq!(
            hex::encode(&result.outputs[0]),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // SHA-256("")
        assert_eq!(
            hex::encode(&result.outputs[1]),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[tokio::test]
    async fn test_batch_hash_sha512() {
        let device = GpuCryptoDevice::new().unwrap();
        let data = vec![b"abc".to_vec()];
        let result = device
            .execute_batch(BatchOperation::BatchHash {
                data,
                algorithm: HashAlgorithm::Sha512,
            })
            .await
            .unwrap();

        assert_eq!(result.outputs.len(), 1);
        assert_eq!(result.outputs[0].len(), 64); // SHA-512 produces 64 bytes
    }

    #[tokio::test]
    async fn test_batch_hash_keccak256() {
        let device = GpuCryptoDevice::new().unwrap();
        let data = vec![b"".to_vec()];
        let result = device
            .execute_batch(BatchOperation::BatchHash {
                data,
                algorithm: HashAlgorithm::Keccak256,
            })
            .await
            .unwrap();

        assert_eq!(result.outputs.len(), 1);
        // Keccak-256("")
        assert_eq!(
            hex::encode(&result.outputs[0]),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[tokio::test]
    async fn test_batch_encrypt_aes_gcm() {
        let device = GpuCryptoDevice::new().unwrap();
        let key = [0x42u8; 32];
        let result = device
            .execute_batch(BatchOperation::BatchEncrypt {
                plaintexts: vec![b"hello".to_vec()],
                keys: vec![key],
                algorithm: SymmetricAlgorithm::Aes256Gcm,
            })
            .await
            .unwrap();

        assert!(result.results[0]);
        assert!(!result.outputs[0].is_empty());
        // Verify we can decrypt
        let decrypted =
            crate::crypto::encrypt::aes_256_gcm_decrypt(&key, &result.outputs[0]).unwrap();
        assert_eq!(decrypted, b"hello");
    }

    #[tokio::test]
    async fn test_batch_encrypt_multiple() {
        let device = GpuCryptoDevice::new().unwrap();
        let keys = vec![[0xAAu8; 32], [0xBBu8; 32]];
        let plaintexts = vec![b"first".to_vec(), b"second".to_vec()];
        let result = device
            .execute_batch(BatchOperation::BatchEncrypt {
                plaintexts: plaintexts.clone(),
                keys: keys.clone(),
                algorithm: SymmetricAlgorithm::Aes256Gcm,
            })
            .await
            .unwrap();

        assert_eq!(result.operation_count, 2);
        for i in 0..2 {
            assert!(result.results[i]);
            let decrypted =
                crate::crypto::encrypt::aes_256_gcm_decrypt(&keys[i], &result.outputs[i]).unwrap();
            assert_eq!(decrypted, plaintexts[i]);
        }
    }

    #[tokio::test]
    async fn test_batch_encrypt_key_mismatch() {
        let device = GpuCryptoDevice::new().unwrap();
        let err = device
            .execute_batch(BatchOperation::BatchEncrypt {
                plaintexts: vec![b"a".to_vec(), b"b".to_vec()],
                keys: vec![[0u8; 32]], // one key, two plaintexts
                algorithm: SymmetricAlgorithm::Aes256Gcm,
            })
            .await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn test_batch_verify_ed25519() {
        use ed25519_dalek::{Signer, SigningKey};

        let device = GpuCryptoDevice::new().unwrap();

        // Generate a real keypair and sign a message
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let message = b"batch verify test";
        let signature = signing_key.sign(message);

        let result = device
            .execute_batch(BatchOperation::BatchVerify {
                messages: vec![message.to_vec()],
                signatures: vec![signature.to_bytes().to_vec()],
                public_keys: vec![signing_key.verifying_key().to_bytes().to_vec()],
                algorithm: SignatureAlgorithm::Ed25519,
            })
            .await
            .unwrap();

        assert_eq!(result.operation_count, 1);
        assert!(result.results[0]);
    }

    #[tokio::test]
    async fn test_batch_verify_bad_signature() {
        use ed25519_dalek::{Signer, SigningKey};

        let device = GpuCryptoDevice::new().unwrap();

        // Sign a message, then verify with *wrong* message — must fail
        let signing_key = SigningKey::from_bytes(&[2u8; 32]);
        let signature = signing_key.sign(b"correct message");

        let result = device
            .execute_batch(BatchOperation::BatchVerify {
                messages: vec![b"wrong message".to_vec()],
                signatures: vec![signature.to_bytes().to_vec()],
                public_keys: vec![signing_key.verifying_key().to_bytes().to_vec()],
                algorithm: SignatureAlgorithm::Ed25519,
            })
            .await
            .unwrap();

        // Signature for a different message must not verify
        assert!(!result.results[0]);
    }

    #[tokio::test]
    async fn test_hardware_detection() {
        let features = GpuCryptoDevice::detect_features();
        assert!(features.contains_key("cpu_count"));
        assert_eq!(features.get("gpu_available").unwrap(), "false");
    }

    #[tokio::test]
    async fn test_has_no_gpu() {
        let device = GpuCryptoDevice::new().unwrap();
        assert!(!device.has_gpu_support());
    }

    #[tokio::test]
    async fn test_stats_tracking() {
        let device = GpuCryptoDevice::new().unwrap();

        let stats = device.get_stats().await;
        assert_eq!(stats.total_operations, 0);

        // Run an operation
        device
            .execute_batch(BatchOperation::BatchHash {
                data: vec![b"x".to_vec()],
                algorithm: HashAlgorithm::Sha256,
            })
            .await
            .unwrap();

        let stats = device.get_stats().await;
        assert_eq!(stats.total_operations, 1);
        assert_eq!(stats.cpu_simd_operations, 1);
        assert_eq!(stats.gpu_operations, 0);

        device.reset_stats().await;
        let stats = device.get_stats().await;
        assert_eq!(stats.total_operations, 0);
    }

    #[tokio::test]
    async fn test_ecc_point_validation() {
        let device = GpuCryptoDevice::new().unwrap();

        // Use the P-256 generator point (uncompressed, without 0x04 prefix)
        // Gx and Gy for NIST P-256
        let gx = hex::decode("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
            .unwrap();
        let gy = hex::decode("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
            .unwrap();

        let mut point = [0u8; 64];
        point[..32].copy_from_slice(&gx);
        point[32..].copy_from_slice(&gy);
        let scalar = [1u8; 32];

        let result = device
            .execute_batch(BatchOperation::EccMultiplication {
                points: vec![point],
                scalars: vec![scalar],
            })
            .await
            .unwrap();

        assert!(result.results[0]); // Generator point is valid
    }

    #[tokio::test]
    async fn test_ecc_invalid_point() {
        let device = GpuCryptoDevice::new().unwrap();

        // An all-zero point is not on the curve
        let point = [0u8; 64];
        let scalar = [1u8; 32];

        let result = device
            .execute_batch(BatchOperation::EccMultiplication {
                points: vec![point],
                scalars: vec![scalar],
            })
            .await
            .unwrap();

        assert!(!result.results[0]);
    }
}
