// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company

//! Enhanced crypto backend with performance optimizations and advanced algorithms.
//!
//! This module implements the comprehensive improvements identified in the HSM
//! enhancement plan, including:
//! - Zero-copy buffer operations
//! - Stack-allocated signature buffers
//! - Advanced signature schemes (RSA-PSS with SHA-3, EdDSA curves)
//! - Additional key derivation functions (X9.63, Concat KDF, ANSI X9.42)
//! - Hardware acceleration integration points
//! - Post-quantum cryptography enhancements

use arrayvec::ArrayVec;
use std::sync::Arc;
use zeroize::Zeroizing;

use crate::crypto::backend::CryptoBackend;
use crate::error::{HsmError, HsmResult};
use crate::pkcs11_abi::constants::*;

/// Maximum signature size for stack allocation
/// Covers RSA-4096 (512 bytes), ECDSA P-384 (96 bytes), Ed25519 (64 bytes)
const MAX_SIGNATURE_SIZE: usize = 512;

/// Stack-allocated signature buffer for zero-copy operations
pub type SignatureBuffer = ArrayVec<u8, MAX_SIGNATURE_SIZE>;

/// Enhanced hash algorithms including SHA-3 variants
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    // Traditional algorithms
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    // SHA-3 family
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    // SHAKE XOFs
    Shake128,
    Shake256,
}

/// Enhanced key derivation function algorithms
#[derive(Debug, Clone)]
pub enum KdfAlgorithm {
    /// HKDF (RFC 5869) - already implemented
    Hkdf { hash: HashAlgorithm, salt: Option<Vec<u8>>, info: Vec<u8> },
    /// X9.63 KDF (IEEE 1363-2000)
    X963 { hash: HashAlgorithm, shared_info: Vec<u8> },
    /// Concat KDF (SP 800-56A)
    Concat { hash: HashAlgorithm, algorithm_id: Vec<u8>, party_u_info: Vec<u8>, party_v_info: Vec<u8> },
    /// ANSI X9.42 DH KDF
    AnsiX942 { kek_algorithm: SymmetricAlgorithm },
    /// HKDF-Expand-Label for TLS 1.3
    HkdfExpandLabel { hash: HashAlgorithm, label: String, context: Vec<u8> },
    /// PBKDF2 (already implemented, included for completeness)
    Pbkdf2 { hash: HashAlgorithm, salt: Vec<u8>, iterations: u32 },
}

/// Enhanced symmetric encryption algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymmetricAlgorithm {
    Aes128,
    Aes192,
    Aes256,
    ChaCha20Poly1305,
    XChaCha20Poly1305,
}

/// Additional signature schemes for enhanced compatibility
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureScheme {
    // RSA schemes
    RsaPkcs1v15(HashAlgorithm),
    RsaPss { hash: HashAlgorithm, mgf_hash: HashAlgorithm, salt_len: Option<usize> },
    // ECDSA schemes
    EcdsaP256(HashAlgorithm),
    EcdsaP384(HashAlgorithm),
    EcdsaP521(HashAlgorithm),
    EcdsaSecp256k1(HashAlgorithm), // Bitcoin/Ethereum curve
    EcdsaBrainpoolP256r1(HashAlgorithm),
    EcdsaBrainpoolP384r1(HashAlgorithm),
    // EdDSA schemes
    Ed25519,
    Ed448,
    // Post-quantum signatures
    MlDsa44,
    MlDsa65,
    MlDsa87,
    SlhDsaSha2_128s,
    SlhDsaSha2_128f,
    SlhDsaSha2_192s,
    SlhDsaSha2_192f,
    SlhDsaSha2_256s,
    SlhDsaSha2_256f,
}

/// Enhanced crypto backend trait with zero-copy operations and advanced algorithms
pub trait EnhancedCryptoBackend: CryptoBackend {
    // ========================================================================
    // Zero-copy signature operations (Phase 1 optimization)
    // ========================================================================

    /// Sign data using stack-allocated buffer for improved performance.
    /// Returns the signature length written to the buffer.
    fn sign_to_buffer(
        &self,
        private_key: &Arc<dyn AsRef<[u8]>>,
        scheme: SignatureScheme,
        data: &[u8],
        output: &mut SignatureBuffer,
    ) -> HsmResult<usize>;

    /// Verify signature with zero-copy operation.
    fn verify_from_buffer(
        &self,
        public_key: &Arc<dyn AsRef<[u8]>>,
        scheme: SignatureScheme,
        data: &[u8],
        signature: &[u8],
    ) -> HsmResult<bool>;

    // ========================================================================
    // Advanced signature schemes (Phase 2 enhancement)
    // ========================================================================

    /// RSA-PSS signature with SHA-3 hash functions
    fn rsa_pss_sha3_sign(
        &self,
        private_key: &[u8],
        hash: HashAlgorithm,
        data: &[u8],
        salt_len: Option<usize>,
    ) -> HsmResult<Vec<u8>>;

    /// EdDSA signature with Ed448 curve
    fn ed448_sign(&self, private_key: &[u8], data: &[u8]) -> HsmResult<Vec<u8>>;

    /// EdDSA verification with Ed448 curve
    fn ed448_verify(&self, public_key: &[u8], data: &[u8], signature: &[u8]) -> HsmResult<bool>;

    /// ECDSA with secp256k1 curve (Bitcoin/Ethereum)
    fn secp256k1_sign(&self, private_key: &[u8], data: &[u8]) -> HsmResult<Vec<u8>>;

    /// ECDSA verification with secp256k1 curve
    fn secp256k1_verify(&self, public_key: &[u8], data: &[u8], signature: &[u8]) -> HsmResult<bool>;

    // ========================================================================
    // Advanced key derivation functions (Phase 2 enhancement)
    // ========================================================================

    /// Enhanced key derivation supporting multiple algorithms
    fn derive_key_enhanced(
        &self,
        input_key_material: &[u8],
        algorithm: KdfAlgorithm,
        output_length: usize,
    ) -> HsmResult<Zeroizing<Vec<u8>>>;

    /// X9.63 Key Derivation Function (IEEE 1363-2000)
    fn kdf_x963(
        &self,
        shared_secret: &[u8],
        hash: HashAlgorithm,
        shared_info: &[u8],
        output_length: usize,
    ) -> HsmResult<Zeroizing<Vec<u8>>>;

    /// Concat KDF (SP 800-56A)
    fn kdf_concat(
        &self,
        shared_secret: &[u8],
        hash: HashAlgorithm,
        algorithm_id: &[u8],
        party_u_info: &[u8],
        party_v_info: &[u8],
        output_length: usize,
    ) -> HsmResult<Zeroizing<Vec<u8>>>;

    /// ANSI X9.42 DH Key Derivation Function
    fn kdf_ansi_x942(
        &self,
        shared_secret: &[u8],
        kek_algorithm: SymmetricAlgorithm,
        output_length: usize,
    ) -> HsmResult<Zeroizing<Vec<u8>>>;

    /// HKDF-Expand-Label for TLS 1.3
    fn hkdf_expand_label(
        &self,
        prk: &[u8],
        hash: HashAlgorithm,
        label: &str,
        context: &[u8],
        output_length: usize,
    ) -> HsmResult<Zeroizing<Vec<u8>>>;

    // ========================================================================
    // Hardware acceleration integration (Phase 2 enhancement)
    // ========================================================================

    /// Check if hardware acceleration is available for given operation
    fn has_hardware_acceleration(&self, operation: &str) -> bool;

    /// Get hardware acceleration capabilities
    fn get_acceleration_info(&self) -> HardwareAccelerationInfo;

    /// Enable/disable hardware acceleration dynamically
    fn set_hardware_acceleration(&mut self, enabled: bool) -> HsmResult<()>;

    // ========================================================================
    // Enhanced digest operations with SHA-3
    // ========================================================================

    /// Compute digest using enhanced hash algorithms including SHA-3
    fn digest_enhanced(&self, algorithm: HashAlgorithm, data: &[u8]) -> HsmResult<Vec<u8>>;

    /// Initialize incremental hash computation
    fn digest_init(&self, algorithm: HashAlgorithm) -> HsmResult<Box<dyn DigestContext>>;

    // ========================================================================
    // Post-quantum cryptography enhancements (Phase 2/3)
    // ========================================================================

    /// Enhanced ML-DSA (FIPS 204) signature with all parameter sets
    fn ml_dsa_sign(&self, private_key: &[u8], parameter_set: MlDsaParameterSet, data: &[u8]) -> HsmResult<Vec<u8>>;

    /// Enhanced ML-DSA verification
    fn ml_dsa_verify(&self, public_key: &[u8], parameter_set: MlDsaParameterSet, data: &[u8], signature: &[u8]) -> HsmResult<bool>;

    /// Enhanced SLH-DSA (FIPS 205) with all variants
    fn slh_dsa_sign(&self, private_key: &[u8], parameter_set: SlhDsaParameterSet, data: &[u8]) -> HsmResult<Vec<u8>>;

    /// Enhanced SLH-DSA verification
    fn slh_dsa_verify(&self, public_key: &[u8], parameter_set: SlhDsaParameterSet, data: &[u8], signature: &[u8]) -> HsmResult<bool>;

    /// Hybrid signature combining classical and post-quantum algorithms
    fn hybrid_sign(
        &self,
        classical_key: &[u8],
        classical_scheme: SignatureScheme,
        pq_key: &[u8],
        pq_scheme: SignatureScheme,
        data: &[u8],
    ) -> HsmResult<HybridSignature>;
}

/// Hardware acceleration information
#[derive(Debug, Clone)]
pub struct HardwareAccelerationInfo {
    pub cpu_features: CpuFeatures,
    pub hardware_devices: Vec<HardwareDevice>,
    pub performance_multipliers: std::collections::HashMap<String, f64>,
}

/// CPU-specific acceleration features
#[derive(Debug, Clone)]
pub struct CpuFeatures {
    pub aes_ni: bool,
    pub avx2: bool,
    pub avx512: bool,
    pub sha_ext: bool,
    pub arm_crypto: bool,
}

/// Hardware acceleration device
#[derive(Debug, Clone)]
pub struct HardwareDevice {
    pub device_type: HardwareDeviceType,
    pub vendor: String,
    pub model: String,
    pub supported_operations: Vec<String>,
}

/// Types of hardware acceleration devices
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HardwareDeviceType {
    IntelQat,
    ArmCryptoCell,
    NvidiaGpu,
    AmdGpu,
    TrustedPlatformModule,
    HardwareSecurityModule,
}

/// ML-DSA parameter sets (FIPS 204)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlDsaParameterSet {
    /// ML-DSA-44 (security category 2)
    Level2,
    /// ML-DSA-65 (security category 3)
    Level3,
    /// ML-DSA-87 (security category 5)
    Level5,
}

/// SLH-DSA parameter sets (FIPS 205)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlhDsaParameterSet {
    Sha2_128s,
    Sha2_128f,
    Sha2_192s,
    Sha2_192f,
    Sha2_256s,
    Sha2_256f,
    Shake_128s,
    Shake_128f,
    Shake_192s,
    Shake_192f,
    Shake_256s,
    Shake_256f,
}

/// Hybrid signature combining classical and post-quantum schemes
#[derive(Debug, Clone)]
pub struct HybridSignature {
    pub classical_signature: Vec<u8>,
    pub pq_signature: Vec<u8>,
    pub metadata: HybridSignatureMetadata,
}

/// Metadata for hybrid signatures
#[derive(Debug, Clone)]
pub struct HybridSignatureMetadata {
    pub classical_scheme: SignatureScheme,
    pub pq_scheme: SignatureScheme,
    pub version: u32,
    pub timestamp: u64,
}

/// Trait for incremental digest computation
pub trait DigestContext: Send + Sync {
    fn update(&mut self, data: &[u8]) -> HsmResult<()>;
    fn finalize(self: Box<Self>) -> HsmResult<Vec<u8>>;
    fn clone_context(&self) -> Box<dyn DigestContext>;
}

/// Error types for enhanced crypto operations
#[derive(Debug, thiserror::Error)]
pub enum EnhancedCryptoError {
    #[error("Hardware acceleration not available: {device}")]
    HardwareUnavailable { device: String },
    #[error("Unsupported algorithm: {algorithm}")]
    UnsupportedAlgorithm { algorithm: String },
    #[error("Invalid parameter set: {parameter_set}")]
    InvalidParameterSet { parameter_set: String },
    #[error("Buffer too small: need {needed}, got {available}")]
    BufferTooSmall { needed: usize, available: usize },
    #[error("Hybrid signature verification failed: {reason}")]
    HybridVerificationFailed { reason: String },
}

/// Convert enhanced crypto errors to HSM errors
impl From<EnhancedCryptoError> for HsmError {
    fn from(err: EnhancedCryptoError) -> Self {
        match err {
            EnhancedCryptoError::HardwareUnavailable { .. } => HsmError::GeneralError,
            EnhancedCryptoError::UnsupportedAlgorithm { .. } => HsmError::MechanismInvalid,
            EnhancedCryptoError::InvalidParameterSet { .. } => HsmError::MechanismParamInvalid,
            EnhancedCryptoError::BufferTooSmall { .. } => HsmError::BufferTooSmall,
            EnhancedCryptoError::HybridVerificationFailed { .. } => HsmError::SignatureInvalid,
        }
    }
}