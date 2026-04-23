// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Quantum-Resistant Cryptography Module
//!
//! This module provides cutting-edge quantum-resistant cryptographic capabilities:
//! - NIST-approved post-quantum algorithms (ML-KEM, ML-DSA, SLH-DSA)
//! - Hybrid classical/post-quantum key exchange
//! - Quantum-safe key derivation and management
//! - Post-quantum signature schemes with classical fallback
//! - Quantum entropy estimation and enhancement
//! - Crypto-agility for seamless algorithm transitions

use crate::error::{HsmError, HsmResult};
use tracing::{error, warn};
// Note: These are cutting-edge libraries with evolving APIs
// For now, we provide a framework that can be adapted as the APIs stabilize
use crate::pkcs11_abi::constants::*;
use crate::pkcs11_abi::types::CK_MECHANISM_TYPE;
#[cfg(feature = "quantum-resistant")]
use ml_dsa;
#[cfg(feature = "quantum-resistant")]
use ml_kem;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
#[cfg(feature = "quantum-resistant")]
use slh_dsa;
use std::collections::HashMap;
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Quantum-resistant cryptography manager
pub struct QuantumResistantCrypto {
    /// Available PQC algorithms and their configurations
    algorithms: HashMap<PqcAlgorithm, AlgorithmConfig>,

    /// Hybrid mode configurations
    hybrid_configs: HashMap<String, HybridConfig>,

    /// Quantum entropy estimator
    entropy_estimator: QuantumEntropyEstimator,

    /// Algorithm transition manager
    transition_manager: CryptoAgilityManager,
}

/// Post-quantum cryptographic algorithms supported
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PqcAlgorithm {
    /// ML-KEM (formerly CRYSTALS-Kyber) - Key Encapsulation
    MlKem512,
    MlKem768,
    MlKem1024,

    /// ML-DSA (formerly CRYSTALS-Dilithium) - Digital Signatures
    MlDsa44,
    MlDsa65,
    MlDsa87,

    /// SLH-DSA (formerly SPHINCS+) - Stateless Hash-based Signatures
    SlhDsaSha2_128s,
    SlhDsaSha2_128f,
    SlhDsaSha2_192s,
    SlhDsaSha2_256s,

    /// Hybrid algorithms (classical + post-quantum)
    HybridP256MlKem512,
    HybridP384MlKem768,
    HybridRsaSlhDsa,
    HybridEcdsaMlDsa,
}

/// Algorithm configuration and metadata
#[derive(Debug, Clone)]
pub struct AlgorithmConfig {
    /// Security level in bits
    pub security_level: u32,

    /// Key size in bytes
    pub key_size: usize,

    /// Signature size in bytes (for signature algorithms)
    pub signature_size: Option<usize>,

    /// Ciphertext size in bytes (for KEM algorithms)
    pub ciphertext_size: Option<usize>,

    /// Performance category
    pub performance: PerformanceCategory,

    /// NIST standardization status
    pub standardization_status: StandardizationStatus,

    /// Recommended usage
    pub usage: Vec<UsageContext>,
}

/// Performance categories for algorithm selection
#[derive(Debug, Clone, PartialEq)]
pub enum PerformanceCategory {
    /// Optimized for speed
    Fast,
    /// Balanced speed/size
    Balanced,
    /// Optimized for small signatures/keys
    Compact,
}

/// NIST standardization status
#[derive(Debug, Clone, PartialEq)]
pub enum StandardizationStatus {
    /// NIST approved standard
    Approved,
    /// Finalist in NIST competition
    Finalist,
    /// Alternative candidate
    Alternative,
    /// Experimental/research
    Experimental,
}

/// Usage contexts for algorithms
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum UsageContext {
    /// Long-term key establishment
    KeyEstablishment,
    /// Digital signatures
    DigitalSignatures,
    /// Ephemeral key exchange
    EphemeralKeyExchange,
    /// Code signing
    CodeSigning,
    /// Certificate authorities
    CertificateAuthority,
    /// IoT/constrained environments
    ConstrainedEnvironment,
}

/// Hybrid cryptography configuration
#[derive(Debug, Clone)]
pub struct HybridConfig {
    /// Classical algorithm
    pub classical_algorithm: ClassicalAlgorithm,

    /// Post-quantum algorithm
    pub pqc_algorithm: PqcAlgorithm,

    /// Combination mode
    pub combination_mode: HybridMode,

    /// Security policy
    pub security_policy: HybridSecurityPolicy,
}

/// Classical cryptographic algorithms for hybrid use
#[derive(Debug, Clone, PartialEq)]
pub enum ClassicalAlgorithm {
    /// Elliptic Curve Cryptography
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,

    /// RSA
    Rsa2048,
    Rsa3072,
    Rsa4096,

    /// Elliptic Curve Diffie-Hellman
    EcdhP256,
    EcdhP384,
    EcdhP521,
}

/// Hybrid combination modes
#[derive(Debug, Clone, PartialEq)]
pub enum HybridMode {
    /// Both algorithms must succeed
    Concatenation,
    /// XOR combination of results
    Xor,
    /// KDF-based combination
    KdfCombination,
    /// Nested encryption/signing
    Nested,
}

/// Hybrid security policies
#[derive(Debug, Clone)]
pub struct HybridSecurityPolicy {
    /// Require both algorithms to succeed
    pub require_both_success: bool,

    /// Fail if classical algorithm fails
    pub fail_on_classical_failure: bool,

    /// Fail if PQC algorithm fails
    pub fail_on_pqc_failure: bool,

    /// Maximum allowed classical key age
    pub max_classical_key_age_days: u32,

    /// Minimum quantum security level
    pub min_quantum_security_bits: u32,
}

/// Post-quantum key pair.
///
/// `ZeroizeOnDrop` via a manual `Drop` impl: `Zeroize` isn't derived directly
/// because PqcAlgorithm / SystemTime / KeyMetadata don't impl Zeroize, but
/// we still clear `private_key` on drop — the only bytes that matter.
#[derive(Clone)]
pub struct PqcKeyPair {
    /// Algorithm used
    pub algorithm: PqcAlgorithm,

    /// Public key material
    pub public_key: Vec<u8>,

    /// Private key material (zeroized on drop)
    pub private_key: Vec<u8>,

    /// Key generation timestamp
    pub created_at: std::time::SystemTime,

    /// Key metadata
    pub metadata: KeyMetadata,
}

impl Drop for PqcKeyPair {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

/// Key metadata for post-quantum keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Key identifier
    pub key_id: String,

    /// Security level achieved
    pub security_level: u32,

    /// Intended usage
    pub usage: Vec<UsageContext>,

    /// Algorithm parameters
    pub parameters: HashMap<String, String>,

    /// Compliance information
    pub compliance: ComplianceInfo,
}

/// Compliance and certification information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceInfo {
    /// FIPS 140-3 compliance
    pub fips_140_3: bool,

    /// Common Criteria certification
    pub common_criteria: Option<String>,

    /// NIST approval status
    pub nist_approved: bool,

    /// Algorithm OID (if standardized)
    pub algorithm_oid: Option<String>,
}

/// Quantum entropy estimator for assessing randomness quality
pub struct QuantumEntropyEstimator {
    /// Entropy estimation algorithms
    estimators: Vec<Box<dyn EntropyEstimator + Send + Sync>>,

    /// Historical entropy measurements
    entropy_history: std::collections::VecDeque<EntropyMeasurement>,

    /// Minimum acceptable entropy per byte
    min_entropy_per_byte: f64,
}

/// Entropy estimation trait
pub trait EntropyEstimator {
    /// Estimate entropy in bits per byte
    fn estimate_entropy(&self, data: &[u8]) -> f64;

    /// Get estimator name
    fn name(&self) -> &str;

    /// Check if estimator is applicable to data
    fn is_applicable(&self, data: &[u8]) -> bool;
}

/// Entropy measurement record
#[derive(Debug, Clone)]
pub struct EntropyMeasurement {
    /// Measurement timestamp
    pub timestamp: std::time::SystemTime,

    /// Entropy estimate in bits per byte
    pub entropy_per_byte: f64,

    /// Data source
    pub source: String,

    /// Estimator used
    pub estimator: String,

    /// Sample size
    pub sample_size: usize,
}

/// Crypto-agility manager for algorithm transitions
pub struct CryptoAgilityManager {
    /// Algorithm deprecation schedule
    deprecation_schedule: HashMap<PqcAlgorithm, std::time::SystemTime>,

    /// Migration paths between algorithms
    migration_paths: HashMap<PqcAlgorithm, Vec<PqcAlgorithm>>,

    /// Algorithm preference ordering
    algorithm_preferences: Vec<PqcAlgorithm>,

    /// Transition policies
    transition_policies: TransitionPolicies,
}

/// Algorithm transition policies
#[derive(Debug, Clone)]
pub struct TransitionPolicies {
    /// Automatically migrate deprecated keys
    pub auto_migrate_deprecated: bool,

    /// Warn before algorithm deprecation (days)
    pub deprecation_warning_days: u32,

    /// Maximum key lifetime (days)
    pub max_key_lifetime_days: u32,

    /// Require manual approval for new algorithms
    pub require_approval_for_new_algorithms: bool,
}

/// Shannon entropy estimator
pub struct ShannonEntropyEstimator;

/// Min-entropy estimator
pub struct MinEntropyEstimator;

/// Compression-based entropy estimator
pub struct CompressionEntropyEstimator;

impl QuantumResistantCrypto {
    /// Create a new quantum-resistant crypto manager
    pub fn new() -> HsmResult<Self> {
        let mut algorithms = HashMap::new();

        // Configure ML-KEM algorithms
        algorithms.insert(
            PqcAlgorithm::MlKem512,
            AlgorithmConfig {
                security_level: 128,
                key_size: 1632, // ML-KEM-512 public key size
                signature_size: None,
                ciphertext_size: Some(768),
                performance: PerformanceCategory::Fast,
                standardization_status: StandardizationStatus::Approved,
                usage: vec![
                    UsageContext::KeyEstablishment,
                    UsageContext::EphemeralKeyExchange,
                ],
            },
        );

        algorithms.insert(
            PqcAlgorithm::MlKem768,
            AlgorithmConfig {
                security_level: 192,
                key_size: 2400,
                signature_size: None,
                ciphertext_size: Some(1088),
                performance: PerformanceCategory::Balanced,
                standardization_status: StandardizationStatus::Approved,
                usage: vec![UsageContext::KeyEstablishment],
            },
        );

        algorithms.insert(
            PqcAlgorithm::MlKem1024,
            AlgorithmConfig {
                security_level: 256,
                key_size: 3168,
                signature_size: None,
                ciphertext_size: Some(1568),
                performance: PerformanceCategory::Compact,
                standardization_status: StandardizationStatus::Approved,
                usage: vec![
                    UsageContext::KeyEstablishment,
                    UsageContext::CertificateAuthority,
                ],
            },
        );

        // Configure ML-DSA algorithms
        algorithms.insert(
            PqcAlgorithm::MlDsa44,
            AlgorithmConfig {
                security_level: 128,
                key_size: 1312, // ML-DSA-44 public key size
                signature_size: Some(2420),
                ciphertext_size: None,
                performance: PerformanceCategory::Fast,
                standardization_status: StandardizationStatus::Approved,
                usage: vec![UsageContext::DigitalSignatures, UsageContext::CodeSigning],
            },
        );

        algorithms.insert(
            PqcAlgorithm::MlDsa65,
            AlgorithmConfig {
                security_level: 192,
                key_size: 1952,
                signature_size: Some(3309),
                ciphertext_size: None,
                performance: PerformanceCategory::Balanced,
                standardization_status: StandardizationStatus::Approved,
                usage: vec![
                    UsageContext::DigitalSignatures,
                    UsageContext::CertificateAuthority,
                ],
            },
        );

        algorithms.insert(
            PqcAlgorithm::MlDsa87,
            AlgorithmConfig {
                security_level: 256,
                key_size: 2592,
                signature_size: Some(4627),
                ciphertext_size: None,
                performance: PerformanceCategory::Compact,
                standardization_status: StandardizationStatus::Approved,
                usage: vec![
                    UsageContext::CertificateAuthority,
                    UsageContext::DigitalSignatures,
                ],
            },
        );

        // Configure SLH-DSA algorithms
        algorithms.insert(
            PqcAlgorithm::SlhDsaSha2_128s,
            AlgorithmConfig {
                security_level: 128,
                key_size: 32, // SLH-DSA public key size
                signature_size: Some(7856),
                ciphertext_size: None,
                performance: PerformanceCategory::Compact,
                standardization_status: StandardizationStatus::Approved,
                usage: vec![UsageContext::DigitalSignatures, UsageContext::CodeSigning],
            },
        );

        // Configure hybrid algorithms
        algorithms.insert(
            PqcAlgorithm::HybridP256MlKem512,
            AlgorithmConfig {
                security_level: 128,
                key_size: 1696, // Combined size
                signature_size: None,
                ciphertext_size: Some(832),
                performance: PerformanceCategory::Balanced,
                standardization_status: StandardizationStatus::Experimental,
                usage: vec![
                    UsageContext::KeyEstablishment,
                    UsageContext::EphemeralKeyExchange,
                ],
            },
        );

        // Create entropy estimators
        let estimators: Vec<Box<dyn EntropyEstimator + Send + Sync>> = vec![
            Box::new(ShannonEntropyEstimator),
            Box::new(MinEntropyEstimator),
            Box::new(CompressionEntropyEstimator),
        ];

        let entropy_estimator = QuantumEntropyEstimator {
            estimators,
            entropy_history: std::collections::VecDeque::new(),
            min_entropy_per_byte: 7.5, // Require high entropy
        };

        // Create crypto-agility manager
        let transition_manager = CryptoAgilityManager {
            deprecation_schedule: HashMap::new(),
            migration_paths: Self::create_migration_paths(),
            algorithm_preferences: vec![
                PqcAlgorithm::MlKem768,
                PqcAlgorithm::MlDsa65,
                PqcAlgorithm::SlhDsaSha2_128s,
                PqcAlgorithm::HybridP256MlKem512,
            ],
            transition_policies: TransitionPolicies {
                auto_migrate_deprecated: false,
                deprecation_warning_days: 90,
                max_key_lifetime_days: 365 * 5, // 5 years
                require_approval_for_new_algorithms: true,
            },
        };

        Ok(Self {
            algorithms,
            hybrid_configs: Self::create_hybrid_configs(),
            entropy_estimator,
            transition_manager,
        })
    }

    /// Generate a post-quantum key pair
    pub fn generate_keypair<R: RngCore + CryptoRng>(
        &self,
        algorithm: &PqcAlgorithm,
        rng: &mut R,
        usage: Vec<UsageContext>,
    ) -> HsmResult<PqcKeyPair> {
        // Validate entropy quality of the caller's RNG before delegating.
        let mut entropy_sample = vec![0u8; 1024];
        rng.fill_bytes(&mut entropy_sample);
        self.validate_entropy(&entropy_sample, "key_generation")?;

        // Delegate to the real PQC primitives in `crate::crypto::pqc`. The
        // caller-supplied `rng` is used only for the entropy validation
        // above; the PQC keygen routes through the SP 800-90A HMAC_DRBG,
        // consistent with the rest of the HSM.
        let (public_key, private_key) = match algorithm {
            PqcAlgorithm::MlKem512 => {
                let (sk, pk) = crate::crypto::pqc::ml_kem_keygen(
                    crate::crypto::pqc::MlKemVariant::MlKem512,
                )?;
                (pk, sk.as_bytes().to_vec())
            }
            PqcAlgorithm::MlKem768 => {
                let (sk, pk) = crate::crypto::pqc::ml_kem_keygen(
                    crate::crypto::pqc::MlKemVariant::MlKem768,
                )?;
                (pk, sk.as_bytes().to_vec())
            }
            PqcAlgorithm::MlKem1024 => {
                let (sk, pk) = crate::crypto::pqc::ml_kem_keygen(
                    crate::crypto::pqc::MlKemVariant::MlKem1024,
                )?;
                (pk, sk.as_bytes().to_vec())
            }
            PqcAlgorithm::MlDsa44 => {
                let (sk, pk) = crate::crypto::pqc::ml_dsa_keygen(
                    crate::crypto::pqc::MlDsaVariant::MlDsa44,
                )?;
                (pk, sk.as_bytes().to_vec())
            }
            PqcAlgorithm::MlDsa65 => {
                let (sk, pk) = crate::crypto::pqc::ml_dsa_keygen(
                    crate::crypto::pqc::MlDsaVariant::MlDsa65,
                )?;
                (pk, sk.as_bytes().to_vec())
            }
            PqcAlgorithm::MlDsa87 => {
                let (sk, pk) = crate::crypto::pqc::ml_dsa_keygen(
                    crate::crypto::pqc::MlDsaVariant::MlDsa87,
                )?;
                (pk, sk.as_bytes().to_vec())
            }
            PqcAlgorithm::SlhDsaSha2_128s => {
                let (sk, pk) = crate::crypto::pqc::slh_dsa_keygen(
                    crate::crypto::pqc::SlhDsaVariant::Sha2_128s,
                )?;
                (pk, sk.as_bytes().to_vec())
            }
            _ => {
                return Err(HsmError::FunctionNotSupported);
            }
        };

        let config = self
            .algorithms
            .get(algorithm)
            .ok_or_else(|| HsmError::FunctionNotSupported)?;

        let metadata = KeyMetadata {
            key_id: uuid::Uuid::new_v4().to_string(),
            security_level: config.security_level,
            usage,
            parameters: HashMap::new(),
            compliance: ComplianceInfo {
                fips_140_3: false, // Would need FIPS certification
                common_criteria: None,
                nist_approved: matches!(
                    config.standardization_status,
                    StandardizationStatus::Approved
                ),
                algorithm_oid: None,
            },
        };

        Ok(PqcKeyPair {
            algorithm: algorithm.clone(),
            public_key,
            private_key,
            created_at: std::time::SystemTime::now(),
            metadata,
        })
    }

    /// Perform ML-KEM key encapsulation.
    pub fn kem_encapsulate<R: RngCore + CryptoRng>(
        &self,
        public_key: &[u8],
        algorithm: &PqcAlgorithm,
        rng: &mut R,
    ) -> HsmResult<(Vec<u8>, Vec<u8>)> {
        // Caller-RNG entropy validation only; the real ML-KEM encapsulation
        // routes through the SP 800-90A DRBG inside `crypto::pqc`.
        let mut entropy_sample = vec![0u8; 512];
        rng.fill_bytes(&mut entropy_sample);
        self.validate_entropy(&entropy_sample, "kem_encapsulation")?;

        let variant = match algorithm {
            PqcAlgorithm::MlKem512 => crate::crypto::pqc::MlKemVariant::MlKem512,
            PqcAlgorithm::MlKem768 => crate::crypto::pqc::MlKemVariant::MlKem768,
            PqcAlgorithm::MlKem1024 => crate::crypto::pqc::MlKemVariant::MlKem1024,
            _ => return Err(HsmError::FunctionNotSupported),
        };
        crate::crypto::pqc::ml_kem_encapsulate(public_key, variant)
    }

    /// Perform ML-KEM key decapsulation.
    pub fn kem_decapsulate(
        &self,
        private_key: &[u8],
        ciphertext: &[u8],
        algorithm: &PqcAlgorithm,
    ) -> HsmResult<Vec<u8>> {
        let variant = match algorithm {
            PqcAlgorithm::MlKem512 => crate::crypto::pqc::MlKemVariant::MlKem512,
            PqcAlgorithm::MlKem768 => crate::crypto::pqc::MlKemVariant::MlKem768,
            PqcAlgorithm::MlKem1024 => crate::crypto::pqc::MlKemVariant::MlKem1024,
            _ => return Err(HsmError::FunctionNotSupported),
        };
        crate::crypto::pqc::ml_kem_decapsulate(private_key, ciphertext, variant)
    }

    /// Sign a message using a post-quantum digital signature algorithm.
    pub fn sign<R: RngCore + CryptoRng>(
        &self,
        private_key: &[u8],
        message: &[u8],
        algorithm: &PqcAlgorithm,
        rng: &mut R,
    ) -> HsmResult<Vec<u8>> {
        // Entropy sanity-check the caller's RNG; the PQC signing path uses
        // the DRBG inside `crypto::pqc`.
        let mut entropy_sample = vec![0u8; 256];
        rng.fill_bytes(&mut entropy_sample);
        self.validate_entropy(&entropy_sample, "pqc_signing")?;

        match algorithm {
            PqcAlgorithm::MlDsa44 => crate::crypto::pqc::ml_dsa_sign(
                private_key,
                message,
                crate::crypto::pqc::MlDsaVariant::MlDsa44,
            ),
            PqcAlgorithm::MlDsa65 => crate::crypto::pqc::ml_dsa_sign(
                private_key,
                message,
                crate::crypto::pqc::MlDsaVariant::MlDsa65,
            ),
            PqcAlgorithm::MlDsa87 => crate::crypto::pqc::ml_dsa_sign(
                private_key,
                message,
                crate::crypto::pqc::MlDsaVariant::MlDsa87,
            ),
            PqcAlgorithm::SlhDsaSha2_128s => crate::crypto::pqc::slh_dsa_sign(
                private_key,
                message,
                crate::crypto::pqc::SlhDsaVariant::Sha2_128s,
            ),
            _ => Err(HsmError::UnsupportedOperation(format!(
                "Signing not supported for {:?}",
                algorithm
            ))),
        }
    }

    /// Verify a post-quantum digital signature.
    pub fn verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
        algorithm: &PqcAlgorithm,
    ) -> HsmResult<bool> {
        match algorithm {
            PqcAlgorithm::MlDsa44 => crate::crypto::pqc::ml_dsa_verify(
                public_key,
                message,
                signature,
                crate::crypto::pqc::MlDsaVariant::MlDsa44,
            ),
            PqcAlgorithm::MlDsa65 => crate::crypto::pqc::ml_dsa_verify(
                public_key,
                message,
                signature,
                crate::crypto::pqc::MlDsaVariant::MlDsa65,
            ),
            PqcAlgorithm::MlDsa87 => crate::crypto::pqc::ml_dsa_verify(
                public_key,
                message,
                signature,
                crate::crypto::pqc::MlDsaVariant::MlDsa87,
            ),
            PqcAlgorithm::SlhDsaSha2_128s => crate::crypto::pqc::slh_dsa_verify(
                public_key,
                message,
                signature,
                crate::crypto::pqc::SlhDsaVariant::Sha2_128s,
            ),
            _ => Err(HsmError::UnsupportedOperation(format!(
                "Verification not supported for {:?}",
                algorithm
            ))),
        }
    }

    /// Validate entropy quality for cryptographic operations
    fn validate_entropy(&self, data: &[u8], source: &str) -> HsmResult<()> {
        let mut total_entropy = 0.0;
        let mut estimator_count = 0;

        for estimator in &self.entropy_estimator.estimators {
            if estimator.is_applicable(data) {
                let entropy = estimator.estimate_entropy(data);
                total_entropy += entropy;
                estimator_count += 1;
            }
        }

        if estimator_count == 0 {
            error!("No entropy estimators applicable");
            return Err(HsmError::GeneralError);
        }

        let avg_entropy = total_entropy / estimator_count as f64;

        if avg_entropy < self.entropy_estimator.min_entropy_per_byte {
            error!(
                "Insufficient entropy: {:.2} bits/byte (minimum: {:.2})",
                avg_entropy, self.entropy_estimator.min_entropy_per_byte
            );
            return Err(HsmError::GeneralError);
        }

        Ok(())
    }

    /// Get algorithm information
    pub fn get_algorithm_info(&self, algorithm: &PqcAlgorithm) -> Option<&AlgorithmConfig> {
        self.algorithms.get(algorithm)
    }

    /// List available algorithms for a use case
    pub fn list_algorithms_for_usage(&self, usage: &UsageContext) -> Vec<PqcAlgorithm> {
        self.algorithms
            .iter()
            .filter(|(_, config)| config.usage.contains(usage))
            .map(|(alg, _)| alg.clone())
            .collect()
    }

    /// Recommend algorithm for security level and usage
    pub fn recommend_algorithm(
        &self,
        min_security_level: u32,
        usage: &UsageContext,
    ) -> Option<PqcAlgorithm> {
        self.transition_manager
            .algorithm_preferences
            .iter()
            .find(|&alg| {
                if let Some(config) = self.algorithms.get(alg) {
                    config.security_level >= min_security_level && config.usage.contains(usage)
                } else {
                    false
                }
            })
            .cloned()
    }

    /// Create migration paths between algorithms
    fn create_migration_paths() -> HashMap<PqcAlgorithm, Vec<PqcAlgorithm>> {
        let mut paths = HashMap::new();

        // ML-KEM migration paths
        paths.insert(
            PqcAlgorithm::MlKem512,
            vec![PqcAlgorithm::MlKem768, PqcAlgorithm::HybridP256MlKem512],
        );
        paths.insert(PqcAlgorithm::MlKem768, vec![PqcAlgorithm::MlKem1024]);

        // ML-DSA migration paths
        paths.insert(
            PqcAlgorithm::MlDsa44,
            vec![PqcAlgorithm::MlDsa65, PqcAlgorithm::SlhDsaSha2_128s],
        );
        paths.insert(PqcAlgorithm::MlDsa65, vec![PqcAlgorithm::MlDsa87]);

        paths
    }

    /// Create hybrid configuration templates
    fn create_hybrid_configs() -> HashMap<String, HybridConfig> {
        let mut configs = HashMap::new();

        configs.insert(
            "p256_mlkem512".to_string(),
            HybridConfig {
                classical_algorithm: ClassicalAlgorithm::EcdsaP256,
                pqc_algorithm: PqcAlgorithm::MlKem512,
                combination_mode: HybridMode::KdfCombination,
                security_policy: HybridSecurityPolicy {
                    require_both_success: true,
                    fail_on_classical_failure: false,
                    fail_on_pqc_failure: true,
                    max_classical_key_age_days: 365,
                    min_quantum_security_bits: 128,
                },
            },
        );

        configs.insert(
            "rsa_slhdsa".to_string(),
            HybridConfig {
                classical_algorithm: ClassicalAlgorithm::Rsa3072,
                pqc_algorithm: PqcAlgorithm::SlhDsaSha2_128s,
                combination_mode: HybridMode::Nested,
                security_policy: HybridSecurityPolicy {
                    require_both_success: true,
                    fail_on_classical_failure: true,
                    fail_on_pqc_failure: true,
                    max_classical_key_age_days: 180,
                    min_quantum_security_bits: 128,
                },
            },
        );

        configs
    }

    /// Convert PKCS#11 mechanism to PQC algorithm
    pub fn mechanism_to_algorithm(mechanism: CK_MECHANISM_TYPE) -> Option<PqcAlgorithm> {
        match mechanism {
            CKM_ML_KEM_512 => Some(PqcAlgorithm::MlKem512),
            CKM_ML_KEM_768 => Some(PqcAlgorithm::MlKem768),
            CKM_ML_KEM_1024 => Some(PqcAlgorithm::MlKem1024),
            CKM_ML_DSA_44 => Some(PqcAlgorithm::MlDsa44),
            CKM_ML_DSA_65 => Some(PqcAlgorithm::MlDsa65),
            CKM_ML_DSA_87 => Some(PqcAlgorithm::MlDsa87),
            CKM_SLH_DSA_SHA2_128S => Some(PqcAlgorithm::SlhDsaSha2_128s),
            _ => None,
        }
    }
}

// Entropy estimator implementations
impl EntropyEstimator for ShannonEntropyEstimator {
    fn estimate_entropy(&self, data: &[u8]) -> f64 {
        let mut counts = [0u32; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for &count in &counts {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    fn name(&self) -> &str {
        "shannon"
    }

    fn is_applicable(&self, data: &[u8]) -> bool {
        data.len() >= 32
    }
}

impl EntropyEstimator for MinEntropyEstimator {
    fn estimate_entropy(&self, data: &[u8]) -> f64 {
        let mut counts = [0u32; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }

        let max_count = *counts.iter().max().unwrap_or(&1);
        let len = data.len() as f64;
        let max_prob = max_count as f64 / len;

        if max_prob > 0.0 {
            -max_prob.log2()
        } else {
            0.0
        }
    }

    fn name(&self) -> &str {
        "min_entropy"
    }

    fn is_applicable(&self, data: &[u8]) -> bool {
        data.len() >= 16
    }
}

impl EntropyEstimator for CompressionEntropyEstimator {
    fn estimate_entropy(&self, data: &[u8]) -> f64 {
        // Simple compression ratio based estimate
        let original_size = data.len() as f64;

        // Use a simple run-length encoding estimate
        let mut compressed_size = 0.0;
        let mut i = 0;
        while i < data.len() {
            let mut count = 1;
            while i + count < data.len() && data[i] == data[i + count] {
                count += 1;
            }
            compressed_size += 2.0; // Byte + count
            i += count;
        }

        let compression_ratio = compressed_size / original_size;
        (8.0 * compression_ratio).min(8.0)
    }

    fn name(&self) -> &str {
        "compression"
    }

    fn is_applicable(&self, data: &[u8]) -> bool {
        data.len() >= 64
    }
}

impl fmt::Display for PqcAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PqcAlgorithm::MlKem512 => write!(f, "ML-KEM-512"),
            PqcAlgorithm::MlKem768 => write!(f, "ML-KEM-768"),
            PqcAlgorithm::MlKem1024 => write!(f, "ML-KEM-1024"),
            PqcAlgorithm::MlDsa44 => write!(f, "ML-DSA-44"),
            PqcAlgorithm::MlDsa65 => write!(f, "ML-DSA-65"),
            PqcAlgorithm::MlDsa87 => write!(f, "ML-DSA-87"),
            PqcAlgorithm::SlhDsaSha2_128s => write!(f, "SLH-DSA-SHA2-128s"),
            PqcAlgorithm::SlhDsaSha2_128f => write!(f, "SLH-DSA-SHA2-128f"),
            PqcAlgorithm::SlhDsaSha2_192s => write!(f, "SLH-DSA-SHA2-192s"),
            PqcAlgorithm::SlhDsaSha2_256s => write!(f, "SLH-DSA-SHA2-256s"),
            PqcAlgorithm::HybridP256MlKem512 => write!(f, "Hybrid-P256-ML-KEM-512"),
            PqcAlgorithm::HybridP384MlKem768 => write!(f, "Hybrid-P384-ML-KEM-768"),
            PqcAlgorithm::HybridRsaSlhDsa => write!(f, "Hybrid-RSA-SLH-DSA"),
            PqcAlgorithm::HybridEcdsaMlDsa => write!(f, "Hybrid-ECDSA-ML-DSA"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_quantum_resistant_crypto_creation() {
        let pqc = QuantumResistantCrypto::new().expect("Failed to create PQC manager");

        let info = pqc.get_algorithm_info(&PqcAlgorithm::MlKem768);
        assert!(info.is_some());
        assert_eq!(info.unwrap().security_level, 192);
    }

    #[test]
    fn test_algorithm_recommendation() {
        let pqc = QuantumResistantCrypto::new().expect("Failed to create PQC manager");

        let recommended = pqc.recommend_algorithm(128, &UsageContext::KeyEstablishment);
        assert!(recommended.is_some());
    }

    #[test]
    fn test_ml_kem_keypair_generation() {
        let pqc = QuantumResistantCrypto::new().expect("Failed to create PQC manager");
        let mut rng = OsRng;

        let keypair = pqc
            .generate_keypair(
                &PqcAlgorithm::MlKem512,
                &mut rng,
                vec![UsageContext::KeyEstablishment],
            )
            .expect("Failed to generate ML-KEM-512 keypair");

        assert_eq!(keypair.algorithm, PqcAlgorithm::MlKem512);
        assert!(!keypair.public_key.is_empty());
        assert!(!keypair.private_key.is_empty());
    }

    #[test]
    fn test_ml_dsa_keypair_generation() {
        let pqc = QuantumResistantCrypto::new().expect("Failed to create PQC manager");
        let mut rng = OsRng;

        let keypair = pqc
            .generate_keypair(
                &PqcAlgorithm::MlDsa65,
                &mut rng,
                vec![UsageContext::DigitalSignatures],
            )
            .expect("Failed to generate ML-DSA-65 keypair");

        assert_eq!(keypair.algorithm, PqcAlgorithm::MlDsa65);
        assert_eq!(keypair.metadata.security_level, 192);
    }

    #[test]
    fn test_entropy_estimators() {
        let shannon = ShannonEntropyEstimator;
        let min_entropy = MinEntropyEstimator;

        // High entropy data
        let high_entropy_data = (0..256).map(|i| i as u8).collect::<Vec<u8>>();
        let shannon_entropy = shannon.estimate_entropy(&high_entropy_data);
        let min_entropy_val = min_entropy.estimate_entropy(&high_entropy_data);

        assert!(shannon_entropy > 7.0); // Should be close to 8.0 for uniform distribution
        assert!(min_entropy_val > 0.0);

        // Low entropy data
        let low_entropy_data = vec![0u8; 256];
        let shannon_entropy_low = shannon.estimate_entropy(&low_entropy_data);
        assert!(shannon_entropy_low < 1.0); // Should be close to 0 for repeated data
    }

    #[test]
    fn test_mechanism_conversion() {
        assert_eq!(
            QuantumResistantCrypto::mechanism_to_algorithm(CKM_ML_KEM_768),
            Some(PqcAlgorithm::MlKem768)
        );

        assert_eq!(
            QuantumResistantCrypto::mechanism_to_algorithm(CKM_ML_DSA_65),
            Some(PqcAlgorithm::MlDsa65)
        );
    }

    #[test]
    fn test_algorithm_listing() {
        let pqc = QuantumResistantCrypto::new().expect("Failed to create PQC manager");

        let kem_algorithms = pqc.list_algorithms_for_usage(&UsageContext::KeyEstablishment);
        assert!(!kem_algorithms.is_empty());
        assert!(kem_algorithms.contains(&PqcAlgorithm::MlKem768));

        let signature_algorithms = pqc.list_algorithms_for_usage(&UsageContext::DigitalSignatures);
        assert!(!signature_algorithms.is_empty());
        assert!(signature_algorithms.contains(&PqcAlgorithm::MlDsa65));
    }
}
