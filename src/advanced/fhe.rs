// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Fully Homomorphic Encryption (FHE) via **TFHE-rs** by Zama.
//!
//! FHE allows an untrusted cloud service (or another HSM cluster node) to
//! perform computations *directly on ciphertexts* — the server never sees the
//! plaintext values.  This module exposes the subset of FHE operations that
//! are useful in an HSM context:
//!
//! | Use case | FHE operation | HSM benefit |
//! |---|---|---|
//! | Encrypted usage counters | `FheUint32::add` | Count key-uses in cloud without exposing counts |
//! | Encrypted audit score | `FheUint32::gt`, `FheUint32::eq` | Evaluate risk threshold without decrypting event data |
//! | Homomorphic key blinding | XOR / AND on `FheUint8` | Blind a key fragment before shipping to an enclave |
//! | Threshold sum | `FheUint32::add` × n | Sum partial results from cluster nodes |
//!
//! # Architecture
//!
//! ```text
//!   Client (HSM operator)           Cloud / remote cluster node
//!   ─────────────────────           ──────────────────────────────
//!   FheClientKey  (secret)   -->    FheServerKey (public eval key)
//!                                       │
//!   FheUint32::encrypt(val)  -->    FheCiphertext
//!                                       │  homomorphic arithmetic
//!                                   FheCiphertext (result)
//!                                       │
//!                           <--    transfer result back
//!   FheClientKey::decrypt()         (never reveals plaintext)
//! ```
//!
//! # Warning
//! FHE is **computationally expensive**.  A 32-bit addition over TFHE
//! takes ~10 ms on a modern CPU.  Enable the `fhe-compute` feature only
//! for workflows that specifically require computing on encrypted data.

#![cfg(feature = "fhe-compute")]

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tfhe::prelude::*;
use tfhe::{
    generate_keys, set_server_key, ClientKey, CompactPublicKey, ConfigBuilder, FheUint32, FheUint8,
    ServerKey,
};

use crate::error::HsmError;

// ── Key management ────────────────────────────────────────────────────────────

/// FHE key set for the HSM operator (client side).
///
/// `ClientKey` is secret and never leaves the operator's trust boundary.
/// `ServerKey` is the evaluation key sent to any party that performs
/// homomorphic operations.
pub struct FheKeySet {
    /// Secret key — decrypt results.  Keep this in the HSM's secure memory.
    pub client_key: ClientKey,
    /// Public evaluation key — share with compute nodes.
    pub server_key: ServerKey,
}

impl FheKeySet {
    /// Generate a new FHE key set with default TFHE parameters.
    ///
    /// Uses `ConfigBuilder::default()` which selects parameters targeting
    /// 128-bit security with a reasonable performance/size trade-off.
    pub fn generate() -> Self {
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = generate_keys(config);
        Self {
            client_key,
            server_key,
        }
    }

    /// Activate the server key for this thread.
    ///
    /// Must be called on the compute thread before any homomorphic operations.
    pub fn activate_server_key(&self) {
        set_server_key(self.server_key.clone());
    }

    /// Serialize the key set to bytes for persistence.
    ///
    /// Uses bincode serialization since tfhe's ClientKey and ServerKey
    /// implement serde::Serialize. The output should be encrypted at rest
    /// using AES-256-GCM before storage.
    ///
    /// Format: [8:client_key_len_le][client_key_bytes][server_key_bytes]
    pub fn serialize(&self) -> Result<Vec<u8>, HsmError> {
        let mut buf = Vec::new();

        let ck_bytes = bincode::serialize(&self.client_key)
            .map_err(|e| HsmError::CryptographicError(format!("FHE client key serialize: {e}")))?;
        let ck_len = (ck_bytes.len() as u64).to_le_bytes();
        buf.extend_from_slice(&ck_len);
        buf.extend_from_slice(&ck_bytes);

        let sk_bytes = bincode::serialize(&self.server_key)
            .map_err(|e| HsmError::CryptographicError(format!("FHE server key serialize: {e}")))?;
        buf.extend_from_slice(&sk_bytes);

        Ok(buf)
    }

    /// Deserialize a key set from bytes previously produced by `serialize()`.
    pub fn deserialize(data: &[u8]) -> Result<Self, HsmError> {
        if data.len() < 8 {
            return Err(HsmError::DataLenRange);
        }
        let ck_len =
            u64::from_le_bytes(data[..8].try_into().map_err(|_| HsmError::DataInvalid)?) as usize;
        if data.len() < 8 + ck_len {
            return Err(HsmError::DataLenRange);
        }

        let client_key: ClientKey = bincode::deserialize(&data[8..8 + ck_len]).map_err(|e| {
            HsmError::CryptographicError(format!("FHE client key deserialize: {e}"))
        })?;
        let server_key: ServerKey = bincode::deserialize(&data[8 + ck_len..]).map_err(|e| {
            HsmError::CryptographicError(format!("FHE server key deserialize: {e}"))
        })?;

        Ok(Self {
            client_key,
            server_key,
        })
    }
}

// ── Encrypted counter ─────────────────────────────────────────────────────────

/// An encrypted key-usage counter stored and incremented by untrusted nodes.
///
/// The cloud never learns the actual count; only the HSM operator can decrypt it.
pub struct EncryptedCounter {
    value: FheUint32,
}

impl EncryptedCounter {
    /// Create a new counter starting at `initial`.
    pub fn new(initial: u32, keys: &FheKeySet) -> Self {
        Self {
            value: FheUint32::encrypt(initial, &keys.client_key),
        }
    }

    /// Homomorphically increment the counter by `delta` (no decryption needed).
    ///
    /// The compute node calls this; it never sees the current count.
    pub fn increment(&mut self, delta: u32, keys: &FheKeySet) {
        let enc_delta = FheUint32::encrypt(delta, &keys.client_key);
        // Addition over encrypted integers — server doesn't learn either operand
        self.value = &self.value + &enc_delta;
    }

    /// Homomorphically check whether the counter has exceeded `limit`.
    ///
    /// Returns an encrypted boolean (0 or 1) — the server learns nothing.
    pub fn exceeds_limit(&self, limit: u32, keys: &FheKeySet) -> FheUint32 {
        let enc_limit = FheUint32::encrypt(limit, &keys.client_key);
        // gt returns 1 if self.value > enc_limit, else 0
        FheUint32::cast_from(self.value.gt(&enc_limit))
    }

    /// Decrypt the counter.  Requires the secret client key.
    pub fn decrypt(&self, keys: &FheKeySet) -> u32 {
        self.value.decrypt(&keys.client_key)
    }

    /// Homomorphically check whether the counter is less than `limit`.
    /// Returns an encrypted boolean (0 or 1) as FheUint32.
    pub fn is_below(&self, limit: u32, keys: &FheKeySet) -> FheUint32 {
        let enc_limit = FheUint32::encrypt(limit, &keys.client_key);
        FheUint32::cast_from(self.value.lt(&enc_limit))
    }

    /// Homomorphically check whether two counters are equal.
    /// Returns an encrypted boolean (0 or 1) as FheUint32.
    pub fn equals(&self, other: &EncryptedCounter) -> FheUint32 {
        FheUint32::cast_from(self.value.eq(&other.value))
    }
}

// ── Encrypted byte buffer ─────────────────────────────────────────────────────

/// An encrypted byte array for homomorphic blinding/masking of key material.
///
/// # Use case
/// Blind a key fragment before handing it to an untrusted enclave:
/// 1. HSM generates `mask` (random bytes, encrypted with FHE).
/// 2. Sends `blinded = fragment XOR mask` (also encrypted).
/// 3. Enclave operates on blinded data; later the HSM removes the mask.
pub struct EncryptedBytes {
    data: Vec<FheUint8>,
}

impl EncryptedBytes {
    /// Encrypt a byte slice element-wise.
    pub fn encrypt(plaintext: &[u8], keys: &FheKeySet) -> Self {
        let data = plaintext
            .iter()
            .map(|&b| FheUint8::encrypt(b, &keys.client_key))
            .collect();
        Self { data }
    }

    /// Homomorphic XOR with another `EncryptedBytes` of the same length.
    ///
    /// Returns `Err` if lengths differ.
    pub fn xor(&self, other: &EncryptedBytes) -> Result<EncryptedBytes, HsmError> {
        if self.data.len() != other.data.len() {
            return Err(HsmError::DataLenRange);
        }
        let data = self
            .data
            .iter()
            .zip(other.data.iter())
            .map(|(a, b)| a ^ b)
            .collect();
        Ok(EncryptedBytes { data })
    }

    /// Decrypt the byte array.  Requires the secret client key.
    pub fn decrypt(&self, keys: &FheKeySet) -> Vec<u8> {
        self.data
            .iter()
            .map(|eb| eb.decrypt(&keys.client_key))
            .collect()
    }

    /// Length of the encrypted buffer (in bytes).
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns `true` if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Homomorphic AND with another `EncryptedBytes` of the same length.
    pub fn bitand(&self, other: &EncryptedBytes) -> Result<EncryptedBytes, HsmError> {
        if self.data.len() != other.data.len() {
            return Err(HsmError::DataLenRange);
        }
        let data = self
            .data
            .iter()
            .zip(other.data.iter())
            .map(|(a, b)| a & b)
            .collect();
        Ok(EncryptedBytes { data })
    }

    /// Homomorphic OR with another `EncryptedBytes` of the same length.
    pub fn bitor(&self, other: &EncryptedBytes) -> Result<EncryptedBytes, HsmError> {
        if self.data.len() != other.data.len() {
            return Err(HsmError::DataLenRange);
        }
        let data = self
            .data
            .iter()
            .zip(other.data.iter())
            .map(|(a, b)| a | b)
            .collect();
        Ok(EncryptedBytes { data })
    }

    /// Homomorphic NOT (bitwise complement) of each encrypted byte.
    pub fn bitnot(&self) -> EncryptedBytes {
        let data = self.data.iter().map(|a| !a).collect();
        EncryptedBytes { data }
    }
}

// ── Homomorphic risk scorer ───────────────────────────────────────────────────

/// Compute an encrypted risk score from encrypted event features.
///
/// The compute node adds encrypted feature weights without learning any
/// individual feature value or the resulting score.
pub struct FheRiskScorer;

impl FheRiskScorer {
    /// Aggregate `n` encrypted feature values into a combined risk score.
    ///
    /// `weights` are public (not sensitive); `feature_values` are encrypted.
    /// The result is an encrypted `FheUint32` the HSM can decrypt and threshold.
    pub fn score(encrypted_features: &[FheUint32], weights: &[u32]) -> Result<FheUint32, HsmError> {
        if encrypted_features.len() != weights.len() || encrypted_features.is_empty() {
            return Err(HsmError::ArgumentsBad);
        }

        // Weighted sum: Σ (w_i * feature_i)
        // The server multiplies each encrypted feature by its public weight,
        // then sums — all without decrypting any feature.
        let mut score = encrypted_features[0].clone() * weights[0];
        for (feat, &w) in encrypted_features[1..].iter().zip(weights[1..].iter()) {
            score = score + (feat.clone() * w);
        }
        Ok(score)
    }
}

/// Generate encrypted random bytes using the HSM's DRBG.
///
/// Produces random bytes via SP 800-90A HMAC_DRBG, then encrypts them
/// element-wise with FHE. Useful for generating encrypted masks/nonces.
pub fn encrypted_random(len: usize, keys: &FheKeySet) -> Result<EncryptedBytes, HsmError> {
    use zeroize::Zeroize;
    let mut random_bytes = vec![0u8; len];
    let mut drbg = crate::crypto::drbg::HmacDrbg::new()?;
    drbg.generate(&mut random_bytes)?;
    let encrypted = EncryptedBytes::encrypt(&random_bytes, keys);
    random_bytes.zeroize();
    Ok(encrypted)
}

/// Thread-safe wrapper for FheKeySet that handles server key activation.
///
/// The TFHE library requires `set_server_key()` to be called per-thread.
/// This wrapper ensures the server key is activated when needed.
pub struct ThreadSafeFheKeys {
    keys: Arc<FheKeySet>,
}

impl ThreadSafeFheKeys {
    /// Wrap a key set for thread-safe sharing.
    pub fn new(keys: FheKeySet) -> Self {
        Self {
            keys: Arc::new(keys),
        }
    }

    /// Activate the server key on the current thread and return a reference.
    pub fn activate(&self) -> &FheKeySet {
        self.keys.activate_server_key();
        &self.keys
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_counter_increment_and_decrypt() {
        let keys = FheKeySet::generate();
        keys.activate_server_key();

        let mut counter = EncryptedCounter::new(0, &keys);
        counter.increment(5, &keys);
        counter.increment(3, &keys);

        let value = counter.decrypt(&keys);
        assert_eq!(value, 8);
    }

    #[test]
    fn counter_limit_check() {
        let keys = FheKeySet::generate();
        keys.activate_server_key();

        let mut counter = EncryptedCounter::new(100, &keys);
        counter.increment(50, &keys);

        // Encrypted comparison: 150 > 200? → 0
        let over_200: u32 = counter.exceeds_limit(200, &keys).decrypt(&keys.client_key);
        assert_eq!(over_200, 0);

        // Encrypted comparison: 150 > 100? → 1
        let over_100: u32 = counter.exceeds_limit(100, &keys).decrypt(&keys.client_key);
        assert_eq!(over_100, 1);
    }

    #[test]
    fn encrypted_bytes_xor_roundtrip() {
        let keys = FheKeySet::generate();
        keys.activate_server_key();

        let data = b"secret_fragment!";
        let mask = b"random__mask____";

        let enc_data = EncryptedBytes::encrypt(data, &keys);
        let enc_mask = EncryptedBytes::encrypt(mask, &keys);

        // blind = data XOR mask
        let blinded = enc_data.xor(&enc_mask).unwrap();

        // unblind = blinded XOR mask = data
        let unblinded = blinded.xor(&enc_mask).unwrap();
        let recovered = unblinded.decrypt(&keys);

        assert_eq!(&recovered, data);
    }

    #[test]
    fn risk_score_weighted_sum() {
        let keys = FheKeySet::generate();
        keys.activate_server_key();

        let feature_values = [3u32, 5u32, 2u32];
        let weights = [10u32, 20u32, 5u32];
        // Expected: 3*10 + 5*20 + 2*5 = 30 + 100 + 10 = 140

        let enc_features: Vec<FheUint32> = feature_values
            .iter()
            .map(|&v| FheUint32::encrypt(v, &keys.client_key))
            .collect();

        let enc_score = FheRiskScorer::score(&enc_features, &weights).unwrap();
        let score: u32 = enc_score.decrypt(&keys.client_key);
        assert_eq!(score, 140);
    }

    #[test]
    fn encrypted_bytes_bitand() {
        let keys = FheKeySet::generate();
        keys.activate_server_key();

        let a = EncryptedBytes::encrypt(&[0xFF, 0x0F], &keys);
        let b = EncryptedBytes::encrypt(&[0xF0, 0xFF], &keys);
        let result = a.bitand(&b).unwrap();
        assert_eq!(result.decrypt(&keys), vec![0xF0, 0x0F]);
    }

    #[test]
    fn encrypted_bytes_bitor() {
        let keys = FheKeySet::generate();
        keys.activate_server_key();

        let a = EncryptedBytes::encrypt(&[0xF0, 0x00], &keys);
        let b = EncryptedBytes::encrypt(&[0x0F, 0xFF], &keys);
        let result = a.bitor(&b).unwrap();
        assert_eq!(result.decrypt(&keys), vec![0xFF, 0xFF]);
    }

    #[test]
    fn encrypted_bytes_bitnot() {
        let keys = FheKeySet::generate();
        keys.activate_server_key();

        let a = EncryptedBytes::encrypt(&[0xFF, 0x00], &keys);
        let result = a.bitnot();
        assert_eq!(result.decrypt(&keys), vec![0x00, 0xFF]);
    }

    #[test]
    fn encrypted_bytes_length_mismatch() {
        let keys = FheKeySet::generate();
        keys.activate_server_key();

        let a = EncryptedBytes::encrypt(&[0xFF], &keys);
        let b = EncryptedBytes::encrypt(&[0xFF, 0xFF], &keys);
        assert!(a.bitand(&b).is_err());
    }

    #[test]
    fn counter_is_below() {
        let keys = FheKeySet::generate();
        keys.activate_server_key();

        let counter = EncryptedCounter::new(50, &keys);
        let below_100: u32 = counter.is_below(100, &keys).decrypt(&keys.client_key);
        assert_eq!(below_100, 1);
        let below_25: u32 = counter.is_below(25, &keys).decrypt(&keys.client_key);
        assert_eq!(below_25, 0);
    }

    #[test]
    fn counter_equals() {
        let keys = FheKeySet::generate();
        keys.activate_server_key();

        let a = EncryptedCounter::new(42, &keys);
        let b = EncryptedCounter::new(42, &keys);
        let c = EncryptedCounter::new(99, &keys);

        let eq_ab: u32 = a.equals(&b).decrypt(&keys.client_key);
        assert_eq!(eq_ab, 1);
        let eq_ac: u32 = a.equals(&c).decrypt(&keys.client_key);
        assert_eq!(eq_ac, 0);
    }

    #[test]
    fn encrypted_random_nonzero() {
        let keys = FheKeySet::generate();
        keys.activate_server_key();

        let enc = encrypted_random(16, &keys).unwrap();
        let decrypted = enc.decrypt(&keys);
        assert_eq!(decrypted.len(), 16);
        // Random bytes should not be all zeros (probability 2^-128)
        assert!(!decrypted.iter().all(|&b| b == 0));
    }

    #[test]
    fn thread_safe_wrapper() {
        let keys = FheKeySet::generate();
        let safe = ThreadSafeFheKeys::new(keys);
        let k = safe.activate();

        let mut counter = EncryptedCounter::new(10, k);
        counter.increment(5, k);
        assert_eq!(counter.decrypt(k), 15);
    }
}
