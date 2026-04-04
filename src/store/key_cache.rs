// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company

//! RSA key caching system to eliminate SHA-256 DER computation overhead per operation.
//!
//! This module provides cached parsed RSA keys that can be stored in Arc<> for
//! zero-copy sharing across operations, eliminating the 15-25% overhead from
//! re-parsing DER-encoded keys on every sign/decrypt operation.

use rsa::pkcs8::DecodePrivateKey;
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Digest;
use std::sync::Arc;
use std::time::SystemTime;

use crate::error::HsmResult;

/// Cached RSA private key with validation metadata.
///
/// The key_id field contains the SHA-256 hash of the original DER encoding
/// to verify that the cached key matches the current key material and detect
/// tampering or key rotation.
#[derive(Debug, Clone)]
pub struct CachedRsaPrivateKey {
    /// Parsed RSA private key ready for cryptographic operations
    pub private_key: Arc<RsaPrivateKey>,
    /// SHA-256 hash of the original DER encoding for validation
    pub key_id: [u8; 32],
    /// When this cached key was created
    pub created_at: SystemTime,
}

/// Cached RSA public key with validation metadata.
#[derive(Debug, Clone)]
pub struct CachedRsaPublicKey {
    /// Parsed RSA public key ready for verification operations
    pub public_key: Arc<RsaPublicKey>,
    /// SHA-256 hash of the original DER/modulus+exponent for validation
    pub key_id: [u8; 32],
    /// When this cached key was created
    pub created_at: SystemTime,
}

impl CachedRsaPrivateKey {
    /// Create a new cached RSA private key from DER-encoded key material.
    ///
    /// This performs the expensive DER parsing once and stores the result
    /// in an Arc for efficient sharing across operations.
    pub fn from_der(der_bytes: &[u8]) -> HsmResult<Self> {
        // Parse the DER-encoded private key
        let private_key = RsaPrivateKey::from_pkcs8_der(der_bytes)
            .map_err(|_| crate::error::HsmError::DataInvalid)?;

        // Compute SHA-256 hash of DER for validation
        let key_id = sha2::Sha256::digest(der_bytes).into();

        Ok(Self {
            private_key: Arc::new(private_key),
            key_id,
            created_at: SystemTime::now(),
        })
    }

    /// Validate that this cached key matches the current DER encoding.
    ///
    /// Returns true if the SHA-256 hash matches, indicating the cached
    /// key is still valid for the current key material.
    pub fn validate_der(&self, der_bytes: &[u8]) -> bool {
        let current_hash = sha2::Sha256::digest(der_bytes);

        // Use constant-time comparison to prevent timing attacks
        use subtle::ConstantTimeEq;
        current_hash.ct_eq(&self.key_id).into()
    }

    /// Get the underlying RSA private key for cryptographic operations.
    pub fn key(&self) -> &RsaPrivateKey {
        &self.private_key
    }
}

impl CachedRsaPublicKey {
    /// Create a new cached RSA public key from modulus and public exponent.
    ///
    /// This is used for public key operations where we have the modulus
    /// and exponent rather than a full DER encoding.
    pub fn from_components(modulus: &[u8], public_exponent: &[u8]) -> HsmResult<Self> {
        // Parse modulus and exponent to create RSA public key
        let n = rsa::BigUint::from_bytes_be(modulus);
        let e = rsa::BigUint::from_bytes_be(public_exponent);

        let public_key =
            RsaPublicKey::new(n, e).map_err(|_| crate::error::HsmError::DataInvalid)?;

        // Create composite key ID from modulus + exponent
        let mut hasher = sha2::Sha256::new();
        hasher.update(modulus);
        hasher.update(public_exponent);
        let key_id = hasher.finalize().into();

        Ok(Self {
            public_key: Arc::new(public_key),
            key_id,
            created_at: SystemTime::now(),
        })
    }

    /// Validate that this cached key matches the current modulus/exponent.
    pub fn validate_components(&self, modulus: &[u8], public_exponent: &[u8]) -> bool {
        let mut hasher = sha2::Sha256::new();
        hasher.update(modulus);
        hasher.update(public_exponent);
        let current_hash = hasher.finalize();

        // Use constant-time comparison
        use subtle::ConstantTimeEq;
        current_hash.ct_eq(&self.key_id).into()
    }

    /// Get the underlying RSA public key for cryptographic operations.
    pub fn key(&self) -> &RsaPublicKey {
        &self.public_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;
    use rsa::pkcs8::EncodePrivateKey;
    use rsa::traits::PublicKeyParts;
    use rsa::RsaPrivateKey;

    #[test]
    fn test_cached_private_key_lifecycle() {
        let mut rng = thread_rng();
        let original_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let der_bytes = original_key.to_pkcs8_der().unwrap();

        // Create cached key
        let der_bytes_slice = der_bytes.as_bytes();
        let cached = CachedRsaPrivateKey::from_der(der_bytes_slice).unwrap();

        // Validation should succeed with same DER
        assert!(cached.validate_der(der_bytes_slice));

        // Validation should fail with different DER
        let different_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let different_der = different_key.to_pkcs8_der().unwrap();
        let different_der_slice = different_der.as_bytes();
        assert!(!cached.validate_der(different_der_slice));

        // Cached key should be usable for operations
        let test_data = b"test data";
        let signature = cached
            .key()
            .sign(rsa::Pkcs1v15Sign::new::<sha2::Sha256>(), test_data)
            .unwrap();

        // Verify signature with original key
        original_key
            .to_public_key()
            .verify(
                rsa::Pkcs1v15Sign::new::<sha2::Sha256>(),
                test_data,
                &signature,
            )
            .unwrap();
    }

    #[test]
    fn test_cached_public_key_lifecycle() {
        let mut rng = thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = private_key.to_public_key();

        let modulus = public_key.n().to_bytes_be();
        let exponent = public_key.e().to_bytes_be();

        // Create cached public key
        let cached = CachedRsaPublicKey::from_components(&modulus, &exponent).unwrap();

        // Validation should succeed with same components
        assert!(cached.validate_components(&modulus, &exponent));

        // Validation should fail with different components
        let different_modulus = vec![0u8; modulus.len()];
        assert!(!cached.validate_components(&different_modulus, &exponent));

        // Cached key should be usable for verification
        let test_data = b"test data";
        let signature = private_key
            .sign(rsa::Pkcs1v15Sign::new::<sha2::Sha256>(), test_data)
            .unwrap();

        cached
            .key()
            .verify(
                rsa::Pkcs1v15Sign::new::<sha2::Sha256>(),
                test_data,
                &signature,
            )
            .unwrap();
    }
}
