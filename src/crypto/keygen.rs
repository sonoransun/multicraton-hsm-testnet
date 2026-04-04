// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
use zeroize::Zeroizing;

use crate::error::{HsmError, HsmResult};
use crate::store::key_material::RawKeyMaterial;

/// Generate cryptographic random bytes using the FIPS-approved HMAC_DRBG.
///
/// All key generation MUST use this function (not OsRng directly) so that
/// randomness passes through the SP 800-90A DRBG with health testing and
/// continuous output comparison.
///
/// A fresh DRBG is instantiated per call, seeded from OsRng. This is
/// intentional: each key gets independently seeded randomness, and modern
/// OS entropy sources (getrandom/BCryptGenRandom) do not exhaust under load.
/// Sharing a single DRBG across keys would create a correlation risk if the
/// DRBG's internal state were ever compromised.
fn generate_random_bytes(out: &mut [u8]) -> HsmResult<()> {
    let mut drbg = crate::crypto::drbg::HmacDrbg::new()?;
    drbg.generate(out)
}

use crate::crypto::drbg::DrbgRng;

/// Generate an AES key of the specified length (16, 24, or 32 bytes).
/// If `fips_mode` is true, AES-128 (16 bytes) is rejected per FIPS 140-3.
pub fn generate_aes_key(key_len_bytes: usize, fips_mode: bool) -> HsmResult<RawKeyMaterial> {
    match key_len_bytes {
        16 | 24 | 32 => {}
        _ => return Err(HsmError::KeySizeRange),
    }
    if fips_mode && key_len_bytes == 16 {
        return Err(HsmError::MechanismParamInvalid);
    }

    // Use Zeroizing<Vec<u8>> to ensure the intermediate buffer is scrubbed
    // even if RawKeyMaterial::new() triggers a reallocation. Without this,
    // the allocator could leave copies of key bytes in freed heap memory.
    let mut key = Zeroizing::new(vec![0u8; key_len_bytes]);
    generate_random_bytes(&mut key)?;
    // Move out of Zeroizing into RawKeyMaterial (which handles mlock + zeroize-on-drop).
    // The Zeroizing wrapper will zeroize its copy on drop.
    Ok(RawKeyMaterial::new(key.to_vec()))
}

/// Generate an RSA key pair. Returns (private_key_der, public_modulus, public_exponent).
/// If `fips_mode` is true, RSA key sizes below 3072 are rejected per FIPS 140-3.
pub fn generate_rsa_key_pair(
    modulus_bits: u32,
    fips_mode: bool,
) -> HsmResult<(RawKeyMaterial, Vec<u8>, Vec<u8>)> {
    use rsa::traits::PublicKeyParts;
    use rsa::{pkcs8::EncodePrivateKey, RsaPrivateKey};

    match modulus_bits {
        2048 | 3072 | 4096 => {}
        _ => return Err(HsmError::KeySizeRange),
    }
    if fips_mode && modulus_bits < 3072 {
        return Err(HsmError::MechanismParamInvalid);
    }

    let mut rng = DrbgRng::new()?;
    let private_key =
        RsaPrivateKey::new(&mut rng, modulus_bits as usize).map_err(|_| HsmError::GeneralError)?;

    let modulus = private_key.n().to_bytes_be();
    let pub_exp = private_key.e().to_bytes_be();

    let der = private_key
        .to_pkcs8_der()
        .map_err(|_| HsmError::GeneralError)?;

    // Move DER bytes directly into RawKeyMaterial — avoid unnecessary clone
    // that would create an extra unzeroized copy in memory (fix #16).
    // RawKeyMaterial handles mlock + zeroize-on-drop for the key material.
    let result = RawKeyMaterial::new(der.as_bytes().to_vec());

    Ok((result, modulus, pub_exp))
}

/// Generate EC key pair for P-256. Returns (private_key_bytes, public_key_sec1_uncompressed).
pub fn generate_ec_p256_key_pair() -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
    use elliptic_curve::sec1::ToEncodedPoint;
    use p256::SecretKey;

    let mut rng = DrbgRng::new()?;
    let secret_key = SecretKey::random(&mut rng);
    let public_key = secret_key.public_key();
    let pub_point = public_key.to_encoded_point(false);

    Ok((
        RawKeyMaterial::new(secret_key.to_bytes().to_vec()),
        pub_point.as_bytes().to_vec(),
    ))
}

/// Generate EC key pair for P-384. Returns (private_key_bytes, public_key_sec1_uncompressed).
pub fn generate_ec_p384_key_pair() -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
    use elliptic_curve::sec1::ToEncodedPoint;
    use p384::SecretKey;

    let mut rng = DrbgRng::new()?;
    let secret_key = SecretKey::random(&mut rng);
    let public_key = secret_key.public_key();
    let pub_point = public_key.to_encoded_point(false);

    Ok((
        RawKeyMaterial::new(secret_key.to_bytes().to_vec()),
        pub_point.as_bytes().to_vec(),
    ))
}

/// Generate Ed25519 key pair. Returns (private_key_bytes, public_key_bytes).
pub fn generate_ed25519_key_pair() -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
    use ed25519_dalek::SigningKey;

    let mut rng = DrbgRng::new()?;
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();

    Ok((
        RawKeyMaterial::new(signing_key.to_bytes().to_vec()),
        verifying_key.to_bytes().to_vec(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_key_lengths() {
        // Valid lengths succeed
        assert!(generate_aes_key(16, false).is_ok());
        assert!(generate_aes_key(24, false).is_ok());
        assert!(generate_aes_key(32, false).is_ok());

        // Invalid lengths fail
        assert!(generate_aes_key(15, false).is_err());
        assert!(generate_aes_key(20, false).is_err());
        assert!(generate_aes_key(33, false).is_err());
    }

    #[test]
    fn test_fips_rejects_aes128() {
        let result = generate_aes_key(16, true);
        assert!(result.is_err());
        // AES-256 should still work in FIPS mode
        assert!(generate_aes_key(32, true).is_ok());
    }

    #[test]
    fn test_rsa_valid_sizes() {
        // 2048, 3072, 4096 succeed (only test 2048 to keep test fast)
        let (priv_key, modulus, pub_exp) = generate_rsa_key_pair(2048, false).unwrap();
        assert!(!priv_key.is_empty());
        assert!(!modulus.is_empty());
        assert!(!pub_exp.is_empty());
    }

    #[test]
    fn test_rsa_invalid_sizes() {
        assert!(generate_rsa_key_pair(1024, false).is_err());
        assert!(generate_rsa_key_pair(512, false).is_err());
        assert!(generate_rsa_key_pair(8192, false).is_err());
    }

    #[test]
    fn test_fips_rejects_rsa_2048() {
        let result = generate_rsa_key_pair(2048, true);
        assert!(result.is_err());
        // RSA-3072 should work in FIPS mode (but skip to save time)
    }

    #[test]
    fn test_ec_p256_key_format() {
        let (private_key, public_key) = generate_ec_p256_key_pair().unwrap();
        // P-256 private key is 32 bytes
        assert_eq!(private_key.len(), 32);
        // P-256 uncompressed public key is 65 bytes (04 || x || y)
        assert_eq!(public_key.len(), 65);
        assert_eq!(public_key[0], 0x04);
    }

    #[test]
    fn test_ec_p384_key_format() {
        let (private_key, public_key) = generate_ec_p384_key_pair().unwrap();
        // P-384 private key is 48 bytes
        assert_eq!(private_key.len(), 48);
        // P-384 uncompressed public key is 97 bytes (04 || x || y)
        assert_eq!(public_key.len(), 97);
        assert_eq!(public_key[0], 0x04);
    }

    #[test]
    fn test_ed25519_key_format() {
        let (private_key, public_key) = generate_ed25519_key_pair().unwrap();
        // Ed25519 private key is 32 bytes
        assert_eq!(private_key.len(), 32);
        // Ed25519 public key is 32 bytes
        assert_eq!(public_key.len(), 32);
    }

    #[test]
    fn test_keys_are_random() {
        // Two AES-256 keys must differ
        let key1 = generate_aes_key(32, false).unwrap();
        let key2 = generate_aes_key(32, false).unwrap();
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }
}
