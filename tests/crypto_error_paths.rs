// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Tests for crypto error paths and edge cases.
//!
//! This test file is parallel-safe (no global PKCS#11 state).

use craton_hsm::crypto::encrypt;
use craton_hsm::crypto::keygen;
use craton_hsm::error::HsmError;

// ── AES-GCM error paths ───────────────────────────────────────────────────

#[test]
fn test_gcm_invalid_key_16_bytes() {
    let key = [0u8; 16];
    assert!(matches!(
        encrypt::aes_256_gcm_encrypt(&key, b"data"),
        Err(HsmError::KeySizeRange)
    ));
}

#[test]
fn test_gcm_invalid_key_0_bytes() {
    assert!(matches!(
        encrypt::aes_256_gcm_encrypt(&[], b"data"),
        Err(HsmError::KeySizeRange)
    ));
}

#[test]
fn test_gcm_invalid_key_33_bytes() {
    let key = [0u8; 33];
    assert!(matches!(
        encrypt::aes_256_gcm_encrypt(&key, b"data"),
        Err(HsmError::KeySizeRange)
    ));
}

#[test]
fn test_gcm_decrypt_too_short() {
    let key = [0x42u8; 32];
    // Minimum is 28 bytes (12 nonce + 16 tag)
    assert!(matches!(
        encrypt::aes_256_gcm_decrypt(&key, &[0u8; 27]),
        Err(HsmError::EncryptedDataInvalid)
    ));
}

#[test]
fn test_gcm_decrypt_empty() {
    let key = [0x42u8; 32];
    assert!(matches!(
        encrypt::aes_256_gcm_decrypt(&key, &[]),
        Err(HsmError::EncryptedDataInvalid)
    ));
}

#[test]
fn test_gcm_decrypt_tampered_tag() {
    let key = [0x99u8; 32];
    encrypt::force_reset_all_counters();
    let ct = encrypt::aes_256_gcm_encrypt(&key, b"secret data").unwrap();
    let mut tampered = ct.clone();
    // Flip last byte (part of GCM auth tag)
    let last = tampered.len() - 1;
    tampered[last] ^= 0xFF;
    assert!(encrypt::aes_256_gcm_decrypt(&key, &tampered).is_err());
    encrypt::force_reset_all_counters();
}

#[test]
fn test_gcm_decrypt_tampered_ciphertext() {
    let key = [0xAAu8; 32];
    encrypt::force_reset_all_counters();
    let ct = encrypt::aes_256_gcm_encrypt(&key, b"secret data").unwrap();
    let mut tampered = ct.clone();
    // Flip a byte in the ciphertext body (after 12-byte nonce)
    if tampered.len() > 14 {
        tampered[14] ^= 0xFF;
    }
    assert!(encrypt::aes_256_gcm_decrypt(&key, &tampered).is_err());
    encrypt::force_reset_all_counters();
}

#[test]
fn test_gcm_decrypt_tampered_nonce() {
    let key = [0xBBu8; 32];
    encrypt::force_reset_all_counters();
    let ct = encrypt::aes_256_gcm_encrypt(&key, b"secret data").unwrap();
    let mut tampered = ct.clone();
    // Flip first byte of nonce
    tampered[0] ^= 0xFF;
    assert!(encrypt::aes_256_gcm_decrypt(&key, &tampered).is_err());
    encrypt::force_reset_all_counters();
}

#[test]
fn test_gcm_aad_mismatch() {
    let key = [0xCCu8; 32];
    encrypt::force_reset_all_counters();
    let ct = encrypt::aes_256_gcm_encrypt_with_aad(&key, b"data", b"context_a").unwrap();
    assert!(encrypt::aes_256_gcm_decrypt_with_aad(&key, &ct, b"context_b").is_err());
    encrypt::force_reset_all_counters();
}

// ── AES-CBC error paths ───────────────────────────────────────────────────

#[test]
fn test_cbc_zero_iv_rejected() {
    let key = [0x42u8; 32];
    let iv = [0u8; 16];
    assert!(matches!(
        encrypt::aes_cbc_encrypt(&key, &iv, b"data"),
        Err(HsmError::MechanismParamInvalid)
    ));
}

#[test]
fn test_cbc_invalid_iv_length_8() {
    let key = [0x42u8; 32];
    let iv = [1u8; 8];
    assert!(matches!(
        encrypt::aes_cbc_encrypt(&key, &iv, b"data"),
        Err(HsmError::MechanismParamInvalid)
    ));
}

#[test]
fn test_cbc_invalid_iv_length_0() {
    let key = [0x42u8; 32];
    assert!(matches!(
        encrypt::aes_cbc_encrypt(&key, &[], b"data"),
        Err(HsmError::MechanismParamInvalid)
    ));
}

#[test]
fn test_cbc_invalid_key_size_20() {
    let key = [0x42u8; 20];
    let iv = [1u8; 16];
    assert!(encrypt::aes_cbc_encrypt(&key, &iv, b"data").is_err());
}

// ── AES-CTR error paths ───────────────────────────────────────────────────

#[test]
fn test_ctr_zero_iv_rejected() {
    let key = [0x42u8; 32];
    let iv = [0u8; 16];
    assert!(matches!(
        encrypt::aes_ctr_encrypt(&key, &iv, b"data"),
        Err(HsmError::MechanismParamInvalid)
    ));
}

#[test]
fn test_ctr_invalid_iv_length() {
    let key = [0x42u8; 32];
    let iv = [1u8; 8];
    assert!(matches!(
        encrypt::aes_ctr_encrypt(&key, &iv, b"data"),
        Err(HsmError::MechanismParamInvalid)
    ));
}

#[test]
fn test_ctr_invalid_key_size() {
    let key = [0x42u8; 20];
    let iv = [1u8; 16];
    assert!(matches!(
        encrypt::aes_ctr_encrypt(&key, &iv, b"data"),
        Err(HsmError::KeySizeRange)
    ));
}

// ── Key generation error paths ─────────────────────────────────────────────

#[test]
fn test_aes_keygen_invalid_length_15() {
    assert!(matches!(
        keygen::generate_aes_key(15, false),
        Err(HsmError::KeySizeRange)
    ));
}

#[test]
fn test_aes_keygen_invalid_length_20() {
    assert!(matches!(
        keygen::generate_aes_key(20, false),
        Err(HsmError::KeySizeRange)
    ));
}

#[test]
fn test_rsa_keygen_invalid_size_1024() {
    assert!(matches!(
        keygen::generate_rsa_key_pair(1024, false),
        Err(HsmError::KeySizeRange)
    ));
}

#[test]
fn test_fips_rejects_aes128() {
    assert!(matches!(
        keygen::generate_aes_key(16, true),
        Err(HsmError::MechanismParamInvalid)
    ));
}

#[test]
fn test_fips_rejects_rsa_2048() {
    assert!(matches!(
        keygen::generate_rsa_key_pair(2048, true),
        Err(HsmError::MechanismParamInvalid)
    ));
}
