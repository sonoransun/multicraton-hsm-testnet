// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! GCM counter safety tests verifying nonce uniqueness guarantees.
//!
//! This test file is parallel-safe (no global PKCS#11 state).
//! Uses unique keys per test to avoid cross-test interference.

use craton_hsm::crypto::encrypt;
use std::collections::HashSet;

/// Generate a unique test key to avoid counter interference.
fn unique_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
    key
}

#[test]
fn test_gcm_nonce_uniqueness_1000_ops() {
    let key = unique_key();
    let mut nonces = HashSet::new();

    for _ in 0..1000 {
        let ct = encrypt::aes_256_gcm_encrypt(&key, b"test").unwrap();
        // First 12 bytes are the nonce
        let nonce: [u8; 12] = ct[..12].try_into().unwrap();
        assert!(
            nonces.insert(nonce),
            "Nonce collision detected! This is a critical security violation."
        );
    }
    assert_eq!(nonces.len(), 1000);
    encrypt::remove_gcm_counter(&key);
}

#[test]
fn test_gcm_prefix_stable_within_session() {
    let key = unique_key();
    let mut prefixes = HashSet::new();

    for _ in 0..100 {
        let ct = encrypt::aes_256_gcm_encrypt(&key, b"test").unwrap();
        let prefix: [u8; 4] = ct[..4].try_into().unwrap();
        prefixes.insert(prefix);
    }
    // All nonces for the same key should share the same 4-byte prefix
    assert_eq!(
        prefixes.len(),
        1,
        "Expected all nonces for the same key to share the same prefix"
    );
    encrypt::remove_gcm_counter(&key);
}

#[test]
fn test_gcm_counter_monotonic() {
    let key = unique_key();
    let mut prev_counter = 0u64;

    for i in 0..100 {
        let ct = encrypt::aes_256_gcm_encrypt(&key, b"test").unwrap();
        // Counter is bytes 4..12 of the nonce, big-endian
        let counter = u64::from_be_bytes(ct[4..12].try_into().unwrap());
        if i > 0 {
            assert!(
                counter > prev_counter,
                "Counter must be monotonically increasing: {} <= {}",
                counter,
                prev_counter
            );
        }
        prev_counter = counter;
    }
    encrypt::remove_gcm_counter(&key);
}

#[test]
fn test_gcm_different_keys_different_prefixes() {
    let key_a = unique_key();
    let key_b = unique_key();

    let ct_a = encrypt::aes_256_gcm_encrypt(&key_a, b"test").unwrap();
    let ct_b = encrypt::aes_256_gcm_encrypt(&key_b, b"test").unwrap();

    let prefix_a: [u8; 4] = ct_a[..4].try_into().unwrap();
    let prefix_b: [u8; 4] = ct_b[..4].try_into().unwrap();

    // Different keys should get different random prefixes (with overwhelming probability)
    // The probability of collision is 1/2^32 ≈ 2.3e-10
    assert_ne!(
        prefix_a, prefix_b,
        "Different keys should have different nonce prefixes (collision probability ~2^-32)"
    );

    encrypt::remove_gcm_counter(&key_a);
    encrypt::remove_gcm_counter(&key_b);
}

#[test]
fn test_gcm_counter_survives_key_removal_and_recreation() {
    let key = unique_key();

    // Encrypt once
    let ct1 = encrypt::aes_256_gcm_encrypt(&key, b"test").unwrap();
    let nonce1: [u8; 12] = ct1[..12].try_into().unwrap();

    // Remove the counter
    encrypt::remove_gcm_counter(&key);

    // Encrypt again -- should get a new prefix (different random value)
    let ct2 = encrypt::aes_256_gcm_encrypt(&key, b"test").unwrap();
    let nonce2: [u8; 12] = ct2[..12].try_into().unwrap();

    // The nonces should differ (different prefix after reset)
    assert_ne!(nonce1, nonce2);

    encrypt::remove_gcm_counter(&key);
}
