// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! NIST-standardized test vectors for cryptographic operations.
//!
//! This test file is parallel-safe (no global PKCS#11 state).

use craton_hsm::crypto::digest::compute_digest;
use craton_hsm::crypto::encrypt;
use craton_hsm::crypto::wrap;
use craton_hsm::pkcs11_abi::constants::*;

// ── SHA-2 NIST FIPS 180-4 test vectors ─────────────────────────────────────

#[test]
fn test_sha256_nist_abc() {
    let result = compute_digest(CKM_SHA256, b"abc").unwrap();
    assert_eq!(
        hex::encode(&result),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn test_sha256_nist_empty() {
    let result = compute_digest(CKM_SHA256, b"").unwrap();
    assert_eq!(
        hex::encode(&result),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn test_sha384_nist_abc() {
    let result = compute_digest(CKM_SHA384, b"abc").unwrap();
    assert_eq!(
        hex::encode(&result),
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
    );
}

#[test]
fn test_sha512_nist_abc() {
    let result = compute_digest(CKM_SHA512, b"abc").unwrap();
    assert_eq!(result.len(), 64);
    let expected = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
    assert_eq!(hex::encode(&result), expected);
}

// ── SHA-3 NIST FIPS 202 test vectors ───────────────────────────────────────

#[test]
fn test_sha3_256_nist_abc() {
    let result = compute_digest(CKM_SHA3_256, b"abc").unwrap();
    assert_eq!(
        hex::encode(&result),
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
    );
}

#[test]
fn test_sha3_256_nist_empty() {
    let result = compute_digest(CKM_SHA3_256, b"").unwrap();
    assert_eq!(
        hex::encode(&result),
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    );
}

#[test]
fn test_sha3_384_nist_abc() {
    let result = compute_digest(CKM_SHA3_384, b"abc").unwrap();
    assert_eq!(
        hex::encode(&result),
        "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"
    );
}

#[test]
fn test_sha3_512_nist_abc() {
    let result = compute_digest(CKM_SHA3_512, b"abc").unwrap();
    assert_eq!(result.len(), 64);
    let expected = "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0";
    assert_eq!(hex::encode(&result), expected);
}

// ── RFC 3394 AES Key Wrap test vectors ─────────────────────────────────────

#[test]
fn test_rfc3394_4_1_aes128_wrap_128bit_key() {
    let kek = hex::decode("000102030405060708090A0B0C0D0E0F").unwrap();
    let key_data = hex::decode("00112233445566778899AABBCCDDEEFF").unwrap();
    let expected = hex::decode("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5").unwrap();

    let wrapped = wrap::aes_key_wrap(&kek, &key_data, false).unwrap();
    assert_eq!(wrapped, expected);

    let unwrapped = wrap::aes_key_unwrap(&kek, &wrapped, false).unwrap();
    assert_eq!(unwrapped, key_data);
}

#[test]
fn test_rfc3394_4_3_aes192_wrap_128bit_key() {
    let kek = hex::decode("000102030405060708090A0B0C0D0E0F1011121314151617").unwrap();
    let key_data = hex::decode("00112233445566778899AABBCCDDEEFF").unwrap();
    let expected = hex::decode("96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D").unwrap();

    let wrapped = wrap::aes_key_wrap(&kek, &key_data, false).unwrap();
    assert_eq!(wrapped, expected);

    let unwrapped = wrap::aes_key_unwrap(&kek, &wrapped, false).unwrap();
    assert_eq!(unwrapped, key_data);
}

#[test]
fn test_rfc3394_4_5_aes256_wrap_128bit_key() {
    let kek =
        hex::decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F").unwrap();
    let key_data = hex::decode("00112233445566778899AABBCCDDEEFF").unwrap();
    let expected = hex::decode("64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7").unwrap();

    let wrapped = wrap::aes_key_wrap(&kek, &key_data, false).unwrap();
    assert_eq!(wrapped, expected);

    let unwrapped = wrap::aes_key_unwrap(&kek, &wrapped, false).unwrap();
    assert_eq!(unwrapped, key_data);
}

#[test]
fn test_rfc3394_4_6_aes256_wrap_256bit_key() {
    let kek =
        hex::decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F").unwrap();
    let key_data =
        hex::decode("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F").unwrap();
    let expected = hex::decode(
        "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21",
    )
    .unwrap();

    let wrapped = wrap::aes_key_wrap(&kek, &key_data, false).unwrap();
    assert_eq!(wrapped, expected);

    let unwrapped = wrap::aes_key_unwrap(&kek, &wrapped, false).unwrap();
    assert_eq!(unwrapped, key_data);
}

// ── AES-GCM roundtrip tests ───────────────────────────────────────────────

#[test]
fn test_gcm_encrypt_decrypt_roundtrip() {
    let key = [0x42u8; 32];
    encrypt::force_reset_all_counters();
    let plaintext = b"Hello, NIST test vectors!";
    let ciphertext = encrypt::aes_256_gcm_encrypt(&key, plaintext).unwrap();
    let decrypted = encrypt::aes_256_gcm_decrypt(&key, &ciphertext).unwrap();
    assert_eq!(decrypted, plaintext);
    encrypt::force_reset_all_counters();
}

#[test]
fn test_gcm_different_plaintexts_different_ciphertexts() {
    let key = [0x55u8; 32];
    encrypt::force_reset_all_counters();
    let ct1 = encrypt::aes_256_gcm_encrypt(&key, b"plaintext A").unwrap();
    let ct2 = encrypt::aes_256_gcm_encrypt(&key, b"plaintext B").unwrap();
    assert_ne!(ct1, ct2);
    encrypt::force_reset_all_counters();
}
