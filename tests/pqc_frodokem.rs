// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! FrodoKEM encap/decap roundtrip and implicit-rejection tests.
//! Runs only when the `frodokem-kem` feature is enabled.

#![cfg(feature = "frodokem-kem")]

use craton_hsm::crypto::frodokem::{
    frodo_decapsulate, frodo_encapsulate, frodo_keygen, is_frodo_mechanism,
    mechanism_to_frodo_variant, FrodoVariant,
};
use craton_hsm::pkcs11_abi::constants::{
    CKM_FRODO_KEM_1344_AES, CKM_FRODO_KEM_640_AES, CKM_FRODO_KEM_976_AES,
};

#[test]
fn frodo640_aes_roundtrip() {
    let (sk, pk) = frodo_keygen(FrodoVariant::Frodo640Aes).unwrap();
    let (ct, ss_a) = frodo_encapsulate(&pk, FrodoVariant::Frodo640Aes).unwrap();
    let ss_b = frodo_decapsulate(sk.as_bytes(), &ct, FrodoVariant::Frodo640Aes).unwrap();
    assert_eq!(ss_a, ss_b);
    assert_eq!(ss_a.len(), 16); // FrodoKEM-640 SS = 128 bits
}

#[test]
fn frodo976_aes_roundtrip() {
    let (sk, pk) = frodo_keygen(FrodoVariant::Frodo976Aes).unwrap();
    let (ct, ss_a) = frodo_encapsulate(&pk, FrodoVariant::Frodo976Aes).unwrap();
    let ss_b = frodo_decapsulate(sk.as_bytes(), &ct, FrodoVariant::Frodo976Aes).unwrap();
    assert_eq!(ss_a, ss_b);
    assert_eq!(ss_a.len(), 24); // FrodoKEM-976 SS = 192 bits
}

#[test]
fn frodo1344_aes_roundtrip() {
    let (sk, pk) = frodo_keygen(FrodoVariant::Frodo1344Aes).unwrap();
    let (ct, ss_a) = frodo_encapsulate(&pk, FrodoVariant::Frodo1344Aes).unwrap();
    let ss_b = frodo_decapsulate(sk.as_bytes(), &ct, FrodoVariant::Frodo1344Aes).unwrap();
    assert_eq!(ss_a, ss_b);
    assert_eq!(ss_a.len(), 32); // FrodoKEM-1344 SS = 256 bits
}

#[test]
fn wrong_secret_key_yields_different_ss() {
    // Implicit rejection: wrong SK produces a pseudorandom (non-matching) SS.
    let (_sk1, pk) = frodo_keygen(FrodoVariant::Frodo640Aes).unwrap();
    let (sk2, _) = frodo_keygen(FrodoVariant::Frodo640Aes).unwrap();
    let (ct, ss_a) = frodo_encapsulate(&pk, FrodoVariant::Frodo640Aes).unwrap();
    let ss_b = frodo_decapsulate(sk2.as_bytes(), &ct, FrodoVariant::Frodo640Aes).unwrap();
    assert_ne!(ss_a, ss_b);
}

#[test]
fn tampered_ciphertext_yields_different_ss() {
    // FrodoKEM uses implicit rejection — a corrupted ciphertext produces a
    // pseudorandom SS, not an error.
    let (sk, pk) = frodo_keygen(FrodoVariant::Frodo640Aes).unwrap();
    let (mut ct, ss_a) = frodo_encapsulate(&pk, FrodoVariant::Frodo640Aes).unwrap();
    ct[0] ^= 0xFF;
    let ss_b = frodo_decapsulate(sk.as_bytes(), &ct, FrodoVariant::Frodo640Aes).unwrap();
    assert_ne!(ss_a, ss_b);
}

#[test]
fn two_encapsulations_differ() {
    // Each encap is randomized; two against the same pk must differ.
    let (_, pk) = frodo_keygen(FrodoVariant::Frodo640Aes).unwrap();
    let (ct1, _) = frodo_encapsulate(&pk, FrodoVariant::Frodo640Aes).unwrap();
    let (ct2, _) = frodo_encapsulate(&pk, FrodoVariant::Frodo640Aes).unwrap();
    assert_ne!(ct1, ct2);
}

#[test]
fn mechanism_dispatch() {
    assert_eq!(
        mechanism_to_frodo_variant(CKM_FRODO_KEM_640_AES),
        Some(FrodoVariant::Frodo640Aes)
    );
    assert_eq!(
        mechanism_to_frodo_variant(CKM_FRODO_KEM_976_AES),
        Some(FrodoVariant::Frodo976Aes)
    );
    assert_eq!(
        mechanism_to_frodo_variant(CKM_FRODO_KEM_1344_AES),
        Some(FrodoVariant::Frodo1344Aes)
    );
    assert!(is_frodo_mechanism(CKM_FRODO_KEM_640_AES));
    assert!(!is_frodo_mechanism(0));
}
