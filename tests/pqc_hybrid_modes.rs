// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Roundtrip tests for the three additional hybrid KEM constructions
//! (X25519+ML-KEM-1024, P-256+ML-KEM-768, P-384+ML-KEM-1024) plus the
//! Ed25519+ML-DSA-65 composite signature. Parallel-safe.

#![cfg(feature = "hybrid-kem")]

use craton_hsm::crypto::hybrid::{
    hybrid_kem_decapsulate_by_mechanism, hybrid_kem_encapsulate_by_mechanism,
    hybrid_kem_keygen_by_mechanism, hybrid_p256_mlkem768_decapsulate,
    hybrid_p256_mlkem768_encapsulate, hybrid_p256_mlkem768_keygen,
    hybrid_p384_mlkem1024_decapsulate, hybrid_p384_mlkem1024_encapsulate,
    hybrid_p384_mlkem1024_keygen, hybrid_x25519_mlkem1024_decapsulate,
    hybrid_x25519_mlkem1024_encapsulate, hybrid_x25519_mlkem1024_keygen,
    is_new_hybrid_kem_mechanism,
};
use craton_hsm::crypto::pqc::{
    hybrid_ed25519_mldsa65_sign, hybrid_ed25519_mldsa65_verify, ml_dsa_keygen, MlDsaVariant,
};
use craton_hsm::pkcs11_abi::constants::{
    CKM_HYBRID_P256_MLKEM768, CKM_HYBRID_P384_MLKEM1024, CKM_HYBRID_X25519_MLKEM1024,
};

// ============================================================================
// X25519 + ML-KEM-1024
// ============================================================================

#[test]
fn x25519_mlkem1024_roundtrip() {
    let (sk, pk) = hybrid_x25519_mlkem1024_keygen().unwrap();
    // 32 (X25519 pk) + 1568 (ML-KEM-1024 ek) = 1600 bytes
    assert_eq!(pk.len(), 1600);
    let (ct, ss_a) = hybrid_x25519_mlkem1024_encapsulate(&pk).unwrap();
    assert_eq!(ct.len(), 1600);
    assert_eq!(ss_a.len(), 32);
    let ss_b = hybrid_x25519_mlkem1024_decapsulate(&sk, &ct).unwrap();
    assert_eq!(ss_a, ss_b);
}

#[test]
fn x25519_mlkem1024_wrong_sk_differs() {
    let (_, pk) = hybrid_x25519_mlkem1024_keygen().unwrap();
    let (sk2, _) = hybrid_x25519_mlkem1024_keygen().unwrap();
    let (ct, ss_a) = hybrid_x25519_mlkem1024_encapsulate(&pk).unwrap();
    let ss_b = hybrid_x25519_mlkem1024_decapsulate(&sk2, &ct).unwrap();
    assert_ne!(ss_a, ss_b);
}

// ============================================================================
// P-256 + ML-KEM-768 (CNSA 2.0)
// ============================================================================

#[test]
fn p256_mlkem768_roundtrip() {
    let (sk, pk) = hybrid_p256_mlkem768_keygen().unwrap();
    // 65 (SEC1 uncompressed P-256) + 1184 (ML-KEM-768 ek) = 1249
    assert_eq!(pk.len(), 1249);
    let (ct, ss_a) = hybrid_p256_mlkem768_encapsulate(&pk).unwrap();
    assert_eq!(ct.len(), 65 + 1088); // 1153
    assert_eq!(ss_a.len(), 32);
    let ss_b = hybrid_p256_mlkem768_decapsulate(&sk, &ct).unwrap();
    assert_eq!(ss_a, ss_b);
}

// ============================================================================
// P-384 + ML-KEM-1024 (TOP SECRET aligned)
// ============================================================================

#[test]
fn p384_mlkem1024_roundtrip() {
    let (sk, pk) = hybrid_p384_mlkem1024_keygen().unwrap();
    // 97 (SEC1 uncompressed P-384) + 1568 (ML-KEM-1024 ek) = 1665
    assert_eq!(pk.len(), 1665);
    let (ct, ss_a) = hybrid_p384_mlkem1024_encapsulate(&pk).unwrap();
    assert_eq!(ct.len(), 97 + 1568); // 1665
    assert_eq!(ss_a.len(), 32);
    let ss_b = hybrid_p384_mlkem1024_decapsulate(&sk, &ct).unwrap();
    assert_eq!(ss_a, ss_b);
}

// ============================================================================
// Cross-variant domain separation
// ============================================================================

#[test]
fn mechanism_dispatch_exhaustive() {
    assert!(is_new_hybrid_kem_mechanism(CKM_HYBRID_X25519_MLKEM1024));
    assert!(is_new_hybrid_kem_mechanism(CKM_HYBRID_P256_MLKEM768));
    assert!(is_new_hybrid_kem_mechanism(CKM_HYBRID_P384_MLKEM1024));
    assert!(!is_new_hybrid_kem_mechanism(0));
}

#[test]
fn mechanism_dispatch_roundtrips() {
    for mech in [
        CKM_HYBRID_X25519_MLKEM1024,
        CKM_HYBRID_P256_MLKEM768,
        CKM_HYBRID_P384_MLKEM1024,
    ] {
        let (sk, pk) = hybrid_kem_keygen_by_mechanism(mech).unwrap();
        let (ct, ss_a) = hybrid_kem_encapsulate_by_mechanism(mech, &pk).unwrap();
        let ss_b = hybrid_kem_decapsulate_by_mechanism(mech, &sk, &ct).unwrap();
        assert_eq!(ss_a, ss_b, "mechanism 0x{:X} roundtrip mismatch", mech);
    }
}

// ============================================================================
// Ed25519 + ML-DSA-65 composite signature
// ============================================================================

#[test]
fn ed25519_mldsa65_composite_sign_verify() {
    let (ed_sk, ed_pk) = craton_hsm::crypto::keygen::generate_ed25519_key_pair().unwrap();
    let (mldsa_sk, mldsa_vk) = ml_dsa_keygen(MlDsaVariant::MlDsa65).unwrap();

    let message = b"Ed25519+ML-DSA-65 composite test";
    let sig = hybrid_ed25519_mldsa65_sign(mldsa_sk.as_bytes(), ed_sk.as_bytes(), message).unwrap();
    assert!(hybrid_ed25519_mldsa65_verify(&mldsa_vk, &ed_pk, message, &sig).unwrap());
}

#[test]
fn ed25519_mldsa65_wrong_message_rejected() {
    let (ed_sk, ed_pk) = craton_hsm::crypto::keygen::generate_ed25519_key_pair().unwrap();
    let (mldsa_sk, mldsa_vk) = ml_dsa_keygen(MlDsaVariant::MlDsa65).unwrap();

    let sig = hybrid_ed25519_mldsa65_sign(mldsa_sk.as_bytes(), ed_sk.as_bytes(), b"orig").unwrap();
    let valid =
        hybrid_ed25519_mldsa65_verify(&mldsa_vk, &ed_pk, b"tampered", &sig).unwrap();
    assert!(!valid);
}

#[test]
fn ed25519_mldsa65_mismatched_ed_key_rejected() {
    // Verify with a *different* Ed25519 pk — ML-DSA check still passes but the
    // Ed25519 check fails, so the AND combiner returns false.
    let (ed_sk, _ed_pk) = craton_hsm::crypto::keygen::generate_ed25519_key_pair().unwrap();
    let (_, ed_pk_other) = craton_hsm::crypto::keygen::generate_ed25519_key_pair().unwrap();
    let (mldsa_sk, mldsa_vk) = ml_dsa_keygen(MlDsaVariant::MlDsa65).unwrap();

    let sig = hybrid_ed25519_mldsa65_sign(mldsa_sk.as_bytes(), ed_sk.as_bytes(), b"msg").unwrap();
    assert!(!hybrid_ed25519_mldsa65_verify(&mldsa_vk, &ed_pk_other, b"msg", &sig).unwrap());
}
