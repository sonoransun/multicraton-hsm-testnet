// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Stored-key format compatibility tests for PQC crate upgrades.
//!
//! PQC private keys are stored as raw seeds (ML-KEM: 64-byte d||z, ML-DSA:
//! 32-byte xi) or raw signing-key bytes (SLH-DSA). Seed expansion is fully
//! specified by FIPS 203/204/205, so the same stored seed must reconstruct
//! the same public key and produce interoperable results across crate
//! upgrades. These fixtures were recorded at the ml-kem 0.3.2 / ml-dsa 0.1.1 /
//! slh-dsa 0.2.0-rc.5 upgrade; if a future upgrade changes any of these
//! outputs, existing stored tokens would break — that is a release blocker,
//! not a fixture to regenerate.
//!
//! Parallel-safe: exercises `craton_hsm::crypto::pqc` directly, no PKCS#11
//! ABI globals.

use craton_hsm::crypto::pqc::{
    ml_dsa_expand_seed, ml_dsa_sign, ml_dsa_verify, ml_kem_decapsulate, ml_kem_encapsulate,
    ml_kem_expand_seed, MlDsaVariant, MlKemVariant,
};
use sha2::{Digest, Sha256};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// Fixed test seeds: NOT secret, never use outside tests.
fn mlkem_seed() -> [u8; 64] {
    core::array::from_fn(|i| i as u8)
}

fn mldsa_seed() -> [u8; 32] {
    core::array::from_fn(|i| 0xA0 ^ (i as u8))
}

// Recorded with ml-kem 0.3.2 (see module docs). SHA-256 of the encapsulation
// key reconstructed from the fixed 64-byte seed above.
const MLKEM768_EK_SHA256: &str = "0b7934c83125c788995e2ba6bd761e33046b3e40571be53e023309a29f398cc9";
// Recorded with ml-dsa 0.1.1: SHA-256 of the verifying key expanded from the
// fixed 32-byte xi seed, and of the deterministic empty-context signature
// over MSG below.
const MLDSA65_VK_SHA256: &str = "01d49c7013b1eb414d51e5d5ca01e53988af1329512e71bcbe2b3260dad3edf2";
const MLDSA65_SIG_SHA256: &str = "27c2be369c7050bcc1115a88f55652f255f953b1a1a246a07a282088af8ad45f";

const MSG: &[u8] = b"craton-hsm pqc key compatibility fixture message";

#[test]
fn ml_kem_768_seed_expansion_is_stable() {
    let (_sk, ek) = ml_kem_expand_seed(mlkem_seed(), MlKemVariant::MlKem768).expect("expand");
    assert_eq!(
        sha256_hex(&ek),
        MLKEM768_EK_SHA256,
        "ML-KEM-768 seed->ek expansion changed: stored keys from previous releases would break"
    );

    // The stored seed must still round-trip through encapsulate/decapsulate.
    let (ct, ss_enc) = ml_kem_encapsulate(&ek, MlKemVariant::MlKem768).expect("encapsulate");
    let ss_dec = ml_kem_decapsulate(&mlkem_seed(), &ct, MlKemVariant::MlKem768).expect("decap");
    assert_eq!(ss_enc, ss_dec);
    assert_eq!(ss_dec.len(), 32);
}

#[test]
fn ml_dsa_65_seed_expansion_and_signature_are_stable() {
    let (_sk, vk) = ml_dsa_expand_seed(mldsa_seed(), MlDsaVariant::MlDsa65).expect("expand");
    assert_eq!(
        sha256_hex(&vk),
        MLDSA65_VK_SHA256,
        "ML-DSA-65 seed->vk expansion changed: stored keys from previous releases would break"
    );

    let sig = ml_dsa_sign(&mldsa_seed(), MSG, MlDsaVariant::MlDsa65).expect("sign");
    assert_eq!(
        sha256_hex(&sig),
        MLDSA65_SIG_SHA256,
        "ML-DSA-65 deterministic signature changed for a fixed seed+message"
    );
    assert!(ml_dsa_verify(&vk, MSG, &sig, MlDsaVariant::MlDsa65).expect("verify"));
}

/// One-time fixture generator. Run manually with:
/// `cargo test --test pqc_key_compat -- --ignored --nocapture generate_fixtures`
#[test]
#[ignore = "fixture generator, not a test"]
fn generate_fixtures() {
    let (_sk, ek) = ml_kem_expand_seed(mlkem_seed(), MlKemVariant::MlKem768).expect("expand");
    println!("MLKEM768_EK_SHA256 = \"{}\"", sha256_hex(&ek));

    let (_sk, vk) = ml_dsa_expand_seed(mldsa_seed(), MlDsaVariant::MlDsa65).expect("expand");
    println!("MLDSA65_VK_SHA256 = \"{}\"", sha256_hex(&vk));

    let sig = ml_dsa_sign(&mldsa_seed(), MSG, MlDsaVariant::MlDsa65).expect("sign");
    println!("MLDSA65_SIG_SHA256 = \"{}\"", sha256_hex(&sig));
}
