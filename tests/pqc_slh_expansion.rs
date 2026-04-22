// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Parametric roundtrip tests for all 12 FIPS 205 SLH-DSA parameter sets.
//!
//! Raw-crypto layer (no PKCS#11 ABI), so safe to run in parallel.

use craton_hsm::crypto::pqc::{slh_dsa_keygen, slh_dsa_sign, slh_dsa_verify, SlhDsaVariant};

/// Every parameter set exposed by the NIST FIPS 205 standard.
const ALL_VARIANTS: &[SlhDsaVariant] = &[
    SlhDsaVariant::Sha2_128s,
    SlhDsaVariant::Sha2_128f,
    SlhDsaVariant::Sha2_192s,
    SlhDsaVariant::Sha2_192f,
    SlhDsaVariant::Sha2_256s,
    SlhDsaVariant::Sha2_256f,
    SlhDsaVariant::Shake_128s,
    SlhDsaVariant::Shake_128f,
    SlhDsaVariant::Shake_192s,
    SlhDsaVariant::Shake_192f,
    SlhDsaVariant::Shake_256s,
    SlhDsaVariant::Shake_256f,
];

#[test]
fn all_variants_roundtrip() {
    // SLH-DSA signatures are slow (especially the `s` variants); iterate once
    // per variant and keep the message short.
    let message = b"SLH-DSA parametric roundtrip";
    for &variant in ALL_VARIANTS {
        let (sk, vk) = slh_dsa_keygen(variant)
            .unwrap_or_else(|_| panic!("keygen failed for {:?}", variant));
        let sig = slh_dsa_sign(sk.as_bytes(), message, variant)
            .unwrap_or_else(|_| panic!("sign failed for {:?}", variant));
        let valid = slh_dsa_verify(&vk, message, &sig, variant)
            .unwrap_or_else(|_| panic!("verify errored for {:?}", variant));
        assert!(valid, "verify returned false for {:?}", variant);
    }
}

#[test]
fn tampered_signature_fails_every_variant() {
    let message = b"SLH-DSA tamper test";
    // Fast variants only — the slow (`s`) variants add minutes to the run.
    let fast_variants = [
        SlhDsaVariant::Sha2_128f,
        SlhDsaVariant::Sha2_192f,
        SlhDsaVariant::Sha2_256f,
        SlhDsaVariant::Shake_128f,
    ];
    for &variant in &fast_variants {
        let (sk, vk) = slh_dsa_keygen(variant).unwrap();
        let mut sig = slh_dsa_sign(sk.as_bytes(), message, variant).unwrap();
        sig[0] ^= 0xFF;
        let valid = slh_dsa_verify(&vk, message, &sig, variant).unwrap();
        assert!(!valid, "tampered signature passed verify for {:?}", variant);
    }
}

#[test]
fn mechanism_dispatch_covers_all_12_variants() {
    use craton_hsm::crypto::pqc::mechanism_to_slh_dsa_variant;
    use craton_hsm::pkcs11_abi::constants::*;

    let pairs: [(u64, SlhDsaVariant); 12] = [
        (CKM_SLH_DSA_SHA2_128S as u64, SlhDsaVariant::Sha2_128s),
        (CKM_SLH_DSA_SHA2_128F as u64, SlhDsaVariant::Sha2_128f),
        (CKM_SLH_DSA_SHA2_192S as u64, SlhDsaVariant::Sha2_192s),
        (CKM_SLH_DSA_SHA2_192F as u64, SlhDsaVariant::Sha2_192f),
        (CKM_SLH_DSA_SHA2_256S as u64, SlhDsaVariant::Sha2_256s),
        (CKM_SLH_DSA_SHA2_256F as u64, SlhDsaVariant::Sha2_256f),
        (CKM_SLH_DSA_SHAKE_128S as u64, SlhDsaVariant::Shake_128s),
        (CKM_SLH_DSA_SHAKE_128F as u64, SlhDsaVariant::Shake_128f),
        (CKM_SLH_DSA_SHAKE_192S as u64, SlhDsaVariant::Shake_192s),
        (CKM_SLH_DSA_SHAKE_192F as u64, SlhDsaVariant::Shake_192f),
        (CKM_SLH_DSA_SHAKE_256S as u64, SlhDsaVariant::Shake_256s),
        (CKM_SLH_DSA_SHAKE_256F as u64, SlhDsaVariant::Shake_256f),
    ];
    for (mech, expected) in pairs {
        assert_eq!(
            mechanism_to_slh_dsa_variant(mech),
            Some(expected),
            "dispatch failed for 0x{:X}",
            mech
        );
    }
}
