// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Falcon (FN-DSA) roundtrip and tamper-detection tests.
//! Runs only when the `falcon-sig` feature is enabled.

#![cfg(feature = "falcon-sig")]

use craton_hsm::crypto::falcon::{
    falcon_keygen, falcon_sign, falcon_verify, is_falcon_mechanism, mechanism_to_falcon_variant,
    FalconVariant,
};
use craton_hsm::pkcs11_abi::constants::{CKM_FALCON_1024, CKM_FALCON_512};

#[test]
fn falcon512_sign_verify() {
    let (sk, pk) = falcon_keygen(FalconVariant::Falcon512).unwrap();
    let message = b"Falcon-512 signing test vector";
    let sig = falcon_sign(sk.as_bytes(), message, FalconVariant::Falcon512).unwrap();
    assert!(!sig.is_empty());
    // Falcon signatures are variable-length; upper-bound the expected size.
    assert!(sig.len() <= 752, "Falcon-512 sig unexpectedly long: {}", sig.len());
    let valid = falcon_verify(&pk, message, &sig, FalconVariant::Falcon512).unwrap();
    assert!(valid);
}

#[test]
fn falcon1024_sign_verify() {
    let (sk, pk) = falcon_keygen(FalconVariant::Falcon1024).unwrap();
    let message = b"Falcon-1024 signing test vector";
    let sig = falcon_sign(sk.as_bytes(), message, FalconVariant::Falcon1024).unwrap();
    assert!(!sig.is_empty());
    assert!(sig.len() <= 1462, "Falcon-1024 sig unexpectedly long: {}", sig.len());
    let valid = falcon_verify(&pk, message, &sig, FalconVariant::Falcon1024).unwrap();
    assert!(valid);
}

#[test]
fn falcon_tampered_message_rejected() {
    let (sk, pk) = falcon_keygen(FalconVariant::Falcon512).unwrap();
    let sig = falcon_sign(sk.as_bytes(), b"original", FalconVariant::Falcon512).unwrap();
    let valid = falcon_verify(&pk, b"tampered", &sig, FalconVariant::Falcon512).unwrap();
    assert!(!valid);
}

#[test]
fn falcon_wrong_public_key_rejected() {
    let (sk, _) = falcon_keygen(FalconVariant::Falcon512).unwrap();
    let (_, pk_other) = falcon_keygen(FalconVariant::Falcon512).unwrap();
    let sig = falcon_sign(sk.as_bytes(), b"message", FalconVariant::Falcon512).unwrap();
    let valid = falcon_verify(&pk_other, b"message", &sig, FalconVariant::Falcon512).unwrap();
    assert!(!valid);
}

#[test]
fn falcon_tampered_signature_rejected() {
    let (sk, pk) = falcon_keygen(FalconVariant::Falcon512).unwrap();
    let mut sig = falcon_sign(sk.as_bytes(), b"msg", FalconVariant::Falcon512).unwrap();
    sig[10] ^= 0x55;
    // Tampering may produce either a verify=false or a parse error converted
    // to Ok(false) by the module. Either way the signature must be rejected.
    let valid = falcon_verify(&pk, b"msg", &sig, FalconVariant::Falcon512).unwrap_or(false);
    assert!(!valid);
}

#[test]
fn mechanism_dispatch() {
    assert_eq!(
        mechanism_to_falcon_variant(CKM_FALCON_512),
        Some(FalconVariant::Falcon512)
    );
    assert_eq!(
        mechanism_to_falcon_variant(CKM_FALCON_1024),
        Some(FalconVariant::Falcon1024)
    );
    assert!(is_falcon_mechanism(CKM_FALCON_512));
    assert!(is_falcon_mechanism(CKM_FALCON_1024));
    assert!(!is_falcon_mechanism(0));
}
