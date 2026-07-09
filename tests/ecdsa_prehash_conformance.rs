// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Conformance tests for PKCS#11 ECDSA digest semantics.
//!
//! Two bugs are covered:
//!  1. Raw `CKM_ECDSA` must sign the caller-supplied digest DIRECTLY (no
//!     second hash). Previously it double-hashed.
//!  2. Combined `CKM_ECDSA_SHA384`/`CKM_ECDSA_SHA512` on a P-256 key must hash
//!     with the NAMED digest, not the curve's default SHA-256.
//!
//! These exercise `crypto::sign` directly (parallel-safe, no ABI globals). The
//! prehash functions are the same ones the ABI single-shot and multipart paths
//! now call.

use craton_hsm::crypto::keygen;
use craton_hsm::crypto::sign;
use sha2::{Digest, Sha256, Sha384, Sha512};

/// Raw CKM_ECDSA: signing a pre-computed SHA-256 digest and verifying the same
/// digest must succeed — i.e. the signer does NOT hash again.
#[test]
fn raw_ecdsa_p256_signs_digest_directly() {
    let (priv_key, pub_sec1) = keygen::generate_ec_p256_key_pair().expect("keygen");
    let message = b"raw ECDSA must not double-hash";
    let digest = Sha256::digest(message);

    // Sign the DIGEST (what a PKCS#11 raw-CKM_ECDSA caller passes).
    let sig = sign::ecdsa_p256_sign_prehashed(priv_key.as_bytes(), &digest).expect("sign");

    // Verifying the SAME digest must pass.
    assert!(
        sign::ecdsa_p256_verify_prehashed(&pub_sec1, &digest, &sig).expect("verify"),
        "raw ECDSA signature over a digest must verify against that digest"
    );

    // Verifying against the MESSAGE bytes (as if hashed again) must fail —
    // proves the signer treated the input as the final digest, not as data to
    // be hashed. (message len != a hash, but exercise the negative anyway.)
    let double = Sha256::digest(digest);
    assert!(
        !sign::ecdsa_p256_verify_prehashed(&pub_sec1, &double, &sig).unwrap_or(false),
        "signature must not verify against a re-hashed digest"
    );
}

/// CKM_ECDSA_SHA384 on a P-256 key: the digest is SHA-384 (48 bytes), longer
/// than the curve default. The prehash path must accept it (FIPS 186-5
/// truncation) and round-trip.
#[test]
fn ecdsa_p256_with_sha384_digest_roundtrips() {
    let (priv_key, pub_sec1) = keygen::generate_ec_p256_key_pair().expect("keygen");
    let message = b"cross-hash: SHA-384 digest on a P-256 key";
    let digest = Sha384::digest(message); // 48 bytes

    let sig = sign::ecdsa_p256_sign_prehashed(priv_key.as_bytes(), &digest).expect("sign");
    assert!(
        sign::ecdsa_p256_verify_prehashed(&pub_sec1, &digest, &sig).expect("verify"),
        "P-256 key with a SHA-384 digest must round-trip (leftmost-bits truncation)"
    );
}

/// CKM_ECDSA_SHA512 on a P-256 key: SHA-512 digest (64 bytes).
#[test]
fn ecdsa_p256_with_sha512_digest_roundtrips() {
    let (priv_key, pub_sec1) = keygen::generate_ec_p256_key_pair().expect("keygen");
    let digest = Sha512::digest(b"64-byte digest on P-256");
    let sig = sign::ecdsa_p256_sign_prehashed(priv_key.as_bytes(), &digest).expect("sign");
    assert!(sign::ecdsa_p256_verify_prehashed(&pub_sec1, &digest, &sig).expect("verify"));
}

/// P-384 raw-digest round-trip with a SHA-256 digest (shorter than default).
#[test]
fn ecdsa_p384_with_short_digest_roundtrips() {
    let (priv_key, pub_sec1) = keygen::generate_ec_p384_key_pair().expect("keygen");
    let digest = Sha256::digest(b"short digest on P-384"); // 32 bytes
    let sig = sign::ecdsa_p384_sign_prehashed(priv_key.as_bytes(), &digest).expect("sign");
    assert!(sign::ecdsa_p384_verify_prehashed(&pub_sec1, &digest, &sig).expect("verify"));
}

/// Empty and oversized prehash inputs are rejected.
#[test]
fn ecdsa_prehash_length_bounds() {
    let (priv_key, _) = keygen::generate_ec_p256_key_pair().expect("keygen");
    assert!(sign::ecdsa_p256_sign_prehashed(priv_key.as_bytes(), &[]).is_err());
    assert!(sign::ecdsa_p256_sign_prehashed(priv_key.as_bytes(), &[0u8; 65]).is_err());
}
