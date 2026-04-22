// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Additional hybrid (classical + PQC) Key Encapsulation Mechanisms.
//!
//! This module extends the original `hybrid_kem` (X25519 + ML-KEM-768) with
//! three further constructions used in practice:
//!
//! | Variant                 | Classical leg | PQC leg      | Label                         |
//! |-------------------------|---------------|--------------|-------------------------------|
//! | X25519 + ML-KEM-1024    | X25519        | ML-KEM-1024  | `CRATON-HYBRID-X25519-MLKEM1024-V1` |
//! | P-256  + ML-KEM-768     | ECDH P-256    | ML-KEM-768   | `CRATON-HYBRID-P256-MLKEM768-V1`    |
//! | P-384  + ML-KEM-1024    | ECDH P-384    | ML-KEM-1024  | `CRATON-HYBRID-P384-MLKEM1024-V1`   |
//!
//! All variants share the same combiner: `HKDF-SHA-256(IKM = classical_ss || pq_ss,
//! info = label)`. Each uses a distinct `info` label so that ciphertexts/SS from
//! one variant cannot be reinterpreted as another — domain separation between
//! hybrid constructions.
//!
//! Storage and wire-format layouts:
//!
//! ```text
//! Secret key:  [classical_sk_raw][mlkem_seed_64]
//! Public key:  [classical_pk_encoded][mlkem_ek_encoded]
//! Ciphertext:  [classical_ephemeral_pk][mlkem_ct]
//! ```
//!
//! # Security
//! * Secure as long as **either** the classical ECDH **or** ML-KEM is unbroken
//!   (IND-CCA2 via implicit rejection inherited from ML-KEM).
//! * The P-256/P-384 legs are raw ECDH without authenticity; callers should
//!   transport or pin the recipient public key over an authenticated channel.

#![cfg(feature = "hybrid-kem")]

use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{DecapsulationKey, EncapsulationKey, KeyExport, MlKem1024, MlKem768};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::error::{HsmError, HsmResult};

/// Length of every combined shared secret (HKDF-SHA-256 output) — 32 bytes.
pub const HYBRID_SHARED_SECRET_LEN: usize = 32;

/// Derive a 32-byte hybrid shared secret from two per-scheme shared secrets.
/// Uses HKDF-SHA-256 with a scheme-specific `info` label for domain separation.
fn hkdf_combine(classical_ss: &[u8], pq_ss: &[u8], label: &[u8]) -> HsmResult<[u8; 32]> {
    // Stack-allocated IKM: avoids leaving concatenated secrets in a resizable
    // Vec (which would leak via realloc and miss zeroization on drop).
    let mut ikm = [0u8; 128];
    let total = classical_ss.len() + pq_ss.len();
    if total > ikm.len() {
        return Err(HsmError::GeneralError);
    }
    ikm[..classical_ss.len()].copy_from_slice(classical_ss);
    ikm[classical_ss.len()..total].copy_from_slice(pq_ss);

    let mut out = [0u8; 32];
    let result = Hkdf::<Sha256>::new(None, &ikm[..total])
        .expand(label, &mut out)
        .map_err(|_| HsmError::GeneralError);

    ikm.zeroize();
    result?;
    Ok(out)
}

/// Generate 64 random bytes for an ML-KEM seed via the FIPS DRBG.
fn mlkem_seed_from_drbg() -> HsmResult<[u8; 64]> {
    let mut seed = [0u8; 64];
    let mut drbg = crate::crypto::drbg::HmacDrbg::new()?;
    drbg.generate(&mut seed)?;
    Ok(seed)
}

// ============================================================================
// X25519 + ML-KEM-1024  (high-security KEM hybrid)
// ============================================================================
//
// Wire formats:
//   Secret key  (`sk_bytes`):  32 (X25519 static) + 64 (ML-KEM-1024 seed) = 96 bytes
//   Public key  (`pk_bytes`):  32 (X25519 pk)     + 1568 (ML-KEM-1024 ek) = 1600 bytes
//   Ciphertext  (`ct_bytes`):  32 (X25519 epk)    + 1568 (ML-KEM-1024 ct) = 1600 bytes

const X25519_MLKEM1024_LABEL: &[u8] = b"CRATON-HYBRID-X25519-MLKEM1024-V1";
const X25519_LEN: usize = 32;
const MLKEM1024_EK_LEN: usize = 1568;
const MLKEM1024_CT_LEN: usize = 1568;
const MLKEM_SEED_LEN: usize = 64;

/// Generate an X25519 + ML-KEM-1024 long-term keypair. Returns `(sk, pk)`.
pub fn hybrid_x25519_mlkem1024_keygen() -> HsmResult<(Vec<u8>, Vec<u8>)> {
    use x25519_dalek::{PublicKey as X25519Pk, StaticSecret};

    let x_sk = StaticSecret::random_from_rng(rand_core::OsRng);
    let x_pk = X25519Pk::from(&x_sk);

    let seed_bytes = mlkem_seed_from_drbg()?;
    let seed: ml_kem::Seed = seed_bytes.into();
    let dk = DecapsulationKey::<MlKem1024>::from_seed(seed);
    let ek = dk.encapsulation_key();
    let stored_seed = dk.to_seed().ok_or(HsmError::GeneralError)?;
    let ek_bytes_ga = ek.to_bytes();
    let ek_bytes = &ek_bytes_ga[..];

    let mut sk = Vec::with_capacity(X25519_LEN + MLKEM_SEED_LEN);
    sk.extend_from_slice(x_sk.as_bytes());
    sk.extend_from_slice(&stored_seed[..]);

    let mut pk = Vec::with_capacity(X25519_LEN + MLKEM1024_EK_LEN);
    pk.extend_from_slice(x_pk.as_bytes());
    pk.extend_from_slice(ek_bytes);

    Ok((sk, pk))
}

/// Encapsulate against a serialized X25519+ML-KEM-1024 public key.
/// Returns `(ciphertext, shared_secret)`.
pub fn hybrid_x25519_mlkem1024_encapsulate(pk_bytes: &[u8]) -> HsmResult<(Vec<u8>, Vec<u8>)> {
    use x25519_dalek::{EphemeralSecret, PublicKey as X25519Pk};

    if pk_bytes.len() != X25519_LEN + MLKEM1024_EK_LEN {
        return Err(HsmError::DataInvalid);
    }
    let mut x_pk_arr = [0u8; 32];
    x_pk_arr.copy_from_slice(&pk_bytes[..X25519_LEN]);
    let x_pk = X25519Pk::from(x_pk_arr);

    let ek_key: ml_kem::kem::Key<EncapsulationKey<MlKem1024>> =
        pk_bytes[X25519_LEN..].try_into().map_err(|_| HsmError::DataInvalid)?;
    let ek = EncapsulationKey::<MlKem1024>::new(&ek_key).map_err(|_| HsmError::DataInvalid)?;

    let eph_sk = EphemeralSecret::random_from_rng(rand_core::OsRng);
    let eph_pk = X25519Pk::from(&eph_sk);
    let x_ss = eph_sk.diffie_hellman(&x_pk);

    let mut rng = crate::crypto::pqc::new_rng()?;
    let (mlkem_ct, mlkem_ss) = ek.encapsulate_with_rng(&mut rng);

    let shared = hkdf_combine(x_ss.as_bytes(), &mlkem_ss[..], X25519_MLKEM1024_LABEL)?;

    let mut ct = Vec::with_capacity(X25519_LEN + MLKEM1024_CT_LEN);
    ct.extend_from_slice(eph_pk.as_bytes());
    ct.extend_from_slice(&mlkem_ct[..]);

    Ok((ct, shared.to_vec()))
}

/// Decapsulate with an X25519+ML-KEM-1024 long-term secret key.
pub fn hybrid_x25519_mlkem1024_decapsulate(sk_bytes: &[u8], ct_bytes: &[u8]) -> HsmResult<Vec<u8>> {
    use x25519_dalek::{PublicKey as X25519Pk, StaticSecret};

    if sk_bytes.len() != X25519_LEN + MLKEM_SEED_LEN
        || ct_bytes.len() != X25519_LEN + MLKEM1024_CT_LEN
    {
        return Err(HsmError::DataInvalid);
    }

    let mut x_sk_arr = [0u8; 32];
    x_sk_arr.copy_from_slice(&sk_bytes[..X25519_LEN]);
    let x_sk = StaticSecret::from(x_sk_arr);
    let mut seed_arr = [0u8; 64];
    seed_arr.copy_from_slice(&sk_bytes[X25519_LEN..]);
    let dk = DecapsulationKey::<MlKem1024>::from_seed(seed_arr.into());

    let mut eph_pk_arr = [0u8; 32];
    eph_pk_arr.copy_from_slice(&ct_bytes[..X25519_LEN]);
    let eph_pk = X25519Pk::from(eph_pk_arr);
    let x_ss = x_sk.diffie_hellman(&eph_pk);

    let mlkem_ct = ct_bytes[X25519_LEN..]
        .try_into()
        .map_err(|_| HsmError::EncryptedDataInvalid)?;
    let mlkem_ss = dk.decapsulate(&mlkem_ct);

    let shared = hkdf_combine(x_ss.as_bytes(), &mlkem_ss[..], X25519_MLKEM1024_LABEL)?;
    Ok(shared.to_vec())
}

// ============================================================================
// P-256 + ML-KEM-768  (CNSA 2.0 aligned)
// ============================================================================
//
// Wire formats (P-256 uncompressed SEC1 = 65 bytes, ML-KEM-768 ek = 1184,
// ML-KEM-768 ct = 1088, ML-KEM seed = 64):
//   Secret key: 32 (P-256 scalar) + 64 (ML-KEM-768 seed) = 96 bytes
//   Public key: 65 (P-256 SEC1)   + 1184 (ML-KEM-768 ek) = 1249 bytes
//   Ciphertext: 65 (P-256 eph pk) + 1088 (ML-KEM-768 ct) = 1153 bytes

const P256_MLKEM768_LABEL: &[u8] = b"CRATON-HYBRID-P256-MLKEM768-V1";
const P256_SCALAR_LEN: usize = 32;
const P256_PK_SEC1_LEN: usize = 65; // uncompressed SEC1 (0x04 || X || Y)
const MLKEM768_EK_LEN: usize = 1184;
const MLKEM768_CT_LEN: usize = 1088;

/// Generate a P-256 + ML-KEM-768 long-term keypair. Returns `(sk, pk)`.
pub fn hybrid_p256_mlkem768_keygen() -> HsmResult<(Vec<u8>, Vec<u8>)> {
    use p256::{elliptic_curve::sec1::ToEncodedPoint, PublicKey, SecretKey};

    let p_sk = SecretKey::random(&mut rand_core::OsRng);
    let p_pk = p_sk.public_key();
    let p_sk_bytes = p_sk.to_bytes();
    let p_pk_enc = p_pk.to_encoded_point(false);
    debug_assert_eq!(p_pk_enc.as_bytes().len(), P256_PK_SEC1_LEN);

    let seed_bytes = mlkem_seed_from_drbg()?;
    let dk = DecapsulationKey::<MlKem768>::from_seed(seed_bytes.into());
    let ek = dk.encapsulation_key();
    let stored_seed = dk.to_seed().ok_or(HsmError::GeneralError)?;
    let ek_bytes_ga = ek.to_bytes();

    let mut sk = Vec::with_capacity(P256_SCALAR_LEN + MLKEM_SEED_LEN);
    sk.extend_from_slice(&p_sk_bytes);
    sk.extend_from_slice(&stored_seed[..]);

    let mut pk = Vec::with_capacity(P256_PK_SEC1_LEN + MLKEM768_EK_LEN);
    pk.extend_from_slice(p_pk_enc.as_bytes());
    pk.extend_from_slice(&ek_bytes_ga[..]);

    let _ = PublicKey::from(p_sk.public_key()); // silence unused import on some paths
    Ok((sk, pk))
}

/// Encapsulate against a serialized P-256+ML-KEM-768 public key.
pub fn hybrid_p256_mlkem768_encapsulate(pk_bytes: &[u8]) -> HsmResult<(Vec<u8>, Vec<u8>)> {
    use p256::{ecdh::EphemeralSecret, elliptic_curve::sec1::ToEncodedPoint, PublicKey};

    if pk_bytes.len() != P256_PK_SEC1_LEN + MLKEM768_EK_LEN {
        return Err(HsmError::DataInvalid);
    }
    let p_pk = PublicKey::from_sec1_bytes(&pk_bytes[..P256_PK_SEC1_LEN])
        .map_err(|_| HsmError::DataInvalid)?;
    let ek_key: ml_kem::kem::Key<EncapsulationKey<MlKem768>> = pk_bytes[P256_PK_SEC1_LEN..]
        .try_into()
        .map_err(|_| HsmError::DataInvalid)?;
    let ek = EncapsulationKey::<MlKem768>::new(&ek_key).map_err(|_| HsmError::DataInvalid)?;

    let eph_sk = EphemeralSecret::random(&mut rand_core::OsRng);
    let eph_pk_enc = eph_sk.public_key().to_encoded_point(false);
    let p_ss = eph_sk.diffie_hellman(&p_pk);

    let mut rng = crate::crypto::pqc::new_rng()?;
    let (mlkem_ct, mlkem_ss) = ek.encapsulate_with_rng(&mut rng);

    let shared = hkdf_combine(
        p_ss.raw_secret_bytes().as_slice(),
        &mlkem_ss[..],
        P256_MLKEM768_LABEL,
    )?;

    let mut ct = Vec::with_capacity(P256_PK_SEC1_LEN + MLKEM768_CT_LEN);
    ct.extend_from_slice(eph_pk_enc.as_bytes());
    ct.extend_from_slice(&mlkem_ct[..]);

    Ok((ct, shared.to_vec()))
}

/// Decapsulate with a P-256+ML-KEM-768 long-term secret key.
pub fn hybrid_p256_mlkem768_decapsulate(sk_bytes: &[u8], ct_bytes: &[u8]) -> HsmResult<Vec<u8>> {
    use p256::{ecdh::diffie_hellman, PublicKey, SecretKey};

    if sk_bytes.len() != P256_SCALAR_LEN + MLKEM_SEED_LEN
        || ct_bytes.len() != P256_PK_SEC1_LEN + MLKEM768_CT_LEN
    {
        return Err(HsmError::DataInvalid);
    }

    let p_sk = SecretKey::from_slice(&sk_bytes[..P256_SCALAR_LEN])
        .map_err(|_| HsmError::KeyHandleInvalid)?;
    let mut seed_arr = [0u8; 64];
    seed_arr.copy_from_slice(&sk_bytes[P256_SCALAR_LEN..]);
    let dk = DecapsulationKey::<MlKem768>::from_seed(seed_arr.into());

    let eph_pk = PublicKey::from_sec1_bytes(&ct_bytes[..P256_PK_SEC1_LEN])
        .map_err(|_| HsmError::EncryptedDataInvalid)?;
    let p_ss = diffie_hellman(p_sk.to_nonzero_scalar(), eph_pk.as_affine());

    let mlkem_ct = ct_bytes[P256_PK_SEC1_LEN..]
        .try_into()
        .map_err(|_| HsmError::EncryptedDataInvalid)?;
    let mlkem_ss = dk.decapsulate(&mlkem_ct);

    let shared = hkdf_combine(
        p_ss.raw_secret_bytes().as_slice(),
        &mlkem_ss[..],
        P256_MLKEM768_LABEL,
    )?;
    Ok(shared.to_vec())
}

// ============================================================================
// P-384 + ML-KEM-1024  (TOP SECRET aligned)
// ============================================================================
//
// Wire formats (P-384 uncompressed SEC1 = 97 bytes):
//   Secret key: 48 (P-384 scalar) + 64 (ML-KEM-1024 seed) = 112 bytes
//   Public key: 97 (P-384 SEC1)   + 1568 (ML-KEM-1024 ek) = 1665 bytes
//   Ciphertext: 97 (P-384 eph pk) + 1568 (ML-KEM-1024 ct) = 1665 bytes

const P384_MLKEM1024_LABEL: &[u8] = b"CRATON-HYBRID-P384-MLKEM1024-V1";
const P384_SCALAR_LEN: usize = 48;
const P384_PK_SEC1_LEN: usize = 97;

/// Generate a P-384 + ML-KEM-1024 long-term keypair.
pub fn hybrid_p384_mlkem1024_keygen() -> HsmResult<(Vec<u8>, Vec<u8>)> {
    use p384::{elliptic_curve::sec1::ToEncodedPoint, SecretKey};

    let p_sk = SecretKey::random(&mut rand_core::OsRng);
    let p_pk = p_sk.public_key();
    let p_sk_bytes = p_sk.to_bytes();
    let p_pk_enc = p_pk.to_encoded_point(false);
    debug_assert_eq!(p_pk_enc.as_bytes().len(), P384_PK_SEC1_LEN);

    let seed_bytes = mlkem_seed_from_drbg()?;
    let dk = DecapsulationKey::<MlKem1024>::from_seed(seed_bytes.into());
    let ek = dk.encapsulation_key();
    let stored_seed = dk.to_seed().ok_or(HsmError::GeneralError)?;
    let ek_bytes_ga = ek.to_bytes();

    let mut sk = Vec::with_capacity(P384_SCALAR_LEN + MLKEM_SEED_LEN);
    sk.extend_from_slice(&p_sk_bytes);
    sk.extend_from_slice(&stored_seed[..]);

    let mut pk = Vec::with_capacity(P384_PK_SEC1_LEN + MLKEM1024_EK_LEN);
    pk.extend_from_slice(p_pk_enc.as_bytes());
    pk.extend_from_slice(&ek_bytes_ga[..]);

    Ok((sk, pk))
}

/// Encapsulate against a P-384+ML-KEM-1024 public key.
pub fn hybrid_p384_mlkem1024_encapsulate(pk_bytes: &[u8]) -> HsmResult<(Vec<u8>, Vec<u8>)> {
    use p384::{ecdh::EphemeralSecret, elliptic_curve::sec1::ToEncodedPoint, PublicKey};

    if pk_bytes.len() != P384_PK_SEC1_LEN + MLKEM1024_EK_LEN {
        return Err(HsmError::DataInvalid);
    }
    let p_pk = PublicKey::from_sec1_bytes(&pk_bytes[..P384_PK_SEC1_LEN])
        .map_err(|_| HsmError::DataInvalid)?;
    let ek_key: ml_kem::kem::Key<EncapsulationKey<MlKem1024>> = pk_bytes[P384_PK_SEC1_LEN..]
        .try_into()
        .map_err(|_| HsmError::DataInvalid)?;
    let ek = EncapsulationKey::<MlKem1024>::new(&ek_key).map_err(|_| HsmError::DataInvalid)?;

    let eph_sk = EphemeralSecret::random(&mut rand_core::OsRng);
    let eph_pk_enc = eph_sk.public_key().to_encoded_point(false);
    let p_ss = eph_sk.diffie_hellman(&p_pk);

    let mut rng = crate::crypto::pqc::new_rng()?;
    let (mlkem_ct, mlkem_ss) = ek.encapsulate_with_rng(&mut rng);

    let shared = hkdf_combine(
        p_ss.raw_secret_bytes().as_slice(),
        &mlkem_ss[..],
        P384_MLKEM1024_LABEL,
    )?;

    let mut ct = Vec::with_capacity(P384_PK_SEC1_LEN + MLKEM1024_CT_LEN);
    ct.extend_from_slice(eph_pk_enc.as_bytes());
    ct.extend_from_slice(&mlkem_ct[..]);

    Ok((ct, shared.to_vec()))
}

/// Decapsulate with a P-384+ML-KEM-1024 long-term secret key.
pub fn hybrid_p384_mlkem1024_decapsulate(sk_bytes: &[u8], ct_bytes: &[u8]) -> HsmResult<Vec<u8>> {
    use p384::{ecdh::diffie_hellman, PublicKey, SecretKey};

    if sk_bytes.len() != P384_SCALAR_LEN + MLKEM_SEED_LEN
        || ct_bytes.len() != P384_PK_SEC1_LEN + MLKEM1024_CT_LEN
    {
        return Err(HsmError::DataInvalid);
    }

    let p_sk = SecretKey::from_slice(&sk_bytes[..P384_SCALAR_LEN])
        .map_err(|_| HsmError::KeyHandleInvalid)?;
    let mut seed_arr = [0u8; 64];
    seed_arr.copy_from_slice(&sk_bytes[P384_SCALAR_LEN..]);
    let dk = DecapsulationKey::<MlKem1024>::from_seed(seed_arr.into());

    let eph_pk = PublicKey::from_sec1_bytes(&ct_bytes[..P384_PK_SEC1_LEN])
        .map_err(|_| HsmError::EncryptedDataInvalid)?;
    let p_ss = diffie_hellman(p_sk.to_nonzero_scalar(), eph_pk.as_affine());

    let mlkem_ct = ct_bytes[P384_PK_SEC1_LEN..]
        .try_into()
        .map_err(|_| HsmError::EncryptedDataInvalid)?;
    let mlkem_ss = dk.decapsulate(&mlkem_ct);

    let shared = hkdf_combine(
        p_ss.raw_secret_bytes().as_slice(),
        &mlkem_ss[..],
        P384_MLKEM1024_LABEL,
    )?;
    Ok(shared.to_vec())
}

// ============================================================================
// Mechanism dispatch helpers
// ============================================================================

use crate::pkcs11_abi::constants::{
    CKM_HYBRID_P256_MLKEM768, CKM_HYBRID_P384_MLKEM1024, CKM_HYBRID_X25519_MLKEM1024,
};
use crate::pkcs11_abi::types::CK_MECHANISM_TYPE;

/// True for any of the three hybrid KEM mechanisms implemented in this module.
pub fn is_new_hybrid_kem_mechanism(mechanism: CK_MECHANISM_TYPE) -> bool {
    matches!(
        mechanism,
        CKM_HYBRID_X25519_MLKEM1024 | CKM_HYBRID_P256_MLKEM768 | CKM_HYBRID_P384_MLKEM1024
    )
}

/// Dispatch keygen by mechanism.
pub fn hybrid_kem_keygen_by_mechanism(
    mechanism: CK_MECHANISM_TYPE,
) -> HsmResult<(Vec<u8>, Vec<u8>)> {
    match mechanism {
        CKM_HYBRID_X25519_MLKEM1024 => hybrid_x25519_mlkem1024_keygen(),
        CKM_HYBRID_P256_MLKEM768 => hybrid_p256_mlkem768_keygen(),
        CKM_HYBRID_P384_MLKEM1024 => hybrid_p384_mlkem1024_keygen(),
        _ => Err(HsmError::MechanismInvalid),
    }
}

/// Dispatch encapsulate by mechanism.
pub fn hybrid_kem_encapsulate_by_mechanism(
    mechanism: CK_MECHANISM_TYPE,
    pk_bytes: &[u8],
) -> HsmResult<(Vec<u8>, Vec<u8>)> {
    match mechanism {
        CKM_HYBRID_X25519_MLKEM1024 => hybrid_x25519_mlkem1024_encapsulate(pk_bytes),
        CKM_HYBRID_P256_MLKEM768 => hybrid_p256_mlkem768_encapsulate(pk_bytes),
        CKM_HYBRID_P384_MLKEM1024 => hybrid_p384_mlkem1024_encapsulate(pk_bytes),
        _ => Err(HsmError::MechanismInvalid),
    }
}

/// Dispatch decapsulate by mechanism.
pub fn hybrid_kem_decapsulate_by_mechanism(
    mechanism: CK_MECHANISM_TYPE,
    sk_bytes: &[u8],
    ct_bytes: &[u8],
) -> HsmResult<Vec<u8>> {
    match mechanism {
        CKM_HYBRID_X25519_MLKEM1024 => hybrid_x25519_mlkem1024_decapsulate(sk_bytes, ct_bytes),
        CKM_HYBRID_P256_MLKEM768 => hybrid_p256_mlkem768_decapsulate(sk_bytes, ct_bytes),
        CKM_HYBRID_P384_MLKEM1024 => hybrid_p384_mlkem1024_decapsulate(sk_bytes, ct_bytes),
        _ => Err(HsmError::MechanismInvalid),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_mlkem1024_roundtrip() {
        let (sk, pk) = hybrid_x25519_mlkem1024_keygen().unwrap();
        let (ct, ss_a) = hybrid_x25519_mlkem1024_encapsulate(&pk).unwrap();
        let ss_b = hybrid_x25519_mlkem1024_decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss_a, ss_b);
        assert_eq!(ss_a.len(), HYBRID_SHARED_SECRET_LEN);
    }

    #[test]
    fn p256_mlkem768_roundtrip() {
        let (sk, pk) = hybrid_p256_mlkem768_keygen().unwrap();
        let (ct, ss_a) = hybrid_p256_mlkem768_encapsulate(&pk).unwrap();
        let ss_b = hybrid_p256_mlkem768_decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss_a, ss_b);
    }

    #[test]
    fn p384_mlkem1024_roundtrip() {
        let (sk, pk) = hybrid_p384_mlkem1024_keygen().unwrap();
        let (ct, ss_a) = hybrid_p384_mlkem1024_encapsulate(&pk).unwrap();
        let ss_b = hybrid_p384_mlkem1024_decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss_a, ss_b);
    }

    #[test]
    fn domain_separation_labels() {
        // Same IKM, different labels, must yield different SS.
        let ss1 = hkdf_combine(b"aaaa", b"bbbb", b"LABEL-A").unwrap();
        let ss2 = hkdf_combine(b"aaaa", b"bbbb", b"LABEL-B").unwrap();
        assert_ne!(ss1, ss2);
    }

    #[test]
    fn wrong_sk_yields_different_ss() {
        let (_sk1, pk) = hybrid_p256_mlkem768_keygen().unwrap();
        let (sk2, _) = hybrid_p256_mlkem768_keygen().unwrap();
        let (ct, ss_a) = hybrid_p256_mlkem768_encapsulate(&pk).unwrap();
        let ss_b = hybrid_p256_mlkem768_decapsulate(&sk2, &ct).unwrap();
        assert_ne!(ss_a, ss_b);
    }
}
