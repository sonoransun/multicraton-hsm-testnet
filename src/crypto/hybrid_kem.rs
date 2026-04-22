// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Hybrid Key Encapsulation Mechanism: X25519 + ML-KEM-768.
//!
//! Combines classical Diffie-Hellman (X25519) with a post-quantum KEM
//! (ML-KEM-768, FIPS 203) in a dual-encapsulation scheme.  The two
//! independently-derived shared secrets are combined via HKDF-SHA-256,
//! so the combined secret is secure unless **both** schemes are broken.
//!
//! # Rationale
//! * **NIST IR 8413-B** and **CNSA 2.0** both recommend hybrid classical+PQC
//!   key establishment for systems that must remain secure through the
//!   quantum-computing transition era.
//! * An attacker who breaks X25519 *or* ML-KEM alone gains nothing.
//! * The overhead vs. pure ML-KEM-768 is one X25519 scalar multiplication
//!   (~100 µs) and one HKDF expansion.
//!
//! # Wire format
//! `HybridCiphertext` encodes as:
//! ```text
//! [ x25519_epk : 32 bytes ][ mlkem768_ct : 1088 bytes ]
//! ```
//! Total: **1120 bytes** per encapsulation.
//!
//! # Usage
//! ```rust,ignore
//! let (pk, sk) = hybrid_kem_keygen();
//! let (shared_secret, ct) = hybrid_kem_encapsulate(&pk).unwrap();
//! let recovered   = hybrid_kem_decapsulate(&sk, &ct).unwrap();
//! assert_eq!(shared_secret.as_bytes(), recovered.as_bytes());
//! ```

#![cfg(feature = "hybrid-kem")]

use hkdf::Hkdf;
use ml_kem::kem::{Ciphertext, Decapsulate, Encapsulate, Key as MlKemKey};
use ml_kem::{DecapsulationKey, EncapsulationKey, KeyExport, MlKem768};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::HsmError;

// ── Constants ─────────────────────────────────────────────────────────────────

/// HKDF info string — uniquely identifies this hybrid scheme version.
const HYBRID_KEM_INFO: &[u8] = b"CRATON-HYBRID-X25519-MLKEM768-V1";

/// Length of the combined shared secret output (256-bit).
pub const SHARED_SECRET_LEN: usize = 32;

/// Byte length of the ML-KEM-768 ciphertext.
pub const MLKEM768_CT_LEN: usize = 1088;

/// Total byte length of a serialised [`HybridCiphertext`].
pub const HYBRID_CT_LEN: usize = 32 + MLKEM768_CT_LEN; // 1120

// ── Public key ────────────────────────────────────────────────────────────────

/// Combined public key for hybrid KEM encapsulation.
pub struct HybridKemPublicKey {
    /// Recipient's long-term X25519 public key (32 bytes).
    pub x25519_pk: [u8; 32],
    /// Recipient's ML-KEM-768 encapsulation key.
    pub mlkem_ek: EncapsulationKey<MlKem768>,
}

impl HybridKemPublicKey {
    /// Serialise to `32 + 1184` = 1216 bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let ek_bytes = self.mlkem_ek.to_bytes();
        let mut out = Vec::with_capacity(32 + ek_bytes.len());
        out.extend_from_slice(&self.x25519_pk);
        out.extend_from_slice(&ek_bytes[..]);
        out
    }
}

// ── Secret key ────────────────────────────────────────────────────────────────

/// Combined secret key for hybrid KEM decapsulation — zeroized on drop.
#[derive(ZeroizeOnDrop)]
pub struct HybridKemSecretKey {
    /// Recipient's long-term X25519 static secret.
    #[zeroize(skip)] // x25519_dalek StaticSecret implements Zeroize internally
    x25519_sk: StaticSecret,
    /// ML-KEM-768 decapsulation key (contains the seed; sensitive).
    #[zeroize(skip)] // ml-kem types implement ZeroizeOnDrop via Drop
    mlkem_dk: DecapsulationKey<MlKem768>,
}

// ── Ciphertext ────────────────────────────────────────────────────────────────

/// Encapsulated ciphertext transmitted to the recipient.
///
/// Serialises to exactly [`HYBRID_CT_LEN`] (1120) bytes.
pub struct HybridCiphertext {
    /// Sender's ephemeral X25519 public key.
    pub x25519_epk: [u8; 32],
    /// ML-KEM-768 ciphertext (1088 bytes).
    pub mlkem_ct: Ciphertext<MlKem768>,
}

impl HybridCiphertext {
    /// Serialise to [`HYBRID_CT_LEN`] bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HYBRID_CT_LEN);
        out.extend_from_slice(&self.x25519_epk);
        out.extend_from_slice(&self.mlkem_ct[..]);
        out
    }

    /// Deserialise from exactly [`HYBRID_CT_LEN`] bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HsmError> {
        if bytes.len() != HYBRID_CT_LEN {
            return Err(HsmError::DataLenRange);
        }
        let mut x25519_epk = [0u8; 32];
        x25519_epk.copy_from_slice(&bytes[..32]);
        let mlkem_ct = bytes[32..]
            .try_into()
            .map_err(|_| HsmError::DataInvalid)?;
        Ok(Self {
            x25519_epk,
            mlkem_ct,
        })
    }
}

// ── Shared secret ─────────────────────────────────────────────────────────────

/// The 32-byte combined shared secret — zeroized on drop.
#[derive(ZeroizeOnDrop)]
pub struct HybridSharedSecret {
    bytes: [u8; SHARED_SECRET_LEN],
}

impl HybridSharedSecret {
    /// View the raw key material.  Feed directly into a KDF or AEAD key schedule.
    pub fn as_bytes(&self) -> &[u8; SHARED_SECRET_LEN] {
        &self.bytes
    }
}

// ── Key generation ────────────────────────────────────────────────────────────

/// Generate a fresh hybrid KEM keypair.
///
/// Uses the OS CSPRNG for the X25519 static secret and the FIPS DRBG for the
/// ML-KEM-768 seed (matching the randomness discipline in `pqc::ml_kem_keygen`).
pub fn hybrid_kem_keygen() -> (HybridKemPublicKey, HybridKemSecretKey) {
    // X25519 long-term keypair
    let x25519_sk = StaticSecret::random_from_rng(rand_core::OsRng);
    let x25519_pk = X25519PublicKey::from(&x25519_sk);

    // ML-KEM-768 keypair — seed sourced from the SP 800-90A DRBG, then
    // `DecapsulationKey::from_seed` derives (dk, ek). Infallible DRBG failures
    // abort the process (see `pqc::PqcDrbgRng`); unwrap here is a panic-on-abort
    // branch that cannot actually fire.
    let mut seed = [0u8; 64];
    let mut drbg = crate::crypto::drbg::HmacDrbg::new()
        .expect("DRBG construction is infallible outside POST_FAILED");
    drbg.generate(&mut seed)
        .expect("DRBG generation is infallible (aborts process on failure)");
    let mlkem_dk = DecapsulationKey::<MlKem768>::from_seed(seed.into());
    let mlkem_ek = mlkem_dk.encapsulation_key().clone();

    let pk = HybridKemPublicKey {
        x25519_pk: x25519_pk.to_bytes(),
        mlkem_ek,
    };
    let sk = HybridKemSecretKey {
        x25519_sk,
        mlkem_dk,
    };
    (pk, sk)
}

// ── Encapsulate ───────────────────────────────────────────────────────────────

/// Encapsulate: produce a shared secret and a ciphertext for the recipient.
///
/// The caller sends `ct` to the recipient; both parties derive the same
/// [`HybridSharedSecret`] without communicating it directly.
///
/// # Errors
/// [`HsmError::GeneralError`] if ML-KEM encapsulation fails (library invariant
/// violation; should not occur with a valid recipient public key).
pub fn hybrid_kem_encapsulate(
    recipient_pk: &HybridKemPublicKey,
) -> Result<(HybridSharedSecret, HybridCiphertext), HsmError> {
    // ── Step 1: X25519 ephemeral DH ──────────────────────────────────────────
    let eph_sk = EphemeralSecret::random_from_rng(rand_core::OsRng);
    let eph_pk = X25519PublicKey::from(&eph_sk);
    let recipient_x25519 = X25519PublicKey::from(recipient_pk.x25519_pk);
    let x25519_ss = eph_sk.diffie_hellman(&recipient_x25519);

    // ── Step 2: ML-KEM-768 encapsulation ─────────────────────────────────────
    // DRBG-backed randomness for FIPS compliance (SP 800-90A health testing).
    let mut rng = crate::crypto::pqc::new_rng()?;
    let (mlkem_ct, mlkem_ss) = recipient_pk.mlkem_ek.encapsulate_with_rng(&mut rng);

    // ── Step 3: HKDF-SHA-256 combination ─────────────────────────────────────
    // IKM = x25519_ss (32B) || mlkem_ss (32B); both secrets contribute entropy.
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(x25519_ss.as_bytes());
    ikm[32..].copy_from_slice(&mlkem_ss[..]);

    let mut shared = [0u8; SHARED_SECRET_LEN];
    Hkdf::<Sha256>::new(None, &ikm)
        .expand(HYBRID_KEM_INFO, &mut shared)
        .map_err(|_| HsmError::GeneralError)?;

    // Wipe IKM from stack immediately
    ikm.zeroize();

    Ok((
        HybridSharedSecret { bytes: shared },
        HybridCiphertext {
            x25519_epk: eph_pk.to_bytes(),
            mlkem_ct,
        },
    ))
}

// ── Decapsulate ───────────────────────────────────────────────────────────────

/// Decapsulate: recover the shared secret from `ct` using the recipient's secret key.
///
/// ML-KEM-768 is designed to be *implicit rejection* secure: a malformed
/// ciphertext produces a pseudorandom (but incorrect) shared secret rather
/// than an error, preventing adaptive chosen-ciphertext distinguishing attacks.
/// The X25519 leg does the same by construction.
///
/// # Errors
/// Returns [`HsmError::DataInvalid`] if `ct` is structurally malformed.
pub fn hybrid_kem_decapsulate(
    sk: &HybridKemSecretKey,
    ct: &HybridCiphertext,
) -> Result<HybridSharedSecret, HsmError> {
    // ── Step 1: X25519 DH ────────────────────────────────────────────────────
    let eph_pk = X25519PublicKey::from(ct.x25519_epk);
    let x25519_ss = sk.x25519_sk.diffie_hellman(&eph_pk);

    // ── Step 2: ML-KEM-768 decapsulation ─────────────────────────────────────
    // Returns a shared key even on failure (implicit rejection — FIPS 203 §6.4)
    let mlkem_ss = sk.mlkem_dk.decapsulate(&ct.mlkem_ct);

    // ── Step 3: HKDF-SHA-256 combination ─────────────────────────────────────
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(x25519_ss.as_bytes());
    ikm[32..].copy_from_slice(&mlkem_ss[..]);

    let mut shared = [0u8; SHARED_SECRET_LEN];
    Hkdf::<Sha256>::new(None, &ikm)
        .expand(HYBRID_KEM_INFO, &mut shared)
        .map_err(|_| HsmError::GeneralError)?;

    ikm.zeroize();

    Ok(HybridSharedSecret { bytes: shared })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encap_decap_roundtrip() {
        let (pk, sk) = hybrid_kem_keygen();
        let (ss_enc, ct) = hybrid_kem_encapsulate(&pk).unwrap();
        let ss_dec = hybrid_kem_decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss_enc.as_bytes(), ss_dec.as_bytes());
    }

    #[test]
    fn ciphertext_serialisation() {
        let (pk, sk) = hybrid_kem_keygen();
        let (_, ct) = hybrid_kem_encapsulate(&pk).unwrap();
        let bytes = ct.to_bytes();
        assert_eq!(bytes.len(), HYBRID_CT_LEN);
        let ct2 = HybridCiphertext::from_bytes(&bytes).unwrap();
        // Round-trip decapsulation must still succeed
        hybrid_kem_decapsulate(&sk, &ct2).unwrap();
    }

    #[test]
    fn different_keys_different_secrets() {
        let (pk, sk) = hybrid_kem_keygen();
        let (pk2, sk2) = hybrid_kem_keygen();
        let (ss1, ct) = hybrid_kem_encapsulate(&pk).unwrap();
        // Decapsulate with wrong key → different (pseudorandom) secret
        let ss_wrong = hybrid_kem_decapsulate(&sk2, &ct).unwrap();
        assert_ne!(ss1.as_bytes(), ss_wrong.as_bytes());
    }

    #[test]
    fn two_independent_encapsulations_differ() {
        let (pk, _sk) = hybrid_kem_keygen();
        let (ss1, _ct1) = hybrid_kem_encapsulate(&pk).unwrap();
        let (ss2, _ct2) = hybrid_kem_encapsulate(&pk).unwrap();
        // Each encapsulation generates fresh ephemeral material
        assert_ne!(ss1.as_bytes(), ss2.as_bytes());
    }
}
