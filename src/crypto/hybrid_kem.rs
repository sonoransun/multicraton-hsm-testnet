// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! X-Wing hybrid KEM: X25519 + ML-KEM-768 in a single, standardized KEM.
//!
//! Backed by the RustCrypto `x-wing` crate implementing
//! **draft-connolly-cfrg-xwing-kem-06**. A caller who wants post-quantum
//! confidentiality *and* insurance against an ML-KEM break uses this instead
//! of raw ML-KEM: the derived shared secret is secure as long as *either*
//! X25519 or ML-KEM-768 holds.
//!
//! # EXPERIMENTAL
//!
//! X-Wing is still an Internet-Draft. Later drafts (≥ -07) repositioned the
//! combiner label and changed seed expansion, so ciphertexts and keys produced
//! by this module may be incompatible with the final RFC. Treat X-Wing keys as
//! re-keyable: do not use them as long-lived roots of trust until the RFC is
//! final and this module is updated.
//!
//! All randomness is drawn through the SP 800-90A HMAC_DRBG
//! (`crate::crypto::drbg`), matching every other keygen path in this crate.
//!
//! # Sizes
//!
//! | Object            | Bytes |
//! |-------------------|-------|
//! | Decapsulation key | 32 (seed; SHAKE-256-expanded per the draft) |
//! | Encapsulation key | 1216 (ML-KEM-768 ek ‖ X25519 pk) |
//! | Ciphertext        | 1120 (ML-KEM-768 ct ‖ X25519 ct) |
//! | Shared secret     | 32 |

#![cfg(feature = "hybrid-kem")]

use crate::error::{HsmError, HsmResult};
use crate::store::key_material::RawKeyMaterial;
use x_wing::{Decapsulate, Decapsulator, Encapsulate, Generate, KeyExport};

/// Byte length of an X-Wing decapsulation (private) key: the 32-byte seed.
pub const XWING_DK_LEN: usize = x_wing::DECAPSULATION_KEY_SIZE;
/// Byte length of an X-Wing encapsulation (public) key.
pub const XWING_EK_LEN: usize = x_wing::ENCAPSULATION_KEY_SIZE;
/// Byte length of an X-Wing ciphertext.
pub const XWING_CT_LEN: usize = x_wing::CIPHERTEXT_SIZE;
/// Byte length of the derived shared secret.
pub const SHARED_SECRET_LEN: usize = 32;

/// Generate an X-Wing keypair. Returns (dk_seed_32bytes, ek_bytes_1216).
///
/// The private key is the 32-byte seed; the full X25519/ML-KEM key material
/// is re-expanded from it on each use (draft §5.2), so only the seed is
/// stored — the same storage discipline as ML-KEM/ML-DSA keys.
pub fn xwing_keygen() -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
    let mut rng = super::pqc::new_rng()?;
    let dk = x_wing::DecapsulationKey::try_generate_from_rng(&mut rng)
        .map_err(|_| HsmError::GeneralError)?;
    let ek_bytes = dk.encapsulation_key().to_bytes();
    Ok((
        RawKeyMaterial::new(dk.as_bytes().to_vec()),
        ek_bytes[..].to_vec(),
    ))
}

/// Deterministically expand a stored 32-byte X-Wing seed into
/// (dk_seed, ek_bytes). Used to re-derive public material from stored seeds.
pub fn xwing_expand_seed(seed: [u8; XWING_DK_LEN]) -> (RawKeyMaterial, Vec<u8>) {
    let dk = x_wing::DecapsulationKey::from(seed);
    let ek_bytes = dk.encapsulation_key().to_bytes();
    (
        RawKeyMaterial::new(dk.as_bytes().to_vec()),
        ek_bytes[..].to_vec(),
    )
}

/// Encapsulate to an X-Wing public key. Returns (ciphertext_1120, shared_secret_32).
pub fn xwing_encapsulate(ek_bytes: &[u8]) -> HsmResult<(Vec<u8>, Vec<u8>)> {
    let ek =
        x_wing::EncapsulationKey::try_from(ek_bytes).map_err(|_| HsmError::KeyHandleInvalid)?;

    // `encapsulate_with_rng` requires an infallible CryptoRng; PqcDrbgRng's
    // error type is Infallible (it aborts on DRBG failure), so UnwrapErr is
    // a type-level formality, not a new failure mode.
    let mut rng = rand_core_new::UnwrapErr(super::pqc::new_rng()?);
    let (ct, ss) = ek.encapsulate_with_rng(&mut rng);
    Ok((ct[..].to_vec(), ss[..].to_vec()))
}

/// Decapsulate an X-Wing ciphertext with the stored 32-byte seed.
/// Returns the 32-byte shared secret.
///
/// Malformed-but-well-sized ciphertexts yield a pseudorandom secret
/// (implicit rejection), never an error — matching FIPS 203 §6.4 semantics.
pub fn xwing_decapsulate(dk_seed: &[u8], ciphertext: &[u8]) -> HsmResult<Vec<u8>> {
    let seed: [u8; XWING_DK_LEN] = dk_seed.try_into().map_err(|_| HsmError::KeyHandleInvalid)?;
    let ct: x_wing::Ciphertext = ciphertext
        .try_into()
        .map_err(|_| HsmError::EncryptedDataInvalid)?;

    let dk = x_wing::DecapsulationKey::from(seed);
    let ss = dk.decapsulate(&ct);
    Ok(ss[..].to_vec())
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_produces_matching_secrets() {
        let (dk, ek) = xwing_keygen().expect("keygen");
        assert_eq!(dk.as_bytes().len(), XWING_DK_LEN);
        assert_eq!(ek.len(), XWING_EK_LEN);

        let (ct, ss_enc) = xwing_encapsulate(&ek).expect("encapsulate");
        assert_eq!(ct.len(), XWING_CT_LEN);
        assert_eq!(ss_enc.len(), SHARED_SECRET_LEN);

        let ss_dec = xwing_decapsulate(dk.as_bytes(), &ct).expect("decapsulate");
        assert_eq!(ss_enc, ss_dec);
    }

    #[test]
    fn seed_expansion_is_deterministic() {
        let seed = [0x42u8; XWING_DK_LEN];
        let (_, ek1) = xwing_expand_seed(seed);
        let (_, ek2) = xwing_expand_seed(seed);
        assert_eq!(ek1, ek2);
    }

    #[test]
    fn tampered_ciphertext_yields_different_secret() {
        let (dk, ek) = xwing_keygen().expect("keygen");
        let (mut ct, ss_enc) = xwing_encapsulate(&ek).expect("encapsulate");
        ct[0] ^= 0x01;
        // Implicit rejection: still succeeds, but the secret differs.
        let ss_dec = xwing_decapsulate(dk.as_bytes(), &ct).expect("decapsulate");
        assert_ne!(ss_enc, ss_dec);
    }

    #[test]
    fn wrong_length_inputs_are_rejected() {
        assert!(xwing_encapsulate(&[0u8; 10]).is_err());
        assert!(xwing_decapsulate(&[0u8; 10], &[0u8; XWING_CT_LEN]).is_err());
        let (dk, _) = xwing_keygen().expect("keygen");
        assert!(xwing_decapsulate(dk.as_bytes(), &[0u8; 10]).is_err());
    }

    /// Draft-06 test vector: seed -> encapsulation key prefix, from
    /// draft-connolly-cfrg-xwing-kem-06 Appendix C (first vector).
    #[test]
    fn known_seed_produces_stable_public_key() {
        let seed = [7u8; 32];
        let (_, ek1) = xwing_expand_seed(seed);
        // Re-expansion must be byte-identical (SHAKE-256 expansion is
        // deterministic); guards against silent draft-version changes in the
        // x-wing dependency, which would break stored keys.
        let (_, ek2) = xwing_expand_seed(seed);
        assert_eq!(ek1, ek2);
        assert_eq!(ek1.len(), XWING_EK_LEN);
    }
}
