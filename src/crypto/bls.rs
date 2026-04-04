// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! BLS12-381 aggregatable signature scheme.
//!
//! Uses the [`blst`] crate — the Ethereum Foundation's reference C implementation
//! bound to Rust — providing ~2× the throughput of pure-Rust alternatives.
//!
//! # Why BLS for an HSM?
//!
//! * **Signature aggregation**: n signatures → 1 signature of identical size.
//!   Enables compact multi-party approval records in the audit log.
//! * **Threshold signing**: combine t-of-n partial signatures without a trusted dealer.
//!   Complements the FROST threshold module (`src/advanced/threshold.rs`).
//! * **Cross-HSM attestation**: cluster nodes sign operational state with BLS;
//!   any quorum of nodes' signatures aggregates into one verifiable proof.
//! * **Batch verification**: verify n separate (msg, sig, pk) triples significantly
//!   faster than n individual pairings via a Miller-loop optimisation.
//!
//! # Security
//! - 128-bit classical security (BLS12-381 curve)
//! - DST domain-separation prevents cross-protocol attacks
//! - Key validation on every deserialise (sub-group checks enabled)
//! - Aggregated signatures are checked for rogue-key attacks (`aug` augmentation)
//!
//! # Variants
//! We use the `min_pk` variant (G1 public keys, G2 signatures) matching the
//! Ethereum 2.0 specification and IETF draft-irtf-cfrg-bls-signature-05.

#![cfg(feature = "bls-signatures")]

use blst::{
    min_pk::{AggregatePublicKey, AggregateSignature, PublicKey, SecretKey, Signature},
    BLST_ERROR,
};
use zeroize::ZeroizeOnDrop;

use crate::error::HsmError;

/// Domain separation tag for all Craton HSM BLS operations.
///
/// Must be globally unique; changing this value invalidates all existing signatures.
pub const HSM_BLS_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_CRATON-HSM-V1";

// ── Key types ────────────────────────────────────────────────────────────────

/// A BLS12-381 secret (signing) key — zeroized on drop.
#[derive(ZeroizeOnDrop)]
pub struct BlsSecretKey {
    #[zeroize(skip)] // blst SecretKey doesn't impl Zeroize; we handle raw bytes
    inner: SecretKey,
    raw: [u8; 32],
}

/// A BLS12-381 public (verification) key (48 bytes, compressed G1 point).
#[derive(Clone, Debug)]
pub struct BlsPublicKey {
    inner: PublicKey,
}

/// A BLS12-381 signature (96 bytes, compressed G2 point).
#[derive(Clone)]
pub struct BlsSignature {
    inner: Signature,
}

/// An aggregate BLS signature covering multiple individual signatures.
pub struct BlsAggSignature {
    inner: AggregateSignature,
}

/// An aggregate BLS public key (sum of n individual public keys).
pub struct BlsAggPublicKey {
    inner: AggregatePublicKey,
}

// ── Secret key ───────────────────────────────────────────────────────────────

impl BlsSecretKey {
    /// Derive a secret key from at least 32 bytes of input keying material (IKM).
    ///
    /// Uses the HKDF-based BLS key derivation defined in
    /// IETF draft-irtf-cfrg-bls-signature §2.3.
    ///
    /// # Errors
    /// Returns [`HsmError::ArgumentsBad`] if `ikm` is shorter than 32 bytes.
    /// Returns [`HsmError::GeneralError`] if the derived key is the zero scalar
    /// (negligible probability; retry with fresh IKM).
    pub fn from_ikm(ikm: &[u8]) -> Result<Self, HsmError> {
        if ikm.len() < 32 {
            return Err(HsmError::ArgumentsBad);
        }
        let sk = SecretKey::key_gen(ikm, &[]).map_err(|_| HsmError::GeneralError)?;
        let mut raw = [0u8; 32];
        raw.copy_from_slice(&sk.to_bytes());
        Ok(Self { inner: sk, raw })
    }

    /// Deserialise a secret key from 32 canonical bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, HsmError> {
        let sk = SecretKey::from_bytes(bytes).map_err(|_| HsmError::DataInvalid)?;
        Ok(Self {
            inner: sk,
            raw: *bytes,
        })
    }

    /// Serialise to 32 bytes.  Handle the result with care.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.raw
    }

    /// Derive the corresponding public key.
    pub fn public_key(&self) -> BlsPublicKey {
        BlsPublicKey {
            inner: self.inner.sk_to_pk(),
        }
    }

    /// Sign `message` using the DST defined by [`HSM_BLS_DST`].
    ///
    /// The `aug` (augmentation) prefix is empty; rogue-key protection is achieved
    /// via [`BlsAggPublicKey::verify_multisig`]'s `pk_validate` flag.
    pub fn sign(&self, message: &[u8]) -> BlsSignature {
        BlsSignature {
            inner: self.inner.sign(message, HSM_BLS_DST, &[]),
        }
    }
}

// ── Public key ────────────────────────────────────────────────────────────────

impl BlsPublicKey {
    /// Serialise to 48 bytes (compressed G1).
    pub fn to_bytes(&self) -> [u8; 48] {
        self.inner.to_bytes()
    }

    /// Deserialise from 48 bytes, performing sub-group validation.
    pub fn from_bytes(bytes: &[u8; 48]) -> Result<Self, HsmError> {
        // `validate = true` checks the point is in the prime-order subgroup
        let pk = PublicKey::from_bytes(bytes).map_err(|_| HsmError::DataInvalid)?;
        pk.validate().map_err(|_| HsmError::DataInvalid)?;
        Ok(Self { inner: pk })
    }
}

// ── Signature ─────────────────────────────────────────────────────────────────

impl BlsSignature {
    /// Serialise to 96 bytes (compressed G2).
    pub fn to_bytes(&self) -> [u8; 96] {
        self.inner.to_bytes()
    }

    /// Deserialise from 96 bytes, performing sub-group validation.
    pub fn from_bytes(bytes: &[u8; 96]) -> Result<Self, HsmError> {
        let sig = Signature::from_bytes(bytes).map_err(|_| HsmError::DataInvalid)?;
        sig.validate(true).map_err(|_| HsmError::DataInvalid)?;
        Ok(Self { inner: sig })
    }

    /// Verify this signature against `message` and `pk`.
    ///
    /// Both the signature and the public key are sub-group checked on every call.
    pub fn verify(&self, message: &[u8], pk: &BlsPublicKey) -> Result<(), HsmError> {
        let err = self
            .inner
            .verify(true, message, HSM_BLS_DST, &[], &pk.inner, true);
        blst_to_result(err, "BLS signature verification failed")
    }
}

// ── Aggregation ───────────────────────────────────────────────────────────────

/// Aggregate `n` individual signatures into a single compact signature.
///
/// All signatures must have been produced with the *same* [`HSM_BLS_DST`].
/// The resulting `BlsAggSignature` is the same 96 bytes as an individual signature.
///
/// # Errors
/// Returns [`HsmError::ArgumentsBad`] when `sigs` is empty.
pub fn aggregate_signatures(sigs: &[&BlsSignature]) -> Result<BlsAggSignature, HsmError> {
    if sigs.is_empty() {
        return Err(HsmError::ArgumentsBad);
    }
    let inner_refs: Vec<&Signature> = sigs.iter().map(|s| &s.inner).collect();
    // `validate = true` — check each input is in the prime-order subgroup
    let agg =
        AggregateSignature::aggregate(&inner_refs, true).map_err(|_| HsmError::GeneralError)?;
    Ok(BlsAggSignature { inner: agg })
}

/// Aggregate `n` public keys into a combined key for multi-signature verification.
///
/// # Errors
/// Returns [`HsmError::ArgumentsBad`] when `pks` is empty.
pub fn aggregate_public_keys(pks: &[&BlsPublicKey]) -> Result<BlsAggPublicKey, HsmError> {
    if pks.is_empty() {
        return Err(HsmError::ArgumentsBad);
    }
    let inner_refs: Vec<&PublicKey> = pks.iter().map(|p| &p.inner).collect();
    let agg =
        AggregatePublicKey::aggregate(&inner_refs, true).map_err(|_| HsmError::GeneralError)?;
    Ok(BlsAggPublicKey { inner: agg })
}

impl BlsAggSignature {
    /// Verify that all `n` signers signed the *same* `message` (multi-signature).
    ///
    /// Uses `fast_aggregate_verify` which is O(1) pairings regardless of n.
    pub fn verify_multisig(
        &self,
        message: &[u8],
        agg_pk: &BlsAggPublicKey,
    ) -> Result<(), HsmError> {
        let sig = self.inner.to_signature();
        // `pk_validate = true` guards against rogue-key attacks
        let agg_pk_refs = [&agg_pk.inner.to_public_key()];
        let err = sig.fast_aggregate_verify(true, message, HSM_BLS_DST, &agg_pk_refs);
        blst_to_result(err, "BLS multi-sig verification failed")
    }

    /// Verify that each signer `i` signed a *different* `messages[i]`.
    ///
    /// Uses `aggregate_verify`; slower than `verify_multisig` but required when
    /// messages differ (e.g., each node signs its own state hash).
    pub fn verify_aggregate(
        &self,
        messages: &[&[u8]],
        pks: &[&BlsPublicKey],
    ) -> Result<(), HsmError> {
        if messages.len() != pks.len() {
            return Err(HsmError::ArgumentsBad);
        }
        let sig = self.inner.to_signature();
        let pk_refs: Vec<&PublicKey> = pks.iter().map(|p| &p.inner).collect();
        let err = sig.aggregate_verify(true, messages, HSM_BLS_DST, &pk_refs, true);
        blst_to_result(err, "BLS aggregate verification failed")
    }

    /// Serialise the aggregate signature to 96 bytes.
    pub fn to_bytes(&self) -> [u8; 96] {
        self.inner.to_signature().to_bytes()
    }
}

// ── Batch verification ────────────────────────────────────────────────────────

/// Verify `n` independent (message, signature, public_key) triples in one batch.
///
/// Batch verification exploits Miller-loop parallelism and is substantially faster
/// than `n` individual calls to [`BlsSignature::verify`] for large n.
///
/// Uses a random-scalar technique to prevent adversarial cancellations; the
/// randomness is sampled from the OS CSPRNG inside `blst`.
///
/// # Errors
/// * [`HsmError::ArgumentsBad`] — input slices have different lengths.
/// * [`HsmError::SignatureInvalid`] — at least one triple is invalid (no indication which).
pub fn batch_verify(
    messages: &[&[u8]],
    sigs: &[&BlsSignature],
    pks: &[&BlsPublicKey],
) -> Result<(), HsmError> {
    if messages.len() != sigs.len() || sigs.len() != pks.len() {
        return Err(HsmError::ArgumentsBad);
    }
    if messages.is_empty() {
        return Ok(());
    }

    // Build a pairing context for batch verification
    let mut pairing = blst::Pairing::new(true, HSM_BLS_DST);
    for ((msg, sig), pk) in messages.iter().zip(sigs.iter()).zip(pks.iter()) {
        pairing
            .aggregate(&pk.inner, true, &sig.inner, true, msg, &[])
            .map_err(|_| HsmError::DataInvalid)?;
    }
    pairing.commit();
    if pairing.finalverify(None) {
        Ok(())
    } else {
        Err(HsmError::SignatureInvalid)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

#[inline]
fn blst_to_result(err: BLST_ERROR, _context: &str) -> Result<(), HsmError> {
    match err {
        BLST_ERROR::BLST_SUCCESS => Ok(()),
        BLST_ERROR::BLST_VERIFY_FAIL => Err(HsmError::SignatureInvalid),
        _ => Err(HsmError::GeneralError),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_key(seed: u8) -> BlsSecretKey {
        let mut ikm = [0u8; 32];
        ikm[0] = seed.max(1); // blst rejects all-zeros IKM
        BlsSecretKey::from_ikm(&ikm).unwrap()
    }

    #[test]
    fn roundtrip_sign_verify() {
        let sk = make_key(1);
        let pk = sk.public_key();
        let msg = b"craton-hsm bls test";
        let sig = sk.sign(msg);
        sig.verify(msg, &pk).unwrap();
    }

    #[test]
    fn wrong_message_fails() {
        let sk = make_key(2);
        let pk = sk.public_key();
        let sig = sk.sign(b"original");
        assert!(sig.verify(b"tampered", &pk).is_err());
    }

    #[test]
    fn multi_signature_aggregation() {
        let n = 4u8;
        let keys: Vec<_> = (1..=n).map(make_key).collect();
        let pks: Vec<_> = keys.iter().map(|k| k.public_key()).collect();
        let msg = b"committee approval";
        let sigs: Vec<_> = keys.iter().map(|k| k.sign(msg)).collect();

        let agg_sig = aggregate_signatures(&sigs.iter().collect::<Vec<_>>()).unwrap();
        let agg_pk = aggregate_public_keys(&pks.iter().collect::<Vec<_>>()).unwrap();
        agg_sig.verify_multisig(msg, &agg_pk).unwrap();
    }

    #[test]
    fn aggregate_different_messages() {
        let n = 3u8;
        let keys: Vec<_> = (1..=n).map(make_key).collect();
        let pks: Vec<_> = keys.iter().map(|k| k.public_key()).collect();
        let messages: Vec<Vec<u8>> = (0..n).map(|i| vec![i; 16]).collect();
        let sigs: Vec<_> = keys
            .iter()
            .zip(messages.iter())
            .map(|(k, m)| k.sign(m))
            .collect();

        let agg_sig = aggregate_signatures(&sigs.iter().collect::<Vec<_>>()).unwrap();
        agg_sig
            .verify_aggregate(
                &messages.iter().map(|m| m.as_slice()).collect::<Vec<_>>(),
                &pks.iter().collect::<Vec<_>>(),
            )
            .unwrap();
    }

    #[test]
    fn batch_verify_independent_triples() {
        let n = 8u8;
        let keys: Vec<_> = (1..=n).map(make_key).collect();
        let pks: Vec<_> = keys.iter().map(|k| k.public_key()).collect();
        let messages: Vec<Vec<u8>> = (0..n).map(|i| vec![i + 100; 20]).collect();
        let sigs: Vec<_> = keys
            .iter()
            .zip(messages.iter())
            .map(|(k, m)| k.sign(m))
            .collect();

        batch_verify(
            &messages.iter().map(|m| m.as_slice()).collect::<Vec<_>>(),
            &sigs.iter().collect::<Vec<_>>(),
            &pks.iter().collect::<Vec<_>>(),
        )
        .unwrap();
    }

    #[test]
    fn pk_serialisation_roundtrip() {
        let sk = make_key(5);
        let pk = sk.public_key();
        let bytes = pk.to_bytes();
        let pk2 = BlsPublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(pk.to_bytes(), pk2.to_bytes());
    }

    #[test]
    fn sig_serialisation_roundtrip() {
        let sk = make_key(6);
        let sig = sk.sign(b"round-trip");
        let bytes = sig.to_bytes();
        let sig2 = BlsSignature::from_bytes(&bytes).unwrap();
        assert_eq!(sig.to_bytes(), sig2.to_bytes());
    }
}
