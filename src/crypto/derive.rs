// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
use p256::ecdh::diffie_hellman as p256_dh;
use p256::PublicKey as P256PublicKey;
use p256::SecretKey as P256SecretKey;
use p384::ecdh::diffie_hellman as p384_dh;
use p384::PublicKey as P384PublicKey;
use p384::SecretKey as P384SecretKey;
use zeroize::Zeroizing;

use crate::error::{HsmError, HsmResult};
use crate::store::key_material::RawKeyMaterial;

/// Maximum HKDF-SHA256 output length (255 * 32 = 8160 bytes per RFC 5869).
/// We cap at a practical limit well below this.
const MAX_OKM_LEN: usize = 64;

/// ECDH key derivation for P-256.
///
/// `okm_len` specifies the desired derived key length in bytes. If `None`,
/// defaults to 32 (matching P-256's security level). Common values:
/// - 16 for AES-128
/// - 24 for AES-192
/// - 32 for AES-256
pub fn ecdh_p256(
    private_key_bytes: &[u8],
    peer_public_key_sec1: &[u8],
    okm_len: Option<usize>,
) -> HsmResult<RawKeyMaterial> {
    let derived_len = okm_len.unwrap_or(32);
    validate_okm_len(derived_len)?;

    let secret_key =
        P256SecretKey::from_slice(private_key_bytes).map_err(|_| HsmError::KeyHandleInvalid)?;
    let peer_public =
        P256PublicKey::from_sec1_bytes(peer_public_key_sec1).map_err(|_| HsmError::ArgumentsBad)?;

    let shared_secret = p256_dh(secret_key.to_nonzero_scalar(), peer_public.as_affine());

    // Copy raw bytes into a Zeroizing wrapper so the shared secret is scrubbed
    // from memory promptly after HKDF extraction, regardless of compiler optimizations.
    let raw_bytes = Zeroizing::new(shared_secret.raw_secret_bytes().to_vec());

    // Build context-enriched HKDF info for domain separation (SP 800-56C §4.1).
    //
    // Uses the P-256 OID (1.2.840.10045.3.1.7) as the algorithm identifier per
    // NIST SP 800-56C Rev 2 §4.1, which recommends OID-based identifiers for
    // interoperability. The info string also includes output length and both
    // public keys so that:
    //  - Different curves produce different keys (OID)
    //  - Different requested lengths produce different keys (okm_len)
    //  - Different key pairs between the same parties produce different keys (public keys)
    //
    // NOTE: Changing this info string is a BREAKING CHANGE — existing derived
    // keys will not reproduce. Version the salt (HKDF_SALT) if migration is needed.
    let our_public = secret_key.public_key();
    let our_pk_bytes = elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(&our_public, false);
    // OID 1.2.840.10045.3.1.7 (P-256 / prime256v1) DER-encoded
    const P256_OID: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    let mut info =
        Vec::with_capacity(P256_OID.len() + 4 + our_pk_bytes.len() + peer_public_key_sec1.len());
    info.extend_from_slice(P256_OID);
    info.extend_from_slice(&(derived_len as u32).to_be_bytes());
    info.extend_from_slice(our_pk_bytes.as_bytes());
    info.extend_from_slice(peer_public_key_sec1);

    // Apply HKDF-SHA256 per NIST SP 800-56C — raw shared secret must not be used directly
    let okm = apply_hkdf(&raw_bytes, &info, derived_len)?;
    Ok(RawKeyMaterial::new(okm))
}

/// ECDH key derivation for P-384.
///
/// `okm_len` specifies the desired derived key length in bytes. If `None`,
/// defaults to 48 (matching P-384's security level). Common values:
/// - 16 for AES-128
/// - 24 for AES-192
/// - 32 for AES-256
/// - 48 for full P-384 shared secret length
pub fn ecdh_p384(
    private_key_bytes: &[u8],
    peer_public_key_sec1: &[u8],
    okm_len: Option<usize>,
) -> HsmResult<RawKeyMaterial> {
    let derived_len = okm_len.unwrap_or(48);
    validate_okm_len(derived_len)?;

    let secret_key =
        P384SecretKey::from_slice(private_key_bytes).map_err(|_| HsmError::KeyHandleInvalid)?;
    let peer_public =
        P384PublicKey::from_sec1_bytes(peer_public_key_sec1).map_err(|_| HsmError::ArgumentsBad)?;

    let shared_secret = p384_dh(secret_key.to_nonzero_scalar(), peer_public.as_affine());

    // Copy raw bytes into a Zeroizing wrapper so the shared secret is scrubbed
    // from memory promptly after HKDF extraction.
    let raw_bytes = Zeroizing::new(shared_secret.raw_secret_bytes().to_vec());

    // Build context-enriched HKDF info for domain separation (SP 800-56C §4.1).
    // Uses the P-384 OID (1.3.132.0.34) as the algorithm identifier per NIST
    // SP 800-56C Rev 2 §4.1 for interoperability.
    let our_public = secret_key.public_key();
    let our_pk_bytes = elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(&our_public, false);
    // OID 1.3.132.0.34 (P-384 / secp384r1) DER-encoded
    const P384_OID: &[u8] = &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22];
    let mut info =
        Vec::with_capacity(P384_OID.len() + 4 + our_pk_bytes.len() + peer_public_key_sec1.len());
    info.extend_from_slice(P384_OID);
    info.extend_from_slice(&(derived_len as u32).to_be_bytes());
    info.extend_from_slice(our_pk_bytes.as_bytes());
    info.extend_from_slice(peer_public_key_sec1);

    // Apply HKDF-SHA256 per NIST SP 800-56C — raw shared secret must not be used directly
    let okm = apply_hkdf(&raw_bytes, &info, derived_len)?;
    Ok(RawKeyMaterial::new(okm))
}

/// Validate the requested output key material length.
fn validate_okm_len(len: usize) -> HsmResult<()> {
    if len == 0 || len > MAX_OKM_LEN {
        tracing::error!(
            "ECDH: requested OKM length {} is out of range (1..={})",
            len,
            MAX_OKM_LEN
        );
        return Err(HsmError::KeySizeRange);
    }
    Ok(())
}

/// Fixed salt for HKDF extraction per NIST SP 800-56C Rev 2.
/// Using a non-null salt improves extraction randomness compared to
/// the default all-zero salt. This value is a fixed public constant
/// and does not need to be secret.
const HKDF_SALT: &[u8] = b"CratonHSM-ECDH-HKDF-Salt-v1";

/// Apply HKDF-SHA256 to raw ECDH shared secret (NIST SP 800-56C).
/// Uses a fixed salt for extraction and a context-enriched info string
/// that includes the curve label, output key length, and public keys
/// of both parties for domain separation per NIST SP 800-56C Rev 2 §4.1.
/// `okm_len` specifies the output length.
fn apply_hkdf(ikm: &[u8], info: &[u8], okm_len: usize) -> HsmResult<Vec<u8>> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), ikm);
    let mut okm = vec![0u8; okm_len];
    hk.expand(info, &mut okm).map_err(|e| {
        // Zeroize the output buffer on error before returning
        use zeroize::Zeroize;
        okm.zeroize();
        tracing::error!("HKDF expand failed: {}", e);
        HsmError::GeneralError
    })?;
    Ok(okm)
}

/// Upper bound on X9.63 KDF output, matching the ABI's `MAX_DERIVE_OUT`.
const MAX_X963_OUT: usize = 1024;

/// Raw ECDH shared secret (big-endian x-coordinate) for P-256 — **no KDF**.
///
/// Unlike [`ecdh_p256`], this returns the bare shared secret Z. The PKCS#11
/// `CK_ECDH1_DERIVE_PARAMS.kdf` field selects the KDF the caller then applies
/// (`CKD_NULL` truncation or `CKD_SHA*_KDF` via [`x963_kdf`]). Because both
/// parties compute the same Z, both derive the same key — the property the
/// party-asymmetric HKDF path deliberately lacked.
pub fn ecdh_p256_raw(
    private_key_bytes: &[u8],
    peer_public_key_sec1: &[u8],
) -> HsmResult<Zeroizing<Vec<u8>>> {
    let secret_key =
        P256SecretKey::from_slice(private_key_bytes).map_err(|_| HsmError::KeyHandleInvalid)?;
    let peer_public =
        P256PublicKey::from_sec1_bytes(peer_public_key_sec1).map_err(|_| HsmError::ArgumentsBad)?;
    let shared = p256_dh(secret_key.to_nonzero_scalar(), peer_public.as_affine());
    Ok(Zeroizing::new(shared.raw_secret_bytes().to_vec()))
}

/// Raw ECDH shared secret (big-endian x-coordinate) for P-384 — **no KDF**.
/// See [`ecdh_p256_raw`].
pub fn ecdh_p384_raw(
    private_key_bytes: &[u8],
    peer_public_key_sec1: &[u8],
) -> HsmResult<Zeroizing<Vec<u8>>> {
    let secret_key =
        P384SecretKey::from_slice(private_key_bytes).map_err(|_| HsmError::KeyHandleInvalid)?;
    let peer_public =
        P384PublicKey::from_sec1_bytes(peer_public_key_sec1).map_err(|_| HsmError::ArgumentsBad)?;
    let shared = p384_dh(secret_key.to_nonzero_scalar(), peer_public.as_affine());
    Ok(Zeroizing::new(shared.raw_secret_bytes().to_vec()))
}

/// ANSI-X9.63 / NIST SP 800-56A Rev 2 single-step concatenation KDF:
///
/// ```text
/// K = Hash(Z ‖ counter₁ ‖ SharedInfo) ‖ Hash(Z ‖ counter₂ ‖ SharedInfo) ‖ …
/// ```
///
/// where `counter` is a 32-bit big-endian integer starting at 1. This is the
/// KDF used by the PKCS#11 `CKD_SHA*_KDF` derivation functions.
pub fn x963_kdf(
    hash: crate::crypto::hkdf_mech::KdfHash,
    z: &[u8],
    shared_info: &[u8],
    out_len: usize,
) -> HsmResult<Vec<u8>> {
    use crate::crypto::hkdf_mech::KdfHash;
    use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};

    if out_len == 0 || out_len > MAX_X963_OUT {
        return Err(HsmError::KeySizeRange);
    }

    macro_rules! run {
        ($H:ty) => {{
            let hlen = <$H as Digest>::output_size();
            let blocks = out_len.div_ceil(hlen);
            if blocks > u32::MAX as usize {
                return Err(HsmError::KeySizeRange);
            }
            let mut out = Vec::with_capacity(blocks * hlen);
            for counter in 1u32..=(blocks as u32) {
                let mut h = <$H>::new();
                h.update(z);
                h.update(counter.to_be_bytes());
                h.update(shared_info);
                out.extend_from_slice(&h.finalize());
            }
            out.truncate(out_len);
            out
        }};
    }

    let out = match hash {
        KdfHash::Sha224 => run!(Sha224),
        KdfHash::Sha256 => run!(Sha256),
        KdfHash::Sha384 => run!(Sha384),
        KdfHash::Sha512 => run!(Sha512),
    };
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keygen::{generate_ec_p256_key_pair, generate_ec_p384_key_pair};

    #[test]
    fn test_ecdh_p256_produces_key_material() {
        // ECDH + HKDF with party-specific info means the two sides derive
        // different keys (by design: info includes our_pubkey || peer_pubkey
        // in different order). Verify each side produces valid key material.
        let (priv_a, _pub_a) = generate_ec_p256_key_pair().unwrap();
        let (_priv_b, pub_b) = generate_ec_p256_key_pair().unwrap();

        let secret = ecdh_p256(priv_a.as_bytes(), &pub_b, None).unwrap();
        assert_eq!(secret.len(), 32); // default okm_len for P-256
                                      // Key material should not be all zeros
        assert!(!secret.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_ecdh_p384_produces_key_material() {
        let (priv_a, _pub_a) = generate_ec_p384_key_pair().unwrap();
        let (_priv_b, pub_b) = generate_ec_p384_key_pair().unwrap();

        let secret = ecdh_p384(priv_a.as_bytes(), &pub_b, None).unwrap();
        assert_eq!(secret.len(), 48); // default okm_len for P-384
        assert!(!secret.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_ecdh_deterministic() {
        // Same inputs must produce same output
        let (priv_a, _pub_a) = generate_ec_p256_key_pair().unwrap();
        let (_priv_b, pub_b) = generate_ec_p256_key_pair().unwrap();

        let secret_1 = ecdh_p256(priv_a.as_bytes(), &pub_b, Some(32)).unwrap();
        let secret_2 = ecdh_p256(priv_a.as_bytes(), &pub_b, Some(32)).unwrap();

        assert_eq!(secret_1.as_bytes(), secret_2.as_bytes());
    }

    #[test]
    fn test_ecdh_different_okm_lengths() {
        let (priv_a, _pub_a) = generate_ec_p256_key_pair().unwrap();
        let (_priv_b, pub_b) = generate_ec_p256_key_pair().unwrap();

        // okm_len=16 (AES-128), 24 (AES-192), 32 (AES-256) all work
        let s16 = ecdh_p256(priv_a.as_bytes(), &pub_b, Some(16)).unwrap();
        assert_eq!(s16.len(), 16);

        let s24 = ecdh_p256(priv_a.as_bytes(), &pub_b, Some(24)).unwrap();
        assert_eq!(s24.len(), 24);

        let s32 = ecdh_p256(priv_a.as_bytes(), &pub_b, Some(32)).unwrap();
        assert_eq!(s32.len(), 32);

        // Different lengths must produce different keys (not just truncations,
        // because okm_len is included in the HKDF info string)
        assert_ne!(s16.as_bytes(), &s32.as_bytes()[..16]);
    }

    #[test]
    fn test_ecdh_invalid_private_key() {
        let garbage_private = vec![0xFFu8; 32];
        let (_priv_b, pub_b) = generate_ec_p256_key_pair().unwrap();
        let result = ecdh_p256(&garbage_private, &pub_b, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_ecdh_invalid_peer_public_key() {
        let (priv_a, _pub_a) = generate_ec_p256_key_pair().unwrap();
        let garbage_public = vec![0xFFu8; 65];
        let result = ecdh_p256(priv_a.as_bytes(), &garbage_public, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_ecdh_raw_two_party_agreement_p256() {
        // The raw shared secret must be symmetric: priv_a·pub_b == priv_b·pub_a.
        // (The party-asymmetric HKDF path deliberately broke this; raw-Z fixes it.)
        let (priv_a, pub_a) = generate_ec_p256_key_pair().unwrap();
        let (priv_b, pub_b) = generate_ec_p256_key_pair().unwrap();

        let z_ab = ecdh_p256_raw(priv_a.as_bytes(), &pub_b).unwrap();
        let z_ba = ecdh_p256_raw(priv_b.as_bytes(), &pub_a).unwrap();
        assert_eq!(z_ab.as_slice(), z_ba.as_slice(), "ECDH must be symmetric");
        assert_eq!(z_ab.len(), 32, "P-256 raw Z is 32 bytes");
    }

    #[test]
    fn test_ecdh_raw_two_party_agreement_p384() {
        let (priv_a, pub_a) = generate_ec_p384_key_pair().unwrap();
        let (priv_b, pub_b) = generate_ec_p384_key_pair().unwrap();

        let z_ab = ecdh_p384_raw(priv_a.as_bytes(), &pub_b).unwrap();
        let z_ba = ecdh_p384_raw(priv_b.as_bytes(), &pub_a).unwrap();
        assert_eq!(z_ab.as_slice(), z_ba.as_slice());
        assert_eq!(z_ab.len(), 48, "P-384 raw Z is 48 bytes");
    }

    #[test]
    fn test_x963_kdf_deterministic_and_length() {
        use crate::crypto::hkdf_mech::KdfHash;
        let z = [0x11u8; 32];
        let info = b"shared info";
        let k1 = x963_kdf(KdfHash::Sha256, &z, info, 48).unwrap();
        let k2 = x963_kdf(KdfHash::Sha256, &z, info, 48).unwrap();
        assert_eq!(k1, k2, "X9.63 KDF must be deterministic");
        assert_eq!(k1.len(), 48);

        // Different SharedInfo → different output.
        let k3 = x963_kdf(KdfHash::Sha256, &z, b"other info", 48).unwrap();
        assert_ne!(k1, k3);

        // The first 32 bytes equal the first hash block: SHA256(Z ‖ 0x00000001 ‖ info).
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(z);
        h.update(1u32.to_be_bytes());
        h.update(info);
        let block1 = h.finalize();
        assert_eq!(&k1[..32], block1.as_slice());
    }

    #[test]
    fn test_x963_kdf_rejects_bad_length() {
        use crate::crypto::hkdf_mech::KdfHash;
        assert!(x963_kdf(KdfHash::Sha256, &[0u8; 32], b"", 0).is_err());
        assert!(x963_kdf(KdfHash::Sha256, &[0u8; 32], b"", 100_000).is_err());
    }
}
