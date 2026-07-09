// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! HKDF key-derivation core (RFC 5869 / NIST SP 800-56C Rev 2).
//!
//! This module implements the HMAC-based Extract-and-Expand Key Derivation
//! Function as a set of pure crypto primitives. Each entry point takes an
//! explicit [`KdfHash`] selector so the PKCS#11 ABI layer can map `CKM_*`
//! mechanisms (e.g. `CKM_HKDF_DERIVE`, `CKM_HKDF_DATA`) onto these functions
//! without this module depending on any PKCS#11 constants.
//!
//! Three stages are exposed:
//! - [`hkdf_extract`] — HKDF-Extract, producing a pseudo-random key (PRK).
//! - [`hkdf_expand`] — HKDF-Expand, stretching a PRK into output key material.
//! - [`hkdf_derive`] — the full Extract-then-Expand pipeline.

use hkdf::Hkdf;
use zeroize::Zeroizing;

use crate::error::{HsmError, HsmResult};

/// Hash function selector for HKDF operations.
///
/// The ABI layer maps `CKM_SHA*`-parameterised HKDF mechanisms onto these
/// variants; the underlying HMAC uses the corresponding SHA-2 digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfHash {
    /// SHA-224 (28-byte output).
    Sha224,
    /// SHA-256 (32-byte output).
    Sha256,
    /// SHA-384 (48-byte output).
    Sha384,
    /// SHA-512 (64-byte output).
    Sha512,
}

impl KdfHash {
    /// Output length of the underlying hash in bytes (a.k.a. `HashLen` in
    /// RFC 5869).
    pub fn output_len(self) -> usize {
        match self {
            KdfHash::Sha224 => 28,
            KdfHash::Sha256 => 32,
            KdfHash::Sha384 => 48,
            KdfHash::Sha512 => 64,
        }
    }
}

/// Dispatch a block of code over the concrete SHA-2 type selected by a
/// [`KdfHash`]. The identifier bound by `|H|` becomes a type alias in scope
/// inside `$body`, letting the body use `Hkdf::<H>` monomorphised to the
/// chosen digest.
macro_rules! with_hash {
    ($sel:expr, |$H:ident| $body:block) => {{
        match $sel {
            KdfHash::Sha224 => {
                type $H = sha2::Sha224;
                $body
            }
            KdfHash::Sha256 => {
                type $H = sha2::Sha256;
                $body
            }
            KdfHash::Sha384 => {
                type $H = sha2::Sha384;
                $body
            }
            KdfHash::Sha512 => {
                type $H = sha2::Sha512;
                $body
            }
        }
    }};
}

/// HKDF-Extract (RFC 5869 §2.2).
///
/// Derives a fixed-length pseudo-random key (`PRK`, `HashLen` bytes) from the
/// input keying material `ikm` and an optional `salt`. Per RFC 5869, an empty
/// `salt` is treated as a string of `HashLen` zero bytes (HMAC zero-pads keys
/// shorter than its block size, so the empty and all-zero salts are
/// equivalent).
pub fn hkdf_extract(hash: KdfHash, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    // Empty salt → None so the hkdf crate applies the RFC 5869 all-zero salt.
    let salt_opt = if salt.is_empty() { None } else { Some(salt) };
    with_hash!(hash, |H| {
        let (prk, _hk) = Hkdf::<H>::extract(salt_opt, ikm);
        prk.as_slice().to_vec()
    })
}

/// HKDF-Expand (RFC 5869 §2.3).
///
/// Expands a pseudo-random key `prk` into `out_len` bytes of output keying
/// material, bound to the optional context/application string `info`.
///
/// # Errors
/// Returns [`HsmError::DataLenRange`] if `out_len` exceeds `255 * HashLen`
/// (the RFC 5869 maximum), or if `prk` is shorter than `HashLen`.
pub fn hkdf_expand(hash: KdfHash, prk: &[u8], info: &[u8], out_len: usize) -> HsmResult<Vec<u8>> {
    let max_len = 255 * hash.output_len();
    if out_len > max_len {
        return Err(HsmError::DataLenRange);
    }
    with_hash!(hash, |H| {
        // from_prk rejects a PRK shorter than HashLen, matching RFC 5869's
        // requirement that PRK be at least HashLen octets.
        let hk = Hkdf::<H>::from_prk(prk).map_err(|_| HsmError::DataLenRange)?;
        let mut okm = vec![0u8; out_len];
        hk.expand(info, &mut okm)
            .map_err(|_| HsmError::DataLenRange)?;
        Ok(okm)
    })
}

/// Full HKDF Extract-then-Expand (RFC 5869 §2 / SP 800-56C Rev 2).
///
/// Extracts a PRK from `salt` and `ikm`, then expands it to `out_len` bytes
/// under `info`. The intermediate PRK is scrubbed from memory before return.
///
/// # Errors
/// Propagates the errors of [`hkdf_expand`].
pub fn hkdf_derive(
    hash: KdfHash,
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    out_len: usize,
) -> HsmResult<Vec<u8>> {
    let prk = Zeroizing::new(hkdf_extract(hash, salt, ikm));
    hkdf_expand(hash, &prk, info, out_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 5869 Appendix A.1 — Test Case 1 (HKDF-SHA-256, basic).
    #[test]
    fn rfc5869_test_case_1_sha256() {
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let expected_prk =
            hex::decode("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
                .unwrap();
        let expected_okm = hex::decode(
            "3cb25f25faacd57a90434f64d0362f2a\
             2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
             34007208d5b887185865",
        )
        .unwrap();

        let prk = hkdf_extract(KdfHash::Sha256, &salt, &ikm);
        assert_eq!(prk, expected_prk, "PRK mismatch");

        let okm = hkdf_expand(KdfHash::Sha256, &prk, &info, 42).unwrap();
        assert_eq!(okm, expected_okm, "OKM mismatch");

        // Full pipeline must agree with the two-stage form.
        let derived = hkdf_derive(KdfHash::Sha256, &salt, &ikm, &info, 42).unwrap();
        assert_eq!(derived, expected_okm, "hkdf_derive OKM mismatch");
    }

    // RFC 5869 Appendix A.3 — Test Case 3 (HKDF-SHA-256, zero-length salt/info).
    #[test]
    fn rfc5869_test_case_3_sha256_empty_salt_info() {
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = b""; // zero-length → RFC 5869 all-zero salt
        let info = b"";
        let expected_prk =
            hex::decode("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04")
                .unwrap();
        let expected_okm = hex::decode(
            "8da4e775a563c18f715f802a063c5a31\
             b8a11f5c5ee1879ec3454e5f3c738d2d\
             9d201395faa4b61a96c8",
        )
        .unwrap();

        let prk = hkdf_extract(KdfHash::Sha256, salt, &ikm);
        assert_eq!(prk, expected_prk, "PRK mismatch (empty salt)");

        let okm = hkdf_derive(KdfHash::Sha256, salt, &ikm, info, 42).unwrap();
        assert_eq!(okm, expected_okm, "OKM mismatch (empty salt/info)");
    }

    // SHA-512 round-trip sanity: output length, determinism, and info binding.
    #[test]
    fn sha512_round_trip_sanity() {
        let ikm = b"input keying material for sha-512 hkdf";
        let salt = b"some salt value";
        let info = b"application context";

        let okm1 = hkdf_derive(KdfHash::Sha512, salt, ikm, info, 100).unwrap();
        let okm2 = hkdf_derive(KdfHash::Sha512, salt, ikm, info, 100).unwrap();
        assert_eq!(okm1.len(), 100);
        assert_eq!(okm1, okm2, "HKDF must be deterministic");
        assert!(!okm1.iter().all(|&b| b == 0), "OKM must not be all zeros");

        // Different info → different output (domain separation).
        let okm3 = hkdf_derive(KdfHash::Sha512, salt, ikm, b"other context", 100).unwrap();
        assert_ne!(okm1, okm3, "different info must yield different OKM");
    }

    #[test]
    fn expand_rejects_oversized_output() {
        // 255 * 32 = 8160 is the maximum for SHA-256; one more must fail.
        let prk = [0x42u8; 32];
        assert!(hkdf_expand(KdfHash::Sha256, &prk, b"", 255 * 32).is_ok());
        // HsmError does not implement PartialEq, so match on the variant.
        assert!(matches!(
            hkdf_expand(KdfHash::Sha256, &prk, b"", 255 * 32 + 1),
            Err(HsmError::DataLenRange)
        ));
    }

    #[test]
    fn expand_rejects_short_prk() {
        // A PRK shorter than HashLen is invalid per RFC 5869.
        let short_prk = [0u8; 16];
        assert!(matches!(
            hkdf_expand(KdfHash::Sha256, &short_prk, b"", 32),
            Err(HsmError::DataLenRange)
        ));
    }
}
