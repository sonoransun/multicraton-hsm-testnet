// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! NIST SP 800-108 Counter-Mode Key-Based KDF (KBKDF) over HMAC.
//!
//! Implements the counter-mode KDF of NIST SP 800-108r1 §4.1 using the
//! fixed-input construction. There is no stable RustCrypto `kbkdf` crate, so
//! the PRF chaining is hand-rolled over the [`hmac`] crate.
//!
//! The single entry point [`sp800_108_counter`] is a pure crypto primitive
//! taking an explicit [`PrfHash`] selector, so the PKCS#11 ABI layer can map
//! the relevant `CKM_SP800_108_COUNTER_KDF` mechanism onto it without this
//! module depending on any PKCS#11 constants.
//!
//! ## Construction (SP 800-108r1 §4.1, counter mode, before-fixed-data)
//! For `i = 1..=n` with `n = ceil(out_len / HashLen)`:
//! ```text
//! K(i) = PRF(KI, [i]_32 || Label || 0x00 || Context || [L]_32)
//! ```
//! where `[i]_32` is the 4-byte big-endian counter, `0x00` is the separator
//! byte, and `[L]_32` is the total requested output length **in bits** as a
//! 4-byte big-endian integer. The blocks `K(1) .. K(n)` are concatenated and
//! truncated to `out_len` bytes. `PRF` is HMAC with the selected SHA-2 hash.

use hmac::{Hmac, Mac};

use crate::error::{HsmError, HsmResult};

/// Upper bound on requested output length (1 MiB) to bound work and prevent
/// resource-exhaustion via absurd derivation requests.
const MAX_OUT_LEN: usize = 1 << 20;

/// PRF hash selector for the SP 800-108 counter-mode KDF.
///
/// Each variant selects the HMAC digest used as the underlying PRF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrfHash {
    /// HMAC-SHA-224 (28-byte PRF output).
    Sha224,
    /// HMAC-SHA-256 (32-byte PRF output).
    Sha256,
    /// HMAC-SHA-384 (48-byte PRF output).
    Sha384,
    /// HMAC-SHA-512 (64-byte PRF output).
    Sha512,
}

impl PrfHash {
    /// Output length of the underlying HMAC/hash in bytes.
    pub fn output_len(self) -> usize {
        match self {
            PrfHash::Sha224 => 28,
            PrfHash::Sha256 => 32,
            PrfHash::Sha384 => 48,
            PrfHash::Sha512 => 64,
        }
    }
}

/// Dispatch a block over the concrete SHA-2 type selected by a [`PrfHash`].
/// The identifier bound by `|H|` becomes a type alias in scope inside `$body`,
/// letting the body use `Hmac::<H>` monomorphised to the chosen digest.
macro_rules! with_prf {
    ($sel:expr, |$H:ident| $body:block) => {{
        match $sel {
            PrfHash::Sha224 => {
                type $H = sha2::Sha224;
                $body
            }
            PrfHash::Sha256 => {
                type $H = sha2::Sha256;
                $body
            }
            PrfHash::Sha384 => {
                type $H = sha2::Sha384;
                $body
            }
            PrfHash::Sha512 => {
                type $H = sha2::Sha512;
                $body
            }
        }
    }};
}

/// Derive `out_len` bytes of key material with the SP 800-108 counter-mode KDF.
///
/// `key` is the key-derivation key (`KI`); `label` and `context` are the
/// fixed-input fields, separated by a `0x00` byte per the standard
/// fixed-input encoding. `L` (the total requested length in bits) is appended.
///
/// # Errors
/// Returns [`HsmError::DataLenRange`] if `out_len` is `0`, exceeds
/// [`MAX_OUT_LEN`], or would require a counter or `L` value that does not fit
/// in 32 bits.
pub fn sp800_108_counter(
    prf: PrfHash,
    key: &[u8],
    label: &[u8],
    context: &[u8],
    out_len: usize,
) -> HsmResult<Vec<u8>> {
    if out_len == 0 || out_len > MAX_OUT_LEN {
        return Err(HsmError::DataLenRange);
    }

    let hash_len = prf.output_len();
    let n = out_len.div_ceil(hash_len);
    // The counter i is encoded in 32 bits; guard against overflow. With the
    // MAX_OUT_LEN cap this can never trip, but keep the check explicit.
    if n > u32::MAX as usize {
        return Err(HsmError::DataLenRange);
    }

    // L is the total requested output length in bits, encoded as 4 big-endian
    // bytes. Reject requests whose bit-length would not fit in 32 bits.
    let l_bits = (out_len as u64)
        .checked_mul(8)
        .filter(|&b| b <= u32::MAX as u64)
        .ok_or(HsmError::DataLenRange)?;
    let l_encoded = (l_bits as u32).to_be_bytes();

    let mut out: Vec<u8> = Vec::with_capacity(n * hash_len);
    with_prf!(prf, |H| {
        for i in 1..=(n as u32) {
            // HMAC over any key length always succeeds (keys are hashed/padded).
            let mut mac = Hmac::<H>::new_from_slice(key)
                .map_err(|_| HsmError::CryptographicError("HMAC key init failed".into()))?;
            mac.update(&i.to_be_bytes()); // [i]_32
            mac.update(label); // Label
            mac.update(&[0x00u8]); // 0x00 separator
            mac.update(context); // Context
            mac.update(&l_encoded); // [L]_32
            let block = mac.finalize().into_bytes();
            out.extend_from_slice(block.as_slice());
        }
    });

    out.truncate(out_len);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Independent-implementation known-answer test: recompute the counter-mode
    // blocks directly with raw HMAC-SHA-256 following SP 800-108r1 §4.1 and
    // compare against sp800_108_counter. This validates the exact byte layout
    // (counter width, separator, L-in-bits encoding, concatenation, and final
    // truncation) against a separately written reference.
    #[test]
    fn kat_independent_hmac_sha256() {
        let key = b"key-derivation-key-material-0123";
        let label = b"craton-kdf-label";
        let context = b"session-context-42";
        let out_len = 40usize; // > 32 → forces two counter blocks (n = 2)

        let l_encoded = ((out_len * 8) as u32).to_be_bytes();
        let mut expected = Vec::new();
        for i in 1u32..=2 {
            let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key).unwrap();
            mac.update(&i.to_be_bytes());
            mac.update(label);
            mac.update(&[0x00u8]);
            mac.update(context);
            mac.update(&l_encoded);
            expected.extend_from_slice(mac.finalize().into_bytes().as_slice());
        }
        expected.truncate(out_len);

        let got = sp800_108_counter(PrfHash::Sha256, key, label, context, out_len).unwrap();
        assert_eq!(got, expected, "counter-mode output must match reference");
        assert_eq!(got.len(), out_len);
    }

    #[test]
    fn deterministic() {
        let key = b"kdk";
        let a = sp800_108_counter(PrfHash::Sha256, key, b"label", b"ctx", 32).unwrap();
        let b = sp800_108_counter(PrfHash::Sha256, key, b"label", b"ctx", 32).unwrap();
        assert_eq!(a, b, "same inputs must produce same output");
    }

    #[test]
    fn different_label_differs() {
        let key = b"kdk";
        let a = sp800_108_counter(PrfHash::Sha256, key, b"label-a", b"ctx", 32).unwrap();
        let b = sp800_108_counter(PrfHash::Sha256, key, b"label-b", b"ctx", 32).unwrap();
        assert_ne!(a, b, "different label must change output");
    }

    #[test]
    fn different_context_differs() {
        let key = b"kdk";
        let a = sp800_108_counter(PrfHash::Sha256, key, b"label", b"ctx-a", 32).unwrap();
        let b = sp800_108_counter(PrfHash::Sha256, key, b"label", b"ctx-b", 32).unwrap();
        assert_ne!(a, b, "different context must change output");
    }

    #[test]
    fn exact_output_length_all_hashes() {
        let key = b"kdk";
        for prf in [
            PrfHash::Sha224,
            PrfHash::Sha256,
            PrfHash::Sha384,
            PrfHash::Sha512,
        ] {
            for len in [1usize, 16, 31, 32, 33, 100] {
                let out = sp800_108_counter(prf, key, b"l", b"c", len).unwrap();
                assert_eq!(out.len(), len, "wrong length for {:?} len={}", prf, len);
            }
        }
    }

    #[test]
    fn rejects_zero_and_oversized() {
        let key = b"kdk";
        // HsmError does not implement PartialEq, so match on the variant.
        assert!(matches!(
            sp800_108_counter(PrfHash::Sha256, key, b"l", b"c", 0),
            Err(HsmError::DataLenRange)
        ));
        assert!(matches!(
            sp800_108_counter(PrfHash::Sha256, key, b"l", b"c", MAX_OUT_LEN + 1),
            Err(HsmError::DataLenRange)
        ));
    }
}
