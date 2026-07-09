// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! HMAC message authentication codes (SHA-2 family).
//!
//! Pure, backend-independent HMAC primitives built on the `hmac` and `sha2`
//! crates. The public [`hmac_sign`] and [`hmac_verify`] functions enforce a
//! key-size policy derived from NIST SP 800-107 (a 112-bit / 14-byte minimum
//! effective key strength) before performing the computation. The ABI layer is
//! expected to map `CKM_SHA*_HMAC` mechanism types onto [`HmacHash`].

use crate::error::{HsmError, HsmResult};
use hmac::{Hmac, Mac};
use sha2::{Sha224, Sha256, Sha384, Sha512};

/// Minimum permitted HMAC key length in bytes (112-bit floor, SP 800-107).
const MIN_KEY_LEN: usize = 14;
/// Maximum permitted HMAC key length in bytes.
const MAX_KEY_LEN: usize = 512;

/// SHA-2 hash function selecting the HMAC variant.
///
/// The ABI layer maps PKCS#11 mechanism types (`CKM_SHA224_HMAC`,
/// `CKM_SHA256_HMAC`, `CKM_SHA384_HMAC`, `CKM_SHA512_HMAC`) onto these values so
/// that this module carries no dependency on the mechanism constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HmacHash {
    /// HMAC-SHA-224 (28-byte tag).
    Sha224,
    /// HMAC-SHA-256 (32-byte tag).
    Sha256,
    /// HMAC-SHA-384 (48-byte tag).
    Sha384,
    /// HMAC-SHA-512 (64-byte tag).
    Sha512,
}

/// Returns the output (tag) length in bytes for the given HMAC variant.
pub fn hmac_output_len(hash: HmacHash) -> usize {
    match hash {
        HmacHash::Sha224 => 28,
        HmacHash::Sha256 => 32,
        HmacHash::Sha384 => 48,
        HmacHash::Sha512 => 64,
    }
}

/// Validates an HMAC key against the SP 800-107 length policy.
fn check_key_policy(key: &[u8]) -> HsmResult<()> {
    if key.len() < MIN_KEY_LEN || key.len() > MAX_KEY_LEN {
        return Err(HsmError::KeySizeRange);
    }
    Ok(())
}

/// Computes an HMAC tag without enforcing the key-size policy.
///
/// This is the pure primitive shared by [`hmac_sign`] and [`hmac_verify`]. It is
/// kept private so that all externally reachable paths go through the policy
/// check; test vectors with short published keys (e.g. RFC 4231) exercise it
/// directly.
fn hmac_raw(hash: HmacHash, key: &[u8], data: &[u8]) -> Vec<u8> {
    // `new_from_slice` only fails for algorithms with a fixed key length; HMAC
    // accepts keys of any length, so this never errors here.
    match hash {
        HmacHash::Sha224 => Hmac::<Sha224>::new_from_slice(key)
            .expect("HMAC accepts any key length")
            .chain_update(data)
            .finalize()
            .into_bytes()
            .to_vec(),
        HmacHash::Sha256 => Hmac::<Sha256>::new_from_slice(key)
            .expect("HMAC accepts any key length")
            .chain_update(data)
            .finalize()
            .into_bytes()
            .to_vec(),
        HmacHash::Sha384 => Hmac::<Sha384>::new_from_slice(key)
            .expect("HMAC accepts any key length")
            .chain_update(data)
            .finalize()
            .into_bytes()
            .to_vec(),
        HmacHash::Sha512 => Hmac::<Sha512>::new_from_slice(key)
            .expect("HMAC accepts any key length")
            .chain_update(data)
            .finalize()
            .into_bytes()
            .to_vec(),
    }
}

/// Computes the HMAC tag over `data` using `key` and the selected hash.
///
/// Enforces the key-size policy: keys shorter than 14 bytes (112-bit floor,
/// SP 800-107) or longer than 512 bytes are rejected with
/// [`HsmError::KeySizeRange`].
pub fn hmac_sign(hash: HmacHash, key: &[u8], data: &[u8]) -> HsmResult<Vec<u8>> {
    check_key_policy(key)?;
    Ok(hmac_raw(hash, key, data))
}

/// Verifies a candidate HMAC `tag` over `data` in constant time.
///
/// Returns `Ok(true)` when the tag matches, `Ok(false)` otherwise. The
/// comparison is performed via the `hmac` crate's constant-time
/// `verify_slice`, so a mismatch does not leak timing information about where
/// the tag differs. Enforces the same key-size policy as [`hmac_sign`].
pub fn hmac_verify(hash: HmacHash, key: &[u8], data: &[u8], tag: &[u8]) -> HsmResult<bool> {
    check_key_policy(key)?;
    let matched = match hash {
        HmacHash::Sha224 => Hmac::<Sha224>::new_from_slice(key)
            .expect("HMAC accepts any key length")
            .chain_update(data)
            .verify_slice(tag)
            .is_ok(),
        HmacHash::Sha256 => Hmac::<Sha256>::new_from_slice(key)
            .expect("HMAC accepts any key length")
            .chain_update(data)
            .verify_slice(tag)
            .is_ok(),
        HmacHash::Sha384 => Hmac::<Sha384>::new_from_slice(key)
            .expect("HMAC accepts any key length")
            .chain_update(data)
            .verify_slice(tag)
            .is_ok(),
        HmacHash::Sha512 => Hmac::<Sha512>::new_from_slice(key)
            .expect("HMAC accepts any key length")
            .chain_update(data)
            .verify_slice(tag)
            .is_ok(),
    };
    Ok(matched)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4231 Test Case 2: key = "Jefe", data = "what do ya want for nothing?".
    // The 4-byte key is below the SP 800-107 policy floor, so these vectors are
    // validated against the pure `hmac_raw` primitive rather than `hmac_sign`.
    const TC2_KEY: &[u8] = b"Jefe";
    const TC2_DATA: &[u8] = b"what do ya want for nothing?";

    #[test]
    fn rfc4231_test_case_2_sha224() {
        let expected =
            hex::decode("a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44").unwrap();
        assert_eq!(hmac_raw(HmacHash::Sha224, TC2_KEY, TC2_DATA), expected);
    }

    #[test]
    fn rfc4231_test_case_2_sha256() {
        let expected =
            hex::decode("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
                .unwrap();
        assert_eq!(hmac_raw(HmacHash::Sha256, TC2_KEY, TC2_DATA), expected);
    }

    #[test]
    fn rfc4231_test_case_2_sha384() {
        let expected = hex::decode(
            "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e\
             8e2240ca5e69e2c78b3239ecfab21649",
        )
        .unwrap();
        assert_eq!(hmac_raw(HmacHash::Sha384, TC2_KEY, TC2_DATA), expected);
    }

    #[test]
    fn rfc4231_test_case_2_sha512() {
        let expected = hex::decode(
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554\
             9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
        )
        .unwrap();
        assert_eq!(hmac_raw(HmacHash::Sha512, TC2_KEY, TC2_DATA), expected);
    }

    // RFC 4231 Test Case 1 uses a 20-byte key, which satisfies the policy and so
    // can be driven through the public `hmac_sign` path end-to-end.
    #[test]
    fn rfc4231_test_case_1_sha256_via_public_api() {
        let key = [0x0b_u8; 20];
        let data = b"Hi There";
        let expected =
            hex::decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
                .unwrap();
        assert_eq!(hmac_sign(HmacHash::Sha256, &key, data).unwrap(), expected);
    }

    #[test]
    fn output_len_matches_tag_len() {
        let key = [0x42_u8; 32];
        for hash in [
            HmacHash::Sha224,
            HmacHash::Sha256,
            HmacHash::Sha384,
            HmacHash::Sha512,
        ] {
            let tag = hmac_sign(hash, &key, b"abc").unwrap();
            assert_eq!(tag.len(), hmac_output_len(hash));
        }
    }

    #[test]
    fn verify_round_trip() {
        let key = [0x24_u8; 32];
        let data = b"authenticate me";
        for hash in [
            HmacHash::Sha224,
            HmacHash::Sha256,
            HmacHash::Sha384,
            HmacHash::Sha512,
        ] {
            let tag = hmac_sign(hash, &key, data).unwrap();

            // Correct tag verifies.
            assert!(hmac_verify(hash, &key, data, &tag).unwrap());

            // Tampered tag fails.
            let mut bad_tag = tag.clone();
            bad_tag[0] ^= 0xff;
            assert!(!hmac_verify(hash, &key, data, &bad_tag).unwrap());

            // Tampered data fails.
            assert!(!hmac_verify(hash, &key, b"authenticate ME", &tag).unwrap());

            // Truncated tag fails.
            assert!(!hmac_verify(hash, &key, data, &tag[..tag.len() - 1]).unwrap());
        }
    }

    #[test]
    fn key_policy_lower_bound() {
        // 13 bytes: below the 14-byte floor -> rejected.
        let short = [0x01_u8; 13];
        assert!(matches!(
            hmac_sign(HmacHash::Sha256, &short, b"x"),
            Err(HsmError::KeySizeRange)
        ));
        assert!(matches!(
            hmac_verify(HmacHash::Sha256, &short, b"x", &[0u8; 32]),
            Err(HsmError::KeySizeRange)
        ));

        // 14 bytes: exactly at the floor -> accepted.
        let ok = [0x01_u8; 14];
        assert!(hmac_sign(HmacHash::Sha256, &ok, b"x").is_ok());
        let tag = hmac_sign(HmacHash::Sha256, &ok, b"x").unwrap();
        assert!(hmac_verify(HmacHash::Sha256, &ok, b"x", &tag).unwrap());
    }

    #[test]
    fn key_policy_upper_bound() {
        // 512 bytes: exactly at the ceiling -> accepted.
        let max = vec![0x02_u8; 512];
        assert!(hmac_sign(HmacHash::Sha256, &max, b"x").is_ok());

        // 513 bytes: above the ceiling -> rejected.
        let too_long = vec![0x02_u8; 513];
        assert!(matches!(
            hmac_sign(HmacHash::Sha256, &too_long, b"x"),
            Err(HsmError::KeySizeRange)
        ));
        assert!(matches!(
            hmac_verify(HmacHash::Sha256, &too_long, b"x", &[0u8; 32]),
            Err(HsmError::KeySizeRange)
        ));
    }
}
