// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
use crate::error::{HsmError, HsmResult};
use aes_kw::Kek;
use zeroize::Zeroize;

/// AES Key Wrap (RFC 3394) — wraps a key using an AES wrapping key.
///
/// If `fips_mode` is true, AES-128 (16-byte) wrapping keys are rejected
/// per FIPS 140-3 requirements (minimum 192-bit for key wrapping).
pub fn aes_key_wrap(
    wrapping_key: &[u8],
    key_to_wrap: &[u8],
    fips_mode: bool,
) -> HsmResult<Vec<u8>> {
    if key_to_wrap.len() % 8 != 0 || key_to_wrap.len() < 16 {
        return Err(HsmError::DataLenRange);
    }

    if fips_mode && wrapping_key.len() == 16 {
        tracing::warn!("FIPS mode: rejecting AES-128 wrapping key — minimum 192-bit required");
        return Err(HsmError::KeySizeRange);
    }

    match wrapping_key.len() {
        16 => {
            let kek =
                Kek::<aes::Aes128>::try_from(wrapping_key).map_err(|_| HsmError::KeySizeRange)?;
            let mut buf = vec![0u8; key_to_wrap.len() + 8];
            kek.wrap(key_to_wrap, &mut buf)
                .map_err(|_| HsmError::GeneralError)?;
            Ok(buf)
        }
        24 => {
            let kek =
                Kek::<aes::Aes192>::try_from(wrapping_key).map_err(|_| HsmError::KeySizeRange)?;
            let mut buf = vec![0u8; key_to_wrap.len() + 8];
            kek.wrap(key_to_wrap, &mut buf)
                .map_err(|_| HsmError::GeneralError)?;
            Ok(buf)
        }
        32 => {
            let kek =
                Kek::<aes::Aes256>::try_from(wrapping_key).map_err(|_| HsmError::KeySizeRange)?;
            let mut buf = vec![0u8; key_to_wrap.len() + 8];
            kek.wrap(key_to_wrap, &mut buf)
                .map_err(|_| HsmError::GeneralError)?;
            Ok(buf)
        }
        _ => Err(HsmError::KeySizeRange),
    }
}

/// AES Key Unwrap (RFC 3394) — unwraps a wrapped key.
///
/// If `fips_mode` is true, AES-128 (16-byte) wrapping keys are rejected
/// per FIPS 140-3 requirements (minimum 192-bit for key wrapping).
pub fn aes_key_unwrap(
    wrapping_key: &[u8],
    wrapped_key: &[u8],
    fips_mode: bool,
) -> HsmResult<Vec<u8>> {
    if wrapped_key.len() % 8 != 0 || wrapped_key.len() < 24 {
        return Err(HsmError::DataLenRange);
    }

    if fips_mode && wrapping_key.len() == 16 {
        tracing::warn!("FIPS mode: rejecting AES-128 unwrapping key — minimum 192-bit required");
        return Err(HsmError::KeySizeRange);
    }

    match wrapping_key.len() {
        16 => {
            let kek =
                Kek::<aes::Aes128>::try_from(wrapping_key).map_err(|_| HsmError::KeySizeRange)?;
            let mut buf = vec![0u8; wrapped_key.len() - 8];
            if let Err(_) = kek.unwrap(wrapped_key, &mut buf) {
                buf.zeroize(); // scrub partial key material on failure
                return Err(HsmError::EncryptedDataInvalid);
            }
            Ok(buf)
        }
        24 => {
            let kek =
                Kek::<aes::Aes192>::try_from(wrapping_key).map_err(|_| HsmError::KeySizeRange)?;
            let mut buf = vec![0u8; wrapped_key.len() - 8];
            if let Err(_) = kek.unwrap(wrapped_key, &mut buf) {
                buf.zeroize();
                return Err(HsmError::EncryptedDataInvalid);
            }
            Ok(buf)
        }
        32 => {
            let kek =
                Kek::<aes::Aes256>::try_from(wrapping_key).map_err(|_| HsmError::KeySizeRange)?;
            let mut buf = vec![0u8; wrapped_key.len() - 8];
            if let Err(_) = kek.unwrap(wrapped_key, &mut buf) {
                buf.zeroize();
                return Err(HsmError::EncryptedDataInvalid);
            }
            Ok(buf)
        }
        _ => Err(HsmError::KeySizeRange),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wrap_unwrap_roundtrip_128() {
        // 16-byte wrapping key, 16-byte data
        let wrapping_key = [0x42u8; 16];
        let data = [0xABu8; 16];
        let wrapped = aes_key_wrap(&wrapping_key, &data, false).unwrap();
        assert_eq!(wrapped.len(), data.len() + 8);
        let unwrapped = aes_key_unwrap(&wrapping_key, &wrapped, false).unwrap();
        assert_eq!(unwrapped, data);
    }

    #[test]
    fn test_wrap_unwrap_roundtrip_256() {
        // 32-byte wrapping key, 32-byte data
        let wrapping_key = [0x55u8; 32];
        let data = [0xCDu8; 32];
        let wrapped = aes_key_wrap(&wrapping_key, &data, false).unwrap();
        assert_eq!(wrapped.len(), data.len() + 8);
        let unwrapped = aes_key_unwrap(&wrapping_key, &wrapped, false).unwrap();
        assert_eq!(unwrapped, data);
    }

    #[test]
    fn test_rfc3394_vector_4_1() {
        // RFC 3394 Section 4.1 — AES-128 KEK
        // KEK: 000102030405060708090A0B0C0D0E0F
        // Data: 00112233445566778899AABBCCDDEEFF
        // Expected: 1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5
        let kek = hex::decode("000102030405060708090A0B0C0D0E0F").unwrap();
        let data = hex::decode("00112233445566778899AABBCCDDEEFF").unwrap();
        let expected = hex::decode("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5").unwrap();
        let wrapped = aes_key_wrap(&kek, &data, false).unwrap();
        assert_eq!(wrapped, expected);
        let unwrapped = aes_key_unwrap(&kek, &wrapped, false).unwrap();
        assert_eq!(unwrapped, data);
    }

    #[test]
    fn test_unwrap_tampered_data() {
        let wrapping_key = [0x42u8; 32];
        let data = [0xABu8; 16];
        let mut wrapped = aes_key_wrap(&wrapping_key, &data, false).unwrap();
        // Flip a bit in the wrapped data
        wrapped[4] ^= 0x01;
        let result = aes_key_unwrap(&wrapping_key, &wrapped, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrap_unaligned_rejected() {
        // 15-byte data is not a multiple of 8 -> error
        let wrapping_key = [0x42u8; 16];
        let data = [0xABu8; 15];
        let result = aes_key_wrap(&wrapping_key, &data, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrap_too_small_rejected() {
        // 8-byte data -> error (minimum is 16)
        let wrapping_key = [0x42u8; 16];
        let data = [0xABu8; 8];
        let result = aes_key_wrap(&wrapping_key, &data, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_unwrap_too_small_rejected() {
        // 16-byte wrapped data -> error (minimum is 24)
        let wrapping_key = [0x42u8; 16];
        let data = [0xABu8; 16];
        let result = aes_key_unwrap(&wrapping_key, &data, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_wrapping_key_size() {
        // 20-byte key is not a valid AES key size -> error
        let wrapping_key = [0x42u8; 20];
        let data = [0xABu8; 16];
        let result = aes_key_wrap(&wrapping_key, &data, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_fips_mode_rejects_aes128() {
        // 16-byte wrapping key + fips=true -> error
        let wrapping_key = [0x42u8; 16];
        let data = [0xABu8; 16];
        let result = aes_key_wrap(&wrapping_key, &data, true);
        assert!(result.is_err());

        // But 32-byte key should work in FIPS mode
        let wrapping_key_256 = [0x42u8; 32];
        let wrapped = aes_key_wrap(&wrapping_key_256, &data, true).unwrap();
        let unwrapped = aes_key_unwrap(&wrapping_key_256, &wrapped, true).unwrap();
        assert_eq!(unwrapped, data);
    }
}
