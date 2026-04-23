// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Key-wrapping service, including the vendor-extension PQ-safe
//! `CKM_HYBRID_KEM_WRAP` construction.
//!
//! Wire format for `CKM_HYBRID_KEM_WRAP`:
//!
//! ```text
//! [ 4-byte BE length of kem_ct ][ kem_ct ][ aes_kw_ct ]
//! ```
//!
//! Step 1: `(kem_ct, kem_ss) = hybrid_kem_encapsulate(recipient_pk)`.
//! Step 2: `kek = HKDF-SHA-256(kem_ss, info="CRATON-HYBRID-KEM-WRAP-V1", 32 B)`.
//! Step 3: `aes_kw_ct = AES-KW(kek, target_key_bytes)`.
//!
//! Decapsulation reverses exactly: length-prefixed KEM ciphertext is split
//! out, decapsulated to `kem_ss`, the same HKDF derivation yields `kek`,
//! and `aes_kw_ct` is unwrapped with AES-KW.
//!
//! This is the minimum-viable construction — it does **not** authenticate
//! the recipient's public key, so callers must transport the public key
//! over an authenticated channel (the same assumption applies to the
//! underlying hybrid KEM).

#![cfg(feature = "hybrid-kem")]

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::core::HsmCore;
use crate::crypto::hybrid;
use crate::crypto::wrap as aes_kw;
use crate::error::{HsmError, HsmResult};
use crate::pkcs11_abi::types::{CK_MECHANISM_TYPE, CK_OBJECT_HANDLE};

const WRAP_LABEL: &[u8] = b"CRATON-HYBRID-KEM-WRAP-V1";

fn derive_kek(kem_ss: &[u8]) -> HsmResult<[u8; 32]> {
    let mut kek = [0u8; 32];
    Hkdf::<Sha256>::new(None, kem_ss)
        .expand(WRAP_LABEL, &mut kek)
        .map_err(|_| HsmError::GeneralError)?;
    Ok(kek)
}

/// Wrap a symmetric key under a recipient's hybrid-KEM public-key handle.
/// Returns the opaque ciphertext.
pub fn hybrid_kem_wrap(
    core: &HsmCore,
    recipient_pub_handle: CK_OBJECT_HANDLE,
    kem_mechanism: CK_MECHANISM_TYPE,
    target_key_handle: CK_OBJECT_HANDLE,
) -> HsmResult<Vec<u8>> {
    // Fetch recipient public key bytes.
    let pub_bytes = {
        let arc = core.object_store().get_object(recipient_pub_handle)?;
        let obj = arc.read();
        obj.public_key_data
            .clone()
            .ok_or(HsmError::KeyHandleInvalid)?
    };
    // Fetch target symmetric key bytes.
    let target_bytes = {
        let arc = core.object_store().get_object(target_key_handle)?;
        let obj = arc.read();
        obj.key_material
            .as_ref()
            .map(|m| m.as_bytes().to_vec())
            .ok_or(HsmError::KeyHandleInvalid)?
    };

    let (kem_ct, kem_ss) =
        hybrid::hybrid_kem_encapsulate_by_mechanism(kem_mechanism, &pub_bytes)?;
    let mut kek = derive_kek(&kem_ss)?;

    // Honour FIPS mode if the runtime policy requires it.
    let fips_mode = core.algorithm_config().fips_approved_only;
    let aes_kw_ct = aes_kw::aes_key_wrap(&kek, &target_bytes, fips_mode)
        .map_err(|_| HsmError::GeneralError)?;
    kek.zeroize();

    if kem_ct.len() > u32::MAX as usize {
        return Err(HsmError::DataLenRange);
    }
    let mut out = Vec::with_capacity(4 + kem_ct.len() + aes_kw_ct.len());
    out.extend_from_slice(&(kem_ct.len() as u32).to_be_bytes());
    out.extend_from_slice(&kem_ct);
    out.extend_from_slice(&aes_kw_ct);
    Ok(out)
}

/// Unwrap a `CKM_HYBRID_KEM_WRAP` blob with the recipient's private-key handle,
/// returning the underlying key bytes (caller re-imports as a `StoredObject`).
pub fn hybrid_kem_unwrap(
    core: &HsmCore,
    recipient_priv_handle: CK_OBJECT_HANDLE,
    kem_mechanism: CK_MECHANISM_TYPE,
    wrapped: &[u8],
) -> HsmResult<Vec<u8>> {
    if wrapped.len() < 4 {
        return Err(HsmError::EncryptedDataInvalid);
    }
    let kem_ct_len = u32::from_be_bytes([wrapped[0], wrapped[1], wrapped[2], wrapped[3]]) as usize;
    let total_kem = match 4usize.checked_add(kem_ct_len) {
        Some(v) => v,
        None => return Err(HsmError::EncryptedDataInvalid),
    };
    if wrapped.len() < total_kem {
        return Err(HsmError::EncryptedDataInvalid);
    }
    let kem_ct = &wrapped[4..total_kem];
    let aes_kw_ct = &wrapped[total_kem..];

    let priv_bytes = {
        let arc = core.object_store().get_object(recipient_priv_handle)?;
        let obj = arc.read();
        obj.key_material
            .as_ref()
            .map(|m| m.as_bytes().to_vec())
            .ok_or(HsmError::KeyHandleInvalid)?
    };

    let kem_ss = hybrid::hybrid_kem_decapsulate_by_mechanism(kem_mechanism, &priv_bytes, kem_ct)?;
    let mut kek = derive_kek(&kem_ss)?;
    let fips_mode = core.algorithm_config().fips_approved_only;
    let result =
        aes_kw::aes_key_unwrap(&kek, aes_kw_ct, fips_mode).map_err(|_| HsmError::EncryptedDataInvalid);
    kek.zeroize();
    result
}
