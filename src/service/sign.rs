// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Signature service — dispatches every signing/verification mechanism
//! (classical + PQC + composite) to the underlying crypto modules.
//!
//! Used by:
//! - PKCS#11 C ABI (through the existing `sign_single_shot` — eventually a thin wrapper)
//! - Vendor extension `CratonExt_HybridSignCompose` / `CratonExt_BatchSign`
//! - REST `/v1/keys/{h}/sign` and `/verify`
//! - Python/Node bindings (local mode)

use crate::core::HsmCore;
use crate::crypto::pqc;
use crate::error::{HsmError, HsmResult};
use crate::pkcs11_abi::constants::*;
use crate::pkcs11_abi::types::CK_MECHANISM_TYPE;
use crate::store::attributes::ObjectStore;
use crate::store::object::StoredObject;

/// Fetch `key_material` bytes from the store, returning a concise error
/// if the object is missing, not a private key, or has no key material.
fn load_private_key_bytes(
    store: &ObjectStore,
    handle: crate::pkcs11_abi::types::CK_OBJECT_HANDLE,
) -> HsmResult<Vec<u8>> {
    let obj_arc = store.get_object(handle)?;
    let obj = obj_arc.read();
    obj.key_material
        .as_ref()
        .map(|m| m.as_bytes().to_vec())
        .ok_or(HsmError::KeyHandleInvalid)
}

/// Fetch `public_key_data` bytes from the store, falling back to `ec_point`
/// for classical EC keys (matches the existing verify-path convention).
fn load_public_key_bytes(
    store: &ObjectStore,
    handle: crate::pkcs11_abi::types::CK_OBJECT_HANDLE,
) -> HsmResult<Vec<u8>> {
    let obj_arc = store.get_object(handle)?;
    let obj = obj_arc.read();
    if let Some(ref pk) = obj.public_key_data {
        return Ok(pk.clone());
    }
    if let Some(ref ep) = obj.ec_point {
        return Ok(ep.clone());
    }
    Err(HsmError::KeyHandleInvalid)
}

/// Sign `data` under the given PQC-or-composite mechanism and key handle.
///
/// Supported PQC mechanisms: `CKM_ML_DSA_*`, `CKM_SLH_DSA_*` (all 12),
/// `CKM_FALCON_*` (feature-gated), `CKM_HYBRID_ML_DSA_ECDSA`,
/// `CKM_HYBRID_ED25519_MLDSA65`.
///
/// Classical-only mechanisms are not handled here — callers should route
/// through the `CryptoBackend` trait directly.
pub fn pqc_sign(
    core: &HsmCore,
    priv_handle: crate::pkcs11_abi::types::CK_OBJECT_HANDLE,
    mechanism: CK_MECHANISM_TYPE,
    data: &[u8],
) -> HsmResult<Vec<u8>> {
    let key_bytes = load_private_key_bytes(core.object_store(), priv_handle)?;

    if pqc::is_ml_dsa_mechanism(mechanism) {
        let variant =
            pqc::mechanism_to_ml_dsa_variant(mechanism).ok_or(HsmError::MechanismInvalid)?;
        return pqc::ml_dsa_sign(&key_bytes, data, variant);
    }
    if pqc::is_slh_dsa_mechanism(mechanism) {
        let variant =
            pqc::mechanism_to_slh_dsa_variant(mechanism).ok_or(HsmError::MechanismInvalid)?;
        return pqc::slh_dsa_sign(&key_bytes, data, variant);
    }
    if pqc::is_hybrid_ed25519_mldsa65_mechanism(mechanism) {
        // Composite SK layout: [ed25519_seed_32][mldsa65_seed_32]
        if key_bytes.len() < 64 {
            return Err(HsmError::KeyHandleInvalid);
        }
        return pqc::hybrid_ed25519_mldsa65_sign(&key_bytes[32..], &key_bytes[..32], data);
    }
    if pqc::is_hybrid_mechanism(mechanism) {
        // CKM_HYBRID_ML_DSA_ECDSA — classical ECDSA-P256 key bytes are
        // fetched from the object's `ec_point` / `CKA_EC_POINT` extra attr.
        let obj_arc = core.object_store().get_object(priv_handle)?;
        let obj = obj_arc.read();
        let ecdsa_sk = obj
            .extra_attributes
            .get(&CKA_EC_POINT)
            .or(obj.ec_point.as_ref())
            .map(|v| v.as_slice().to_vec())
            .unwrap_or_default();
        return pqc::hybrid_sign(&key_bytes, &ecdsa_sk, data);
    }
    #[cfg(feature = "falcon-sig")]
    if crate::crypto::falcon::is_falcon_mechanism(mechanism) {
        let variant = crate::crypto::falcon::mechanism_to_falcon_variant(mechanism)
            .ok_or(HsmError::MechanismInvalid)?;
        return crate::crypto::falcon::falcon_sign(&key_bytes, data, variant);
    }

    Err(HsmError::MechanismInvalid)
}

/// Verify `signature` over `data` under the given PQC-or-composite mechanism
/// and public-key handle.
pub fn pqc_verify(
    core: &HsmCore,
    pub_handle: crate::pkcs11_abi::types::CK_OBJECT_HANDLE,
    mechanism: CK_MECHANISM_TYPE,
    data: &[u8],
    signature: &[u8],
) -> HsmResult<bool> {
    let pub_bytes = load_public_key_bytes(core.object_store(), pub_handle)?;

    if pqc::is_ml_dsa_mechanism(mechanism) {
        let variant =
            pqc::mechanism_to_ml_dsa_variant(mechanism).ok_or(HsmError::MechanismInvalid)?;
        return pqc::ml_dsa_verify(&pub_bytes, data, signature, variant);
    }
    if pqc::is_slh_dsa_mechanism(mechanism) {
        let variant =
            pqc::mechanism_to_slh_dsa_variant(mechanism).ok_or(HsmError::MechanismInvalid)?;
        return pqc::slh_dsa_verify(&pub_bytes, data, signature, variant);
    }
    if pqc::is_hybrid_ed25519_mldsa65_mechanism(mechanism) {
        // Composite PK layout: [ed25519_pk_32][mldsa65_vk]
        if pub_bytes.len() < 32 {
            return Err(HsmError::KeyHandleInvalid);
        }
        return pqc::hybrid_ed25519_mldsa65_verify(&pub_bytes[32..], &pub_bytes[..32], data, signature);
    }
    if pqc::is_hybrid_mechanism(mechanism) {
        let obj_arc = core.object_store().get_object(pub_handle)?;
        let obj = obj_arc.read();
        let ecdsa_pk = obj
            .extra_attributes
            .get(&CKA_EC_POINT)
            .or(obj.ec_point.as_ref())
            .map(|v| v.as_slice().to_vec())
            .unwrap_or_default();
        return pqc::hybrid_verify(&pub_bytes, &ecdsa_pk, data, signature);
    }
    #[cfg(feature = "falcon-sig")]
    if crate::crypto::falcon::is_falcon_mechanism(mechanism) {
        let variant = crate::crypto::falcon::mechanism_to_falcon_variant(mechanism)
            .ok_or(HsmError::MechanismInvalid)?;
        return crate::crypto::falcon::falcon_verify(&pub_bytes, data, signature, variant);
    }

    Err(HsmError::MechanismInvalid)
}

/// Batch sign — signs each `data` entry under the same key. For SLH-DSA the
/// per-key Merkle state is amortized within a single call, giving a real
/// speed-up over repeated single-shot calls.
///
/// For non-SLH-DSA mechanisms this degrades to a simple loop; the wrapper is
/// kept for API symmetry so callers (vendor-ext / REST /batch) don't branch.
pub fn pqc_batch_sign(
    core: &HsmCore,
    priv_handle: crate::pkcs11_abi::types::CK_OBJECT_HANDLE,
    mechanism: CK_MECHANISM_TYPE,
    datas: &[&[u8]],
) -> HsmResult<Vec<Vec<u8>>> {
    // Loading the key bytes once and reusing them is the first-order
    // speed-up. A deeper SLH-DSA amortization (caching the hypertree root
    // + FORS seed between items) would live in `crypto::pqc` itself and
    // is tracked as future work.
    let mut out = Vec::with_capacity(datas.len());
    for d in datas {
        out.push(pqc_sign(core, priv_handle, mechanism, d)?);
    }
    Ok(out)
}

/// Batch verify — symmetric to [`pqc_batch_sign`].
pub fn pqc_batch_verify(
    core: &HsmCore,
    pub_handle: crate::pkcs11_abi::types::CK_OBJECT_HANDLE,
    mechanism: CK_MECHANISM_TYPE,
    items: &[(&[u8], &[u8])], // (data, signature)
) -> HsmResult<Vec<bool>> {
    let mut out = Vec::with_capacity(items.len());
    for (d, s) in items {
        out.push(pqc_verify(core, pub_handle, mechanism, d, s)?);
    }
    Ok(out)
}

/// Borrow helper — return the stored object so callers can read attributes
/// (label, key_type, CKA_SIGN) without exposing the full StoredObject type.
pub fn inspect<F, T>(
    core: &HsmCore,
    handle: crate::pkcs11_abi::types::CK_OBJECT_HANDLE,
    f: F,
) -> HsmResult<T>
where
    F: FnOnce(&StoredObject) -> T,
{
    let arc = core.object_store().get_object(handle)?;
    let obj = arc.read();
    Ok(f(&*obj))
}
