// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Key-Encapsulation Mechanism service.
//!
//! Unifies ML-KEM, FrodoKEM, and all hybrid KEM constructions behind a single
//! `encapsulate_by_handle` / `decapsulate_by_handle` pair. Consumed by the new
//! PKCS#11 `C_EncapsulateKey` / `C_DecapsulateKey` exports, the REST
//! `/v1/kems/.../encapsulate` route, and the Python bindings.

use crate::core::HsmCore;
use crate::crypto::pqc;
use crate::error::{HsmError, HsmResult};
use crate::pkcs11_abi::constants::*;
use crate::pkcs11_abi::types::{CK_MECHANISM_TYPE, CK_OBJECT_HANDLE};

/// KEM encapsulate result bundle.
///
/// `ciphertext` is sent to the decapsulator; `shared_secret` is the 32-byte
/// (ML-KEM / hybrid) or 16/24/32-byte (FrodoKEM) key material that both
/// parties derive.
pub struct EncapsulateResult {
    pub ciphertext: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

/// Encapsulate against the public key identified by `pub_handle`, using the
/// given KEM mechanism. Returns `(ciphertext, shared_secret)`.
pub fn encapsulate_by_handle(
    core: &HsmCore,
    pub_handle: CK_OBJECT_HANDLE,
    mechanism: CK_MECHANISM_TYPE,
) -> HsmResult<EncapsulateResult> {
    let pub_bytes = {
        let arc = core.object_store().get_object(pub_handle)?;
        let obj = arc.read();
        obj.public_key_data
            .clone()
            .ok_or(HsmError::KeyHandleInvalid)?
    };

    if pqc::is_ml_kem_mechanism(mechanism) {
        let variant =
            pqc::mechanism_to_ml_kem_variant(mechanism).ok_or(HsmError::MechanismInvalid)?;
        let (ct, ss) = pqc::ml_kem_encapsulate(&pub_bytes, variant)?;
        return Ok(EncapsulateResult { ciphertext: ct, shared_secret: ss });
    }
    #[cfg(feature = "frodokem-kem")]
    if crate::crypto::frodokem::is_frodo_mechanism(mechanism) {
        let variant = crate::crypto::frodokem::mechanism_to_frodo_variant(mechanism)
            .ok_or(HsmError::MechanismInvalid)?;
        let (ct, ss) = crate::crypto::frodokem::frodo_encapsulate(&pub_bytes, variant)?;
        return Ok(EncapsulateResult { ciphertext: ct, shared_secret: ss });
    }
    #[cfg(feature = "hybrid-kem")]
    if crate::crypto::hybrid::is_new_hybrid_kem_mechanism(mechanism) {
        let (ct, ss) =
            crate::crypto::hybrid::hybrid_kem_encapsulate_by_mechanism(mechanism, &pub_bytes)?;
        return Ok(EncapsulateResult { ciphertext: ct, shared_secret: ss });
    }

    Err(HsmError::MechanismInvalid)
}

/// Decapsulate `ciphertext` using the private key identified by `priv_handle`,
/// recovering the shared secret that the sender derived during encapsulation.
pub fn decapsulate_by_handle(
    core: &HsmCore,
    priv_handle: CK_OBJECT_HANDLE,
    mechanism: CK_MECHANISM_TYPE,
    ciphertext: &[u8],
) -> HsmResult<Vec<u8>> {
    let priv_bytes = {
        let arc = core.object_store().get_object(priv_handle)?;
        let obj = arc.read();
        obj.key_material
            .as_ref()
            .map(|m| m.as_bytes().to_vec())
            .ok_or(HsmError::KeyHandleInvalid)?
    };

    if pqc::is_ml_kem_mechanism(mechanism) {
        let variant =
            pqc::mechanism_to_ml_kem_variant(mechanism).ok_or(HsmError::MechanismInvalid)?;
        return pqc::ml_kem_decapsulate(&priv_bytes, ciphertext, variant);
    }
    #[cfg(feature = "frodokem-kem")]
    if crate::crypto::frodokem::is_frodo_mechanism(mechanism) {
        let variant = crate::crypto::frodokem::mechanism_to_frodo_variant(mechanism)
            .ok_or(HsmError::MechanismInvalid)?;
        return crate::crypto::frodokem::frodo_decapsulate(&priv_bytes, ciphertext, variant);
    }
    #[cfg(feature = "hybrid-kem")]
    if crate::crypto::hybrid::is_new_hybrid_kem_mechanism(mechanism) {
        return crate::crypto::hybrid::hybrid_kem_decapsulate_by_mechanism(
            mechanism,
            &priv_bytes,
            ciphertext,
        );
    }

    Err(HsmError::MechanismInvalid)
}

/// Set of mechanisms `encapsulate_by_handle` knows how to dispatch, useful
/// for `C_GetMechanismList` filters and REST `/v1/capabilities`.
pub fn supported_kem_mechanisms() -> Vec<CK_MECHANISM_TYPE> {
    let mut out = vec![CKM_ML_KEM_512, CKM_ML_KEM_768, CKM_ML_KEM_1024];
    #[cfg(feature = "frodokem-kem")]
    {
        out.extend_from_slice(&[
            CKM_FRODO_KEM_640_AES,
            CKM_FRODO_KEM_976_AES,
            CKM_FRODO_KEM_1344_AES,
        ]);
    }
    #[cfg(feature = "hybrid-kem")]
    {
        out.extend_from_slice(&[
            CKM_HYBRID_X25519_MLKEM1024,
            CKM_HYBRID_P256_MLKEM768,
            CKM_HYBRID_P384_MLKEM1024,
        ]);
    }
    out
}
