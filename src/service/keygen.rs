// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Key-pair generation service.
//!
//! Thin wrapper over [`crate::pkcs11_abi::functions::generate_pqc_keypair`]
//! that returns an `HsmResult` instead of a `CK_RV`. Both [`crate::service::rotate`]
//! and [`crate::service::attest`] compose on top of this so they never have
//! to re-implement mechanism dispatch or the pairwise-consistency machinery.
//!
//! Keeping the dispatch table in `pkcs11_abi::functions` is deliberate —
//! it already owns the `POST_FAILED` global, `apply_pub_template`,
//! `apply_priv_template`, and `build_pqc_objects`. Relocating those would
//! span half the code base; wrapping is cleaner.

use crate::core::HsmCore;
use crate::error::{HsmError, HsmResult};
use crate::pkcs11_abi::types::{CK_ATTRIBUTE_TYPE, CK_MECHANISM_TYPE, CK_OBJECT_HANDLE};

/// Result of a successful keygen: `(public_handle, private_handle, key_bits)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Generated {
    pub public_handle: CK_OBJECT_HANDLE,
    pub private_handle: CK_OBJECT_HANDLE,
    /// Informational key-strength indicator (CKA_MODULUS_BITS semantics).
    /// For SLH-DSA this is the NIST security category (128/192/256), not a
    /// bit length.
    pub key_bits: u32,
}

/// Generate a PQC key pair and insert it into the object store.
///
/// Accepts any mechanism the PKCS#11 layer knows: ML-KEM, ML-DSA, SLH-DSA,
/// and (feature-gated) Falcon, FrodoKEM, hybrid KEMs, and composite
/// signatures. Runs the standard pairwise-consistency test inline —
/// failure trips `POST_FAILED` and returns [`HsmError::GeneralError`].
pub fn generate_pqc_keypair(
    core: &HsmCore,
    mechanism: CK_MECHANISM_TYPE,
    pub_template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    priv_template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
) -> HsmResult<Generated> {
    let (pub_handle, priv_handle, key_bits) =
        crate::pkcs11_abi::functions::generate_pqc_keypair(
            core,
            mechanism,
            pub_template,
            priv_template,
        )
        .map_err(ck_rv_to_hsm_error)?;
    Ok(Generated {
        public_handle: pub_handle,
        private_handle: priv_handle,
        key_bits,
    })
}

/// Map a subset of `CK_RV` codes encountered in `generate_pqc_keypair`
/// back onto [`HsmError`].
///
/// Only codes the dispatcher can actually return are handled specifically;
/// anything else falls through to `HsmError::GeneralError`. The C ABI maps
/// `HsmError -> CK_RV` via `err_to_rv`; this is the approximate inverse used
/// only where a service-layer caller needs to observe the error kind.
fn ck_rv_to_hsm_error(rv: crate::pkcs11_abi::types::CK_RV) -> HsmError {
    use crate::pkcs11_abi::constants::*;
    match rv {
        CKR_MECHANISM_INVALID => HsmError::MechanismInvalid,
        CKR_ARGUMENTS_BAD => HsmError::ArgumentsBad,
        CKR_TEMPLATE_INCOMPLETE => HsmError::TemplateIncomplete,
        CKR_TEMPLATE_INCONSISTENT => HsmError::TemplateInconsistent,
        CKR_ATTRIBUTE_VALUE_INVALID => HsmError::AttributeValueInvalid,
        CKR_HOST_MEMORY => HsmError::HostMemory,
        CKR_USER_NOT_LOGGED_IN => HsmError::UserNotLoggedIn,
        CKR_SESSION_HANDLE_INVALID => HsmError::SessionHandleInvalid,
        _ => HsmError::GeneralError,
    }
}
