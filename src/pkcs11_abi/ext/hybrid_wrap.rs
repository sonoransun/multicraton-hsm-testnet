// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! `CKM_HYBRID_KEM_WRAP` handler.
//!
//! Called from the existing `C_WrapKey` / `C_UnwrapKey` dispatch inside
//! `src/pkcs11_abi/functions.rs` when the mechanism is `CKM_HYBRID_KEM_WRAP`.
//! The real construction lives in [`crate::service::wrap`]; this module is a
//! thin bridge that converts between PKCS#11 handle types and
//! `HsmResult<Vec<u8>>` values for the rest of the ABI layer.
//!
//! Only compiled when the `vendor-ext` and `hybrid-kem` features are both on.

#![cfg(all(feature = "vendor-ext", feature = "hybrid-kem"))]

use crate::core::HsmCore;
use crate::error::HsmResult;
use crate::pkcs11_abi::types::{CK_MECHANISM_TYPE, CK_OBJECT_HANDLE};

/// Wrap `h_target_key` under `h_recipient_pub` using the hybrid-KEM transport.
///
/// `kem_mechanism` must be one of:
/// - `CKM_HYBRID_X25519_MLKEM1024`
/// - `CKM_HYBRID_P256_MLKEM768`
/// - `CKM_HYBRID_P384_MLKEM1024`
pub fn wrap(
    core: &HsmCore,
    h_recipient_pub: CK_OBJECT_HANDLE,
    kem_mechanism: CK_MECHANISM_TYPE,
    h_target_key: CK_OBJECT_HANDLE,
) -> HsmResult<Vec<u8>> {
    crate::service::wrap::hybrid_kem_wrap(core, h_recipient_pub, kem_mechanism, h_target_key)
}

/// Unwrap a `CKM_HYBRID_KEM_WRAP` blob under `h_recipient_priv`.
pub fn unwrap(
    core: &HsmCore,
    h_recipient_priv: CK_OBJECT_HANDLE,
    kem_mechanism: CK_MECHANISM_TYPE,
    wrapped: &[u8],
) -> HsmResult<Vec<u8>> {
    crate::service::wrap::hybrid_kem_unwrap(core, h_recipient_priv, kem_mechanism, wrapped)
}
