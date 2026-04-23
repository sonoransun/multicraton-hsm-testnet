// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
pub mod constants;
pub mod functions;
pub mod types;

/// PKCS#11 vendor-extension surface. Gated by the `vendor-ext` feature so
/// default builds do not add any new exports. When enabled, contributes:
///
/// * `C_GetInterfaceList` / `C_GetFunctionListExt` — discovery of alternative
///   interfaces including the Craton vendor table and a PKCS#11 v3.2 facade.
/// * `C_EncapsulateKey` / `C_DecapsulateKey` — native KEM ABI, replacing
///   the current pattern of layering KEM over `C_Encrypt` / `C_UnwrapKey`.
/// * `CratonExt_*` function table (batch sign/verify, composite sign,
///   PQ key rotate, attested keygen, capabilities introspection).
/// * `CKM_HYBRID_KEM_WRAP` dispatch through the existing `C_WrapKey`
///   / `C_UnwrapKey` path (no new exports required).
#[cfg(feature = "vendor-ext")]
pub mod ext;
