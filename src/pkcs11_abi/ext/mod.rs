// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! PKCS#11 vendor extension surface (feature `vendor-ext`).
//!
//! Exposes:
//! - [`interface_list::C_GetInterfaceList`] — enumerate every interface this
//!   library publishes (PKCS#11 v3.0, PKCS#11 v3.2-subset, Craton vendor).
//! - [`kem_v32`] — native `C_EncapsulateKey` / `C_DecapsulateKey` exports that
//!   match the PKCS#11 v3.2 spec signatures.
//! - [`vendor_table::C_GetFunctionListExt`] + [`vendor_table::CK_CRATON_EXT_FUNCTION_LIST`] —
//!   vendor function table for batch signing, composite signatures, key rotation,
//!   attested keygen, and PQC capability introspection.
//! - [`hybrid_wrap`] — handler for `CKM_HYBRID_KEM_WRAP` invoked from the
//!   standard `C_WrapKey` / `C_UnwrapKey` dispatch (no new exports).
//!
//! Discovery path. Clients have three options, in increasing order of
//! spec conformance:
//!
//! 1. **Classic v3.0 only**: `C_GetFunctionList` still works and returns the
//!    unchanged 68-entry table. No vendor extensions are reachable.
//! 2. **v3.0 + extensions**: `C_GetFunctionListExt` returns the Craton table;
//!    additionally, passing a `CK_C_INITIALIZE_ARGS` whose `pReserved` points
//!    at a `CK_CRATON_EXT_INIT_OUT` with magic `0x43_52_41_54` ("CRAT") causes
//!    `C_Initialize` to write the ext table pointer into the caller-provided
//!    out slot.
//! 3. **v3.0+ canonical**: `C_GetInterfaceList` enumerates `("PKCS 11", 3.0)`,
//!    `("PKCS 11", 3.2)`, and `("Craton PKCS 11", 1.0)`. The caller picks an
//!    interface by name + version; the corresponding function table is returned.

pub mod hybrid_wrap;
pub mod interface_list;
pub mod kem_v32;
pub mod vendor_table;

pub use vendor_table::{CK_CRATON_EXT_FUNCTION_LIST, CratonPQCCaps, CratonBatchItem};
