// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Craton vendor function table and its `C_GetFunctionListExt` exporter.
//!
//! The table contains function pointers to each `CratonExt_*` operation. It
//! is ABI-stable once published: new fields may only be appended, and the
//! `version` field lets callers detect the available subset.

use std::panic::catch_unwind;
use std::sync::OnceLock;

use crate::error::HsmError;
use crate::pkcs11_abi::types::*;

/// Version of the Craton vendor function table.
///
/// Follows PKCS#11's convention: major versions may break ABI, minor versions
/// only append fields. Current release is `1.0`.
pub const CRATON_EXT_VERSION: CK_VERSION = CK_VERSION { major: 1, minor: 0 };

/// Magic value recognized inside `CK_C_INITIALIZE_ARGS::pReserved` that signals
/// "please populate the vendor-ext function-list pointer in this struct".
///
/// Encoded big-endian: `C R A T` (0x43 0x52 0x41 0x54).
pub const CRATON_EXT_INIT_MAGIC: u32 = 0x43_52_41_54;

/// Layout of the caller-supplied buffer pointed at by `pReserved` when the
/// client wants the vendor-ext table populated during `C_Initialize`.
///
/// The caller sets `magic` and `size_of_self` before calling `C_Initialize`;
/// on success `p_function_list` is populated with a pointer to the same
/// `CK_CRATON_EXT_FUNCTION_LIST` as returned by `C_GetFunctionListExt`.
#[repr(C)]
#[derive(Debug)]
pub struct CK_CRATON_EXT_INIT_OUT {
    pub magic: u32,
    pub size_of_self: u32,
    pub p_function_list: *mut CK_CRATON_EXT_FUNCTION_LIST,
}

// ============================================================================
// Batch item (CratonExt_BatchSign / BatchVerify)
// ============================================================================

/// One element of a batch-sign / batch-verify request.
///
/// On input, `data` + `data_len` identify the message. On batch-sign output,
/// `signature` + `signature_len` point at caller-allocated buffers where the
/// signature is written; the implementation updates `signature_len` to the
/// actual signature size. For batch-verify, `signature` + `signature_len`
/// are inputs; `verified` is written to `1` if the signature is valid.
#[repr(C)]
#[derive(Debug)]
pub struct CratonBatchItem {
    pub data: *const u8,
    pub data_len: CK_ULONG,
    pub signature: *mut u8,
    pub signature_len: CK_ULONG,
    pub verified: CK_BBOOL,
}

// ============================================================================
// Capability introspection DTO
// ============================================================================

/// C-ABI capability snapshot. Scalars are `CK_BBOOL`; lists are sized at the
/// caller via `*_count` + buffer pointer (following PKCS#11's standard pattern
/// for variable-length output).
///
/// To probe sizes, pass NULL for each `*_names` buffer; the implementation
/// writes the required count to each `*_count`. Then allocate and call again.
///
/// Strings are NUL-terminated C strings; the implementation owns the storage
/// (static lifetime) — callers must not free the returned pointers.
#[repr(C)]
#[derive(Debug)]
pub struct CratonPQCCaps {
    pub enable_pqc: CK_BBOOL,
    pub fips_approved_only: CK_BBOOL,
    pub vendor_ext_available: CK_BBOOL,
    pub hybrid_kem_wrap_available: CK_BBOOL,
    pub ml_kem_count: CK_ULONG,
    pub ml_kem_names: *const *const std::os::raw::c_char,
    pub ml_dsa_count: CK_ULONG,
    pub ml_dsa_names: *const *const std::os::raw::c_char,
    pub slh_dsa_count: CK_ULONG,
    pub slh_dsa_names: *const *const std::os::raw::c_char,
    pub falcon_count: CK_ULONG,
    pub falcon_names: *const *const std::os::raw::c_char,
    pub frodokem_count: CK_ULONG,
    pub frodokem_names: *const *const std::os::raw::c_char,
    pub hybrid_kem_count: CK_ULONG,
    pub hybrid_kem_names: *const *const std::os::raw::c_char,
    pub composite_sig_count: CK_ULONG,
    pub composite_sig_names: *const *const std::os::raw::c_char,
}

// ============================================================================
// The function table itself
// ============================================================================

/// Craton vendor extension function list.
///
/// Every fn is `extern "C"`, catches panics internally via `catch_unwind`, and
/// returns a standard `CK_RV`. Signatures are documented at each field.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CK_CRATON_EXT_FUNCTION_LIST {
    pub version: CK_VERSION,

    /// Populate a `CratonPQCCaps` with the runtime capability snapshot.
    /// See [`CratonPQCCaps`] for the probe-size-then-fetch pattern.
    pub GetPQCCapabilities: extern "C" fn(*mut CratonPQCCaps) -> CK_RV,

    /// Sign each `CratonBatchItem::data` under `pMechanism` with
    /// `hPrivateKey`; writes signature into each item's buffer.
    ///
    /// For SLH-DSA this amortizes the per-key hypertree root across items
    /// (future work — falls back to a simple loop today).
    pub BatchSign: extern "C" fn(
        CK_SESSION_HANDLE,
        CK_MECHANISM_PTR,
        CK_OBJECT_HANDLE,
        *mut CratonBatchItem,
        CK_ULONG,
    ) -> CK_RV,

    /// Verify each item's signature against its data under `pMechanism`.
    /// Writes `verified = CK_TRUE/CK_FALSE` per item; only returns
    /// `CKR_OK` if dispatch succeeded for every item (individual verification
    /// failures are signalled via `verified`, not the return value).
    pub BatchVerify: extern "C" fn(
        CK_SESSION_HANDLE,
        CK_MECHANISM_PTR,
        CK_OBJECT_HANDLE,
        *mut CratonBatchItem,
        CK_ULONG,
    ) -> CK_RV,

    /// Compose a hybrid signature: sign `pData` with both `hClassicalKey`
    /// and `hPqKey` (must be ML-DSA-65 today), emitting the composite wire
    /// format `[BE u32 len(pq_sig)][pq_sig][classical_sig]`.
    ///
    /// Writes signature + length to `pSignature` / `*pulSigLen`. Standard
    /// PKCS#11 size-probing applies: if `pSignature` is NULL, the required
    /// buffer size is written to `*pulSigLen` and `CKR_OK` returned.
    pub HybridSignCompose: extern "C" fn(
        CK_SESSION_HANDLE,
        CK_OBJECT_HANDLE /*classical*/,
        CK_OBJECT_HANDLE /*pq*/,
        *const u8 /*data*/,
        CK_ULONG /*data_len*/,
        *mut u8 /*sig_out*/,
        *mut CK_ULONG /*sig_len in/out*/,
    ) -> CK_RV,

    /// Verify a composite signature produced by `HybridSignCompose`.
    /// Writes `CK_TRUE/CK_FALSE` to `*pVerified`; returns `CKR_OK` if the
    /// signature parsed and both legs were queried, regardless of outcome.
    pub HybridVerifyCompose: extern "C" fn(
        CK_SESSION_HANDLE,
        CK_OBJECT_HANDLE /*classical_pub*/,
        CK_OBJECT_HANDLE /*pq_pub*/,
        *const u8 /*data*/,
        CK_ULONG,
        *const u8 /*sig*/,
        CK_ULONG,
        *mut CK_BBOOL,
    ) -> CK_RV,

    /// Rotate a PQ key pair under a policy: generates a fresh pair of the
    /// same mechanism as the old key, transitions the old key to Deactivated
    /// or Compromised per policy, and returns the new + retired handles.
    ///
    /// Stub in the current release (`CKR_FUNCTION_NOT_SUPPORTED`) until the
    /// service-layer keygen extraction lands.
    pub PQKeyRotate: extern "C" fn(
        CK_SESSION_HANDLE,
        CK_OBJECT_HANDLE /*old_private*/,
        CK_BBOOL /*mark_compromised*/,
        *mut CK_OBJECT_HANDLE /*new_private*/,
        *mut CK_OBJECT_HANDLE /*new_public*/,
        *mut CK_OBJECT_HANDLE /*retired_private*/,
    ) -> CK_RV,

    /// Generate a key pair and bind it to a platform attestation statement.
    /// Stub in the current release — see `service::attest`.
    pub AttestedKeygen: extern "C" fn(
        CK_SESSION_HANDLE,
        CK_MECHANISM_PTR,
        *const u8 /*nonce*/,
        CK_ULONG,
        *mut CK_OBJECT_HANDLE /*public*/,
        *mut CK_OBJECT_HANDLE /*private*/,
        *mut u8 /*statement_out*/,
        *mut CK_ULONG /*statement_len in/out*/,
    ) -> CK_RV,
}

// SAFETY: all fields are function pointers to `'static` exported symbols; no
// heap state escapes this struct, so `Send`+`Sync` are trivially satisfied.
unsafe impl Send for CK_CRATON_EXT_FUNCTION_LIST {}
unsafe impl Sync for CK_CRATON_EXT_FUNCTION_LIST {}

// ============================================================================
// Static instance of the table + the exported `C_GetFunctionListExt`
// ============================================================================

static EXT_FUNCTION_LIST: OnceLock<CK_CRATON_EXT_FUNCTION_LIST> = OnceLock::new();

/// Build (or return the already-initialised) function table. Callers must
/// never mutate it — treat the returned reference as read-only.
pub fn ext_function_list() -> &'static CK_CRATON_EXT_FUNCTION_LIST {
    EXT_FUNCTION_LIST.get_or_init(|| CK_CRATON_EXT_FUNCTION_LIST {
        version: CRATON_EXT_VERSION,
        GetPQCCapabilities: craton_ext_get_pqc_capabilities,
        BatchSign: craton_ext_batch_sign,
        BatchVerify: craton_ext_batch_verify,
        HybridSignCompose: craton_ext_hybrid_sign_compose,
        HybridVerifyCompose: craton_ext_hybrid_verify_compose,
        PQKeyRotate: craton_ext_pq_key_rotate,
        AttestedKeygen: craton_ext_attested_keygen,
    })
}

/// Vendor-extension equivalent of `C_GetFunctionList`. Writes a pointer to
/// the Craton function table into `*ppList` and returns `CKR_OK`.
#[no_mangle]
pub extern "C" fn C_GetFunctionListExt(
    pp_list: *mut *mut CK_CRATON_EXT_FUNCTION_LIST,
) -> CK_RV {
    if pp_list.is_null() {
        return crate::pkcs11_abi::constants::CKR_ARGUMENTS_BAD;
    }
    let list_ptr = ext_function_list() as *const _ as *mut _;
    unsafe { *pp_list = list_ptr };
    crate::pkcs11_abi::constants::CKR_OK
}

// ============================================================================
// Vendor-function bodies — all thin panic-catching wrappers over service::
// ============================================================================

use crate::pkcs11_abi::constants::*;
use crate::pkcs11_abi::functions::get_hsm;
use crate::pkcs11_abi::functions::err_to_rv;

fn ck_bbool(b: bool) -> CK_BBOOL {
    if b { 1 } else { 0 }
}

// ----- GetPQCCapabilities -----
//
// Static NUL-terminated C string storage. Built lazily on first call so we
// don't pay for CString allocation on every invocation.

use std::ffi::CString;

struct CapsCStrings {
    _owning: Vec<CString>,
    ml_kem: Vec<*const std::os::raw::c_char>,
    ml_dsa: Vec<*const std::os::raw::c_char>,
    slh_dsa: Vec<*const std::os::raw::c_char>,
    falcon: Vec<*const std::os::raw::c_char>,
    frodokem: Vec<*const std::os::raw::c_char>,
    hybrid_kem: Vec<*const std::os::raw::c_char>,
    composite: Vec<*const std::os::raw::c_char>,
}

unsafe impl Send for CapsCStrings {}
unsafe impl Sync for CapsCStrings {}

static CAPS_STRINGS: OnceLock<CapsCStrings> = OnceLock::new();

fn caps_strings() -> &'static CapsCStrings {
    CAPS_STRINGS.get_or_init(|| {
        let mut owning: Vec<CString> = Vec::new();
        let mut push_group = |names: &[&str]| -> Vec<*const std::os::raw::c_char> {
            let mut ptrs = Vec::with_capacity(names.len());
            for n in names {
                let c = CString::new(*n).expect("static cap name has no NUL");
                ptrs.push(c.as_ptr());
                owning.push(c);
            }
            ptrs
        };
        let ml_kem = push_group(&["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]);
        let ml_dsa = push_group(&["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]);
        let slh_dsa = push_group(&[
            "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f",
            "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
            "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f",
            "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
            "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f",
            "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f",
        ]);
        #[cfg(feature = "falcon-sig")]
        let falcon = push_group(&["Falcon-512", "Falcon-1024"]);
        #[cfg(not(feature = "falcon-sig"))]
        let falcon: Vec<*const std::os::raw::c_char> = Vec::new();
        #[cfg(feature = "frodokem-kem")]
        let frodokem = push_group(&["FrodoKEM-640-AES", "FrodoKEM-976-AES", "FrodoKEM-1344-AES"]);
        #[cfg(not(feature = "frodokem-kem"))]
        let frodokem: Vec<*const std::os::raw::c_char> = Vec::new();
        #[cfg(feature = "hybrid-kem")]
        let hybrid_kem = push_group(&[
            "X25519+ML-KEM-768",
            "X25519+ML-KEM-1024",
            "P-256+ML-KEM-768",
            "P-384+ML-KEM-1024",
        ]);
        #[cfg(not(feature = "hybrid-kem"))]
        let hybrid_kem: Vec<*const std::os::raw::c_char> = Vec::new();
        let composite = push_group(&["ECDSA-P256+ML-DSA-65", "Ed25519+ML-DSA-65"]);
        CapsCStrings { _owning: owning, ml_kem, ml_dsa, slh_dsa, falcon, frodokem, hybrid_kem, composite }
    })
}

extern "C" fn craton_ext_get_pqc_capabilities(out: *mut CratonPQCCaps) -> CK_RV {
    catch_unwind(|| {
        if out.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        let caps = match crate::service::caps::get_pqc_capabilities(&hsm) {
            Ok(c) => c,
            Err(e) => return err_to_rv(e),
        };
        let cs = caps_strings();
        unsafe {
            *out = CratonPQCCaps {
                enable_pqc: ck_bbool(caps.enable_pqc),
                fips_approved_only: ck_bbool(caps.fips_approved_only),
                vendor_ext_available: ck_bbool(caps.vendor_ext_available),
                hybrid_kem_wrap_available: ck_bbool(caps.hybrid_kem_wrap_available),
                ml_kem_count: cs.ml_kem.len() as CK_ULONG,
                ml_kem_names: cs.ml_kem.as_ptr(),
                ml_dsa_count: cs.ml_dsa.len() as CK_ULONG,
                ml_dsa_names: cs.ml_dsa.as_ptr(),
                slh_dsa_count: cs.slh_dsa.len() as CK_ULONG,
                slh_dsa_names: cs.slh_dsa.as_ptr(),
                falcon_count: cs.falcon.len() as CK_ULONG,
                falcon_names: if cs.falcon.is_empty() { std::ptr::null() } else { cs.falcon.as_ptr() },
                frodokem_count: cs.frodokem.len() as CK_ULONG,
                frodokem_names: if cs.frodokem.is_empty() { std::ptr::null() } else { cs.frodokem.as_ptr() },
                hybrid_kem_count: cs.hybrid_kem.len() as CK_ULONG,
                hybrid_kem_names: if cs.hybrid_kem.is_empty() { std::ptr::null() } else { cs.hybrid_kem.as_ptr() },
                composite_sig_count: cs.composite.len() as CK_ULONG,
                composite_sig_names: cs.composite.as_ptr(),
            };
        }
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

// ----- BatchSign / BatchVerify -----

extern "C" fn craton_ext_batch_sign(
    _session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    h_key: CK_OBJECT_HANDLE,
    p_items: *mut CratonBatchItem,
    ul_count: CK_ULONG,
) -> CK_RV {
    catch_unwind(|| {
        if p_mechanism.is_null() || (p_items.is_null() && ul_count > 0) {
            return CKR_ARGUMENTS_BAD;
        }
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        let mechanism = unsafe { (*p_mechanism).mechanism };

        for i in 0..ul_count as usize {
            let item = unsafe { &mut *p_items.add(i) };
            if item.data.is_null() && item.data_len > 0 {
                return CKR_ARGUMENTS_BAD;
            }
            let data =
                unsafe { std::slice::from_raw_parts(item.data, item.data_len as usize) };
            let sig = match crate::service::sign::pqc_sign(&hsm, h_key, mechanism, data) {
                Ok(s) => s,
                Err(e) => return err_to_rv(e),
            };
            if item.signature.is_null() {
                item.signature_len = sig.len() as CK_ULONG;
                continue; // size-probing path
            }
            if (item.signature_len as usize) < sig.len() {
                item.signature_len = sig.len() as CK_ULONG;
                return CKR_BUFFER_TOO_SMALL;
            }
            unsafe {
                std::ptr::copy_nonoverlapping(sig.as_ptr(), item.signature, sig.len());
            }
            item.signature_len = sig.len() as CK_ULONG;
        }
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

extern "C" fn craton_ext_batch_verify(
    _session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    h_key: CK_OBJECT_HANDLE,
    p_items: *mut CratonBatchItem,
    ul_count: CK_ULONG,
) -> CK_RV {
    catch_unwind(|| {
        if p_mechanism.is_null() || (p_items.is_null() && ul_count > 0) {
            return CKR_ARGUMENTS_BAD;
        }
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        let mechanism = unsafe { (*p_mechanism).mechanism };

        for i in 0..ul_count as usize {
            let item = unsafe { &mut *p_items.add(i) };
            if item.data.is_null() && item.data_len > 0 {
                return CKR_ARGUMENTS_BAD;
            }
            let data =
                unsafe { std::slice::from_raw_parts(item.data, item.data_len as usize) };
            let sig = unsafe {
                std::slice::from_raw_parts(item.signature, item.signature_len as usize)
            };
            match crate::service::sign::pqc_verify(&hsm, h_key, mechanism, data, sig) {
                Ok(ok) => item.verified = ck_bbool(ok),
                Err(e) => return err_to_rv(e),
            }
        }
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

// ----- HybridSignCompose / HybridVerifyCompose -----
//
// Composite sig wire format matches the existing ECDSA + ML-DSA-65 hybrid
// produced by `pqc::hybrid_sign`: `[BE u32 len(ml_sig)][ml_sig][classical_sig]`.

extern "C" fn craton_ext_hybrid_sign_compose(
    _session: CK_SESSION_HANDLE,
    h_classical: CK_OBJECT_HANDLE,
    h_pq: CK_OBJECT_HANDLE,
    p_data: *const u8,
    ul_data_len: CK_ULONG,
    p_sig: *mut u8,
    p_sig_len: *mut CK_ULONG,
) -> CK_RV {
    catch_unwind(|| {
        if p_data.is_null() && ul_data_len > 0 {
            return CKR_ARGUMENTS_BAD;
        }
        if p_sig_len.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        let data = unsafe { std::slice::from_raw_parts(p_data, ul_data_len as usize) };

        // Fetch both private keys.
        let pq_bytes = match crate::service::sign::inspect(&hsm, h_pq, |obj| {
            obj.key_material.as_ref().map(|m| m.as_bytes().to_vec())
        }) {
            Ok(Some(v)) => v,
            Ok(None) | Err(_) => return CKR_KEY_HANDLE_INVALID,
        };
        let cl_bytes = match crate::service::sign::inspect(&hsm, h_classical, |obj| {
            obj.key_material.as_ref().map(|m| m.as_bytes().to_vec())
        }) {
            Ok(Some(v)) => v,
            Ok(None) | Err(_) => return CKR_KEY_HANDLE_INVALID,
        };

        let sig = match crate::crypto::pqc::hybrid_sign(&pq_bytes, &cl_bytes, data) {
            Ok(s) => s,
            Err(e) => return err_to_rv(e),
        };

        let needed = sig.len() as CK_ULONG;
        if p_sig.is_null() {
            unsafe { *p_sig_len = needed };
            return CKR_OK;
        }
        let avail = unsafe { *p_sig_len };
        if avail < needed {
            unsafe { *p_sig_len = needed };
            return CKR_BUFFER_TOO_SMALL;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(sig.as_ptr(), p_sig, sig.len());
            *p_sig_len = needed;
        }
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

extern "C" fn craton_ext_hybrid_verify_compose(
    _session: CK_SESSION_HANDLE,
    h_classical_pub: CK_OBJECT_HANDLE,
    h_pq_pub: CK_OBJECT_HANDLE,
    p_data: *const u8,
    ul_data_len: CK_ULONG,
    p_sig: *const u8,
    ul_sig_len: CK_ULONG,
    p_verified: *mut CK_BBOOL,
) -> CK_RV {
    catch_unwind(|| {
        if p_verified.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        let data = unsafe { std::slice::from_raw_parts(p_data, ul_data_len as usize) };
        let sig = unsafe { std::slice::from_raw_parts(p_sig, ul_sig_len as usize) };

        let pq_pub = match crate::service::sign::inspect(&hsm, h_pq_pub, |obj| {
            obj.public_key_data.clone()
        }) {
            Ok(Some(v)) => v,
            Ok(None) | Err(_) => return CKR_KEY_HANDLE_INVALID,
        };
        let cl_pub = match crate::service::sign::inspect(&hsm, h_classical_pub, |obj| {
            obj.public_key_data
                .clone()
                .or_else(|| obj.ec_point.clone())
        }) {
            Ok(Some(v)) => v,
            Ok(None) | Err(_) => return CKR_KEY_HANDLE_INVALID,
        };

        let ok = crate::crypto::pqc::hybrid_verify(&pq_pub, &cl_pub, data, sig)
            .unwrap_or(false);
        unsafe { *p_verified = ck_bbool(ok) };
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

// ----- PQKeyRotate / AttestedKeygen (stubs pending service::keygen extraction) -----

extern "C" fn craton_ext_pq_key_rotate(
    _session: CK_SESSION_HANDLE,
    h_old_private: CK_OBJECT_HANDLE,
    mark_compromised: CK_BBOOL,
    new_private: *mut CK_OBJECT_HANDLE,
    new_public: *mut CK_OBJECT_HANDLE,
    retired_private: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    catch_unwind(|| {
        if new_private.is_null() || new_public.is_null() || retired_private.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };

        // Recover the mechanism from the old object. Stored at keygen time
        // only implicitly (via CKK_*), so we infer by scanning the PQC
        // variant tables; if inference fails we bail with `KEY_HANDLE_INVALID`.
        let mechanism = match infer_mechanism_from_handle(&hsm, h_old_private) {
            Ok(m) => m,
            Err(rv) => return rv,
        };

        let policy = crate::service::rotate::RotatePolicy {
            mark_compromised: mark_compromised != 0,
        };
        let rotated =
            match crate::service::rotate::rotate_key(&hsm, h_old_private, mechanism, policy) {
                Ok(r) => r,
                Err(e) => return err_to_rv(e),
            };

        unsafe {
            *new_private = rotated.new_private;
            *new_public = rotated.new_public;
            *retired_private = rotated.retired_private;
        }
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

extern "C" fn craton_ext_attested_keygen(
    _session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    p_nonce: *const u8,
    ul_nonce_len: CK_ULONG,
    p_public: *mut CK_OBJECT_HANDLE,
    p_private: *mut CK_OBJECT_HANDLE,
    p_statement: *mut u8,
    p_statement_len: *mut CK_ULONG,
) -> CK_RV {
    catch_unwind(|| {
        if p_mechanism.is_null() || p_statement_len.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        let mechanism = unsafe { (*p_mechanism).mechanism };
        let nonce = if p_nonce.is_null() || ul_nonce_len == 0 {
            &[][..]
        } else {
            unsafe { std::slice::from_raw_parts(p_nonce, ul_nonce_len as usize) }
        };

        let attested = match crate::service::attest::attested_keygen(&hsm, mechanism, nonce) {
            Ok(a) => a,
            Err(e) => return err_to_rv(e),
        };

        // Size-probing: when p_statement is NULL, just report the needed size.
        let needed = attested.statement.len() as CK_ULONG;
        if p_statement.is_null() {
            unsafe { *p_statement_len = needed };
            // The handles must still be written even on the sizing probe so
            // the caller doesn't generate the key twice.
            if !p_public.is_null() {
                unsafe { *p_public = attested.public_handle };
            }
            if !p_private.is_null() {
                unsafe { *p_private = attested.private_handle };
            }
            return CKR_OK;
        }
        let cap = unsafe { *p_statement_len };
        if cap < needed {
            unsafe { *p_statement_len = needed };
            return CKR_BUFFER_TOO_SMALL;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(
                attested.statement.as_ptr(),
                p_statement,
                attested.statement.len(),
            );
            *p_statement_len = needed;
            if !p_public.is_null() {
                *p_public = attested.public_handle;
            }
            if !p_private.is_null() {
                *p_private = attested.private_handle;
            }
        }
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// Infer the PKCS#11 mechanism from a stored private-key object handle.
///
/// We examine `public_key_data.len()` alongside `key_type` to disambiguate
/// fixed-size variants (e.g. ML-KEM-768 vs 1024 both stored as `CKK_ML_KEM`).
/// Composite and hybrid mechanisms store handles under `CKK_ML_DSA` /
/// `CKK_ML_KEM` with the classical leg concatenated — those paths match on
/// length too.
fn infer_mechanism_from_handle(
    hsm: &crate::core::HsmCore,
    handle: CK_OBJECT_HANDLE,
) -> Result<CK_MECHANISM_TYPE, CK_RV> {
    let arc = hsm
        .object_store()
        .get_object(handle)
        .map_err(err_to_rv)?;
    let obj = arc.read();
    let kt = obj.key_type.unwrap_or(0);
    let pk_len = obj.public_key_data.as_ref().map(|v| v.len()).unwrap_or(0);

    match kt {
        crate::pkcs11_abi::constants::CKK_ML_KEM => match pk_len {
            800 => Ok(crate::pkcs11_abi::constants::CKM_ML_KEM_512),
            1184 => Ok(crate::pkcs11_abi::constants::CKM_ML_KEM_768),
            1568 => Ok(crate::pkcs11_abi::constants::CKM_ML_KEM_1024),
            _ => Err(CKR_KEY_HANDLE_INVALID),
        },
        crate::pkcs11_abi::constants::CKK_ML_DSA => match pk_len {
            1312 => Ok(crate::pkcs11_abi::constants::CKM_ML_DSA_44),
            1952 => Ok(crate::pkcs11_abi::constants::CKM_ML_DSA_65),
            2592 => Ok(crate::pkcs11_abi::constants::CKM_ML_DSA_87),
            // Composite: [ed25519_pk_32 ∥ ml_dsa_65_vk_1952] = 1984
            1984 => Ok(crate::pkcs11_abi::constants::CKM_HYBRID_ED25519_MLDSA65),
            _ => Err(CKR_KEY_HANDLE_INVALID),
        },
        crate::pkcs11_abi::constants::CKK_SLH_DSA => match pk_len {
            32 => Ok(crate::pkcs11_abi::constants::CKM_SLH_DSA_SHA2_128S),
            48 => Ok(crate::pkcs11_abi::constants::CKM_SLH_DSA_SHA2_192S),
            64 => Ok(crate::pkcs11_abi::constants::CKM_SLH_DSA_SHA2_256S),
            _ => Err(CKR_KEY_HANDLE_INVALID),
        },
        crate::pkcs11_abi::constants::CKK_FALCON => match pk_len {
            897 => Ok(crate::pkcs11_abi::constants::CKM_FALCON_512),
            1793 => Ok(crate::pkcs11_abi::constants::CKM_FALCON_1024),
            _ => Err(CKR_KEY_HANDLE_INVALID),
        },
        crate::pkcs11_abi::constants::CKK_FRODO_KEM => match pk_len {
            9616 => Ok(crate::pkcs11_abi::constants::CKM_FRODO_KEM_640_AES),
            15632 => Ok(crate::pkcs11_abi::constants::CKM_FRODO_KEM_976_AES),
            21520 => Ok(crate::pkcs11_abi::constants::CKM_FRODO_KEM_1344_AES),
            _ => Err(CKR_KEY_HANDLE_INVALID),
        },
        _ => Err(CKR_KEY_HANDLE_INVALID),
    }
}
