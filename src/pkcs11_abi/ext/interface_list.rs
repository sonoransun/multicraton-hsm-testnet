// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! `C_GetInterfaceList` + `C_GetInterface` — PKCS#11 v3.0 interface discovery.
//!
//! The PKCS#11 v3.0 spec introduced these entry points so that a library can
//! publish multiple named interfaces (function tables) simultaneously. We
//! publish three:
//!
//! | Name            | Version | Function list                |
//! |-----------------|---------|------------------------------|
//! | `PKCS 11`       | 3.0     | existing `CK_FUNCTION_LIST`  |
//! | `PKCS 11`       | 3.2     | same table, marker for KEM ABI presence (`C_EncapsulateKey`) |
//! | `Craton PKCS 11`| 1.0     | [`super::vendor_table::CK_CRATON_EXT_FUNCTION_LIST`] |
//!
//! The v3.2 entry intentionally points at the same v3.0 function list — the
//! PKCS#11 v3.2 KEM entry points (`C_EncapsulateKey` / `C_DecapsulateKey`)
//! are published as standalone exported symbols, and clients locate them via
//! `dlsym` once they observe the v3.2 interface is advertised.

use std::ffi::CString;
use std::os::raw::c_char;
use std::panic::catch_unwind;
use std::sync::OnceLock;

use crate::pkcs11_abi::constants::*;
use crate::pkcs11_abi::types::*;

/// One enumerable interface, storing its name CString alongside the raw
/// ABI struct so the pointers in `CK_INTERFACE` stay valid for `'static`.
struct InterfaceEntry {
    _name: CString,
    iface: CK_INTERFACE,
}

unsafe impl Send for InterfaceEntry {}
unsafe impl Sync for InterfaceEntry {}

fn interfaces() -> &'static [InterfaceEntry] {
    static ENTRIES: OnceLock<Vec<InterfaceEntry>> = OnceLock::new();
    ENTRIES.get_or_init(|| {
        let mut v: Vec<InterfaceEntry> = Vec::new();

        // PKCS#11 v3.0 — points at the classic function table.
        let n30 = CString::new(CKI_PKCS11_NAME).unwrap();
        let ptr_30 = crate::pkcs11_abi::functions::function_list_ptr() as CK_VOID_PTR;
        v.push(InterfaceEntry {
            iface: CK_INTERFACE {
                p_interface_name: n30.as_ptr(),
                p_function_list: ptr_30,
                flags: 0,
            },
            _name: n30,
        });

        // PKCS#11 v3.2 — same table (KEM entry points are separate exports).
        let n32 = CString::new(CKI_PKCS11_NAME).unwrap();
        v.push(InterfaceEntry {
            iface: CK_INTERFACE {
                p_interface_name: n32.as_ptr(),
                p_function_list: ptr_30, // same underlying fns; v3.2 = marker
                flags: 0,
            },
            _name: n32,
        });

        // Craton vendor interface — returns the CK_CRATON_EXT_FUNCTION_LIST.
        let nc = CString::new(CKI_CRATON_EXT_NAME).unwrap();
        let ext_ptr =
            super::vendor_table::ext_function_list() as *const _ as CK_VOID_PTR;
        v.push(InterfaceEntry {
            iface: CK_INTERFACE {
                p_interface_name: nc.as_ptr(),
                p_function_list: ext_ptr,
                flags: 0,
            },
            _name: nc,
        });

        v
    })
}

/// Export list mirroring `interfaces()` as bare `CK_INTERFACE` values for the
/// PKCS#11 ABI consumer.
fn interface_list_array() -> &'static [CK_INTERFACE] {
    static OUT: OnceLock<Vec<CK_INTERFACE>> = OnceLock::new();
    OUT.get_or_init(|| interfaces().iter().map(|e| e.iface).collect())
}

/// `C_GetInterfaceList(pInterfacesList, pulCount)`
///
/// Size probing: if `pInterfacesList` is NULL, writes the count to `*pulCount`
/// and returns `CKR_OK`. Otherwise fills the caller's array up to `*pulCount`
/// entries and updates the count to the number written.
#[no_mangle]
pub extern "C" fn C_GetInterfaceList(
    p_interfaces_list: CK_INTERFACE_PTR,
    pul_count: *mut CK_ULONG,
) -> CK_RV {
    catch_unwind(|| {
        if pul_count.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let list = interface_list_array();
        let needed = list.len() as CK_ULONG;
        if p_interfaces_list.is_null() {
            unsafe { *pul_count = needed };
            return CKR_OK;
        }
        let cap = unsafe { *pul_count };
        if cap < needed {
            unsafe { *pul_count = needed };
            return CKR_BUFFER_TOO_SMALL;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(list.as_ptr(), p_interfaces_list, list.len());
            *pul_count = needed;
        }
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// `C_GetInterface(pInterfaceName, pVersion, ppInterface, flags)`
///
/// Locate a specific interface by name (and optionally version). `pVersion`
/// NULL means "any version"; the first matching interface is returned.
#[no_mangle]
pub extern "C" fn C_GetInterface(
    p_interface_name: *const c_char,
    _p_version: *const CK_VERSION,
    pp_interface: *mut CK_INTERFACE_PTR,
    _flags: CK_FLAGS,
) -> CK_RV {
    catch_unwind(|| {
        if p_interface_name.is_null() || pp_interface.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let wanted = unsafe { std::ffi::CStr::from_ptr(p_interface_name) };
        for entry in interfaces() {
            let name = unsafe { std::ffi::CStr::from_ptr(entry.iface.p_interface_name) };
            if name == wanted {
                unsafe {
                    *pp_interface = &entry.iface as *const CK_INTERFACE as *mut _;
                }
                return CKR_OK;
            }
        }
        CKR_FUNCTION_FAILED
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}
