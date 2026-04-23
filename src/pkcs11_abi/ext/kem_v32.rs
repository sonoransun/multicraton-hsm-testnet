// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! PKCS#11 v3.2 native KEM ABI.
//!
//! Exposes `C_EncapsulateKey` and `C_DecapsulateKey` as standalone exported
//! symbols matching the v3.2 spec prototype. They route through the same
//! `service::kem` layer that the REST API and the bindings use, so behaviour
//! is consistent across every surface.
//!
//! Dispatch covers:
//! - ML-KEM-{512,768,1024}
//! - FrodoKEM-{640,976,1344}-AES (feature `frodokem-kem`)
//! - Hybrid KEM (X25519+ML-KEM-*, P-256+ML-KEM-768, P-384+ML-KEM-1024) (`hybrid-kem`)
//!
//! ## Current limitation
//! The shared-secret output is written directly to a caller buffer
//! (`pSharedSecret` / `*pulSharedSecretLen`) rather than materialized as a
//! new PKCS#11 secret-key object. Supporting the second form requires
//! hooking into `service::keygen` once the keygen extraction from
//! `pkcs11_abi::functions::generate_pqc_keypair` lands. Returning a byte
//! buffer matches the behaviour of every hybrid-KEM helper already in
//! `crypto::hybrid_kem` and `crypto::hybrid`.

use std::panic::catch_unwind;

use crate::pkcs11_abi::constants::*;
use crate::pkcs11_abi::functions::{err_to_rv, get_hsm};
use crate::pkcs11_abi::types::*;

/// `C_EncapsulateKey(hSession, pMechanism, hPublicKey,
///                   pCiphertext, pulCiphertextLen,
///                   pSharedSecret, pulSharedSecretLen)`
///
/// The implementation follows PKCS#11's standard two-call probing pattern:
/// if `pCiphertext` or `pSharedSecret` is NULL, the required byte count is
/// written to the matching `*pul*Len` and the function returns `CKR_OK`.
/// When both buffers are provided, they are filled and the returned lengths
/// updated to the actual output sizes.
#[no_mangle]
pub extern "C" fn C_EncapsulateKey(
    _session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    h_public_key: CK_OBJECT_HANDLE,
    p_ciphertext: *mut u8,
    p_ct_len: *mut CK_ULONG,
    p_shared_secret: *mut u8,
    p_ss_len: *mut CK_ULONG,
) -> CK_RV {
    catch_unwind(|| {
        if p_mechanism.is_null() || p_ct_len.is_null() || p_ss_len.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        let mechanism = unsafe { (*p_mechanism).mechanism };

        let result =
            crate::service::kem::encapsulate_by_handle(&hsm, h_public_key, mechanism);
        let bundle = match result {
            Ok(b) => b,
            Err(e) => return err_to_rv(e),
        };

        let ct_needed = bundle.ciphertext.len() as CK_ULONG;
        let ss_needed = bundle.shared_secret.len() as CK_ULONG;

        if p_ciphertext.is_null() || p_shared_secret.is_null() {
            unsafe {
                *p_ct_len = ct_needed;
                *p_ss_len = ss_needed;
            }
            return CKR_OK;
        }
        let ct_cap = unsafe { *p_ct_len };
        let ss_cap = unsafe { *p_ss_len };
        if ct_cap < ct_needed || ss_cap < ss_needed {
            unsafe {
                *p_ct_len = ct_needed;
                *p_ss_len = ss_needed;
            }
            return CKR_BUFFER_TOO_SMALL;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(
                bundle.ciphertext.as_ptr(),
                p_ciphertext,
                bundle.ciphertext.len(),
            );
            std::ptr::copy_nonoverlapping(
                bundle.shared_secret.as_ptr(),
                p_shared_secret,
                bundle.shared_secret.len(),
            );
            *p_ct_len = ct_needed;
            *p_ss_len = ss_needed;
        }
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}

/// `C_DecapsulateKey(hSession, pMechanism, hPrivateKey,
///                   pCiphertext, ulCiphertextLen,
///                   pSharedSecret, pulSharedSecretLen)`
#[no_mangle]
pub extern "C" fn C_DecapsulateKey(
    _session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    h_private_key: CK_OBJECT_HANDLE,
    p_ciphertext: *const u8,
    ul_ct_len: CK_ULONG,
    p_shared_secret: *mut u8,
    p_ss_len: *mut CK_ULONG,
) -> CK_RV {
    catch_unwind(|| {
        if p_mechanism.is_null() || p_ciphertext.is_null() || p_ss_len.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let hsm = match get_hsm() {
            Ok(h) => h,
            Err(rv) => return rv,
        };
        let mechanism = unsafe { (*p_mechanism).mechanism };
        let ct = unsafe { std::slice::from_raw_parts(p_ciphertext, ul_ct_len as usize) };

        let ss = match crate::service::kem::decapsulate_by_handle(
            &hsm,
            h_private_key,
            mechanism,
            ct,
        ) {
            Ok(v) => v,
            Err(e) => return err_to_rv(e),
        };

        let needed = ss.len() as CK_ULONG;
        if p_shared_secret.is_null() {
            unsafe { *p_ss_len = needed };
            return CKR_OK;
        }
        let cap = unsafe { *p_ss_len };
        if cap < needed {
            unsafe { *p_ss_len = needed };
            return CKR_BUFFER_TOO_SMALL;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(ss.as_ptr(), p_shared_secret, ss.len());
            *p_ss_len = needed;
        }
        CKR_OK
    })
    .unwrap_or(CKR_GENERAL_ERROR)
}
