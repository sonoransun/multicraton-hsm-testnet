// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
// Tests that a POST (Power-On Self-Test) failure blocks all PKCS#11 operations
// with CKR_GENERAL_ERROR, ensuring no cryptographic service is available when
// the module is in a failed state.

#![allow(non_snake_case)]

use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm::pkcs11_abi::functions::*;
use craton_hsm::pkcs11_abi::types::*;
use std::ptr;

#[test]
fn test_post_failed_blocks_all_operations() {
    // 1. Initialize the library so it is in a known-good state.
    let rv = C_Initialize(ptr::null_mut());
    assert!(
        rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED,
        "C_Initialize failed unexpectedly: 0x{:08X}",
        rv
    );

    // 2. Force the POST_FAILED flag to simulate a self-test failure.
    test_force_post_failed();

    // ---------------------------------------------------------------
    // 3. Verify that every operation gated by get_hsm() returns
    //    CKR_GENERAL_ERROR (0x00000005).
    // ---------------------------------------------------------------

    // C_GetSlotList
    {
        let mut count: CK_ULONG = 0;
        let rv = C_GetSlotList(CK_FALSE, ptr::null_mut(), &mut count);
        assert_eq!(
            rv, CKR_GENERAL_ERROR,
            "C_GetSlotList should return CKR_GENERAL_ERROR after POST failure, got 0x{:08X}",
            rv
        );
    }

    // C_OpenSession
    {
        let mut session: CK_SESSION_HANDLE = 0;
        let rv = C_OpenSession(
            0,
            CKF_RW_SESSION | CKF_SERIAL_SESSION,
            ptr::null_mut(),
            None,
            &mut session,
        );
        assert_eq!(
            rv, CKR_GENERAL_ERROR,
            "C_OpenSession should return CKR_GENERAL_ERROR after POST failure, got 0x{:08X}",
            rv
        );
    }

    // C_Login
    {
        let pin = b"12345678";
        let rv = C_Login(
            1, // dummy session handle
            CKU_USER,
            pin.as_ptr() as *mut _,
            pin.len() as CK_ULONG,
        );
        assert_eq!(
            rv, CKR_GENERAL_ERROR,
            "C_Login should return CKR_GENERAL_ERROR after POST failure, got 0x{:08X}",
            rv
        );
    }

    // C_GenerateRandom
    {
        let mut buf = [0u8; 32];
        let rv = C_GenerateRandom(
            1, // dummy session handle
            buf.as_mut_ptr(),
            buf.len() as CK_ULONG,
        );
        assert_eq!(
            rv, CKR_GENERAL_ERROR,
            "C_GenerateRandom should return CKR_GENERAL_ERROR after POST failure, got 0x{:08X}",
            rv
        );
    }

    // C_DigestInit
    {
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_SHA256,
            p_parameter: ptr::null_mut(),
            parameter_len: 0,
        };
        let rv = C_DigestInit(
            1, // dummy session handle
            &mut mechanism,
        );
        assert_eq!(
            rv, CKR_GENERAL_ERROR,
            "C_DigestInit should return CKR_GENERAL_ERROR after POST failure, got 0x{:08X}",
            rv
        );
    }

    // C_SignInit
    {
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS,
            p_parameter: ptr::null_mut(),
            parameter_len: 0,
        };
        let rv = C_SignInit(
            1, // dummy session handle
            &mut mechanism,
            0, // dummy key handle
        );
        assert_eq!(
            rv, CKR_GENERAL_ERROR,
            "C_SignInit should return CKR_GENERAL_ERROR after POST failure, got 0x{:08X}",
            rv
        );
    }

    // C_EncryptInit
    {
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS,
            p_parameter: ptr::null_mut(),
            parameter_len: 0,
        };
        let rv = C_EncryptInit(
            1, // dummy session handle
            &mut mechanism,
            0, // dummy key handle
        );
        assert_eq!(
            rv, CKR_GENERAL_ERROR,
            "C_EncryptInit should return CKR_GENERAL_ERROR after POST failure, got 0x{:08X}",
            rv
        );
    }

    // C_CreateObject
    {
        let mut handle: CK_OBJECT_HANDLE = 0;
        let rv = C_CreateObject(
            1,            // dummy session handle
            ptr::null_mut(), // no template
            0,            // zero attributes
            &mut handle,
        );
        assert_eq!(
            rv, CKR_GENERAL_ERROR,
            "C_CreateObject should return CKR_GENERAL_ERROR after POST failure, got 0x{:08X}",
            rv
        );
    }

    // ---------------------------------------------------------------
    // 4. Clean up: clear the POST_FAILED flag and finalize.
    // ---------------------------------------------------------------
    test_clear_post_failed();

    let rv = C_Finalize(ptr::null_mut());
    assert!(
        rv == CKR_OK || rv == CKR_CRYPTOKI_NOT_INITIALIZED,
        "C_Finalize failed unexpectedly: 0x{:08X}",
        rv
    );
}
