// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
// Buffer limits ABI tests — exercises defense-in-depth bounds on PIN length,
// template attribute count, and attribute value size through the PKCS#11 C ABI.
//
// Must be run with `--test-threads=1` due to shared global OnceLock state.

use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm::pkcs11_abi::functions::*;
use craton_hsm::pkcs11_abi::types::*;
use std::ptr;

fn ck_ulong_bytes(val: CK_ULONG) -> Vec<u8> {
    val.to_ne_bytes().to_vec()
}

/// Ensure HSM is initialized. Idempotent.
fn ensure_init() {
    let rv = C_Initialize(ptr::null_mut());
    assert!(
        rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED,
        "C_Initialize failed: 0x{:08X}",
        rv
    );
}

/// Re-initialize token, open RW session, set up user PIN, login as user.
/// Returns session handle.
fn setup_user_session() -> CK_SESSION_HANDLE {
    ensure_init();
    let so_pin = b"sopin123";
    let mut label = [b' '; 32];
    label[..7].copy_from_slice(b"BufTest");
    let rv = C_InitToken(
        0,
        so_pin.as_ptr() as *mut _,
        so_pin.len() as CK_ULONG,
        label.as_ptr() as *mut _,
    );
    assert_eq!(rv, CKR_OK, "C_InitToken failed");

    let mut session: CK_SESSION_HANDLE = 0;
    let rv = C_OpenSession(
        0,
        CKF_RW_SESSION | CKF_SERIAL_SESSION,
        ptr::null_mut(),
        None,
        &mut session,
    );
    assert_eq!(rv, CKR_OK);

    let rv = C_Login(
        session,
        CKU_SO,
        so_pin.as_ptr() as *mut _,
        so_pin.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_OK);
    let user_pin = b"userpin1";
    let rv = C_InitPIN(
        session,
        user_pin.as_ptr() as *mut _,
        user_pin.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_OK);
    let rv = C_Logout(session);
    assert_eq!(rv, CKR_OK);
    let rv = C_Login(
        session,
        CKU_USER,
        user_pin.as_ptr() as *mut _,
        user_pin.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_OK);
    session
}

// ============================================================================
// PIN length limits (MAX_PIN_BYTES = 256)
// ============================================================================

#[test]
fn test_pin_exceeds_max_bytes_init_token() {
    ensure_init();
    // A PIN of 257 bytes exceeds MAX_PIN_BYTES (256)
    let oversized_pin = vec![b'A'; 257];
    let mut label = [b' '; 32];
    label[..7].copy_from_slice(b"PinTest");
    let rv = C_InitToken(
        0,
        oversized_pin.as_ptr() as *mut _,
        oversized_pin.len() as CK_ULONG,
        label.as_ptr() as *mut _,
    );
    assert_eq!(
        rv, CKR_PIN_LEN_RANGE,
        "C_InitToken with PIN > 256 bytes should return CKR_PIN_LEN_RANGE, got: 0x{:08X}",
        rv
    );
}

#[test]
fn test_pin_exceeds_max_bytes_login() {
    let session = setup_user_session();
    // Logout first so we can attempt a login
    let rv = C_Logout(session);
    assert_eq!(rv, CKR_OK);

    // Attempt login with oversized PIN (257 bytes)
    let oversized_pin = vec![b'X'; 257];
    let rv = C_Login(
        session,
        CKU_USER,
        oversized_pin.as_ptr() as *mut _,
        oversized_pin.len() as CK_ULONG,
    );
    assert_eq!(
        rv, CKR_PIN_LEN_RANGE,
        "C_Login with PIN > 256 bytes should return CKR_PIN_LEN_RANGE, got: 0x{:08X}",
        rv
    );
}

#[test]
fn test_pin_just_over_max_bytes_init_pin() {
    let session = setup_user_session();
    // Logout user, login as SO to call C_InitPIN
    let rv = C_Logout(session);
    assert_eq!(rv, CKR_OK);
    let so_pin = b"sopin123";
    let rv = C_Login(
        session,
        CKU_SO,
        so_pin.as_ptr() as *mut _,
        so_pin.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_OK);

    // 257 bytes exceeds MAX_PIN_BYTES (256)
    let oversized_pin = vec![b'Z'; 257];
    let rv = C_InitPIN(
        session,
        oversized_pin.as_ptr() as *mut _,
        oversized_pin.len() as CK_ULONG,
    );
    assert_eq!(
        rv, CKR_PIN_LEN_RANGE,
        "C_InitPIN with PIN > 256 bytes should return CKR_PIN_LEN_RANGE, got: 0x{:08X}",
        rv
    );
}

// ============================================================================
// Template attribute count limits (MAX_TEMPLATE_ATTRS = 256)
// ============================================================================

#[test]
fn test_template_exceeds_max_attrs_find() {
    let session = setup_user_session();
    // Build a template with 257 attributes — exceeds MAX_TEMPLATE_ATTRS (256)
    let ck_true: CK_BBOOL = CK_TRUE;
    let mut oversized_template: Vec<CK_ATTRIBUTE> = (0..257)
        .map(|_| CK_ATTRIBUTE {
            attr_type: CKA_ENCRYPT,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        })
        .collect();
    let rv = C_FindObjectsInit(
        session,
        oversized_template.as_mut_ptr(),
        oversized_template.len() as CK_ULONG,
    );
    assert_eq!(
        rv, CKR_ARGUMENTS_BAD,
        "C_FindObjectsInit with > 256 template attrs should return CKR_ARGUMENTS_BAD, got: 0x{:08X}",
        rv
    );
}

#[test]
fn test_template_exceeds_max_attrs_create_object() {
    let session = setup_user_session();
    // Build a template with 257 attributes for C_CreateObject
    let ck_true: CK_BBOOL = CK_TRUE;
    let mut oversized_template: Vec<CK_ATTRIBUTE> = (0..257)
        .map(|_| CK_ATTRIBUTE {
            attr_type: CKA_ENCRYPT,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        })
        .collect();
    let mut handle: CK_OBJECT_HANDLE = 0;
    let rv = C_CreateObject(
        session,
        oversized_template.as_mut_ptr(),
        oversized_template.len() as CK_ULONG,
        &mut handle,
    );
    assert_eq!(
        rv, CKR_ARGUMENTS_BAD,
        "C_CreateObject with > 256 template attrs should return CKR_ARGUMENTS_BAD, got: 0x{:08X}",
        rv
    );
}

#[test]
fn test_template_at_max_attrs_does_not_reject_count() {
    let session = setup_user_session();
    // 256 attributes should not be rejected by the count check itself
    let ck_true: CK_BBOOL = CK_TRUE;
    let mut max_template: Vec<CK_ATTRIBUTE> = (0..256)
        .map(|_| CK_ATTRIBUTE {
            attr_type: CKA_ENCRYPT,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        })
        .collect();
    let rv = C_FindObjectsInit(
        session,
        max_template.as_mut_ptr(),
        max_template.len() as CK_ULONG,
    );
    // Should not fail with ARGUMENTS_BAD (may return OK or other error)
    assert_ne!(
        rv, CKR_ARGUMENTS_BAD,
        "C_FindObjectsInit with exactly 256 attrs should not return CKR_ARGUMENTS_BAD"
    );
    // Clean up the find operation if it succeeded
    if rv == CKR_OK {
        C_FindObjectsFinal(session);
    }
}

// ============================================================================
// Attribute value size limits (MAX_ATTR_VALUE_LEN = 64 KB)
// ============================================================================

#[test]
fn test_attribute_value_exceeds_max_create_object() {
    let session = setup_user_session();
    // Create an attribute value larger than 64 KB (65537 bytes)
    let oversized_value = vec![0u8; 65537];
    let class_bytes = ck_ulong_bytes(CKO_DATA);
    let mut template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_CLASS,
            p_value: class_bytes.as_ptr() as CK_VOID_PTR,
            value_len: class_bytes.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_VALUE,
            p_value: oversized_value.as_ptr() as CK_VOID_PTR,
            value_len: oversized_value.len() as CK_ULONG,
        },
    ];
    let mut handle: CK_OBJECT_HANDLE = 0;
    let rv = C_CreateObject(
        session,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut handle,
    );
    assert!(
        rv == CKR_ATTRIBUTE_VALUE_INVALID || rv == CKR_ARGUMENTS_BAD,
        "C_CreateObject with attribute value > 64 KB should be rejected, got: 0x{:08X}",
        rv
    );
}

#[test]
fn test_attribute_value_exceeds_max_find_objects() {
    let session = setup_user_session();
    // Try C_FindObjectsInit with an attribute value > 64 KB
    let oversized_value = vec![0u8; 65537];
    let mut template = vec![CK_ATTRIBUTE {
        attr_type: CKA_VALUE,
        p_value: oversized_value.as_ptr() as CK_VOID_PTR,
        value_len: oversized_value.len() as CK_ULONG,
    }];
    let rv = C_FindObjectsInit(
        session,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
    );
    assert!(
        rv == CKR_ATTRIBUTE_VALUE_INVALID || rv == CKR_ARGUMENTS_BAD,
        "C_FindObjectsInit with attribute value > 64 KB should be rejected, got: 0x{:08X}",
        rv
    );
}

#[test]
fn test_attribute_value_well_over_max_generate_key() {
    let session = setup_user_session();
    // Use C_GenerateKey with a label attribute whose value is > 64 KB.
    // This exercises parse_template via the key generation path.
    let oversized_label = vec![b'L'; 65537];
    let value_len_bytes = ck_ulong_bytes(32);
    let ck_true: CK_BBOOL = CK_TRUE;
    let mut template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_VALUE_LEN,
            p_value: value_len_bytes.as_ptr() as CK_VOID_PTR,
            value_len: value_len_bytes.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_ENCRYPT,
            p_value: &ck_true as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_LABEL,
            p_value: oversized_label.as_ptr() as CK_VOID_PTR,
            value_len: oversized_label.len() as CK_ULONG,
        },
    ];
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let mut key: CK_OBJECT_HANDLE = 0;
    let rv = C_GenerateKey(
        session,
        &mut mechanism,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut key,
    );
    assert!(
        rv == CKR_ATTRIBUTE_VALUE_INVALID || rv == CKR_ARGUMENTS_BAD,
        "C_GenerateKey with attribute value > 64 KB should be rejected, got: 0x{:08X}",
        rv
    );
}
