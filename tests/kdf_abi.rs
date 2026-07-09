// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! End-to-end ABI tests for HKDF derivation (CKM_HKDF_DERIVE, Stage 1e-KDF).
//!
//! The headline test is an RFC 5869 known-answer test driven entirely through
//! the C ABI: inject the RFC IKM via C_CreateObject, HKDF-derive an AES key,
//! and prove it equals a reference AES key built from the RFC OKM bytes by
//! cross-decrypting an AES-GCM ciphertext.
//!
//! Must run with --test-threads=1 (global PKCS#11 state).

use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm::pkcs11_abi::functions::*;
use craton_hsm::pkcs11_abi::types::*;
use std::ptr;

fn ck_ulong_bytes(v: CK_ULONG) -> Vec<u8> {
    v.to_ne_bytes().to_vec()
}

fn setup_session(label8: &[u8; 8]) -> CK_SESSION_HANDLE {
    let rv = C_Initialize(ptr::null_mut());
    assert!(rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED);
    let so_pin = b"SoPin1234";
    let mut label = [b' '; 32];
    label[..8].copy_from_slice(label8);
    assert_eq!(
        C_InitToken(
            0,
            so_pin.as_ptr() as *mut _,
            so_pin.len() as CK_ULONG,
            label.as_ptr() as *mut _
        ),
        CKR_OK
    );
    let mut session = 0;
    assert_eq!(
        C_OpenSession(
            0,
            CKF_RW_SESSION | CKF_SERIAL_SESSION,
            ptr::null_mut(),
            None,
            &mut session
        ),
        CKR_OK
    );
    assert_eq!(
        C_Login(
            session,
            CKU_SO,
            so_pin.as_ptr() as *mut _,
            so_pin.len() as CK_ULONG
        ),
        CKR_OK
    );
    let user_pin = b"UserPin1234";
    assert_eq!(
        C_InitPIN(
            session,
            user_pin.as_ptr() as *mut _,
            user_pin.len() as CK_ULONG
        ),
        CKR_OK
    );
    assert_eq!(C_Logout(session), CKR_OK);
    assert_eq!(
        C_Login(
            session,
            CKU_USER,
            user_pin.as_ptr() as *mut _,
            user_pin.len() as CK_ULONG
        ),
        CKR_OK
    );
    session
}

/// Create a secret key object with an explicit value.
fn create_secret_key(
    session: CK_SESSION_HANDLE,
    key_type: CK_ULONG,
    value: &[u8],
    derive: bool,
    encrypt: bool,
) -> CK_OBJECT_HANDLE {
    let class = ck_ulong_bytes(CKO_SECRET_KEY);
    let kt = ck_ulong_bytes(key_type);
    let d: CK_BBOOL = if derive { CK_TRUE } else { CK_FALSE };
    let e: CK_BBOOL = if encrypt { CK_TRUE } else { CK_FALSE };
    // Note: secret keys default to CKA_SENSITIVE=true and it is one-way, so we
    // do not pass CKA_SENSITIVE=false here. The tests never read a key's value;
    // they compare keys via cross encrypt/decrypt, which works on sensitive keys.
    let mut tmpl = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_CLASS,
            p_value: class.as_ptr() as CK_VOID_PTR,
            value_len: class.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_KEY_TYPE,
            p_value: kt.as_ptr() as CK_VOID_PTR,
            value_len: kt.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_VALUE,
            p_value: value.as_ptr() as CK_VOID_PTR,
            value_len: value.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_DERIVE,
            p_value: &d as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_ENCRYPT,
            p_value: &e as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_DECRYPT,
            p_value: &e as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
    ];
    let mut handle = 0;
    let rv = C_CreateObject(
        session,
        tmpl.as_mut_ptr(),
        tmpl.len() as CK_ULONG,
        &mut handle,
    );
    assert_eq!(rv, CKR_OK, "C_CreateObject failed: 0x{:08X}", rv);
    handle
}

/// HKDF-derive a key via CKM_HKDF_DERIVE with a conforming CK_HKDF_PARAMS.
#[allow(clippy::too_many_arguments)]
fn hkdf_derive(
    session: CK_SESSION_HANDLE,
    base_key: CK_OBJECT_HANDLE,
    extract: bool,
    expand: bool,
    salt: &[u8],
    info: &[u8],
    out_key_type: CK_ULONG,
    out_len: CK_ULONG,
    encrypt: bool,
) -> CK_OBJECT_HANDLE {
    let mut params = CK_HKDF_PARAMS {
        b_extract: if extract { CK_TRUE } else { CK_FALSE },
        b_expand: if expand { CK_TRUE } else { CK_FALSE },
        prf_hash_mechanism: CKM_SHA256,
        ul_salt_type: if salt.is_empty() {
            CKF_HKDF_SALT_NULL
        } else {
            CKF_HKDF_SALT_DATA
        },
        p_salt: salt.as_ptr() as CK_BYTE_PTR,
        ul_salt_len: salt.len() as CK_ULONG,
        h_salt_key: 0,
        p_info: info.as_ptr() as CK_BYTE_PTR,
        ul_info_len: info.len() as CK_ULONG,
    };
    let mut mech = CK_MECHANISM {
        mechanism: CKM_HKDF_DERIVE,
        p_parameter: &mut params as *mut _ as CK_VOID_PTR,
        parameter_len: std::mem::size_of::<CK_HKDF_PARAMS>() as CK_ULONG,
    };
    let class = ck_ulong_bytes(CKO_SECRET_KEY);
    let kt = ck_ulong_bytes(out_key_type);
    let vl = ck_ulong_bytes(out_len);
    let e: CK_BBOOL = if encrypt { CK_TRUE } else { CK_FALSE };
    let mut tmpl = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_CLASS,
            p_value: class.as_ptr() as CK_VOID_PTR,
            value_len: class.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_KEY_TYPE,
            p_value: kt.as_ptr() as CK_VOID_PTR,
            value_len: kt.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_VALUE_LEN,
            p_value: vl.as_ptr() as CK_VOID_PTR,
            value_len: vl.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_ENCRYPT,
            p_value: &e as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_DECRYPT,
            p_value: &e as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
    ];
    let mut derived = 0;
    let rv = C_DeriveKey(
        session,
        &mut mech,
        base_key,
        tmpl.as_mut_ptr(),
        tmpl.len() as CK_ULONG,
        &mut derived,
    );
    assert_eq!(rv, CKR_OK, "C_DeriveKey(HKDF) failed: 0x{:08X}", rv);
    derived
}

fn gcm_encrypt(session: CK_SESSION_HANDLE, key: CK_OBJECT_HANDLE, iv: &[u8], pt: &[u8]) -> Vec<u8> {
    let mut mech = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: iv.as_ptr() as CK_VOID_PTR,
        parameter_len: iv.len() as CK_ULONG,
    };
    assert_eq!(C_EncryptInit(session, &mut mech, key), CKR_OK);
    let mut ct = vec![0u8; pt.len() + 32];
    let mut ct_len = ct.len() as CK_ULONG;
    assert_eq!(
        C_Encrypt(
            session,
            pt.as_ptr() as *mut _,
            pt.len() as CK_ULONG,
            ct.as_mut_ptr(),
            &mut ct_len
        ),
        CKR_OK
    );
    ct.truncate(ct_len as usize);
    ct
}

fn gcm_decrypt(
    session: CK_SESSION_HANDLE,
    key: CK_OBJECT_HANDLE,
    iv: &[u8],
    ct: &mut [u8],
) -> Option<Vec<u8>> {
    let mut mech = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: iv.as_ptr() as CK_VOID_PTR,
        parameter_len: iv.len() as CK_ULONG,
    };
    if C_DecryptInit(session, &mut mech, key) != CKR_OK {
        return None;
    }
    let mut pt = vec![0u8; ct.len()];
    let mut pt_len = pt.len() as CK_ULONG;
    if C_Decrypt(
        session,
        ct.as_mut_ptr(),
        ct.len() as CK_ULONG,
        pt.as_mut_ptr(),
        &mut pt_len,
    ) != CKR_OK
    {
        return None;
    }
    pt.truncate(pt_len as usize);
    Some(pt)
}

// RFC 5869 Appendix A.1 (SHA-256).
const RFC5869_IKM: [u8; 22] = [0x0b; 22];
const RFC5869_SALT: [u8; 13] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
];
const RFC5869_INFO: [u8; 10] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
/// First 32 bytes of the RFC 5869 A.1 OKM (the derived AES-256 key).
const RFC5869_OKM32: [u8; 32] = [
    0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
    0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
];

#[test]
fn test_hkdf_rfc5869_case1_kat_via_abi() {
    let session = setup_session(b"HkdfKat1");
    // IKM injected as a derivable, non-sensitive generic secret.
    let ikm_key = create_secret_key(session, CKK_GENERIC_SECRET, &RFC5869_IKM, true, false);

    // HKDF-derive an AES-256 key (first 32 bytes of the 42-byte RFC OKM stream).
    let derived = hkdf_derive(
        session,
        ikm_key,
        true,
        true,
        &RFC5869_SALT,
        &RFC5869_INFO,
        CKK_AES,
        32,
        true,
    );
    // Reference AES key built directly from the RFC OKM bytes.
    let reference = create_secret_key(session, CKK_AES, &RFC5869_OKM32, false, true);

    // Encrypt with the reference key, decrypt with the derived key: success proves
    // the HKDF-derived key equals the RFC known answer.
    let iv = [0x17u8; 12];
    let plaintext = b"hkdf rfc5869 kat probe";
    let mut ct = gcm_encrypt(session, reference, &iv, plaintext);
    let recovered = gcm_decrypt(session, derived, &iv, &mut ct)
        .expect("derived HKDF key must decrypt the reference key's ciphertext");
    assert_eq!(
        recovered, plaintext,
        "HKDF-derived AES key must match RFC 5869 A.1 OKM"
    );
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
}

#[test]
fn test_hkdf_generic_secret_output() {
    let session = setup_session(b"HkdfGen1");
    let ikm_key = create_secret_key(session, CKK_GENERIC_SECRET, &[0x2bu8; 32], true, false);

    // Derive a 48-byte generic secret (impossible under the old AES-only path).
    let derived = hkdf_derive(
        session,
        ikm_key,
        true,
        true,
        &[],
        b"context-A",
        CKK_GENERIC_SECRET,
        48,
        false,
    );
    let mut vl: CK_ULONG = 0;
    let mut tmpl = [CK_ATTRIBUTE {
        attr_type: CKA_VALUE_LEN,
        p_value: &mut vl as *mut _ as CK_VOID_PTR,
        value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
    }];
    assert_eq!(
        C_GetAttributeValue(session, derived, tmpl.as_mut_ptr(), 1),
        CKR_OK
    );
    assert_eq!(vl, 48, "HKDF generic secret must be 48 bytes");
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
}

#[test]
fn test_hkdf_different_info_differs() {
    let session = setup_session(b"HkdfInfo");
    let ikm_key = create_secret_key(session, CKK_GENERIC_SECRET, &[0x99u8; 32], true, false);

    let k1 = hkdf_derive(
        session,
        ikm_key,
        true,
        true,
        &[],
        b"info-1",
        CKK_AES,
        32,
        true,
    );
    let k2 = hkdf_derive(
        session,
        ikm_key,
        true,
        true,
        &[],
        b"info-2",
        CKK_AES,
        32,
        true,
    );

    // Different info => different keys: k1's ciphertext must NOT decrypt under k2.
    let iv = [0x31u8; 12];
    let mut ct = gcm_encrypt(session, k1, &iv, b"probe");
    assert!(
        gcm_decrypt(session, k2, &iv, &mut ct).is_none(),
        "different HKDF info must yield a different key"
    );
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
}
