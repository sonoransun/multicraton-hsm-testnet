// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! End-to-end ABI tests for HMAC signing (CKM_SHA*_HMAC) and generic-secret
//! key generation (CKM_GENERIC_SECRET_KEY_GEN).
//!
//! Must run with --test-threads=1 (global PKCS#11 state).

use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm::pkcs11_abi::functions::*;
use craton_hsm::pkcs11_abi::types::*;
use std::ptr;

fn ck_ulong_bytes(v: CK_ULONG) -> Vec<u8> {
    v.to_ne_bytes().to_vec()
}

fn setup_session() -> CK_SESSION_HANDLE {
    let rv = C_Initialize(ptr::null_mut());
    assert!(rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED);
    let so_pin = b"SoPin1234";
    let mut label = [b' '; 32];
    label[..8].copy_from_slice(b"HmacTok1");
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

/// Generate a generic-secret key for HMAC (CKA_SIGN + CKA_VERIFY).
fn generate_hmac_key(session: CK_SESSION_HANDLE, len: CK_ULONG) -> CK_OBJECT_HANDLE {
    let mut mech = CK_MECHANISM {
        mechanism: CKM_GENERIC_SECRET_KEY_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let len_b = ck_ulong_bytes(len);
    let class = ck_ulong_bytes(CKO_SECRET_KEY);
    let kt = ck_ulong_bytes(CKK_GENERIC_SECRET);
    let t: CK_BBOOL = CK_TRUE;
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
            p_value: len_b.as_ptr() as CK_VOID_PTR,
            value_len: len_b.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_SIGN,
            p_value: &t as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_VERIFY,
            p_value: &t as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
    ];
    let mut key = 0;
    assert_eq!(
        C_GenerateKey(
            session,
            &mut mech,
            tmpl.as_mut_ptr(),
            tmpl.len() as CK_ULONG,
            &mut key
        ),
        CKR_OK,
        "generic-secret keygen"
    );
    key
}

fn hmac_sign(
    session: CK_SESSION_HANDLE,
    mech_type: CK_MECHANISM_TYPE,
    key: CK_OBJECT_HANDLE,
    data: &[u8],
) -> Vec<u8> {
    let mut mech = CK_MECHANISM {
        mechanism: mech_type,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    assert_eq!(C_SignInit(session, &mut mech, key), CKR_OK, "HMAC SignInit");
    // Two-call: query length first.
    let mut mac_len: CK_ULONG = 0;
    assert_eq!(
        C_Sign(
            session,
            data.as_ptr() as *mut _,
            data.len() as CK_ULONG,
            ptr::null_mut(),
            &mut mac_len
        ),
        CKR_OK
    );
    let mut mac = vec![0u8; mac_len as usize];
    assert_eq!(
        C_Sign(
            session,
            data.as_ptr() as *mut _,
            data.len() as CK_ULONG,
            mac.as_mut_ptr(),
            &mut mac_len
        ),
        CKR_OK,
        "HMAC Sign"
    );
    mac.truncate(mac_len as usize);
    mac
}

fn hmac_verify(
    session: CK_SESSION_HANDLE,
    mech_type: CK_MECHANISM_TYPE,
    key: CK_OBJECT_HANDLE,
    data: &[u8],
    mac: &[u8],
) -> CK_RV {
    let mut mech = CK_MECHANISM {
        mechanism: mech_type,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    assert_eq!(
        C_VerifyInit(session, &mut mech, key),
        CKR_OK,
        "HMAC VerifyInit"
    );
    C_Verify(
        session,
        data.as_ptr() as *mut _,
        data.len() as CK_ULONG,
        mac.as_ptr() as *mut _,
        mac.len() as CK_ULONG,
    )
}

#[test]
fn test_hmac_sign_verify_all_hashes() {
    let session = setup_session();
    let key = generate_hmac_key(session, 32);
    let data = b"HMAC end-to-end through the PKCS#11 ABI";

    for (mech, len) in [
        (CKM_SHA224_HMAC, 28usize),
        (CKM_SHA256_HMAC, 32),
        (CKM_SHA384_HMAC, 48),
        (CKM_SHA512_HMAC, 64),
    ] {
        let mac = hmac_sign(session, mech, key, data);
        assert_eq!(mac.len(), len, "HMAC output length for mech {:#x}", mech);
        assert_eq!(
            hmac_verify(session, mech, key, data, &mac),
            CKR_OK,
            "verify mech {:#x}",
            mech
        );

        // Tampered MAC must be rejected.
        let mut bad = mac.clone();
        bad[0] ^= 0xFF;
        assert_eq!(
            hmac_verify(session, mech, key, data, &bad),
            CKR_SIGNATURE_INVALID,
            "tampered MAC must fail for mech {:#x}",
            mech
        );
    }
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
}

#[test]
fn test_hmac_wrong_key_fails() {
    let session = setup_session();
    let key_a = generate_hmac_key(session, 32);
    let key_b = generate_hmac_key(session, 32);
    let data = b"context";
    let mac = hmac_sign(session, CKM_SHA256_HMAC, key_a, data);
    assert_eq!(
        hmac_verify(session, CKM_SHA256_HMAC, key_b, data, &mac),
        CKR_SIGNATURE_INVALID,
        "MAC under a different key must not verify"
    );
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
}

#[test]
fn test_generic_secret_below_hmac_floor_rejected() {
    // 13-byte key is below the SP 800-107 112-bit (14-byte) HMAC floor.
    let session = setup_session();
    let mut mech = CK_MECHANISM {
        mechanism: CKM_GENERIC_SECRET_KEY_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let len_b = ck_ulong_bytes(13);
    let class = ck_ulong_bytes(CKO_SECRET_KEY);
    let kt = ck_ulong_bytes(CKK_GENERIC_SECRET);
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
            p_value: len_b.as_ptr() as CK_VOID_PTR,
            value_len: len_b.len() as CK_ULONG,
        },
    ];
    let mut key = 0;
    let rv = C_GenerateKey(
        session,
        &mut mech,
        tmpl.as_mut_ptr(),
        tmpl.len() as CK_ULONG,
        &mut key,
    );
    assert_eq!(rv, CKR_KEY_SIZE_RANGE, "13-byte HMAC key must be rejected");
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
}
