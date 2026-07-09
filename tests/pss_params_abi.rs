// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! End-to-end ABI tests for RSA-PSS parameter validation (Stage 1 conformance):
//! a consistent CK_RSA_PKCS_PSS_PARAMS is accepted (sign/verify roundtrip),
//! while inconsistent hash / MGF / salt length are rejected at C_SignInit
//! instead of silently ignored. A null parameter uses the FIPS default.
//!
//! One RSA-2048 keypair is reused across cases. Must run with --test-threads=1.

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
    label[..8].copy_from_slice(b"PssTok01");
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

fn gen_rsa_keypair(session: CK_SESSION_HANDLE) -> (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) {
    let mut mech = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let bits = ck_ulong_bytes(2048);
    let t: CK_BBOOL = CK_TRUE;
    let mut pub_tmpl = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_MODULUS_BITS,
            p_value: bits.as_ptr() as CK_VOID_PTR,
            value_len: bits.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_VERIFY,
            p_value: &t as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
    ];
    let mut priv_tmpl = vec![CK_ATTRIBUTE {
        attr_type: CKA_SIGN,
        p_value: &t as *const _ as CK_VOID_PTR,
        value_len: 1,
    }];
    let mut pub_key = 0;
    let mut priv_key = 0;
    assert_eq!(
        C_GenerateKeyPair(
            session,
            &mut mech,
            pub_tmpl.as_mut_ptr(),
            pub_tmpl.len() as CK_ULONG,
            priv_tmpl.as_mut_ptr(),
            priv_tmpl.len() as CK_ULONG,
            &mut pub_key,
            &mut priv_key,
        ),
        CKR_OK,
        "RSA-2048 keygen"
    );
    (pub_key, priv_key)
}

fn pss_mech(params: &mut CK_RSA_PKCS_PSS_PARAMS) -> CK_MECHANISM {
    CK_MECHANISM {
        mechanism: CKM_SHA256_RSA_PKCS_PSS,
        p_parameter: params as *mut _ as CK_VOID_PTR,
        parameter_len: std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() as CK_ULONG,
    }
}

/// C_SignInit with an explicit PSS param; returns the rv (for validation tests).
fn pss_sign_init_rv(
    session: CK_SESSION_HANDLE,
    priv_key: CK_OBJECT_HANDLE,
    hash: CK_ULONG,
    mgf: CK_ULONG,
    s_len: CK_ULONG,
) -> CK_RV {
    let mut params = CK_RSA_PKCS_PSS_PARAMS {
        hash_alg: hash,
        mgf,
        s_len,
    };
    let mut mech = pss_mech(&mut params);
    C_SignInit(session, &mut mech, priv_key)
}

#[test]
fn test_pss_params_validation() {
    let session = setup_session();
    let (pub_key, priv_key) = gen_rsa_keypair(session);
    let data = b"craton RSA-PSS params conformance";

    // (1) Consistent params (SHA-256 / MGF1-SHA256 / salt=32): sign + verify.
    let mut sp = CK_RSA_PKCS_PSS_PARAMS {
        hash_alg: CKM_SHA256,
        mgf: CKG_MGF1_SHA256,
        s_len: 32,
    };
    let mut sm = pss_mech(&mut sp);
    assert_eq!(
        C_SignInit(session, &mut sm, priv_key),
        CKR_OK,
        "valid PSS params SignInit"
    );
    let mut sig_len: CK_ULONG = 0;
    assert_eq!(
        C_Sign(
            session,
            data.as_ptr() as *mut _,
            data.len() as CK_ULONG,
            ptr::null_mut(),
            &mut sig_len
        ),
        CKR_OK
    );
    let mut sig = vec![0u8; sig_len as usize];
    assert_eq!(
        C_Sign(
            session,
            data.as_ptr() as *mut _,
            data.len() as CK_ULONG,
            sig.as_mut_ptr(),
            &mut sig_len
        ),
        CKR_OK
    );
    sig.truncate(sig_len as usize);

    let mut vp = CK_RSA_PKCS_PSS_PARAMS {
        hash_alg: CKM_SHA256,
        mgf: CKG_MGF1_SHA256,
        s_len: 32,
    };
    let mut vm = pss_mech(&mut vp);
    assert_eq!(
        C_VerifyInit(session, &mut vm, pub_key),
        CKR_OK,
        "valid PSS params VerifyInit"
    );
    assert_eq!(
        C_Verify(
            session,
            data.as_ptr() as *mut _,
            data.len() as CK_ULONG,
            sig.as_ptr() as *mut _,
            sig.len() as CK_ULONG,
        ),
        CKR_OK,
        "PSS signature with consistent params must verify"
    );

    // (2) Inconsistent hash (SHA-512 param on a SHA-256 mechanism) → rejected.
    assert_eq!(
        pss_sign_init_rv(session, priv_key, CKM_SHA512, CKG_MGF1_SHA256, 32),
        CKR_MECHANISM_PARAM_INVALID,
        "inconsistent PSS hash must be rejected"
    );
    // (3) Wrong MGF (MGF1-SHA384) → rejected.
    assert_eq!(
        pss_sign_init_rv(session, priv_key, CKM_SHA256, CKG_MGF1_SHA384, 32),
        CKR_MECHANISM_PARAM_INVALID,
        "inconsistent PSS MGF must be rejected"
    );
    // (4) Non-default salt length (48 != 32) → rejected.
    assert_eq!(
        pss_sign_init_rv(session, priv_key, CKM_SHA256, CKG_MGF1_SHA256, 48),
        CKR_MECHANISM_PARAM_INVALID,
        "non-default PSS salt length must be rejected"
    );

    // (5) Null parameter uses the FIPS default and still works.
    let mut null_mech = CK_MECHANISM {
        mechanism: CKM_SHA256_RSA_PKCS_PSS,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    assert_eq!(
        C_SignInit(session, &mut null_mech, priv_key),
        CKR_OK,
        "null PSS param uses the default"
    );
    let mut nlen: CK_ULONG = 0;
    assert_eq!(
        C_Sign(
            session,
            data.as_ptr() as *mut _,
            data.len() as CK_ULONG,
            ptr::null_mut(),
            &mut nlen
        ),
        CKR_OK
    );
    assert!(nlen > 0, "null-param PSS sign must produce a signature");

    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
}
