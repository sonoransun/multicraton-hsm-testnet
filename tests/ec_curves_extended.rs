// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! End-to-end ABI tests for the extended elliptic curves wired in Stage 1:
//! P-521 and secp256k1 ECDSA (via `CKM_EC_KEY_PAIR_GEN` + `CKA_EC_PARAMS`),
//! and X25519 key generation (via `CKM_EC_MONTGOMERY_KEY_PAIR_GEN`).
//!
//! X25519 *derivation* is covered separately in `key_derivation_abi.rs`; here we
//! only assert that a Montgomery key pair can be generated.
//!
//! Must run with --test-threads=1 (global PKCS#11 state).

use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm::pkcs11_abi::functions::*;
use craton_hsm::pkcs11_abi::types::*;
use std::ptr;

/// DER-encoded OID for NIST P-521 (secp521r1), 1.3.132.0.35.
const P521_OID: [u8; 7] = [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23];
/// DER-encoded OID for secp256k1, 1.3.132.0.10.
const SECP256K1_OID: [u8; 7] = [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A];
/// DER-encoded OID for X25519, 1.3.101.110 (RFC 8410).
const X25519_OID: [u8; 5] = [0x06, 0x03, 0x2B, 0x65, 0x6E];

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

/// Generate a Weierstrass EC key pair for the given curve OID.
fn gen_ec_keypair(session: CK_SESSION_HANDLE, oid: &[u8]) -> (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) {
    let mut mech = CK_MECHANISM {
        mechanism: CKM_EC_KEY_PAIR_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let t: CK_BBOOL = CK_TRUE;
    let mut pub_tmpl = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_EC_PARAMS,
            p_value: oid.as_ptr() as CK_VOID_PTR,
            value_len: oid.len() as CK_ULONG,
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
        "EC keygen for OID {:02x?}",
        oid
    );
    (pub_key, priv_key)
}

fn ecdsa_sign(
    session: CK_SESSION_HANDLE,
    mech_type: CK_MECHANISM_TYPE,
    priv_key: CK_OBJECT_HANDLE,
    data: &[u8],
) -> Vec<u8> {
    let mut mech = CK_MECHANISM {
        mechanism: mech_type,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    assert_eq!(C_SignInit(session, &mut mech, priv_key), CKR_OK, "SignInit");
    let mut sig_len: CK_ULONG = 0;
    assert_eq!(
        C_Sign(
            session,
            data.as_ptr() as *mut _,
            data.len() as CK_ULONG,
            ptr::null_mut(),
            &mut sig_len
        ),
        CKR_OK,
        "Sign length query"
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
        CKR_OK,
        "Sign"
    );
    sig.truncate(sig_len as usize);
    sig
}

fn ecdsa_verify(
    session: CK_SESSION_HANDLE,
    mech_type: CK_MECHANISM_TYPE,
    pub_key: CK_OBJECT_HANDLE,
    data: &[u8],
    sig: &[u8],
) -> CK_RV {
    let mut mech = CK_MECHANISM {
        mechanism: mech_type,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    assert_eq!(
        C_VerifyInit(session, &mut mech, pub_key),
        CKR_OK,
        "VerifyInit"
    );
    C_Verify(
        session,
        data.as_ptr() as *mut _,
        data.len() as CK_ULONG,
        sig.as_ptr() as *mut _,
        sig.len() as CK_ULONG,
    )
}

#[test]
fn test_p521_ecdsa_sign_verify() {
    let session = setup_session(b"P521Tok1");
    let (pub_key, priv_key) = gen_ec_keypair(session, &P521_OID);
    let data = b"craton p-521 end-to-end ECDSA over the PKCS#11 ABI";

    // P-521 requires a >= 33-byte prehash, so use SHA-512.
    let sig = ecdsa_sign(session, CKM_ECDSA_SHA512, priv_key, data);
    assert!(!sig.is_empty(), "P-521 signature must be non-empty");
    assert_eq!(
        ecdsa_verify(session, CKM_ECDSA_SHA512, pub_key, data, &sig),
        CKR_OK,
        "valid P-521 signature must verify"
    );

    // Tampered signature must be rejected.
    let mut bad = sig.clone();
    let last = bad.len() - 1;
    bad[last] ^= 0x01;
    assert_eq!(
        ecdsa_verify(session, CKM_ECDSA_SHA512, pub_key, data, &bad),
        CKR_SIGNATURE_INVALID,
        "tampered P-521 signature must be rejected"
    );
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
}

#[test]
fn test_secp256k1_ecdsa_sign_verify() {
    let session = setup_session(b"Secp256k");
    let (pub_key, priv_key) = gen_ec_keypair(session, &SECP256K1_OID);
    let data = b"craton secp256k1 end-to-end ECDSA over the PKCS#11 ABI";

    let sig = ecdsa_sign(session, CKM_ECDSA_SHA256, priv_key, data);
    assert!(!sig.is_empty(), "secp256k1 signature must be non-empty");
    assert_eq!(
        ecdsa_verify(session, CKM_ECDSA_SHA256, pub_key, data, &sig),
        CKR_OK,
        "valid secp256k1 signature must verify"
    );

    // A signature under a different key must not verify.
    let (other_pub, _other_priv) = gen_ec_keypair(session, &SECP256K1_OID);
    assert_eq!(
        ecdsa_verify(session, CKM_ECDSA_SHA256, other_pub, data, &sig),
        CKR_SIGNATURE_INVALID,
        "secp256k1 signature must not verify under a different key"
    );
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
}

#[test]
fn test_x25519_keygen() {
    let session = setup_session(b"X25519Tk");
    let t: CK_BBOOL = CK_TRUE;
    let mut mech = CK_MECHANISM {
        mechanism: CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let mut pub_tmpl = vec![CK_ATTRIBUTE {
        attr_type: CKA_EC_PARAMS,
        p_value: X25519_OID.as_ptr() as CK_VOID_PTR,
        value_len: X25519_OID.len() as CK_ULONG,
    }];
    let mut priv_tmpl = vec![CK_ATTRIBUTE {
        attr_type: CKA_DERIVE,
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
        "X25519 keygen via CKM_EC_MONTGOMERY_KEY_PAIR_GEN"
    );

    // The public key type must be CKK_EC_MONTGOMERY.
    let mut kt: CK_ULONG = 0;
    let mut tmpl = [CK_ATTRIBUTE {
        attr_type: CKA_KEY_TYPE,
        p_value: &mut kt as *mut _ as CK_VOID_PTR,
        value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
    }];
    assert_eq!(
        C_GetAttributeValue(session, priv_key, tmpl.as_mut_ptr(), 1),
        CKR_OK
    );
    assert_eq!(
        kt, CKK_EC_MONTGOMERY,
        "X25519 key type must be CKK_EC_MONTGOMERY"
    );
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
}
