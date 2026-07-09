// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! End-to-end ABI tests for the rewritten ECDH derive path (Stage 1e):
//! conforming `CK_ECDH1_DERIVE_PARAMS`, genuine two-party key agreement
//! (priv_A+pub_B == priv_B+pub_A), CKD_NULL vs CKD_SHA256_KDF, X25519 ECDH,
//! and CKK_GENERIC_SECRET output.
//!
//! Each test does all its derivations on a single session to keep the
//! per-test token-init / PBKDF2 cost down. Must run with --test-threads=1.

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

const P256_OID: [u8; 10] = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const X25519_OID: [u8; 5] = [0x06, 0x03, 0x2B, 0x65, 0x6E];

/// Generate a Weierstrass EC key pair (derive-enabled) for the given OID.
fn gen_ec_keypair(session: CK_SESSION_HANDLE, oid: &[u8]) -> (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) {
    let mut mech = CK_MECHANISM {
        mechanism: CKM_EC_KEY_PAIR_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let t: CK_BBOOL = CK_TRUE;
    let mut pub_tmpl = vec![CK_ATTRIBUTE {
        attr_type: CKA_EC_PARAMS,
        p_value: oid.as_ptr() as CK_VOID_PTR,
        value_len: oid.len() as CK_ULONG,
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
        "EC keygen OID {:02x?}",
        oid
    );
    (pub_key, priv_key)
}

fn gen_x25519_keypair(session: CK_SESSION_HANDLE) -> (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) {
    let mut mech = CK_MECHANISM {
        mechanism: CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let t: CK_BBOOL = CK_TRUE;
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
        "X25519 keygen"
    );
    (pub_key, priv_key)
}

fn read_ec_point(session: CK_SESSION_HANDLE, pub_key: CK_OBJECT_HANDLE) -> Vec<u8> {
    let mut tmpl = [CK_ATTRIBUTE {
        attr_type: CKA_EC_POINT,
        p_value: ptr::null_mut(),
        value_len: 0,
    }];
    assert_eq!(
        C_GetAttributeValue(session, pub_key, tmpl.as_mut_ptr(), 1),
        CKR_OK
    );
    let size = tmpl[0].value_len as usize;
    let mut buf = vec![0u8; size];
    tmpl[0].p_value = buf.as_mut_ptr() as CK_VOID_PTR;
    tmpl[0].value_len = size as CK_ULONG;
    assert_eq!(
        C_GetAttributeValue(session, pub_key, tmpl.as_mut_ptr(), 1),
        CKR_OK
    );
    buf.truncate(tmpl[0].value_len as usize);
    buf
}

/// Derive a secret key via CKM_ECDH1_DERIVE using a conforming
/// CK_ECDH1_DERIVE_PARAMS struct.
fn derive_ecdh_params(
    session: CK_SESSION_HANDLE,
    base_priv: CK_OBJECT_HANDLE,
    peer_point: &[u8],
    kdf: CK_ULONG,
    key_type: CK_ULONG,
    value_len: CK_ULONG,
) -> CK_OBJECT_HANDLE {
    let mut params = CK_ECDH1_DERIVE_PARAMS {
        kdf,
        ul_shared_data_len: 0,
        p_shared_data: ptr::null_mut(),
        ul_public_data_len: peer_point.len() as CK_ULONG,
        p_public_data: peer_point.as_ptr() as CK_BYTE_PTR,
    };
    let mut mech = CK_MECHANISM {
        mechanism: CKM_ECDH1_DERIVE,
        p_parameter: &mut params as *mut _ as CK_VOID_PTR,
        parameter_len: std::mem::size_of::<CK_ECDH1_DERIVE_PARAMS>() as CK_ULONG,
    };
    let t: CK_BBOOL = CK_TRUE;
    let class = ck_ulong_bytes(CKO_SECRET_KEY);
    let kt = ck_ulong_bytes(key_type);
    let vl = ck_ulong_bytes(value_len);
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
            p_value: &t as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_DECRYPT,
            p_value: &t as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
    ];
    let mut derived = 0;
    let rv = C_DeriveKey(
        session,
        &mut mech,
        base_priv,
        tmpl.as_mut_ptr(),
        tmpl.len() as CK_ULONG,
        &mut derived,
    );
    assert_eq!(rv, CKR_OK, "C_DeriveKey (kdf={:#x}) failed", kdf);
    derived
}

/// Read a secret key's CKA_VALUE (only valid when non-sensitive / extractable
/// is not enforced — here we compare via encrypt/decrypt instead).
fn same_key_via_gcm(
    session: CK_SESSION_HANDLE,
    enc_key: CK_OBJECT_HANDLE,
    dec_key: CK_OBJECT_HANDLE,
) -> bool {
    let plaintext = b"two-party ecdh agreement probe";
    let iv = [0x24u8; 12];
    let mut mech = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: iv.as_ptr() as CK_VOID_PTR,
        parameter_len: iv.len() as CK_ULONG,
    };
    if C_EncryptInit(session, &mut mech, enc_key) != CKR_OK {
        return false;
    }
    let mut ct = vec![0u8; plaintext.len() + 32];
    let mut ct_len = ct.len() as CK_ULONG;
    if C_Encrypt(
        session,
        plaintext.as_ptr() as *mut _,
        plaintext.len() as CK_ULONG,
        ct.as_mut_ptr(),
        &mut ct_len,
    ) != CKR_OK
    {
        return false;
    }
    if C_DecryptInit(session, &mut mech, dec_key) != CKR_OK {
        return false;
    }
    let mut pt = vec![0u8; plaintext.len() + 32];
    let mut pt_len = pt.len() as CK_ULONG;
    if C_Decrypt(
        session,
        ct.as_mut_ptr(),
        ct_len,
        pt.as_mut_ptr(),
        &mut pt_len,
    ) != CKR_OK
    {
        return false;
    }
    &pt[..pt_len as usize] == plaintext
}

#[test]
fn test_ecdh_two_party_agreement_conforming_params() {
    let session = setup_session(b"EcdhTwo1");
    let (pub_a, priv_a) = gen_ec_keypair(session, &P256_OID);
    let (pub_b, priv_b) = gen_ec_keypair(session, &P256_OID);
    let point_a = read_ec_point(session, pub_a);
    let point_b = read_ec_point(session, pub_b);

    // A derives with B's point; B derives with A's point. With the raw-Z (CKD_NULL)
    // fix these MUST be the same key — the party-asymmetric HKDF path failed this.
    let key_ab = derive_ecdh_params(session, priv_a, &point_b, CKD_NULL, CKK_AES, 32);
    let key_ba = derive_ecdh_params(session, priv_b, &point_a, CKD_NULL, CKK_AES, 32);
    assert!(
        same_key_via_gcm(session, key_ab, key_ba),
        "two-party ECDH must derive the same key (priv_A+pub_B == priv_B+pub_A)"
    );
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
}

#[test]
fn test_ecdh_x963_kdf_two_party() {
    let session = setup_session(b"EcdhX963");
    let (pub_a, priv_a) = gen_ec_keypair(session, &P256_OID);
    let (pub_b, priv_b) = gen_ec_keypair(session, &P256_OID);
    let point_a = read_ec_point(session, pub_a);
    let point_b = read_ec_point(session, pub_b);

    // CKD_SHA256_KDF (ANSI X9.63) must also agree between the two parties.
    let key_ab = derive_ecdh_params(session, priv_a, &point_b, CKD_SHA256_KDF, CKK_AES, 32);
    let key_ba = derive_ecdh_params(session, priv_b, &point_a, CKD_SHA256_KDF, CKK_AES, 32);
    assert!(
        same_key_via_gcm(session, key_ab, key_ba),
        "X9.63 KDF two-party derivation must agree"
    );
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
}

#[test]
fn test_x25519_ecdh_two_party() {
    let session = setup_session(b"X25519Dh");
    let (pub_a, priv_a) = gen_x25519_keypair(session);
    let (pub_b, priv_b) = gen_x25519_keypair(session);
    let point_a = read_ec_point(session, pub_a);
    let point_b = read_ec_point(session, pub_b);

    let key_ab = derive_ecdh_params(session, priv_a, &point_b, CKD_NULL, CKK_AES, 32);
    let key_ba = derive_ecdh_params(session, priv_b, &point_a, CKD_NULL, CKK_AES, 32);
    assert!(
        same_key_via_gcm(session, key_ab, key_ba),
        "X25519 two-party ECDH must derive the same key"
    );
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
}

#[test]
fn test_ecdh_generic_secret_output() {
    let session = setup_session(b"EcdhGen1");
    let (_pub_a, priv_a) = gen_ec_keypair(session, &P256_OID);
    let (pub_b, _priv_b) = gen_ec_keypair(session, &P256_OID);
    let point_b = read_ec_point(session, pub_b);

    // Derive a 48-byte generic secret via X9.63 (was impossible under the old
    // AES-only 16/24/32 constraint).
    let derived = derive_ecdh_params(
        session,
        priv_a,
        &point_b,
        CKD_SHA384_KDF,
        CKK_GENERIC_SECRET,
        48,
    );
    let mut kt: CK_ULONG = 0;
    let mut tmpl = [CK_ATTRIBUTE {
        attr_type: CKA_KEY_TYPE,
        p_value: &mut kt as *mut _ as CK_VOID_PTR,
        value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
    }];
    assert_eq!(
        C_GetAttributeValue(session, derived, tmpl.as_mut_ptr(), 1),
        CKR_OK
    );
    assert_eq!(
        kt, CKK_GENERIC_SECRET,
        "derived key type must be generic secret"
    );

    let mut vl: CK_ULONG = 0;
    let mut tmpl2 = [CK_ATTRIBUTE {
        attr_type: CKA_VALUE_LEN,
        p_value: &mut vl as *mut _ as CK_VOID_PTR,
        value_len: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
    }];
    assert_eq!(
        C_GetAttributeValue(session, derived, tmpl2.as_mut_ptr(), 1),
        CKR_OK
    );
    assert_eq!(vl, 48, "derived generic secret must be 48 bytes");
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
}
