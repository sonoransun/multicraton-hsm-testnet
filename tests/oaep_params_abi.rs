// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! End-to-end ABI tests for RSA-OAEP parameter handling (Stage 1 conformance):
//! full CK_RSA_PKCS_OAEP_PARAMS with label + MGF, MGF differing from the OAEP
//! hash, SHA-384 OAEP, and the legacy bare-hashAlg parameter (backward compat).
//!
//! One RSA-2048 keypair is generated and reused across all cases (RSA keygen is
//! the dominant cost in debug builds). Must run with --test-threads=1.

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
    label[..8].copy_from_slice(b"OaepTok1");
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
            attr_type: CKA_ENCRYPT,
            p_value: &t as *const _ as CK_VOID_PTR,
            value_len: 1,
        },
    ];
    let mut priv_tmpl = vec![CK_ATTRIBUTE {
        attr_type: CKA_DECRYPT,
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

fn oaep_mech(params: &mut CK_RSA_PKCS_OAEP_PARAMS, full: bool, hash_only: &[u8]) -> CK_MECHANISM {
    if full {
        CK_MECHANISM {
            mechanism: CKM_RSA_PKCS_OAEP,
            p_parameter: params as *mut _ as CK_VOID_PTR,
            parameter_len: std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>() as CK_ULONG,
        }
    } else {
        // Legacy: bare hashAlg ulong.
        CK_MECHANISM {
            mechanism: CKM_RSA_PKCS_OAEP,
            p_parameter: hash_only.as_ptr() as CK_VOID_PTR,
            parameter_len: hash_only.len() as CK_ULONG,
        }
    }
}

fn make_params(hash: CK_ULONG, mgf: CK_ULONG, label: &[u8]) -> CK_RSA_PKCS_OAEP_PARAMS {
    CK_RSA_PKCS_OAEP_PARAMS {
        hash_alg: hash,
        mgf,
        source: if label.is_empty() {
            0
        } else {
            CKZ_DATA_SPECIFIED
        },
        p_source_data: if label.is_empty() {
            ptr::null_mut()
        } else {
            label.as_ptr() as CK_VOID_PTR
        },
        ul_source_data_len: label.len() as CK_ULONG,
    }
}

fn oaep_encrypt(
    session: CK_SESSION_HANDLE,
    mech: &mut CK_MECHANISM,
    pub_key: CK_OBJECT_HANDLE,
    pt: &[u8],
) -> Vec<u8> {
    let ei = C_EncryptInit(session, mech, pub_key);
    assert_eq!(ei, CKR_OK, "OAEP EncryptInit rv=0x{:08X}", ei);
    let mut ct_len: CK_ULONG = 0;
    let q = C_Encrypt(
        session,
        pt.as_ptr() as *mut _,
        pt.len() as CK_ULONG,
        ptr::null_mut(),
        &mut ct_len,
    );
    assert_eq!(q, CKR_OK, "OAEP Encrypt length-query rv=0x{:08X}", q);
    let mut ct = vec![0u8; ct_len as usize];
    assert_eq!(
        C_Encrypt(
            session,
            pt.as_ptr() as *mut _,
            pt.len() as CK_ULONG,
            ct.as_mut_ptr(),
            &mut ct_len
        ),
        CKR_OK,
        "OAEP Encrypt"
    );
    ct.truncate(ct_len as usize);
    ct
}

/// Returns Some(plaintext) on success, None if decrypt fails (e.g. wrong label).
fn oaep_decrypt(
    session: CK_SESSION_HANDLE,
    mech: &mut CK_MECHANISM,
    priv_key: CK_OBJECT_HANDLE,
    ct: &[u8],
) -> Option<Vec<u8>> {
    if C_DecryptInit(session, mech, priv_key) != CKR_OK {
        return None;
    }
    let mut pt = vec![0u8; ct.len()];
    let mut pt_len: CK_ULONG = pt.len() as CK_ULONG;
    let mut ct_buf = ct.to_vec();
    if C_Decrypt(
        session,
        ct_buf.as_mut_ptr(),
        ct_buf.len() as CK_ULONG,
        pt.as_mut_ptr(),
        &mut pt_len,
    ) != CKR_OK
    {
        return None;
    }
    pt.truncate(pt_len as usize);
    Some(pt)
}

#[test]
fn test_oaep_params_end_to_end() {
    let session = setup_session();
    let (pub_key, priv_key) = gen_rsa_keypair(session);
    let plaintext = b"craton OAEP params conformance";

    // (1) SHA-256 with a label — roundtrip.
    let label = b"context-label-A";
    let mut p_enc = make_params(CKM_SHA256, CKG_MGF1_SHA256, label);
    let mut m_enc = oaep_mech(&mut p_enc, true, &[]);
    let ct = oaep_encrypt(session, &mut m_enc, pub_key, plaintext);

    let mut p_dec = make_params(CKM_SHA256, CKG_MGF1_SHA256, label);
    let mut m_dec = oaep_mech(&mut p_dec, true, &[]);
    let recovered = oaep_decrypt(session, &mut m_dec, priv_key, &ct)
        .expect("OAEP decrypt with matching label must succeed");
    assert_eq!(recovered, plaintext, "OAEP label roundtrip");

    // (2) Decrypt the same ciphertext with the WRONG label — must fail.
    let wrong = b"context-label-B";
    let mut p_wrong = make_params(CKM_SHA256, CKG_MGF1_SHA256, wrong);
    let mut m_wrong = oaep_mech(&mut p_wrong, true, &[]);
    assert!(
        oaep_decrypt(session, &mut m_wrong, priv_key, &ct).is_none(),
        "OAEP decrypt with a different label must fail"
    );

    // (3) MGF hash differing from the OAEP hash (SHA-256 hash, SHA-384 MGF).
    let mut p_enc2 = make_params(CKM_SHA256, CKG_MGF1_SHA384, &[]);
    let mut m_enc2 = oaep_mech(&mut p_enc2, true, &[]);
    let ct2 = oaep_encrypt(session, &mut m_enc2, pub_key, plaintext);
    let mut p_dec2 = make_params(CKM_SHA256, CKG_MGF1_SHA384, &[]);
    let mut m_dec2 = oaep_mech(&mut p_dec2, true, &[]);
    assert_eq!(
        oaep_decrypt(session, &mut m_dec2, priv_key, &ct2).as_deref(),
        Some(&plaintext[..]),
        "OAEP with MGF != hash must roundtrip"
    );

    // (4) SHA-384 OAEP (hash and MGF both SHA-384).
    let mut p_enc3 = make_params(CKM_SHA384, CKG_MGF1_SHA384, &[]);
    let mut m_enc3 = oaep_mech(&mut p_enc3, true, &[]);
    let ct3 = oaep_encrypt(session, &mut m_enc3, pub_key, plaintext);
    let mut p_dec3 = make_params(CKM_SHA384, CKG_MGF1_SHA384, &[]);
    let mut m_dec3 = oaep_mech(&mut p_dec3, true, &[]);
    assert_eq!(
        oaep_decrypt(session, &mut m_dec3, priv_key, &ct3).as_deref(),
        Some(&plaintext[..]),
        "SHA-384 OAEP must roundtrip"
    );

    // (5) Legacy bare-hashAlg parameter (backward compatibility).
    let hash_only = ck_ulong_bytes(CKM_SHA256);
    let mut dummy = make_params(CKM_SHA256, CKG_MGF1_SHA256, &[]);
    let mut m_legacy_enc = oaep_mech(&mut dummy, false, &hash_only);
    let ct4 = oaep_encrypt(session, &mut m_legacy_enc, pub_key, plaintext);
    let mut m_legacy_dec = oaep_mech(&mut dummy, false, &hash_only);
    assert_eq!(
        oaep_decrypt(session, &mut m_legacy_dec, priv_key, &ct4).as_deref(),
        Some(&plaintext[..]),
        "legacy bare-hash OAEP must still roundtrip"
    );

    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
}
