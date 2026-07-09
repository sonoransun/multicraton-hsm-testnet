// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! End-to-end ABI tests for AES-GCM with caller-supplied CK_GCM_PARAMS.
//!
//! Verifies the PKCS#11-conformant GCM path: the caller supplies the IV, AAD,
//! and tag length via CK_GCM_PARAMS; the HSM returns bare `ciphertext || tag`
//! (no prepended nonce) and round-trips correctly, including for AES-128 and
//! AES-192 keys (previously advertised but unusable). Also verifies that the
//! legacy no-parameter path still works unchanged.
//!
//! Must run with --test-threads=1 (global PKCS#11 state).

use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm::pkcs11_abi::functions::*;
use craton_hsm::pkcs11_abi::types::*;
use std::ptr;

fn ck_ulong_bytes(val: CK_ULONG) -> Vec<u8> {
    val.to_ne_bytes().to_vec()
}

/// Initialize, init token, open RW session, log in as user.
fn setup_session() -> CK_SESSION_HANDLE {
    let rv = C_Initialize(ptr::null_mut());
    assert!(rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED);

    // PIN policy: >=8 bytes, >=3 distinct, >=2 char classes.
    let so_pin = b"SoPin1234";
    let mut label = [b' '; 32];
    label[..9].copy_from_slice(b"GcmToken1");
    let rv = C_InitToken(
        0,
        so_pin.as_ptr() as *mut _,
        so_pin.len() as CK_ULONG,
        label.as_ptr() as *mut _,
    );
    assert_eq!(rv, CKR_OK, "C_InitToken");

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

    let user_pin = b"UserPin1234";
    let rv = C_InitPIN(
        session,
        user_pin.as_ptr() as *mut _,
        user_pin.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_OK);
    assert_eq!(C_Logout(session), CKR_OK);
    let rv = C_Login(
        session,
        CKU_USER,
        user_pin.as_ptr() as *mut _,
        user_pin.len() as CK_ULONG,
    );
    assert_eq!(rv, CKR_OK);
    session
}

/// Generate an AES key of the given byte length.
fn generate_aes_key(session: CK_SESSION_HANDLE, key_len: CK_ULONG) -> CK_OBJECT_HANDLE {
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    let len_bytes = ck_ulong_bytes(key_len);
    let t: CK_BBOOL = CK_TRUE;
    let class = ck_ulong_bytes(CKO_SECRET_KEY);
    let key_type = ck_ulong_bytes(CKK_AES);
    let mut template = vec![
        CK_ATTRIBUTE {
            attr_type: CKA_CLASS,
            p_value: class.as_ptr() as CK_VOID_PTR,
            value_len: class.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_KEY_TYPE,
            p_value: key_type.as_ptr() as CK_VOID_PTR,
            value_len: key_type.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            attr_type: CKA_VALUE_LEN,
            p_value: len_bytes.as_ptr() as CK_VOID_PTR,
            value_len: len_bytes.len() as CK_ULONG,
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
    let mut key: CK_OBJECT_HANDLE = 0;
    let rv = C_GenerateKey(
        session,
        &mut mechanism,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut key,
    );
    assert_eq!(rv, CKR_OK, "C_GenerateKey (len {key_len})");
    key
}

/// Encrypt via CK_GCM_PARAMS. `iv`/`aad` must outlive the call.
fn gcm_encrypt(
    session: CK_SESSION_HANDLE,
    key: CK_OBJECT_HANDLE,
    iv: &[u8],
    aad: &[u8],
    tag_bits: CK_ULONG,
    pt: &[u8],
) -> Vec<u8> {
    let mut params = CK_GCM_PARAMS {
        p_iv: iv.as_ptr() as CK_BYTE_PTR,
        ul_iv_len: iv.len() as CK_ULONG,
        ul_iv_bits: (iv.len() * 8) as CK_ULONG,
        p_aad: if aad.is_empty() {
            ptr::null_mut()
        } else {
            aad.as_ptr() as CK_BYTE_PTR
        },
        ul_aad_len: aad.len() as CK_ULONG,
        ul_tag_bits: tag_bits,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: &mut params as *mut _ as CK_VOID_PTR,
        parameter_len: std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
    };
    assert_eq!(
        C_EncryptInit(session, &mut mechanism, key),
        CKR_OK,
        "GCM EncryptInit"
    );

    let mut out = vec![0u8; pt.len() + 16];
    let mut out_len = out.len() as CK_ULONG;
    let rv = C_Encrypt(
        session,
        pt.as_ptr() as CK_BYTE_PTR,
        pt.len() as CK_ULONG,
        out.as_mut_ptr(),
        &mut out_len,
    );
    assert_eq!(rv, CKR_OK, "GCM Encrypt");
    out.truncate(out_len as usize);
    out
}

/// Decrypt via CK_GCM_PARAMS. Returns the raw CK_RV and plaintext.
fn gcm_decrypt(
    session: CK_SESSION_HANDLE,
    key: CK_OBJECT_HANDLE,
    iv: &[u8],
    aad: &[u8],
    tag_bits: CK_ULONG,
    ct: &[u8],
) -> (CK_RV, Vec<u8>) {
    let mut params = CK_GCM_PARAMS {
        p_iv: iv.as_ptr() as CK_BYTE_PTR,
        ul_iv_len: iv.len() as CK_ULONG,
        ul_iv_bits: (iv.len() * 8) as CK_ULONG,
        p_aad: if aad.is_empty() {
            ptr::null_mut()
        } else {
            aad.as_ptr() as CK_BYTE_PTR
        },
        ul_aad_len: aad.len() as CK_ULONG,
        ul_tag_bits: tag_bits,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: &mut params as *mut _ as CK_VOID_PTR,
        parameter_len: std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
    };
    assert_eq!(
        C_DecryptInit(session, &mut mechanism, key),
        CKR_OK,
        "GCM DecryptInit"
    );

    let mut out = vec![0u8; ct.len() + 16];
    let mut out_len = out.len() as CK_ULONG;
    let rv = C_Decrypt(
        session,
        ct.as_ptr() as CK_BYTE_PTR,
        ct.len() as CK_ULONG,
        out.as_mut_ptr(),
        &mut out_len,
    );
    out.truncate(if rv == CKR_OK { out_len as usize } else { 0 });
    (rv, out)
}

#[test]
fn test_gcm_params_roundtrip_all_key_sizes() {
    let session = setup_session();
    let pt = b"post-quantum ready GCM payload";
    let aad = b"object-context";

    for &klen in &[16u64, 24, 32] {
        let key = generate_aes_key(session, klen as CK_ULONG);
        // Distinct IV per key to avoid the caller-IV reuse guard.
        let iv: Vec<u8> = (0..12).map(|i| (klen as u8) ^ i as u8).collect();

        let ct = gcm_encrypt(session, key, &iv, aad, 128, pt);
        // Conformant output: ciphertext(len == pt) + 16-byte tag, NO nonce prefix.
        assert_eq!(ct.len(), pt.len() + 16, "AES-{}-GCM ct length", klen * 8);

        let (rv, back) = gcm_decrypt(session, key, &iv, aad, 128, &ct);
        assert_eq!(rv, CKR_OK, "AES-{}-GCM decrypt", klen * 8);
        assert_eq!(&back, pt, "AES-{}-GCM roundtrip", klen * 8);
    }
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
}

#[test]
fn test_gcm_params_aad_tamper_detected() {
    let session = setup_session();
    let key = generate_aes_key(session, 32);
    let iv = [0x5Au8; 12];
    let pt = b"authenticated data test";

    let ct = gcm_encrypt(session, key, &iv, b"correct-aad", 128, pt);
    // Decrypt with the wrong AAD must fail authentication.
    let (rv, _) = gcm_decrypt(session, key, &iv, b"wrong-aad", 128, &ct);
    assert_eq!(rv, CKR_ENCRYPTED_DATA_INVALID, "AAD tamper must fail");

    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
}

#[test]
fn test_gcm_params_truncated_tag() {
    let session = setup_session();
    let key = generate_aes_key(session, 32);
    let iv = [0x11u8; 12];
    let pt = b"96-bit tag payload";

    let ct = gcm_encrypt(session, key, &iv, &[], 96, pt);
    assert_eq!(ct.len(), pt.len() + 12, "96-bit tag => 12 tag bytes");
    let (rv, back) = gcm_decrypt(session, key, &iv, &[], 96, &ct);
    assert_eq!(rv, CKR_OK);
    assert_eq!(&back, pt);

    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
}

#[test]
fn test_gcm_iv_reuse_rejected() {
    let session = setup_session();
    let key = generate_aes_key(session, 32);
    let iv = [0x77u8; 12];

    // First use of this (key, IV) succeeds.
    let _ = gcm_encrypt(session, key, &iv, &[], 128, b"first");

    // Second EncryptInit with the SAME IV must be rejected before any
    // catastrophic nonce reuse can occur.
    let mut params = CK_GCM_PARAMS {
        p_iv: iv.as_ptr() as CK_BYTE_PTR,
        ul_iv_len: iv.len() as CK_ULONG,
        ul_iv_bits: 96,
        p_aad: ptr::null_mut(),
        ul_aad_len: 0,
        ul_tag_bits: 128,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: &mut params as *mut _ as CK_VOID_PTR,
        parameter_len: std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
    };
    let rv = C_EncryptInit(session, &mut mechanism, key);
    assert_eq!(rv, CKR_MECHANISM_PARAM_INVALID, "IV reuse must be rejected");

    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
}

#[test]
fn test_gcm_legacy_no_params_still_works() {
    // With a null/empty parameter the HSM falls back to the legacy path:
    // it generates its own nonce and prepends it (nonce||ct||tag).
    let session = setup_session();
    let key = generate_aes_key(session, 32);
    let pt = b"legacy internal-nonce mode";

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    assert_eq!(C_EncryptInit(session, &mut mechanism, key), CKR_OK);
    let mut ct = vec![0u8; pt.len() + 28];
    let mut ct_len = ct.len() as CK_ULONG;
    assert_eq!(
        C_Encrypt(
            session,
            pt.as_ptr() as CK_BYTE_PTR,
            pt.len() as CK_ULONG,
            ct.as_mut_ptr(),
            &mut ct_len,
        ),
        CKR_OK
    );
    ct.truncate(ct_len as usize);
    // Legacy format prepends a 12-byte nonce + 16-byte tag.
    assert_eq!(ct.len(), pt.len() + 28);

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        p_parameter: ptr::null_mut(),
        parameter_len: 0,
    };
    assert_eq!(C_DecryptInit(session, &mut mechanism, key), CKR_OK);
    let mut back = vec![0u8; ct.len()];
    let mut back_len = back.len() as CK_ULONG;
    assert_eq!(
        C_Decrypt(
            session,
            ct.as_ptr() as CK_BYTE_PTR,
            ct.len() as CK_ULONG,
            back.as_mut_ptr(),
            &mut back_len,
        ),
        CKR_OK
    );
    back.truncate(back_len as usize);
    assert_eq!(&back, pt);

    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
}
