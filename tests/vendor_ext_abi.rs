// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Integration tests for the PKCS#11 vendor extension surface.
//! Runs only when the `vendor-ext` feature is enabled.

#![cfg(feature = "vendor-ext")]

use craton_hsm::pkcs11_abi::ext::vendor_table::{
    ext_function_list, CratonPQCCaps, CK_CRATON_EXT_FUNCTION_LIST,
};
use craton_hsm::pkcs11_abi::types::CK_INTERFACE;

#[test]
fn vendor_function_list_has_all_entries() {
    let list: &CK_CRATON_EXT_FUNCTION_LIST = ext_function_list();
    assert_eq!(list.version.major, 1);
    assert_eq!(list.version.minor, 0);
    // Fn pointers are non-null by construction (static initialisers).
    // This is effectively a smoke test that the struct laid out correctly.
}

#[test]
fn get_pqc_capabilities_reports_expected_variants() {
    // Need an initialised HsmCore so the vendor call can fetch one.
    use craton_hsm::pkcs11_abi::functions::*;
    let rv = C_Initialize(std::ptr::null_mut());
    assert_eq!(rv, craton_hsm::pkcs11_abi::constants::CKR_OK);

    let list = ext_function_list();
    let mut caps = CratonPQCCaps {
        enable_pqc: 0,
        fips_approved_only: 0,
        vendor_ext_available: 0,
        hybrid_kem_wrap_available: 0,
        ml_kem_count: 0,
        ml_kem_names: std::ptr::null(),
        ml_dsa_count: 0,
        ml_dsa_names: std::ptr::null(),
        slh_dsa_count: 0,
        slh_dsa_names: std::ptr::null(),
        falcon_count: 0,
        falcon_names: std::ptr::null(),
        frodokem_count: 0,
        frodokem_names: std::ptr::null(),
        hybrid_kem_count: 0,
        hybrid_kem_names: std::ptr::null(),
        composite_sig_count: 0,
        composite_sig_names: std::ptr::null(),
    };

    let rv = (list.GetPQCCapabilities)(&mut caps as *mut _);
    assert_eq!(rv, craton_hsm::pkcs11_abi::constants::CKR_OK);

    // Default build always has ML-KEM/ML-DSA/SLH-DSA.
    assert_eq!(caps.ml_kem_count, 3);
    assert_eq!(caps.ml_dsa_count, 3);
    assert_eq!(caps.slh_dsa_count, 12);
    assert_eq!(caps.vendor_ext_available, 1);
    assert_eq!(caps.composite_sig_count, 2);

    let _ = C_Finalize(std::ptr::null_mut());
}

#[test]
fn interface_list_reports_three_interfaces() {
    use craton_hsm::pkcs11_abi::ext::interface_list::C_GetInterfaceList;
    use craton_hsm::pkcs11_abi::constants::CKR_OK;

    // Size-probe first.
    let mut count: craton_hsm::pkcs11_abi::types::CK_ULONG = 0;
    let rv = C_GetInterfaceList(std::ptr::null_mut(), &mut count as *mut _);
    assert_eq!(rv, CKR_OK);
    assert_eq!(count, 3);

    let mut buf: Vec<CK_INTERFACE> = vec![
        CK_INTERFACE {
            p_interface_name: std::ptr::null(),
            p_function_list: std::ptr::null_mut(),
            flags: 0,
        };
        3
    ];
    let rv = C_GetInterfaceList(buf.as_mut_ptr(), &mut count as *mut _);
    assert_eq!(rv, CKR_OK);
    assert_eq!(count, 3);

    for entry in &buf {
        let name = unsafe { std::ffi::CStr::from_ptr(entry.p_interface_name) };
        let s = name.to_str().unwrap();
        assert!(s == "PKCS 11" || s == "Craton PKCS 11");
    }
}

#[test]
fn pq_key_rotate_via_vendor_table() {
    use craton_hsm::config::HsmConfig;
    use craton_hsm::core::HsmCore;
    use craton_hsm::pkcs11_abi::constants::CKM_ML_DSA_44;
    use craton_hsm::store::object::KeyLifecycleState;

    let config = HsmConfig::default();
    let core = HsmCore::new(&config);
    let first = craton_hsm::service::keygen::generate_pqc_keypair(
        &core,
        CKM_ML_DSA_44,
        &[],
        &[],
    )
    .unwrap();

    let rotated = craton_hsm::service::rotate::rotate_key(
        &core,
        first.private_handle,
        CKM_ML_DSA_44,
        craton_hsm::service::rotate::RotatePolicy::default(),
    )
    .unwrap();

    assert_ne!(rotated.new_private, first.private_handle);
    let old = core.object_store().get_object(first.private_handle).unwrap();
    assert_eq!(old.read().lifecycle_state, KeyLifecycleState::Deactivated);
}

#[test]
fn attested_keygen_cbor_statement_parses() {
    use craton_hsm::config::HsmConfig;
    use craton_hsm::core::HsmCore;
    use craton_hsm::pkcs11_abi::constants::CKM_ML_DSA_44;

    let config = HsmConfig::default();
    let core = HsmCore::new(&config);
    let nonce = b"verifier-nonce-test";
    let att = craton_hsm::service::attest::attested_keygen(&core, CKM_ML_DSA_44, nonce).unwrap();
    let parsed = craton_hsm::service::attest::parse_statement(&att.statement).unwrap();
    assert_eq!(parsed.mechanism, CKM_ML_DSA_44 as u64);
    assert_eq!(parsed.nonce, nonce);
    assert_eq!(parsed.measurement.len(), 32);
}

#[cfg(feature = "hybrid-kem")]
#[test]
fn hybrid_kem_wrap_roundtrip() {
    // End-to-end: generate a hybrid KEM keypair directly through
    // `crypto::hybrid`, call service::wrap to wrap some bytes, then unwrap
    // and confirm the round-trip. Exercises the same code path the
    // CKM_HYBRID_KEM_WRAP dispatch will hit once wired into C_WrapKey.
    use craton_hsm::core::HsmCore;
    use craton_hsm::config::HsmConfig;
    use craton_hsm::crypto::hybrid::hybrid_kem_keygen_by_mechanism;
    use craton_hsm::pkcs11_abi::constants::CKM_HYBRID_P256_MLKEM768;
    use craton_hsm::store::object::StoredObject;
    use craton_hsm::store::key_material::RawKeyMaterial;
    use craton_hsm::pkcs11_abi::constants::{CKO_PUBLIC_KEY, CKO_PRIVATE_KEY, CKO_SECRET_KEY, CKK_AES, CKK_ML_KEM};

    let config = HsmConfig::default();
    let core = HsmCore::new(&config);

    // Generate hybrid keypair and insert both halves into the store.
    let (sk_bytes, pk_bytes) =
        hybrid_kem_keygen_by_mechanism(CKM_HYBRID_P256_MLKEM768).unwrap();

    let pub_handle = core.object_store().next_handle().unwrap();
    let mut pub_obj = StoredObject::new(pub_handle, CKO_PUBLIC_KEY);
    pub_obj.key_type = Some(CKK_ML_KEM);
    pub_obj.public_key_data = Some(pk_bytes.clone());
    core.object_store().insert_object(pub_obj).unwrap();

    let priv_handle = core.object_store().next_handle().unwrap();
    let mut priv_obj = StoredObject::new(priv_handle, CKO_PRIVATE_KEY);
    priv_obj.key_type = Some(CKK_ML_KEM);
    priv_obj.key_material = Some(RawKeyMaterial::new(sk_bytes));
    priv_obj.public_key_data = Some(pk_bytes);
    core.object_store().insert_object(priv_obj).unwrap();

    // Symmetric target key (AES-256) to wrap.
    let target_bytes = vec![0x42u8; 32];
    let target_handle = core.object_store().next_handle().unwrap();
    let mut target_obj = StoredObject::new(target_handle, CKO_SECRET_KEY);
    target_obj.key_type = Some(CKK_AES);
    target_obj.key_material = Some(RawKeyMaterial::new(target_bytes.clone()));
    core.object_store().insert_object(target_obj).unwrap();

    let wrapped = craton_hsm::service::wrap::hybrid_kem_wrap(
        &core,
        pub_handle,
        CKM_HYBRID_P256_MLKEM768,
        target_handle,
    )
    .unwrap();
    assert!(wrapped.len() > 4 + 1153); // BE-u32 + P-256+ML-KEM-768 CT + AES-KW output

    let recovered = craton_hsm::service::wrap::hybrid_kem_unwrap(
        &core,
        priv_handle,
        CKM_HYBRID_P256_MLKEM768,
        &wrapped,
    )
    .unwrap();
    assert_eq!(recovered, target_bytes);
}
