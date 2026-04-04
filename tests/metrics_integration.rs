// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Integration tests for the Prometheus metrics framework.

use craton_hsm::config::config::HsmConfig;
use craton_hsm::core::HsmCore;
use craton_hsm::pkcs11_abi::{functions::*, types::*};
use std::ptr;

/// Test that metrics are properly collected during basic PKCS#11 operations.
#[test]
fn test_metrics_collection() {
    // Initialize HSM
    let config = HsmConfig::default();
    let hsm = HsmCore::new(&config);

    // Store in global static for C ABI access
    unsafe {
        craton_hsm::pkcs11_abi::functions::set_hsm(hsm);
    }

    // Initialize the library
    let rv = C_Initialize(ptr::null_mut());
    assert_eq!(rv, CKR_OK);

    // Test that basic metrics are working by checking initial values
    let hsm = unsafe { craton_hsm::pkcs11_abi::functions::get_hsm() }.unwrap();
    let initial_operations = hsm.metrics.operations_total.get();

    // Open a session (should increment metrics)
    let mut session: CK_SESSION_HANDLE = 0;
    let rv = C_OpenSession(
        0, // slot 0
        CKF_SERIAL_SESSION | CKF_RW_SESSION,
        ptr::null_mut(),
        None,
        &mut session as *mut CK_SESSION_HANDLE,
    );
    assert_eq!(rv, CKR_OK);

    // Verify metrics have been updated
    let after_session_operations = hsm.metrics.operations_total.get();
    assert!(
        after_session_operations > initial_operations,
        "Operations counter should have incremented"
    );

    assert_eq!(
        hsm.metrics.active_sessions.get(),
        1,
        "Active sessions should be 1"
    );

    assert!(
        hsm.metrics.sessions_created_total.get() > 0,
        "Sessions created counter should have incremented"
    );

    // Close the session (should decrement active sessions)
    let rv = C_CloseSession(session);
    assert_eq!(rv, CKR_OK);

    // Verify session metrics updated
    assert_eq!(
        hsm.metrics.active_sessions.get(),
        0,
        "Active sessions should be 0 after closing"
    );

    // Test metrics collection in text format
    let collector = craton_hsm::metrics::collector::MetricsCollector::new(hsm.metrics.clone());
    let metrics_text = collector.collect_metrics().expect("Should collect metrics");

    // Verify some key metrics are present in the output
    assert!(
        metrics_text.contains("hsm_operations_total"),
        "Should contain operations total metric"
    );
    assert!(
        metrics_text.contains("hsm_sessions_created_total"),
        "Should contain sessions created metric"
    );
    assert!(
        metrics_text.contains("hsm_active_sessions"),
        "Should contain active sessions metric"
    );

    // Clean up
    let _rv = C_Finalize(ptr::null_mut());
}

/// Test that operation timing metrics are collected properly.
#[test]
fn test_operation_timing_metrics() {
    let config = HsmConfig::default();
    let hsm = HsmCore::new(&config);

    unsafe {
        craton_hsm::pkcs11_abi::functions::set_hsm(hsm);
    }

    let rv = C_Initialize(ptr::null_mut());
    assert_eq!(rv, CKR_OK);

    let hsm = unsafe { craton_hsm::pkcs11_abi::functions::get_hsm() }.unwrap();

    // Check initial histogram sample count
    let initial_samples = hsm.metrics.operation_duration_seconds.get_sample_count();

    // Perform an operation that should be timed
    let mut session: CK_SESSION_HANDLE = 0;
    let _rv = C_OpenSession(
        0,
        CKF_SERIAL_SESSION | CKF_RW_SESSION,
        ptr::null_mut(),
        None,
        &mut session as *mut CK_SESSION_HANDLE,
    );

    // Verify timing metric was recorded
    let after_samples = hsm.metrics.operation_duration_seconds.get_sample_count();
    assert!(
        after_samples > initial_samples,
        "Operation duration histogram should have recorded a sample"
    );

    let _rv = C_CloseSession(session);
    let _rv = C_Finalize(ptr::null_mut());
}

/// Test that error metrics are properly tracked.
#[test]
fn test_error_metrics_tracking() {
    let config = HsmConfig::default();
    let hsm = HsmCore::new(&config);

    unsafe {
        craton_hsm::pkcs11_abi::functions::set_hsm(hsm);
    }

    let rv = C_Initialize(ptr::null_mut());
    assert_eq!(rv, CKR_OK);

    let hsm = unsafe { craton_hsm::pkcs11_abi::functions::get_hsm() }.unwrap();

    let initial_errors = hsm.metrics.operations_error_total.get();

    // Cause an error by passing invalid arguments
    let rv = C_OpenSession(
        0,
        CKF_SERIAL_SESSION | CKF_RW_SESSION,
        ptr::null_mut(),
        None,
        ptr::null_mut(), // Invalid - should cause error
    );
    assert_eq!(rv, CKR_ARGUMENTS_BAD);

    // Verify error metric was incremented
    let after_errors = hsm.metrics.operations_error_total.get();
    assert!(
        after_errors > initial_errors,
        "Error counter should have incremented for bad arguments"
    );

    let _rv = C_Finalize(ptr::null_mut());
}
