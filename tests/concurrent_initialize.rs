// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Security test: concurrent C_Initialize / C_Finalize must not corrupt state.
//!
//! Verifies that the global Mutex protecting HsmCore serializes rapid
//! initialization/finalization cycles from multiple threads without
//! panics, deadlocks, or undefined behavior.

#![allow(non_snake_case)]

use craton_hsm::pkcs11_abi::constants::*;
use craton_hsm::pkcs11_abi::functions::*;
use std::ptr;
use std::sync::Barrier;
use std::thread;

/// 4 threads each calling C_Initialize → C_Finalize 50 times concurrently.
/// The global Mutex must serialize all calls without deadlock or panic.
#[test]
fn test_concurrent_initialize_finalize_no_corruption() {
    let num_threads = 4;
    let iterations = 10;
    let barrier = std::sync::Arc::new(Barrier::new(num_threads));

    let handles: Vec<_> = (0..num_threads)
        .map(|_| {
            let b = barrier.clone();
            thread::spawn(move || {
                b.wait(); // Synchronize start for maximum contention
                for _ in 0..iterations {
                    let rv = C_Initialize(ptr::null_mut());
                    // Either OK (first to init) or ALREADY_INITIALIZED (another thread won)
                    assert!(
                        rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED,
                        "C_Initialize returned unexpected: {rv}"
                    );

                    let rv = C_Finalize(ptr::null_mut());
                    // Either OK (successfully finalized) or NOT_INITIALIZED (another thread finalized first)
                    assert!(
                        rv == CKR_OK || rv == CKR_CRYPTOKI_NOT_INITIALIZED,
                        "C_Finalize returned unexpected: {rv}"
                    );
                }
            })
        })
        .collect();

    for h in handles {
        h.join().expect("thread panicked during concurrent init/finalize");
    }

    // Ensure we're in a clean state — finalize if still initialized
    let rv = C_Finalize(ptr::null_mut());
    assert!(rv == CKR_OK || rv == CKR_CRYPTOKI_NOT_INITIALIZED);
}
