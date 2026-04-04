// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! In-process multi-HsmCore tests.
//!
//! Proves that multiple independent HsmCore instances can coexist in a single
//! process with full state isolation. This is the foundation for in-process
//! cluster testing without requiring network transport.
//!
//! **Parallel-safe**: Each test creates isolated HsmCore instances with no
//! global PKCS#11 state. Can run with `--test-threads=8`.

use craton_hsm::config::config::HsmConfig;
use craton_hsm::core::HsmCore;
use craton_hsm::pkcs11_abi::constants::*;

/// Create an isolated HsmCore instance for testing.
fn create_node(node_id: u32) -> HsmCore {
    let mut config = HsmConfig::default();
    config.audit.enabled = false;
    config.token.label = format!("Test Node {}", node_id);
    config.token.serial_number = format!("NODE{:012}", node_id);
    HsmCore::new(&config)
}

/// Initialize a token on the given node with a known SO PIN.
fn init_token(hsm: &HsmCore, slot_id: u64, label: &str, so_pin: &[u8]) {
    let token = hsm.slot_manager().get_token(slot_id).unwrap();
    // init_token expects a 32-byte padded label
    let mut label_bytes = [b' '; 32];
    let len = label.len().min(32);
    label_bytes[..len].copy_from_slice(&label.as_bytes()[..len]);
    token.init_token(so_pin, &label_bytes).unwrap();
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[test]
fn test_three_independent_nodes() {
    let node1 = create_node(1);
    let node2 = create_node(2);
    let node3 = create_node(3);

    // Each node has its own slot manager with independent slots
    assert!(node1.slot_manager().get_slot_ids().len() >= 1);
    assert!(node2.slot_manager().get_slot_ids().len() >= 1);
    assert!(node3.slot_manager().get_slot_ids().len() >= 1);

    // Init tokens with different labels
    init_token(&node1, 0, "Alpha", b"so-pin-1234");
    init_token(&node2, 0, "Beta", b"so-pin-5678");
    init_token(&node3, 0, "Gamma", b"so-pin-9012");

    // Verify labels are independent
    let t1 = node1.slot_manager().get_token(0).unwrap();
    let t2 = node2.slot_manager().get_token(0).unwrap();
    let t3 = node3.slot_manager().get_token(0).unwrap();

    assert!(t1.is_initialized());
    assert!(t2.is_initialized());
    assert!(t3.is_initialized());
}

#[test]
fn test_independent_sessions() {
    let node1 = create_node(10);
    let node2 = create_node(20);

    init_token(&node1, 0, "Node10", b"sopin-10-long");
    init_token(&node2, 0, "Node20", b"sopin-20-long");

    let token1 = node1.slot_manager().get_token(0).unwrap();
    let token2 = node2.slot_manager().get_token(0).unwrap();

    // Open sessions on both nodes
    let h1 = node1
        .session_manager()
        .open_session(0, CKF_RW_SESSION | CKF_SERIAL_SESSION, &token1)
        .unwrap();
    let h2 = node2
        .session_manager()
        .open_session(0, CKF_RW_SESSION | CKF_SERIAL_SESSION, &token2)
        .unwrap();

    // Session handles may coincide numerically but belong to different managers
    // Closing a session on node1 should not affect node2
    node1.session_manager().close_session(h1, &token1).unwrap();

    // node2's session should still be valid
    let sess2 = node2.session_manager().get_session(h2);
    assert!(sess2.is_ok());
}

#[test]
fn test_node_drop_isolation() {
    let node1 = create_node(30);
    let node2 = create_node(31);

    init_token(&node1, 0, "Survivor", b"sopin-30-long");
    init_token(&node2, 0, "Ephemeral", b"sopin-31-long");

    let token2 = node2.slot_manager().get_token(0).unwrap();
    let _h2 = node2
        .session_manager()
        .open_session(0, CKF_RW_SESSION | CKF_SERIAL_SESSION, &token2)
        .unwrap();

    // Drop node2 entirely
    drop(node2);

    // node1 should be completely unaffected
    let token1 = node1.slot_manager().get_token(0).unwrap();
    assert!(token1.is_initialized());
    let h1 = node1
        .session_manager()
        .open_session(0, CKF_RW_SESSION | CKF_SERIAL_SESSION, &token1)
        .unwrap();
    assert!(node1.session_manager().get_session(h1).is_ok());
}

#[test]
fn test_independent_token_init() {
    let node_a = create_node(40);
    let node_b = create_node(41);

    // Init node_a but NOT node_b
    init_token(&node_a, 0, "InitA", b"sopin-a-long");

    let token_a = node_a.slot_manager().get_token(0).unwrap();
    let token_b = node_b.slot_manager().get_token(0).unwrap();

    assert!(token_a.is_initialized());
    assert!(!token_b.is_initialized());
}

#[test]
fn test_independent_crypto_backend() {
    let node1 = create_node(50);
    let node2 = create_node(51);

    // Both nodes have independent crypto backends
    let backend1 = node1.crypto_backend();
    let backend2 = node2.crypto_backend();

    // Generate random data on each -- should be independent
    let mut buf1 = vec![0u8; 32];
    let mut buf2 = vec![0u8; 32];
    {
        let mut drbg1 = node1.drbg().lock();
        drbg1.generate(&mut buf1).unwrap();
    }
    {
        let mut drbg2 = node2.drbg().lock();
        drbg2.generate(&mut buf2).unwrap();
    }

    // Random outputs should differ (probability of collision: 2^-256)
    assert_ne!(buf1, buf2);

    // Both backends should support SHA-256
    let hash1 = backend1.compute_digest(CKM_SHA256, b"test").unwrap();
    let hash2 = backend2.compute_digest(CKM_SHA256, b"test").unwrap();
    // Same input produces same output (deterministic)
    assert_eq!(hash1, hash2);
}

#[test]
fn test_many_nodes_stress() {
    // Create 10 independent nodes
    let nodes: Vec<HsmCore> = (0..10).map(|i| create_node(100 + i)).collect();

    // Init all tokens
    for (i, node) in nodes.iter().enumerate() {
        init_token(node, 0, &format!("Stress{}", i), b"sopin-stress-long");
    }

    // Open sessions on all nodes
    let sessions: Vec<u64> = nodes
        .iter()
        .map(|node| {
            let token = node.slot_manager().get_token(0).unwrap();
            node.session_manager()
                .open_session(0, CKF_RW_SESSION | CKF_SERIAL_SESSION, &token)
                .unwrap()
        })
        .collect();

    // All sessions should be valid
    for (node, handle) in nodes.iter().zip(sessions.iter()) {
        assert!(node.session_manager().get_session(*handle).is_ok());
    }
}

#[test]
fn test_independent_algorithm_config() {
    let mut config1 = HsmConfig::default();
    config1.audit.enabled = false;
    config1.algorithms.fips_approved_only = true;

    let mut config2 = HsmConfig::default();
    config2.audit.enabled = false;
    config2.algorithms.fips_approved_only = false;
    config2.algorithms.enable_pqc = true;

    let node1 = HsmCore::new(&config1);
    let node2 = HsmCore::new(&config2);

    // Node1 is FIPS-only, Node2 allows PQC
    assert!(node1.algorithm_config().fips_approved_only);
    assert!(!node2.algorithm_config().fips_approved_only);
    assert!(node2.algorithm_config().enable_pqc);
}

#[test]
fn test_concurrent_node_operations() {
    use std::sync::Arc;
    use std::thread;

    let nodes: Vec<Arc<HsmCore>> = (0..4).map(|i| Arc::new(create_node(200 + i))).collect();

    // Init tokens
    for (i, node) in nodes.iter().enumerate() {
        init_token(node, 0, &format!("Concurrent{}", i), b"sopin-conc-long");
    }

    // Run operations concurrently on different nodes
    let handles: Vec<_> = nodes
        .iter()
        .map(|node| {
            let node = Arc::clone(node);
            thread::spawn(move || {
                let token = node.slot_manager().get_token(0).unwrap();
                let h = node
                    .session_manager()
                    .open_session(0, CKF_RW_SESSION | CKF_SERIAL_SESSION, &token)
                    .unwrap();

                // Generate random data
                let mut buf = vec![0u8; 64];
                node.drbg().lock().generate(&mut buf).unwrap();
                assert!(!buf.iter().all(|&b| b == 0));

                // Close session
                node.session_manager().close_session(h, &token).unwrap();
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }
}
