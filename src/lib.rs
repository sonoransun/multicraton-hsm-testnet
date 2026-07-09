// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Craton HSM — a PKCS#11-compliant Software HSM in pure Rust.
//!
//! This crate provides a complete software HSM implementation with classical
//! and post-quantum cryptography, FIPS 140-3 readiness, and a C ABI compatible
//! with any PKCS#11 consumer.
//!
//! # Entry points
//!
//! - **PKCS#11 C ABI** ([`pkcs11_abi`]): the `cdylib` exports `C_Initialize`,
//!   `C_GetFunctionList`, `C_GetInterface`, and the rest of the Cryptoki
//!   surface for use from any PKCS#11 host application. Only one
//!   `C_Initialize`/`C_Finalize` lifecycle may exist per process.
//! - **Rust API** ([`core::HsmCore`]): embed the HSM directly; construct with
//!   [`core::HsmCore::new_default`] or inject a custom [`crypto::backend::CryptoBackend`].
//! - **Crypto primitives** ([`crypto`]): stateless building blocks used by both.
//!
//! # Quick start (Rust API, stateless primitives)
//!
//! ```
//! use craton_hsm::crypto::{keygen, sign};
//!
//! // Generate an Ed25519 keypair (private key is mlocked + zeroize-on-drop).
//! let (private_key, public_key) = keygen::generate_ed25519_key_pair()?;
//!
//! let message = b"hello from craton-hsm";
//! let signature = sign::ed25519_sign(private_key.as_bytes(), message)?;
//! assert!(sign::ed25519_verify(&public_key, message, &signature)?);
//! # Ok::<(), craton_hsm::error::HsmError>(())
//! ```
//!
//! Post-quantum equivalents live in [`crypto::pqc`] (ML-KEM, ML-DSA, SLH-DSA).

#![warn(missing_docs)]

/// Tamper-evident audit logging with chained SHA-256.
pub mod audit;
/// Configuration — TOML-based `HsmConfig` with algorithm policy.
pub mod config;
/// Core HSM state — the central `HsmCore` struct shared by all entry points.
pub mod core;
/// Cryptographic operations — keygen, sign, encrypt, digest, PQC, DRBG, self-tests, backends.
pub mod crypto;
/// Error types — `HsmError` enum with `CK_RV` mapping.
pub mod error;
/// Metrics and observability — Prometheus-compatible metrics collection and HTTP server.
#[cfg(feature = "observability")]
pub mod metrics;
/// PKCS#11 C ABI layer — types, constants, and 70+ `#[no_mangle]` function exports.
///
/// This module uses PKCS#11 naming conventions (e.g., `CK_RV`, `CKR_OK`, `C_Initialize`)
/// which require `non_camel_case_types`, `non_snake_case`, and `non_upper_case_globals`.
#[allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]
pub mod pkcs11_abi;
/// Platform-specific file ACL helpers (Windows DACL restriction).
#[cfg(windows)]
pub(crate) mod platform_acl;
/// Service layer — pure-Rust action flows shared by every public surface
/// (PKCS#11 C ABI, vendor-ext, REST, language bindings). Mechanism dispatch
/// and object-store access for PQC ops live here; each entry point wraps
/// with its own transport-specific error conversion.
pub mod service;

/// Session management — `SessionManager`, session state machine, handle allocation.
pub mod session;
/// Object storage — in-memory `ObjectStore`, encrypted persistence, key material, backups.
pub mod store;
/// Token and slot management — PIN hashing, login state, multi-slot support.
pub mod token;

/// Advanced cryptographic and enterprise features.
///
/// Includes: ZKP, threshold cryptography, GPU acceleration, ML analytics,
/// policy engine, FHE, TPM binding, STARK proofs, WASM plugins, and attestation.
/// Individual sub-modules are gated behind their own feature flags; this top-level
/// module is enabled whenever any advanced feature is active.
#[cfg(any(
    feature = "advanced-all",
    feature = "fhe-compute",
    feature = "tpm-binding",
    feature = "stark-proofs",
    feature = "wasm-plugins",
    feature = "zkp",
    feature = "threshold",
    feature = "gpu-acceleration",
    feature = "ml-analytics",
    feature = "policy-engine",
    feature = "quantum-resistant",
))]
pub mod advanced;

/// HSM clustering — Raft consensus, key replication, QUIC/Noise/mTLS transport.
/// Feature-gated: the cluster module uses async traits and network transports
/// that require explicit opt-in.
#[cfg(feature = "networking")]
pub mod cluster;
