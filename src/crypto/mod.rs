// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
#[cfg(feature = "awslc-backend")]
pub mod awslc_backend;
pub mod backend;
pub mod derive;
pub mod digest;
pub mod drbg;
pub mod encrypt;
pub mod integrity;
pub mod keygen;
pub mod mechanisms;
pub mod mlock;
pub mod pairwise_test;
pub mod pqc;
#[cfg(feature = "rustcrypto-backend")]
pub mod rustcrypto_backend;
pub mod self_test;
pub mod sign;
pub mod wrap;
// Temporarily disabled enhanced backends to focus on wrapped key functionality
// pub mod enhanced_backend;
// #[cfg(feature = "rustcrypto-backend")]
// pub mod enhanced_rustcrypto_backend;

// ── Cutting-edge crypto modules ───────────────────────────────────────────────

/// BLS12-381 aggregatable signatures — used for threshold schemes and audit proofs.
/// Enable with `bls-signatures` feature.
#[cfg(feature = "bls-signatures")]
pub mod bls;

/// Hybrid KEM: X25519 + ML-KEM-768 dual encapsulation (NIST IR 8413 / CNSA 2.0).
/// Secure against both classical and quantum adversaries.
/// Enable with `hybrid-kem` feature.
#[cfg(feature = "hybrid-kem")]
pub mod hybrid_kem;
