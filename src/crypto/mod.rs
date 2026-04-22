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

/// Additional hybrid KEM constructions: X25519+ML-KEM-1024, P-256+ML-KEM-768
/// (CNSA 2.0), and P-384+ML-KEM-1024 (TOP SECRET aligned).
/// Enable with `hybrid-kem` feature.
#[cfg(feature = "hybrid-kem")]
pub mod hybrid;

/// Falcon (FN-DSA) signatures via PQClean reference code (C FFI).
/// Enable with `falcon-sig` feature.
#[cfg(feature = "falcon-sig")]
pub mod falcon;

/// FrodoKEM (conservative LWE-based KEM) via PQClean reference code (C FFI).
/// Enable with `frodokem-kem` feature.
#[cfg(feature = "frodokem-kem")]
pub mod frodokem;
