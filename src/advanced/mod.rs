// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Advanced cryptographic and enterprise features for Craton HSM.
//!
//! This module provides cutting-edge capabilities including:
//! - Zero-knowledge proofs for privacy-preserving authentication
//! - Threshold cryptography for distributed key management
//! - Hardware acceleration for performance-critical operations
//! - Machine learning analytics for security insights
//! - Enterprise policy engines for access control
//! - Cloud-native integrations

// ── Existing feature-gated modules ───────────────────────────────────────────

#[cfg(feature = "zkp")]
pub mod zkp;

#[cfg(feature = "threshold")]
pub mod threshold;

#[cfg(feature = "gpu-acceleration")]
pub mod gpu_crypto;

#[cfg(feature = "ml-analytics")]
pub mod analytics;

#[cfg(feature = "policy-engine")]
pub mod policy;

// Quantum-resistant cryptography framework
#[cfg(feature = "quantum-resistant")]
pub mod quantum_resistant;

// ── New cutting-edge modules ──────────────────────────────────────────────────

/// Fully Homomorphic Encryption — compute on encrypted data without decryption.
/// Enables sealed cloud operations, encrypted counters, and homomorphic MACs.
#[cfg(feature = "fhe-compute")]
pub mod fhe;

/// TPM 2.0 hardware root-of-trust — PCR-sealed key storage and platform attestation.
/// Requires `libtss2-dev` and a hardware or firmware TPM.
#[cfg(feature = "tpm-binding")]
pub mod tpm;

/// STARK proof system (Winterfell / Polygon Miden) — transparent, post-quantum ZK.
/// Prove correctness of HSM operations without revealing secret material.
#[cfg(feature = "stark-proofs")]
pub mod stark;

/// WebAssembly plugin engine (Wasmtime) — sandboxed custom crypto extensions.
/// Load operator-supplied `.wasm` modules with capability-based access control.
#[cfg(feature = "wasm-plugins")]
pub mod wasm_plugin;

/// Remote attestation — Intel TDX, AMD SEV-SNP, AWS Nitro Enclave, and software fallback.
/// Produces IETF EAT-compatible tokens for remote verifiers.
pub mod attestation;
