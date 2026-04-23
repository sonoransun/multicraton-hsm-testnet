// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Service layer — pure-Rust action flows shared by every public surface.
//!
//! The PKCS#11 C ABI, the REST gateway, the vendor-extension function table,
//! and the language bindings all funnel through the same handlers here.
//! This keeps behaviour consistent across transports and avoids the drift
//! that would happen if each surface reimplemented mechanism dispatch.
//!
//! ## Shape
//! Every public function in this module takes a `&HsmCore` plus the
//! operation's parameters and returns `HsmResult<T>`. No `CK_RV` conversion
//! happens here — that stays in [`crate::pkcs11_abi::functions`] (C ABI)
//! or the REST error layer. Panics are forbidden; every fallible path must
//! return `HsmError`.
//!
//! ## Layers
//! - [`caps`] — runtime capability introspection
//! - [`kem`] — ML-KEM / FrodoKEM / hybrid-KEM encapsulate + decapsulate
//! - [`sign`] — every signature mechanism (classical, ML-DSA, SLH-DSA, Falcon, composite)
//! - [`wrap`] — `CKM_HYBRID_KEM_WRAP` (vendor-ext) + classical AES key wrap passthrough
//! - [`rotate`] — atomic PQ key rotation with policy
//! - [`attest`] — attested keygen producing a signed statement

pub mod caps;
pub mod kem;
pub mod keygen;
pub mod rotate;
pub mod sign;
pub mod wrap;

/// Attested key generation. Always compiled — produces a self-attesting
/// CBOR statement by default, and upgrades to real TEE reports when the
/// `advanced` module's platform detectors are compiled in.
pub mod attest;
