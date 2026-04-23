// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Request/response DTOs with utoipa schema annotations.
//!
//! Byte-valued fields (data, signatures, ciphertexts, keys) are transported
//! as base64url-unpadded strings. The schema is published at
//! `/v1/openapi.json` — generators (openapi-generator, OpenAPI Codegen,
//! Swagger Codegen) can be pointed at that endpoint to produce clients.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

// ----- Capabilities ---------------------------------------------------------

/// Same shape as `CratonExt_GetPQCCapabilities` and `service::caps::PqcCapabilities`.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CapabilitiesResponse {
    pub enable_pqc: bool,
    pub fips_approved_only: bool,
    pub vendor_ext_available: bool,
    pub hybrid_kem_wrap_available: bool,
    pub ml_kem_variants: Vec<String>,
    pub ml_dsa_variants: Vec<String>,
    pub slh_dsa_variants: Vec<String>,
    pub falcon_variants: Vec<String>,
    pub frodokem_variants: Vec<String>,
    pub hybrid_kem_variants: Vec<String>,
    pub composite_sig_variants: Vec<String>,
}

// ----- Signatures -----------------------------------------------------------

/// Request for `POST /v1/keys/{handle}/sign`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SignRequest {
    /// PKCS#11 mechanism as a hex string (e.g. `0x80000011` for ML-DSA-65).
    pub mechanism: String,
    /// Message to sign, base64url-unpadded.
    pub data_b64: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SignResponse {
    pub signature_b64: String,
    pub signature_len: usize,
    pub mechanism: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct VerifyRequest {
    pub mechanism: String,
    pub data_b64: String,
    pub signature_b64: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct VerifyResponse {
    pub valid: bool,
}

// ----- KEM ------------------------------------------------------------------

#[derive(Debug, Deserialize, ToSchema)]
pub struct EncapsulateRequest {
    pub mechanism: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct EncapsulateResponse {
    pub ciphertext_b64: String,
    /// **Warning:** the shared secret is returned in the clear here because
    /// PKCS#11 `C_DeriveKey`-style server-side key import is not yet wired
    /// through the REST surface. Do not enable this route in environments
    /// where the TLS termination point differs from the trust boundary.
    /// See the PKCS#11 vendor-extension `C_EncapsulateKey` for the
    /// server-resident-secret variant.
    pub shared_secret_b64: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct DecapsulateRequest {
    pub mechanism: String,
    pub ciphertext_b64: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DecapsulateResponse {
    pub shared_secret_b64: String,
}

// ----- Composite signatures -------------------------------------------------

#[derive(Debug, Deserialize, ToSchema)]
pub struct ComposeSignRequest {
    pub classical_key_handle: u64,
    pub pq_key_handle: u64,
    pub data_b64: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ComposeSignResponse {
    pub signature_b64: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ComposeVerifyRequest {
    pub classical_pub_handle: u64,
    pub pq_pub_handle: u64,
    pub data_b64: String,
    pub signature_b64: String,
}

// ----- Hybrid KEM wrap ------------------------------------------------------

#[derive(Debug, Deserialize, ToSchema)]
pub struct HybridWrapRequest {
    pub recipient_pub_handle: u64,
    pub target_key_handle: u64,
    /// Which hybrid-KEM to use. e.g. `"P-256+ML-KEM-768"`.
    pub kem_mechanism: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct HybridWrapResponse {
    pub wrapped_b64: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct HybridUnwrapRequest {
    pub recipient_priv_handle: u64,
    pub kem_mechanism: String,
    pub wrapped_b64: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct HybridUnwrapResponse {
    pub key_b64: String,
}
