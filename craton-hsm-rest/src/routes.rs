// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Route handlers.
//!
//! Every handler pulls in an `AuthContext` (set by the auth middleware),
//! checks the required scope, decodes base64 inputs, calls the matching
//! `service::*` function on the shared `HsmCore`, and encodes the response.

use axum::extract::{Path, State};
use axum::Json;
use base64::Engine;
use craton_hsm::pkcs11_abi::types::CK_MECHANISM_TYPE;
use std::sync::Arc;

use crate::auth::AuthContext;
use crate::dto::*;
use crate::errors::{RestError, RestResult};
use crate::router::AppState;

fn b64_decode(s: &str) -> Result<Vec<u8>, RestError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(s))
        .map_err(|e| RestError::BadRequest(format!("base64 decode: {e}")))
}

fn b64_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn parse_mechanism(s: &str) -> Result<CK_MECHANISM_TYPE, RestError> {
    // Accept decimal, `0x…` hex, or `CKM_…` constant names for ergonomics.
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16)
            .map(|n| n as CK_MECHANISM_TYPE)
            .map_err(|e| RestError::BadRequest(format!("bad hex mechanism: {e}")));
    }
    if let Ok(n) = s.parse::<u64>() {
        return Ok(n as CK_MECHANISM_TYPE);
    }
    mechanism_by_name(s).ok_or_else(|| RestError::BadRequest(format!("unknown mechanism: {s}")))
}

fn mechanism_by_name(name: &str) -> Option<CK_MECHANISM_TYPE> {
    use craton_hsm::pkcs11_abi::constants::*;
    Some(match name {
        "CKM_ML_KEM_512" => CKM_ML_KEM_512,
        "CKM_ML_KEM_768" => CKM_ML_KEM_768,
        "CKM_ML_KEM_1024" => CKM_ML_KEM_1024,
        "CKM_ML_DSA_44" => CKM_ML_DSA_44,
        "CKM_ML_DSA_65" => CKM_ML_DSA_65,
        "CKM_ML_DSA_87" => CKM_ML_DSA_87,
        "CKM_HYBRID_ED25519_MLDSA65" => CKM_HYBRID_ED25519_MLDSA65,
        "CKM_HYBRID_ML_DSA_ECDSA" => CKM_HYBRID_ML_DSA_ECDSA,
        "CKM_HYBRID_X25519_MLKEM1024" => CKM_HYBRID_X25519_MLKEM1024,
        "CKM_HYBRID_P256_MLKEM768" | "P-256+ML-KEM-768" => CKM_HYBRID_P256_MLKEM768,
        "CKM_HYBRID_P384_MLKEM1024" | "P-384+ML-KEM-1024" => CKM_HYBRID_P384_MLKEM1024,
        "X25519+ML-KEM-1024" => CKM_HYBRID_X25519_MLKEM1024,
        _ => return None,
    })
}

// ============================================================================
// GET /v1/capabilities
// ============================================================================

#[utoipa::path(
    get,
    path = "/v1/capabilities",
    responses((status = 200, body = CapabilitiesResponse))
)]
pub async fn get_capabilities(State(state): State<AppState>) -> RestResult<Json<CapabilitiesResponse>> {
    let caps = craton_hsm::service::caps::get_pqc_capabilities(&state.core)?;
    Ok(Json(CapabilitiesResponse {
        enable_pqc: caps.enable_pqc,
        fips_approved_only: caps.fips_approved_only,
        vendor_ext_available: caps.vendor_ext_available,
        hybrid_kem_wrap_available: caps.hybrid_kem_wrap_available,
        ml_kem_variants: caps.ml_kem_variants,
        ml_dsa_variants: caps.ml_dsa_variants,
        slh_dsa_variants: caps.slh_dsa_variants,
        falcon_variants: caps.falcon_variants,
        frodokem_variants: caps.frodokem_variants,
        hybrid_kem_variants: caps.hybrid_kem_variants,
        composite_sig_variants: caps.composite_sig_variants,
    }))
}

// ============================================================================
// POST /v1/keys/{handle}/sign  |  /verify
// ============================================================================

#[utoipa::path(
    post,
    path = "/v1/keys/{handle}/sign",
    params(("handle" = u64, Path)),
    request_body = SignRequest,
    responses((status = 200, body = SignResponse))
)]
pub async fn sign_with_key(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(handle): Path<u64>,
    Json(body): Json<SignRequest>,
) -> RestResult<Json<SignResponse>> {
    auth.require_scope("sign")?;
    let mechanism = parse_mechanism(&body.mechanism)?;
    let data = b64_decode(&body.data_b64)?;
    let sig = craton_hsm::service::sign::pqc_sign(&state.core, handle, mechanism, &data)?;
    Ok(Json(SignResponse {
        signature_len: sig.len(),
        signature_b64: b64_encode(&sig),
        mechanism: body.mechanism,
    }))
}

#[utoipa::path(
    post,
    path = "/v1/keys/{handle}/verify",
    params(("handle" = u64, Path)),
    request_body = VerifyRequest,
    responses((status = 200, body = VerifyResponse))
)]
pub async fn verify_with_key(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(handle): Path<u64>,
    Json(body): Json<VerifyRequest>,
) -> RestResult<Json<VerifyResponse>> {
    auth.require_scope("verify")?;
    let mechanism = parse_mechanism(&body.mechanism)?;
    let data = b64_decode(&body.data_b64)?;
    let sig = b64_decode(&body.signature_b64)?;
    let valid = craton_hsm::service::sign::pqc_verify(&state.core, handle, mechanism, &data, &sig)?;
    Ok(Json(VerifyResponse { valid }))
}

// ============================================================================
// POST /v1/kems/{handle}/encapsulate  |  /decapsulate
// ============================================================================

#[utoipa::path(
    post,
    path = "/v1/kems/{handle}/encapsulate",
    params(("handle" = u64, Path)),
    request_body = EncapsulateRequest,
    responses((status = 200, body = EncapsulateResponse))
)]
pub async fn kem_encapsulate(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(handle): Path<u64>,
    Json(body): Json<EncapsulateRequest>,
) -> RestResult<Json<EncapsulateResponse>> {
    auth.require_scope("kem")?;
    let mechanism = parse_mechanism(&body.mechanism)?;
    let bundle = craton_hsm::service::kem::encapsulate_by_handle(&state.core, handle, mechanism)?;
    Ok(Json(EncapsulateResponse {
        ciphertext_b64: b64_encode(&bundle.ciphertext),
        shared_secret_b64: b64_encode(&bundle.shared_secret),
    }))
}

#[utoipa::path(
    post,
    path = "/v1/kems/{handle}/decapsulate",
    params(("handle" = u64, Path)),
    request_body = DecapsulateRequest,
    responses((status = 200, body = DecapsulateResponse))
)]
pub async fn kem_decapsulate(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(handle): Path<u64>,
    Json(body): Json<DecapsulateRequest>,
) -> RestResult<Json<DecapsulateResponse>> {
    auth.require_scope("kem")?;
    let mechanism = parse_mechanism(&body.mechanism)?;
    let ct = b64_decode(&body.ciphertext_b64)?;
    let ss =
        craton_hsm::service::kem::decapsulate_by_handle(&state.core, handle, mechanism, &ct)?;
    Ok(Json(DecapsulateResponse {
        shared_secret_b64: b64_encode(&ss),
    }))
}

// ============================================================================
// POST /v1/hybrid/compose-sign  |  /compose-verify
// ============================================================================

#[utoipa::path(
    post,
    path = "/v1/hybrid/compose-sign",
    request_body = ComposeSignRequest,
    responses((status = 200, body = ComposeSignResponse))
)]
pub async fn compose_sign(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(body): Json<ComposeSignRequest>,
) -> RestResult<Json<ComposeSignResponse>> {
    auth.require_scope("sign")?;
    let pq_bytes = fetch_private(&state.core, body.pq_key_handle)?;
    let cl_bytes = fetch_private(&state.core, body.classical_key_handle)?;
    let data = b64_decode(&body.data_b64)?;
    let sig = craton_hsm::crypto::pqc::hybrid_sign(&pq_bytes, &cl_bytes, &data)?;
    Ok(Json(ComposeSignResponse {
        signature_b64: b64_encode(&sig),
    }))
}

#[utoipa::path(
    post,
    path = "/v1/hybrid/compose-verify",
    request_body = ComposeVerifyRequest,
    responses((status = 200, body = VerifyResponse))
)]
pub async fn compose_verify(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(body): Json<ComposeVerifyRequest>,
) -> RestResult<Json<VerifyResponse>> {
    auth.require_scope("verify")?;
    let pq_pub = fetch_public(&state.core, body.pq_pub_handle)?;
    let cl_pub = fetch_public(&state.core, body.classical_pub_handle)?;
    let data = b64_decode(&body.data_b64)?;
    let sig = b64_decode(&body.signature_b64)?;
    let valid = craton_hsm::crypto::pqc::hybrid_verify(&pq_pub, &cl_pub, &data, &sig)?;
    Ok(Json(VerifyResponse { valid }))
}

// ============================================================================
// POST /v1/wrap  |  /unwrap  — hybrid-KEM wrap transport
// ============================================================================

#[cfg(feature = "hybrid-kem")]
#[utoipa::path(
    post,
    path = "/v1/wrap",
    request_body = HybridWrapRequest,
    responses((status = 200, body = HybridWrapResponse))
)]
pub async fn hybrid_wrap(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(body): Json<HybridWrapRequest>,
) -> RestResult<Json<HybridWrapResponse>> {
    auth.require_scope("wrap")?;
    let kem = parse_mechanism(&body.kem_mechanism)?;
    let wrapped = craton_hsm::service::wrap::hybrid_kem_wrap(
        &state.core,
        body.recipient_pub_handle,
        kem,
        body.target_key_handle,
    )?;
    Ok(Json(HybridWrapResponse {
        wrapped_b64: b64_encode(&wrapped),
    }))
}

#[cfg(feature = "hybrid-kem")]
#[utoipa::path(
    post,
    path = "/v1/unwrap",
    request_body = HybridUnwrapRequest,
    responses((status = 200, body = HybridUnwrapResponse))
)]
pub async fn hybrid_unwrap(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(body): Json<HybridUnwrapRequest>,
) -> RestResult<Json<HybridUnwrapResponse>> {
    auth.require_scope("wrap")?;
    let kem = parse_mechanism(&body.kem_mechanism)?;
    let wrapped = b64_decode(&body.wrapped_b64)?;
    let key = craton_hsm::service::wrap::hybrid_kem_unwrap(
        &state.core,
        body.recipient_priv_handle,
        kem,
        &wrapped,
    )?;
    Ok(Json(HybridUnwrapResponse {
        key_b64: b64_encode(&key),
    }))
}

// ----- internal helpers -----

fn fetch_private(core: &craton_hsm::core::HsmCore, handle: u64) -> RestResult<Vec<u8>> {
    let v = craton_hsm::service::sign::inspect(core, handle, |obj| {
        obj.key_material.as_ref().map(|m| m.as_bytes().to_vec())
    })?;
    v.ok_or(RestError::NotFound("key material absent"))
}

fn fetch_public(core: &craton_hsm::core::HsmCore, handle: u64) -> RestResult<Vec<u8>> {
    let v = craton_hsm::service::sign::inspect(core, handle, |obj| {
        obj.public_key_data
            .clone()
            .or_else(|| obj.ec_point.clone())
    })?;
    v.ok_or(RestError::NotFound("public key bytes absent"))
}

// Dummy use to quiet the Arc import when hybrid-kem is disabled.
fn _use(_: Arc<()>) {}
