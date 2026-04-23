// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! HTTP error responses (RFC 7807 ProblemDetails).
//!
//! Maps `HsmError` → (HTTP status, machine-readable error code, human
//! message). The `type` field uses the same identifiers as the PKCS#11
//! `CK_RV` constants so that tooling built around PKCS#11 can reuse its
//! error taxonomy unchanged.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use craton_hsm::error::HsmError;
use serde::Serialize;

/// RFC 7807 ProblemDetails response body.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ProblemDetails {
    /// Stable machine-readable error code — maps to a PKCS#11 `CK_RV` name
    /// (e.g. `CKR_MECHANISM_INVALID`).
    pub r#type: &'static str,
    /// Short human-readable title.
    pub title: &'static str,
    /// HTTP status code echoed into the body for convenience.
    pub status: u16,
    /// Longer detail — may vary per instance.
    pub detail: String,
    /// Opaque per-request identifier (request ID) if one was set by the
    /// upstream middleware.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
}

/// REST-layer error wrapping `HsmError` + a transport-specific tag for
/// authorization / request-shape failures that never arise inside HsmCore.
#[derive(Debug, thiserror::Error)]
pub enum RestError {
    #[error(transparent)]
    Hsm(#[from] HsmError),

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("unauthorized: {0}")]
    Unauthorized(&'static str),

    #[error("forbidden: missing scope `{0}`")]
    Forbidden(&'static str),

    #[error("not found: {0}")]
    NotFound(&'static str),

    #[error("internal error: {0}")]
    Internal(&'static str),
}

impl IntoResponse for RestError {
    fn into_response(self) -> Response {
        let (status, code, title, detail) = match &self {
            RestError::BadRequest(d) => (
                StatusCode::BAD_REQUEST,
                "CKR_ARGUMENTS_BAD",
                "Bad request",
                d.clone(),
            ),
            RestError::Unauthorized(d) => (
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "Unauthorized",
                (*d).to_string(),
            ),
            RestError::Forbidden(s) => (
                StatusCode::FORBIDDEN,
                "FORBIDDEN",
                "Missing scope",
                (*s).to_string(),
            ),
            RestError::NotFound(d) => (
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                "Not found",
                (*d).to_string(),
            ),
            RestError::Internal(d) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "CKR_GENERAL_ERROR",
                "Internal error",
                (*d).to_string(),
            ),
            RestError::Hsm(e) => hsm_error_map(e),
        };
        let body = ProblemDetails {
            r#type: code,
            title,
            status: status.as_u16(),
            detail,
            instance: None,
        };
        (status, Json(body)).into_response()
    }
}

/// Translate an `HsmError` into a (status, code, title, detail) tuple.
fn hsm_error_map(e: &HsmError) -> (StatusCode, &'static str, &'static str, String) {
    use HsmError as E;
    match e {
        E::MechanismInvalid => (
            StatusCode::BAD_REQUEST,
            "CKR_MECHANISM_INVALID",
            "Invalid mechanism",
            e.to_string(),
        ),
        E::KeyHandleInvalid => (
            StatusCode::NOT_FOUND,
            "CKR_KEY_HANDLE_INVALID",
            "Key not found",
            e.to_string(),
        ),
        E::SignatureInvalid => (
            StatusCode::BAD_REQUEST,
            "CKR_SIGNATURE_INVALID",
            "Signature invalid",
            e.to_string(),
        ),
        E::EncryptedDataInvalid => (
            StatusCode::BAD_REQUEST,
            "CKR_ENCRYPTED_DATA_INVALID",
            "Ciphertext invalid",
            e.to_string(),
        ),
        E::DataInvalid => (
            StatusCode::BAD_REQUEST,
            "CKR_DATA_INVALID",
            "Data invalid",
            e.to_string(),
        ),
        E::DataLenRange => (
            StatusCode::BAD_REQUEST,
            "CKR_DATA_LEN_RANGE",
            "Data length out of range",
            e.to_string(),
        ),
        E::FunctionNotSupported => (
            StatusCode::NOT_IMPLEMENTED,
            "CKR_FUNCTION_NOT_SUPPORTED",
            "Function not supported",
            e.to_string(),
        ),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "CKR_GENERAL_ERROR",
            "Internal HSM error",
            e.to_string(),
        ),
    }
}

pub type RestResult<T> = Result<T, RestError>;
