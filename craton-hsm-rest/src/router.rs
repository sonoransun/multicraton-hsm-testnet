// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Router assembly.
//!
//! [`build_router`] is the library entry point — it takes an `Arc<HsmCore>`
//! and returns a fully-wired `axum::Router`. The binary (`src/main.rs`)
//! calls this with the same state it uses to serve HTTPS.

use axum::routing::{get, post};
use axum::Router;
use axum::async_trait;
use axum::extract::{FromRequestParts, Request};
use axum::http::request::Parts;
use axum::middleware::{self, Next};
use axum::response::Response;
use craton_hsm::core::HsmCore;
use std::sync::Arc;
use tower_http::request_id::{MakeRequestUuid, SetRequestIdLayer};
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;

use crate::auth::{AuthContext, Claims, JwksCache, SharedJwks};
use crate::errors::RestError;

/// Runtime JWT/mTLS parameters pulled from [`crate::config::RestConfig`] or
/// hand-assembled by embedding hosts. Held on `AppState` so handlers can
/// reach the JWKS cache + binding policy.
#[derive(Clone)]
pub struct AuthRuntime {
    pub jwks: SharedJwks,
    pub expected_issuer: String,
    pub expected_audience: Option<String>,
    pub leeway_seconds: u64,
    pub require_cert_binding: bool,
}

/// Shared application state cloned into every handler.
#[derive(Clone)]
pub struct AppState {
    pub core: Arc<HsmCore>,
    /// `None` when the host uses the dev-auth shortcut (env `CRATON_REST_DEV_AUTH=1`).
    pub auth: Option<AuthRuntime>,
}

/// Auth-context extractor: every handler takes `auth: AuthContext`. The
/// context is injected by [`auth_middleware`] into request extensions; this
/// extractor just pulls it out.
#[async_trait]
impl<S: Send + Sync> FromRequestParts<S> for AuthContext {
    type Rejection = RestError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthContext>()
            .cloned()
            .ok_or(RestError::Unauthorized("auth middleware did not attach an AuthContext"))
    }
}

/// Axum extension attached by the TLS acceptor. Carries the
/// base64url-no-pad SHA-256 of the presented client cert's SPKI, already
/// computed to match `jwt.cnf["x5t#S256"]`.
#[derive(Clone, Debug)]
pub struct ClientCertBinding(pub String);

/// Auth middleware.
///
/// Two code paths:
///
/// 1. **Dev-auth** — enabled when `CRATON_REST_DEV_AUTH=1`. Any request is
///    authenticated with scopes from the `X-Dev-Scopes` header (or a sane
///    default). Useful for integration tests; never enable in production.
///
/// 2. **Production** — requires a Bearer JWT that passes
///    [`crate::auth::verify_jwt`] against the configured JWKS, issuer,
///    audience, and leeway. When the app state's [`AuthRuntime`] specifies
///    `require_cert_binding = true`, the request must also carry a
///    [`ClientCertBinding`] extension matching the JWT's `cnf.x5t#S256`.
pub async fn auth_middleware(
    axum::extract::State(state): axum::extract::State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, RestError> {
    // Dev-auth path: enabled only when an explicit env var is set.
    if std::env::var("CRATON_REST_DEV_AUTH").ok().as_deref() == Some("1") {
        let scopes = req
            .headers()
            .get("x-dev-scopes")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("sign verify kem wrap admin attest");
        let ctx = AuthContext {
            subject: "dev".to_string(),
            scopes: crate::auth::parse_scopes(scopes),
            client_spki_b64: None,
        };
        req.extensions_mut().insert(ctx);
        return Ok(next.run(req).await);
    }

    // Production path — the `AuthRuntime` must be configured.
    let runtime = state
        .auth
        .as_ref()
        .ok_or(RestError::Unauthorized(
            "production auth stack not configured (set CRATON_REST_DEV_AUTH=1 or provide AuthRuntime)",
        ))?;

    let bearer = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or(RestError::Unauthorized("missing Bearer token"))?;

    let claims = crate::auth::verify_jwt(
        bearer,
        &runtime.jwks,
        &runtime.expected_issuer,
        runtime.expected_audience.as_deref(),
        runtime.leeway_seconds,
    )
    .await?;

    // Extract the mTLS cert binding if the TLS acceptor attached one.
    let client_spki = req
        .extensions()
        .get::<ClientCertBinding>()
        .map(|b| b.0.clone());

    let ctx = crate::auth::build_auth_context(
        claims,
        client_spki,
        runtime.require_cert_binding,
    )?;

    req.extensions_mut().insert(ctx);
    Ok(next.run(req).await)
}

/// Assemble the axum router with every route and the auth middleware.
///
/// Uses dev-auth if the `CRATON_REST_DEV_AUTH` env var is set, otherwise
/// expects [`build_router_with_auth`] to be called with a real `AuthRuntime`.
pub fn build_router(core: Arc<HsmCore>) -> Router {
    build_router_with_auth(core, None)
}

/// Variant that wires in a real JWKS-backed auth runtime.
pub fn build_router_with_auth(core: Arc<HsmCore>, auth: Option<AuthRuntime>) -> Router {
    use crate::routes::*;

    let state = AppState { core, auth };

    #[allow(unused_mut)]
    let mut api = Router::new()
        .route("/v1/capabilities", get(get_capabilities))
        .route("/v1/keys/:handle/sign", post(sign_with_key))
        .route("/v1/keys/:handle/verify", post(verify_with_key))
        .route("/v1/kems/:handle/encapsulate", post(kem_encapsulate))
        .route("/v1/kems/:handle/decapsulate", post(kem_decapsulate))
        .route("/v1/hybrid/compose-sign", post(compose_sign))
        .route("/v1/hybrid/compose-verify", post(compose_verify));

    #[cfg(feature = "hybrid-kem")]
    {
        api = api
            .route("/v1/wrap", post(hybrid_wrap))
            .route("/v1/unwrap", post(hybrid_unwrap));
    }

    let api = api
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        .with_state(state);

    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(|| async { "ok" }))
        .route("/v1/openapi.json", get(openapi_json))
        .merge(api)
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .layer(TraceLayer::new_for_http())
}

async fn openapi_json() -> axum::Json<utoipa::openapi::OpenApi> {
    axum::Json(ApiDoc::openapi())
}

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::routes::get_capabilities,
        crate::routes::sign_with_key,
        crate::routes::verify_with_key,
        crate::routes::kem_encapsulate,
        crate::routes::kem_decapsulate,
        crate::routes::compose_sign,
        crate::routes::compose_verify,
    ),
    components(schemas(
        crate::dto::CapabilitiesResponse,
        crate::dto::SignRequest,
        crate::dto::SignResponse,
        crate::dto::VerifyRequest,
        crate::dto::VerifyResponse,
        crate::dto::EncapsulateRequest,
        crate::dto::EncapsulateResponse,
        crate::dto::DecapsulateRequest,
        crate::dto::DecapsulateResponse,
        crate::dto::ComposeSignRequest,
        crate::dto::ComposeSignResponse,
        crate::dto::ComposeVerifyRequest,
        crate::dto::HybridWrapRequest,
        crate::dto::HybridWrapResponse,
        crate::dto::HybridUnwrapRequest,
        crate::dto::HybridUnwrapResponse,
        crate::errors::ProblemDetails,
    )),
    info(
        title = "Craton HSM REST API",
        description = "Quantum-safe cryptographic operations over HTTPS. JWT-on-mTLS auth per RFC 8705. Every operation delegates to the shared service layer that also backs the PKCS#11 C ABI and language bindings.",
        version = "0.1.0",
        license(name = "Apache-2.0"),
    )
)]
pub struct ApiDoc;
