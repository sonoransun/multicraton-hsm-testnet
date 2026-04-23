// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Craton HSM REST gateway binary.
//!
//! Wires the shared `craton-hsm-rest::build_router` into an HTTPS listener.
//! Configuration comes from `craton_hsm_rest.toml` (path via the
//! `CRATON_HSM_REST_CONFIG` env var) or the built-in dev defaults.

use std::sync::Arc;

use craton_hsm::core::HsmCore;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .json()
        .init();

    // Load HsmCore — uses the same config loader as the daemon and CLI.
    let core = Arc::new(HsmCore::new_default().map_err(|e| anyhow::anyhow!(e.to_string()))?);

    let router = craton_hsm_rest::build_router(core);

    let bind = std::env::var("CRATON_REST_BIND").unwrap_or_else(|_| "127.0.0.1:9443".to_string());
    tracing::info!(%bind, "craton-hsm-rest listening (plain HTTP in dev; wrap with TLS termination for prod)");

    // Dev path: plain HTTP. Production deployments front this with a TLS
    // terminator (nginx, envoy) or extend `main.rs` to load a TLS config
    // from `RestConfig::tls`.
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    axum::serve(listener, router).await?;
    Ok(())
}
