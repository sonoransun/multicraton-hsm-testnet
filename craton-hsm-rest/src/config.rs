// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! REST server configuration.
//!
//! Loads from `craton_hsm_rest.toml` (or `CRATON_HSM_REST_CONFIG`) and layers
//! environment variables on top. The design intentionally reuses the same
//! TLS / PIN configuration formats used by `craton-hsm-daemon` so operators
//! can run both binaries out of a single deployment artefact.

use serde::Deserialize;
use std::path::PathBuf;

/// Top-level REST config.
#[derive(Debug, Clone, Deserialize)]
pub struct RestConfig {
    /// Socket address to bind (`0.0.0.0:9443` by default).
    #[serde(default = "default_bind")]
    pub bind: String,

    /// TLS + mTLS options. Cert/key paths are relative to the config file.
    pub tls: TlsConfig,

    /// JWT issuer + JWKS location.
    pub jwt: JwtConfig,

    /// Maximum request body size (bytes). Defaults to 16 MiB which is ample
    /// for wrap/unwrap of FrodoKEM-1344-sized payloads.
    #[serde(default = "default_body_limit")]
    pub max_body_bytes: usize,

    /// Rate limit: requests per second per (JWT sub, cert SPKI) pair.
    #[serde(default = "default_rate_limit")]
    pub rate_per_second: u64,
}

fn default_bind() -> String { "0.0.0.0:9443".to_string() }
fn default_body_limit() -> usize { 16 * 1024 * 1024 }
fn default_rate_limit() -> u64 { 100 }

#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    /// Server certificate chain (PEM).
    pub cert_path: PathBuf,
    /// Server private key (PEM).
    pub key_path: PathBuf,
    /// Required CA for mTLS client certs (PEM). If absent, TLS is still
    /// required but mTLS is not — JWT-only auth will apply and the RFC 8705
    /// cert-binding check is skipped.
    pub client_ca_path: Option<PathBuf>,
    /// Minimum TLS version. Defaults to 1.3.
    #[serde(default = "default_min_tls")]
    pub min_version: String,
}

fn default_min_tls() -> String { "1.3".to_string() }

#[derive(Debug, Clone, Deserialize)]
pub struct JwtConfig {
    /// Expected issuer (`iss`) — rejects JWTs from other issuers.
    pub expected_issuer: String,
    /// Expected audience (`aud`) — optional; when present, checked exactly.
    #[serde(default)]
    pub expected_audience: Option<String>,
    /// Either a static JWKS file path, or an HTTPS URL the REST server
    /// periodically fetches.
    pub jwks_source: JwksSource,
    /// Clock-skew tolerance for `exp`/`nbf` checks (seconds).
    #[serde(default = "default_clock_skew")]
    pub leeway_seconds: u64,
    /// When `true` (the default), require RFC 8705 `cnf.x5t#S256` JWT binding.
    /// Set to `false` only in dev when mTLS isn't available.
    #[serde(default = "default_require_cert_binding")]
    pub require_cert_binding: bool,
}

fn default_clock_skew() -> u64 { 30 }
fn default_require_cert_binding() -> bool { true }

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum JwksSource {
    /// JWKS loaded from a local JSON file.
    File { path: PathBuf },
    /// JWKS fetched from a URL (not implemented in this scaffold).
    Url { url: String },
}

impl RestConfig {
    /// Load the REST config from disk.
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let s = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&s)?)
    }
}
