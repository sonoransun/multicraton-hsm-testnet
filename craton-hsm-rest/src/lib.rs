// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Craton HSM REST gateway.
//!
//! An axum-based HTTP/JSON gateway that exposes every PQ-safe cryptographic
//! operation as REST endpoints under `/v1/*`, backed by an `HsmCore` instance.
//! The router is available both as a standalone binary (`craton-hsm-rest`) and
//! as a library surface via [`build_router`] for embedding in tests or
//! Kubernetes sidecar hosts.
//!
//! ## Authentication
//!
//! Default is **JWT-on-mTLS**: the client must present a valid mTLS cert AND
//! a Bearer JWT whose `cnf["x5t#S256"]` claim (per RFC 8705) matches the
//! SHA-256 hash of the client cert's SPKI. Scopes in the JWT `scope` claim
//! (`sign`, `kem`, `wrap`, `admin`, `attest`) gate routes.
//!
//! ## Routes
//!
//! See [`routes`] for the full catalog. Schemas are generated as
//! OpenAPI 3.1 at `/v1/openapi.json`.

#![allow(clippy::needless_return)]

pub mod auth;
pub mod config;
pub mod dto;
pub mod errors;
pub mod router;
pub mod routes;

pub use router::{build_router, AppState};
