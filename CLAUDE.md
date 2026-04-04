# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Craton HSM is a PKCS#11 v3.0-compliant Software Hardware Security Module written in pure Rust. It provides cryptographic services through a standard C ABI, a gRPC daemon, and an admin CLI.

**Not FIPS 140-3 certified** — this software has not undergone CMVP validation.

## Workspace Structure

This is a Cargo workspace with the following crates:

- **craton-hsm** (root): Core PKCS#11 library (`cdylib` + `rlib`)
- **craton-hsm-daemon**: gRPC server with mutual TLS for remote HSM access
- **tools/craton-hsm-admin**: CLI for token management, PIN operations, diagnostics
- **tools/pkcs11-spy**: PKCS#11 spy/logging wrapper for debugging

## Build Commands

```bash
# Debug build (core library only)
cargo build

# Release build (core library only)
cargo build --release

# Full workspace (requires protoc for gRPC daemon)
cargo build --workspace --release

# With optional features
cargo build --release --features "enterprise"
cargo build --release --features "awslc-backend,fips"
cargo build --release --features "quantum-resistant,wrapped-keys"
```

Library output: `target/release/libcraton_hsm.{so,dylib,dll}` (cdylib) and rlib.

## Testing

**Critical**: All tests MUST run single-threaded due to global PKCS#11 state (one `C_Initialize`/`C_Finalize` per process).

```bash
# Full test suite (safe default)
cargo test -- --test-threads=1

# Run a specific test file
cargo test --test pkcs11_compliance -- --test-threads=1

# Run a specific test function
cargo test test_c_initialize -- --test-threads=1

# Workspace member tests
cargo test -p craton-hsm-admin -p pkcs11-spy -p craton-hsm-daemon -- --test-threads=1
```

### Parallel-Safe Tests

These tests use no global PKCS#11 state and can run with higher parallelism:

```bash
cargo test --lib --test crypto_vectors --test drbg_tests --test concurrent_stress \
  --test audit_and_integrity --test zeroization --test integrity_tests --test multi_slot \
  -- --test-threads=8
```

### Serial PKCS#11 ABI Tests

These require serial execution due to `C_Initialize`/`C_Finalize` global state:

```bash
cargo test --test attribute_management --test pkcs11_compliance \
  --test session_state_machine -- --test-threads=1
```

## Linting and Formatting

```bash
cargo fmt --check          # Format check
cargo fmt                  # Apply formatting

# Clippy (denies correctness and suspicious lints)
cargo clippy --workspace -- -D clippy::correctness -D clippy::suspicious

# Dependency license/security audit (see deny.toml)
cargo deny check
```

Note: `deny.toml` ignores `RUSTSEC-2023-0071` (RSA Marvin Attack) — no fix available yet; mitigated by not exposing raw RSA decryption.

## Architecture

### Core Components

- **HsmCore** (`src/core.rs`): Central state manager holding `slot_manager`, `session_manager`, `object_store`, `audit_log`, `crypto_backend`, `drbg`, and `algorithm_config`. Use `new()` for defaults or `new_with_backend()` to inject an external `CryptoBackend`.
- **pkcs11_abi/** (`src/pkcs11_abi/`): C ABI layer — `types.rs` (PKCS#11 type defs), `constants.rs` (CK_ constants), `functions.rs` (~68 `#[no_mangle]` exports). Uses `#[allow(non_camel_case_types, non_snake_case)]`.
- **session/** (`src/session/`): `SessionManager` using `DashMap<CK_SESSION_HANDLE, Arc<RwLock<Session>>>`. Sessions track `SessionState` (RoPublic/RoUser/RwPublic/RwUser/RwSO) and `ActiveOperation` contexts. Includes thread-local caching (`tls_cache`).
- **token/** (`src/token/`): Token/slot management, PIN lifecycle, multi-slot support.
- **store/** (`src/store/`): Encrypted redb backend (`encrypted_store.rs`) with AES-256-GCM + PBKDF2-derived keys. `StoredObject` carries full PKCS#11 attributes and SP 800-57 key lifecycle states. Also contains `wrapped_key.rs` (import/export), `backup.rs`, `key_cache.rs`, `lockout_store.rs`.
- **crypto/** (`src/crypto/`): Pluggable backends via `CryptoBackend` trait (`backend.rs`). Includes `sign.rs`, `encrypt.rs`, `digest.rs`, `keygen.rs`, `derive.rs`, `wrap.rs`, `drbg.rs` (SP 800-90A HMAC_DRBG), `pqc.rs` (ML-KEM/ML-DSA/SLH-DSA), `self_test.rs` (17 POST KATs), `integrity.rs`, `bls.rs`, `hybrid_kem.rs`.
- **audit/** (`src/audit/`): Tamper-evident append-only audit log with chained SHA-256 hashes.
- **config/** (`src/config/`): TOML-based `HsmConfig` with algorithm policy. Runtime config via `craton_hsm.toml`.
- **cluster/** (`src/cluster/`): Raft consensus (`consensus.rs`), key replication, membership management, `ClusterTransport` with mTLS/QUIC/Noise Protocol transport.
- **error.rs**: `HsmError` enum (64 variants) with `From<HsmError> for CK_RV` mapping to PKCS#11 return codes.
- **metrics/** (`src/metrics/`, feature `observability`): Prometheus metrics + HTTP server.

### Crypto Backend System

Two backends via the `CryptoBackend` trait:

- **RustCrypto** (default, feature `rustcrypto-backend`): Pure Rust
- **aws-lc-rs** (optional, feature `awslc-backend`): FIPS 140-3 validated

### Rand Ecosystem Version Split

**Important gotcha**: The PQC crates (`ml-kem`, `ml-dsa`, `slh-dsa`) depend on `rand_core` 0.10 / `getrandom` 0.4, while classical RustCrypto crates use `rand_core` 0.6 / `getrandom` 0.2. The newer versions are aliased in `Cargo.toml` as `rand_core_new` and `getrandom_new`. When adding new crypto code, use the correct `rand_core` version for the ecosystem you're targeting.

### Security Properties

- Key material locked via `mlock()`/`VirtualLock()` to prevent swapping
- All sensitive data implements `ZeroizeOnDrop`; PIN verification uses constant-time comparison
- 17 Power-On Self-Tests (POST) run before any cryptographic service (integrity check + 16 KATs)
- Fork detection reinitializes state to prevent key material leakage

## Feature Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `rustcrypto-backend` | yes | Pure Rust crypto backend |
| `awslc-backend` | — | FIPS 140-3 validated AWS-LC backend |
| `fips` | — | FIPS-only mode |
| `quantum-resistant` | — | ML-KEM, ML-DSA, SLH-DSA |
| `wrapped-keys` | — | Key import/export (JSON, PKCS#8, PKCS#12) |
| `observability` | — | Prometheus metrics + HTTP server |
| `enterprise` | — | `wrapped-keys` + `observability` |
| `blake3-hash` | — | BLAKE3 parallel tree-hashing |
| `hybrid-kem` | — | X25519 + ML-KEM-768 dual KEM |
| `chacha20-aead` | — | ChaCha20-Poly1305 / XChaCha20 AEAD |
| `argon2-kdf` | — | Argon2id memory-hard KDF |
| `bls-signatures` | — | BLS12-381 aggregatable signatures |
| `opaque-auth` | — | OPAQUE augmented PAKE (RFC 9497) |
| `stark-proofs` | — | STARK proofs via Winterfell |
| `fhe-compute` | — | FHE via tfhe-rs (large build footprint) |
| `tpm-binding` | — | TPM 2.0 via tss-esapi (requires libtss2) |
| `wasm-plugins` | — | WASM plugins via Wasmtime (~50 MB debug) |
| `quic-transport` | — | QUIC cluster transport via quinn |
| `noise-protocol` | — | Noise Protocol encrypted channels |
| `advanced-all` | — | Most features (excludes fhe-compute, tpm-binding, quic-transport, wasm-plugins due to build size) |

## Error Handling

All internal errors use the `HsmError` enum (`src/error.rs`), which maps to PKCS#11 `CK_RV` return codes via `impl From<HsmError> for CK_RV`.

## Adding New Crypto Operations

1. Implement in the appropriate `src/crypto/` module
2. Add mechanism constant to `src/pkcs11_abi/constants.rs`
3. Wire up in `src/pkcs11_abi/functions.rs`
4. Add tests following existing patterns

## Disabled and Placeholder Modules

- **`src/advanced/`**: Feature-gated. `zkp`, `threshold`, `gpu_crypto`, `analytics`, `policy` are placeholder implementations. Fully implemented: `fhe.rs`, `tpm.rs`, `stark.rs`, `wasm_plugin.rs`, `attestation.rs` (always compiled).
- **`src/crypto/enhanced_backend.rs`** and **`enhanced_rustcrypto_backend.rs`**: Currently disabled.

## Benchmarking

```bash
cargo bench --bench crypto_bench

# PKCS#11 ABI benchmarks (needs SoftHSMv2 for comparison)
SOFTHSM2_LIB=/usr/lib/softhsm/libsofthsm2.so cargo bench --bench pkcs11_abi_bench
```

## Other Tools

```bash
# Admin CLI
cargo build -p craton-hsm-admin && ./target/debug/craton-hsm-admin --help

# PKCS#11 spy for debugging
cargo build -p pkcs11-spy
PKCS11_SPY_OUTPUT=/tmp/pkcs11.log  # use spy library instead of main library

# Miri (undefined behavior detection)
cargo +nightly miri test --lib -- --test-threads=1 crypto::zeroize crypto::digest

# Fuzzing
cargo +nightly fuzz run <target_name>

# Documentation
cargo doc --no-deps --open
```
