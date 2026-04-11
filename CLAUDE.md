# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Craton HSM is a PKCS#11 v3.0-compliant Software Hardware Security Module written in pure Rust. It provides cryptographic services through a standard C ABI, a gRPC daemon, and an admin CLI.

**Not FIPS 140-3 certified** — this software has not undergone CMVP validation.

## Workspace Structure

This is a Cargo workspace with the following crates:

- **craton-hsm** (root): Core PKCS#11 library (`cdylib` + `rlib`)
- **craton-hsm-daemon**: gRPC server with mutual TLS for remote HSM access (requires `protoc`)
- **tools/craton-hsm-admin**: CLI for token management, PIN operations, diagnostics
- **tools/pkcs11-spy**: PKCS#11 spy/logging wrapper for debugging

Non-crate directories worth knowing about:

- **`docs/`**: 20+ detailed design documents. For deep dives, see `architecture.md`, `fork-safety.md`, `security-model.md`, `fips-gap-analysis.md`, and `operator-runbook.md`.
- **`kreya/`**: Kreya gRPC collections (`CratonHSM-gRPC.krproj` + envs) for manual daemon testing.
- **`deploy/`**: `Dockerfile`, `docker-compose.cluster.yml`, Helm chart, and `gen-test-certs.sh` for local mTLS setup.
- **`fuzz/`**: 12 cargo-fuzz targets in `fuzz/fuzz_targets/`.

MSRV: Rust 1.75 (`rust-version` in Cargo.toml). Toolchain pinned to stable via `rust-toolchain.toml`.

## Build Commands

**Prerequisites**: `protoc` is required for `craton-hsm-daemon` (gRPC codegen). `libtss2-dev` is required when building the `tpm-binding` feature. The core library builds without either.

```bash
# Debug build (core library only)
cargo build

# Release build (core library only — slow: LTO + codegen-units=1)
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

> **⚠ Default to `cargo test -- --test-threads=1`.** The C ABI holds a single global `static HSM: parking_lot::Mutex<Option<Arc<HsmCore>>>` in `src/pkcs11_abi/functions.rs` — running PKCS#11 tests in parallel corrupts the one-per-process `C_Initialize`/`C_Finalize` lifecycle. Only the explicitly-listed parallel-safe tests below may use higher `--test-threads`.

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

`lib.rs` has `#![warn(missing_docs)]` — new public items need doc comments.

Note: `deny.toml` ignores `RUSTSEC-2023-0071` (RSA Marvin Attack) — no fix available yet; mitigated by not exposing raw RSA decryption.

### Local CI

Two scripts exist in `scripts/` and both mirror GitHub Actions CI. **Prefer `ci-local.sh`** — it's the richer of the two and has a `quick` subcommand for the everyday feedback loop:

```bash
./scripts/ci-local.sh              # Run all jobs
./scripts/ci-local.sh quick        # fmt + test + clippy (fastest useful check)
./scripts/ci-local.sh test         # Build & test only
```

`ci-local.sh` also supports: `fmt`, `clippy`, `audit`, `miri`, `docs`, `coverage`, `semver`.

`scripts/local-ci.sh` is a parallel implementation that covers the same jobs minus `quick`/`coverage` but adds `bench`. Use it only if you specifically need `bench` as part of the CI sweep.

## Architecture

### Global State and Request Flow

The C ABI entrypoint is `src/pkcs11_abi/functions.rs`, which exports ~68 `#[no_mangle]` PKCS#11 functions. These all access the global `static HSM` (a `Mutex<Option<Arc<HsmCore>>>`) with a thread-local cache (`CACHED_HSM`) for fast-path access. A generation counter is bumped on every `C_Initialize`/`C_Finalize` (and on fork recovery) so stale thread-local caches are detected and invalidated — threads compare their cached generation against the global one before using the cached `Arc`. Fork detection (`INIT_PID`) reinitializes state to prevent key material leakage in child processes.

### Core Components

- **HsmCore** (`src/core.rs`): Central state manager holding `slot_manager`, `session_manager`, `object_store`, `audit_log`, `crypto_backend`, `drbg`, and `algorithm_config`. Use `new()` for defaults or `new_with_backend()` to inject an external `CryptoBackend`.
- **pkcs11_abi/** (`src/pkcs11_abi/`): C ABI layer — `types.rs` (PKCS#11 type defs), `constants.rs` (CK_ constants), `functions.rs` (exports). Uses `#[allow(non_camel_case_types, non_snake_case)]`.
- **session/** (`src/session/`): `SessionManager` using `DashMap<CK_SESSION_HANDLE, Arc<RwLock<Session>>>`. Sessions track `SessionState` (RoPublic/RoUser/RwPublic/RwUser/RwSO) and `ActiveOperation` contexts. Includes thread-local caching (`tls_cache`).
- **token/** (`src/token/`): Token/slot management, PIN lifecycle, multi-slot support.
- **store/** (`src/store/`): Encrypted redb backend (`encrypted_store.rs`) with AES-256-GCM + PBKDF2-derived keys. `StoredObject` carries full PKCS#11 attributes and SP 800-57 key lifecycle states. Also contains `wrapped_key.rs` (import/export), `backup.rs`, `key_cache.rs`, `lockout_store.rs`.
- **crypto/** (`src/crypto/`): Pluggable backends via `CryptoBackend` trait (`backend.rs`). Includes `sign.rs`, `encrypt.rs`, `digest.rs`, `keygen.rs`, `derive.rs`, `wrap.rs`, `drbg.rs` (SP 800-90A HMAC_DRBG), `pqc.rs` (ML-KEM/ML-DSA/SLH-DSA), `self_test.rs` (17 POST KATs), `integrity.rs`, `bls.rs`, `hybrid_kem.rs`.
- **audit/** (`src/audit/`): Tamper-evident append-only audit log with chained SHA-256 hashes.
- **config/** (`src/config/`): TOML-based `HsmConfig` with algorithm policy. Runtime config via `craton_hsm.toml`.
- **cluster/** (`src/cluster/`): Raft consensus, key replication, membership management. **Requires `networking` feature flag.**
- **error.rs**: `HsmError` enum (64 variants, intentionally no `Copy` derive) with `From<HsmError> for CK_RV` mapping to PKCS#11 return codes.
- **metrics/** (`src/metrics/`, feature `observability`): Prometheus metrics + HTTP server.

### Feature-Gated Modules

- **`cluster`** module requires `networking` feature
- **`advanced`** module compiles when any of: `advanced-all`, `fhe-compute`, `tpm-binding`, `stark-proofs`, `wasm-plugins`, `zkp`, `threshold`, `gpu-acceleration`, `ml-analytics`, `policy-engine`, `quantum-resistant`

### Crypto Backend System

Two backends via the `CryptoBackend` trait (covers classical crypto only; PQC has no alternative backends):

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
| `networking` | — | Enables `cluster` module (Raft, mTLS, transport) |
| `blake3-hash` | — | BLAKE3 parallel tree-hashing |
| `hybrid-kem` | — | X25519 + ML-KEM-768 dual KEM |
| `chacha20-aead` | — | ChaCha20-Poly1305 / XChaCha20 AEAD |
| `argon2-kdf` | — | Argon2id memory-hard KDF |
| `bls-signatures` | — | BLS12-381 aggregatable signatures |
| `stark-proofs` | — | STARK proofs via Winterfell |
| `fhe-compute` | — | FHE via tfhe-rs (large build footprint) |
| `tpm-binding` | — | TPM 2.0 via tss-esapi (requires libtss2) |
| `wasm-plugins` | — | WASM plugins via Wasmtime (~50 MB debug) |
| `quic-transport` | — | QUIC cluster transport via quinn |
| `noise-protocol` | — | Noise Protocol encrypted channels |
| `advanced-all` | — | Most features (excludes fhe-compute, tpm-binding, quic-transport, wasm-plugins due to build size) |

**Disabled features**: `opaque-auth` and `voprf-protocol` are commented out in Cargo.toml due to `curve25519-dalek` version conflicts with `opaque-ke`.

## Error Handling

All internal errors use the `HsmError` enum (`src/error.rs`), which maps to PKCS#11 `CK_RV` return codes via `impl From<HsmError> for CK_RV`.

## Adding New Crypto Operations

1. Implement in the appropriate `src/crypto/` module
2. Add mechanism constant to `src/pkcs11_abi/constants.rs`
3. Wire up in `src/pkcs11_abi/functions.rs`
4. Add tests following existing patterns

## Disabled and Placeholder Modules

- **`src/advanced/`**: Feature-gated. `zkp`, `threshold`, `gpu_crypto`, `analytics`, `policy` are placeholder implementations. Fully implemented: `fhe.rs`, `tpm.rs`, `stark.rs`, `wasm_plugin.rs`, `attestation.rs` (compiled whenever the `advanced` module is active).

Note: `attestation.rs` uses `ciborium` (not the unmaintained `serde_cbor`) for CBOR framing of AWS Nitro NSM requests. `tpm.rs` and `attestation.rs` expose substantive APIs (`tpm_seal`/`tpm_unseal` under PCR 0/2/7 policy, TDX/SEV-SNP/Nitro ioctl paths) but are **not yet wired into the HSM init path** — nothing in `HsmCore` currently calls them. Wiring them into the boot/self-test flow and into an optional `KekProvider` for the encrypted store is tracked as future work.

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

# Fuzzing (12 fuzz targets in fuzz/fuzz_targets/)
cargo +nightly fuzz run <target_name>

# Documentation
cargo doc --no-deps --open
```
