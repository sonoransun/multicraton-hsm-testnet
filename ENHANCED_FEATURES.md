# Enhanced & Advanced Features

This document is an overview of the "enhanced/advanced" feature area of Craton
HSM: the optional modules that sit on top of the core PKCS#11 library. It
describes **what actually exists in the tree today** and separates that from
work that is planned but not yet implemented.

> **Not FIPS 140-3 certified.** Nothing described here has undergone CMVP
> validation. Treat performance and security claims as design intent unless a
> benchmark or test in the repo backs them up.

## What exists today

### Performance caches (always compiled)

- **RSA key cache** — `src/store/key_cache.rs`. Parsed `RsaPrivateKey`/public
  key structs are cached (keyed by SHA-256 of the DER) so PKCS#8 parsing and
  bignum reconstruction are not repeated on every operation. See
  `src/store/object.rs` for how objects hook into the cache.
- **Thread-local session caching** — `src/session/tls_cache.rs`, wired up in
  `src/session/manager.rs`. Reduces lock acquisitions on session hot paths and
  caches operation context between Init/Update/Final calls.

For measured, reproducible numbers see [`docs/benchmarks.md`](docs/benchmarks.md)
— that file is the source of truth for performance, not this overview.

### Enhanced HSM core (always compiled)

- `src/core/enhanced.rs` exposes `EnhancedHsmCore` and `EnhancedHsmConfig`, a
  wrapper around `HsmCore` that bundles the caches, performance counters
  (`EnhancedPerformanceMetrics`), and configuration knobs behind one interface.
  Existing `HsmCore` callers are unaffected.

### Clustering — feature `networking`

`src/cluster/` (Raft consensus, key replication, membership, network transport,
and a distributed-operations coordinator). Compiles only with the `networking`
feature flag. Modules present: `mod.rs`, `consensus.rs`, `replication.rs`,
`membership.rs`, `network.rs`, `coordinator.rs`. This is substantial code but has
not been validated for production HA use — exercise it before relying on it.

### Advanced module — `src/advanced/`

Gated behind the advanced feature flags (`advanced-all`, `fhe-compute`,
`tpm-binding`, `stark-proofs`, `wasm-plugins`, `zkp`, `threshold`,
`gpu-acceleration`, `ml-analytics`, `policy-engine`, `quantum-resistant`).

- **Implemented:** `fhe.rs`, `tpm.rs`, `stark.rs`, `wasm_plugin.rs`,
  `attestation.rs`.
- **Placeholder implementations** (structure present, logic incomplete):
  `zkp.rs`, `threshold.rs`, `gpu_crypto.rs`, `analytics.rs`, `policy.rs`.

### Post-quantum cryptography — feature `quantum-resistant`

ML-KEM, ML-DSA, and SLH-DSA live in `src/crypto/pqc.rs` (see also
`src/crypto/hybrid_kem.rs` for X25519 + ML-KEM-768 under the `hybrid-kem`
feature). There is no alternative backend for PQC.

### Crypto backends

Classical crypto goes through the `CryptoBackend` trait (`src/crypto/backend.rs`)
with two implementations: `src/crypto/rustcrypto_backend.rs` (default) and
`src/crypto/awslc_backend.rs` (feature `awslc-backend`, FIPS-validated
primitives). There is no separate "enhanced" backend.

## Planned (not implemented)

The following were described in earlier drafts of this document but do **not**
exist in the tree. They are recorded here as intent, not shipped features:

- **Enhanced crypto backend** (`enhanced_backend.rs` /
  `enhanced_rustcrypto_backend.rs`) — extra signature schemes (RSA-PSS with
  SHA-3, Ed448, secp256k1), additional KDFs, and SHA-3 family support as a
  distinct backend. No such files exist.
- **Hardware-acceleration framework** — Intel QAT / ARM CryptoCell integration
  and CPU-feature-driven dispatch. Not implemented. (Compiler-level
  `target-cpu=native` codegen is the only hardware acceleration in use today;
  see `docs/benchmarks.md`.)
- **Stack-allocated signature buffers** as a zero-copy backend interface. Not
  implemented.
- **FIPS 140-3 certification, cloud-KMS bridges, KMIP, WebAuthn/FIDO2, and
  formal verification** — none of these are present.

## Notes for contributors

- Keep this file honest. If you add a module, link its real path here; if you
  remove one, delete the reference. Do not add performance numbers here — put
  reproducible benchmarks in `docs/benchmarks.md` and link them.
- Feature-flag semantics live in `CLAUDE.md` and `Cargo.toml`; this file should
  not restate the full flag table.
