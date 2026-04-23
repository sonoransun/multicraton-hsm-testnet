# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Unreleased — Stub-reduction batch

### Added
- **Service-layer keygen** (`src/service/keygen.rs`) — `HsmResult`-returning wrapper around the PKCS#11 keygen dispatcher so REST / vendor-ext / bindings share the same path.
- **`service::rotate::rotate_key`** — atomic PQ key rotation with lifecycle transition of the retired key (`Deactivated` or `Compromised` per policy). Unit tests verify both transitions.
- **`service::attest::attested_keygen`** — keygen plus a CBOR attestation statement binding the new public key to host measurements under a caller nonce. Platform defaults to `software`; upgrades to TDX / SEV-SNP / Nitro quotes when the `advanced` attestation module is compiled in. Includes a `parse_statement` helper.
- **Vendor extensions** (`feature = "vendor-ext"`):
  - `CratonExt_PQKeyRotate` — now a real implementation routed through `service::rotate`.
  - `CratonExt_AttestedKeygen` — now real, with standard PKCS#11 two-call size-probing for the statement buffer.
  - New helper `infer_mechanism_from_handle` inside `src/pkcs11_abi/ext/vendor_table.rs` so the rotate path can reconstruct the mechanism from `CKK_*` + public-key byte length.
- **REST production auth stack** (`craton-hsm-rest`):
  - `auth::JwksCache` with file-based loading plus an async API ready for URL refresh.
  - `auth::verify_jwt` enforcing `iss` / `aud` / `exp` / `nbf` with configurable leeway, `kid` → JWKS lookup, and RS256/384/512 + PS256/384/512 + ES256/384 + EdDSA algorithms.
  - `router::AuthRuntime` + `build_router_with_auth` to wire the full JWKS + mTLS binding stack; the dev-auth shortcut remains available via `CRATON_REST_DEV_AUTH=1`.
  - `router::ClientCertBinding` extension shape for the TLS acceptor to attach the RFC-8705 SPKI hash.
- **Cluster**:
  - `RaftConsensus::add_node` / `::remove_node` now mutate a real in-memory membership map (`Arc<RwLock<ClusterConfiguration>>`), bumping the config version atomically. Duplicate-add / absent-remove surface as descriptive errors.
  - `ReplicationManager::get_local_object` reads from the live object store instead of returning `ReplicationError`.
  - `NetworkManager::verify_certificate` matches the presented cert against the pinned `node_certs` registry; returns a useful error (with SHA-256 fingerprint) on miss.

### Changed
- `src/advanced/quantum_resistant.rs` — deleted the placeholder ghost-keygen + ghost-encap bodies that previously produced random bytes instead of real PQC. Every ML-KEM / ML-DSA / SLH-DSA operation now delegates to `crate::crypto::pqc`, so the `quantum-resistant` feature build compiles again. `PqcKeyPair` now has a manual `Drop` impl zeroing private-key bytes (the `Zeroize` derive can't handle the non-`Zeroize` fields on the struct).
- Vendor-ext integration test file (`tests/vendor_ext_abi.rs`) extended with `pq_key_rotate_via_vendor_table` and `attested_keygen_cbor_statement_parses`.
- Documentation: `docs/vendor-extensions.md` describes the now-real `PQKeyRotate` and `AttestedKeygen`, including the CBOR statement layout. `docs/rest-api.md` describes the real JWT + JWKS + mTLS-binding stack.

### Deferred
- **PKCS#12 export / import** in `src/store/wrapped_key.rs` still returns `FunctionNotSupported`. PKCS#12 PFX construction needs full ASN.1 nesting (AuthenticatedSafe + SafeBag + optional PBE) and was descoped from this batch to keep the session focused.
- **TPM wiring** in `src/advanced/tpm.rs` remains a feature-gated stub — `tss-esapi` API research was deferred.
- **Go proto-stub generation** — `bindings/go/client.go` still returns `ErrNotImplemented`. Needs `protoc` / `buf` toolchain fetch.

## [0.9.1] - 2026-03-20 (Security Audit Hardening)

### Security Fixes
- **CRITICAL: DRBG bypass in key generation** — RSA, EC P-256/P-384, and Ed25519 key generation was using `OsRng` directly, bypassing the SP 800-90A HMAC_DRBG health checks. All key generation now routes through a `DrbgRng` wrapper implementing `rand::RngCore + rand::CryptoRng`. (`crypto/keygen.rs`)
- **HIGH: Per-key AES-GCM nonce counters** — The GCM encryption counter was global (shared across all keys), meaning a multi-key workload could hit the 2^32 birthday bound prematurely. Changed to per-key counters using `DashMap<u64, AtomicU64>` keyed by SHA-256 hash of key material. Counters reset on `C_Initialize`. (`crypto/encrypt.rs`)
- **HIGH: Circular KATs replaced** — AES-CBC and AES-CTR POST self-tests were circular (encrypt→decrypt roundtrip), which would pass even if both paths had the same symmetric bug. Replaced with genuine known-answer tests using hardcoded expected ciphertexts. (`crypto/self_test.rs`)
- **HIGH: RSA PKCS#1 v1.5 KAT added** — POST was missing an RSA signing KAT entirely. Added RSA-2048 PKCS#1 v1.5 sign/verify roundtrip. POST now has 17 self-tests (integrity + 16 KATs). (`crypto/self_test.rs`)
- **MEDIUM: RSA public key size validation** — `validate_rsa_public_key_size` didn't strip leading zero bytes before counting significant bits, potentially accepting keys that appear larger than they are. (`crypto/sign.rs`)
- **MEDIUM: All-zero IV rejection at C_EncryptInit** — AES-CBC and AES-CTR previously accepted all-zero IVs at `C_EncryptInit` time (rejection only happened later in `C_Encrypt`). Zero IVs are now rejected early in `C_EncryptInit`. (`pkcs11_abi/functions.rs`)
- **MEDIUM: POST_FAILED reset on re-initialization** — `POST_FAILED` was never cleared, meaning after `C_Finalize` → `C_Initialize`, a previous POST failure would permanently block the module. Now reset before re-running POST. (`pkcs11_abi/functions.rs`)
- **MEDIUM: Session count race in close_all_sessions** — Fixed to track actual removed counts instead of zeroing all counters, which could affect session counts for other slots. (`session/manager.rs`)
- **LOW: Config path traversal hardening** — Added UNC path rejection (`\\server\share` and `//server/share`) and literal `..` segment check as defense-in-depth. (`config/config.rs`)
- **LOW: RSA DER key material copy eliminated** — Removed unnecessary `.clone()` of RSA private key DER bytes that created an unzeroized copy in memory. (`crypto/keygen.rs`)
- **LOW: AES-GCM max plaintext size check** — Added NIST SP 800-38D maximum plaintext length enforcement (2^36 - 32 bytes). (`crypto/encrypt.rs`)

### Changed
- Software integrity check (`crypto/integrity.rs`) now uses opt-in model: `.hmac` sidecar file presence triggers verification. Without the file, the check passes (development/test/non-FIPS deployments). With `fips` feature, the `.hmac` file is mandatory.
- POST self-test count increased from 15 to 17 (added RSA PKCS#1 v1.5 KAT, software integrity counts separately)

### Added
- **PKCS#11 conformance test suite** (`tests/pkcs11_conformance.rs`) — 46 comprehensive tests covering:
  - AES-CBC/CTR zero IV rejection
  - Double session close safety
  - PIN complexity and length validation
  - Init/finalize lifecycle and re-initialization
  - Null pointer handling for all info functions
  - Invalid slot/session/user type error paths
  - AES-GCM encrypt/decrypt roundtrip via ABI
  - RSA-2048 keygen + PKCS#1 v1.5 sign/verify via ABI
  - EC P-256 keygen + ECDSA sign/verify via ABI
  - SHA-256 digest via ABI
  - FindObjects lifecycle and DestroyObject
  - Operation state save/restore for digest
  - Multi-part digest (SHA-256)
  - Login lockout after max failed attempts
  - Mechanism list and info validation
  - Token info flags and version checks
  - Configuration validation (path traversal, absolute paths, UNC paths, PBKDF2 floor)
  - Audit log chain integrity and injection prevention
- Total test count: 617+ (46 new conformance tests)

## [0.9.0] - 2026-02-24 (Phases 12–13: Release Polish & Roadmap Items)

### Changed (Phase 12: Release Polish)
- Version synchronized across all workspace crates (0.9.0 / 0.3.0)
- License changed to Apache-2.0
- Added Cargo.toml metadata: repository, homepage, keywords, categories
- Added `[profile.release]` with LTO, codegen-units=1, strip=symbols
- Created ROADMAP.md documenting all 12 phases and future directions
- Updated docs (architecture, audit-scope, PRESENTATION, FIPS certification, security-policy) to v0.9.0

### Added (Phase 13: Actionable Roadmap Items)
- **Audit log export**: JSON, NDJSON (JSON Lines for SIEM), syslog RFC 5424 format
- **Audit chain verification**: `verify_chain()` validates SHA-256 hash chain integrity
- **Admin CLI audit commands**: `audit export-json`, `audit export-ndjson`, `audit export-syslog`, `audit verify-chain`
- **macOS CI**: Added `macos-latest` to GitHub Actions build matrix
- **Code coverage CI**: `cargo-tarpaulin` job with HTML/XML report artifacts
- **Future work guide**: `docs/future-work-guide.md` with detailed instructions for PQC upgrades, rand_core unification, FIPS certification, HSM clustering, and KMIP support
- 9 new audit export/chain tests — 580+ total

### Added (Phase 10-11)
- **Multi-slot support**: Configurable via `slot_count` in `[token]` section of craton_hsm.toml (default: 1, backward compatible)
- **C_GetOperationState / C_SetOperationState**: Save and restore digest/sign/verify operations mid-stream across sessions
- **HSM backup/restore**: `craton-hsm-admin backup` / `restore` subcommands with AES-256-GCM encrypted backup files (PBKDF2 key derivation)
- `ObjectStore::export_all_objects()` method for backup support
- 24 new tests: multi_slot (8), operation_state (8), backup_restore (8) — 571 total

### Changed
- `HsmCore` fields restricted to `pub(crate)` with public accessor methods (internal encapsulation)
- `#[must_use]` attribute on `HsmError` enum
- `#![forbid(unsafe_code)]` enforced on safe modules (audit, session, config, store, token)

### Removed
- Unused `bincode` dependency

### Known Issues
- PQC crates (ml-kem, ml-dsa, slh-dsa) remain at RC versions — no stable releases available as of March 2026
- Dual rand_core versions (0.6 + 0.10) required until PQC ecosystem unifies

## [0.8.0] - 2026-01-19

### Added
- 11 new comprehensive test suites (261 new tests, 547 total):
  - `pkcs11_info_functions` (25): C_GetInfo, C_GetSlotInfo, C_GetTokenInfo, C_GetMechanismInfo
  - `key_lifecycle_abi` (25): SP 800-57 date-based activation/deactivation through C ABI
  - `key_wrapping_abi` (22): C_WrapKey/C_UnwrapKey roundtrips and error paths
  - `key_derivation_abi` (19): ECDH P-256/P-384 derivation, cross-party validation
  - `rsa_abi_comprehensive` (28): RSA 2048/3072 sign/verify/encrypt/decrypt, OAEP, PSS
  - `digest_abi` (25): All 7 hash algorithms, single-part and multi-part
  - `attribute_management` (25): C_GetAttributeValue, C_SetAttributeValue, C_FindObjects
  - `random_and_session` (22): C_GenerateRandom, session management, PIN operations
  - `pqc_abi_comprehensive` (28): ML-DSA/ML-KEM/SLH-DSA/hybrid through C ABI
  - `audit_and_integrity` (24): AuditLog chain integrity, StoredObject lifecycle
  - `negative_edge_cases` (30): Cross-algo failures, boundary conditions, empty data

### Fixed
- CKA_START_DATE/CKA_END_DATE attributes now applied during C_GenerateKey and C_GenerateKeyPair
  (previously silently ignored in template override section)

## [0.7.0] - 2025-10-17

### Added
- **FIPS Approved Mode**: `fips_approved_only` config flag restricts operations to FIPS-approved algorithms only
- `is_fips_approved()` mechanism classifier and `validate_mechanism_for_policy()` enforcement in all Init/keygen functions
- `C_GetMechanismList` filters non-approved mechanisms when FIPS mode is active
- **Pairwise Consistency Tests (§9.6)**: Sign/verify or encap/decap roundtrip after every key pair generation (RSA, ECDSA P-256/P-384, Ed25519, ML-DSA, ML-KEM, SLH-DSA)
- **Software Integrity Test (§9.4)**: HMAC-SHA256 of module binary at POST time with `.hmac` sidecar verification
- `tools/compute-integrity-hmac.sh` and `.ps1` for computing integrity HMAC
- **Algorithm Indicator (IG 2.4.C)**: `fips_approved: bool` field in all crypto audit log entries (Sign, Verify, Encrypt, Decrypt, Digest, GenerateKey, GenerateKeyPair, WrapKey, UnwrapKey, DeriveKey)
- `last_operation_fips_approved` field on `Session` for runtime indicator querying
- `CKA_VENDOR_FIPS_APPROVED` (0x80000001) vendor-defined attribute constant
- **Intermediate Zeroization**: `Zeroizing<Vec<u8>>` for all `ActiveOperation` data and mechanism_param fields
- FIPS mode operator guide (`docs/fips-mode-guide.md`)
- 17 new tests: 11 FIPS approved mode tests, 6 pairwise consistency integration tests, 3 integrity unit tests

### Changed
- `HsmCore` stores `AlgorithmConfig` for runtime policy enforcement
- POST now runs software integrity check as first test (16 total self-tests)
- Security Policy updated to v3.0 with pairwise tests, integrity test, algorithm indicator, intermediate zeroization

## [0.6.0] - 2025-09-11

### Added
- `cargo audit` and `cargo deny` in CI pipeline (CVE check, license/advisory compliance)
- `deny.toml` configuration for dependency vetting
- Miri CI job for undefined behavior detection (`cargo +nightly miri test`)
- 2 new fuzz targets: `fuzz_session_lifecycle` (state machine edge cases, login/logout sequences) and `fuzz_buffer_overflow` (integer overflow, two-call pattern, null pointers)
- Security review checklist (`docs/security-review-checklist.md`) — pre-audit self-assessment
- Release signing documentation (`docs/release-signing.md`) — GPG, cosign, Authenticode
- Side-channel resistance documentation in security model — constant-time operations, RSA blinding, AES-NI
- Visual examples in PRESENTATION.md — Admin CLI output, Audit Log chain, FIPS POST, pkcs11-tool
- AddressSanitizer / MemorySanitizer usage instructions
- Supply-chain security documentation (dependency vetting, reproducible builds, binary signing)

### Changed
- Fuzz target count increased from 3 to 5
- CI pipeline expanded from 5 to 7 jobs (added security-audit, miri)
- PRESENTATION.md updated with visual examples, side-channel analysis, supply-chain table

## [0.5.0] - 2025-07-14

### Added
- PKCS#11 C ABI benchmarks via Criterion (10 benchmark groups through `C_GetFunctionList`)
- SoftHSMv2 head-to-head comparative benchmarks (controlled via `SOFTHSM2_LIB` env var)
- Java SunPKCS11 interop test script (`tests/interop/java_sunpkcs11.sh`)
- OpenSSL / pkcs11-tool interop test script (`tests/interop/openssl_pkcs11.sh`)
- Benchmark documentation (`docs/benchmarks.md`)
- CI benchmark job (runs on push to main, uploads Criterion reports as artifacts)
- Comprehensive Java SunPKCS11 usage guide in install docs (keytool + programmatic)
- Comprehensive OpenSSL / pkcs11-tool / p11tool usage guide in install docs
- SSH agent integration documentation

## [0.4.0] - 2025-06-06

### Added
- Multi-part sign/verify: `C_SignUpdate`, `C_SignFinal`, `C_VerifyUpdate`, `C_VerifyFinal`
- Multi-part encrypt/decrypt: `C_EncryptUpdate`, `C_EncryptFinal`, `C_DecryptUpdate`, `C_DecryptFinal`
- SP 800-90A HMAC_DRBG with prediction resistance and continuous health test
- DRBG POST known-answer test (KAT #15)
- `C_CopyObject` with PKCS#11 sensitivity/extractability enforcement
- `C_DigestKey` for feeding key material into digest operations
- SP 800-57 key lifecycle states (pre-activation, active, deactivated, compromised, destroyed)
- `CKA_START_DATE` / `CKA_END_DATE` attribute support with date-based lifecycle transitions
- Lifecycle enforcement in `C_SignInit`, `C_VerifyInit`, `C_EncryptInit`, `C_DecryptInit`
- README.md and CHANGELOG.md
- GitHub Actions CI pipeline (build, test, lint, docs on Ubuntu + Windows)
- 50+ new integration tests (multi-part sign/verify, encrypt/decrypt, supplementary functions, DRBG)

## [0.3.0] - 2025-04-28

### Added
- aws-lc-rs crypto backend (`awslc-backend` feature flag) for FIPS 140-3 Level 1
- `CryptoBackend` trait with 26 methods, wired into all 29 callsites
- Encrypted persistent storage (redb + AES-256-GCM with PBKDF2-derived keys)
- File-level locking (`fs2`) for multi-process safety
- Tamper-evident append-only audit log with chained SHA-256
- FIPS 140-3 Power-On Self-Tests: 14 KATs covering all approved algorithms
- Continuous RNG health test (SP 800-90B)
- Memory hardening: mlock/VirtualLock on key material, ZeroizeOnDrop, custom Debug impls
- Fork detection (Unix): PID comparison forces child processes to re-initialize
- Fuzzing harness for ABI boundary (3 cargo-fuzz targets)
- FIPS Security Policy document with CSP table
- Audit scope documentation and FIPS gap analysis
- Tested platforms documentation
- `PRESENTATION.md` with detailed architecture walkthrough

## [0.2.0] - 2025-03-21

### Added
- Criterion benchmarks for all crypto operations (RSA, ECDSA, Ed25519, AES, SHA, ML-DSA, ML-KEM)
- gRPC daemon with mutual TLS (`craton-hsm-daemon`)
- Admin CLI tool (`craton-hsm-admin`) for token, key, PIN, and audit management
- PKCS#11 spy/logging wrapper (`pkcs11-spy`)
- Dockerfile (multi-stage distroless) and Helm chart for Kubernetes deployment
- Operator runbook and installation guide
- Session state machine validation tests (42 tests)
- Attribute validation tests (24 tests)
- Concurrent session stress tests (6 tests)
- Error path coverage tests (50 tests)

## [0.1.0] - 2025-02-14

### Added
- Core PKCS#11 v3.0 C ABI with 70+ exported functions
- Session management with DashMap-based concurrent access
- Token/slot management with PIN lifecycle (SO + User)
- Object store with template-based search
- RSA keygen/sign/verify (2048/3072/4096), ECDSA (P-256/P-384), EdDSA (Ed25519)
- AES-256 encrypt/decrypt (GCM, CBC, CTR)
- SHA-256/384/512/SHA3-256 digest
- ECDH key derivation (P-256, P-384)
- AES key wrapping (RFC 3394)
- Post-quantum cryptography: ML-KEM-768, ML-DSA-44/65/87, SLH-DSA-SHA2-128s
- Hybrid X25519+ML-KEM-768 key exchange
- PBKDF2-SHA256 PIN hashing with constant-time comparison
