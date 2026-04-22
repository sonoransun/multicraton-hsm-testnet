# Craton HSM Architecture

## Overview

Craton HSM is a software HSM (Hardware Security Module emulator) that exposes a PKCS#11 v3.0-compliant C ABI. It is written entirely in Rust to leverage the language's memory safety and concurrency guarantees. The module can be consumed three ways: as a dynamically loaded library, over gRPC, or via the admin CLI.

## High-Level Module Diagram

```mermaid
graph TB
    subgraph consumers ["Consumer Applications"]
        OSSl["OpenSSL / NSS"]
        Java["Java SunPKCS11"]
        SSH["ssh-agent"]
    end

    subgraph interfaces ["Interface Layer"]
        ABI["pkcs11_abi/<br/>70+ C exports<br/><i>dlopen</i>"]
        DAEMON["craton-hsm-daemon<br/><i>gRPC / mTLS</i>"]
        ADMIN["craton-hsm-admin<br/><i>clap CLI</i>"]
    end

    subgraph hsmcore ["HsmCore  (src/core.rs)"]
        direction TB
        SM["SessionManager"]
        SL["SlotManager"]
        OS["ObjectStore"]
        AL["AuditLog"]
    end

    subgraph modules ["Internal Modules"]
        SESSION["session/<br/><i>state machine, DashMap</i>"]
        TOKEN["token/<br/><i>PIN auth, PBKDF2, lockout</i>"]
        STORE["store/<br/><i>EncryptedStore, redb</i>"]
        CRYPTO["crypto/<br/><i>keygen, sign, encrypt, digest,<br/>PQC (ML-KEM/DSA, SLH-DSA,<br/>Falcon, FrodoKEM, hybrid),<br/>DRBG, self-test, mlock</i>"]
        AUDIT["audit/<br/><i>append-only,<br/>chained SHA-256</i>"]
    end

    OSSl & Java & SSH --> ABI
    OSSl & Java --> DAEMON
    ADMIN --> ADMIN

    ABI & DAEMON & ADMIN --> hsmcore
    hsmcore --> SESSION & TOKEN & STORE & CRYPTO & AUDIT

    classDef iface fill:#e0e0e0,color:#333
    classDef core fill:#2d4a7a,color:#fff
    classDef mod fill:#1a6e2e,color:#fff
    class ABI,DAEMON,ADMIN iface
    class SM,SL,OS,AL core
    class SESSION,TOKEN,STORE,CRYPTO,AUDIT mod
```

## Source Layout

```mermaid
graph LR
    ROOT["craton_hsm/"] --> SRC["src/"]
    ROOT --> DAEMON["craton-hsm-daemon/<br/><i>gRPC daemon (tonic + rustls)</i>"]
    ROOT --> TOOLS["tools/"]
    ROOT --> DEPLOY["deploy/<br/><i>Dockerfile, Helm chart</i>"]
    ROOT --> BENCH["benches/<br/><i>Criterion benchmarks</i>"]
    ROOT --> TESTS["tests/<br/><i>617+ integration tests</i>"]
    ROOT --> DOCS["docs/"]

    SRC --> LIB["lib.rs — crate root"]
    SRC --> CORE["core.rs — HsmCore"]
    SRC --> ERR["error.rs — HsmError ↔ CK_RV"]
    SRC --> ABI["pkcs11_abi/<br/><i>types, constants, 70+ exports</i>"]
    SRC --> SESS["session/<br/><i>state machine, DashMap manager</i>"]
    SRC --> TOK["token/<br/><i>PIN hashing, lockout, slots</i>"]
    SRC --> STORE["store/<br/><i>objects, encrypted redb,<br/>backup, key_material</i>"]
    SRC --> CRYPTO["crypto/<br/><i>keygen, sign, encrypt, digest,<br/>derive, wrap, DRBG,<br/>pqc (ML-KEM/DSA, SLH-DSA × 12),<br/>falcon, frodokem, hybrid*, hybrid_kem,<br/>self_test, mlock, backends</i>"]
    SRC --> CFG["config/<br/><i>TOML config + defaults</i>"]
    SRC --> AUDIT["audit/<br/><i>append-only chained SHA-256</i>"]

    TOOLS --> ADMINCLI["craton-hsm-admin/<br/><i>Admin CLI (clap)</i>"]
    TOOLS --> SPY["pkcs11-spy/<br/><i>PKCS#11 interceptor</i>"]

    classDef dir fill:#2d4a7a,color:#fff
    classDef file fill:#e0e0e0,color:#333
    class ROOT,SRC,TOOLS,DEPLOY,BENCH,TESTS,DOCS,DAEMON dir
    class LIB,CORE,ERR,ABI,SESS,TOK,STORE,CRYPTO,CFG,AUDIT,ADMINCLI,SPY file
```

## Core Components

### HsmCore (`src/core.rs`)

The central struct holding all managers. All three consumer interfaces (C ABI, gRPC daemon, admin CLI) operate against the same `HsmCore` instance.

```rust
pub struct HsmCore {
    pub(crate) slot_manager: SlotManager,
    pub(crate) session_manager: SessionManager,
    pub(crate) object_store: ObjectStore,
    pub(crate) audit_log: AuditLog,
    pub(crate) crypto_backend: Arc<dyn CryptoBackend>,
    pub(crate) drbg: Mutex<HmacDrbg>,    // SP 800-90A HMAC_DRBG
    pub(crate) algorithm_config: AlgorithmConfig,
}
```

For the C ABI path, `HsmCore` lives inside a `Mutex<Option<Arc<HsmCore>>>` that is initialized during `C_Initialize` and reset to `None` during `C_Finalize`, allowing re-initialization per the PKCS#11 spec.

### PKCS#11 C ABI (`src/pkcs11_abi/`)

Exports 70+ `#[no_mangle] pub extern "C"` functions matching the PKCS#11 v3.0 specification. Every function is wrapped in `catch_unwind` to prevent Rust panics from crossing the FFI boundary (which would be undefined behavior).

All `unsafe` code is confined to this module and follows four documented patterns:
1. Dereferencing caller-provided output pointers
2. Constructing slices from (pointer, length) pairs
3. Reading `CK_MECHANISM` through a raw pointer
4. Casting `CK_C_INITIALIZE_ARGS`

### Session State Machine (`src/session/`)

Five PKCS#11-compliant session states with enforced transitions:

```mermaid
stateDiagram-v2
    [*] --> RoPublic : C_OpenSession(RO)
    [*] --> RwPublic : C_OpenSession(RW)

    RoPublic --> RoUser : C_Login(USER)
    RoUser --> RoPublic : C_Logout

    RwPublic --> RwUser : C_Login(USER)
    RwUser --> RwPublic : C_Logout

    RwPublic --> RwSO : C_Login(SO)
    RwSO --> RwPublic : C_Logout

    RoPublic --> [*] : C_CloseSession
    RoUser --> [*] : C_CloseSession
    RwPublic --> [*] : C_CloseSession
    RwUser --> [*] : C_CloseSession
    RwSO --> [*] : C_CloseSession

    classDef public fill:#e0e0e0,color:#333
    classDef authed fill:#1a6e2e,color:#fff
    classDef so fill:#7a5c2d,color:#fff
    class RoPublic,RwPublic public
    class RoUser,RwUser authed
    class RwSO so
```

Sessions are stored in a `DashMap<CK_SESSION_HANDLE, Session>` for lock-free concurrent access.

### Token & PIN Authentication (`src/token/`)

- PINs hashed with PBKDF2-HMAC-SHA256 (600,000 iterations, random salt)
- Comparison uses `subtle::ConstantTimeEq` (timing-attack resistant)
- Brute-force protection: configurable lockout after N failed attempts
- SO can unlock a locked user PIN

### Object Store (`src/store/`)

Two storage backends:
1. **In-memory** (`ObjectStore`): fast, volatile, used by default
2. **Encrypted persistent** (`EncryptedStore`): redb database with per-object AES-256-GCM encryption and file-level locking

Objects follow the PKCS#11 attribute model with enforcement of:
- `CKA_SENSITIVE` / `CKA_EXTRACTABLE` for key export control
- `CKA_PRIVATE` for visibility filtering based on login state
- Permission attributes (`CKA_ENCRYPT`, `CKA_SIGN`, etc.)
- `CKA_START_DATE` / `CKA_END_DATE` for date-based key lifecycle (SP 800-57)

### Key Lifecycle (`src/store/object.rs`)

SP 800-57-compliant key lifecycle states with automatic date-based transitions:

| State | Permitted Operations |
|-------|---------------------|
| **PreActivation** | None (key not yet at start_date) |
| **Active** | All permitted operations |
| **Deactivated** | Verify, decrypt, unwrap only (past end_date) |
| **Compromised** | None (manually marked) |
| **Destroyed** | Handle invalid |

Lifecycle checks are enforced in `C_SignInit`, `C_VerifyInit`, `C_EncryptInit`, and `C_DecryptInit`.

### DRBG (`src/crypto/drbg.rs`)

SP 800-90A HMAC_DRBG using HMAC-SHA256:
- Seeded from OS CSPRNG (`OsRng`)
- Prediction resistance: fresh entropy on every generate call
- Continuous health test: compares consecutive outputs (SP 800-90B)
- Reseed interval: 2^48 requests
- All key generation (RSA, EC, Ed25519, AES) routed through DRBG via `DrbgRng` adapter
- Per-key AES-GCM encryption counters (2^31 limit per key, tracked via SHA-256 key hash)

### Crypto Engine (`src/crypto/`)

60+ mechanisms across 8 categories (PQC counts vary by enabled features):

| Category | Algorithms |
|----------|-----------|
| Asymmetric keygen | RSA-2048/3072/4096, ECDSA P-256/P-384, Ed25519 |
| Signing | RSA PKCS#1 v1.5, RSA-PSS, ECDSA, Ed25519, HMAC |
| Encryption | AES-GCM, AES-CBC, AES-CTR, RSA-OAEP |
| Digest | SHA-1, SHA-256, SHA-384, SHA-512, SHA3-256/384/512 |
| Key derivation | ECDH (P-256, P-384) |
| Key wrapping | AES Key Wrap (RFC 3394) |
| Post-quantum (default) | ML-KEM-512/768/1024, ML-DSA-44/65/87, SLH-DSA (all 12 FIPS 205 parameter sets) |
| Post-quantum (feature-gated) | Falcon-512/1024 (`falcon-sig`), FrodoKEM-640/976/1344-AES (`frodokem-kem`) |
| Hybrid | X25519/P-256/P-384 + ML-KEM (`hybrid-kem`); ECDSA-P256+ML-DSA-65, Ed25519+ML-DSA-65 (default) |

#### PQC module layout

```mermaid
graph TB
    subgraph DEFAULT["Default build — pure Rust"]
        direction TB
        PQC["crypto/pqc.rs<br/><i>ML-KEM · ML-DSA · SLH-DSA ×12<br/>Ed25519+ML-DSA-65 composite<br/>ECDSA+ML-DSA-65 composite</i>"]
        DRBG["crypto/drbg.rs<br/><i>HMAC_DRBG (SP 800-90A)</i>"]
        PQC --> DRBG
    end

    subgraph HYBRID_FEAT["feature: hybrid-kem"]
        direction TB
        HKEM["crypto/hybrid_kem.rs<br/><i>X25519+ML-KEM-768 (original)</i>"]
        HNEW["crypto/hybrid.rs<br/><i>X25519+ML-KEM-1024<br/>P-256+ML-KEM-768 (CNSA 2.0)<br/>P-384+ML-KEM-1024 (TOP SECRET)</i>"]
    end

    subgraph FALCON_FEAT["feature: falcon-sig"]
        FAL["crypto/falcon.rs<br/><i>Falcon-512 · Falcon-1024<br/>via pqcrypto-falcon (C FFI)</i>"]
    end

    subgraph FRODO_FEAT["feature: frodokem-kem"]
        FRO["crypto/frodokem.rs<br/><i>FrodoKEM-640/976/1344-AES<br/>via pqcrypto-frodo (C FFI)</i>"]
    end

    HKEM & HNEW --> DRBG
    FAL -.->|"PQClean randombytes"| OSRNG[("OS entropy")]
    FRO -.->|"PQClean randombytes"| OSRNG

    classDef default_m fill:#4a2d7a,color:#fff
    classDef hybrid_m fill:#1a6e2e,color:#fff
    classDef ffi_m fill:#7a2d4a,color:#fff
    classDef util fill:#2d4a7a,color:#fff
    class PQC default_m
    class HKEM,HNEW hybrid_m
    class FAL,FRO ffi_m
    class DRBG,OSRNG util
```

Pure-Rust PQC (FIPS 203/204/205) routes all key generation and ML-KEM encapsulation through the SP 800-90A HMAC_DRBG. Falcon and FrodoKEM delegate randomness to PQClean's internal `randombytes` because those crates expose no RNG-injection hook; this is documented as an upstream limitation in [`docs/future-work-guide.md`](future-work-guide.md).

### Audit Log (`src/audit/`)

Append-only log with tamper-evident chained SHA-256 hashes:

```
Entry[n].previous_hash = SHA-256(Entry[n-1])
```

Any modification, deletion, or reordering breaks the chain. Events are recorded synchronously before the PKCS#11 function returns (not fire-and-forget).

### FIPS 140-3 POST (`src/crypto/self_test.rs`)

17 self-tests (software integrity check + 16 KATs) plus continuous RNG health checks run during `C_Initialize`:

| # | Test | Type | Vector Source |
|---|------|------|---------------|
| 0 | Software integrity | HMAC-SHA256 of module binary | §9.4 sidecar `.hmac` file |
| 1 | SHA-256 | Known Answer Test | NIST "abc" |
| 2 | SHA-384 | Known Answer Test | NIST "abc" |
| 3 | SHA-512 | Known Answer Test | NIST "abc" |
| 4 | SHA3-256 | Known Answer Test | NIST "abc" |
| 5 | HMAC-SHA256 | Known Answer Test | RFC 4231 TC2 |
| 6 | HMAC-SHA384 | Known Answer Test | RFC 4231 TC2 |
| 7 | HMAC-SHA512 | Known Answer Test | RFC 4231 TC2 |
| 8 | AES-256-GCM | Encrypt/Decrypt roundtrip + known-answer decrypt | Fixed key |
| 9 | AES-256-CBC | Known Answer Test (hardcoded expected ciphertext) | Fixed key/IV |
| 10 | AES-256-CTR | Known Answer Test (hardcoded expected ciphertext) | Fixed key/IV |
| 11 | RSA 2048 PKCS#1 v1.5 | Sign/Verify roundtrip | Generated key |
| 12 | ECDSA P-256 | Sign/Verify roundtrip | Generated key |
| 13 | ML-DSA-44 | Sign/Verify roundtrip | Generated key |
| 14 | ML-KEM-768 | Encapsulate/Decapsulate roundtrip | Generated key |
| 15 | RNG health | Entropy + continuous test | OsRng (SP 800-90B §4.3) |
| 16 | HMAC_DRBG | Known Answer Test | NIST CAVP vector |

If any test fails, `POST_FAILED` is set and all subsequent operations return `CKR_GENERAL_ERROR`. On re-initialization (after `C_Finalize`), `POST_FAILED` is reset and POST re-runs.

Three additional PQC KATs run when their features are enabled (20 tests total with everything on):

| Test | Feature | Vector Source |
|------|---------|---------------|
| SLH-DSA-SHA2-128f | default | Generated key (fast-variant coverage) |
| Falcon-512 | `falcon-sig` | Generated key + detached sign/verify |
| FrodoKEM-640-AES | `frodokem-kem` | Generated key + encap/decap constant-time compare |

Pairwise consistency tests (FIPS 140-3 §9.6) run after every asymmetric keygen — including Falcon, FrodoKEM, all four hybrid KEM variants, and the composite Ed25519+ML-DSA-65 signature. Failure sets `POST_FAILED` just as with the boot-time KATs.

## Data Flow: Sign Operation

```mermaid
flowchart TD
    APP1["Application calls<br/>C_SignInit(hSession, pMechanism, hKey)"]
    CU1["catch_unwind boundary"]
    VS["Validate session exists"]
    VL["Check login state"]
    LK["Look up key in ObjectStore"]
    VCS["Verify CKA_SIGN == true"]
    STORE["Store (mechanism, key_handle)<br/>in Session.active_operation"]
    OK1(["CKR_OK"])

    APP1 --> CU1 --> VS
    VS -->|not found| E1["CKR_SESSION_HANDLE_INVALID"]
    VS -->|found| VL
    VL -->|not logged in| E2["CKR_USER_NOT_LOGGED_IN"]
    VL -->|authenticated| LK
    LK -->|not found| E3["CKR_KEY_HANDLE_INVALID"]
    LK -->|found| VCS
    VCS -->|denied| E4["CKR_KEY_FUNCTION_NOT_PERMITTED"]
    VCS -->|permitted| STORE --> OK1

    APP2["Application calls<br/>C_Sign(hSession, pData, pSignature)"]
    CU2["catch_unwind boundary"]
    ROP["Retrieve active Sign operation"]
    LOAD["Load key material"]
    DISP["Dispatch by mechanism"]
    RSA["CKM_RSA_PKCS<br/>→ rsa_pkcs1v15_sign()"]
    EC["CKM_ECDSA<br/>→ ecdsa_sign()"]
    ED["CKM_EDDSA<br/>→ ed25519_sign()"]
    PQC["CKM_ML_DSA_*<br/>→ ml_dsa_sign()"]
    WRITE["Write signature to buffer"]
    ADTL["Record to AuditLog<br/><i>synchronous</i>"]
    CLR["Clear active_operation"]
    OK2(["CKR_OK"])

    APP2 --> CU2 --> ROP
    ROP -->|no active op| E5["CKR_OPERATION_NOT_INITIALIZED"]
    ROP -->|active| LOAD --> DISP
    DISP --> RSA & EC & ED & PQC & FAL & HYB
    RSA & EC & ED & PQC & FAL & HYB --> WRITE --> ADTL --> CLR --> OK2

    FAL["CKM_FALCON_*<br/>→ falcon::falcon_sign()<br/><i>(feature-gated)</i>"]
    HYB["CKM_HYBRID_*<br/>→ pqc::hybrid_*_sign()"]

    classDef error fill:#7a2d2d,color:#fff
    classDef success fill:#1a6e2e,color:#fff
    classDef crypto fill:#2d4a7a,color:#fff
    classDef ffi fill:#7a2d4a,color:#fff
    classDef hybrid fill:#1a6e2e,color:#fff
    class E1,E2,E3,E4,E5 error
    class OK1,OK2 success
    class RSA,EC,ED,PQC crypto
    class FAL ffi
    class HYB hybrid
```

## Concurrency Model

- **Sessions**: `DashMap` provides lock-free concurrent reads, per-shard locks on writes
- **Token state**: `parking_lot::RwLock` for PIN/login state
- **Object store**: `parking_lot::RwLock` protecting the object map
- **Audit log**: `std::sync::Mutex` serializing log writes
- **Global state**: `Mutex<Option<Arc<HsmCore>>>` for initialization/finalization cycles
- **GCM counters**: `LazyLock<DashMap<[u8; 32], AtomicU64>>` for per-key nonce tracking (keyed by SHA-256 of key material)

## Deployment Topology

### In-process (shared library)

```mermaid
flowchart LR
    subgraph process ["Application Process"]
        APP["App Code"] -->|dlopen| LIB["libcraton_hsm.so/.dll<br/><i>PKCS#11 C ABI</i>"]
    end

    classDef lib fill:#2d4a7a,color:#fff
    class LIB lib
```

### Network daemon (standalone or sidecar)

```mermaid
flowchart LR
    subgraph client ["Client Host"]
        APP["Application"]
    end
    subgraph server ["Daemon Host"]
        DAEMON["craton-hsm-daemon<br/><i>port 5696</i>"]
        CORE["HsmCore"]
        DAEMON --> CORE
    end

    APP -->|"gRPC / mTLS"| DAEMON

    classDef core fill:#2d4a7a,color:#fff
    class CORE core
```

### Kubernetes sidecar

```mermaid
flowchart TB
    subgraph pod ["Kubernetes Pod"]
        subgraph appC ["App Container"]
            APP["Application"]
        end
        subgraph hsmC ["HSM Sidecar Container"]
            DAEMON["craton-hsm-daemon<br/><i>:5696</i>"]
        end
        APP -->|"gRPC localhost"| DAEMON

        CM["ConfigMap: craton_hsm.toml"]
        SEC["Secret: TLS cert/key"]
        CM -.-> DAEMON
        SEC -.-> DAEMON
    end

    classDef config fill:#7a5c2d,color:#fff
    classDef hsm fill:#2d4a7a,color:#fff
    class CM,SEC config
    class DAEMON hsm
```

---

## Storage backend

The default object store is **in-memory** (`DashMap<CK_OBJECT_HANDLE, Arc<RwLock<StoredObject>>>`). Objects are lost on process exit unless the optional **redb** persistent backend is enabled.

When persistence is enabled:
- Each object is serialized and encrypted with **AES-256-GCM** before writing to redb.
- The encryption key is derived from the user PIN via **PBKDF2-HMAC-SHA256** (600,000 iterations).
- There is no separate master KEK — the PIN-derived key is the only encryption key.
- An exclusive file lock (`fs2`) prevents two processes from opening the same database.
- Token re-initialization (`C_InitToken`) destroys all persisted objects.

## Concurrency model

Craton HSM is **single-process, multi-threaded**:
- `DashMap` for lock-free concurrent session and object access
- `parking_lot::RwLock` for per-session state
- `AtomicU64` for session handle and object handle allocation
- `AtomicBool` for FIPS POST gate

Two processes loading `libcraton_hsm.so` independently operate on isolated token state. If persistent storage is enabled, an exclusive file lock (`fs2`) prevents two processes from opening the same database. Multi-process access to the same token is supported through the **gRPC daemon** (`craton-hsm-daemon`), which serializes all operations. See `docs/fork-safety.md` for fork detection and multi-process patterns.

## Crypto backend

All classical cryptographic operations are routed through a **`CryptoBackend` trait** (`src/crypto/backend.rs`), with two implementations:

1. **RustCryptoBackend** (`src/crypto/rustcrypto_backend.rs`) — Default. Uses pure-Rust RustCrypto crates. No external C dependencies.
2. **AwsLcBackend** (`src/crypto/awslc_backend.rs`) — Optional (`--features awslc-backend`). Uses AWS-LC (aws-lc-rs) with FIPS 140-3 validated cryptographic module.

Backend selection is config-driven via `algorithms.crypto_backend` in `craton_hsm.toml` (`"rustcrypto"` or `"awslc"`). The backend is resolved at `C_Initialize` time. PQC operations remain direct calls to dedicated crates — no alternative PQC backends exist yet.

### PQC dispatch in the signing path

```mermaid
flowchart TD
    APP["C_Sign(hSession, data, sig)"]
    DISP["sign_single_shot(mechanism, key_bytes, data, obj)"]

    APP --> DISP
    DISP -->|"is_ml_dsa_mechanism"| MLDSA["pqc::ml_dsa_sign(seed, data, variant)"]
    DISP -->|"is_slh_dsa_mechanism"| SLH["pqc::slh_dsa_sign(sk, data, variant)<br/><i>macro-dispatched over 12 sets</i>"]
    DISP -->|"is_hybrid_mechanism"| HYB1["pqc::hybrid_sign<br/>ML-DSA-65 + ECDSA-P256"]
    DISP -->|"is_hybrid_ed25519_mldsa65_mechanism"| HYB2["pqc::hybrid_ed25519_mldsa65_sign<br/>Ed25519 + ML-DSA-65"]
    DISP -->|"is_falcon_mechanism<br/>(feature = falcon-sig)"| FAL["falcon::falcon_sign(sk, data, variant)"]
    DISP -->|"classical (RSA/EC/Ed)"| CLA["backend.rsa_* / ecdsa_* / ed25519_sign"]

    MLDSA & SLH & HYB1 & HYB2 & FAL & CLA --> OUT["Vec<u8> signature bytes"]

    classDef pqc fill:#4a2d7a,color:#fff
    classDef hybrid fill:#1a6e2e,color:#fff
    classDef ffi fill:#7a2d4a,color:#fff
    classDef classical fill:#2d4a7a,color:#fff
    class MLDSA,SLH pqc
    class HYB1,HYB2 hybrid
    class FAL ffi
    class CLA classical
```

See [PQC deep-dive](post-quantum-crypto.md) for full byte layouts, RNG routing, pairwise-test coverage, and storage formats.

### Fork Safety

Craton HSM detects `fork(2)` on Unix by recording the PID during `C_Initialize`. If a child process calls any PKCS#11 function, it receives `CKR_CRYPTOKI_NOT_INITIALIZED` and must re-initialize. See `docs/fork-safety.md` for full details.

### Memory Hardening

Key material is protected at the memory level:
- **`RawKeyMaterial`** wraps `Vec<u8>` with `mlock` on allocation (prevents paging to swap) and `zeroize` + `munlock` on drop
- **Unix**: `libc::mlock` / `libc::munlock`
- **Windows**: `VirtualLock` / `VirtualUnlock` via `windows-sys`
- **Debug output**: Custom `Debug` impl prints `[REDACTED]` for all key bytes
