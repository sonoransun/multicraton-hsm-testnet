# Craton HSM

[![CI](https://github.com/craton-co/craton-hsm-core/actions/workflows/ci.yml/badge.svg)](https://github.com/craton-co/craton-hsm-core/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Crates.io](https://img.shields.io/crates/v/craton_hsm.svg)](https://crates.io/crates/craton_hsm)
[![docs.rs](https://docs.rs/craton_hsm/badge.svg)](https://docs.rs/craton_hsm)
[![codecov](https://codecov.io/gh/craton-co/craton-hsm-core/branch/main/graph/badge.svg)](https://codecov.io/gh/craton-co/craton-hsm-core)

> **Not FIPS 140-3 certified.** This software has not undergone CMVP validation.
> See [FIPS Gap Analysis](docs/fips-gap-analysis.md) for details.

**A next-generation PKCS#11 v3.0-compliant Software Hardware Security Module written in pure Rust.**

Craton HSM is an enterprise cryptographic platform combining the compliance of traditional HSMs with modern cloud-native features: post-quantum cryptography, fully homomorphic encryption, hardware attestation, STARK proofs, BLS aggregation, WebAssembly plugins, and multi-protocol cluster networking.

---

## Platform Overview

```mermaid
graph TB
    subgraph CLIENTS["Client Applications"]
        A1[OpenSSL / NSS]
        A2[Java PKCS11]
        A3[Cloud Services]
        A4[Admin CLI]
    end

    subgraph INTERFACES["Interface Layer"]
        I1["PKCS#11 C ABI<br/>70+ Functions"]
        I2["gRPC / mTLS<br/>30+ Methods"]
        I3["Admin CLI<br/>Token · Key · Audit"]
    end

    subgraph CORE["Core HSM Engine"]
        C1["HsmCore<br/>Central State Manager"]
        C2["Session Manager<br/>DashMap concurrent sessions"]
        C3["Token Manager<br/>PIN lifecycle · SP 800-57"]
        C4["Object Store<br/>AES-256-GCM · redb"]
        C5["Audit Log<br/>SHA-256 integrity chain"]
    end

    subgraph CRYPTO["Cryptographic Layer"]
        direction LR
        CL["Classical<br/>RSA · ECDSA · EdDSA · AES"]
        PQ["Post-Quantum<br/>ML-KEM · ML-DSA · SLH-DSA"]
        HY["Hybrid KEM<br/>X25519 + ML-KEM-768"]
        BL["BLS12-381<br/>Aggregatable signatures"]
        DR["HMAC_DRBG<br/>SP 800-90A"]
    end

    subgraph ADVANCED["Advanced Capabilities"]
        direction LR
        FH["FHE<br/>tfhe-rs"]
        TP["TPM 2.0<br/>PCR sealing"]
        SK["STARK Proofs<br/>Winterfell"]
        WA["WASM Plugins<br/>Wasmtime"]
        AT["Attestation<br/>TDX · SEV-SNP · Nitro"]
    end

    subgraph CLUSTER["Cluster Transport"]
        direction LR
        MT["mTLS 1.3"]
        QU["QUIC<br/>quinn · 0-RTT"]
        NO["Noise Protocol<br/>XX_25519_AESGCM"]
    end

    A1 & A2 --> I1
    A3 --> I2
    A4 --> I3
    I1 & I2 & I3 --> C1
    C1 --> C2 & C3 & C4 & C5
    C1 --> CL & PQ & HY & BL & DR
    C1 --> FH & TP & SK & WA & AT
    C1 --> MT & QU & NO
```

---

## Cryptographic Capabilities

### Algorithm taxonomy

```mermaid
graph LR
    subgraph CLASS["Classical  (128-256 bit security)"]
        RSA["RSA<br/>2048 · 3072 · 4096"]
        EC["ECDSA<br/>P-256 · P-384 · K-256"]
        ED["EdDSA<br/>Ed25519 · Ed448"]
        AES["AES<br/>CBC · CTR · GCM · KW · SIV"]
        SHA["Hash<br/>SHA-1/2/3 · BLAKE3 · HMAC"]
        KDF["KDF<br/>PBKDF2 · Argon2id · HKDF"]
    end

    subgraph PQC["Post-Quantum  (NIST FIPS 203-205)"]
        KEM["ML-KEM<br/>512 · 768 · 1024"]
        DSA["ML-DSA<br/>44 · 65 · 87"]
        SLH["SLH-DSA<br/>SHA2-128s · SHA2-256s"]
    end

    subgraph HYBRID["Hybrid  (classical + PQ)"]
        HK["Hybrid KEM<br/>X25519 ⊕ ML-KEM-768<br/>HKDF-combined"]
        HS["Hybrid Sign<br/>ECDSA-P256 ⊕ ML-DSA-65"]
    end

    subgraph AGG["Aggregatable"]
        BLS["BLS12-381<br/>Sign · Verify<br/>Aggregate n→1<br/>Batch verify"]
    end

    subgraph OPRF["Oblivious"]
        VF["VOPRF<br/>RFC 9497<br/>Rate-limited tokens"]
    end

    CLASS --> HYBRID
    PQC  --> HYBRID
    CLASS --> AGG
```

### Hybrid KEM encapsulation flow

```mermaid
sequenceDiagram
    participant S as Sender
    participant R as Recipient

    Note over S,R: Both parties hold HybridKemPublicKey / HybridKemSecretKey

    S->>S: Generate ephemeral X25519 key pair (eph_sk, eph_pk)
    S->>S: X25519 DH → ss₁ = eph_sk · recipient.x25519_pk
    S->>S: ML-KEM-768 Encap(recipient.mlkem_ek) → (ss₂, mlkem_ct)
    S->>S: HKDF-SHA256(ss₁ ∥ ss₂, info) → shared_secret  [32 bytes]

    S-->>R: Send HybridCiphertext { eph_pk [32 B], mlkem_ct [1088 B] }

    R->>R: X25519 DH → ss₁ = sk.x25519_sk · eph_pk
    R->>R: ML-KEM-768 Decap(sk.mlkem_dk, mlkem_ct) → ss₂
    R->>R: HKDF-SHA256(ss₁ ∥ ss₂, info) → shared_secret  [32 bytes]

    Note over S,R: Both hold identical shared_secret.<br/>Secure if EITHER X25519 OR ML-KEM-768 is unbroken.
```

### BLS12-381 signature aggregation

```mermaid
graph LR
    subgraph SIGNERS["n Signers"]
        SK1["sk₁ · sign(msg)"] --> SIG1["sig₁  [96 B]"]
        SK2["sk₂ · sign(msg)"] --> SIG2["sig₂  [96 B]"]
        SKN["skₙ · sign(msg)"] --> SIGN["sigₙ  [96 B]"]
    end

    SIG1 & SIG2 & SIGN --> AGG["aggregate_signatures()<br/>AggregateSignature"]
    PK1["pk₁  [48 B]"] & PK2["pk₂  [48 B]"] & PKN["pkₙ  [48 B]"] --> AGGPK["aggregate_public_keys()<br/>AggregatePublicKey"]

    AGG & AGGPK --> VFY{"verify_multisig(msg)<br/>O(1) pairings"}
    VFY -->|"✓"| OK["Valid — all n<br/>parties approved"]
    VFY -->|"✗"| FAIL["Invalid"]

    style AGG fill:#2d4a7a,color:#fff
    style AGGPK fill:#2d4a7a,color:#fff
    style OK fill:#1a6e2e,color:#fff
    style FAIL fill:#7a2d2d,color:#fff
```

---

## Advanced Capabilities

### Fully Homomorphic Encryption

Compute on encrypted data without decryption — the server never sees plaintext values.

```mermaid
sequenceDiagram
    participant OP as HSM Operator<br/>(holds ClientKey)
    participant SRV as Cloud Node<br/>(holds ServerKey only)

    OP->>OP: FheKeySet::generate() → (client_key, server_key)
    OP-->>SRV: Share server_key (public evaluation key)

    OP->>OP: EncryptedCounter::new(0, keys)
    OP-->>SRV: Send encrypted counter ciphertext

    loop Per key-use event (server never decrypts)
        SRV->>SRV: counter.increment(1, keys)
        SRV->>SRV: check = counter.exceeds_limit(1000, keys)
        Note over SRV: check is still encrypted — value unknown
    end

    SRV-->>OP: Return encrypted counter + encrypted check
    OP->>OP: counter.decrypt(keys) → 42
    OP->>OP: check.decrypt(client_key) → 0  (not exceeded)
```

**Use cases:** encrypted key-use counters in untrusted cloud nodes, homomorphic risk scoring without exposing event data, homomorphic key blinding for enclave hand-off.

### TPM 2.0 Hardware Binding

```mermaid
flowchart TD
    subgraph INIT["Token Initialisation (once)"]
        A["Generate HSM master key"] --> B["tpm_seal(master_key, PCR[0,2,7])"]
        B --> C["Store SealedBlob alongside token DB"]
        B --> D["Record PCR values in audit log"]
    end

    subgraph BOOT["Every Boot"]
        E["Load SealedBlob"] --> F{"tpm_unseal()<br/>TPM verifies PCR[0,2,7]"}
        F -->|"PCR match"| G["Master key recovered<br/>→ decrypt token DB"]
        F -->|"PCR mismatch<br/>(firmware changed / Secure Boot off)"| H["TPM refuses<br/>Key permanently inaccessible"]
    end

    subgraph ATTEST["Remote Attestation"]
        I["Verifier sends nonce"] --> J["tpm_quote(nonce, PCR[0,2,7])"]
        J --> K["TpmQuote { attestation, signature }"]
        K --> L["Verifier checks EK cert chain<br/>+ PCR values match policy"]
    end

    INIT --> BOOT
    BOOT --> ATTEST

    style G fill:#1a6e2e,color:#fff
    style H fill:#7a2d2d,color:#fff
```

### STARK Proof System

Prove correctness of HSM operations **without revealing secret material** — transparent, post-quantum secure, no trusted setup.

```mermaid
flowchart LR
    subgraph PROVE["Prover  (HSM, offline)"]
        T["Build execution trace<br/>N steps × 2 columns"] --> A["Define AIR constraints<br/>transition + boundary"]
        A --> P["winterfell::prove()<br/>Blake3_256 FRI"]
        P --> PR["CounterStarkProof<br/>~10 KB for N=64"]
    end

    subgraph VERIFY["Verifier  (auditor, ~1 ms)"]
        PR2["CounterStarkProof"] --> V["winterfell::verify()<br/>no secret knowledge needed"]
        V -->|"✓"| VALID["Counter advanced<br/>from A to B correctly"]
        V -->|"✗"| INV["Proof invalid"]
    end

    PR --> PR2

    style VALID fill:#1a6e2e,color:#fff
    style INV fill:#7a2d2d,color:#fff
```

**Properties:** Post-quantum security (hash-based, not pairing-based). Proof size sub-linear in trace length. Verification ~1 ms regardless of computation size.

### Remote Attestation

```mermaid
flowchart TD
    subgraph DETECT["Platform Detection"]
        D{"/dev/tdx_guest?<br/>/dev/sev-guest?<br/>/dev/nsm?"}
        D -->|TDX| TDX["Intel TDX<br/>TD Quote via QE"]
        D -->|SEV-SNP| SNP["AMD SEV-SNP<br/>Attestation report"]
        D -->|Nitro| NITRO["AWS Nitro<br/>COSE_Sign1 doc"]
        D -->|none| SW["Software fallback<br/>P-256 self-signed"]
    end

    subgraph TOKEN["AttestationToken (EAT-compatible)"]
        F["platform · issued_at · nonce<br/>measurement · report · signature"]
    end

    subgraph VERIFY["Remote Verifier"]
        V1["Verify nonce matches challenge"]
        V2["Verify signature against platform CA"]
        V3["Check measurement against known-good policy"]
    end

    TDX & SNP & NITRO & SW --> F
    F --> V1 --> V2 --> V3
```

### WebAssembly Plugin System

```mermaid
flowchart LR
    subgraph OPERATOR["Operator"]
        WM["custom_kdf.wasm<br/>+ SHA-256 digest"] --> LOAD["engine.load_plugin()<br/>verify SHA-256 hash<br/>Cranelift JIT compile<br/>validate exports"]
    end

    subgraph RUNTIME["Sandboxed Execution"]
        LOAD --> STORE["Store with<br/>PluginState { capabilities }"]
        STORE --> FUEL["Set MAX_FUEL = 100,000<br/>instructions budget"]
        FUEL --> EXEC["craton_execute(input_ptr, len)<br/>→ output_len"]
    end

    subgraph HOSTABI["Host ABI  (capability-gated)"]
        H1["hsm_log(ptr, len)<br/>→ audit log"]
        H2["hsm_sha256(in, len, out)<br/>→ 32-byte digest"]
        H3["(future) hsm_random(out, len)<br/>→ DRBG bytes"]
    end

    EXEC <-->|"linear memory isolation<br/>no host pointer access"| HOSTABI

    style FUEL fill:#4a2d7a,color:#fff
    style HOSTABI fill:#2d4a7a,color:#fff
```

---

## Cluster Architecture

### Transport protocol selection

```mermaid
graph TB
    subgraph TRANSPORT["ClusterTransport  (select per deployment)"]
        direction LR

        subgraph MTLS["MutualTls  (default)"]
            MT1["TLS 1.3 + client certs"]
            MT2["Standard PKI integration"]
            MT3["Widest tooling support"]
        end

        subgraph QUIC["Quic  (quic-transport feature)"]
            QU1["0-RTT session resumption"]
            QU2["Independent stream multiplexing<br/>no HOL blocking between Raft msgs"]
            QU3["Connection migration<br/>survives IP change / NAT rebind"]
        end

        subgraph NOISE["Noise  (noise-protocol feature)"]
            NO1["Noise_XX_25519_AESGCM_SHA256"]
            NO2["No PKI / certificate authority"]
            NO3["Static X25519 keys per node<br/>authenticated peer map"]
        end
    end
```

### Raft cluster with multi-transport

```mermaid
sequenceDiagram
    participant C as Client App
    participant LB as Load Balancer
    participant L as Leader (Node 1)
    participant F1 as Follower (Node 2)
    participant F2 as Follower (Node 3)

    C->>LB: Crypto operation request
    LB->>L: Route to leader

    L->>L: Apply to state machine
    L-->>F1: AppendEntries (QUIC stream 1)
    L-->>F2: AppendEntries (QUIC stream 2)
    Note over L,F2: Streams are independent — F2 lag<br/>does not block F1 acknowledgement

    F1-->>L: ACK
    F2-->>L: ACK
    Note over L: Quorum reached (2-of-3)

    L-->>C: Operation committed + result

    Note over L,F2: Heartbeats flow on a separate QUIC stream<br/>concurrently with replication traffic
```

### Key replication and wrapped-key transfer

```mermaid
sequenceDiagram
    participant HSM1 as Source HSM
    participant KS as Key Store / Transit
    participant HSM2 as Target HSM

    Note over HSM1,HSM2: Export wrapped key
    HSM1->>HSM1: WrapKey(kek, target_key) → AES-KW ciphertext
    HSM1->>HSM1: Build JSON envelope { version, metadata, wrapped }
    HSM1-->>KS: Store export file

    Note over HSM1,HSM2: Import on target
    KS-->>HSM2: Load export file
    HSM2->>HSM2: Validate format, age, serial binding
    HSM2->>HSM2: UnwrapKey(kek, wrapped_data) → key handle
    HSM2-->>HSM1: Acknowledge (cluster replicated)
```

---

## Security Architecture

### Defence-in-depth layers

```mermaid
graph TB
    subgraph L1["Layer 1 — Application"]
        A1["OPAQUE PAKE auth<br/>zero-knowledge PIN"]
        A2["Cedar / OPA policy engine<br/>RBAC + ABAC"]
        A3["Exponential backoff<br/>lockout on failed auth"]
    end

    subgraph L2["Layer 2 — Transport"]
        B1["mTLS 1.3 / QUIC / Noise<br/>mutual authentication"]
        B2["gRPC token validation"]
        B3["Token-bucket rate limiting<br/>per-node"]
    end

    subgraph L3["Layer 3 — Cryptography"]
        C1["SP 800-90A HMAC_DRBG<br/>prediction resistance"]
        C2["17 Power-On Self-Tests<br/>integrity + 16 KATs"]
        C3["Constant-time operations<br/>side-channel resistance"]
    end

    subgraph L4["Layer 4 — Storage"]
        D1["AES-256-GCM object store<br/>PBKDF2 / Argon2id keys"]
        D2["mlock / VirtualLock<br/>prevent swap of key material"]
        D3["ZeroizeOnDrop on all<br/>sensitive types"]
    end

    subgraph L5["Layer 5 — Hardware / Platform"]
        E1["TPM 2.0 PCR sealing<br/>bound to firmware state"]
        E2["TDX / SEV-SNP attestation<br/>confidential VM verified"]
        E3["Tamper-evident audit log<br/>chained SHA-256"]
    end

    L1 --> L2 --> L3 --> L4 --> L5
```

### Zero-knowledge proof subsystem

```mermaid
graph LR
    subgraph ZKP["ZKP Module  (zkp feature)"]
        direction TB
        BP["Bulletproof range proofs<br/>Prove value in [0, 2^64)"]
        G16["Groth16 proving<br/>BN254 pairing curve"]
        AUTH["Authentication proof<br/>Prove PIN knowledge<br/>without revealing PIN"]
        OWN["Key ownership proof<br/>Prove sk ↔ pk binding<br/>without exposing sk"]
        MEM["Merkle membership proof<br/>Prove key is in approved set"]
    end

    subgraph STARK_BOX["STARK Module  (stark-proofs feature)"]
        ST1["Counter integrity proof<br/>monotonic advance N steps"]
        ST2["Post-quantum secure<br/>hash-based (Blake3)"]
        ST3["Transparent<br/>no trusted setup"]
    end

    ZKP -->|"small proofs<br/>fast generation"| USE1["Audit: prove operation<br/>without revealing data"]
    STARK_BOX -->|"scalable<br/>fast verification"| USE2["Compliance: prove algorithm<br/>policy was followed"]
```

---

## Quick Start

```bash
# Core library only (default RustCrypto backend)
cargo build --release

# Full workspace with gRPC daemon (requires protoc)
cargo build --workspace --release

# Enterprise features
cargo build --release --features "enterprise"

# Post-quantum + hybrid KEM
cargo build --release --features "quantum-resistant,hybrid-kem"

# BLS signatures + STARK proofs
cargo build --release --features "bls-signatures,stark-proofs"

# Full advanced stack (large build — see Feature Flags)
cargo build --release --features "advanced-all"

# Run full test suite (single-threaded — required for PKCS#11 global state)
cargo test -- --test-threads=1
```

### Container deployment

```bash
docker build -t craton-hsm:latest .
kubectl apply -f deploy/helm/
```

### Library integration

```bash
# PKCS#11 dynamic library output
# Linux:   target/release/libcraton_hsm.so
# macOS:   target/release/libcraton_hsm.dylib
# Windows: target/release/craton_hsm.dll

export PKCS11_MODULE_PATH=/path/to/libcraton_hsm.so
pkcs11-tool --module $PKCS11_MODULE_PATH --list-slots
```

---

## Feature Flags

| Flag | Default | Adds |
|---|---|---|
| `rustcrypto-backend` | ✓ | Pure-Rust classical crypto |
| `awslc-backend` | — | FIPS 140-3 validated AWS-LC |
| `fips` | — | Restrict to FIPS-approved algorithms |
| `quantum-resistant` | — | ML-KEM, ML-DSA, SLH-DSA |
| `hybrid-kem` | — | X25519 + ML-KEM-768 dual encapsulation |
| `bls-signatures` | — | BLS12-381 aggregatable signatures (blst) |
| `blake3-hash` | — | BLAKE3 parallel hashing |
| `argon2-kdf` | — | Argon2id memory-hard KDF |
| `voprf-protocol` | — | Verifiable OPRF (RFC 9497) |
| `opaque-auth` | — | OPAQUE PAKE zero-knowledge auth |
| `stark-proofs` | — | STARK proofs via Winterfell |
| `fhe-compute` | — | Fully Homomorphic Encryption (tfhe-rs) ⚠ large |
| `tpm-binding` | — | TPM 2.0 PCR sealing (requires libtss2) |
| `quic-transport` | — | QUIC cluster transport (quinn) |
| `noise-protocol` | — | Noise_XX cluster transport (snow) |
| `wasm-plugins` | — | WASM plugin engine (wasmtime) ⚠ large |
| `onnx-analytics` | — | ONNX ML inference (tract-onnx) |
| `wrapped-keys` | — | JSON / PKCS#8 / PKCS#12 key export |
| `observability` | — | Prometheus metrics + HTTP server |
| `enterprise` | — | `wrapped-keys` + `observability` |
| `advanced-all` | — | All advanced features except fhe-compute, tpm-binding, wasm-plugins |

> ⚠ `fhe-compute`, `tpm-binding`, and `wasm-plugins` are excluded from `advanced-all` due to large compile-time footprint. Enable individually when needed.

---

## Feature Matrix

| Capability | Crate / Algorithm | Status |
|---|---|---|
| **PKCS#11 v3.0 C ABI** | 70+ `#[no_mangle]` functions | ✅ Complete |
| **RSA · ECDSA · EdDSA** | rsa, p256/p384, ed25519-dalek | ✅ Complete |
| **AES-GCM/CBC/CTR/KW** | aes-gcm, cbc, ctr, aes-kw | ✅ Complete |
| **SHA-1/2/3 · HMAC** | sha1/2/3, hmac | ✅ Complete |
| **BLAKE3** | blake3 | ✅ Feature-gated |
| **Argon2id KDF** | argon2 | ✅ Feature-gated |
| **SP 800-90A HMAC_DRBG** | internal | ✅ Complete |
| **ML-KEM 512/768/1024** | ml-kem 0.3 (FIPS 203) | ✅ Complete |
| **ML-DSA 44/65/87** | ml-dsa 0.1 (FIPS 204) | ✅ Complete |
| **SLH-DSA** | slh-dsa 0.2 (FIPS 205) | ✅ Complete |
| **Hybrid KEM** | x25519-dalek + ml-kem | ✅ Feature-gated |
| **BLS12-381** | blst 0.3 (Ethereum ref) | ✅ Feature-gated |
| **VOPRF** | voprf 0.5 (RFC 9497) | ✅ Feature-gated |
| **Groth16 / Bulletproofs ZKP** | ark-groth16, bulletproofs | ✅ Feature-gated |
| **STARK proofs** | winterfell 0.9 | ✅ Feature-gated |
| **FHE** | tfhe 0.10 (Zama) | ✅ Feature-gated |
| **TPM 2.0** | tss-esapi 8 | ✅ Feature-gated |
| **Intel TDX attestation** | ioctl + EAT token | ✅ Linux only |
| **AMD SEV-SNP attestation** | ioctl + EAT token | ✅ Linux only |
| **AWS Nitro attestation** | /dev/nsm + COSE | ✅ Linux only |
| **WASM plugins** | wasmtime 25 + cranelift | ✅ Feature-gated |
| **QUIC transport** | quinn 0.11 | ✅ Feature-gated |
| **Noise Protocol** | snow 0.9 | ✅ Feature-gated |
| **Raft consensus** | internal | ✅ Enabled |
| **Wrapped key I/O** | JSON · PKCS#8 · PKCS#12 | ✅ Feature-gated |
| **Prometheus metrics** | prometheus 0.13, axum | ✅ Feature-gated |
| **Policy engine** | Cedar + OPA/WASM | ✅ Feature-gated |
| **Threshold FROST** | frost-ristretto255, vsss-rs | ✅ Feature-gated |
| **FIPS 140-3 POST** | 17 self-tests (16 KATs) | ✅ Always-on |
| **SP 800-57 key lifecycle** | pre-activation → compromised | ✅ Complete |
| **ONNX anomaly detection** | tract-onnx 0.21 | ✅ Feature-gated |
| **Fork safety** | libc pid detection | ✅ Unix |

---

## System Architecture

### Component layout

```mermaid
graph TB
    subgraph WS["Cargo Workspace"]
        subgraph CORE_LIB["craton-hsm  (core library)"]
            direction TB
            ABI_M["pkcs11_abi/<br/>types · constants · 70+ fns"]
            CORE_M["core.rs<br/>HsmCore"]
            SESSION_M["session/<br/>DashMap sessions"]
            TOKEN_M["token/<br/>PIN · lockout · SP 800-57"]
            STORE_M["store/<br/>encrypted redb · key cache<br/>wrapped-key I/O · backup"]
            CRYPTO_M["crypto/<br/>classical · PQC · hybrid KEM<br/>BLS · DRBG · self-tests<br/>backends (RustCrypto · AWS-LC)"]
            AUDIT_M["audit/<br/>chained SHA-256 log"]
            CLUSTER_M["cluster/<br/>Raft · replication<br/>mTLS · QUIC · Noise"]
            ADV_M["advanced/<br/>FHE · TPM · STARK<br/>WASM plugins · attestation<br/>ZKP · threshold · policy"]
            METRICS_M["metrics/<br/>Prometheus · Axum HTTP"]
        end

        DAEMON["craton-hsm-daemon<br/>gRPC server · mTLS"]
        ADMIN["tools/craton-hsm-admin<br/>CLI"]
        SPY["tools/pkcs11-spy<br/>debug wrapper"]
    end

    ABI_M & DAEMON & ADMIN --> CORE_M
    SPY --> ABI_M
    CORE_M --> SESSION_M & TOKEN_M & STORE_M & CRYPTO_M
    CORE_M --> AUDIT_M & CLUSTER_M & ADV_M & METRICS_M
```

### Data flow for a typical operation

```mermaid
flowchart LR
    subgraph IN["Entry"]
        CA["C_Sign() call"]
    end
    subgraph SESS["Session layer"]
        SV["Session validation<br/>handle → Session"]
        AUTH["Auth state check<br/>UserLoggedIn?"]
    end
    subgraph OPS["Operation"]
        DISP["HsmCore dispatch"]
        KEY["Load key from<br/>ObjectStore"]
        SIGN["Crypto backend<br/>sign()"]
    end
    subgraph OUT["Output + side effects"]
        RET["Return signature bytes<br/>CKR_OK"]
        AUDIT["Append to audit log<br/>HMAC chain"]
        METRICS["Increment Prometheus<br/>counters"]
    end

    CA --> SV --> AUTH --> DISP --> KEY --> SIGN --> RET
    SIGN --> AUDIT
    SIGN --> METRICS
```

---

## Performance

| Area | Improvement | Mechanism |
|---|---|---|
| RSA operations | 15–25% faster | `Arc<RsaPrivateKey>` in-memory cache |
| Session dispatch | 5–10% faster | Thread-local caching, reduced lock contention |
| Signature serialisation | 3–5% faster | Stack-allocated buffers, zero-copy |
| BLS batch verify | O(1) pairings for n triples | Miller-loop batching via blst |
| Cluster reconnect | 0-RTT on QUIC | quinn session resumption |
| STARK verification | ~1 ms regardless of N | FRI polynomial commitment |
| Key derivation | memory-hard | Argon2id (replaces PBKDF2 for new tokens) |
| Hashing throughput | 3× SHA-256 | BLAKE3 parallel tree |

---

## Standards Compliance

| Standard | Coverage |
|---|---|
| PKCS#11 v3.0 | 70+ C ABI functions, all major mechanisms |
| FIPS 203 (ML-KEM) | All three parameter sets |
| FIPS 204 (ML-DSA) | All three parameter sets |
| FIPS 205 (SLH-DSA) | SHA2-128s, SHA2-256s |
| SP 800-90A | HMAC_DRBG with prediction resistance |
| SP 800-57 | Full key lifecycle state machine |
| FIPS 140-3 Level 1 | Technical requirements implemented; not CMVP-validated |
| RFC 9497 | VOPRF (verifiable oblivious PRF) |
| IETF EAT | Entity Attestation Token output from attestation module |
| Noise Protocol | XX_25519_AESGCM_SHA256 cluster transport |

---

## Documentation

- [Documentation Index](docs/README.md)
- [Installation Guide](docs/install.md)
- [API Reference](docs/api-reference.md)
- [Configuration Reference](docs/configuration-reference.md)
- [Architecture Overview](docs/architecture.md)
- [Security Model](docs/security-model.md)
- [FIPS Gap Analysis](docs/fips-gap-analysis.md)
- [Operator Runbook](docs/operator-runbook.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Examples](docs/examples.md)
- [Migration Guide](docs/migration-guide.md)
- [Benchmarks](docs/benchmarks.md)
- [Tested Platforms](docs/tested-platforms.md)
- [Changelog](CHANGELOG.md)
- [Roadmap](ROADMAP.md)

---

## Disclaimer

**Craton HSM is NOT FIPS 140-3 certified.** While the codebase implements FIPS 140-3 Level 1 technical requirements (POST KATs, pairwise consistency tests, approved algorithms), it has not undergone CMVP validation. See `docs/fips-gap-analysis.md`.

## License

Copyright 2026 Craton Software Company. Licensed under the [Apache License, Version 2.0](LICENSE).
