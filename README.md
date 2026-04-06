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
    subgraph CLIENTS["Clients"]
        A1["OpenSSL / NSS / Java"]
        A2["Cloud Services"]
        A3["Admin CLI"]
    end

    subgraph INTERFACES["Interfaces"]
        I1["PKCS#11 C ABI"]
        I2["gRPC / mTLS"]
        I3["Admin CLI"]
    end

    subgraph CORE["HsmCore"]
        C1["Sessions"]
        C2["Tokens & PIN"]
        C3["Object Store"]
        C4["Audit Log"]
    end

    subgraph CRYPTO["Crypto Engine"]
        direction LR
        CL["Classical<br/><i>RSA · ECDSA · EdDSA · AES</i>"]
        PQ["Post-Quantum<br/><i>ML-KEM · ML-DSA · SLH-DSA</i>"]
        HY["Hybrid & BLS<br/><i>X25519⊕ML-KEM · BLS12-381</i>"]
        DR["DRBG<br/><i>SP 800-90A</i>"]
    end

    subgraph ADVANCED["Advanced"]
        direction LR
        FH["FHE · TPM 2.0"]
        SK["STARK · WASM"]
        AT["Attestation"]
    end

    subgraph CLUSTER["Transport"]
        direction LR
        MT["mTLS"]
        QU["QUIC"]
        NO["Noise"]
    end

    A1 --> I1
    A2 --> I2
    A3 --> I3
    I1 & I2 & I3 --> CORE
    CORE --> CRYPTO
    CORE --> ADVANCED
    CORE --> CLUSTER

    classDef client fill:#e0e0e0,color:#333
    classDef iface fill:#7a5c2d,color:#fff
    classDef core fill:#2d4a7a,color:#fff
    classDef crypto fill:#1a6e2e,color:#fff
    classDef adv fill:#4a2d7a,color:#fff
    class A1,A2,A3 client
    class I1,I2,I3 iface
    class C1,C2,C3,C4 core
    class CL,PQ,HY,DR crypto
    class FH,SK,AT adv
    class MT,QU,NO iface
```

---

## Cryptographic Capabilities

### Algorithm taxonomy

```mermaid
graph LR
    subgraph CLASS["Classical  (128–256 bit)"]
        direction TB
        RSA["RSA  2048 · 3072 · 4096"]
        EC["ECDSA  P-256 · P-384 · K-256"]
        ED["EdDSA  Ed25519 · Ed448"]
        AES["AES  CBC · CTR · GCM · KW"]
        SHA["Hash  SHA-1/2/3 · BLAKE3 · HMAC"]
        KDF["KDF  PBKDF2 · Argon2id · HKDF"]
    end

    subgraph PQC["Post-Quantum  (FIPS 203-205)"]
        direction TB
        KEM["ML-KEM  512 · 768 · 1024"]
        DSA["ML-DSA  44 · 65 · 87"]
        SLH["SLH-DSA  SHA2-128s · 256s"]
    end

    subgraph HYBRID["Hybrid  (classical ⊕ PQ)"]
        direction TB
        HK["Hybrid KEM<br/>X25519 ⊕ ML-KEM-768"]
        HS["Hybrid Sign<br/>ECDSA-P256 ⊕ ML-DSA-65"]
    end

    subgraph SPECIAL["Specialized"]
        direction TB
        BLS["BLS12-381<br/>Aggregatable signatures"]
        VF["VOPRF  RFC 9497"]
    end

    CLASS --> HYBRID
    PQC --> HYBRID
    CLASS --> SPECIAL

    classDef classical fill:#2d4a7a,color:#fff
    classDef pqc fill:#4a2d7a,color:#fff
    classDef hybrid fill:#1a6e2e,color:#fff
    classDef special fill:#7a5c2d,color:#fff
    class RSA,EC,ED,AES,SHA,KDF classical
    class KEM,DSA,SLH pqc
    class HK,HS hybrid
    class BLS,VF special
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
    SIGN["n Signers<br/><i>sk₁…skₙ sign(msg)</i>"]
    SIGS["n Signatures<br/><i>[96 B each]</i>"]
    PKS["n Public Keys<br/><i>[48 B each]</i>"]

    SIGN --> SIGS
    SIGS --> AGG["aggregate()<br/><i>→ 1 AggSig [96 B]</i>"]
    PKS --> AGGPK["aggregate()<br/><i>→ 1 AggPK [48 B]</i>"]

    AGG & AGGPK --> VFY{"verify(msg)<br/><i>O(1) pairings</i>"}
    VFY -->|"valid"| OK(["All n signers approved"])
    VFY -->|"invalid"| FAIL(["Rejected"])

    classDef agg fill:#2d4a7a,color:#fff
    classDef ok fill:#1a6e2e,color:#fff
    classDef fail fill:#7a2d2d,color:#fff
    class AGG,AGGPK agg
    class OK ok
    class FAIL fail
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
        T["Execution trace<br/><i>N steps × 2 columns</i>"]
        A["AIR constraints<br/><i>transition + boundary</i>"]
        LDE["Low-degree extension<br/><i>evaluation domain</i>"]
        FRI["FRI commitment<br/><i>log(N) rounds</i>"]
        PR["Proof<br/><i>~10 KB for N=64</i>"]
        T --> A --> LDE --> FRI --> PR
    end

    subgraph VERIFY["Verifier  (~1 ms)"]
        V["winterfell::verify()<br/><i>no secret knowledge</i>"]
        V -->|valid| OK(["Counter correct"])
        V -->|invalid| FAIL(["Proof rejected"])
    end

    PR --> V

    classDef prove fill:#2d4a7a,color:#fff
    classDef ok fill:#1a6e2e,color:#fff
    classDef fail fill:#7a2d2d,color:#fff
    class T,A,LDE,FRI,PR prove
    class OK ok
    class FAIL fail
```

**Properties:** Post-quantum security (hash-based, not pairing-based). Proof size sub-linear in trace length. Verification ~1 ms regardless of computation size.

### Remote Attestation

```mermaid
flowchart TD
    subgraph DETECT["Platform Detection"]
        D{"/dev/tdx_guest?<br/>/dev/sev-guest?<br/>/dev/nsm?"}
        D -->|TDX| TDX["Intel TDX<br/><i>TD Quote via QE</i>"]
        D -->|SEV-SNP| SNP["AMD SEV-SNP<br/><i>attestation report</i>"]
        D -->|Nitro| NITRO["AWS Nitro<br/><i>COSE_Sign1</i>"]
        D -->|none| SW["Software fallback<br/><i>P-256 self-signed</i>"]
    end

    TDX & SNP & NITRO & SW --> TOKEN["AttestationToken<br/><i>platform · nonce · measurement · signature</i>"]

    TOKEN --> V1["Verify nonce freshness"]
    V1 --> V2["Verify signature vs platform CA"]
    V2 --> V3{"Measurement matches<br/>known-good policy?"}
    V3 -->|match| TRUST(["Node trusted<br/>allow key operations"])
    V3 -->|mismatch| REJECT(["Attestation failed<br/>reject node"])

    classDef ok fill:#1a6e2e,color:#fff
    classDef fail fill:#7a2d2d,color:#fff
    classDef platform fill:#2d4a7a,color:#fff
    class TRUST ok
    class REJECT fail
    class TDX,SNP,NITRO,SW,TOKEN platform
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
    subgraph TRANSPORT["ClusterTransport — select per deployment"]
        direction LR

        subgraph MTLS["mTLS  (default)"]
            MT1["TLS 1.3 + client certs"]
            MT2["Standard PKI integration"]
            MT3["Widest tooling support"]
        end

        subgraph QUIC["QUIC  (quic-transport)"]
            QU1["0-RTT session resumption"]
            QU2["Stream multiplexing<br/>no HOL blocking"]
            QU3["Connection migration<br/>survives NAT rebind"]
        end

        subgraph NOISE["Noise  (noise-protocol)"]
            NO1["Noise_XX_25519_AESGCM"]
            NO2["No PKI needed"]
            NO3["Static X25519 key pairs"]
        end
    end

    MTLS ~~~ N1["Use when: existing PKI,<br/>enterprise compliance"]
    QUIC ~~~ N2["Use when: high throughput,<br/>mobile/NAT, multiplexed"]
    NOISE ~~~ N3["Use when: peer-to-peer,<br/>no CA, minimal deps"]

    classDef note fill:#7a5c2d,color:#fff
    class N1,N2,N3 note
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

    Note over L,F2: Heartbeats on separate QUIC stream

    alt Leader failure
        Note over L: Leader crashes or network partition
        F1->>F1: Election timeout expires
        F1->>F2: RequestVote
        F2-->>F1: VoteGranted
        Note over F1: F1 becomes new Leader
        C->>LB: Retry operation
        LB->>F1: Route to new leader
    end
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

    rect rgb(122, 92, 45)
        Note over HSM2: Validation checks
        HSM2->>HSM2: Verify JSON schema version
        HSM2->>HSM2: Check export timestamp < max_age
        HSM2->>HSM2: Verify serial_number matches target
    end

    alt Validation passes
        HSM2->>HSM2: UnwrapKey(kek, wrapped_data) → key handle
        HSM2-->>HSM1: Acknowledge (cluster replicated)
    else Validation fails
        HSM2->>HSM2: Reject import, log audit event
    end
```

---

## Security Architecture

### Defence-in-depth layers

```mermaid
flowchart TD
    ATK1(["External attacker"])
    ATK1 --> L1

    subgraph L1["Layer 1 — Authentication"]
        A1["OPAQUE PAKE · PIN lockout · RBAC policy"]
    end
    L1 -->|"no credentials"| STOP1["Blocked: unauthorized"]
    L1 -->|"authenticated"| L2

    subgraph L2["Layer 2 — Transport"]
        B1["mTLS 1.3 / QUIC / Noise · rate limiting"]
    end
    L2 -->|"invalid cert"| STOP2["Blocked: TLS rejected"]
    L2 -->|"encrypted channel"| L3

    subgraph L3["Layer 3 — Crypto Integrity"]
        C1["17 POST KATs · HMAC_DRBG · constant-time ops"]
    end
    L3 -->|"tampered binary"| STOP3["Blocked: POST failed"]
    L3 -->|"verified"| L4

    subgraph L4["Layer 4 — Key Storage"]
        D1["AES-256-GCM store · mlock · ZeroizeOnDrop"]
    end
    L4 -->|"swap/remanence"| STOP4["Blocked: memory locked"]
    L4 -->|"key loaded"| L5

    subgraph L5["Layer 5 — Platform"]
        E1["TPM PCR seal · TEE attestation · audit chain"]
    end
    L5 --> SAFE(["Operation complete<br/>Audit logged"])

    classDef stop fill:#7a2d2d,color:#fff
    classDef safe fill:#1a6e2e,color:#fff
    classDef layer fill:#2d4a7a,color:#fff
    class STOP1,STOP2,STOP3,STOP4 stop
    class SAFE safe
    class A1,B1,C1,D1,E1 layer
```

### Zero-knowledge proof subsystem

```mermaid
flowchart TD
    Q{"What do you<br/>need to prove?"}

    Q -->|"Range proof<br/>(value in bounds)"| BP["Bulletproofs<br/><i>small proofs, no setup</i>"]
    Q -->|"Complex statement<br/>(trusted setup OK)"| G16["Groth16<br/><i>constant-size proofs, fast verify</i>"]
    Q -->|"Scalable integrity<br/>(post-quantum)"| STARK["STARK<br/><i>transparent, hash-based</i>"]

    BP --> USE1["Audit: prove operation<br/>without revealing data"]
    G16 --> USE1
    STARK --> USE2["Compliance: prove algorithm<br/>policy was followed"]

    subgraph APPS["Proof Applications"]
        AUTH["PIN knowledge proof<br/><i>without revealing PIN</i>"]
        OWN["Key ownership proof<br/><i>sk ↔ pk binding</i>"]
        MEM["Merkle membership<br/><i>key in approved set</i>"]
    end

    USE1 --> APPS

    classDef zkp fill:#4a2d7a,color:#fff
    classDef stark fill:#2d4a7a,color:#fff
    classDef app fill:#1a6e2e,color:#fff
    class BP,G16 zkp
    class STARK stark
    class AUTH,OWN,MEM app
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
        subgraph LIB["craton-hsm  (cdylib + rlib)"]
            ABI["PKCS#11 ABI"]
            CORE["HsmCore"]
            SESS_TOK["Sessions & Tokens"]
            STORE["Object Store"]
            CRYPTO["Crypto Engine"]
            AUDIT["Audit Log"]
        end
        DAEMON["craton-hsm-daemon"]
        ADMIN["craton-hsm-admin"]
        SPY["pkcs11-spy"]
    end

    ABI & DAEMON & ADMIN --> CORE
    SPY --> ABI
    CORE --> SESS_TOK & STORE & CRYPTO & AUDIT

    classDef core fill:#2d4a7a,color:#fff
    classDef tool fill:#e0e0e0,color:#333
    class ABI,CORE,SESS_TOK,STORE,CRYPTO,AUDIT core
    class DAEMON,ADMIN,SPY tool
```

### Data flow for a typical operation

```mermaid
flowchart LR
    CA["C_Sign()"] --> SV["Validate<br/>session"]
    SV -->|invalid| E1["CKR_SESSION_<br/>HANDLE_INVALID"]
    SV -->|ok| AUTH["Check<br/>auth"]
    AUTH -->|not logged in| E2["CKR_USER_<br/>NOT_LOGGED_IN"]
    AUTH -->|ok| KEY["Load key"]
    KEY -->|not found| E3["CKR_KEY_<br/>HANDLE_INVALID"]
    KEY -->|ok| SIGN["Crypto<br/>sign()"]
    SIGN --> RET(["Signature bytes<br/>CKR_OK"])
    SIGN --> AUDIT["Audit log"]
    SIGN --> MET["Metrics"]

    classDef err fill:#7a2d2d,color:#fff
    classDef ok fill:#1a6e2e,color:#fff
    classDef step fill:#2d4a7a,color:#fff
    class E1,E2,E3 err
    class RET ok
    class CA,SV,AUTH,KEY,SIGN,AUDIT,MET step
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
