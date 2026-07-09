# Performance Tuning and Hardware Acceleration

## Overview

Craton HSM is written in pure Rust and, in its default configuration, ships **portable** binaries: a single build runs correctly on any CPU of the target architecture. Most of the hot cryptographic primitives already select hardware-accelerated implementations at **runtime**, by probing CPU feature flags on first use. This means the default build is fast without sacrificing portability.

This guide explains what is accelerated automatically, what a CPU-tuned build (`scripts/build-native.sh`) does and does not add, and how packagers should reason about the trade-off between portability and speed.

---

## Quick Reference

| Primitive | Default portable build | `target-cpu=native` adds? |
|-----------|------------------------|---------------------------|
| AES-GCM / CBC / CTR / KW | AES-NI + PCLMULQDQ (x86-64) / ARMv8 AES+PMULL (aarch64), runtime-detected | No — already dispatched |
| SHA-1 / SHA-256 | SHA-NI, runtime-detected | No — already dispatched |
| SHA-512 | Scalar (no SHA-NI path) | Modest autovectorization only |
| SHA-3 / Keccak | Scalar | Modest autovectorization only |
| RSA | Pure-Rust bignum (`rsa` 0.9) | **Yes** |
| P-256 / P-384 / P-521 / secp256k1 | Pure-Rust field arithmetic | **Yes** |
| curve25519 (Ed25519, X25519) | AVX2/SIMD backend, compile-time gated + runtime-guarded | **Yes** |
| ML-KEM / ML-DSA / SLH-DSA | Scalar pure-Rust | **Yes** (~+10-25% measured) |
| ChaCha20-Poly1305 | Internal runtime SIMD dispatch | No — already dispatched |
| BLAKE3 | Internal runtime SIMD dispatch | No — already dispatched |
| aws-lc-rs backend (`awslc-backend`) | Assembly + own runtime dispatch | No — independent of Rust flags |

---

## Default (Portable) Builds — What Is Runtime-Detected

The default `rustcrypto-backend` relies on the RustCrypto crates' built-in CPU feature detection. No special build flags are needed for these paths on x86-64:

- **AES-GCM, AES-CBC, AES-CTR, AES-KW / AES-KWP** — the `aes` crate selects **AES-NI** and the `polyval` crate (GHASH for GCM) selects **PCLMULQDQ / CLMUL** at runtime on x86-64 CPUs that advertise the features, falling back to constant-time software otherwise.
- **SHA-1 and SHA-256** — the `sha2` (and `sha1`) crates select **SHA-NI** at runtime (sha2 0.10 runtime detection), falling back to a scalar implementation.

### aarch64 (Apple Silicon, AWS Graviton)

On 64-bit ARM the ARMv8 Cryptographic Extensions (AES and PMULL) are **not** enabled by the crate defaults in the pinned versions. Craton HSM turns them on with two compile-time cfgs, now shipped in `.cargo/config.toml`:

```
--cfg aes_armv8 --cfg polyval_armv8
```

Crucially, these cfgs enable the ARMv8 backends **with runtime detection still active** on Linux and macOS — the code probes `AT_HWCAP` / `sysctl` for the AES feature before using it. The resulting binary therefore remains **portable across aarch64 CPUs**: it uses the accelerated path where available and the software path elsewhere. Because `.cargo/config.toml` applies these cfgs to every ordinary `cargo build`, no extra action is required for accelerated aarch64 builds.

> **Windows-on-ARM caveat:** the pinned `aes` / `polyval` versions have **no runtime feature detection on Windows aarch64**. On that target the crates fall back to the software implementation regardless of the cfgs. This affects only Windows-on-ARM; Linux and macOS on aarch64 are unaffected.

---

## What `target-cpu=native` Actually Helps

`scripts/build-native.sh` builds a release binary with `-C target-cpu=native` (plus, on aarch64, a re-added `--cfg aes_armv8 --cfg polyval_armv8` — see the gotcha below). This lets the compiler emit instructions specific to the building machine (AVX2, BMI2, etc.) and autovectorize scalar Rust code.

It measurably helps the primitives whose inner loops are **pure Rust** rather than intrinsic-dispatched:

- **RSA** — the modular arithmetic in the `rsa` 0.9 crate is pure-Rust bignum code; wider registers and BMI2 (`MULX`/`ADCX`/`ADOX`) speed multiply/reduce.
- **NIST curves** — P-256, P-384, and also P-521 and secp256k1 field arithmetic is pure Rust and benefits from native codegen.
- **curve25519-dalek** — its AVX2/SIMD backend is compile-time gated but **runtime-guarded**; a native build lets the compiler target the host's vector width.
- **Pure-Rust PQC** — ML-KEM, ML-DSA, and SLH-DSA are scalar Rust; autovectorization under `target-cpu=native` gives a measured **~+10-25%** on these operations.

It does **not** further speed AES-GCM or SHA-256: those already run on AES-NI / PCLMULQDQ / SHA-NI via runtime dispatch, and `target-cpu=native` changes nothing on those paths.

```bash
# Build a CPU-tuned binary for THIS machine only
./scripts/build-native.sh

# Extra cargo args are forwarded, e.g. features:
./scripts/build-native.sh --features "quantum-resistant"
```

> **Not for distribution.** A `target-cpu=native` binary may execute an instruction (e.g. an AVX-512 op) that a different CPU does not implement, causing a **SIGILL** (illegal instruction) crash. Only run these binaries on the machine class they were built for.

---

## SHA-512 and SHA-3

Neither SHA-512 nor SHA-3 / Keccak has a hardware instruction path in the pinned crate versions:

- **SHA-512** — there is no SHA-NI equivalent for SHA-512 on current x86-64, and the crate provides no dedicated dispatch. It runs a **scalar** implementation on all platforms.
- **SHA-3 / Keccak** — scalar on all platforms; no dedicated dispatch.

For both, a `target-cpu=native` build yields only **modest autovectorization**, not an order-of-magnitude change. Where SHA-512 throughput matters and a FIPS backend is acceptable, the `awslc-backend` provides an assembly implementation (see below).

---

## ChaCha20-Poly1305 and BLAKE3 (Optional Features)

These optional primitives ship their **own internal runtime SIMD dispatch** and need no build configuration:

- **ChaCha20-Poly1305 / XChaCha20** (`chacha20-aead` feature) — the `chacha20` and `poly1305` crates select SSE2/AVX2 (x86-64) or NEON (aarch64) at runtime.
- **BLAKE3** (`blake3-hash` feature) — the `blake3` crate performs its own runtime SIMD detection and multi-threaded tree hashing.

`target-cpu=native` is neither required nor beneficial for these paths.

---

## aws-lc-rs Backend (`awslc-backend`)

When built with the `awslc-backend` feature, cryptographic operations are dispatched to **AWS-LC**, which uses hand-written **assembly** implementations with its **own runtime CPU dispatch** — independent of any Rust compiler flags. `target-cpu=native` does not affect the aws-lc-rs code paths. Use this backend for FIPS 140-3 mode (see [FIPS Mode Guide](fips-mode-guide.md)); its assembly kernels also give strong SHA-512 and AES performance out of the box.

---

## Packager Guidance

For software distributed to an unknown mix of CPUs, **do not** use `target-cpu=native`. The portable default build already runtime-dispatches the highest-value primitives (AES-GCM, SHA-256, ChaCha20, BLAKE3).

If you control the deployment fleet and want the pure-Rust primitives (RSA, NIST curves, PQC) to benefit from wider instructions without the SIGILL risk of `native`, target a **defined baseline** instead:

```bash
# Middle ground for a controlled fleet: requires Haswell-era (2013+) x86-64.
RUSTFLAGS="-C target-cpu=x86-64-v3" cargo build --release
```

`x86-64-v3` enables AVX2/BMI2/FMA and runs on essentially all server and desktop CPUs from ~2015 onward, while still being a fixed, predictable ISA target — unlike `native`, which is whatever the build host happens to be.

> **SIGILL warning (repeat):** a binary built for a higher ISA than the CPU it runs on will crash with an illegal-instruction fault. If binaries are copied between hosts, pin the ISA to the **lowest** CPU in the fleet.

### Gotcha: `RUSTFLAGS` replaces `.cargo/config.toml` rustflags

Setting the `RUSTFLAGS` **environment variable REPLACES** (does not append to) the `rustflags` array in `.cargo/config.toml`. On **aarch64**, the config file supplies `--cfg aes_armv8 --cfg polyval_armv8`; if you set `RUSTFLAGS` yourself you will **drop those cfgs** and silently lose ARMv8 AES/PMULL acceleration.

When overriding `RUSTFLAGS` on aarch64, re-add them:

```bash
RUSTFLAGS="-C target-cpu=x86-64-v3" cargo build --release            # x86-64: fine
RUSTFLAGS="-C target-cpu=native --cfg aes_armv8 --cfg polyval_armv8" \
  cargo build --release                                              # aarch64: re-add cfgs
```

`scripts/build-native.sh` handles this automatically: it re-adds the two cfgs when `uname -m` reports `arm64` / `aarch64`.

---

## Deliberate Non-Optimizations

Some code paths are intentionally **not** made faster. Do not "optimize" these away — they are security properties, not oversights:

- **AES-CBC decrypt minimum-duration floor** — CBC decryption enforces a minimum operation duration. This is an intentional anti-timing / padding-oracle mitigation; removing the floor would reintroduce a side channel.
- **Always-full PBKDF2 PIN verification** — PIN verification always runs the full PBKDF2 iteration count even on early mismatch, to keep verification time independent of the guessed PIN. This constant-cost behavior is deliberate.
- **GCM nonce-counter key IDs are always SHA-256 hashes** — key identifiers used in GCM nonce construction are always derived via SHA-256 rather than a cheaper function. This chooses security (collision resistance / domain separation) over speed.

---

## Version Pins

This guidance is accurate for the currently pinned crate versions:

| Crate | Pinned version | Relevant behavior |
|-------|----------------|-------------------|
| `aes` | 0.8 | ARMv8 backend opt-in via `--cfg aes_armv8` |
| `polyval` | 0.6 | ARMv8 PMULL backend opt-in via `--cfg polyval_armv8` |
| `sha2` | 0.10 | SHA-NI runtime detection; `asm` feature present |

Upstream defaults change in future major versions:

- **aes 0.9 / polyval 0.7** — the ARMv8 AES/PMULL backends become the **default** (the `--cfg` opt-ins are no longer required).
- **sha2 0.11** — the `asm` feature is **removed** (assembly is folded into the default build).

When upgrading past these versions, revisit `.cargo/config.toml` and this document. See [Future Work Guide](future-work-guide.md) for the crate-upgrade procedure.
