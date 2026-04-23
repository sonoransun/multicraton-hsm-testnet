# craton-hsm (Python)

Quantum-safe cryptographic operations from Python, either in-process or via a
central HSM over REST.

## Install

```bash
pip install craton-hsm
```

For the remote transport, also install `requests`:

```bash
pip install craton-hsm[remote]
```

## Build from source

```bash
cd bindings/python
pip install maturin
# Build + install the native extension in development mode
maturin develop --features "hybrid-kem,falcon-sig"
```

## Usage

### Local (in-process)

```python
from craton_hsm import HsmClient

c = HsmClient(mode="local")
print(c.capabilities()["ml_dsa_variants"])  # → ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87']

# Sign + verify (handles come from prior keygen via the admin CLI or
# PKCS#11 C_GenerateKeyPair)
sig = c.sign(handle=17, mechanism="CKM_ML_DSA_65", data=b"hello")
assert c.verify(handle=18, mechanism="CKM_ML_DSA_65", data=b"hello", signature=sig)
```

### Remote (REST gateway)

```python
c = HsmClient(
    mode="remote",
    base_url="https://hsm.example.com:9443",
    token="<JWT with scope=sign verify kem, cnf.x5t#S256 bound to client cert>",
    client_cert=("/etc/tls/client.crt", "/etc/tls/client.key"),
    verify="/etc/tls/ca.crt",
)
assert "ML-DSA-65" in c.capabilities()["ml_dsa_variants"]
```

Local and remote share the same surface — swapping transports requires one
constructor argument.

## Supported mechanisms

Call `c.capabilities()` for the full runtime list. Baseline (default build):

- ML-KEM-{512,768,1024} — `CKM_ML_KEM_*`
- ML-DSA-{44,65,87} — `CKM_ML_DSA_*`
- SLH-DSA (12 parameter sets) — `CKM_SLH_DSA_*`
- Composite signatures — `CKM_HYBRID_ML_DSA_ECDSA`, `CKM_HYBRID_ED25519_MLDSA65`

Feature-gated:

- Falcon-{512,1024} with `falcon-sig` — `CKM_FALCON_*`
- FrodoKEM-AES with `frodokem-kem` — `CKM_FRODO_KEM_*_AES`
- Hybrid KEMs with `hybrid-kem` — `CKM_HYBRID_*_MLKEM*`
