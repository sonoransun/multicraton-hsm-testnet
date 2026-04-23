# craton-hsm-go

Pure-Go client for Craton HSM over gRPC/mTLS. No cgo required.

## Install

```bash
go get github.com/craton-co/craton-hsm-go@latest
```

## Usage

```go
package main

import (
    "context"
    "crypto/tls"
    "fmt"

    hsm "github.com/craton-co/craton-hsm-go"
)

func main() {
    client, err := hsm.New(
        "hsm.example.com:9443",
        hsm.WithMTLS(clientCert, clientKey, caBundle),
    )
    if err != nil { panic(err) }
    defer client.Close()

    ctx := context.Background()

    // Sign (post-quantum: ML-DSA-65)
    sig, err := client.Sign(ctx, keyHandle, hsm.CKM_ML_DSA_65, []byte("hello"))
    if err != nil { panic(err) }

    // Encapsulate + decapsulate (hybrid KEM)
    ct, ss, err := client.Encapsulate(ctx, pubHandle, hsm.CKM_HYBRID_P256_MLKEM768)
    if err != nil { panic(err) }
    fmt.Printf("CT %dB, SS %dB\n", len(ct), len(ss))

    ss2, err := client.Decapsulate(ctx, privHandle, hsm.CKM_HYBRID_P256_MLKEM768, ct)
    if err != nil { panic(err) }

    if !bytes.Equal(ss, ss2) { panic("KEM roundtrip failed") }
}
```

## Proto sources

The proto definitions are regenerated from
`craton-hsm-daemon/proto/craton_hsm.proto`. See the main repository.

## Scope (this release)

| Operation | Status |
|---|---|
| Sessions: open / close / login | ✅ |
| Sign / Verify (all PQC mechanisms) | ✅ |
| Encapsulate / Decapsulate (ML-KEM, FrodoKEM, hybrid) | ✅ |
| Composite hybrid-sign / verify | ✅ |
| Wrap / Unwrap with CKM_HYBRID_KEM_WRAP | ✅ |
| Batch sign (streaming) | ⏳ planned |
| Attest | ⏳ planned |

Mechanism constants live in `mechanisms.go` mirroring
`src/pkcs11_abi/constants.rs` in the core repository.
