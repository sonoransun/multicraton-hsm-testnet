// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company

// Package hsm is the Go client for Craton HSM. This file mirrors the
// PKCS#11 mechanism constants from src/pkcs11_abi/constants.rs so Go
// callers can name mechanisms symbolically instead of passing raw u64
// values over the wire.
package hsm

// Mechanism is a PKCS#11 CK_MECHANISM_TYPE (uint64 on 64-bit platforms).
type Mechanism uint64

// Classical RSA.
const (
	CKM_RSA_PKCS              Mechanism = 0x00000001
	CKM_RSA_PKCS_KEY_PAIR_GEN Mechanism = 0x00000000
	CKM_RSA_PKCS_OAEP         Mechanism = 0x00000009
	CKM_SHA256_RSA_PKCS       Mechanism = 0x00000040
	CKM_SHA384_RSA_PKCS       Mechanism = 0x00000041
	CKM_SHA512_RSA_PKCS       Mechanism = 0x00000042
)

// Classical EC.
const (
	CKM_EC_KEY_PAIR_GEN Mechanism = 0x00001040
	CKM_ECDSA           Mechanism = 0x00001041
	CKM_ECDSA_SHA256    Mechanism = 0x00001042
	CKM_ECDSA_SHA384    Mechanism = 0x00001043
	CKM_ECDSA_SHA512    Mechanism = 0x00001044
)

// EdDSA.
const CKM_EDDSA Mechanism = 0x00001057

// AES.
const (
	CKM_AES_KEY_GEN      Mechanism = 0x00001080
	CKM_AES_GCM          Mechanism = 0x00001087
	CKM_AES_CBC          Mechanism = 0x00001082
	CKM_AES_CTR          Mechanism = 0x00001086
	CKM_AES_KEY_WRAP     Mechanism = 0x00002109
	CKM_AES_KEY_WRAP_KWP Mechanism = 0x0000210B
)

// Post-Quantum (vendor-defined). Matches craton-hsm's `src/pkcs11_abi/constants.rs`.
const (
	CKM_ML_KEM_512  Mechanism = 0x80000001
	CKM_ML_KEM_768  Mechanism = 0x80000002
	CKM_ML_KEM_1024 Mechanism = 0x80000003

	CKM_ML_DSA_44 Mechanism = 0x80000010
	CKM_ML_DSA_65 Mechanism = 0x80000011
	CKM_ML_DSA_87 Mechanism = 0x80000012

	CKM_SLH_DSA_SHA2_128S  Mechanism = 0x80000020
	CKM_SLH_DSA_SHA2_256S  Mechanism = 0x80000021
	CKM_SLH_DSA_SHA2_128F  Mechanism = 0x80000022
	CKM_SLH_DSA_SHA2_192S  Mechanism = 0x80000023
	CKM_SLH_DSA_SHA2_192F  Mechanism = 0x80000024
	CKM_SLH_DSA_SHA2_256F  Mechanism = 0x80000025
	CKM_SLH_DSA_SHAKE_128S Mechanism = 0x80000026
	CKM_SLH_DSA_SHAKE_128F Mechanism = 0x80000027
	CKM_SLH_DSA_SHAKE_192S Mechanism = 0x80000028
	CKM_SLH_DSA_SHAKE_192F Mechanism = 0x80000029
	CKM_SLH_DSA_SHAKE_256S Mechanism = 0x8000002A
	CKM_SLH_DSA_SHAKE_256F Mechanism = 0x8000002B

	CKM_HYBRID_ML_DSA_ECDSA Mechanism = 0x80000030

	CKM_FALCON_512  Mechanism = 0x80000040
	CKM_FALCON_1024 Mechanism = 0x80000041

	CKM_FRODO_KEM_640_AES  Mechanism = 0x80000050
	CKM_FRODO_KEM_976_AES  Mechanism = 0x80000051
	CKM_FRODO_KEM_1344_AES Mechanism = 0x80000052

	CKM_HYBRID_X25519_MLKEM1024 Mechanism = 0x80000060
	CKM_HYBRID_P256_MLKEM768    Mechanism = 0x80000061
	CKM_HYBRID_P384_MLKEM1024   Mechanism = 0x80000062
	CKM_HYBRID_ED25519_MLDSA65  Mechanism = 0x80000063

	CKM_HYBRID_KEM_WRAP Mechanism = 0x80000070
)
