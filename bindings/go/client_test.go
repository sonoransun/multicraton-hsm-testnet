// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company

package hsm

import (
	"errors"
	"testing"
)

func TestMechanismConstantsAreVendorDefined(t *testing.T) {
	// Every PQC mechanism must sit in the vendor-defined range (0x80000000+).
	cases := []struct {
		name string
		m    Mechanism
	}{
		{"CKM_ML_KEM_768", CKM_ML_KEM_768},
		{"CKM_ML_DSA_65", CKM_ML_DSA_65},
		{"CKM_SLH_DSA_SHA2_128S", CKM_SLH_DSA_SHA2_128S},
		{"CKM_HYBRID_ML_DSA_ECDSA", CKM_HYBRID_ML_DSA_ECDSA},
		{"CKM_HYBRID_P256_MLKEM768", CKM_HYBRID_P256_MLKEM768},
		{"CKM_FALCON_512", CKM_FALCON_512},
		{"CKM_FRODO_KEM_640_AES", CKM_FRODO_KEM_640_AES},
		{"CKM_HYBRID_KEM_WRAP", CKM_HYBRID_KEM_WRAP},
	}
	const vendorBase = 0x80000000
	for _, c := range cases {
		if uint64(c.m) < vendorBase {
			t.Errorf("%s = 0x%x is below the vendor-defined range", c.name, uint64(c.m))
		}
	}
}

func TestClientStubsReturnErrNotImplemented(t *testing.T) {
	// Until the proto stubs are generated, every operation returns
	// ErrNotImplemented. This test pins that contract so CI fails loudly
	// if someone accidentally removes the guard.
	c, err := New("localhost:1", WithJWT("dummy"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	if _, err := c.Sign(nil, 1, CKM_ML_DSA_65, []byte("x")); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("Sign returned %v, want ErrNotImplemented", err)
	}
	if _, _, err := c.Encapsulate(nil, 1, CKM_ML_KEM_768); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("Encapsulate returned %v, want ErrNotImplemented", err)
	}
}
