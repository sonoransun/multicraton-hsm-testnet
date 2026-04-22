// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Falcon (FN-DSA, forthcoming FIPS 206) digital signatures.
//!
//! Wraps the PQClean reference C implementation via [`pqcrypto-falcon`].
//! This is the project's only non-pure-Rust crypto module and is therefore
//! gated behind the `falcon-sig` feature. The default library build contains
//! no C dependencies.
//!
//! Variants: Falcon-512 (NIST category I) and Falcon-1024 (NIST category V).
//! Falcon signatures are **variable length**; the returned byte slice encodes
//! the true length.
//!
//! ## RNG caveat
//! `pqcrypto-falcon` invokes PQClean's internal OS-RNG path (`randombytes`)
//! during `keypair()` and `detached_sign()`. There is no public hook to
//! inject our FIPS DRBG, so these operations do not flow through the
//! SP 800-90A health-tested path that ML-KEM/ML-DSA use. This is an
//! upstream-tracked limitation — see `docs/future-work-guide.md`.
//!
//! ## Ciphertext layout
//! Not applicable — Falcon is a signature scheme. Keys and signatures are
//! serialized as raw byte slices via the `pqcrypto-traits` trait methods.

#![cfg(feature = "falcon-sig")]

use pqcrypto_falcon::{falcon1024, falcon512};
use pqcrypto_traits::sign::{
    DetachedSignature as _, PublicKey as _, SecretKey as _,
};

use crate::error::{HsmError, HsmResult};
use crate::store::key_material::RawKeyMaterial;

/// Falcon parameter sets supported by this module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FalconVariant {
    /// Falcon-512 — NIST category I (~AES-128 equivalent).
    Falcon512,
    /// Falcon-1024 — NIST category V (~AES-256 equivalent).
    Falcon1024,
}

/// Generate a Falcon keypair. Returns `(secret_key_bytes, public_key_bytes)`.
pub fn falcon_keygen(variant: FalconVariant) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
    match variant {
        FalconVariant::Falcon512 => {
            let (pk, sk) = falcon512::keypair();
            Ok((
                RawKeyMaterial::new(sk.as_bytes().to_vec()),
                pk.as_bytes().to_vec(),
            ))
        }
        FalconVariant::Falcon1024 => {
            let (pk, sk) = falcon1024::keypair();
            Ok((
                RawKeyMaterial::new(sk.as_bytes().to_vec()),
                pk.as_bytes().to_vec(),
            ))
        }
    }
}

/// Falcon detached signature over `data`. Signature bytes are variable length.
pub fn falcon_sign(
    secret_key_bytes: &[u8],
    data: &[u8],
    variant: FalconVariant,
) -> HsmResult<Vec<u8>> {
    match variant {
        FalconVariant::Falcon512 => {
            let sk = falcon512::SecretKey::from_bytes(secret_key_bytes)
                .map_err(|_| HsmError::KeyHandleInvalid)?;
            let sig = falcon512::detached_sign(data, &sk);
            Ok(sig.as_bytes().to_vec())
        }
        FalconVariant::Falcon1024 => {
            let sk = falcon1024::SecretKey::from_bytes(secret_key_bytes)
                .map_err(|_| HsmError::KeyHandleInvalid)?;
            let sig = falcon1024::detached_sign(data, &sk);
            Ok(sig.as_bytes().to_vec())
        }
    }
}

/// Verify a Falcon detached signature. Returns `Ok(false)` on bad signature,
/// `Err(...)` only on key/parse failure.
pub fn falcon_verify(
    public_key_bytes: &[u8],
    data: &[u8],
    signature: &[u8],
    variant: FalconVariant,
) -> HsmResult<bool> {
    match variant {
        FalconVariant::Falcon512 => {
            let pk = falcon512::PublicKey::from_bytes(public_key_bytes)
                .map_err(|_| HsmError::KeyHandleInvalid)?;
            let sig = match falcon512::DetachedSignature::from_bytes(signature) {
                Ok(s) => s,
                Err(_) => return Ok(false),
            };
            Ok(falcon512::verify_detached_signature(&sig, data, &pk).is_ok())
        }
        FalconVariant::Falcon1024 => {
            let pk = falcon1024::PublicKey::from_bytes(public_key_bytes)
                .map_err(|_| HsmError::KeyHandleInvalid)?;
            let sig = match falcon1024::DetachedSignature::from_bytes(signature) {
                Ok(s) => s,
                Err(_) => return Ok(false),
            };
            Ok(falcon1024::verify_detached_signature(&sig, data, &pk).is_ok())
        }
    }
}

// ----------------------------------------------------------------------------
// Mechanism dispatch helpers
// ----------------------------------------------------------------------------

use crate::pkcs11_abi::constants::{CKM_FALCON_1024, CKM_FALCON_512};
use crate::pkcs11_abi::types::CK_MECHANISM_TYPE;

pub fn mechanism_to_falcon_variant(mechanism: CK_MECHANISM_TYPE) -> Option<FalconVariant> {
    match mechanism {
        CKM_FALCON_512 => Some(FalconVariant::Falcon512),
        CKM_FALCON_1024 => Some(FalconVariant::Falcon1024),
        _ => None,
    }
}

pub fn is_falcon_mechanism(mechanism: CK_MECHANISM_TYPE) -> bool {
    mechanism_to_falcon_variant(mechanism).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn falcon512_roundtrip() {
        let (sk, pk) = falcon_keygen(FalconVariant::Falcon512).unwrap();
        let msg = b"Falcon-512 roundtrip test";
        let sig = falcon_sign(sk.as_bytes(), msg, FalconVariant::Falcon512).unwrap();
        assert!(falcon_verify(&pk, msg, &sig, FalconVariant::Falcon512).unwrap());
    }

    #[test]
    fn falcon1024_roundtrip() {
        let (sk, pk) = falcon_keygen(FalconVariant::Falcon1024).unwrap();
        let msg = b"Falcon-1024 roundtrip test";
        let sig = falcon_sign(sk.as_bytes(), msg, FalconVariant::Falcon1024).unwrap();
        assert!(falcon_verify(&pk, msg, &sig, FalconVariant::Falcon1024).unwrap());
    }

    #[test]
    fn falcon_wrong_message_fails() {
        let (sk, pk) = falcon_keygen(FalconVariant::Falcon512).unwrap();
        let sig = falcon_sign(sk.as_bytes(), b"original", FalconVariant::Falcon512).unwrap();
        assert!(!falcon_verify(&pk, b"tampered", &sig, FalconVariant::Falcon512).unwrap());
    }
}
