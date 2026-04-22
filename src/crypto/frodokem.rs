// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! FrodoKEM conservative-lattice Key Encapsulation Mechanism.
//!
//! Wraps the PQClean reference C implementation via [`pqcrypto-frodo`].
//! FrodoKEM is a **learning with errors** (LWE) based KEM and is a deliberately
//! conservative alternative to lattice KEMs built on structured (M-LWE/R-LWE)
//! problems like ML-KEM (Kyber). Recommended by **BSI TR-02102** as an
//! alternative / diversity hedge.
//!
//! FrodoKEM was not selected by NIST for standardization but remains widely
//! implemented and is on the recommendation lists of several European and
//! academic PQC guidance documents.
//!
//! This module is gated behind the `frodokem-kem` feature and is the only
//! other non-pure-Rust crypto module besides [`crate::crypto::falcon`].
//!
//! ## Variants
//! | Variant                  | Claimed security | Public key | Ciphertext | Shared secret |
//! |--------------------------|------------------|-----------:|-----------:|--------------:|
//! | FrodoKEM-640-AES         | NIST cat I       |   9616 B   |   9720 B   |    16 B       |
//! | FrodoKEM-976-AES         | NIST cat III     |  15632 B   |  15744 B   |    24 B       |
//! | FrodoKEM-1344-AES        | NIST cat V       |  21520 B   |  21632 B   |    32 B       |
//!
//! (SHAKE variants are available upstream but not wired here; add them if
//! you need CNSA-2.0-style XOF-only dependencies.)
//!
//! ## RNG caveat
//! The underlying PQClean code calls `randombytes` internally — there is no
//! hook to inject a DRBG. See the note in [`crate::crypto::falcon`].

#![cfg(feature = "frodokem-kem")]

use pqcrypto_frodo::{frodokem1344aes, frodokem640aes, frodokem976aes};
use pqcrypto_traits::kem::{
    Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _,
};

use crate::error::{HsmError, HsmResult};
use crate::store::key_material::RawKeyMaterial;

/// FrodoKEM parameter sets exposed by this module (AES-based only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrodoVariant {
    /// FrodoKEM-640-AES — NIST category I (~AES-128).
    Frodo640Aes,
    /// FrodoKEM-976-AES — NIST category III (~AES-192).
    Frodo976Aes,
    /// FrodoKEM-1344-AES — NIST category V (~AES-256).
    Frodo1344Aes,
}

/// Generate a FrodoKEM keypair. Returns `(secret_key_bytes, public_key_bytes)`.
pub fn frodo_keygen(variant: FrodoVariant) -> HsmResult<(RawKeyMaterial, Vec<u8>)> {
    match variant {
        FrodoVariant::Frodo640Aes => {
            let (pk, sk) = frodokem640aes::keypair();
            Ok((
                RawKeyMaterial::new(sk.as_bytes().to_vec()),
                pk.as_bytes().to_vec(),
            ))
        }
        FrodoVariant::Frodo976Aes => {
            let (pk, sk) = frodokem976aes::keypair();
            Ok((
                RawKeyMaterial::new(sk.as_bytes().to_vec()),
                pk.as_bytes().to_vec(),
            ))
        }
        FrodoVariant::Frodo1344Aes => {
            let (pk, sk) = frodokem1344aes::keypair();
            Ok((
                RawKeyMaterial::new(sk.as_bytes().to_vec()),
                pk.as_bytes().to_vec(),
            ))
        }
    }
}

/// FrodoKEM encapsulate. Returns `(ciphertext_bytes, shared_secret_bytes)`.
pub fn frodo_encapsulate(
    public_key_bytes: &[u8],
    variant: FrodoVariant,
) -> HsmResult<(Vec<u8>, Vec<u8>)> {
    match variant {
        FrodoVariant::Frodo640Aes => {
            let pk = frodokem640aes::PublicKey::from_bytes(public_key_bytes)
                .map_err(|_| HsmError::KeyHandleInvalid)?;
            let (ss, ct) = frodokem640aes::encapsulate(&pk);
            Ok((ct.as_bytes().to_vec(), ss.as_bytes().to_vec()))
        }
        FrodoVariant::Frodo976Aes => {
            let pk = frodokem976aes::PublicKey::from_bytes(public_key_bytes)
                .map_err(|_| HsmError::KeyHandleInvalid)?;
            let (ss, ct) = frodokem976aes::encapsulate(&pk);
            Ok((ct.as_bytes().to_vec(), ss.as_bytes().to_vec()))
        }
        FrodoVariant::Frodo1344Aes => {
            let pk = frodokem1344aes::PublicKey::from_bytes(public_key_bytes)
                .map_err(|_| HsmError::KeyHandleInvalid)?;
            let (ss, ct) = frodokem1344aes::encapsulate(&pk);
            Ok((ct.as_bytes().to_vec(), ss.as_bytes().to_vec()))
        }
    }
}

/// FrodoKEM decapsulate. Returns the recovered shared secret bytes.
///
/// FrodoKEM uses implicit rejection (like ML-KEM): a corrupted ciphertext
/// produces a pseudorandom shared secret rather than failing, which is safe
/// under authenticated-KEM usage.
pub fn frodo_decapsulate(
    secret_key_bytes: &[u8],
    ciphertext_bytes: &[u8],
    variant: FrodoVariant,
) -> HsmResult<Vec<u8>> {
    match variant {
        FrodoVariant::Frodo640Aes => {
            let sk = frodokem640aes::SecretKey::from_bytes(secret_key_bytes)
                .map_err(|_| HsmError::KeyHandleInvalid)?;
            let ct = frodokem640aes::Ciphertext::from_bytes(ciphertext_bytes)
                .map_err(|_| HsmError::EncryptedDataInvalid)?;
            let ss = frodokem640aes::decapsulate(&ct, &sk);
            Ok(ss.as_bytes().to_vec())
        }
        FrodoVariant::Frodo976Aes => {
            let sk = frodokem976aes::SecretKey::from_bytes(secret_key_bytes)
                .map_err(|_| HsmError::KeyHandleInvalid)?;
            let ct = frodokem976aes::Ciphertext::from_bytes(ciphertext_bytes)
                .map_err(|_| HsmError::EncryptedDataInvalid)?;
            let ss = frodokem976aes::decapsulate(&ct, &sk);
            Ok(ss.as_bytes().to_vec())
        }
        FrodoVariant::Frodo1344Aes => {
            let sk = frodokem1344aes::SecretKey::from_bytes(secret_key_bytes)
                .map_err(|_| HsmError::KeyHandleInvalid)?;
            let ct = frodokem1344aes::Ciphertext::from_bytes(ciphertext_bytes)
                .map_err(|_| HsmError::EncryptedDataInvalid)?;
            let ss = frodokem1344aes::decapsulate(&ct, &sk);
            Ok(ss.as_bytes().to_vec())
        }
    }
}

// ----------------------------------------------------------------------------
// Mechanism dispatch helpers
// ----------------------------------------------------------------------------

use crate::pkcs11_abi::constants::{
    CKM_FRODO_KEM_1344_AES, CKM_FRODO_KEM_640_AES, CKM_FRODO_KEM_976_AES,
};
use crate::pkcs11_abi::types::CK_MECHANISM_TYPE;

pub fn mechanism_to_frodo_variant(mechanism: CK_MECHANISM_TYPE) -> Option<FrodoVariant> {
    match mechanism {
        CKM_FRODO_KEM_640_AES => Some(FrodoVariant::Frodo640Aes),
        CKM_FRODO_KEM_976_AES => Some(FrodoVariant::Frodo976Aes),
        CKM_FRODO_KEM_1344_AES => Some(FrodoVariant::Frodo1344Aes),
        _ => None,
    }
}

pub fn is_frodo_mechanism(mechanism: CK_MECHANISM_TYPE) -> bool {
    mechanism_to_frodo_variant(mechanism).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frodo640_roundtrip() {
        let (sk, pk) = frodo_keygen(FrodoVariant::Frodo640Aes).unwrap();
        let (ct, ss_a) = frodo_encapsulate(&pk, FrodoVariant::Frodo640Aes).unwrap();
        let ss_b = frodo_decapsulate(sk.as_bytes(), &ct, FrodoVariant::Frodo640Aes).unwrap();
        assert_eq!(ss_a, ss_b);
    }

    #[test]
    fn frodo976_roundtrip() {
        let (sk, pk) = frodo_keygen(FrodoVariant::Frodo976Aes).unwrap();
        let (ct, ss_a) = frodo_encapsulate(&pk, FrodoVariant::Frodo976Aes).unwrap();
        let ss_b = frodo_decapsulate(sk.as_bytes(), &ct, FrodoVariant::Frodo976Aes).unwrap();
        assert_eq!(ss_a, ss_b);
    }

    #[test]
    fn frodo1344_roundtrip() {
        let (sk, pk) = frodo_keygen(FrodoVariant::Frodo1344Aes).unwrap();
        let (ct, ss_a) = frodo_encapsulate(&pk, FrodoVariant::Frodo1344Aes).unwrap();
        let ss_b = frodo_decapsulate(sk.as_bytes(), &ct, FrodoVariant::Frodo1344Aes).unwrap();
        assert_eq!(ss_a, ss_b);
    }
}
