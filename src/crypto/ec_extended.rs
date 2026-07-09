// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Extended elliptic-curve cryptographic cores.
//!
//! This module implements the curve suites that extend the classical
//! P-256/P-384/Ed25519 set already provided in [`crate::crypto::sign`] and
//! [`crate::crypto::keygen`]:
//!
//! - **P-521** (secp521r1) ECDSA sign/verify + ECDH — [`p521`] crate.
//! - **secp256k1** ECDSA sign/verify + ECDH — [`k256`] crate.
//! - **X25519** ECDH over Montgomery keys — [`x25519_dalek`] crate.
//!
//! ECDSA signing is *hedged*: the deterministic RFC 6979 nonce is mixed with
//! fresh randomness drawn from the SP 800-90A HMAC_DRBG ([`DrbgRng`]), matching
//! the pattern used by the P-256/P-384 cores in [`crate::crypto::sign`]. This
//! protects against fault-injection nonce recovery while retaining protection
//! against catastrophic nonce reuse if the RNG stalls.
//!
//! All key generation routes through the DRBG rather than `OsRng` directly, per
//! the project-wide invariant documented in [`crate::crypto::keygen`].

#![allow(dead_code)]

use crate::error::{HsmError, HsmResult};

/// Minimum accepted ECDSA prehash length (SHA-1 output, 20 bytes).
const ECDSA_PREHASH_MIN: usize = 20;
/// Maximum accepted ECDSA prehash length (SHA-512 output, 64 bytes).
const ECDSA_PREHASH_MAX: usize = 64;

/// Validate a caller-supplied ECDSA prehash length.
///
/// Per FIPS 186-5, ECDSA signs a digest of any length, truncating to the
/// leftmost `bit_len(n)` bits — so a digest need not match the curve's default
/// hash size. Bounds the input to `[20, 64]` bytes (SHA-1 … SHA-512 outputs)
/// to reject empty or absurd inputs.
fn validate_ecdsa_prehash_len(digest: &[u8]) -> HsmResult<()> {
    if digest.len() < ECDSA_PREHASH_MIN || digest.len() > ECDSA_PREHASH_MAX {
        return Err(HsmError::DataLenRange);
    }
    Ok(())
}

// ============================================================================
// P-521 ECDSA (secp521r1) + ECDH
// ============================================================================

/// Minimum prehash length the `ecdsa` crate accepts for P-521.
///
/// `ecdsa::hazmat::bits2field` rejects any prehash shorter than half the field
/// size. P-521's field is 66 bytes, so anything under 33 bytes (which includes
/// a 32-byte SHA-256 or a 20-byte SHA-1 digest) is refused — even though FIPS
/// 186-5 permits ECDSA over a digest of any length.
const P521_MIN_PREHASH: usize = 33;

/// Left-pad a short P-521 prehash to [`P521_MIN_PREHASH`] bytes.
///
/// `bits2field` interprets a prehash shorter than the field size by
/// right-aligning it (padding with leading zero bytes), so zero-left-padding
/// here preserves the integer value `z` exactly. The resulting signature is
/// therefore identical to — and interoperable with — one produced over the raw
/// digest by any conformant implementation. Digests already at least
/// [`P521_MIN_PREHASH`] bytes are borrowed unchanged.
fn p521_pad_prehash(digest: &[u8]) -> std::borrow::Cow<'_, [u8]> {
    if digest.len() >= P521_MIN_PREHASH {
        std::borrow::Cow::Borrowed(digest)
    } else {
        let mut buf = vec![0u8; P521_MIN_PREHASH];
        buf[P521_MIN_PREHASH - digest.len()..].copy_from_slice(digest);
        std::borrow::Cow::Owned(buf)
    }
}

/// Generate a P-521 (secp521r1) key pair.
///
/// Returns `(private_scalar_bytes, public_sec1_uncompressed_bytes)` where the
/// private scalar is the 66-byte big-endian field element and the public key
/// is the 133-byte SEC1 uncompressed encoding (`0x04 || X || Y`). Randomness is
/// sourced from the SP 800-90A HMAC_DRBG.
pub fn p521_keygen() -> HsmResult<(Vec<u8>, Vec<u8>)> {
    use crate::crypto::drbg::DrbgRng;
    use elliptic_curve::sec1::ToEncodedPoint;
    use p521::SecretKey;

    let mut rng = DrbgRng::new()?;
    let secret_key = SecretKey::random(&mut rng);
    let public_key = secret_key.public_key();
    let pub_point = public_key.to_encoded_point(false);

    Ok((
        secret_key.to_bytes().to_vec(),
        pub_point.as_bytes().to_vec(),
    ))
}

/// P-521 ECDSA sign over a pre-computed digest (hedged).
///
/// `private_key_bytes` is the 66-byte scalar produced by [`p521_keygen`].
/// `digest` may be any length in `[20, 64]` (FIPS 186-5 truncation). Uses
/// `RandomizedPrehashSigner` to fold DRBG randomness into the nonce, and
/// returns an ASN.1 DER-encoded signature.
pub fn p521_sign_prehashed(private_key_bytes: &[u8], digest: &[u8]) -> HsmResult<Vec<u8>> {
    use crate::crypto::drbg::DrbgRng;
    use p521::ecdsa::signature::hazmat::RandomizedPrehashSigner;
    use p521::ecdsa::SigningKey;

    validate_ecdsa_prehash_len(digest)?;
    let prehash = p521_pad_prehash(digest);
    let signing_key =
        SigningKey::from_slice(private_key_bytes).map_err(|_| HsmError::KeyHandleInvalid)?;
    let mut rng = DrbgRng::new()?;
    let signature: p521::ecdsa::Signature = signing_key
        .sign_prehash_with_rng(&mut rng, prehash.as_ref())
        .map_err(|_| HsmError::GeneralError)?;
    Ok(signature.to_der().to_bytes().to_vec())
}

/// P-521 ECDSA verify a DER signature over a pre-computed digest.
///
/// `public_sec1` is the SEC1-encoded public key (compressed or uncompressed).
pub fn p521_verify_prehashed(public_sec1: &[u8], digest: &[u8], sig_der: &[u8]) -> HsmResult<bool> {
    use p521::ecdsa::signature::hazmat::PrehashVerifier;
    use p521::ecdsa::VerifyingKey;

    validate_ecdsa_prehash_len(digest)?;
    let prehash = p521_pad_prehash(digest);
    let verifying_key =
        VerifyingKey::from_sec1_bytes(public_sec1).map_err(|_| HsmError::KeyHandleInvalid)?;
    let signature =
        p521::ecdsa::Signature::from_der(sig_der).map_err(|_| HsmError::SignatureInvalid)?;
    Ok(verifying_key
        .verify_prehash(prehash.as_ref(), &signature)
        .is_ok())
}

/// P-521 ECDH: derive the raw shared secret x-coordinate.
///
/// `private_key_bytes` is the 66-byte local scalar; `peer_public_sec1` is the
/// peer's SEC1-encoded public key. Returns the raw shared-secret bytes (the
/// big-endian x-coordinate of the shared point) — callers are expected to run
/// this through a KDF before use as keying material.
pub fn p521_ecdh(private_key_bytes: &[u8], peer_public_sec1: &[u8]) -> HsmResult<Vec<u8>> {
    use elliptic_curve::ecdh::diffie_hellman;
    use p521::{PublicKey, SecretKey};

    let secret_key =
        SecretKey::from_slice(private_key_bytes).map_err(|_| HsmError::KeyHandleInvalid)?;
    let peer_public =
        PublicKey::from_sec1_bytes(peer_public_sec1).map_err(|_| HsmError::KeyHandleInvalid)?;
    let shared = diffie_hellman(secret_key.to_nonzero_scalar(), peer_public.as_affine());
    Ok(shared.raw_secret_bytes().to_vec())
}

// ============================================================================
// secp256k1 ECDSA + ECDH
// ============================================================================

/// Generate a secp256k1 key pair.
///
/// Returns `(private_scalar_bytes, public_sec1_uncompressed_bytes)`: a 32-byte
/// big-endian scalar and the 65-byte SEC1 uncompressed public key
/// (`0x04 || X || Y`). Randomness is sourced from the SP 800-90A HMAC_DRBG.
pub fn secp256k1_keygen() -> HsmResult<(Vec<u8>, Vec<u8>)> {
    use crate::crypto::drbg::DrbgRng;
    use elliptic_curve::sec1::ToEncodedPoint;
    use k256::SecretKey;

    let mut rng = DrbgRng::new()?;
    let secret_key = SecretKey::random(&mut rng);
    let public_key = secret_key.public_key();
    let pub_point = public_key.to_encoded_point(false);

    Ok((
        secret_key.to_bytes().to_vec(),
        pub_point.as_bytes().to_vec(),
    ))
}

/// secp256k1 ECDSA sign over a pre-computed digest (hedged).
///
/// `private_key_bytes` is the 32-byte scalar; `digest` may be any length in
/// `[20, 64]`. Returns a DER-encoded, low-S normalized signature. Uses
/// `RandomizedPrehashSigner` to fold DRBG randomness into the nonce.
pub fn secp256k1_sign_prehashed(private_key_bytes: &[u8], digest: &[u8]) -> HsmResult<Vec<u8>> {
    use crate::crypto::drbg::DrbgRng;
    use k256::ecdsa::signature::hazmat::RandomizedPrehashSigner;
    use k256::ecdsa::SigningKey;

    validate_ecdsa_prehash_len(digest)?;
    let signing_key =
        SigningKey::from_slice(private_key_bytes).map_err(|_| HsmError::KeyHandleInvalid)?;
    let mut rng = DrbgRng::new()?;
    let signature: k256::ecdsa::Signature = signing_key
        .sign_prehash_with_rng(&mut rng, digest)
        .map_err(|_| HsmError::GeneralError)?;
    Ok(signature.to_der().to_bytes().to_vec())
}

/// secp256k1 ECDSA verify a DER signature over a pre-computed digest.
///
/// `public_sec1` is the SEC1-encoded public key (compressed or uncompressed).
pub fn secp256k1_verify_prehashed(
    public_sec1: &[u8],
    digest: &[u8],
    sig_der: &[u8],
) -> HsmResult<bool> {
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    use k256::ecdsa::VerifyingKey;

    validate_ecdsa_prehash_len(digest)?;
    let verifying_key =
        VerifyingKey::from_sec1_bytes(public_sec1).map_err(|_| HsmError::KeyHandleInvalid)?;
    let signature =
        k256::ecdsa::Signature::from_der(sig_der).map_err(|_| HsmError::SignatureInvalid)?;
    Ok(verifying_key.verify_prehash(digest, &signature).is_ok())
}

/// secp256k1 ECDH: derive the raw shared secret x-coordinate.
///
/// `private_key_bytes` is the 32-byte local scalar; `peer_public_sec1` is the
/// peer's SEC1-encoded public key. Returns the raw shared-secret bytes; run
/// through a KDF before use as keying material.
pub fn secp256k1_ecdh(private_key_bytes: &[u8], peer_public_sec1: &[u8]) -> HsmResult<Vec<u8>> {
    use elliptic_curve::ecdh::diffie_hellman;
    use k256::{PublicKey, SecretKey};

    let secret_key =
        SecretKey::from_slice(private_key_bytes).map_err(|_| HsmError::KeyHandleInvalid)?;
    let peer_public =
        PublicKey::from_sec1_bytes(peer_public_sec1).map_err(|_| HsmError::KeyHandleInvalid)?;
    let shared = diffie_hellman(secret_key.to_nonzero_scalar(), peer_public.as_affine());
    Ok(shared.raw_secret_bytes().to_vec())
}

// ============================================================================
// X25519 ECDH (RFC 7748)
// ============================================================================

/// Generate an X25519 key pair.
///
/// Returns `(private_bytes, public_bytes)`, each 32 bytes. The private scalar
/// is drawn from the SP 800-90A HMAC_DRBG (not `OsRng` directly) to honour the
/// project-wide invariant that all key material passes through the DRBG's
/// health testing; clamping is handled by `StaticSecret`.
pub fn x25519_keygen() -> HsmResult<(Vec<u8>, Vec<u8>)> {
    use crate::crypto::drbg::HmacDrbg;
    use x25519_dalek::{PublicKey, StaticSecret};
    use zeroize::Zeroizing;

    // Draw 32 bytes of DRBG output for the secret scalar. Using the DRBG (as
    // every other keygen in this crate does) sidesteps the rand_core version
    // split entirely: no RNG handle is threaded through x25519-dalek 2, so its
    // rand_core 0.6 trait bounds never come into play.
    let mut sk_bytes = Zeroizing::new([0u8; 32]);
    let mut drbg = HmacDrbg::new()?;
    drbg.generate(sk_bytes.as_mut())?;

    let secret = StaticSecret::from(*sk_bytes);
    let public = PublicKey::from(&secret);

    Ok((secret.to_bytes().to_vec(), public.to_bytes().to_vec()))
}

/// X25519 ECDH: compute the 32-byte shared secret.
///
/// `private_key_bytes` and `peer_public_bytes` must each be exactly 32 bytes.
/// An all-zero shared secret — produced when the peer supplies a low-order
/// point (RFC 7748 §6.1 contributory-behaviour guard) — is rejected with an
/// error rather than returned.
pub fn x25519_ecdh(private_key_bytes: &[u8], peer_public_bytes: &[u8]) -> HsmResult<Vec<u8>> {
    use x25519_dalek::{PublicKey, StaticSecret};

    let sk_array: [u8; 32] = private_key_bytes
        .try_into()
        .map_err(|_| HsmError::KeyHandleInvalid)?;
    let pk_array: [u8; 32] = peer_public_bytes
        .try_into()
        .map_err(|_| HsmError::KeyHandleInvalid)?;

    let secret = StaticSecret::from(sk_array);
    let peer_public = PublicKey::from(pk_array);
    let shared = secret.diffie_hellman(&peer_public);
    let shared_bytes = shared.to_bytes();

    // RFC 7748 §6.1: reject the all-zero output that results from a peer public
    // key of small order. Returning it would silently agree on a predictable
    // key with any active attacker.
    if shared_bytes == [0u8; 32] {
        return Err(HsmError::GeneralError);
    }

    Ok(shared_bytes.to_vec())
}

// ============================================================================
// DER-encoded curve OID parsing
// ============================================================================

/// Extended curves recognised by [`curve_from_ec_params`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtendedCurve {
    /// NIST P-521 (secp521r1), OID 1.3.132.0.35.
    P521,
    /// secp256k1, OID 1.3.132.0.10.
    Secp256k1,
    /// X25519 (RFC 8410 / Curve25519), OID 1.3.101.110.
    X25519,
}

/// DER encoding of the secp521r1 OID `1.3.132.0.35`.
const OID_P521: &[u8] = &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23];
/// DER encoding of the secp256k1 OID `1.3.132.0.10`.
const OID_SECP256K1: &[u8] = &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A];
/// DER encoding of the X25519 OID `1.3.101.110` (RFC 8410).
const OID_X25519: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x6E];
/// PKCS#11 legacy `CKA_EC_PARAMS` form: PrintableString `"curve25519"`.
const PRINTABLE_CURVE25519: &[u8] = &[
    0x13, 0x0a, 0x63, 0x75, 0x72, 0x76, 0x65, 0x32, 0x35, 0x35, 0x31, 0x39,
];

/// Identify an extended curve from a DER-encoded `CKA_EC_PARAMS` blob.
///
/// Matches the exact DER OID encodings for P-521, secp256k1 and X25519, plus
/// the PKCS#11 legacy PrintableString `"curve25519"` form (also mapped to
/// [`ExtendedCurve::X25519`]). Returns `None` for anything else, including the
/// P-256 OID. Matching is exact against the whole `ec_params` slice.
pub fn curve_from_ec_params(ec_params: &[u8]) -> Option<ExtendedCurve> {
    if ec_params == OID_P521 {
        Some(ExtendedCurve::P521)
    } else if ec_params == OID_SECP256K1 {
        Some(ExtendedCurve::Secp256k1)
    } else if ec_params == OID_X25519 || ec_params == PRINTABLE_CURVE25519 {
        Some(ExtendedCurve::X25519)
    } else {
        None
    }
}

/// DER-encoded `CKA_EC_PARAMS` OID for X25519 (`1.3.101.110`, RFC 8410).
///
/// Used as the canonical `CKA_EC_PARAMS` value stored on a generated X25519
/// key pair so that [`curve_from_ec_params`] later identifies it as
/// [`ExtendedCurve::X25519`] during `C_DeriveKey`.
pub fn x25519_oid() -> &'static [u8] {
    OID_X25519
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256, Sha512};

    // ---- P-521 sign/verify round-trip -------------------------------------

    #[test]
    fn p521_sign_verify_roundtrip() {
        let (private_key, public_key) = p521_keygen().unwrap();
        assert_eq!(private_key.len(), 66, "P-521 scalar is 66 bytes");
        assert_eq!(
            public_key.len(),
            133,
            "P-521 SEC1 uncompressed is 133 bytes"
        );
        assert_eq!(public_key[0], 0x04);

        // P-521 requires a digest >= half the 66-byte field size (>= 33 bytes),
        // so it must be paired with SHA-384/512 — a 32-byte SHA-256 digest is
        // rejected by the ECDSA bits2field conversion.
        let digest = Sha512::digest(b"craton p-521 test message");
        let sig = p521_sign_prehashed(&private_key, &digest).unwrap();

        assert!(
            p521_verify_prehashed(&public_key, &digest, &sig).unwrap(),
            "valid P-521 signature must verify"
        );

        // Tampered digest must not verify.
        let mut bad = digest.to_vec();
        bad[0] ^= 0xFF;
        assert!(
            !p521_verify_prehashed(&public_key, &bad, &sig).unwrap(),
            "tampered digest must fail P-521 verification"
        );

        // A short (20-byte) prehash must also round-trip: it exercises the
        // left-padding shim that works around the ecdsa crate's 33-byte floor.
        let short = &digest[..20];
        let short_sig = p521_sign_prehashed(&private_key, short).unwrap();
        assert!(
            p521_verify_prehashed(&public_key, short, &short_sig).unwrap(),
            "short P-521 prehash must round-trip via the padding shim"
        );
    }

    // ---- secp256k1 sign/verify round-trip ---------------------------------

    #[test]
    fn secp256k1_sign_verify_roundtrip() {
        let (private_key, public_key) = secp256k1_keygen().unwrap();
        assert_eq!(private_key.len(), 32, "secp256k1 scalar is 32 bytes");
        assert_eq!(
            public_key.len(),
            65,
            "secp256k1 SEC1 uncompressed is 65 bytes"
        );
        assert_eq!(public_key[0], 0x04);

        let digest = Sha256::digest(b"craton secp256k1 test message");
        let sig = secp256k1_sign_prehashed(&private_key, &digest).unwrap();

        assert!(
            secp256k1_verify_prehashed(&public_key, &digest, &sig).unwrap(),
            "valid secp256k1 signature must verify"
        );

        let mut bad = digest.to_vec();
        bad[0] ^= 0xFF;
        assert!(
            !secp256k1_verify_prehashed(&public_key, &bad, &sig).unwrap(),
            "tampered digest must fail secp256k1 verification"
        );
    }

    // ---- Two-party ECDH agreement -----------------------------------------

    #[test]
    fn p521_ecdh_agreement() {
        let (a_priv, a_pub) = p521_keygen().unwrap();
        let (b_priv, b_pub) = p521_keygen().unwrap();

        let ab = p521_ecdh(&a_priv, &b_pub).unwrap();
        let ba = p521_ecdh(&b_priv, &a_pub).unwrap();

        assert!(!ab.is_empty());
        assert_eq!(ab, ba, "P-521 ECDH must agree in both directions");
    }

    #[test]
    fn secp256k1_ecdh_agreement() {
        let (a_priv, a_pub) = secp256k1_keygen().unwrap();
        let (b_priv, b_pub) = secp256k1_keygen().unwrap();

        let ab = secp256k1_ecdh(&a_priv, &b_pub).unwrap();
        let ba = secp256k1_ecdh(&b_priv, &a_pub).unwrap();

        assert!(!ab.is_empty());
        assert_eq!(ab, ba, "secp256k1 ECDH must agree in both directions");
    }

    #[test]
    fn x25519_ecdh_agreement() {
        let (a_priv, a_pub) = x25519_keygen().unwrap();
        let (b_priv, b_pub) = x25519_keygen().unwrap();
        assert_eq!(a_priv.len(), 32);
        assert_eq!(a_pub.len(), 32);

        let ab = x25519_ecdh(&a_priv, &b_pub).unwrap();
        let ba = x25519_ecdh(&b_priv, &a_pub).unwrap();

        assert_eq!(ab.len(), 32);
        assert_eq!(ab, ba, "X25519 ECDH must agree in both directions");
    }

    // ---- RFC 7748 §5.2 X25519 known-answer test ---------------------------

    #[test]
    fn x25519_rfc7748_vector() {
        // First test vector from RFC 7748 §5.2.
        let scalar =
            hex::decode("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
                .unwrap();
        let u_coord =
            hex::decode("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
                .unwrap();
        let expected =
            hex::decode("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
                .unwrap();

        let shared = x25519_ecdh(&scalar, &u_coord).unwrap();
        assert_eq!(shared, expected, "X25519 must match RFC 7748 §5.2 vector");
    }

    // ---- OID parsing ------------------------------------------------------

    #[test]
    fn curve_oid_parsing() {
        assert_eq!(
            curve_from_ec_params(&[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23]),
            Some(ExtendedCurve::P521)
        );
        assert_eq!(
            curve_from_ec_params(&[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A]),
            Some(ExtendedCurve::Secp256k1)
        );
        assert_eq!(
            curve_from_ec_params(&[0x06, 0x03, 0x2B, 0x65, 0x6E]),
            Some(ExtendedCurve::X25519)
        );
        // PKCS#11 legacy PrintableString "curve25519".
        assert_eq!(
            curve_from_ec_params(&[
                0x13, 0x0a, 0x63, 0x75, 0x72, 0x76, 0x65, 0x32, 0x35, 0x35, 0x31, 0x39
            ]),
            Some(ExtendedCurve::X25519)
        );

        // P-256 OID (1.2.840.10045.3.1.7) is not an extended curve here.
        assert_eq!(
            curve_from_ec_params(&[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]),
            None
        );
        // Garbage and empty input.
        assert_eq!(curve_from_ec_params(&[0xDE, 0xAD, 0xBE, 0xEF]), None);
        assert_eq!(curve_from_ec_params(&[]), None);
    }
}
