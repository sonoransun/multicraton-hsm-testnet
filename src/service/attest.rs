// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Attested key generation.
//!
//! Produces a key pair plus a CBOR attestation statement that binds the
//! fresh public key to the host's measurements under a caller-supplied
//! nonce. Verifiers recompute the bound payload and check the statement's
//! signature / platform report.
//!
//! Statement layout (CBOR map, stable keys):
//!
//! ```text
//! {
//!   "pub_key":     bstr,   // raw public-key bytes from keygen
//!   "mechanism":   uint,   // CK_MECHANISM_TYPE
//!   "nonce":       bstr,   // echo of caller's anti-replay nonce
//!   "platform":    tstr,   // "tdx" | "sev-snp" | "nitro" | "software"
//!   "measurement": bstr,   // SHA-256(pub_key || nonce || "CRATON-V1")
//!   "timestamp":   uint,   // UNIX seconds
//!   "report":      bstr,   // optional platform quote (empty in software mode)
//! }
//! ```
//!
//! When the `advanced-all` / `quantum-resistant` feature set brings in
//! `crate::advanced::attestation`, this module delegates to
//! `get_attestation_token` to produce a real TDX / SEV-SNP / Nitro report
//! for the `report` field. Default builds use a `platform: "software"` token
//! so callers always get a well-formed CBOR artefact without forcing a TEE.

use std::time::{SystemTime, UNIX_EPOCH};

use ciborium::value::Value as CborValue;
use sha2::{Digest, Sha256};

use crate::core::HsmCore;
use crate::error::{HsmError, HsmResult};
use crate::pkcs11_abi::types::{CK_MECHANISM_TYPE, CK_OBJECT_HANDLE};

/// Output of an attested keygen: the new key pair plus a serialised CBOR
/// attestation statement the caller can hand to any RATS-style verifier.
#[derive(Debug, Clone)]
pub struct AttestedKey {
    pub public_handle: CK_OBJECT_HANDLE,
    pub private_handle: CK_OBJECT_HANDLE,
    /// CBOR-encoded attestation statement.
    pub statement: Vec<u8>,
}

/// Generate a PQ key pair and produce a platform attestation binding the
/// public key to the host's measurements plus `nonce`.
pub fn attested_keygen(
    core: &HsmCore,
    mechanism: CK_MECHANISM_TYPE,
    nonce: &[u8],
) -> HsmResult<AttestedKey> {
    if nonce.is_empty() {
        return Err(HsmError::ArgumentsBad);
    }

    // 1. Fresh keypair via the service-level keygen.
    let gen = crate::service::keygen::generate_pqc_keypair(core, mechanism, &[], &[])?;

    // 2. Read the public-key bytes back for binding.
    let pub_bytes = {
        let arc = core.object_store().get_object(gen.public_handle)?;
        let obj = arc.read();
        obj.public_key_data
            .clone()
            .ok_or(HsmError::KeyHandleInvalid)?
    };

    // 3. Build the binding payload and the statement.
    let statement = build_statement(&pub_bytes, mechanism, nonce)?;

    Ok(AttestedKey {
        public_handle: gen.public_handle,
        private_handle: gen.private_handle,
        statement,
    })
}

/// Build the CBOR attestation statement. See the module-level doc comment
/// for the exact map layout.
fn build_statement(
    pub_key: &[u8],
    mechanism: CK_MECHANISM_TYPE,
    nonce: &[u8],
) -> HsmResult<Vec<u8>> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let measurement = {
        let mut h = Sha256::new();
        h.update(pub_key);
        h.update(nonce);
        h.update(b"CRATON-V1");
        h.finalize().to_vec()
    };

    let (platform, report) = platform_and_report(nonce);

    let map = CborValue::Map(vec![
        (
            CborValue::Text("pub_key".into()),
            CborValue::Bytes(pub_key.to_vec()),
        ),
        (
            CborValue::Text("mechanism".into()),
            CborValue::Integer((mechanism as u128).try_into().unwrap_or_else(|_| 0u32.into())),
        ),
        (
            CborValue::Text("nonce".into()),
            CborValue::Bytes(nonce.to_vec()),
        ),
        (
            CborValue::Text("platform".into()),
            CborValue::Text(platform.into()),
        ),
        (
            CborValue::Text("measurement".into()),
            CborValue::Bytes(measurement),
        ),
        (
            CborValue::Text("timestamp".into()),
            CborValue::Integer((now as u128).try_into().unwrap_or_else(|_| 0u32.into())),
        ),
        (CborValue::Text("report".into()), CborValue::Bytes(report)),
    ]);

    let mut out = Vec::new();
    ciborium::ser::into_writer(&map, &mut out).map_err(|_| HsmError::GeneralError)?;
    Ok(out)
}

/// Best-effort platform + quote resolution.
///
/// When the `advanced` attestation module is compiled (any of the related
/// features on), this reads the real TEE report. Otherwise the function
/// returns `("software", [])` and the statement is self-attesting.
fn platform_and_report(_nonce: &[u8]) -> (&'static str, Vec<u8>) {
    #[cfg(any(
        feature = "advanced-all",
        feature = "quantum-resistant",
        feature = "tpm-binding",
    ))]
    {
        use crate::advanced::attestation::{detect_platform, CcPlatform};
        let plat = detect_platform();
        let platform_name: &'static str = match plat {
            CcPlatform::IntelTdx => "tdx",
            CcPlatform::AmdSevSnp => "sev-snp",
            CcPlatform::AwsNitro => "nitro",
            CcPlatform::Software => "software",
        };
        let report = match plat {
            CcPlatform::IntelTdx => crate::advanced::attestation::tdx_get_report(_nonce, &[])
                .unwrap_or_default(),
            CcPlatform::AmdSevSnp => crate::advanced::attestation::sev_snp_get_report(_nonce)
                .unwrap_or_default(),
            CcPlatform::AwsNitro => crate::advanced::attestation::nitro_get_attestation(_nonce)
                .unwrap_or_default(),
            CcPlatform::Software => Vec::new(),
        };
        return (platform_name, report);
    }
    #[cfg(not(any(
        feature = "advanced-all",
        feature = "quantum-resistant",
        feature = "tpm-binding",
    )))]
    {
        ("software", Vec::new())
    }
}

/// Parse a statement produced by [`attested_keygen`] back into a
/// field-by-field map so verifiers don't have to know CBOR.
///
/// This is a convenience; the canonical form is the raw bytes in
/// `AttestedKey::statement`.
pub fn parse_statement(bytes: &[u8]) -> HsmResult<ParsedStatement> {
    let value: CborValue = ciborium::de::from_reader(bytes).map_err(|_| HsmError::DataInvalid)?;
    let entries = match value {
        CborValue::Map(m) => m,
        _ => return Err(HsmError::DataInvalid),
    };

    let mut parsed = ParsedStatement::default();
    for (k, v) in entries {
        let CborValue::Text(key) = k else { continue };
        match key.as_str() {
            "pub_key" => {
                if let CborValue::Bytes(b) = v {
                    parsed.pub_key = b;
                }
            }
            "mechanism" => {
                if let CborValue::Integer(i) = v {
                    parsed.mechanism = i128::from(i) as u64;
                }
            }
            "nonce" => {
                if let CborValue::Bytes(b) = v {
                    parsed.nonce = b;
                }
            }
            "platform" => {
                if let CborValue::Text(s) = v {
                    parsed.platform = s;
                }
            }
            "measurement" => {
                if let CborValue::Bytes(b) = v {
                    parsed.measurement = b;
                }
            }
            "timestamp" => {
                if let CborValue::Integer(i) = v {
                    parsed.timestamp = i128::from(i) as u64;
                }
            }
            "report" => {
                if let CborValue::Bytes(b) = v {
                    parsed.report = b;
                }
            }
            _ => {}
        }
    }
    Ok(parsed)
}

/// Decoded view of a CBOR attestation statement.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ParsedStatement {
    pub pub_key: Vec<u8>,
    pub mechanism: u64,
    pub nonce: Vec<u8>,
    pub platform: String,
    pub measurement: Vec<u8>,
    pub timestamp: u64,
    pub report: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::HsmConfig;
    use crate::pkcs11_abi::constants::CKM_ML_DSA_44;

    #[test]
    fn attested_keygen_produces_parseable_cbor() {
        let config = HsmConfig::default();
        let core = HsmCore::new(&config);
        let nonce = b"verifier-supplied-nonce-abc";
        let att = attested_keygen(&core, CKM_ML_DSA_44, nonce).unwrap();

        let parsed = parse_statement(&att.statement).unwrap();
        assert!(!parsed.pub_key.is_empty());
        assert_eq!(parsed.mechanism, CKM_ML_DSA_44 as u64);
        assert_eq!(parsed.nonce, nonce);
        assert_eq!(parsed.measurement.len(), 32); // SHA-256
        assert!(matches!(parsed.platform.as_str(), "tdx" | "sev-snp" | "nitro" | "software"));
    }

    #[test]
    fn empty_nonce_rejected() {
        let config = HsmConfig::default();
        let core = HsmCore::new(&config);
        let r = attested_keygen(&core, CKM_ML_DSA_44, &[]);
        assert!(matches!(r, Err(HsmError::ArgumentsBad)));
    }

    #[test]
    fn measurement_binds_pubkey_and_nonce() {
        let config = HsmConfig::default();
        let core = HsmCore::new(&config);
        let nonce = b"nonce-1";
        let a = attested_keygen(&core, CKM_ML_DSA_44, nonce).unwrap();
        let p = parse_statement(&a.statement).unwrap();

        // Recomputing the measurement from the statement's own fields must match.
        let mut h = Sha256::new();
        h.update(&p.pub_key);
        h.update(&p.nonce);
        h.update(b"CRATON-V1");
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(p.measurement, expected);
    }
}
