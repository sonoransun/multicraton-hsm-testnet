// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Runtime PQC capability introspection.
//!
//! Shared by `CratonExt_GetPQCCapabilities` (vendor extension), the REST
//! `GET /v1/capabilities` route, and the Python/Go bindings' `capabilities()`
//! helpers so every surface returns the same answer.

use crate::core::HsmCore;
use crate::error::HsmResult;

/// Snapshot of the runtime PQC surface.
///
/// Reflects *both* the compile-time feature flags that gate optional
/// algorithms (Falcon, FrodoKEM, hybrid-kem) and the runtime
/// `algorithm_config` policy (`enable_pqc`, `fips_approved_only`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct PqcCapabilities {
    /// `true` when PQC mechanisms are runtime-enabled.
    pub enable_pqc: bool,
    /// `true` when only FIPS-approved classical algorithms are usable
    /// (strictly excludes every PQC mechanism).
    pub fips_approved_only: bool,
    /// ML-KEM / ML-DSA / SLH-DSA are always compiled; each entry is the
    /// variant string that can be passed to `service::kem` / `service::sign`.
    pub ml_kem_variants: Vec<String>,
    /// ML-DSA-44/65/87.
    pub ml_dsa_variants: Vec<String>,
    /// SLH-DSA parameter-set names (12 of them when `quantum-resistant` is on).
    pub slh_dsa_variants: Vec<String>,
    /// Falcon-512/1024, populated only when the `falcon-sig` feature is on.
    pub falcon_variants: Vec<String>,
    /// FrodoKEM-640/976/1344-AES, populated only when `frodokem-kem` is on.
    pub frodokem_variants: Vec<String>,
    /// Hybrid KEM constructions (populated only when `hybrid-kem` is on).
    pub hybrid_kem_variants: Vec<String>,
    /// Composite signature schemes (ECDSA-P256 + ML-DSA-65, Ed25519 + ML-DSA-65) — always present.
    pub composite_sig_variants: Vec<String>,
    /// `true` when the vendor extension C ABI surface is compiled in.
    pub vendor_ext_available: bool,
    /// `true` when `CKM_HYBRID_KEM_WRAP` can be dispatched (requires vendor-ext + hybrid-kem).
    pub hybrid_kem_wrap_available: bool,
}

/// Gather the runtime PQC capability snapshot from the running HSM.
pub fn get_pqc_capabilities(core: &HsmCore) -> HsmResult<PqcCapabilities> {
    let cfg = core.algorithm_config();

    let s = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    Ok(PqcCapabilities {
        enable_pqc: cfg.enable_pqc,
        fips_approved_only: cfg.fips_approved_only,
        ml_kem_variants: s(&["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]),
        ml_dsa_variants: s(&["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]),
        slh_dsa_variants: s(&[
            "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f",
            "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
            "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f",
            "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
            "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f",
            "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f",
        ]),
        #[cfg(feature = "falcon-sig")]
        falcon_variants: s(&["Falcon-512", "Falcon-1024"]),
        #[cfg(not(feature = "falcon-sig"))]
        falcon_variants: vec![],
        #[cfg(feature = "frodokem-kem")]
        frodokem_variants: s(&["FrodoKEM-640-AES", "FrodoKEM-976-AES", "FrodoKEM-1344-AES"]),
        #[cfg(not(feature = "frodokem-kem"))]
        frodokem_variants: vec![],
        #[cfg(feature = "hybrid-kem")]
        hybrid_kem_variants: s(&[
            "X25519+ML-KEM-768",
            "X25519+ML-KEM-1024",
            "P-256+ML-KEM-768",
            "P-384+ML-KEM-1024",
        ]),
        #[cfg(not(feature = "hybrid-kem"))]
        hybrid_kem_variants: vec![],
        composite_sig_variants: s(&["ECDSA-P256+ML-DSA-65", "Ed25519+ML-DSA-65"]),
        vendor_ext_available: cfg!(feature = "vendor-ext"),
        hybrid_kem_wrap_available: cfg!(all(feature = "vendor-ext", feature = "hybrid-kem")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_caps_include_fips_standardized_pqc() {
        let config = crate::config::HsmConfig::default();
        let core = HsmCore::new(&config);
        let caps = get_pqc_capabilities(&core).unwrap();
        assert!(caps.ml_kem_variants.iter().any(|v| v == "ML-KEM-768"));
        assert!(caps.ml_dsa_variants.iter().any(|v| v == "ML-DSA-65"));
        assert_eq!(caps.slh_dsa_variants.len(), 12);
        // Composite signatures are implemented in default-compiled pqc.rs.
        assert!(caps.composite_sig_variants.iter().any(|v| v == "Ed25519+ML-DSA-65"));
    }
}
