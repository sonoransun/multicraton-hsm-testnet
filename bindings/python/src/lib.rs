// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Craton HSM Python bindings — in-process mode.
//!
//! Exposes `_native.LocalClient` which wraps an `HsmCore` directly. The
//! higher-level `craton_hsm.HsmClient(mode="local" | "remote")` facade in the
//! Python package picks between this class and a REST-based client written
//! in pure Python.

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::sync::Arc;

use craton_hsm::core::HsmCore;
use craton_hsm::pkcs11_abi::types::{CK_MECHANISM_TYPE, CK_OBJECT_HANDLE};

fn py_err(e: craton_hsm::error::HsmError) -> PyErr {
    PyRuntimeError::new_err(e.to_string())
}

fn parse_mechanism(s: &str) -> Result<CK_MECHANISM_TYPE, PyErr> {
    use craton_hsm::pkcs11_abi::constants::*;
    let by_name = |n: &str| -> Option<CK_MECHANISM_TYPE> {
        Some(match n {
            "CKM_ML_KEM_512" => CKM_ML_KEM_512,
            "CKM_ML_KEM_768" => CKM_ML_KEM_768,
            "CKM_ML_KEM_1024" => CKM_ML_KEM_1024,
            "CKM_ML_DSA_44" => CKM_ML_DSA_44,
            "CKM_ML_DSA_65" => CKM_ML_DSA_65,
            "CKM_ML_DSA_87" => CKM_ML_DSA_87,
            "CKM_HYBRID_ED25519_MLDSA65" => CKM_HYBRID_ED25519_MLDSA65,
            "CKM_HYBRID_ML_DSA_ECDSA" => CKM_HYBRID_ML_DSA_ECDSA,
            "CKM_HYBRID_X25519_MLKEM1024" => CKM_HYBRID_X25519_MLKEM1024,
            "CKM_HYBRID_P256_MLKEM768" => CKM_HYBRID_P256_MLKEM768,
            "CKM_HYBRID_P384_MLKEM1024" => CKM_HYBRID_P384_MLKEM1024,
            _ => return None,
        })
    };
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16)
            .map(|n| n as CK_MECHANISM_TYPE)
            .map_err(|e| PyValueError::new_err(format!("bad hex mechanism: {e}")));
    }
    if let Ok(n) = s.parse::<u64>() {
        return Ok(n as CK_MECHANISM_TYPE);
    }
    by_name(s).ok_or_else(|| PyValueError::new_err(format!("unknown mechanism: {s}")))
}

/// Capabilities DTO mirroring `service::caps::PqcCapabilities`, flattened
/// into a Python dict by the caller.
#[pyclass]
pub struct Capabilities {
    inner: craton_hsm::service::caps::PqcCapabilities,
}

#[pymethods]
impl Capabilities {
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, pyo3::types::PyDict>> {
        let d = pyo3::types::PyDict::new_bound(py);
        d.set_item("enable_pqc", self.inner.enable_pqc)?;
        d.set_item("fips_approved_only", self.inner.fips_approved_only)?;
        d.set_item("vendor_ext_available", self.inner.vendor_ext_available)?;
        d.set_item("hybrid_kem_wrap_available", self.inner.hybrid_kem_wrap_available)?;
        d.set_item("ml_kem_variants", self.inner.ml_kem_variants.clone())?;
        d.set_item("ml_dsa_variants", self.inner.ml_dsa_variants.clone())?;
        d.set_item("slh_dsa_variants", self.inner.slh_dsa_variants.clone())?;
        d.set_item("falcon_variants", self.inner.falcon_variants.clone())?;
        d.set_item("frodokem_variants", self.inner.frodokem_variants.clone())?;
        d.set_item("hybrid_kem_variants", self.inner.hybrid_kem_variants.clone())?;
        d.set_item("composite_sig_variants", self.inner.composite_sig_variants.clone())?;
        Ok(d)
    }
}

/// In-process client. Wraps an `HsmCore` and exposes sign/verify/encap/decap.
///
/// Pyo3 classes are exposed under the `craton_hsm._native` module; the
/// public API is the Python facade in `python/craton_hsm/__init__.py`.
#[pyclass]
pub struct LocalClient {
    core: Arc<HsmCore>,
}

#[pymethods]
impl LocalClient {
    /// Build a new client using the default config (reads the usual env var
    /// and config paths). Raises `RuntimeError` on init failure.
    #[new]
    fn new() -> PyResult<Self> {
        let core = HsmCore::new_default().map_err(py_err)?;
        Ok(Self { core: Arc::new(core) })
    }

    /// Return a capability snapshot.
    fn capabilities(&self) -> PyResult<Capabilities> {
        let inner = craton_hsm::service::caps::get_pqc_capabilities(&self.core).map_err(py_err)?;
        Ok(Capabilities { inner })
    }

    /// Sign `data` under `mechanism` with the private key at `handle`.
    /// Returns the signature bytes.
    fn sign(&self, handle: u64, mechanism: &str, data: &[u8]) -> PyResult<Py<PyBytes>> {
        let mech = parse_mechanism(mechanism)?;
        let sig = craton_hsm::service::sign::pqc_sign(
            &self.core,
            handle as CK_OBJECT_HANDLE,
            mech,
            data,
        )
        .map_err(py_err)?;
        Python::with_gil(|py| Ok(PyBytes::new_bound(py, &sig).into()))
    }

    /// Verify `signature` over `data` with the public key at `handle`.
    fn verify(
        &self,
        handle: u64,
        mechanism: &str,
        data: &[u8],
        signature: &[u8],
    ) -> PyResult<bool> {
        let mech = parse_mechanism(mechanism)?;
        craton_hsm::service::sign::pqc_verify(
            &self.core,
            handle as CK_OBJECT_HANDLE,
            mech,
            data,
            signature,
        )
        .map_err(py_err)
    }

    /// Encapsulate against a public-key handle; returns `(ciphertext, shared_secret)`.
    fn encapsulate(&self, pub_handle: u64, mechanism: &str) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
        let mech = parse_mechanism(mechanism)?;
        let bundle = craton_hsm::service::kem::encapsulate_by_handle(
            &self.core,
            pub_handle as CK_OBJECT_HANDLE,
            mech,
        )
        .map_err(py_err)?;
        Python::with_gil(|py| {
            Ok((
                PyBytes::new_bound(py, &bundle.ciphertext).into(),
                PyBytes::new_bound(py, &bundle.shared_secret).into(),
            ))
        })
    }

    /// Decapsulate a ciphertext using the private-key handle.
    fn decapsulate(&self, priv_handle: u64, mechanism: &str, ciphertext: &[u8]) -> PyResult<Py<PyBytes>> {
        let mech = parse_mechanism(mechanism)?;
        let ss = craton_hsm::service::kem::decapsulate_by_handle(
            &self.core,
            priv_handle as CK_OBJECT_HANDLE,
            mech,
            ciphertext,
        )
        .map_err(py_err)?;
        Python::with_gil(|py| Ok(PyBytes::new_bound(py, &ss).into()))
    }
}

/// Module init — exposes `_native` submodule classes.
#[pymodule]
fn _native(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<LocalClient>()?;
    m.add_class::<Capabilities>()?;
    Ok(())
}
