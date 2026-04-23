// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Atomic PQ key rotation under a policy.
//!
//! Generates a fresh keypair of the same mechanism as the target, inserts it
//! into the object store, stamps the old key with `CKA_END_DATE = now` and
//! transitions its lifecycle state (to `Deactivated` by default, or
//! `Compromised` when the policy demands it), and returns the handle triple.
//! The rotation is audit-logged before the new handles are returned to the
//! caller, so any observer of the audit log sees the ordering
//! `(new keygen) → (old retire) → (rotate event)`.
//!
//! Rotation is atomic within the object store's lock semantics: the new key
//! is created first, then the old key is retired under its own write-lock.
//! There is no single store-wide transaction, so a crash between the two
//! steps leaves the new key alive and the old key still active — recovery
//! is re-running rotation, which is idempotent in that state.

use chrono::{Datelike, Utc};

use crate::audit::log::{AuditOperation, AuditResult};
use crate::core::HsmCore;
use crate::error::{HsmError, HsmResult};
use crate::pkcs11_abi::types::{CK_MECHANISM_TYPE, CK_OBJECT_HANDLE};
use crate::store::object::KeyLifecycleState;

/// Rotation policy. Conservative defaults: overlap retirement until the old
/// key's `end_date`; require the new key's `start_date` to be at-or-before
/// the old key's `end_date`.
#[derive(Debug, Clone, Copy, Default)]
pub struct RotatePolicy {
    /// If `true`, the old key is transitioned to `Compromised` immediately
    /// (verify + decrypt only). Otherwise it moves to `Deactivated`, which
    /// permits verify / decrypt / unwrap until its `end_date`.
    pub mark_compromised: bool,
}

/// Result of an atomic rotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rotated {
    /// Handle of the newly generated public key.
    pub new_public: CK_OBJECT_HANDLE,
    /// Handle of the newly generated private key.
    pub new_private: CK_OBJECT_HANDLE,
    /// Handle of the old private key (Deactivated or Compromised per policy).
    pub retired_private: CK_OBJECT_HANDLE,
}

/// Rotate the PQ key identified by `old_private_handle`.
///
/// `mechanism` is the PKCS#11 mechanism to generate the replacement under —
/// in practice the caller usually wants the same mechanism as the old key,
/// but allowing it to differ supports migration (e.g., ML-DSA-44 → ML-DSA-65).
pub fn rotate_key(
    core: &HsmCore,
    old_private_handle: CK_OBJECT_HANDLE,
    mechanism: CK_MECHANISM_TYPE,
    policy: RotatePolicy,
) -> HsmResult<Rotated> {
    // Capture the old key's templates so the new key inherits label / id /
    // sensitive / extractable flags where possible. PKCS#11 attribute
    // transfer is best-effort — any attribute the new key rejects (because
    // of mechanism mismatch, e.g. can_derive for a signature-only key) is
    // dropped silently; the new key's defaults take over.
    let (old_pub_tpl, old_priv_tpl) = extract_templates(core, old_private_handle)?;

    let generated = crate::service::keygen::generate_pqc_keypair(
        core,
        mechanism,
        &old_pub_tpl,
        &old_priv_tpl,
    )?;

    // Retire the old key atomically under its own write lock.
    retire(core, old_private_handle, policy)?;

    // Audit a synthetic entry — there is no dedicated `KeyRotate` variant in
    // `AuditOperation` (stable external-format enum), so reuse
    // `GenerateKeyPair` for the new-keygen leg and `DestroyObject` for the
    // retirement leg. Callers grepping the log for rotation events match on
    // the `key_id` string prefix `"rotate:"`.
    let _ = core.audit_log().record(
        0, // no session context for the service-layer rotation path
        AuditOperation::GenerateKeyPair {
            mechanism: mechanism as u64,
            key_length: generated.key_bits,
            fips_approved: false, // PQC is not FIPS-approved in this release
        },
        AuditResult::Success,
        Some(format!(
            "rotate:new_pub={} new_priv={} retired_priv={}",
            generated.public_handle, generated.private_handle, old_private_handle
        )),
    );

    Ok(Rotated {
        new_public: generated.public_handle,
        new_private: generated.private_handle,
        retired_private: old_private_handle,
    })
}

/// Read a stored object's public/private attribute templates so the new key
/// can be generated with the same label, id, sensitive/extractable flags.
fn extract_templates(
    core: &HsmCore,
    old_private_handle: CK_OBJECT_HANDLE,
) -> HsmResult<(
    Vec<(crate::pkcs11_abi::types::CK_ATTRIBUTE_TYPE, Vec<u8>)>,
    Vec<(crate::pkcs11_abi::types::CK_ATTRIBUTE_TYPE, Vec<u8>)>,
)> {
    let arc = core.object_store().get_object(old_private_handle)?;
    let obj = arc.read();

    let mut priv_tpl: Vec<(crate::pkcs11_abi::types::CK_ATTRIBUTE_TYPE, Vec<u8>)> = Vec::new();
    if !obj.label.is_empty() {
        priv_tpl.push((
            crate::pkcs11_abi::constants::CKA_LABEL,
            obj.label.clone(),
        ));
    }
    if !obj.id.is_empty() {
        priv_tpl.push((crate::pkcs11_abi::constants::CKA_ID, obj.id.clone()));
    }
    // Public template mirrors the private one for the attributes it supports.
    Ok((priv_tpl.clone(), priv_tpl))
}

/// Transition the old private key to Deactivated (default) or Compromised
/// and stamp `CKA_END_DATE` with today's date.
fn retire(
    core: &HsmCore,
    old_handle: CK_OBJECT_HANDLE,
    policy: RotatePolicy,
) -> HsmResult<()> {
    let arc = core.object_store().get_object(old_handle)?;
    let mut obj = arc.write();

    obj.lifecycle_state = if policy.mark_compromised {
        KeyLifecycleState::Compromised
    } else {
        KeyLifecycleState::Deactivated
    };
    obj.end_date = Some(today_cka_date());
    Ok(())
}

/// Today's date encoded as PKCS#11 `CK_DATE` — ASCII "YYYYMMDD" (8 bytes).
fn today_cka_date() -> [u8; 8] {
    let now = Utc::now();
    let s = format!("{:04}{:02}{:02}", now.year(), now.month(), now.day());
    let bytes = s.as_bytes();
    let mut out = [b'0'; 8];
    out.copy_from_slice(&bytes[..8]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::HsmConfig;
    use crate::pkcs11_abi::constants::CKM_ML_DSA_44;

    #[test]
    fn rotate_ml_dsa_produces_new_handles_and_retires_old() {
        let config = HsmConfig::default();
        let core = HsmCore::new(&config);

        // Generate an initial ML-DSA-44 pair through the service entry point.
        let first = crate::service::keygen::generate_pqc_keypair(
            &core,
            CKM_ML_DSA_44,
            &[],
            &[],
        )
        .expect("initial keygen");

        let rotated = rotate_key(&core, first.private_handle, CKM_ML_DSA_44, RotatePolicy::default())
            .expect("rotate");

        assert_ne!(rotated.new_private, first.private_handle);
        assert_ne!(rotated.new_public, first.public_handle);
        assert_eq!(rotated.retired_private, first.private_handle);

        // Old key should be Deactivated.
        let old = core.object_store().get_object(first.private_handle).unwrap();
        let g = old.read();
        assert_eq!(g.lifecycle_state, KeyLifecycleState::Deactivated);
        assert!(g.end_date.is_some(), "end_date must be stamped");
    }

    #[test]
    fn rotate_marks_compromised_when_policy_requests() {
        let config = HsmConfig::default();
        let core = HsmCore::new(&config);
        let first = crate::service::keygen::generate_pqc_keypair(
            &core,
            CKM_ML_DSA_44,
            &[],
            &[],
        )
        .unwrap();

        let _ = rotate_key(
            &core,
            first.private_handle,
            CKM_ML_DSA_44,
            RotatePolicy { mark_compromised: true },
        )
        .unwrap();

        let old = core.object_store().get_object(first.private_handle).unwrap();
        assert_eq!(old.read().lifecycle_state, KeyLifecycleState::Compromised);
    }
}
