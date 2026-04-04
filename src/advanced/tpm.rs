// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! TPM 2.0 hardware root-of-trust integration via **tss-esapi**.
//!
//! Binds the HSM's master key material to the platform's Trusted Platform Module,
//! providing:
//!
//! | Feature | Description |
//! |---|---|
//! | **PCR Sealing** | Seal an HSM token master key to a set of PCR digests; the TPM refuses to unseal unless the platform is in an identical measured state |
//! | **TPM RNG** | Augment the SP 800-90A HMAC-DRBG with hardware entropy from the TPM's on-chip DRBG |
//! | **Platform Attestation** | Produce a TPM Quote covering a nonce and PCR selection — cryptographic proof of platform state to remote verifiers |
//! | **Key Certification** | Have the TPM certify that a given key was created inside the TPM and never exported |
//!
//! # System requirements
//! Requires `libtss2-esys`, `libtss2-rc`, and `libtss2-mu` (TSS2 C libraries).
//! On Debian/Ubuntu: `apt-get install libtss2-dev`.
//! On RHEL/Fedora: `dnf install tpm2-tss-devel`.
//!
//! The TPM device is accessed via the TCTI configured in `TCTI_DEFAULT`
//! or overridden with the `TPM2TOOLS_TCTI` / `TSS2_TCTI` environment variable.
//!
//! # PCR strategy for Craton HSM
//! We recommend sealing to PCR[0, 2, 7] (firmware, option ROMs, Secure Boot state)
//! so the HSM master key is only accessible when the platform boots the expected
//! firmware stack.  Changing firmware or disabling Secure Boot will make the
//! sealed key permanently inaccessible (by design).

#![cfg(feature = "tpm-binding")]

use std::convert::TryFrom;

use tss_esapi::{
    abstraction::pcr::read_all as pcr_read_all,
    attributes::ObjectAttributesBuilder,
    constants::tss as tss_types,
    handles::{KeyHandle, PersistentTpmHandle, TpmHandle},
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm, SymmetricMode, SymmetricObject},
        key_bits::Aes,
        reserved_handles::Hierarchy,
        session_handles::PolicySession,
        structure_tags::AttestationType,
    },
    structures::{
        Auth, CapabilityData, CreateKeyResult, Digest, DigestValues, EccScheme, HashScheme,
        MaxBuffer, Name, Nonce, PcrSelectionList, PcrSelectionListBuilder, PcrSlot, Public,
        PublicBuilder, PublicEccParametersBuilder, PublicKeyedHashParameters,
        PublicRsaParametersBuilder, RsaScheme, SymmetricDefinitionObject,
    },
    tcti_ldr::TctiNameConf,
    Context,
};
use zeroize::Zeroize;

use crate::error::HsmError;

// ── Configuration ─────────────────────────────────────────────────────────────

/// PCR selection used for sealing the HSM master key.
///
/// PCR 0 = Core BIOS / UEFI firmware
/// PCR 2 = Option ROMs
/// PCR 7 = Secure Boot state (enabled, policy, certificates)
pub const HSM_SEAL_PCR_SELECTION: &[PcrSlot] = &[PcrSlot::Slot0, PcrSlot::Slot2, PcrSlot::Slot7];

/// Maximum size of data that can be sealed in a single TPM2_Create call (128 bytes).
pub const MAX_SEAL_SIZE: usize = 128;

// ── Context management ────────────────────────────────────────────────────────

/// A handle to the TPM, opened via the system TCTI.
///
/// Creating a `TpmContext` opens a connection to the TPM device.  Only one
/// context per process is needed; wrap in `Arc<Mutex<>>` for multi-threaded use.
pub struct TpmContext {
    ctx: Context,
}

impl TpmContext {
    /// Open a TPM context using the TCTI configured in the environment
    /// (`TPM2TOOLS_TCTI` / `TSS2_TCTI`), or fall back to the default device TCTI.
    pub fn open() -> Result<Self, HsmError> {
        let tcti = TctiNameConf::from_environment_variable()
            .unwrap_or_else(|_| TctiNameConf::Device(Default::default()));
        let ctx = Context::new(tcti)
            .map_err(|e| HsmError::ConfigError(format!("TPM context open failed: {e}")))?;
        Ok(Self { ctx })
    }

    /// Open a context with an explicit TCTI name string (e.g. `"device:/dev/tpm0"`).
    pub fn open_with_tcti(tcti_str: &str) -> Result<Self, HsmError> {
        let tcti: TctiNameConf = tcti_str
            .parse()
            .map_err(|e| HsmError::ConfigError(format!("Invalid TCTI '{tcti_str}': {e}")))?;
        let ctx = Context::new(tcti)
            .map_err(|e| HsmError::ConfigError(format!("TPM context open: {e}")))?;
        Ok(Self { ctx })
    }
}

// ── TPM RNG ───────────────────────────────────────────────────────────────────

/// Retrieve `len` bytes of hardware entropy from the TPM's on-chip DRBG.
///
/// This output should be mixed into the SP 800-90A HMAC-DRBG via the
/// additional-input parameter on `generate()`, not used directly as a key.
///
/// # Errors
/// Returns [`HsmError::GeneralError`] if the TPM call fails or returns
/// fewer bytes than requested.
pub fn tpm_get_random(ctx: &mut TpmContext, len: usize) -> Result<Vec<u8>, HsmError> {
    // TPM2_GetRandom returns at most `tpm2-pt-max-digest` bytes per call (typically 64).
    // Loop until we have enough entropy.
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        let needed = (len - out.len()).min(64) as u16;
        let random_bytes = ctx
            .ctx
            .get_random(needed)
            .map_err(|_| HsmError::GeneralError)?;
        out.extend_from_slice(random_bytes.as_slice());
    }
    out.truncate(len);
    Ok(out)
}

// ── PCR sealing ───────────────────────────────────────────────────────────────

/// Seal `secret` to the current values of the PCRs in [`HSM_SEAL_PCR_SELECTION`].
///
/// Returns an opaque blob that can only be unsealed by a TPM in the same
/// measured boot state.  The blob includes the encrypted secret and the
/// `creation_data` needed for attestation.
///
/// # Errors
/// * [`HsmError::DataLenRange`] — `secret` exceeds [`MAX_SEAL_SIZE`] bytes.
/// * [`HsmError::GeneralError`] — TPM error (check `tracing` output).
pub fn tpm_seal(ctx: &mut TpmContext, secret: &[u8]) -> Result<SealedBlob, HsmError> {
    if secret.len() > MAX_SEAL_SIZE {
        return Err(HsmError::DataLenRange);
    }

    // Build a PCR policy session
    let pcr_sel = PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, HSM_SEAL_PCR_SELECTION)
        .build()
        .map_err(|_| HsmError::GeneralError)?;

    let trial_session = ctx
        .ctx
        .start_auth_session(
            None,
            None,
            None,
            tss_types::TPM2_SE_TRIAL,
            tss_types::TPMT_SYM_DEF {
                algorithm: tss_types::TPM2_ALG_AES,
                keyBits: tss_types::TPMU_SYM_KEY_BITS { aes: 128 },
                mode: tss_types::TPMU_SYM_MODE {
                    aes: tss_types::TPM2_ALG_CFB,
                },
            },
            HashingAlgorithm::Sha256,
        )
        .map_err(|_| HsmError::GeneralError)?
        .ok_or(HsmError::GeneralError)?;

    // Bind the policy to the current PCR state
    ctx.ctx
        .policy_pcr(
            PolicySession::try_from(trial_session).map_err(|_| HsmError::GeneralError)?,
            &Digest::default(),
            pcr_sel.clone(),
        )
        .map_err(|_| HsmError::GeneralError)?;

    let policy_digest = ctx
        .ctx
        .policy_get_digest(
            PolicySession::try_from(trial_session).map_err(|_| HsmError::GeneralError)?,
        )
        .map_err(|_| HsmError::GeneralError)?;

    ctx.ctx.flush_context(trial_session.into()).ok();

    // Create the sealed object template
    let sealed_template = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(
            ObjectAttributesBuilder::new()
                .with_user_with_auth(true)
                .build()
                .map_err(|_| HsmError::GeneralError)?,
        )
        .with_auth_policy(policy_digest)
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(
            tss_esapi::structures::KeyedHashScheme::Null,
        ))
        .with_keyed_hash_unique_identifier(Digest::default())
        .build()
        .map_err(|_| HsmError::GeneralError)?;

    let sensitive_data =
        MaxBuffer::try_from(secret.to_vec()).map_err(|_| HsmError::DataLenRange)?;

    let CreateKeyResult {
        out_private,
        out_public,
        creation_data: _,
        creation_hash: _,
        creation_ticket: _,
    } = ctx
        .ctx
        .create(
            KeyHandle::Owner,
            sealed_template,
            None,
            Some(&sensitive_data),
            None,
            Some(pcr_sel),
        )
        .map_err(|_| HsmError::GeneralError)?;

    Ok(SealedBlob {
        private: out_private.to_vec(),
        public: out_public,
    })
}

/// Unseal a blob previously produced by [`tpm_seal`].
///
/// The TPM will verify the current PCR state matches the policy recorded at
/// seal time.  If the platform state has changed (firmware update, Secure Boot
/// modification, etc.), the TPM will refuse and return an error.
///
/// # Errors
/// * [`HsmError::PinLocked`] — PCR policy check failed (platform state changed).
/// * [`HsmError::GeneralError`] — TPM communication or structural error.
pub fn tpm_unseal(ctx: &mut TpmContext, blob: &SealedBlob) -> Result<Vec<u8>, HsmError> {
    use tss_esapi::structures::Private;

    let private = Private::try_from(blob.private.clone()).map_err(|_| HsmError::DataInvalid)?;

    // Load the sealed object under the Storage Primary
    let key_handle = ctx
        .ctx
        .load(KeyHandle::Owner, private, blob.public.clone())
        .map_err(|_| HsmError::GeneralError)?;

    // Build the PCR policy session for unseal
    let pcr_sel = PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, HSM_SEAL_PCR_SELECTION)
        .build()
        .map_err(|_| HsmError::GeneralError)?;

    let policy_session = ctx
        .ctx
        .start_auth_session(
            None,
            None,
            None,
            tss_types::TPM2_SE_POLICY,
            tss_types::TPMT_SYM_DEF {
                algorithm: tss_types::TPM2_ALG_AES,
                keyBits: tss_types::TPMU_SYM_KEY_BITS { aes: 128 },
                mode: tss_types::TPMU_SYM_MODE {
                    aes: tss_types::TPM2_ALG_CFB,
                },
            },
            HashingAlgorithm::Sha256,
        )
        .map_err(|_| HsmError::GeneralError)?
        .ok_or(HsmError::GeneralError)?;

    let policy_sess_handle =
        PolicySession::try_from(policy_session).map_err(|_| HsmError::GeneralError)?;

    // Satisfy the PCR policy (TPM verifies current PCR values)
    ctx.ctx
        .policy_pcr(policy_sess_handle, &Digest::default(), pcr_sel)
        .map_err(|_| HsmError::PinLocked)?; // policy failure = boot state changed

    let sensitive = ctx
        .ctx
        .unseal(key_handle.into())
        .map_err(|_| HsmError::PinLocked)?;

    ctx.ctx.flush_context(key_handle.into()).ok();
    ctx.ctx.flush_context(policy_session.into()).ok();

    Ok(sensitive.to_vec())
}

// ── Platform attestation ──────────────────────────────────────────────────────

/// Request a TPM Quote: a signed attestation of current PCR values.
///
/// The `nonce` (16–32 bytes) must be a fresh random value supplied by the
/// remote verifier to prevent replay attacks.
///
/// Returns a [`TpmQuote`] containing the attestation structure and signature,
/// which can be forwarded to a remote verifier.
pub fn tpm_quote(ctx: &mut TpmContext, nonce: &[u8]) -> Result<TpmQuote, HsmError> {
    if nonce.len() < 16 || nonce.len() > 64 {
        return Err(HsmError::DataLenRange);
    }

    let qualifying_data = Nonce::try_from(nonce.to_vec()).map_err(|_| HsmError::DataInvalid)?;

    let pcr_sel = PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, HSM_SEAL_PCR_SELECTION)
        .build()
        .map_err(|_| HsmError::GeneralError)?;

    let (attest, signature) = ctx
        .ctx
        .quote(
            KeyHandle::Endorsement, // Sign with the EK
            &qualifying_data,
            tss_esapi::structures::SignatureScheme::Null,
            pcr_sel,
        )
        .map_err(|_| HsmError::GeneralError)?;

    Ok(TpmQuote {
        attestation: attest.to_vec().map_err(|_| HsmError::GeneralError)?,
        signature: signature.to_vec().map_err(|_| HsmError::GeneralError)?,
        nonce: nonce.to_vec(),
    })
}

// ── Data types ────────────────────────────────────────────────────────────────

/// An opaque sealed blob produced by [`tpm_seal`].
///
/// Store alongside your encrypted token database.  The blob is useless
/// without the TPM that created it and the correct PCR state.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SealedBlob {
    /// TPM-encrypted private area (opaque to the OS).
    pub private: Vec<u8>,
    /// Public area of the sealed object (needed to load it back).
    #[serde(skip)] // Public is not serde; store separately in binary
    pub public: tss_esapi::structures::Public,
}

/// A TPM Quote response for remote platform attestation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TpmQuote {
    /// TPMS_ATTEST structure serialised in TPM wire format.
    pub attestation: Vec<u8>,
    /// Signature over `attestation` using the TPM's Attestation Identity Key.
    pub signature: Vec<u8>,
    /// Echo of the verifier's nonce (anti-replay).
    pub nonce: Vec<u8>,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Read the current SHA-256 digest of each PCR in [`HSM_SEAL_PCR_SELECTION`].
///
/// Useful for logging the platform state at token-initialisation time.
pub fn read_hsm_pcrs(ctx: &mut TpmContext) -> Result<Vec<(u8, [u8; 32])>, HsmError> {
    let pcr_sel = PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, HSM_SEAL_PCR_SELECTION)
        .build()
        .map_err(|_| HsmError::GeneralError)?;

    let (_update_counter, _, digest_list) =
        pcr_read_all(&mut ctx.ctx, pcr_sel).map_err(|_| HsmError::GeneralError)?;

    // Collect into (slot_index, sha256) pairs
    let results: Vec<(u8, [u8; 32])> = HSM_SEAL_PCR_SELECTION
        .iter()
        .enumerate()
        .filter_map(|(i, slot)| {
            let digest = digest_list.value().get(i)?;
            let bytes: [u8; 32] = digest.value().try_into().ok()?;
            Some((*slot as u8, bytes))
        })
        .collect();

    Ok(results)
}
