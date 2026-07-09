// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Parsing of PKCS#11 mechanism-parameter structures.
//!
//! Several mechanism parameter structs (`CK_GCM_PARAMS`, `CK_RSA_PKCS_PSS_PARAMS`,
//! `CK_RSA_PKCS_OAEP_PARAMS`, `CK_ECDH1_DERIVE_PARAMS`, …) contain **embedded
//! pointers** to caller-owned buffers (IVs, AAD, labels, peer public keys).
//! Those pointers are only valid for the duration of the `C_*Init` call, so
//! this module deep-copies the pointed-to data into owned Rust values at parse
//! time. The parsed value is then carried in the session's `ActiveOperation`.
//!
//! Every parser validates `parameter_len` against the expected struct size
//! *before* dereferencing, and bounds every embedded buffer by
//! [`MAX_PARAM_BUFFER`], so a malformed or malicious `CK_MECHANISM` cannot
//! cause an out-of-bounds read.

use crate::pkcs11_abi::types::{
    CK_ECDH1_DERIVE_PARAMS, CK_GCM_PARAMS, CK_HKDF_PARAMS, CK_MECHANISM_PTR,
    CK_RSA_PKCS_OAEP_PARAMS, CK_RSA_PKCS_PSS_PARAMS, CK_RV, CK_ULONG,
};

/// Upper bound on any single embedded parameter buffer (IV, AAD, label…).
/// No conforming mechanism parameter approaches this size.
const MAX_PARAM_BUFFER: usize = 64 * 1024 * 1024;

// PKCS#11 return codes used here (kept local to avoid a wildcard import).
const CKR_MECHANISM_PARAM_INVALID: CK_RV = 0x00000070;

/// Parsed, owned form of `CK_GCM_PARAMS`.
///
/// The IV and AAD are deep-copied out of the caller's buffers; `tag_bits` is
/// validated to be one of the AES-GCM permitted tag lengths.
#[derive(Debug, Clone)]
pub struct GcmParams {
    /// Deep-copied initialization vector (nonce).
    pub iv: Vec<u8>,
    /// Deep-copied additional authenticated data (may be empty).
    pub aad: Vec<u8>,
    /// Authentication tag length in bits: one of 96, 104, 112, 120, 128.
    pub tag_bits: u32,
}

/// Byte size of the v3.0 (6-field) `CK_GCM_PARAMS` layout.
const GCM_PARAMS_LEN_V30: usize = std::mem::size_of::<CK_GCM_PARAMS>();
/// Byte size of the v2.40 (5-field, no `ul_iv_bits`) layout.
const GCM_PARAMS_LEN_V240: usize =
    GCM_PARAMS_LEN_V30 - std::mem::size_of::<crate::pkcs11_abi::types::CK_ULONG>();

/// Whether `len` matches a recognized `CK_GCM_PARAMS` layout (v3.0 or v2.40).
///
/// Used by the ABI to decide between the conformant params path and the
/// legacy internal-nonce path: any parameter whose length is NOT a known
/// struct size is treated as legacy (the pre-3.0 behavior ignored the
/// parameter entirely and generated its own nonce), preserving 100% backward
/// compatibility for callers that passed a bare IV or other blob.
pub fn is_gcm_params_size(len: usize) -> bool {
    len == GCM_PARAMS_LEN_V30 || len == GCM_PARAMS_LEN_V240
}

/// Parse `CK_GCM_PARAMS` from a `CK_MECHANISM`, accepting both the v3.0
/// (6-field) and v2.40 (5-field) layouts, distinguished by `parameter_len`.
///
/// # Safety
/// `p_mechanism` must be a valid, non-null pointer to a `CK_MECHANISM` whose
/// `p_parameter` (if non-null) points to a `CK_GCM_PARAMS` of the length it
/// declares, with valid `p_iv` / `p_aad` buffers.
pub unsafe fn parse_gcm_params(p_mechanism: CK_MECHANISM_PTR) -> Result<GcmParams, CK_RV> {
    let mech = &*p_mechanism;
    if mech.p_parameter.is_null() {
        return Err(CKR_MECHANISM_PARAM_INVALID);
    }
    let plen = mech.parameter_len as usize;

    // The v2.40 layout is a prefix of the v3.0 layout with `ul_iv_bits`
    // removed from the middle, so we cannot simply truncate. Read the two
    // layouts field-by-field.
    let base = mech.p_parameter as *const u8;
    let (p_iv, ul_iv_len, p_aad, ul_aad_len, ul_tag_bits) = if plen == GCM_PARAMS_LEN_V30 {
        let p = &*(mech.p_parameter as *const CK_GCM_PARAMS);
        (p.p_iv, p.ul_iv_len, p.p_aad, p.ul_aad_len, p.ul_tag_bits)
    } else if plen == GCM_PARAMS_LEN_V240 {
        // v2.40: [p_iv][ul_iv_len][p_aad][ul_aad_len][ul_tag_bits]
        use crate::pkcs11_abi::types::{CK_BYTE_PTR, CK_ULONG};
        let ptr_sz = std::mem::size_of::<CK_BYTE_PTR>();
        let ul_sz = std::mem::size_of::<CK_ULONG>();
        let read_ptr = |off: usize| (base.add(off) as *const CK_BYTE_PTR).read_unaligned();
        let read_ul = |off: usize| (base.add(off) as *const CK_ULONG).read_unaligned();
        let mut off = 0;
        let p_iv = read_ptr(off);
        off += ptr_sz;
        let ul_iv_len = read_ul(off);
        off += ul_sz;
        let p_aad = read_ptr(off);
        off += ptr_sz;
        let ul_aad_len = read_ul(off);
        off += ul_sz;
        let ul_tag_bits = read_ul(off);
        (p_iv, ul_iv_len, p_aad, ul_aad_len, ul_tag_bits)
    } else {
        return Err(CKR_MECHANISM_PARAM_INVALID);
    };

    let iv_len = ul_iv_len as usize;
    let aad_len = ul_aad_len as usize;
    if iv_len == 0 || iv_len > MAX_PARAM_BUFFER || aad_len > MAX_PARAM_BUFFER {
        return Err(CKR_MECHANISM_PARAM_INVALID);
    }
    if p_iv.is_null() {
        return Err(CKR_MECHANISM_PARAM_INVALID);
    }

    let tag_bits = ul_tag_bits as u32;
    if !matches!(tag_bits, 96 | 104 | 112 | 120 | 128) {
        return Err(CKR_MECHANISM_PARAM_INVALID);
    }

    let iv = std::slice::from_raw_parts(p_iv as *const u8, iv_len).to_vec();
    let aad = if aad_len == 0 || p_aad.is_null() {
        Vec::new()
    } else {
        std::slice::from_raw_parts(p_aad as *const u8, aad_len).to_vec()
    };

    Ok(GcmParams { iv, aad, tag_bits })
}

// ── CK_ECDH1_DERIVE_PARAMS ─────────────────────────────────────────────────

/// Parsed, owned form of `CK_ECDH1_DERIVE_PARAMS`.
///
/// The peer public key and optional shared data are deep-copied out of the
/// caller's buffers; `kdf` is the raw `CK_EC_KDF_TYPE` selector (validated by
/// the ABI dispatch, not here).
#[derive(Debug, Clone)]
pub struct Ecdh1Params {
    /// Key-derivation function selector (CKD_NULL, CKD_SHA256_KDF, …).
    pub kdf: CK_ULONG,
    /// Deep-copied KDF shared data (SharedInfo); may be empty.
    pub shared_data: Vec<u8>,
    /// Deep-copied peer public key (EC_POINT).
    pub public_data: Vec<u8>,
}

/// Byte size of the `CK_ECDH1_DERIVE_PARAMS` layout for the target ABI.
const ECDH1_PARAMS_LEN: usize = std::mem::size_of::<CK_ECDH1_DERIVE_PARAMS>();

/// Whether `len` matches the `CK_ECDH1_DERIVE_PARAMS` struct size.
///
/// The ABI uses this to distinguish a conforming parameter struct from the
/// legacy convention of passing a bare EC_POINT as the mechanism parameter:
/// any other length is treated as a raw peer public key (CKD_NULL), preserving
/// backward compatibility.
pub fn is_ecdh1_params_size(len: usize) -> bool {
    len == ECDH1_PARAMS_LEN
}

/// Parse `CK_ECDH1_DERIVE_PARAMS` from a `CK_MECHANISM`, deep-copying the peer
/// public key and optional shared data.
///
/// # Safety
/// `p_mechanism` must be a valid, non-null pointer to a `CK_MECHANISM` whose
/// `p_parameter` points to a `CK_ECDH1_DERIVE_PARAMS` of the declared length,
/// with valid `p_public_data` / `p_shared_data` buffers.
pub unsafe fn parse_ecdh1_params(p_mechanism: CK_MECHANISM_PTR) -> Result<Ecdh1Params, CK_RV> {
    let mech = &*p_mechanism;
    if mech.p_parameter.is_null() || (mech.parameter_len as usize) != ECDH1_PARAMS_LEN {
        return Err(CKR_MECHANISM_PARAM_INVALID);
    }

    // Read fields via unaligned pointer reads so the caller's buffer need not be
    // aligned to the struct on either the packed (Windows) or unpacked layout.
    use crate::pkcs11_abi::types::CK_BYTE_PTR;
    let base = mech.p_parameter as *const u8;
    let ptr_sz = std::mem::size_of::<CK_BYTE_PTR>();
    let ul_sz = std::mem::size_of::<CK_ULONG>();
    let read_ptr = |off: usize| (base.add(off) as *const CK_BYTE_PTR).read_unaligned();
    let read_ul = |off: usize| (base.add(off) as *const CK_ULONG).read_unaligned();

    let mut off = 0;
    let kdf = read_ul(off);
    off += ul_sz;
    let ul_shared_data_len = read_ul(off);
    off += ul_sz;
    let p_shared_data = read_ptr(off);
    off += ptr_sz;
    let ul_public_data_len = read_ul(off);
    off += ul_sz;
    let p_public_data = read_ptr(off);

    let shared_len = ul_shared_data_len as usize;
    let public_len = ul_public_data_len as usize;
    if public_len == 0 || public_len > MAX_PARAM_BUFFER || shared_len > MAX_PARAM_BUFFER {
        return Err(CKR_MECHANISM_PARAM_INVALID);
    }
    if p_public_data.is_null() {
        return Err(CKR_MECHANISM_PARAM_INVALID);
    }

    let public_data = std::slice::from_raw_parts(p_public_data as *const u8, public_len).to_vec();
    let shared_data = if shared_len == 0 || p_shared_data.is_null() {
        Vec::new()
    } else {
        std::slice::from_raw_parts(p_shared_data as *const u8, shared_len).to_vec()
    };

    Ok(Ecdh1Params {
        kdf,
        shared_data,
        public_data,
    })
}

// ── CK_HKDF_PARAMS ─────────────────────────────────────────────────────────

/// Parsed, owned form of `CK_HKDF_PARAMS`.
#[derive(Debug, Clone)]
pub struct HkdfParams {
    /// Whether to run HKDF-Extract.
    pub extract: bool,
    /// Whether to run HKDF-Expand.
    pub expand: bool,
    /// PRF hash mechanism (`CKM_SHA256`, …).
    pub prf_hash_mechanism: CK_ULONG,
    /// Salt type (`CKF_HKDF_SALT_NULL` / `_DATA` / `_KEY`).
    pub salt_type: CK_ULONG,
    /// Deep-copied salt bytes (for `CKF_HKDF_SALT_DATA`; empty otherwise).
    pub salt: Vec<u8>,
    /// Salt key handle (for `CKF_HKDF_SALT_KEY`).
    pub salt_key: CK_ULONG,
    /// Deep-copied info/context bytes (may be empty).
    pub info: Vec<u8>,
}

/// Byte size of the `CK_HKDF_PARAMS` layout for the target ABI.
const HKDF_PARAMS_LEN: usize = std::mem::size_of::<CK_HKDF_PARAMS>();

/// Whether `len` matches the `CK_HKDF_PARAMS` struct size.
pub fn is_hkdf_params_size(len: usize) -> bool {
    len == HKDF_PARAMS_LEN
}

/// Parse `CK_HKDF_PARAMS` from a `CK_MECHANISM`, deep-copying the salt and info.
///
/// Fields are read at compiler-computed offsets (`std::mem::offset_of!`) via
/// unaligned reads, so struct padding and caller-buffer alignment are handled
/// correctly on every target.
///
/// # Safety
/// `p_mechanism` must be a valid, non-null pointer to a `CK_MECHANISM` whose
/// `p_parameter` points to a `CK_HKDF_PARAMS` of the declared length, with valid
/// `p_salt` / `p_info` buffers.
pub unsafe fn parse_hkdf_params(p_mechanism: CK_MECHANISM_PTR) -> Result<HkdfParams, CK_RV> {
    use crate::pkcs11_abi::types::CK_BYTE_PTR;
    use std::mem::offset_of;

    let mech = &*p_mechanism;
    if mech.p_parameter.is_null() || (mech.parameter_len as usize) != HKDF_PARAMS_LEN {
        return Err(CKR_MECHANISM_PARAM_INVALID);
    }
    let base = mech.p_parameter as *const u8;
    let read_u8 = |off: usize| (base.add(off) as *const u8).read_unaligned();
    let read_ul = |off: usize| (base.add(off) as *const CK_ULONG).read_unaligned();
    let read_ptr = |off: usize| (base.add(off) as *const CK_BYTE_PTR).read_unaligned();

    let extract = read_u8(offset_of!(CK_HKDF_PARAMS, b_extract)) != 0;
    let expand = read_u8(offset_of!(CK_HKDF_PARAMS, b_expand)) != 0;
    let prf_hash_mechanism = read_ul(offset_of!(CK_HKDF_PARAMS, prf_hash_mechanism));
    let salt_type = read_ul(offset_of!(CK_HKDF_PARAMS, ul_salt_type));
    let p_salt = read_ptr(offset_of!(CK_HKDF_PARAMS, p_salt));
    let salt_len = read_ul(offset_of!(CK_HKDF_PARAMS, ul_salt_len)) as usize;
    let salt_key = read_ul(offset_of!(CK_HKDF_PARAMS, h_salt_key));
    let p_info = read_ptr(offset_of!(CK_HKDF_PARAMS, p_info));
    let info_len = read_ul(offset_of!(CK_HKDF_PARAMS, ul_info_len)) as usize;

    if salt_len > MAX_PARAM_BUFFER || info_len > MAX_PARAM_BUFFER {
        return Err(CKR_MECHANISM_PARAM_INVALID);
    }
    let salt = if salt_len == 0 || p_salt.is_null() {
        Vec::new()
    } else {
        std::slice::from_raw_parts(p_salt as *const u8, salt_len).to_vec()
    };
    let info = if info_len == 0 || p_info.is_null() {
        Vec::new()
    } else {
        std::slice::from_raw_parts(p_info as *const u8, info_len).to_vec()
    };

    Ok(HkdfParams {
        extract,
        expand,
        prf_hash_mechanism,
        salt_type,
        salt,
        salt_key,
        info,
    })
}

// ── CK_RSA_PKCS_OAEP_PARAMS ────────────────────────────────────────────────

/// Parsed, owned form of `CK_RSA_PKCS_OAEP_PARAMS`.
#[derive(Debug, Clone)]
pub struct OaepParams {
    /// OAEP hash mechanism (`CKM_SHA256`, …).
    pub hash_alg: CK_ULONG,
    /// Mask generation function (`CKG_MGF1_SHA256`, …).
    pub mgf: CK_ULONG,
    /// Label source (`CKZ_DATA_SPECIFIED`).
    pub source: CK_ULONG,
    /// Deep-copied label / encoding parameter (may be empty).
    pub label: Vec<u8>,
}

/// Byte size of the `CK_RSA_PKCS_OAEP_PARAMS` layout for the target ABI.
const OAEP_PARAMS_LEN: usize = std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>();

/// Whether `len` matches the `CK_RSA_PKCS_OAEP_PARAMS` struct size. Any other
/// length is treated as a legacy bare-hashAlg parameter by the ABI.
pub fn is_oaep_params_size(len: usize) -> bool {
    len == OAEP_PARAMS_LEN
}

/// Parse `CK_RSA_PKCS_OAEP_PARAMS` from a `CK_MECHANISM`, deep-copying the label.
///
/// # Safety
/// `p_mechanism` must be a valid, non-null pointer to a `CK_MECHANISM` whose
/// `p_parameter` points to a `CK_RSA_PKCS_OAEP_PARAMS` of the declared length,
/// with a valid `p_source_data` buffer when `ul_source_data_len > 0`.
pub unsafe fn parse_oaep_params(p_mechanism: CK_MECHANISM_PTR) -> Result<OaepParams, CK_RV> {
    use crate::pkcs11_abi::types::CK_BYTE_PTR;
    use std::mem::offset_of;

    let mech = &*p_mechanism;
    if mech.p_parameter.is_null() || (mech.parameter_len as usize) != OAEP_PARAMS_LEN {
        return Err(CKR_MECHANISM_PARAM_INVALID);
    }
    let base = mech.p_parameter as *const u8;
    let read_ul = |off: usize| (base.add(off) as *const CK_ULONG).read_unaligned();
    let read_ptr = |off: usize| (base.add(off) as *const CK_BYTE_PTR).read_unaligned();

    let hash_alg = read_ul(offset_of!(CK_RSA_PKCS_OAEP_PARAMS, hash_alg));
    let mgf = read_ul(offset_of!(CK_RSA_PKCS_OAEP_PARAMS, mgf));
    let source = read_ul(offset_of!(CK_RSA_PKCS_OAEP_PARAMS, source));
    let p_source = read_ptr(offset_of!(CK_RSA_PKCS_OAEP_PARAMS, p_source_data));
    let source_len = read_ul(offset_of!(CK_RSA_PKCS_OAEP_PARAMS, ul_source_data_len)) as usize;

    if source_len > MAX_PARAM_BUFFER {
        return Err(CKR_MECHANISM_PARAM_INVALID);
    }
    let label = if source_len == 0 || p_source.is_null() {
        Vec::new()
    } else {
        std::slice::from_raw_parts(p_source as *const u8, source_len).to_vec()
    };

    Ok(OaepParams {
        hash_alg,
        mgf,
        source,
        label,
    })
}

/// Magic byte marking a params-mode OAEP blob carried in `mechanism_param`.
const OAEP_BLOB_MAGIC: u8 = 0xB3;

/// Encode resolved OAEP parameters into the opaque blob stored in
/// `ActiveOperation::Encrypt`/`Decrypt`. `hash_alg`/`mgf` are `CKM_*`/`CKG_*`
/// mechanism values; the label is carried verbatim.
pub fn encode_oaep_blob(hash_alg: CK_ULONG, mgf: CK_ULONG, label: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 8 + 8 + 4 + label.len());
    out.push(OAEP_BLOB_MAGIC);
    out.extend_from_slice(&(hash_alg as u64).to_le_bytes());
    out.extend_from_slice(&(mgf as u64).to_le_bytes());
    out.extend_from_slice(&(label.len() as u32).to_le_bytes());
    out.extend_from_slice(label);
    out
}

/// Decode an OAEP blob produced by [`encode_oaep_blob`] → `(hash_alg, mgf, label)`.
pub fn decode_oaep_blob(blob: &[u8]) -> Option<(CK_ULONG, CK_ULONG, Vec<u8>)> {
    if blob.first() != Some(&OAEP_BLOB_MAGIC) {
        return None;
    }
    let mut off = 1usize;
    let hash_alg = u64::from_le_bytes(blob.get(off..off + 8)?.try_into().ok()?) as CK_ULONG;
    off += 8;
    let mgf = u64::from_le_bytes(blob.get(off..off + 8)?.try_into().ok()?) as CK_ULONG;
    off += 8;
    let label_len = u32::from_le_bytes(blob.get(off..off + 4)?.try_into().ok()?) as usize;
    off += 4;
    let label = blob.get(off..off + label_len)?.to_vec();
    Some((hash_alg, mgf, label))
}

// ── CK_RSA_PKCS_PSS_PARAMS ─────────────────────────────────────────────────

/// Parsed, owned form of `CK_RSA_PKCS_PSS_PARAMS` (three inline `CK_ULONG`s).
#[derive(Debug, Clone, Copy)]
pub struct PssParams {
    /// PSS hash mechanism (`CKM_SHA256`, …).
    pub hash_alg: CK_ULONG,
    /// Mask generation function (`CKG_MGF1_SHA256`, …).
    pub mgf: CK_ULONG,
    /// Salt length in bytes.
    pub s_len: CK_ULONG,
}

/// Byte size of the `CK_RSA_PKCS_PSS_PARAMS` layout for the target ABI.
const PSS_PARAMS_LEN: usize = std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>();

/// Whether `len` matches the `CK_RSA_PKCS_PSS_PARAMS` struct size.
pub fn is_pss_params_size(len: usize) -> bool {
    len == PSS_PARAMS_LEN
}

/// Parse `CK_RSA_PKCS_PSS_PARAMS` directly from the copied parameter bytes.
/// The struct has no embedded pointers, so no live `CK_MECHANISM` pointer is
/// needed. Returns `None` if `raw` is not the exact struct size.
pub fn parse_pss_params(raw: &[u8]) -> Option<PssParams> {
    if raw.len() != PSS_PARAMS_LEN {
        return None;
    }
    let u = std::mem::size_of::<CK_ULONG>();
    let hash_alg = CK_ULONG::from_ne_bytes(raw[0..u].try_into().ok()?);
    let mgf = CK_ULONG::from_ne_bytes(raw[u..2 * u].try_into().ok()?);
    let s_len = CK_ULONG::from_ne_bytes(raw[2 * u..3 * u].try_into().ok()?);
    Some(PssParams {
        hash_alg,
        mgf,
        s_len,
    })
}

// ── Internal wire encoding for carrying GcmParams through ActiveOperation ──
//
// `ActiveOperation::Encrypt` stores the mechanism parameter as an opaque
// `Vec<u8>`. To avoid changing that shape, params-mode GCM serializes the
// parsed IV/AAD/tag into a self-describing blob at C_*Init and decodes it at
// C_Encrypt/C_Decrypt. A leading magic byte distinguishes this from the raw
// IV bytes used by CBC/CTR (which never start with this marker semantics —
// GCM has its own dispatch arm, so there is no collision).

/// Magic byte marking a params-mode GCM blob. GCM has its own dispatch arm, so
/// this never has to be distinguished from a CBC/CTR IV — the marker only
/// separates params-mode (non-empty, magic-prefixed) from legacy mode (empty).
const GCM_BLOB_MAGIC: u8 = 0xA7;

/// Encode [`GcmParams`] into the opaque blob stored in `ActiveOperation`.
pub fn encode_gcm_blob(p: &GcmParams) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 2 + p.iv.len() + 4 + p.aad.len() + 4);
    out.push(GCM_BLOB_MAGIC);
    out.extend_from_slice(&(p.iv.len() as u16).to_le_bytes());
    out.extend_from_slice(&p.iv);
    out.extend_from_slice(&(p.aad.len() as u32).to_le_bytes());
    out.extend_from_slice(&p.aad);
    out.extend_from_slice(&p.tag_bits.to_le_bytes());
    out
}

/// Decode a params-mode GCM blob previously produced by [`encode_gcm_blob`].
/// Returns `None` if the blob is not a params-mode blob (legacy/empty).
pub fn decode_gcm_blob(blob: &[u8]) -> Option<GcmParams> {
    if blob.first() != Some(&GCM_BLOB_MAGIC) {
        return None;
    }
    let mut off = 1usize;
    let iv_len = u16::from_le_bytes([*blob.get(off)?, *blob.get(off + 1)?]) as usize;
    off += 2;
    let iv = blob.get(off..off + iv_len)?.to_vec();
    off += iv_len;
    let aad_len = u32::from_le_bytes([
        *blob.get(off)?,
        *blob.get(off + 1)?,
        *blob.get(off + 2)?,
        *blob.get(off + 3)?,
    ]) as usize;
    off += 4;
    let aad = blob.get(off..off + aad_len)?.to_vec();
    off += aad_len;
    let tag_bits = u32::from_le_bytes([
        *blob.get(off)?,
        *blob.get(off + 1)?,
        *blob.get(off + 2)?,
        *blob.get(off + 3)?,
    ]);
    Some(GcmParams { iv, aad, tag_bits })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gcm_blob_roundtrip() {
        let p = GcmParams {
            iv: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            aad: b"header".to_vec(),
            tag_bits: 128,
        };
        let blob = encode_gcm_blob(&p);
        let decoded = decode_gcm_blob(&blob).expect("decode");
        assert_eq!(decoded.iv, p.iv);
        assert_eq!(decoded.aad, p.aad);
        assert_eq!(decoded.tag_bits, p.tag_bits);
    }

    #[test]
    fn non_blob_returns_none() {
        // Raw 16-byte CBC IV — not a GCM blob.
        assert!(decode_gcm_blob(&[0u8; 16]).is_none());
        assert!(decode_gcm_blob(&[]).is_none());
    }

    #[test]
    fn empty_aad_roundtrip() {
        let p = GcmParams {
            iv: vec![0xAA; 12],
            aad: Vec::new(),
            tag_bits: 96,
        };
        let blob = encode_gcm_blob(&p);
        let decoded = decode_gcm_blob(&blob).expect("decode");
        assert!(decoded.aad.is_empty());
        assert_eq!(decoded.tag_bits, 96);
    }
}
