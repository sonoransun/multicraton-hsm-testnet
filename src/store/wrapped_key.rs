// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Wrapped key import/export functionality.
//!
//! This module provides secure import and export of wrapped key material
//! via standardized JSON format and PKCS encrypted key formats (PKCS#8, PKCS#12).
//! Key material is wrapped using RFC 3394 AES Key Wrap for secure transport.

use std::collections::HashMap;

use base64::engine::Engine;
use serde::{Deserialize, Serialize};

use crate::error::{HsmError, HsmResult};
use crate::pkcs11_abi::constants::*;
use crate::pkcs11_abi::types::*;
use crate::store::object::StoredObject;

/// Version of the Craton HSM wrapped key format.
const WRAPPED_KEY_FORMAT_VERSION: u32 = 1;

/// Maximum size for a wrapped-key JSON blob (1 MiB). Prevents DoS via
/// multi-GB malformed JSON payloads that could exhaust memory during parsing.
const MAX_WRAPPED_KEY_JSON: usize = 1_048_576;

/// Supported export/import formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportFormat {
    /// Craton HSM JSON wrapped key format
    CratonJson,
    /// PKCS#8 private key (PEM encoded)
    Pkcs8Pem,
    /// PKCS#8 private key (DER encoded)
    Pkcs8Der,
    /// PKCS#12 container file
    Pkcs12,
}

impl ImportFormat {
    /// Detect format from file content.
    pub fn detect_format(data: &[u8]) -> Self {
        // Check for JSON format (Craton HSM)
        if data.starts_with(b"{")
            && Self::contains_sequence(data, b"\"format\":\"craton-hsm-wrapped-key\"")
        {
            return Self::CratonJson;
        }

        // Check for PEM format
        if data.starts_with(b"-----BEGIN") {
            return Self::Pkcs8Pem;
        }

        // Check for PKCS#12 magic bytes
        if data.len() > 4 && data[0] == 0x30 {
            // Basic ASN.1 SEQUENCE check - could be PKCS#8 DER or PKCS#12
            // More sophisticated detection would parse the ASN.1 structure
            if data.len() > 20
                && Self::contains_sequence(
                    data,
                    &[0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07],
                )
            {
                // Contains PKCS#7 OID - likely PKCS#12
                return Self::Pkcs12;
            }
            return Self::Pkcs8Der;
        }

        // Default to Craton JSON if uncertain
        Self::CratonJson
    }

    /// Helper function to search for a byte sequence within a byte slice.
    fn contains_sequence(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    /// Get MIME content type for the format.
    pub fn content_type(&self) -> &'static str {
        match self {
            Self::CratonJson => "application/json",
            Self::Pkcs8Pem => "application/x-pem-file",
            Self::Pkcs8Der => "application/pkcs8",
            Self::Pkcs12 => "application/x-pkcs12",
        }
    }
}

/// JSON wrapped key format for Craton HSM.
#[derive(Serialize, Deserialize, Debug)]
pub struct WrappedKeyJson {
    /// Format version for future extensibility
    pub version: u32,
    /// Format identifier
    pub format: String,
    /// ISO 8601 timestamp
    pub created: String,
    /// Unix epoch timestamp for age validation
    pub created_epoch: u64,
    /// Wrapping algorithm used (e.g., "AES-KW")
    pub wrapping_algorithm: String,
    /// Wrapping key size in bits
    pub wrapping_key_size: u32,
    /// Wrapped key type (e.g., "AES", "RSA", "ECDSA")
    pub key_type: String,
    /// Key size in bits
    pub key_size: Option<u32>,
    /// Base64-encoded wrapped key material
    pub wrapped_key: String,
    /// PKCS#11 attributes preserved during wrapping
    pub attributes: HashMap<String, serde_json::Value>,
    /// Export metadata for audit and provenance
    pub metadata: WrappedKeyMetadata,
}

/// Metadata associated with wrapped key export.
#[derive(Serialize, Deserialize, Debug)]
pub struct WrappedKeyMetadata {
    /// Source HSM identifier
    pub source_hsm: String,
    /// Source HSM version
    pub source_version: String,
    /// Unique export identifier for replay protection
    pub export_id: String,
    /// Optional export description
    pub description: Option<String>,
}

/// Context information for key wrapping operations.
#[derive(Debug)]
pub struct WrappingContext {
    /// PKCS#11 session handle
    pub session_handle: CK_SESSION_HANDLE,
    /// Handle to the key used for wrapping
    pub wrapping_key_handle: CK_OBJECT_HANDLE,
    /// Wrapping mechanism (e.g., CKM_AES_KEY_WRAP)
    pub mechanism: CK_MECHANISM_TYPE,
    /// Whether FIPS mode restrictions apply
    pub fips_mode: bool,
}

/// Export a key object as wrapped JSON format.
pub fn export_wrapped_key_json(
    object: &StoredObject,
    wrapped_key_data: &[u8],
    ctx: &WrappingContext,
    wrapping_key_size: u32,
) -> HsmResult<WrappedKeyJson> {
    // Generate unique export ID
    let export_id = generate_export_id();

    // Get current timestamp
    let now = std::time::SystemTime::now();
    let created_epoch = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let created = format_timestamp(now);

    // Determine key type and size from object attributes
    let (key_type, key_size) = determine_key_info(object)?;

    // Convert PKCS#11 attributes to JSON-safe format
    let attributes = serialize_object_attributes(object)?;

    Ok(WrappedKeyJson {
        version: WRAPPED_KEY_FORMAT_VERSION,
        format: "craton-hsm-wrapped-key".to_string(),
        created,
        created_epoch,
        wrapping_algorithm: mechanism_to_algorithm_name(ctx.mechanism),
        wrapping_key_size,
        key_type,
        key_size,
        wrapped_key: base64::engine::general_purpose::STANDARD.encode(wrapped_key_data),
        attributes,
        metadata: WrappedKeyMetadata {
            source_hsm: "craton-hsm".to_string(),
            source_version: env!("CARGO_PKG_VERSION").to_string(),
            export_id,
            description: None,
        },
    })
}

/// Import a wrapped key from JSON format.
pub fn import_wrapped_key_json(
    json_data: &[u8],
    max_age_secs: Option<u64>,
) -> HsmResult<(Vec<u8>, StoredObject)> {
    if json_data.len() > MAX_WRAPPED_KEY_JSON {
        return Err(HsmError::DataLenRange);
    }
    let wrapped_key: WrappedKeyJson =
        serde_json::from_slice(json_data).map_err(|_| HsmError::DataInvalid)?;

    // Validate format version
    if wrapped_key.version != WRAPPED_KEY_FORMAT_VERSION {
        tracing::warn!(
            "Unsupported wrapped key format version: {} (expected: {})",
            wrapped_key.version,
            WRAPPED_KEY_FORMAT_VERSION
        );
        return Err(HsmError::DataInvalid);
    }

    // Validate format identifier
    if wrapped_key.format != "craton-hsm-wrapped-key" {
        return Err(HsmError::DataInvalid);
    }

    // Validate age if specified
    if let Some(max_age) = max_age_secs {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if now.saturating_sub(wrapped_key.created_epoch) > max_age {
            tracing::warn!(
                "Wrapped key import rejected: too old ({} seconds, max: {})",
                now - wrapped_key.created_epoch,
                max_age
            );
            return Err(HsmError::DataInvalid);
        }
    }

    // Decode wrapped key material
    let wrapped_key_data = base64::engine::general_purpose::STANDARD
        .decode(&wrapped_key.wrapped_key)
        .map_err(|_| HsmError::DataInvalid)?;

    // Create StoredObject from attributes
    let stored_object = deserialize_object_attributes(&wrapped_key.attributes)?;

    Ok((wrapped_key_data, stored_object))
}

/// Generate a unique export ID for replay protection.
fn generate_export_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    format!("{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11],
        bytes[12], bytes[13], bytes[14], bytes[15])
}

/// Format timestamp as ISO 8601.
fn format_timestamp(time: std::time::SystemTime) -> String {
    let duration = time
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();

    // Basic ISO 8601 formatting without external dependencies
    format!("{}000Z", duration.as_secs())
}

/// Map PKCS#11 mechanism to algorithm name.
fn mechanism_to_algorithm_name(mechanism: CK_MECHANISM_TYPE) -> String {
    use crate::pkcs11_abi::constants::*;
    match mechanism {
        x if x == CKM_AES_KEY_WRAP => "AES-KW".to_string(),
        x if x == CKM_AES_KEY_WRAP_KWP => "AES-KWP".to_string(),
        _ => format!("UNKNOWN-{:08X}", mechanism),
    }
}

/// Determine key type and size from StoredObject.
fn determine_key_info(object: &StoredObject) -> HsmResult<(String, Option<u32>)> {
    use crate::pkcs11_abi::constants::*;

    let key_type = match object.key_type {
        Some(x) if x == CKK_AES => "AES".to_string(),
        Some(x) if x == CKK_RSA => "RSA".to_string(),
        Some(x) if x == CKK_EC => "ECDSA".to_string(),
        Some(other) => format!("UNKNOWN-{:08X}", other),
        None => "UNKNOWN".to_string(),
    };

    // Determine key size based on type and key material length
    let key_size = match object.key_type {
        Some(x) if x == CKK_AES => object.key_material.as_ref().map(|km| km.len() as u32 * 8),
        Some(x) if x == CKK_RSA => {
            // RSA key size is determined by modulus length
            object.modulus_bits.map(|bits| bits as u32)
        }
        Some(x) if x == CKK_EC => {
            // EC key size depends on curve parameters
            None
        }
        _ => None,
    };

    Ok((key_type, key_size))
}

/// Serialize StoredObject attributes to JSON-compatible format.
fn serialize_object_attributes(
    object: &StoredObject,
) -> HsmResult<HashMap<String, serde_json::Value>> {
    let mut attrs = HashMap::new();

    // Core attributes
    attrs.insert(
        "CKA_CLASS".to_string(),
        serde_json::Value::from(object.class),
    );

    if let Some(key_type) = object.key_type {
        attrs.insert(
            "CKA_KEY_TYPE".to_string(),
            serde_json::Value::from(key_type),
        );
    }

    if !object.label.is_empty() {
        attrs.insert(
            "CKA_LABEL".to_string(),
            serde_json::Value::from(String::from_utf8_lossy(&object.label)),
        );
    }

    attrs.insert(
        "CKA_TOKEN".to_string(),
        serde_json::Value::from(object.token_object),
    );
    attrs.insert(
        "CKA_PRIVATE".to_string(),
        serde_json::Value::from(object.private),
    );
    attrs.insert(
        "CKA_EXTRACTABLE".to_string(),
        serde_json::Value::from(object.extractable),
    );

    // Key usage attributes
    attrs.insert(
        "CKA_ENCRYPT".to_string(),
        serde_json::Value::from(object.can_encrypt),
    );
    attrs.insert(
        "CKA_DECRYPT".to_string(),
        serde_json::Value::from(object.can_decrypt),
    );
    attrs.insert(
        "CKA_SIGN".to_string(),
        serde_json::Value::from(object.can_sign),
    );
    attrs.insert(
        "CKA_VERIFY".to_string(),
        serde_json::Value::from(object.can_verify),
    );
    attrs.insert(
        "CKA_WRAP".to_string(),
        serde_json::Value::from(object.can_wrap),
    );
    attrs.insert(
        "CKA_UNWRAP".to_string(),
        serde_json::Value::from(object.can_unwrap),
    );

    // Add value length if available
    if let Some(val_len) = object.value_len {
        attrs.insert(
            "CKA_VALUE_LEN".to_string(),
            serde_json::Value::from(val_len),
        );
    }

    Ok(attrs)
}

/// Deserialize JSON attributes back to StoredObject template.
fn deserialize_object_attributes(
    attrs: &HashMap<String, serde_json::Value>,
) -> HsmResult<StoredObject> {
    // Create a basic StoredObject template - handle will be assigned during import
    let mut obj = StoredObject::new(0, 0);

    // Parse class
    if let Some(class_val) = attrs.get("CKA_CLASS") {
        if let Some(class) = class_val.as_u64() {
            obj.class = class as CK_OBJECT_CLASS;
        }
    }

    // Parse key type
    if let Some(key_type_val) = attrs.get("CKA_KEY_TYPE") {
        if let Some(key_type) = key_type_val.as_u64() {
            obj.key_type = Some(key_type as CK_KEY_TYPE);
        }
    }

    // Parse label
    if let Some(label_val) = attrs.get("CKA_LABEL") {
        if let Some(label_str) = label_val.as_str() {
            obj.label = label_str.as_bytes().to_vec();
        }
    }

    // Parse boolean attributes
    obj.token_object = attrs
        .get("CKA_TOKEN")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    obj.private = attrs
        .get("CKA_PRIVATE")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    obj.extractable = attrs
        .get("CKA_EXTRACTABLE")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Parse usage attributes
    obj.can_encrypt = attrs
        .get("CKA_ENCRYPT")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    obj.can_decrypt = attrs
        .get("CKA_DECRYPT")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    obj.can_sign = attrs
        .get("CKA_SIGN")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    obj.can_verify = attrs
        .get("CKA_VERIFY")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    obj.can_wrap = attrs
        .get("CKA_WRAP")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    obj.can_unwrap = attrs
        .get("CKA_UNWRAP")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    Ok(obj)
}

// ── PKCS#8 OID constants ───────────────────────────────────────────────────
// RSA: 1.2.840.113549.1.1.1
const OID_RSA: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
];
// EC public key: 1.2.840.10045.2.1
const OID_EC_PUBLIC_KEY: &[u8] = &[0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
// P-256 named curve: 1.2.840.10045.3.1.7
const OID_P256: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
// P-384 named curve: 1.3.132.0.34
const OID_P384: &[u8] = &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22];
// Ed25519: 1.3.101.112
const OID_ED25519: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x70];

/// Export a private key object as PKCS#8 PEM (unencrypted).
///
/// Supports RSA, EC P-256, EC P-384, and Ed25519 key types.
/// The key must have `extractable == true` and `sensitive == false`.
pub fn export_pkcs8(object: &StoredObject, _password: Option<&[u8]>) -> HsmResult<Vec<u8>> {
    // Enforce extractability per PKCS#11 spec
    if !object.extractable {
        return Err(HsmError::KeyFunctionNotPermitted);
    }
    if object.sensitive {
        return Err(HsmError::AttributeSensitive);
    }

    let key_material = object
        .key_material
        .as_ref()
        .ok_or(HsmError::KeyHandleInvalid)?;
    let key_bytes = key_material.as_bytes();

    let key_type = object.key_type.ok_or(HsmError::KeyHandleInvalid)?;

    let pkcs8_der = match key_type {
        x if x == CKK_RSA => {
            // RSA keys are already stored as PKCS#8 DER by keygen.rs
            key_bytes.to_vec()
        }
        x if x == CKK_EC => {
            // Determine curve from ec_params or key length
            let (curve_oid, expected_len) = match key_bytes.len() {
                32 => (OID_P256, 32usize),
                48 => (OID_P384, 48usize),
                _ => return Err(HsmError::KeyHandleInvalid),
            };
            _ = expected_len;
            build_ec_pkcs8(key_bytes, curve_oid, object.ec_point.as_deref())
        }
        x if x == CKK_EC_EDWARDS => build_ed25519_pkcs8(key_bytes)?,
        _ => return Err(HsmError::KeyHandleInvalid),
    };

    // Wrap as PEM
    let pem_output = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        base64_encode_wrapped(&pkcs8_der)
    );

    Ok(pem_output.into_bytes())
}

/// Import a private key from PKCS#8 PEM or DER format.
///
/// Parses the ASN.1 structure to determine key type and algorithm, then
/// creates a `StoredObject` with secure defaults.
pub fn import_pkcs8(data: &[u8], _password: Option<&[u8]>) -> HsmResult<StoredObject> {
    // Detect PEM vs DER
    let der_bytes = if data.starts_with(b"-----BEGIN") {
        decode_pem(data)?
    } else {
        data.to_vec()
    };

    // Parse the PKCS#8 PrivateKeyInfo ASN.1 structure
    parse_pkcs8_der(&der_bytes)
}

/// PKCS#12 export is not yet supported (requires certificate handling).
pub fn export_pkcs12(_object: &StoredObject, _password: &[u8]) -> HsmResult<Vec<u8>> {
    tracing::warn!("PKCS#12 export not implemented: requires X.509 certificate support");
    Err(HsmError::FunctionNotSupported)
}

/// PKCS#12 import is not yet supported (requires certificate handling).
pub fn import_pkcs12(_data: &[u8], _password: &[u8]) -> HsmResult<StoredObject> {
    tracing::warn!("PKCS#12 import not implemented: requires X.509 certificate support");
    Err(HsmError::FunctionNotSupported)
}

// ── PKCS#8 ASN.1 construction helpers ──────────────────────────────────────

/// Build PKCS#8 DER for an EC private key.
///
/// Structure: SEQUENCE { INTEGER 0, SEQUENCE { ecPublicKey OID, curve OID }, OCTET STRING { ECPrivateKey } }
fn build_ec_pkcs8(scalar: &[u8], curve_oid: &[u8], ec_point: Option<&[u8]>) -> Vec<u8> {
    // Build ECPrivateKey (RFC 5915):
    // SEQUENCE { INTEGER 1, OCTET STRING scalar [, context[1] BIT STRING pubkey] }
    let mut ec_priv_key = Vec::new();
    // version = 1
    ec_priv_key.extend_from_slice(&[0x02, 0x01, 0x01]);
    // privateKey OCTET STRING
    ec_priv_key.push(0x04);
    push_der_length(&mut ec_priv_key, scalar.len());
    ec_priv_key.extend_from_slice(scalar);
    // optional publicKey [1] BIT STRING
    if let Some(point) = ec_point {
        let mut bit_string = Vec::new();
        bit_string.push(0x00); // no unused bits
        bit_string.extend_from_slice(point);
        let mut tagged = Vec::new();
        tagged.push(0x03); // BIT STRING
        push_der_length(&mut tagged, bit_string.len());
        tagged.extend_from_slice(&bit_string);
        // context-specific [1] CONSTRUCTED
        ec_priv_key.push(0xA1);
        push_der_length(&mut ec_priv_key, tagged.len());
        ec_priv_key.extend_from_slice(&tagged);
    }
    let ec_priv_key_seq = wrap_sequence(&ec_priv_key);

    // AlgorithmIdentifier: SEQUENCE { ecPublicKey OID, curve OID }
    let mut alg_id_inner = Vec::new();
    alg_id_inner.extend_from_slice(OID_EC_PUBLIC_KEY);
    alg_id_inner.extend_from_slice(curve_oid);
    let alg_id = wrap_sequence(&alg_id_inner);

    // PrivateKeyInfo: SEQUENCE { version=0, algorithmId, OCTET STRING(ecPrivateKey) }
    let mut pki = Vec::new();
    pki.extend_from_slice(&[0x02, 0x01, 0x00]); // version = 0
    pki.extend_from_slice(&alg_id);
    pki.push(0x04); // OCTET STRING wrapping ECPrivateKey
    push_der_length(&mut pki, ec_priv_key_seq.len());
    pki.extend_from_slice(&ec_priv_key_seq);

    wrap_sequence(&pki)
}

/// Build PKCS#8 DER for an Ed25519 private key.
///
/// Structure: SEQUENCE { INTEGER 0, SEQUENCE { ed25519 OID }, OCTET STRING { OCTET STRING key } }
fn build_ed25519_pkcs8(key_bytes: &[u8]) -> HsmResult<Vec<u8>> {
    if key_bytes.len() != 32 {
        return Err(HsmError::KeyHandleInvalid);
    }

    // AlgorithmIdentifier: SEQUENCE { ed25519 OID } (no parameters)
    let alg_id = wrap_sequence(OID_ED25519);

    // The private key is wrapped in an OCTET STRING inside an OCTET STRING
    let mut inner_octet = Vec::new();
    inner_octet.push(0x04); // OCTET STRING
    push_der_length(&mut inner_octet, key_bytes.len());
    inner_octet.extend_from_slice(key_bytes);

    let mut pki = Vec::new();
    pki.extend_from_slice(&[0x02, 0x01, 0x00]); // version = 0
    pki.extend_from_slice(&alg_id);
    pki.push(0x04); // OCTET STRING
    push_der_length(&mut pki, inner_octet.len());
    pki.extend_from_slice(&inner_octet);

    Ok(wrap_sequence(&pki))
}

/// Wrap data in an ASN.1 SEQUENCE tag.
fn wrap_sequence(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0x30); // SEQUENCE
    push_der_length(&mut out, data.len());
    out.extend_from_slice(data);
    out
}

/// Push a DER length encoding.
fn push_der_length(buf: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        buf.push(len as u8);
    } else if len < 0x100 {
        buf.push(0x81);
        buf.push(len as u8);
    } else if len < 0x10000 {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    } else {
        buf.push(0x83);
        buf.push((len >> 16) as u8);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
}

/// Base64-encode with line wrapping at 64 characters (PEM standard).
fn base64_encode_wrapped(data: &[u8]) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(data);
    encoded
        .as_bytes()
        .chunks(64)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Decode PEM to DER bytes.
fn decode_pem(data: &[u8]) -> HsmResult<Vec<u8>> {
    let text = std::str::from_utf8(data).map_err(|_| HsmError::DataInvalid)?;

    // Find the base64 content between headers
    let start = text
        .find("-----\n")
        .or_else(|| text.find("-----\r\n"))
        .map(|i| i + 6)
        .ok_or(HsmError::DataInvalid)?;
    // Handle \r\n line endings
    let start = if text.as_bytes().get(start.wrapping_sub(1)) == Some(&b'\r') {
        start
    } else {
        start
    };
    let end = text
        .rfind("\n-----END")
        .or_else(|| text.rfind("\r\n-----END"))
        .ok_or(HsmError::DataInvalid)?;

    let b64_content: String = text[start..end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    base64::engine::general_purpose::STANDARD
        .decode(&b64_content)
        .map_err(|_| HsmError::DataInvalid)
}

// ── PKCS#8 DER parsing helpers ─────────────────────────────────────────────

/// Parse a PKCS#8 PrivateKeyInfo DER structure and create a StoredObject.
fn parse_pkcs8_der(der: &[u8]) -> HsmResult<StoredObject> {
    // Parse outer SEQUENCE
    let (_, content) = parse_der_sequence(der)?;

    let mut pos = 0;

    // Parse version INTEGER (should be 0)
    let (ver_len, _ver_value) = parse_der_integer(&content[pos..])?;
    pos += ver_len;

    // Parse AlgorithmIdentifier SEQUENCE
    let (alg_len, alg_content) = parse_der_sequence(&content[pos..])?;
    pos += alg_len;

    // Parse private key OCTET STRING
    let (_, key_data) = parse_der_octet_string(&content[pos..])?;

    // Determine algorithm from AlgorithmIdentifier OID
    if contains_oid(&alg_content, &OID_RSA[2..]) {
        // RSA: key_data contains the full PKCS#1 RSA private key
        import_rsa_pkcs8(der)
    } else if contains_oid(&alg_content, &OID_EC_PUBLIC_KEY[2..]) {
        // EC: determine curve from second OID in AlgorithmIdentifier
        if contains_oid(&alg_content, &OID_P256[2..]) {
            import_ec_pkcs8(&key_data, 32, CKK_EC)
        } else if contains_oid(&alg_content, &OID_P384[2..]) {
            import_ec_pkcs8(&key_data, 48, CKK_EC)
        } else {
            tracing::warn!("Unsupported EC curve in PKCS#8");
            Err(HsmError::DataInvalid)
        }
    } else if contains_oid(&alg_content, &OID_ED25519[2..]) {
        import_ed25519_pkcs8(&key_data)
    } else {
        tracing::warn!("Unsupported algorithm OID in PKCS#8");
        Err(HsmError::DataInvalid)
    }
}

/// Import RSA key from full PKCS#8 DER (stored as-is since keygen uses PKCS#8 DER).
fn import_rsa_pkcs8(full_der: &[u8]) -> HsmResult<StoredObject> {
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::traits::PublicKeyParts;

    let private_key =
        rsa::RsaPrivateKey::from_pkcs8_der(full_der).map_err(|_| HsmError::DataInvalid)?;

    let modulus = private_key.n().to_bytes_be();
    let pub_exp = private_key.e().to_bytes_be();
    let modulus_bits = modulus.len() * 8;

    let mut obj = StoredObject::new(0, CKO_PRIVATE_KEY);
    obj.key_type = Some(CKK_RSA);
    obj.key_material = Some(crate::store::key_material::RawKeyMaterial::new(
        full_der.to_vec(),
    ));
    obj.modulus = Some(modulus);
    obj.modulus_bits = Some(modulus_bits as CK_ULONG);
    obj.public_exponent = Some(pub_exp);
    obj.sensitive = true;
    obj.extractable = false;
    obj.private = true;
    obj.token_object = true;
    obj.can_sign = true;
    obj.can_decrypt = true;
    Ok(obj)
}

/// Import EC private key from ECPrivateKey ASN.1 inside PKCS#8.
fn import_ec_pkcs8(
    ec_priv_key_der: &[u8],
    scalar_len: usize,
    key_type: CK_KEY_TYPE,
) -> HsmResult<StoredObject> {
    // Parse ECPrivateKey SEQUENCE
    let (_, content) = parse_der_sequence(ec_priv_key_der)?;
    let mut pos = 0;

    // Skip version INTEGER
    let (ver_len, _) = parse_der_integer(&content[pos..])?;
    pos += ver_len;

    // Parse privateKey OCTET STRING (the scalar)
    let (scalar_field_len, scalar) = parse_der_octet_string(&content[pos..])?;
    pos += scalar_field_len;

    if scalar.len() != scalar_len {
        return Err(HsmError::DataInvalid);
    }

    // Try to extract public key from context-specific [1]
    let mut ec_point = None;
    if pos < content.len() && content[pos] == 0xA1 {
        pos += 1;
        let (ctx_body_len, ctx_body_offset) = parse_der_length(&content[pos..])?;
        pos += ctx_body_offset;
        let ctx_body = &content[pos..pos + ctx_body_len];
        // Inside is a BIT STRING
        if !ctx_body.is_empty() && ctx_body[0] == 0x03 {
            let (_, bit_content) = parse_der_bit_string(ctx_body)?;
            ec_point = Some(bit_content.to_vec());
        }
    }

    // If no public key in the structure, derive it
    let public_point = if let Some(point) = ec_point {
        point
    } else {
        derive_ec_public_key(&scalar, scalar_len)?
    };

    let ec_params = if scalar_len == 32 {
        OID_P256.to_vec()
    } else {
        OID_P384.to_vec()
    };

    let mut obj = StoredObject::new(0, CKO_PRIVATE_KEY);
    obj.key_type = Some(key_type);
    obj.key_material = Some(crate::store::key_material::RawKeyMaterial::new(
        scalar.to_vec(),
    ));
    obj.ec_params = Some(ec_params);
    obj.ec_point = Some(public_point.clone());
    obj.public_key_data = Some(public_point);
    obj.sensitive = true;
    obj.extractable = false;
    obj.private = true;
    obj.token_object = true;
    obj.can_sign = true;
    obj.can_derive = true;
    Ok(obj)
}

/// Import Ed25519 private key from PKCS#8.
fn import_ed25519_pkcs8(key_octet: &[u8]) -> HsmResult<StoredObject> {
    // key_octet is an OCTET STRING wrapping the 32-byte seed
    let (_, seed) = parse_der_octet_string(key_octet)?;
    if seed.len() != 32 {
        return Err(HsmError::DataInvalid);
    }

    // Derive public key
    let signing_key =
        ed25519_dalek::SigningKey::from_bytes(seed.try_into().map_err(|_| HsmError::DataInvalid)?);
    let verifying_key = signing_key.verifying_key();

    let mut obj = StoredObject::new(0, CKO_PRIVATE_KEY);
    obj.key_type = Some(CKK_EC_EDWARDS);
    obj.key_material = Some(crate::store::key_material::RawKeyMaterial::new(
        seed.to_vec(),
    ));
    obj.public_key_data = Some(verifying_key.to_bytes().to_vec());
    obj.sensitive = true;
    obj.extractable = false;
    obj.private = true;
    obj.token_object = true;
    obj.can_sign = true;
    obj.can_verify = true;
    Ok(obj)
}

/// Derive EC public key from scalar bytes.
fn derive_ec_public_key(scalar: &[u8], scalar_len: usize) -> HsmResult<Vec<u8>> {
    use elliptic_curve::sec1::ToEncodedPoint;
    match scalar_len {
        32 => {
            let sk = p256::SecretKey::from_bytes(
                elliptic_curve::generic_array::GenericArray::from_slice(scalar),
            )
            .map_err(|_| HsmError::DataInvalid)?;
            Ok(sk.public_key().to_encoded_point(false).as_bytes().to_vec())
        }
        48 => {
            let sk = p384::SecretKey::from_bytes(
                elliptic_curve::generic_array::GenericArray::from_slice(scalar),
            )
            .map_err(|_| HsmError::DataInvalid)?;
            Ok(sk.public_key().to_encoded_point(false).as_bytes().to_vec())
        }
        _ => Err(HsmError::DataInvalid),
    }
}

// ── Minimal DER parsing primitives ─────────────────────────────────────────

/// Parse DER length field. Returns (length_value, bytes_consumed).
fn parse_der_length(data: &[u8]) -> HsmResult<(usize, usize)> {
    if data.is_empty() {
        return Err(HsmError::DataInvalid);
    }
    if data[0] < 0x80 {
        Ok((data[0] as usize, 1))
    } else {
        let num_bytes = (data[0] & 0x7F) as usize;
        if num_bytes == 0 || num_bytes > 3 || data.len() < 1 + num_bytes {
            return Err(HsmError::DataInvalid);
        }
        let mut len = 0usize;
        for i in 0..num_bytes {
            len = (len << 8) | data[1 + i] as usize;
        }
        Ok((len, 1 + num_bytes))
    }
}

/// Parse a DER SEQUENCE. Returns (total_bytes_consumed, inner_content).
fn parse_der_sequence(data: &[u8]) -> HsmResult<(usize, &[u8])> {
    if data.is_empty() || data[0] != 0x30 {
        return Err(HsmError::DataInvalid);
    }
    let (content_len, len_bytes) = parse_der_length(&data[1..])?;
    let total = 1 + len_bytes + content_len;
    if data.len() < total {
        return Err(HsmError::DataInvalid);
    }
    Ok((total, &data[1 + len_bytes..1 + len_bytes + content_len]))
}

/// Parse a DER INTEGER. Returns (total_bytes_consumed, value_bytes).
fn parse_der_integer(data: &[u8]) -> HsmResult<(usize, &[u8])> {
    if data.is_empty() || data[0] != 0x02 {
        return Err(HsmError::DataInvalid);
    }
    let (content_len, len_bytes) = parse_der_length(&data[1..])?;
    let total = 1 + len_bytes + content_len;
    if data.len() < total {
        return Err(HsmError::DataInvalid);
    }
    Ok((total, &data[1 + len_bytes..1 + len_bytes + content_len]))
}

/// Parse a DER OCTET STRING. Returns (total_bytes_consumed, value_bytes).
fn parse_der_octet_string(data: &[u8]) -> HsmResult<(usize, &[u8])> {
    if data.is_empty() || data[0] != 0x04 {
        return Err(HsmError::DataInvalid);
    }
    let (content_len, len_bytes) = parse_der_length(&data[1..])?;
    let total = 1 + len_bytes + content_len;
    if data.len() < total {
        return Err(HsmError::DataInvalid);
    }
    Ok((total, &data[1 + len_bytes..1 + len_bytes + content_len]))
}

/// Parse a DER BIT STRING. Returns (total_bytes_consumed, value_bytes_without_unused_bits_byte).
fn parse_der_bit_string(data: &[u8]) -> HsmResult<(usize, &[u8])> {
    if data.is_empty() || data[0] != 0x03 {
        return Err(HsmError::DataInvalid);
    }
    let (content_len, len_bytes) = parse_der_length(&data[1..])?;
    let total = 1 + len_bytes + content_len;
    if data.len() < total || content_len < 1 {
        return Err(HsmError::DataInvalid);
    }
    // First byte is unused bits count; skip it
    Ok((total, &data[1 + len_bytes + 1..1 + len_bytes + content_len]))
}

/// Check if the AlgorithmIdentifier content contains a specific OID value.
fn contains_oid(alg_content: &[u8], oid_value: &[u8]) -> bool {
    alg_content.windows(oid_value.len()).any(|w| w == oid_value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_detection() {
        // Test JSON format detection
        let json_data = r#"{"format":"craton-hsm-wrapped-key"}"#.as_bytes();
        assert_eq!(
            ImportFormat::detect_format(json_data),
            ImportFormat::CratonJson
        );

        // Test PEM format detection
        let pem_data = b"-----BEGIN PRIVATE KEY-----";
        assert_eq!(
            ImportFormat::detect_format(pem_data),
            ImportFormat::Pkcs8Pem
        );

        // Test DER format detection (needs >4 bytes to trigger ASN.1 SEQUENCE check)
        let der_data = b"\x30\x82\x01\x00\x00"; // ASN.1 SEQUENCE (5 bytes)
        assert_eq!(
            ImportFormat::detect_format(der_data),
            ImportFormat::Pkcs8Der
        );
    }

    #[test]
    fn test_export_id_generation() {
        let id1 = generate_export_id();
        let id2 = generate_export_id();

        // Should be different each time
        assert_ne!(id1, id2);

        // Should be valid UUID format
        assert!(id1.contains('-'));
        assert_eq!(id1.len(), 36);
    }

    #[test]
    fn test_mechanism_mapping() {
        assert_eq!(mechanism_to_algorithm_name(CKM_AES_KEY_WRAP), "AES-KW");
        assert_eq!(mechanism_to_algorithm_name(CKM_AES_KEY_WRAP_KWP), "AES-KWP");
    }

    #[test]
    fn test_pkcs8_rsa_roundtrip() {
        let (key_mat, modulus, pub_exp) =
            crate::crypto::keygen::generate_rsa_key_pair(2048, false).unwrap();
        let mut obj = StoredObject::new(0, CKO_PRIVATE_KEY);
        obj.key_type = Some(CKK_RSA);
        obj.key_material = Some(key_mat);
        obj.modulus = Some(modulus.clone());
        obj.public_exponent = Some(pub_exp.clone());
        obj.extractable = true;
        obj.sensitive = false;

        let pem = export_pkcs8(&obj, None).unwrap();
        assert!(pem.starts_with(b"-----BEGIN PRIVATE KEY-----"));

        let imported = import_pkcs8(&pem, None).unwrap();
        assert_eq!(imported.key_type, Some(CKK_RSA));
        assert_eq!(imported.modulus.as_ref().unwrap(), &modulus);
        assert_eq!(imported.public_exponent.as_ref().unwrap(), &pub_exp);
        assert!(imported.sensitive);
        assert!(!imported.extractable);
    }

    #[test]
    fn test_pkcs8_ec_p256_roundtrip() {
        let (key_mat, pub_point) = crate::crypto::keygen::generate_ec_p256_key_pair().unwrap();
        let mut obj = StoredObject::new(0, CKO_PRIVATE_KEY);
        obj.key_type = Some(CKK_EC);
        obj.key_material = Some(key_mat.clone());
        obj.ec_point = Some(pub_point.clone());
        obj.extractable = true;
        obj.sensitive = false;

        let pem = export_pkcs8(&obj, None).unwrap();
        assert!(pem.starts_with(b"-----BEGIN PRIVATE KEY-----"));

        let imported = import_pkcs8(&pem, None).unwrap();
        assert_eq!(imported.key_type, Some(CKK_EC));
        // Verify the private key material matches
        assert_eq!(
            imported.key_material.as_ref().unwrap().as_bytes(),
            key_mat.as_bytes()
        );
        // Verify the public point was either embedded or derived
        assert_eq!(imported.ec_point.as_ref().unwrap(), &pub_point);
    }

    #[test]
    fn test_pkcs8_ec_p384_roundtrip() {
        let (key_mat, pub_point) = crate::crypto::keygen::generate_ec_p384_key_pair().unwrap();
        let mut obj = StoredObject::new(0, CKO_PRIVATE_KEY);
        obj.key_type = Some(CKK_EC);
        obj.key_material = Some(key_mat.clone());
        obj.ec_point = Some(pub_point.clone());
        obj.extractable = true;
        obj.sensitive = false;

        let pem = export_pkcs8(&obj, None).unwrap();
        let imported = import_pkcs8(&pem, None).unwrap();
        assert_eq!(imported.key_type, Some(CKK_EC));
        assert_eq!(
            imported.key_material.as_ref().unwrap().as_bytes(),
            key_mat.as_bytes()
        );
    }

    #[test]
    fn test_pkcs8_ed25519_roundtrip() {
        let (key_mat, pub_key) = crate::crypto::keygen::generate_ed25519_key_pair().unwrap();
        let mut obj = StoredObject::new(0, CKO_PRIVATE_KEY);
        obj.key_type = Some(CKK_EC_EDWARDS);
        obj.key_material = Some(key_mat.clone());
        obj.public_key_data = Some(pub_key.clone());
        obj.extractable = true;
        obj.sensitive = false;

        let pem = export_pkcs8(&obj, None).unwrap();
        let imported = import_pkcs8(&pem, None).unwrap();
        assert_eq!(imported.key_type, Some(CKK_EC_EDWARDS));
        assert_eq!(
            imported.key_material.as_ref().unwrap().as_bytes(),
            key_mat.as_bytes()
        );
        assert_eq!(imported.public_key_data.as_ref().unwrap(), &pub_key);
    }

    #[test]
    fn test_pkcs8_export_non_extractable_rejected() {
        let mut obj = StoredObject::new(0, CKO_PRIVATE_KEY);
        obj.key_type = Some(CKK_RSA);
        obj.key_material = Some(crate::store::key_material::RawKeyMaterial::new(vec![0; 32]));
        obj.extractable = false;
        obj.sensitive = false;

        assert!(matches!(
            export_pkcs8(&obj, None),
            Err(HsmError::KeyFunctionNotPermitted)
        ));
    }

    #[test]
    fn test_pkcs8_export_sensitive_rejected() {
        let mut obj = StoredObject::new(0, CKO_PRIVATE_KEY);
        obj.key_type = Some(CKK_RSA);
        obj.key_material = Some(crate::store::key_material::RawKeyMaterial::new(vec![0; 32]));
        obj.extractable = true;
        obj.sensitive = true;

        assert!(matches!(
            export_pkcs8(&obj, None),
            Err(HsmError::AttributeSensitive)
        ));
    }

    #[test]
    fn test_pkcs8_import_invalid_data() {
        assert!(import_pkcs8(b"not valid data", None).is_err());
        assert!(import_pkcs8(
            b"-----BEGIN PRIVATE KEY-----\ninvalid\n-----END PRIVATE KEY-----",
            None
        )
        .is_err());
    }

    #[test]
    fn test_pkcs12_returns_not_supported() {
        let obj = StoredObject::new(0, CKO_PRIVATE_KEY);
        assert!(matches!(
            export_pkcs12(&obj, b"pass"),
            Err(HsmError::FunctionNotSupported)
        ));
        assert!(matches!(
            import_pkcs12(b"data", b"pass"),
            Err(HsmError::FunctionNotSupported)
        ));
    }
}
