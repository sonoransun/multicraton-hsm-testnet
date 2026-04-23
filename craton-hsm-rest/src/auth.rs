// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! JWT-on-mTLS authentication middleware.
//!
//! Two-factor request authorization:
//! 1. **mTLS** — the client presents a TLS certificate signed by the
//!    configured client CA. The server extracts the cert's SPKI SHA-256.
//! 2. **JWT** — the `Authorization: Bearer …` header carries a signed JWT.
//!    Verification checks:
//!    - signature via JWKS
//!    - `iss` / `aud` / `exp` / `nbf`
//!    - when RFC 8705 is enabled, `cnf["x5t#S256"]` equals the cert SPKI hash
//!    - the requested route's scope is present in the `scope` claim
//!
//! Scopes used by this crate:
//!
//! | Scope   | Grants                                                         |
//! |---------|----------------------------------------------------------------|
//! | `sign`  | `POST /v1/keys/{h}/sign`, `POST /v1/hybrid/compose-sign`, batch |
//! | `verify`| `POST /v1/keys/{h}/verify`, `POST /v1/hybrid/compose-verify`    |
//! | `kem`   | `POST /v1/kems/{h}/encapsulate`, `/decapsulate`                 |
//! | `wrap`  | `POST /v1/wrap`, `POST /v1/unwrap`                              |
//! | `admin` | keygen, rotate, destroy, session/token admin                    |
//! | `attest`| `POST /v1/attest`                                               |

use crate::errors::RestError;
use base64::Engine;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Decoded JWT claims we care about.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    #[serde(default)]
    pub aud: Option<String>,
    pub exp: i64,
    #[serde(default)]
    pub nbf: Option<i64>,
    /// Space-separated scope list (OAuth 2.0 convention).
    #[serde(default)]
    pub scope: String,
    /// RFC 8705 — client cert confirmation key. `cnf["x5t#S256"]` is the
    /// base64url-encoded SHA-256 hash of the client cert's SubjectPublicKeyInfo.
    #[serde(default)]
    pub cnf: Option<Confirmation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Confirmation {
    /// Base64url (unpadded) of SHA-256(SPKI(clientCert)).
    #[serde(rename = "x5t#S256", default)]
    pub x5t_s256: Option<String>,
}

/// Extracted identity passed to handlers via a tower extension.
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub subject: String,
    pub scopes: HashSet<String>,
    /// SHA-256 of the client cert SPKI, base64url without padding, or None
    /// when mTLS wasn't presented (dev path).
    pub client_spki_b64: Option<String>,
}

impl AuthContext {
    /// Return true iff the authenticated principal has `scope`.
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.contains(scope)
    }

    /// `Err(RestError::Forbidden)` if the scope is missing.
    pub fn require_scope(&self, scope: &'static str) -> Result<(), RestError> {
        if self.has_scope(scope) {
            Ok(())
        } else {
            Err(RestError::Forbidden(scope))
        }
    }
}

/// Compute the base64url-no-pad SHA-256 of raw DER SubjectPublicKeyInfo bytes.
/// Used both when accepting a client cert (server side) and when issuers
/// produce the `cnf.x5t#S256` claim (off-line tooling).
pub fn spki_sha256_b64url(spki_der: &[u8]) -> String {
    let digest = Sha256::digest(spki_der);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

/// Verify the RFC 8705 binding: `jwt_cnf_thumbprint == SHA-256(spki)`.
pub fn check_cert_binding(claims: &Claims, client_spki_b64: &str) -> Result<(), RestError> {
    let Some(cnf) = claims.cnf.as_ref() else {
        return Err(RestError::Unauthorized(
            "JWT missing cnf (x5t#S256) claim — required by RFC 8705 when mTLS binding is enabled",
        ));
    };
    let Some(tp) = cnf.x5t_s256.as_deref() else {
        return Err(RestError::Unauthorized("JWT cnf has no x5t#S256 thumbprint"));
    };
    // Constant-time comparison to avoid leaking byte positions on mismatch.
    use subtle::ConstantTimeEq;
    let eq: bool = tp.as_bytes().ct_eq(client_spki_b64.as_bytes()).into();
    if !eq {
        return Err(RestError::Unauthorized(
            "JWT cnf.x5t#S256 does not match client certificate SPKI hash",
        ));
    }
    Ok(())
}

/// Parse a space-delimited OAuth scope claim into a HashSet.
pub fn parse_scopes(scope: &str) -> HashSet<String> {
    scope.split_ascii_whitespace().map(|s| s.to_string()).collect()
}

// ============================================================================
// JWKS cache + JWT verification
// ============================================================================

/// Minimal JWKS entry — one JSON Web Key.
///
/// We only store fields we can actually verify against today. RSA and
/// OKP (Ed25519) and EC (P-256) keys cover every issuer we expect.
#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    pub kty: String,
    #[serde(default)]
    pub kid: Option<String>,
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(default)]
    pub r#use: Option<String>,
    // RSA public key (base64url-unpadded)
    #[serde(default)]
    pub n: Option<String>,
    #[serde(default)]
    pub e: Option<String>,
    // EC public key (base64url-unpadded)
    #[serde(default)]
    pub crv: Option<String>,
    #[serde(default)]
    pub x: Option<String>,
    #[serde(default)]
    pub y: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

/// In-memory JWKS cache.
///
/// Keys are indexed by `kid`; when a JWT header lacks `kid`, the first key
/// whose `kty`+`alg` match the token is used.
pub struct JwksCache {
    keys_by_kid: RwLock<HashMap<String, DecodingKey>>,
    /// Fallback keys keyed by algorithm when a JWT header lacks `kid`.
    keys_by_alg: RwLock<HashMap<Algorithm, Vec<DecodingKey>>>,
    /// Last refresh instant (for time-based invalidation of URL-sourced JWKS).
    last_refresh: RwLock<Instant>,
}

impl Default for JwksCache {
    fn default() -> Self {
        Self {
            keys_by_kid: RwLock::new(HashMap::new()),
            keys_by_alg: RwLock::new(HashMap::new()),
            last_refresh: RwLock::new(Instant::now()),
        }
    }
}

impl JwksCache {
    /// Load a JWKS JSON document into the cache, replacing any existing keys.
    pub async fn load_from_json(&self, json: &[u8]) -> Result<(), RestError> {
        let set: JwkSet = serde_json::from_slice(json)
            .map_err(|e| RestError::BadRequest(format!("invalid JWKS JSON: {e}")))?;

        let mut by_kid: HashMap<String, DecodingKey> = HashMap::new();
        let mut by_alg: HashMap<Algorithm, Vec<DecodingKey>> = HashMap::new();

        for jwk in set.keys {
            let (alg, key) = match jwk_to_decoding_key(&jwk) {
                Some(pair) => pair,
                None => continue, // unsupported kty/alg — skip silently
            };
            if let Some(kid) = jwk.kid {
                by_kid.insert(kid, key.clone());
            }
            by_alg.entry(alg).or_default().push(key);
        }

        *self.keys_by_kid.write().await = by_kid;
        *self.keys_by_alg.write().await = by_alg;
        *self.last_refresh.write().await = Instant::now();
        Ok(())
    }

    /// Load a JWKS from a local file path.
    pub async fn load_from_file(&self, path: &std::path::Path) -> Result<(), RestError> {
        let bytes = std::fs::read(path)
            .map_err(|e| RestError::BadRequest(format!("JWKS file read: {e}")))?;
        self.load_from_json(&bytes).await
    }

    /// Time since the last successful refresh.
    pub async fn age(&self) -> Duration {
        self.last_refresh.read().await.elapsed()
    }

    /// Look up a verifying key by `kid`, or fall back to any key matching
    /// `alg` if no kid was specified on the token.
    async fn select_key(&self, kid: Option<&str>, alg: Algorithm) -> Option<DecodingKey> {
        if let Some(id) = kid {
            if let Some(k) = self.keys_by_kid.read().await.get(id) {
                return Some(k.clone());
            }
        }
        self.keys_by_alg
            .read()
            .await
            .get(&alg)
            .and_then(|v| v.first().cloned())
    }
}

/// Convert a JWK into a (Algorithm, DecodingKey) pair. Returns None for
/// unsupported key types — we deliberately reject anything we can't verify
/// rather than trying to silently downgrade.
fn jwk_to_decoding_key(jwk: &Jwk) -> Option<(Algorithm, DecodingKey)> {
    match jwk.kty.as_str() {
        "RSA" => {
            let n = jwk.n.as_deref()?;
            let e = jwk.e.as_deref()?;
            let alg = match jwk.alg.as_deref() {
                Some("RS256") | None => Algorithm::RS256,
                Some("RS384") => Algorithm::RS384,
                Some("RS512") => Algorithm::RS512,
                Some("PS256") => Algorithm::PS256,
                Some("PS384") => Algorithm::PS384,
                Some("PS512") => Algorithm::PS512,
                _ => return None,
            };
            let key = DecodingKey::from_rsa_components(n, e).ok()?;
            Some((alg, key))
        }
        "EC" => {
            let x = jwk.x.as_deref()?;
            let y = jwk.y.as_deref()?;
            let alg = match jwk.alg.as_deref() {
                Some("ES256") | None => Algorithm::ES256,
                Some("ES384") => Algorithm::ES384,
                _ => return None,
            };
            let key = DecodingKey::from_ec_components(x, y).ok()?;
            Some((alg, key))
        }
        "OKP" => {
            // Ed25519 JWKs carry `x` (the raw 32-byte public key, base64url).
            let x = jwk.x.as_deref()?;
            let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(x)
                .ok()?;
            let key = DecodingKey::from_ed_der(&raw);
            Some((Algorithm::EdDSA, key))
        }
        _ => None,
    }
}

/// Verify a Bearer JWT against the cache, enforcing issuer + audience +
/// expiry + leeway. Returns the decoded Claims on success.
///
/// This is intentionally transport-agnostic; the middleware separately
/// enforces RFC 8705 cert-binding via [`check_cert_binding`] once it has
/// the client-cert SPKI from the TLS handshake.
pub async fn verify_jwt(
    bearer: &str,
    jwks: &JwksCache,
    expected_issuer: &str,
    expected_audience: Option<&str>,
    leeway_seconds: u64,
) -> Result<Claims, RestError> {
    // Decode the header (unverified) to pick the right key + algorithm.
    let header = jsonwebtoken::decode_header(bearer)
        .map_err(|_| RestError::Unauthorized("JWT header malformed"))?;
    let alg = header.alg;
    let key = jwks
        .select_key(header.kid.as_deref(), alg)
        .await
        .ok_or(RestError::Unauthorized("no JWKS entry matches JWT kid/alg"))?;

    let mut v = Validation::new(alg);
    v.leeway = leeway_seconds;
    v.set_issuer(&[expected_issuer]);
    if let Some(aud) = expected_audience {
        v.set_audience(&[aud]);
    } else {
        v.validate_aud = false;
    }

    let data = jsonwebtoken::decode::<Claims>(bearer, &key, &v)
        .map_err(|e| RestError::Unauthorized(match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => "JWT expired",
            jsonwebtoken::errors::ErrorKind::InvalidIssuer => "JWT issuer mismatch",
            jsonwebtoken::errors::ErrorKind::InvalidAudience => "JWT audience mismatch",
            jsonwebtoken::errors::ErrorKind::InvalidSignature => "JWT signature invalid",
            _ => "JWT validation failed",
        }))?;

    Ok(data.claims)
}

/// Build an [`AuthContext`] from a verified claims set, optionally binding
/// to a presented mTLS client-cert SPKI hash per RFC 8705.
pub fn build_auth_context(
    claims: Claims,
    client_spki_b64: Option<String>,
    require_cert_binding: bool,
) -> Result<AuthContext, RestError> {
    if require_cert_binding {
        let spki = client_spki_b64
            .as_deref()
            .ok_or(RestError::Unauthorized("mTLS client cert required"))?;
        check_cert_binding(&claims, spki)?;
    }
    Ok(AuthContext {
        subject: claims.sub,
        scopes: parse_scopes(&claims.scope),
        client_spki_b64,
    })
}

/// Arc alias — handy for sharing the cache across axum handlers.
pub type SharedJwks = Arc<JwksCache>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spki_hash_round_trip() {
        // Any 32-byte input; we just confirm the hash function's base64url
        // output is stable and the comparison checker matches itself.
        let spki = vec![0xAAu8; 64];
        let b64 = spki_sha256_b64url(&spki);
        let claims = Claims {
            iss: "x".into(),
            sub: "y".into(),
            aud: None,
            exp: 9_999_999_999,
            nbf: None,
            scope: "sign kem".into(),
            cnf: Some(Confirmation { x5t_s256: Some(b64.clone()) }),
        };
        check_cert_binding(&claims, &b64).unwrap();

        // Mismatch rejected.
        let wrong = spki_sha256_b64url(&[0xBBu8; 64]);
        assert!(check_cert_binding(&claims, &wrong).is_err());
    }

    #[test]
    fn scopes_parse_correctly() {
        let s = parse_scopes("sign kem wrap admin");
        assert!(s.contains("sign"));
        assert!(s.contains("admin"));
        assert!(!s.contains("attest"));
    }

    #[test]
    fn missing_cnf_is_rejected() {
        let claims = Claims {
            iss: "x".into(),
            sub: "y".into(),
            aud: None,
            exp: 9_999_999_999,
            nbf: None,
            scope: "sign".into(),
            cnf: None,
        };
        assert!(check_cert_binding(&claims, "anything").is_err());
    }
}
