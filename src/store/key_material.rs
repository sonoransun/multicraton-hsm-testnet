// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
use crate::crypto::mlock;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use zeroize::Zeroize;

/// All raw key bytes must be wrapped in this type to guarantee:
/// 1. Memory is locked (mlock/VirtualLock) to prevent swapping to disk
/// 2. Memory is zeroed when the value is dropped (ZeroizeOnDrop)
/// 3. Key bytes are never printed in Debug output
///
/// Internally uses `Box<[u8]>` instead of `Vec<u8>` to prevent reallocation.
/// A `Vec` can silently reallocate during growth (e.g. serde deserialization),
/// leaving unzeroed copies of key material in freed heap pages.  `Box<[u8]>`
/// has a fixed size and never reallocates, so the only copy of key bytes is
/// the one we control and zeroize on drop.
pub struct RawKeyMaterial(Box<[u8]>);

impl RawKeyMaterial {
    pub fn new(mut data: Vec<u8>) -> Self {
        // If the Vec has excess capacity, into_boxed_slice() will reallocate
        // (shrink), leaving unzeroized key bytes in the freed heap page.
        // Pre-shrink to exact capacity so into_boxed_slice() is a no-op.
        // Even after shrinking, the old allocation may contain key bytes,
        // so we must accept this as a best-effort measure — callers should
        // prefer passing Vecs with exact capacity when possible.
        if data.capacity() != data.len() {
            // Copy into an exact-capacity Vec manually so we can zeroize the original
            let mut exact = Vec::with_capacity(data.len());
            exact.extend_from_slice(&data);
            data.zeroize();
            data = exact;
        }
        let boxed = data.into_boxed_slice();
        if !boxed.is_empty() {
            // Best-effort: lock key material into physical memory.
            // Failure is non-fatal (may lack privileges for large buffers).
            if let Err(e) = mlock::mlock_buffer(boxed.as_ptr(), boxed.len()) {
                tracing::warn!("mlock failed for {} byte key buffer: {}", boxed.len(), e);
            }
        }
        Self(boxed)
    }

    /// Create a `RawKeyMaterial` with strict mlock enforcement.
    /// Returns an error if the memory cannot be locked into physical RAM.
    /// Use this in production HSM deployments where key material must
    /// never be swapped to disk under any circumstances.
    pub fn new_strict(mut data: Vec<u8>) -> Result<Self, std::io::Error> {
        if data.capacity() != data.len() {
            let mut exact = Vec::with_capacity(data.len());
            exact.extend_from_slice(&data);
            data.zeroize();
            data = exact;
        }
        let boxed = data.into_boxed_slice();
        if !boxed.is_empty() {
            mlock::mlock_buffer(boxed.as_ptr(), boxed.len())?;
        }
        Ok(Self(boxed))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Clone for RawKeyMaterial {
    fn clone(&self) -> Self {
        tracing::debug!("Cloning RawKeyMaterial — ensure this duplication is intentional");
        // Clone into a Vec with exact capacity, then convert to Box<[u8]>
        // via new() — no reallocation occurs.
        Self::new(self.0.to_vec())
    }
}

impl Drop for RawKeyMaterial {
    fn drop(&mut self) {
        if !self.0.is_empty() {
            // Zeroize before unlocking, so swap never sees key bytes
            self.0.zeroize();
            // Unlock the (now-zeroed) pages
            let _ = mlock::munlock_buffer(self.0.as_ptr(), self.0.len());
        }
    }
}

/// Custom Debug: never log key bytes
impl fmt::Debug for RawKeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("RawKeyMaterial")
            .field("length", &self.0.len())
            .field("data", &"[REDACTED]")
            .finish()
    }
}

/// Custom Serialize: serialize the raw bytes (they will be encrypted by EncryptedStore).
impl Serialize for RawKeyMaterial {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

/// Custom Deserialize: reconstruct RawKeyMaterial with mlock.
/// Deserializes into a temporary Vec, then immediately converts to Box<[u8]>
/// via `new()` — minimizing the window where a Vec could reallocate.
impl<'de> Deserialize<'de> for RawKeyMaterial {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        Ok(RawKeyMaterial::new(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_creates_correct_length() {
        let km = RawKeyMaterial::new(vec![0x42; 32]);
        assert_eq!(km.len(), 32);
        assert_eq!(km.as_bytes(), &[0x42; 32]);
    }

    #[test]
    fn test_debug_redacts() {
        let km = RawKeyMaterial::new(vec![0xFF; 16]);
        let debug = format!("{:?}", km);
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("255")); // should not contain raw byte values
        assert!(!debug.contains("0xff"));
    }

    #[test]
    fn test_clone_produces_independent_copy() {
        let km = RawKeyMaterial::new(vec![1, 2, 3, 4]);
        let cloned = km.clone();
        assert_eq!(km.as_bytes(), cloned.as_bytes());
        assert_eq!(km.len(), cloned.len());
    }

    #[test]
    fn test_is_empty() {
        assert!(RawKeyMaterial::new(vec![]).is_empty());
        assert!(!RawKeyMaterial::new(vec![1]).is_empty());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let original = RawKeyMaterial::new(vec![10, 20, 30, 40, 50]);
        let serialized = serde_json::to_vec(&original).unwrap();
        let deserialized: RawKeyMaterial = serde_json::from_slice(&serialized).unwrap();
        assert_eq!(original.as_bytes(), deserialized.as_bytes());
    }

    #[test]
    fn test_excess_capacity_handled() {
        let mut data = Vec::with_capacity(1024);
        data.extend_from_slice(&[0xAB; 32]);
        assert!(data.capacity() > data.len());
        let km = RawKeyMaterial::new(data);
        assert_eq!(km.len(), 32);
        assert_eq!(km.as_bytes(), &[0xAB; 32]);
    }
}
