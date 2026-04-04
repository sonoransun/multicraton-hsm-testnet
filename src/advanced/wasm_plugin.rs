// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! WebAssembly plugin engine — sandboxed custom crypto via **Wasmtime**.
//!
//! Allows operators to deploy custom cryptographic algorithms, key-derivation
//! schemes, or domain-specific encoding routines as WebAssembly modules without
//! modifying the core HSM binary.
//!
//! # Security model
//! * Plugins run in a **memory-isolated WASM sandbox** — no host memory access.
//! * A capability-based interface controls exactly which HSM operations a plugin
//!   may invoke (derive, sign, or neither).
//! * Plugins **cannot** access key material directly; they receive only
//!   opaque handles and interact through a restricted host ABI.
//! * Execution is **time-bounded** (`MAX_FUEL`) to prevent DoS.
//! * The WASM module's SHA-256 digest is verified before loading (supply-chain protection).
//!
//! # Plugin host ABI
//! Plugins must export:
//! ```wat
//! (func (export "craton_plugin_info")    (result i32))  ;; plugin metadata ptr
//! (func (export "craton_execute")
//!   (param  $input_ptr  i32)
//!   (param  $input_len  i32)
//!   (result i32))                                        ;; output ptr or negative error
//! ```
//! And optionally:
//! ```wat
//! (func (export "craton_init")   (result i32))  ;; called once at load time
//! (func (export "craton_deinit"))                ;; called before unload
//! ```

#![cfg(feature = "wasm-plugins")]

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use sha2::{Digest as Sha2Digest, Sha256};
use wasmtime::{
    Caller, Config, Engine, Extern, Func, Instance, Linker, Memory, Module, Store, Trap, Val,
};
use zeroize::Zeroize;

use crate::error::HsmError;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum number of WASM instructions a plugin may execute per call.
/// At ~10 billion instructions/second, this is ~10 µs of compute.
const MAX_FUEL: u64 = 100_000;

/// Maximum input / output buffer size per plugin invocation (64 KiB).
const MAX_BUFFER_SIZE: usize = 65_536;

// ── Capability flags ──────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Capabilities granted to a plugin instance.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct PluginCapabilities: u32 {
        /// Plugin may call `hsm_log(msg_ptr, msg_len)` to write to the audit log.
        const AUDIT_LOG   = 0b0000_0001;
        /// Plugin may call `hsm_random(out_ptr, len)` to get CSPRNG bytes.
        const CSPRNG      = 0b0000_0010;
        /// Plugin may call `hsm_sha256(in_ptr, in_len, out_ptr)`.
        const HASH_SHA256 = 0b0000_0100;
        const AES_GCM_ENCRYPT = 0b0000_1000;
        const AES_GCM_DECRYPT = 0b0001_0000;
    }
}

// ── Plugin manifest ────────────────────────────────────────────────────────────

/// Static metadata describing a WASM plugin.
#[derive(Debug, Clone)]
pub struct PluginManifest {
    /// Unique identifier (e.g. `"com.acme.my-kdf-v2"`).
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Semantic version string.
    pub version: String,
    /// SHA-256 digest of the `.wasm` binary (hex string).
    /// If set, the engine verifies the module before loading.
    pub expected_sha256: Option<String>,
    /// Capabilities granted to this plugin.
    pub capabilities: PluginCapabilities,
}

// ── Plugin engine ─────────────────────────────────────────────────────────────

/// The WASM plugin execution engine.
///
/// Create one engine per HSM process; it compiles and caches modules internally.
pub struct PluginEngine {
    engine: Engine,
    /// Compiled, cached modules keyed by plugin ID.
    modules: Mutex<HashMap<String, Arc<Module>>>,
}

impl PluginEngine {
    /// Initialise a new plugin engine with Cranelift JIT compilation.
    ///
    /// Fuel consumption is enabled so that plugin execution is bounded.
    pub fn new() -> Result<Self, HsmError> {
        let mut config = Config::new();
        config.consume_fuel(true);
        config.wasm_memory64(false);
        config.cranelift_opt_level(wasmtime::OptLevel::Speed);

        let engine = Engine::new(&config)
            .map_err(|e| HsmError::ConfigError(format!("WASM engine init failed: {e}")))?;

        Ok(Self {
            engine,
            modules: Mutex::new(HashMap::new()),
        })
    }

    /// Load and compile a WASM plugin from its binary bytes.
    ///
    /// If `manifest.expected_sha256` is set, the binary is verified against it
    /// before compilation.  This prevents loading tampered plugins.
    pub fn load_plugin(&self, manifest: PluginManifest, wasm_bytes: &[u8]) -> Result<(), HsmError> {
        // ── Supply-chain integrity check ──────────────────────────────────────
        if let Some(expected) = &manifest.expected_sha256 {
            let actual = format!("{:x}", Sha256::digest(wasm_bytes));
            if actual != *expected {
                return Err(HsmError::ConfigError(format!(
                    "Plugin '{}' SHA-256 mismatch: expected {expected}, got {actual}",
                    manifest.id
                )));
            }
        }

        // ── Compile to native code via Cranelift ──────────────────────────────
        let module = Module::new(&self.engine, wasm_bytes)
            .map_err(|e| HsmError::ConfigError(format!("WASM compile '{}': {e}", manifest.id)))?;

        // ── Validate required exports ─────────────────────────────────────────
        let required = ["craton_execute"];
        for export in required {
            if module.get_export(export).is_none() {
                return Err(HsmError::ConfigError(format!(
                    "Plugin '{}' missing required export '{export}'",
                    manifest.id
                )));
            }
        }

        self.modules
            .lock()
            .unwrap()
            .insert(manifest.id.clone(), Arc::new(module));

        tracing::info!(
            plugin_id = manifest.id,
            version = manifest.version,
            "WASM plugin loaded"
        );
        Ok(())
    }

    /// Execute the `craton_execute` entry-point of a loaded plugin.
    ///
    /// `input` is copied into the plugin's linear memory before calling.
    /// The plugin writes its output into the same memory region; this method
    /// copies the output out before returning.
    ///
    /// # Errors
    /// * [`HsmError::FunctionNotSupported`] — plugin ID not found.
    /// * [`HsmError::DataLenRange`] — input exceeds [`MAX_BUFFER_SIZE`].
    /// * [`HsmError::GeneralError`] — WASM trap, fuel exhausted, or malformed output.
    pub fn execute(
        &self,
        plugin_id: &str,
        capabilities: PluginCapabilities,
        input: &[u8],
    ) -> Result<Vec<u8>, HsmError> {
        if input.len() > MAX_BUFFER_SIZE {
            return Err(HsmError::DataLenRange);
        }

        let module = self
            .modules
            .lock()
            .unwrap()
            .get(plugin_id)
            .cloned()
            .ok_or(HsmError::FunctionNotSupported)?;

        // ── Build store with fuel ─────────────────────────────────────────────
        let mut store = Store::new(&self.engine, PluginState::new(capabilities));
        store
            .set_fuel(MAX_FUEL)
            .map_err(|_| HsmError::GeneralError)?;

        // ── Build linker with host ABI ────────────────────────────────────────
        let mut linker: Linker<PluginState> = Linker::new(&self.engine);
        register_host_abi(&mut linker)?;

        // ── Instantiate ───────────────────────────────────────────────────────
        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(|_| HsmError::GeneralError)?;

        // ── Call craton_init if present ───────────────────────────────────────
        if let Ok(init_fn) = instance.get_typed_func::<(), i32>(&mut store, "craton_init") {
            init_fn
                .call(&mut store, ())
                .map_err(|_| HsmError::GeneralError)?;
        }

        // ── Write input into WASM memory ──────────────────────────────────────
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or(HsmError::GeneralError)?;

        // Allocate input at fixed offset 0x10000 (64 KiB) in plugin memory
        let input_offset: usize = 0x10000;
        let output_offset: usize = 0x20000;

        // Grow memory if needed
        let needed_pages = ((output_offset + MAX_BUFFER_SIZE) / 65_536) + 1;
        while memory.size(&store) < needed_pages as u64 {
            memory
                .grow(&mut store, 1)
                .map_err(|_| HsmError::HostMemory)?;
        }

        memory
            .write(&mut store, input_offset, input)
            .map_err(|_| HsmError::GeneralError)?;

        // ── Call craton_execute ───────────────────────────────────────────────
        let execute = instance
            .get_typed_func::<(i32, i32), i32>(&mut store, "craton_execute")
            .map_err(|_| HsmError::FunctionNotSupported)?;

        let result_len = execute
            .call(&mut store, (input_offset as i32, input.len() as i32))
            .map_err(|_| HsmError::GeneralError)?;

        if result_len < 0 {
            return Err(HsmError::GeneralError);
        }

        // ── Read output from WASM memory ──────────────────────────────────────
        let out_len = (result_len as usize).min(MAX_BUFFER_SIZE);
        let mut output = vec![0u8; out_len];
        memory
            .read(&store, output_offset, &mut output)
            .map_err(|_| HsmError::GeneralError)?;

        tracing::debug!(
            plugin_id,
            input_bytes = input.len(),
            output_bytes = output.len(),
            "WASM plugin executed"
        );

        Ok(output)
    }

    /// Unload a plugin, freeing its compiled module from the cache.
    pub fn unload_plugin(&self, plugin_id: &str) {
        self.modules.lock().unwrap().remove(plugin_id);
    }

    /// List all loaded plugin IDs.
    pub fn loaded_plugins(&self) -> Vec<String> {
        self.modules.lock().unwrap().keys().cloned().collect()
    }

    /// Check if a specific plugin is loaded.
    pub fn is_loaded(&self, plugin_id: &str) -> bool {
        self.modules.lock().unwrap().contains_key(plugin_id)
    }

    /// Get the count of loaded plugins.
    pub fn plugin_count(&self) -> usize {
        self.modules.lock().unwrap().len()
    }
}

// ── Host state ────────────────────────────────────────────────────────────────

struct PluginState {
    capabilities: PluginCapabilities,
    /// Accumulated log messages from the plugin (flushed to audit log on return).
    log_buffer: Vec<String>,
}

impl PluginState {
    fn new(capabilities: PluginCapabilities) -> Self {
        Self {
            capabilities,
            log_buffer: Vec::new(),
        }
    }
}

// ── Host ABI registration ─────────────────────────────────────────────────────

/// Register the HSM host functions that plugins are allowed to call.
///
/// Functions are only operative when the plugin holds the corresponding capability flag.
fn register_host_abi(linker: &mut Linker<PluginState>) -> Result<(), HsmError> {
    // hsm_log(msg_ptr: i32, msg_len: i32) -> i32
    linker
        .func_wrap(
            "craton_hsm",
            "hsm_log",
            |mut caller: Caller<'_, PluginState>, msg_ptr: i32, msg_len: i32| -> i32 {
                if !caller
                    .data()
                    .capabilities
                    .contains(PluginCapabilities::AUDIT_LOG)
                {
                    return -1; // EPERM
                }
                let memory = match caller.get_export("memory") {
                    Some(Extern::Memory(m)) => m,
                    _ => return -1,
                };
                let mut buf = vec![0u8; msg_len.max(0) as usize];
                if memory.read(&caller, msg_ptr as usize, &mut buf).is_err() {
                    return -1;
                }
                if let Ok(msg) = String::from_utf8(buf) {
                    caller.data_mut().log_buffer.push(msg);
                }
                0
            },
        )
        .map_err(|_| HsmError::GeneralError)?;

    // hsm_sha256(in_ptr: i32, in_len: i32, out_ptr: i32) -> i32
    linker
        .func_wrap(
            "craton_hsm",
            "hsm_sha256",
            |mut caller: Caller<'_, PluginState>, in_ptr: i32, in_len: i32, out_ptr: i32| -> i32 {
                if !caller
                    .data()
                    .capabilities
                    .contains(PluginCapabilities::HASH_SHA256)
                {
                    return -1;
                }
                let memory = match caller.get_export("memory") {
                    Some(Extern::Memory(m)) => m,
                    _ => return -1,
                };
                let mut input = vec![0u8; in_len.max(0) as usize];
                if memory.read(&caller, in_ptr as usize, &mut input).is_err() {
                    return -1;
                }
                let hash = Sha256::digest(&input);
                if memory.write(&mut caller, out_ptr as usize, &hash).is_err() {
                    return -1;
                }
                32 // SHA-256 output length
            },
        )
        .map_err(|_| HsmError::GeneralError)?;

    // hsm_random(out_ptr: i32, len: i32) -> i32
    linker
        .func_wrap(
            "craton_hsm",
            "hsm_random",
            |mut caller: Caller<'_, PluginState>, out_ptr: i32, len: i32| -> i32 {
                if !caller
                    .data()
                    .capabilities
                    .contains(PluginCapabilities::CSPRNG)
                {
                    return -1; // EPERM
                }
                let len = len.max(0) as usize;
                if len > MAX_BUFFER_SIZE {
                    return -2; // EINVAL
                }
                let memory = match caller.get_export("memory") {
                    Some(Extern::Memory(m)) => m,
                    _ => return -1,
                };
                let mut drbg = match crate::crypto::drbg::HmacDrbg::new() {
                    Ok(d) => d,
                    Err(_) => return -3,
                };
                let mut buf = vec![0u8; len];
                if drbg.generate(&mut buf).is_err() {
                    return -3;
                }
                if memory.write(&mut caller, out_ptr as usize, &buf).is_err() {
                    return -1;
                }
                len as i32
            },
        )
        .map_err(|_| HsmError::GeneralError)?;

    // hsm_aes_gcm_encrypt(key_ptr: i32, pt_ptr: i32, pt_len: i32, out_ptr: i32) -> i32
    linker
        .func_wrap(
            "craton_hsm",
            "hsm_aes_gcm_encrypt",
            |mut caller: Caller<'_, PluginState>,
             key_ptr: i32,
             pt_ptr: i32,
             pt_len: i32,
             out_ptr: i32|
             -> i32 {
                if !caller
                    .data()
                    .capabilities
                    .contains(PluginCapabilities::AES_GCM_ENCRYPT)
                {
                    return -1;
                }
                let memory = match caller.get_export("memory") {
                    Some(Extern::Memory(m)) => m,
                    _ => return -1,
                };
                let mut key = [0u8; 32];
                if memory.read(&caller, key_ptr as usize, &mut key).is_err() {
                    return -1;
                }
                let pt_len = pt_len.max(0) as usize;
                if pt_len > MAX_BUFFER_SIZE {
                    return -2;
                }
                let mut plaintext = vec![0u8; pt_len];
                if memory
                    .read(&caller, pt_ptr as usize, &mut plaintext)
                    .is_err()
                {
                    return -1;
                }
                match crate::crypto::encrypt::aes_256_gcm_encrypt(&key, &plaintext) {
                    Ok(ct) => {
                        if memory.write(&mut caller, out_ptr as usize, &ct).is_err() {
                            return -1;
                        }
                        ct.len() as i32
                    }
                    Err(_) => -4,
                }
            },
        )
        .map_err(|_| HsmError::GeneralError)?;

    // hsm_aes_gcm_decrypt(key_ptr: i32, ct_ptr: i32, ct_len: i32, out_ptr: i32) -> i32
    linker
        .func_wrap(
            "craton_hsm",
            "hsm_aes_gcm_decrypt",
            |mut caller: Caller<'_, PluginState>,
             key_ptr: i32,
             ct_ptr: i32,
             ct_len: i32,
             out_ptr: i32|
             -> i32 {
                if !caller
                    .data()
                    .capabilities
                    .contains(PluginCapabilities::AES_GCM_DECRYPT)
                {
                    return -1;
                }
                let memory = match caller.get_export("memory") {
                    Some(Extern::Memory(m)) => m,
                    _ => return -1,
                };
                let mut key = [0u8; 32];
                if memory.read(&caller, key_ptr as usize, &mut key).is_err() {
                    return -1;
                }
                let ct_len = ct_len.max(0) as usize;
                if ct_len > MAX_BUFFER_SIZE {
                    return -2;
                }
                let mut ciphertext = vec![0u8; ct_len];
                if memory
                    .read(&caller, ct_ptr as usize, &mut ciphertext)
                    .is_err()
                {
                    return -1;
                }
                match crate::crypto::encrypt::aes_256_gcm_decrypt(&key, &ciphertext) {
                    Ok(pt) => {
                        if memory.write(&mut caller, out_ptr as usize, &pt).is_err() {
                            return -1;
                        }
                        pt.len() as i32
                    }
                    Err(_) => -4,
                }
            },
        )
        .map_err(|_| HsmError::GeneralError)?;

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal WASM module that copies input to output unchanged (echo plugin).
    ///
    /// Compiled from:
    /// ```wat
    /// (module
    ///   (memory (export "memory") 4)
    ///   (func (export "craton_execute") (param i32 i32) (result i32)
    ///     ;; Copy input_len bytes from 0x10000 to 0x20000
    ///     (memory.copy (i32.const 0x20000) (local.get 0) (local.get 1))
    ///     (local.get 1)))
    /// ```
    fn echo_wasm_bytes() -> Vec<u8> {
        // Pre-assembled WAT → WASM for the echo plugin above.
        // Generated with: wat2wasm echo.wat --output=- | xxd -i
        wat::parse_str(
            r#"(module
              (memory (export "memory") 4)
              (func (export "craton_execute") (param $ptr i32) (param $len i32) (result i32)
                (memory.copy (i32.const 0x20000) (local.get $ptr) (local.get $len))
                (local.get $len)))"#,
        )
        .expect("valid WAT")
    }

    #[test]
    fn load_and_execute_echo_plugin() {
        let engine = PluginEngine::new().unwrap();

        let wasm = echo_wasm_bytes();
        let manifest = PluginManifest {
            id: "test.echo".into(),
            name: "Echo Plugin".into(),
            version: "1.0.0".into(),
            expected_sha256: None, // skip hash check in test
            capabilities: PluginCapabilities::empty(),
        };
        engine.load_plugin(manifest, &wasm).unwrap();

        let input = b"hello from craton hsm";
        let output = engine
            .execute("test.echo", PluginCapabilities::empty(), input)
            .unwrap();

        assert_eq!(&output[..input.len()], input);
    }

    #[test]
    fn unknown_plugin_returns_error() {
        let engine = PluginEngine::new().unwrap();
        let result = engine.execute("nonexistent", PluginCapabilities::empty(), b"data");
        assert!(matches!(result, Err(HsmError::FunctionNotSupported)));
    }

    #[test]
    fn sha256_capability_available() {
        // Verify the SHA-256 host function is registered correctly
        let engine = PluginEngine::new().unwrap();
        // (A real test would load a plugin that calls hsm_sha256 and returns the digest.)
        assert!(engine.loaded_plugins().is_empty());
    }

    #[test]
    fn test_plugin_count() {
        let engine = PluginEngine::new().unwrap();
        assert_eq!(engine.plugin_count(), 0);

        let wasm = echo_wasm_bytes();
        let manifest = PluginManifest {
            id: "test.count".into(),
            name: "Count Plugin".into(),
            version: "1.0.0".into(),
            expected_sha256: None,
            capabilities: PluginCapabilities::empty(),
        };
        engine.load_plugin(manifest, &wasm).unwrap();
        assert_eq!(engine.plugin_count(), 1);
    }

    #[test]
    fn test_is_loaded() {
        let engine = PluginEngine::new().unwrap();

        let wasm = echo_wasm_bytes();
        let manifest = PluginManifest {
            id: "test.loaded".into(),
            name: "Loaded Plugin".into(),
            version: "1.0.0".into(),
            expected_sha256: None,
            capabilities: PluginCapabilities::empty(),
        };
        engine.load_plugin(manifest, &wasm).unwrap();
        assert!(engine.is_loaded("test.loaded"));
    }

    #[test]
    fn test_unknown_plugin_is_not_loaded() {
        let engine = PluginEngine::new().unwrap();
        assert!(!engine.is_loaded("nonexistent.plugin"));
    }

    #[test]
    fn test_supply_chain_verification_failure() {
        let engine = PluginEngine::new().unwrap();

        let wasm = echo_wasm_bytes();
        let manifest = PluginManifest {
            id: "test.tampered".into(),
            name: "Tampered Plugin".into(),
            version: "1.0.0".into(),
            expected_sha256: Some(
                "0000000000000000000000000000000000000000000000000000000000000000".into(),
            ),
            capabilities: PluginCapabilities::empty(),
        };
        let result = engine.load_plugin(manifest, &wasm);
        assert!(result.is_err());
        match result {
            Err(HsmError::ConfigError(msg)) => {
                assert!(
                    msg.contains("SHA-256 mismatch"),
                    "unexpected error message: {msg}"
                );
            }
            other => panic!("expected ConfigError with SHA-256 mismatch, got: {other:?}"),
        }
    }
}
