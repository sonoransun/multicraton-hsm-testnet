//! # Metrics and Observability Framework
//!
//! This module provides comprehensive metrics collection for the Craton HSM using
//! Prometheus-compatible metrics. It tracks operation counts, latencies, errors,
//! and resource utilization to enable production monitoring and performance analysis.

use crate::error::HsmResult;
use prometheus::{Gauge, Histogram, HistogramOpts, IntCounter, IntGauge, Opts, Registry};
use std::sync::Arc;

pub mod collector;
pub mod server;

/// Core HSM metrics collection and reporting structure.
///
/// This structure contains all the metrics used to monitor HSM operations,
/// including operation counters, latency histograms, error rates, and
/// resource utilization gauges.
#[derive(Clone)]
pub struct HsmMetrics {
    /// Registry for all metrics
    pub registry: Arc<Registry>,

    // Operation metrics
    /// Total number of operations performed, labeled by operation type
    pub operations_total: IntCounter,
    /// Total number of successful operations
    pub operations_success_total: IntCounter,
    /// Total number of failed operations, labeled by error type
    pub operations_error_total: IntCounter,
    /// Histogram of operation durations in seconds
    pub operation_duration_seconds: Histogram,

    // Session metrics
    /// Current number of active sessions
    pub active_sessions: IntGauge,
    /// Total sessions created
    pub sessions_created_total: IntCounter,
    /// Total sessions closed
    pub sessions_closed_total: IntCounter,

    // Key metrics
    /// Current number of stored keys
    pub stored_keys: IntGauge,
    /// Total keys generated
    pub keys_generated_total: IntCounter,
    /// Total keys imported
    pub keys_imported_total: IntCounter,
    /// Total keys deleted
    pub keys_deleted_total: IntCounter,

    // Crypto operations
    /// Signature operations by mechanism
    pub signatures_total: IntCounter,
    /// Encryption operations by mechanism
    pub encryptions_total: IntCounter,
    /// Decryption operations by mechanism
    pub decryptions_total: IntCounter,
    /// Key derivation operations
    pub derivations_total: IntCounter,

    // Performance metrics
    /// RSA key cache hit rate
    pub rsa_cache_hits: IntCounter,
    /// RSA key cache misses
    pub rsa_cache_misses: IntCounter,
    /// Session cache hit rate
    pub session_cache_hits: IntCounter,
    /// Session cache misses
    pub session_cache_misses: IntCounter,

    // Resource metrics
    /// Memory usage in bytes (when available)
    pub memory_usage_bytes: Gauge,
    /// Number of objects in storage
    pub storage_objects: IntGauge,
    /// DRBG entropy requests
    pub entropy_requests_total: IntCounter,

    // Security metrics
    /// Failed login attempts
    pub login_failures_total: IntCounter,
    /// Successful logins
    pub login_success_total: IntCounter,
    /// PIN lockout events
    pub pin_lockouts_total: IntCounter,

    // Audit metrics
    /// Audit entries written
    pub audit_entries_total: IntCounter,
    /// Audit verification failures
    pub audit_failures_total: IntCounter,
}

impl HsmMetrics {
    /// Create a new HsmMetrics instance with all metrics registered
    pub fn new() -> HsmResult<Self> {
        let registry = Arc::new(Registry::new());

        // Operation metrics
        let operations_total = IntCounter::with_opts(Opts::new(
            "hsm_operations_total",
            "Total number of HSM operations performed",
        ))?;

        let operations_success_total = IntCounter::with_opts(Opts::new(
            "hsm_operations_success_total",
            "Total number of successful HSM operations",
        ))?;

        let operations_error_total = IntCounter::with_opts(Opts::new(
            "hsm_operations_error_total",
            "Total number of failed HSM operations",
        ))?;

        let operation_duration_seconds = Histogram::with_opts(
            HistogramOpts::new(
                "hsm_operation_duration_seconds",
                "Histogram of HSM operation durations in seconds",
            )
            .buckets(vec![
                0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0,
            ]),
        )?;

        // Session metrics
        let active_sessions = IntGauge::with_opts(Opts::new(
            "hsm_active_sessions",
            "Current number of active HSM sessions",
        ))?;

        let sessions_created_total = IntCounter::with_opts(Opts::new(
            "hsm_sessions_created_total",
            "Total number of sessions created",
        ))?;

        let sessions_closed_total = IntCounter::with_opts(Opts::new(
            "hsm_sessions_closed_total",
            "Total number of sessions closed",
        ))?;

        // Key metrics
        let stored_keys = IntGauge::with_opts(Opts::new(
            "hsm_stored_keys",
            "Current number of keys stored in HSM",
        ))?;

        let keys_generated_total = IntCounter::with_opts(Opts::new(
            "hsm_keys_generated_total",
            "Total number of keys generated",
        ))?;

        let keys_imported_total = IntCounter::with_opts(Opts::new(
            "hsm_keys_imported_total",
            "Total number of keys imported",
        ))?;

        let keys_deleted_total = IntCounter::with_opts(Opts::new(
            "hsm_keys_deleted_total",
            "Total number of keys deleted",
        ))?;

        // Crypto operation metrics
        let signatures_total = IntCounter::with_opts(Opts::new(
            "hsm_signatures_total",
            "Total number of signature operations",
        ))?;

        let encryptions_total = IntCounter::with_opts(Opts::new(
            "hsm_encryptions_total",
            "Total number of encryption operations",
        ))?;

        let decryptions_total = IntCounter::with_opts(Opts::new(
            "hsm_decryptions_total",
            "Total number of decryption operations",
        ))?;

        let derivations_total = IntCounter::with_opts(Opts::new(
            "hsm_derivations_total",
            "Total number of key derivation operations",
        ))?;

        // Performance metrics
        let rsa_cache_hits = IntCounter::with_opts(Opts::new(
            "hsm_rsa_cache_hits_total",
            "Total RSA key cache hits",
        ))?;

        let rsa_cache_misses = IntCounter::with_opts(Opts::new(
            "hsm_rsa_cache_misses_total",
            "Total RSA key cache misses",
        ))?;

        let session_cache_hits = IntCounter::with_opts(Opts::new(
            "hsm_session_cache_hits_total",
            "Total session cache hits",
        ))?;

        let session_cache_misses = IntCounter::with_opts(Opts::new(
            "hsm_session_cache_misses_total",
            "Total session cache misses",
        ))?;

        // Resource metrics
        let memory_usage_bytes = Gauge::with_opts(Opts::new(
            "hsm_memory_usage_bytes",
            "Current memory usage in bytes",
        ))?;

        let storage_objects = IntGauge::with_opts(Opts::new(
            "hsm_storage_objects",
            "Number of objects in persistent storage",
        ))?;

        let entropy_requests_total = IntCounter::with_opts(Opts::new(
            "hsm_entropy_requests_total",
            "Total entropy/randomness requests to DRBG",
        ))?;

        // Security metrics
        let login_failures_total = IntCounter::with_opts(Opts::new(
            "hsm_login_failures_total",
            "Total failed login attempts",
        ))?;

        let login_success_total = IntCounter::with_opts(Opts::new(
            "hsm_login_success_total",
            "Total successful login attempts",
        ))?;

        let pin_lockouts_total = IntCounter::with_opts(Opts::new(
            "hsm_pin_lockouts_total",
            "Total PIN lockout events",
        ))?;

        // Audit metrics
        let audit_entries_total = IntCounter::with_opts(Opts::new(
            "hsm_audit_entries_total",
            "Total audit log entries written",
        ))?;

        let audit_failures_total = IntCounter::with_opts(Opts::new(
            "hsm_audit_failures_total",
            "Total audit verification failures",
        ))?;

        // Register all metrics
        registry.register(Box::new(operations_total.clone()))?;
        registry.register(Box::new(operations_success_total.clone()))?;
        registry.register(Box::new(operations_error_total.clone()))?;
        registry.register(Box::new(operation_duration_seconds.clone()))?;
        registry.register(Box::new(active_sessions.clone()))?;
        registry.register(Box::new(sessions_created_total.clone()))?;
        registry.register(Box::new(sessions_closed_total.clone()))?;
        registry.register(Box::new(stored_keys.clone()))?;
        registry.register(Box::new(keys_generated_total.clone()))?;
        registry.register(Box::new(keys_imported_total.clone()))?;
        registry.register(Box::new(keys_deleted_total.clone()))?;
        registry.register(Box::new(signatures_total.clone()))?;
        registry.register(Box::new(encryptions_total.clone()))?;
        registry.register(Box::new(decryptions_total.clone()))?;
        registry.register(Box::new(derivations_total.clone()))?;
        registry.register(Box::new(rsa_cache_hits.clone()))?;
        registry.register(Box::new(rsa_cache_misses.clone()))?;
        registry.register(Box::new(session_cache_hits.clone()))?;
        registry.register(Box::new(session_cache_misses.clone()))?;
        registry.register(Box::new(memory_usage_bytes.clone()))?;
        registry.register(Box::new(storage_objects.clone()))?;
        registry.register(Box::new(entropy_requests_total.clone()))?;
        registry.register(Box::new(login_failures_total.clone()))?;
        registry.register(Box::new(login_success_total.clone()))?;
        registry.register(Box::new(pin_lockouts_total.clone()))?;
        registry.register(Box::new(audit_entries_total.clone()))?;
        registry.register(Box::new(audit_failures_total.clone()))?;

        Ok(Self {
            registry,
            operations_total,
            operations_success_total,
            operations_error_total,
            operation_duration_seconds,
            active_sessions,
            sessions_created_total,
            sessions_closed_total,
            stored_keys,
            keys_generated_total,
            keys_imported_total,
            keys_deleted_total,
            signatures_total,
            encryptions_total,
            decryptions_total,
            derivations_total,
            rsa_cache_hits,
            rsa_cache_misses,
            session_cache_hits,
            session_cache_misses,
            memory_usage_bytes,
            storage_objects,
            entropy_requests_total,
            login_failures_total,
            login_success_total,
            pin_lockouts_total,
            audit_entries_total,
            audit_failures_total,
        })
    }

    /// Record the start of an operation and return a timer
    pub fn operation_timer(&self) -> prometheus::HistogramTimer {
        self.operation_duration_seconds.start_timer()
    }

    /// Record a successful operation
    pub fn record_operation_success(&self) {
        self.operations_total.inc();
        self.operations_success_total.inc();
    }

    /// Record a failed operation
    pub fn record_operation_error(&self) {
        self.operations_total.inc();
        self.operations_error_total.inc();
    }

    /// Record RSA cache hit
    pub fn record_rsa_cache_hit(&self) {
        self.rsa_cache_hits.inc();
    }

    /// Record RSA cache miss
    pub fn record_rsa_cache_miss(&self) {
        self.rsa_cache_misses.inc();
    }

    /// Record session cache hit
    pub fn record_session_cache_hit(&self) {
        self.session_cache_hits.inc();
    }

    /// Record session cache miss
    pub fn record_session_cache_miss(&self) {
        self.session_cache_misses.inc();
    }

    /// Update active session count
    pub fn set_active_sessions(&self, count: i64) {
        self.active_sessions.set(count);
    }

    /// Update stored key count
    pub fn set_stored_keys(&self, count: i64) {
        self.stored_keys.set(count);
    }
}

impl Default for HsmMetrics {
    fn default() -> Self {
        Self::new().expect("Failed to create default HsmMetrics")
    }
}
