//! # Metrics Collection and Export
//!
//! This module provides functionality to collect and export HSM metrics
//! in Prometheus format via HTTP endpoint.

use crate::metrics::HsmMetrics;
use prometheus::{Encoder, TextEncoder};
use std::sync::Arc;

/// Metrics collector that formats metrics for export
pub struct MetricsCollector {
    metrics: Arc<HsmMetrics>,
    encoder: TextEncoder,
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new(metrics: Arc<HsmMetrics>) -> Self {
        Self {
            metrics,
            encoder: TextEncoder::new(),
        }
    }

    /// Collect and format all metrics as Prometheus text format
    pub fn collect_metrics(&self) -> Result<String, prometheus::Error> {
        let metric_families = self.metrics.registry.gather();
        let mut buffer = Vec::new();
        self.encoder.encode(&metric_families, &mut buffer)?;
        Ok(String::from_utf8_lossy(&buffer).to_string())
    }

    /// Get the content type for Prometheus metrics
    pub fn content_type(&self) -> &'static str {
        "text/plain; version=0.0.4; charset=utf-8"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_collection() {
        let metrics = Arc::new(HsmMetrics::new().unwrap());
        let collector = MetricsCollector::new(metrics.clone());

        // Increment some counters
        metrics.operations_total.inc();
        metrics.signatures_total.inc();
        metrics.record_rsa_cache_hit();

        // Collect metrics
        let result = collector.collect_metrics().unwrap();

        // Verify metrics are included in output
        assert!(result.contains("hsm_operations_total"));
        assert!(result.contains("hsm_signatures_total"));
        assert!(result.contains("hsm_rsa_cache_hits_total"));
    }

    #[test]
    fn test_content_type() {
        let metrics = Arc::new(HsmMetrics::new().unwrap());
        let collector = MetricsCollector::new(metrics);

        assert_eq!(
            collector.content_type(),
            "text/plain; version=0.0.4; charset=utf-8"
        );
    }
}
