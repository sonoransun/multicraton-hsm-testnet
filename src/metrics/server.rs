//! # Metrics HTTP Server
//!
//! This module provides an HTTP server that exposes HSM metrics via a `/metrics`
//! endpoint in Prometheus format for monitoring and alerting systems.

use crate::metrics::{collector::MetricsCollector, HsmMetrics};
use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::Response,
    routing::get,
    Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info};

/// Configuration for the metrics server
#[derive(Debug, Clone)]
pub struct MetricsServerConfig {
    /// Address to bind the metrics server
    pub bind_address: SocketAddr,
    /// Whether to enable the metrics server
    pub enabled: bool,
}

impl Default for MetricsServerConfig {
    fn default() -> Self {
        Self {
            bind_address: SocketAddr::from(([127, 0, 0, 1], 9090)),
            enabled: false,
        }
    }
}

/// HTTP server for exposing Prometheus metrics
pub struct MetricsServer {
    config: MetricsServerConfig,
    metrics: Arc<HsmMetrics>,
    collector: MetricsCollector,
}

impl MetricsServer {
    /// Create a new metrics server
    pub fn new(config: MetricsServerConfig, metrics: Arc<HsmMetrics>) -> Self {
        let collector = MetricsCollector::new(metrics.clone());

        Self {
            config,
            metrics,
            collector,
        }
    }

    /// Start the metrics server
    pub async fn start(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !self.config.enabled {
            info!("Metrics server disabled in configuration");
            return Ok(());
        }

        let app = Router::new()
            .route("/metrics", get(metrics_handler))
            .route("/health", get(health_handler))
            .with_state(Arc::new(self.collector));

        let listener = TcpListener::bind(&self.config.bind_address).await?;
        info!("Metrics server listening on {}", self.config.bind_address);

        axum::serve(listener, app).await?;

        Ok(())
    }

    /// Get the configured bind address
    pub fn bind_address(&self) -> SocketAddr {
        self.config.bind_address
    }
}

/// Shared state for handlers
type AppState = Arc<MetricsCollector>;

/// Handle GET /metrics requests
async fn metrics_handler(State(collector): State<AppState>) -> Response {
    match collector.collect_metrics() {
        Ok(metrics_text) => {
            let mut headers = HeaderMap::new();
            headers.insert(
                "content-type",
                HeaderValue::from_static(collector.content_type()),
            );

            Response::builder()
                .status(StatusCode::OK)
                .body(metrics_text.into())
                .unwrap()
        }
        Err(e) => {
            error!("Failed to collect metrics: {}", e);
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body("Failed to collect metrics".into())
                .unwrap()
        }
    }
}

/// Handle GET /health requests
async fn health_handler() -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .body("OK".into())
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::timeout;

    #[tokio::test]
    async fn test_metrics_server_creation() {
        let config = MetricsServerConfig::default();
        let metrics = Arc::new(HsmMetrics::new().unwrap());
        let server = MetricsServer::new(config, metrics);

        assert_eq!(server.bind_address().port(), 9090);
    }

    #[tokio::test]
    async fn test_metrics_handler() {
        let metrics = Arc::new(HsmMetrics::new().unwrap());
        let collector = Arc::new(MetricsCollector::new(metrics.clone()));

        // Increment some test metrics
        metrics.operations_total.inc();
        metrics.signatures_total.inc();

        let response = metrics_handler(State(collector)).await;
        assert_eq!(response.status(), StatusCode::OK);

        // Verify content type
        let content_type = response.headers().get("content-type").unwrap();
        assert!(content_type.to_str().unwrap().contains("text/plain"));
    }

    #[tokio::test]
    async fn test_health_handler() {
        let response = health_handler().await;
        assert_eq!(response.status(), StatusCode::OK);
    }
}
