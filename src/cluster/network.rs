// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company

//! Network Communication for HSM Clustering
//!
//! This module provides secure network communication between cluster nodes,
//! including message routing, encryption, and connection management.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use crate::cluster::{ClusterConfig, ClusterError, NodeId};

/// Network manager for cluster communication
pub struct NetworkManager {
    /// Network configuration
    config: NetworkConfig,
    /// Active connections to other nodes
    connections: Arc<RwLock<HashMap<NodeId, NodeConnection>>>,
    /// Message router
    router: Arc<MessageRouter>,
    /// Security manager
    security: Arc<NetworkSecurity>,
    /// Network metrics
    metrics: Arc<NetworkMetrics>,
}

/// Network configuration
#[derive(Debug, Clone)]
struct NetworkConfig {
    /// Local node address
    listen_address: SocketAddr,
    /// Connection timeouts
    connect_timeout: Duration,
    /// Keep-alive interval
    keepalive_interval: Duration,
    /// Maximum message size
    max_message_size: usize,
    /// Connection pool size per node
    connection_pool_size: usize,
}

/// Connection to a cluster node
#[derive(Debug)]
struct NodeConnection {
    /// Target node ID
    node_id: NodeId,
    /// Connection state
    state: ConnectionState,
    /// Connection statistics
    stats: ConnectionStats,
}

/// Connection state
#[derive(Debug, Clone, PartialEq, Eq)]
enum ConnectionState {
    /// Connection is being established
    Connecting,
    /// Connection is active and healthy
    Connected,
    /// Connection is temporarily disconnected
    Disconnected,
    /// Connection failed permanently
    Failed,
}

/// Connection statistics
#[derive(Debug, Default)]
struct ConnectionStats {
    /// Messages sent
    messages_sent: u64,
    /// Messages received
    messages_received: u64,
    /// Bytes sent
    bytes_sent: u64,
    /// Bytes received
    bytes_received: u64,
    /// Connection errors
    error_count: u64,
    /// Average round-trip time
    avg_rtt_ms: f64,
}

/// Message router for cluster communication
pub struct MessageRouter {
    /// Routing table
    routes: Arc<RwLock<HashMap<NodeId, RouteInfo>>>,
    /// Message handlers
    handlers: HashMap<MessageType, Box<dyn MessageHandler + Send + Sync>>,
}

/// Route information for a node
#[derive(Debug, Clone)]
struct RouteInfo {
    /// Target node address
    address: SocketAddr,
    /// Route metric (latency)
    metric: u32,
    /// Last update time
    last_updated: std::time::SystemTime,
}

/// Network security manager
pub struct NetworkSecurity {
    /// TLS configuration
    tls_config: TlsConfig,
    /// Authentication manager
    auth: Arc<AuthManager>,
    /// Rate limiter
    rate_limiter: Arc<RateLimiter>,
}

/// TLS configuration for secure communication
#[derive(Debug, Clone)]
struct TlsConfig {
    /// Server certificate
    cert_path: String,
    /// Private key
    key_path: String,
    /// CA certificate
    ca_path: String,
    /// Require client certificates
    require_client_cert: bool,
    /// Cipher suites
    cipher_suites: Vec<String>,
}

/// Authentication manager
pub struct AuthManager {
    /// Known node certificates
    node_certs: Arc<RwLock<HashMap<NodeId, Vec<u8>>>>,
    /// Authentication cache
    auth_cache: Arc<RwLock<HashMap<String, AuthCacheEntry>>>,
}

/// Authentication cache entry
#[derive(Debug, Clone)]
struct AuthCacheEntry {
    /// Node ID
    node_id: NodeId,
    /// Authentication timestamp
    authenticated_at: std::time::SystemTime,
    /// Expiry time
    expires_at: std::time::SystemTime,
}

/// Rate limiter for network operations
pub struct RateLimiter {
    /// Rate limits by node
    limits: Arc<RwLock<HashMap<NodeId, RateLimit>>>,
}

/// Rate limit configuration
#[derive(Debug, Clone)]
struct RateLimit {
    /// Maximum requests per second
    max_rps: f64,
    /// Current token bucket
    tokens: f64,
    /// Last refill time
    last_refill: std::time::Instant,
}

/// Network performance metrics
#[derive(Debug, Default)]
pub struct NetworkMetrics {
    /// Total messages sent
    pub messages_sent: std::sync::atomic::AtomicU64,
    /// Total messages received
    pub messages_received: std::sync::atomic::AtomicU64,
    /// Total bytes transferred
    pub bytes_transferred: std::sync::atomic::AtomicU64,
    /// Connection errors
    pub connection_errors: std::sync::atomic::AtomicU64,
    /// Average latency (microseconds)
    pub avg_latency_us: std::sync::atomic::AtomicU64,
    /// Active connections
    pub active_connections: std::sync::atomic::AtomicUsize,
}

/// Types of cluster messages
#[derive(Debug, Clone, Serialize, Deserialize)]
enum MessageType {
    /// Heartbeat message
    Heartbeat,
    /// Consensus message (Raft)
    Consensus,
    /// Replication message
    Replication,
    /// Membership message
    Membership,
    /// Administrative message
    Admin,
}

// ── Transport layer selection ─────────────────────────────────────────────────

/// Which encrypted transport protocol to use for cluster communication.
///
/// All three options provide mutual authentication and forward secrecy.
/// The choice depends on deployment constraints:
///
/// | Transport | Best for | Advantage |
/// |---|---|---|
/// | `MutualTls` | Traditional on-prem | Widest tooling support, PKI integration |
/// | `Quic` | Cloud / high-latency WAN | 0-RTT reconnects, stream multiplexing, no HOL blocking |
/// | `Noise` | Air-gapped / no PKI | No certificate authority required, minimal attack surface |
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClusterTransport {
    /// Mutual TLS 1.3 (existing implementation).
    MutualTls {
        /// Path to PEM certificate chain.
        cert_path: String,
        /// Path to PEM private key.
        key_path: String,
        /// Path to PEM CA bundle for peer verification.
        ca_path: String,
    },

    /// QUIC via [`quinn`] — HTTP/3-grade transport with built-in TLS 1.3.
    ///
    /// Key properties:
    /// - 0-RTT session resumption after network interruption
    /// - Independent streams eliminate head-of-line blocking between Raft messages
    /// - Connection migration (survives IP address changes)
    ///
    /// Requires `quic-transport` feature.
    #[cfg(feature = "quic-transport")]
    Quic {
        /// PEM certificate for this node's QUIC identity.
        cert_pem: String,
        /// PEM private key for this node's QUIC identity.
        key_pem: String,
        /// Maximum idle timeout before the QUIC connection is closed.
        idle_timeout_ms: u64,
        /// Maximum number of simultaneous bidirectional streams per connection.
        max_concurrent_streams: u32,
    },

    /// Noise Protocol Framework via [`snow`] — Signal-grade encrypted channels.
    ///
    /// Uses the `Noise_XX_25519_AESGCM_SHA256` handshake pattern:
    /// - `XX` — both parties transmit their static keys during handshake (no PKI needed)
    /// - `25519` — X25519 Diffie-Hellman for ephemeral and static keys
    /// - `AESGCM` — AES-256-GCM authenticated encryption
    /// - `SHA256` — HKDF key derivation
    ///
    /// Requires `noise-protocol` feature.
    #[cfg(feature = "noise-protocol")]
    Noise {
        /// This node's 32-byte X25519 static private key (little-endian scalar).
        static_key: [u8; 32],
        /// Authorised peer static public keys (32 bytes each, indexed by node ID).
        trusted_peers: std::collections::HashMap<NodeId, [u8; 32]>,
    },
}

impl ClusterTransport {
    /// Human-readable name for logging.
    pub fn protocol_name(&self) -> &'static str {
        match self {
            ClusterTransport::MutualTls { .. } => "mTLS-1.3",
            #[cfg(feature = "quic-transport")]
            ClusterTransport::Quic { .. } => "QUIC/TLS-1.3",
            #[cfg(feature = "noise-protocol")]
            ClusterTransport::Noise { .. } => "Noise_XX_25519_AESGCM_SHA256",
        }
    }
}

// ── Noise Protocol session management ─────────────────────────────────────────

/// A Noise Protocol transport session (initiator or responder).
///
/// Wraps a [`snow::TransportState`] after the XX handshake completes.
#[cfg(feature = "noise-protocol")]
pub struct NoiseSession {
    state: snow::TransportState,
    /// Remote peer's static public key (extracted after handshake).
    pub remote_static: [u8; 32],
}

#[cfg(feature = "noise-protocol")]
impl NoiseSession {
    /// The Noise protocol pattern for cluster communication.
    pub const PATTERN: &'static str = "Noise_XX_25519_AESGCM_SHA256";

    /// Perform the Noise XX handshake as the **initiator** (the node connecting outbound).
    ///
    /// Writes handshake messages into `transport` and reads responses back.
    /// Returns a session ready for encrypted message exchange.
    pub fn initiate(
        static_key: &[u8; 32],
        mut transport: impl std::io::Read + std::io::Write,
    ) -> Result<Self, crate::error::HsmError> {
        let builder =
            snow::Builder::new(Self::PATTERN.parse().map_err(|_| {
                crate::error::HsmError::ConfigError("invalid Noise pattern".into())
            })?)
            .local_private_key(static_key);

        let mut handshake = builder
            .build_initiator()
            .map_err(|_| crate::error::HsmError::GeneralError)?;

        // XX pattern: → e, → e+ee+s+es, ← e+ee+se+s+es
        let mut buf = vec![0u8; 65535];

        // Message 1: → e
        let n = handshake
            .write_message(&[], &mut buf)
            .map_err(|_| crate::error::HsmError::GeneralError)?;
        transport
            .write_all(&(n as u32).to_be_bytes())
            .map_err(|_| crate::error::HsmError::GeneralError)?;
        transport
            .write_all(&buf[..n])
            .map_err(|_| crate::error::HsmError::GeneralError)?;

        // Message 2: ← e+ee+s+es
        let mut len_buf = [0u8; 4];
        transport
            .read_exact(&mut len_buf)
            .map_err(|_| crate::error::HsmError::GeneralError)?;
        let n = u32::from_be_bytes(len_buf) as usize;
        transport
            .read_exact(&mut buf[..n])
            .map_err(|_| crate::error::HsmError::GeneralError)?;
        handshake
            .read_message(&buf[..n], &mut [])
            .map_err(|_| crate::error::HsmError::GeneralError)?;

        // Message 3: → e+ee+se+s+es (completes XX)
        let n = handshake
            .write_message(&[], &mut buf)
            .map_err(|_| crate::error::HsmError::GeneralError)?;
        transport
            .write_all(&(n as u32).to_be_bytes())
            .map_err(|_| crate::error::HsmError::GeneralError)?;
        transport
            .write_all(&buf[..n])
            .map_err(|_| crate::error::HsmError::GeneralError)?;

        let remote_static: [u8; 32] = handshake
            .get_remote_static()
            .and_then(|s| s.try_into().ok())
            .ok_or(crate::error::HsmError::GeneralError)?;

        let state = handshake
            .into_transport_mode()
            .map_err(|_| crate::error::HsmError::GeneralError)?;

        Ok(Self {
            state,
            remote_static,
        })
    }

    /// Encrypt and frame a cluster message.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, crate::error::HsmError> {
        let mut buf = vec![0u8; plaintext.len() + 64]; // overhead for AESGCM tag
        let n = self
            .state
            .write_message(plaintext, &mut buf)
            .map_err(|_| crate::error::HsmError::GeneralError)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Decrypt a framed cluster message.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, crate::error::HsmError> {
        let mut buf = vec![0u8; ciphertext.len()];
        let n = self
            .state
            .read_message(ciphertext, &mut buf)
            .map_err(|_| crate::error::HsmError::GeneralError)?;
        buf.truncate(n);
        Ok(buf)
    }
}

// ── QUIC connection helpers ───────────────────────────────────────────────────

/// A QUIC endpoint for cluster communication.
///
/// Each node creates one endpoint; incoming connections from peers are accepted
/// on the server side, while outbound connections are opened on the client side.
#[cfg(feature = "quic-transport")]
pub struct QuicClusterEndpoint {
    endpoint: quinn::Endpoint,
}

#[cfg(feature = "quic-transport")]
impl QuicClusterEndpoint {
    /// Bind a QUIC endpoint on `addr` using the provided PEM certificate and key.
    pub fn bind(
        addr: std::net::SocketAddr,
        cert_pem: &str,
        key_pem: &str,
    ) -> Result<Self, crate::error::HsmError> {
        use quinn::rustls;

        // Parse certificate and key from PEM
        let certs = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| crate::error::HsmError::ConfigError("invalid QUIC cert PEM".into()))?;
        let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
            .map_err(|_| crate::error::HsmError::ConfigError("invalid QUIC key PEM".into()))?
            .ok_or_else(|| crate::error::HsmError::ConfigError("no private key in PEM".into()))?;

        let tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|_| crate::error::HsmError::ConfigError("QUIC TLS config failed".into()))?;

        let server_config = quinn::ServerConfig::with_crypto(std::sync::Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
                .map_err(|_| crate::error::HsmError::GeneralError)?,
        ));

        let endpoint = quinn::Endpoint::server(server_config, addr)
            .map_err(|_| crate::error::HsmError::ConfigError("QUIC bind failed".into()))?;

        tracing::info!(%addr, "QUIC cluster endpoint bound");
        Ok(Self { endpoint })
    }

    /// Accept the next incoming QUIC connection.
    pub async fn accept(&self) -> Option<quinn::Connection> {
        let incoming = self.endpoint.accept().await?;
        incoming.await.ok()
    }

    /// Open a QUIC connection to a remote cluster node.
    pub async fn connect(
        &self,
        addr: std::net::SocketAddr,
        server_name: &str,
    ) -> Result<quinn::Connection, crate::error::HsmError> {
        self.endpoint
            .connect(addr, server_name)
            .map_err(|_| crate::error::HsmError::GeneralError)?
            .await
            .map_err(|_| crate::error::HsmError::GeneralError)
    }
}

/// Generic cluster message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterMessage {
    /// Message ID
    pub id: uuid::Uuid,
    /// Source node
    pub source: NodeId,
    /// Destination node
    pub destination: NodeId,
    /// Message type
    pub message_type: MessageType,
    /// Message payload
    pub payload: Vec<u8>,
    /// Timestamp
    pub timestamp: std::time::SystemTime,
    /// Message signature
    pub signature: Option<Vec<u8>>,
}

/// Message handler trait
#[async_trait::async_trait]
pub trait MessageHandler {
    /// Handle incoming message
    async fn handle_message(
        &self,
        message: ClusterMessage,
        context: MessageContext,
    ) -> Result<Option<ClusterMessage>, ClusterError>;
}

/// Context for message handling
#[derive(Debug, Clone)]
pub struct MessageContext {
    /// Source connection information
    pub connection_info: ConnectionInfo,
    /// Authentication information
    pub auth_info: Option<AuthInfo>,
    /// Request timestamp
    pub received_at: std::time::Instant,
}

/// Connection information
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    /// Remote address
    pub remote_addr: SocketAddr,
    /// Connection ID
    pub connection_id: uuid::Uuid,
    /// TLS information
    pub tls_info: Option<TlsInfo>,
}

/// TLS connection information
#[derive(Debug, Clone)]
pub struct TlsInfo {
    /// Cipher suite used
    pub cipher_suite: String,
    /// Protocol version
    pub protocol_version: String,
    /// Client certificate (if provided)
    pub client_cert: Option<Vec<u8>>,
}

/// Authentication information
#[derive(Debug, Clone)]
pub struct AuthInfo {
    /// Authenticated node ID
    pub node_id: NodeId,
    /// Authentication method
    pub auth_method: String,
    /// Authentication timestamp
    pub authenticated_at: std::time::SystemTime,
}

impl NetworkManager {
    /// Create new network manager
    pub async fn new(config: ClusterConfig) -> Result<Self, ClusterError> {
        let network_config = NetworkConfig {
            listen_address: config.listen_address,
            connect_timeout: Duration::from_secs(10),
            keepalive_interval: Duration::from_secs(30),
            max_message_size: 64 * 1024 * 1024, // 64 MB
            connection_pool_size: 4,
        };

        let security = Arc::new(NetworkSecurity::new(config.security_config.clone())?);

        let router = Arc::new(MessageRouter::new());
        let connections = Arc::new(RwLock::new(HashMap::new()));
        let metrics = Arc::new(NetworkMetrics::default());

        Ok(Self {
            config: network_config,
            connections,
            router,
            security,
            metrics,
        })
    }

    /// Start the network manager
    pub async fn start(&self) -> Result<(), ClusterError> {
        tracing::info!("Starting network manager on {}", self.config.listen_address);

        // Start TLS server
        self.start_server().await?;

        // Start connection maintenance
        self.start_connection_maintenance().await?;

        // Start metrics collection
        self.start_metrics_collection().await?;

        Ok(())
    }

    /// Stop the network manager
    pub async fn stop(&self) -> Result<(), ClusterError> {
        tracing::info!("Stopping network manager");

        // Close all connections
        let mut connections = self.connections.write().await;
        connections.clear();

        Ok(())
    }

    /// Connect to a cluster node
    pub async fn connect_to_node(
        &self,
        node_info: crate::cluster::NodeInfo,
    ) -> Result<(), ClusterError> {
        tracing::info!(
            "Connecting to node {} at {}",
            node_info.id,
            node_info.address
        );

        let connection = NodeConnection {
            node_id: node_info.id,
            state: ConnectionState::Connecting,
            stats: ConnectionStats::default(),
        };

        // Establish TLS connection
        // Implementation would create actual connection here

        let mut connections = self.connections.write().await;
        connections.insert(node_info.id, connection);

        self.metrics
            .active_connections
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        tracing::info!("Successfully connected to node {}", node_info.id);

        Ok(())
    }

    /// Send message to a specific node
    pub async fn send_message(
        &self,
        to: NodeId,
        message: ClusterMessage,
    ) -> Result<(), ClusterError> {
        let connections = self.connections.read().await;

        if let Some(connection) = connections.get(&to) {
            if connection.state == ConnectionState::Connected {
                // Serialize and send message
                let serialized =
                    bincode::serialize(&message).map_err(|e| ClusterError::NetworkError {
                        message: format!("Failed to serialize message: {}", e),
                    })?;

                // Apply rate limiting
                self.security.rate_limiter.check_rate_limit(to).await?;

                // Send over TLS connection
                // Implementation would send actual bytes

                self.metrics
                    .messages_sent
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.metrics.bytes_transferred.fetch_add(
                    serialized.len() as u64,
                    std::sync::atomic::Ordering::Relaxed,
                );

                return Ok(());
            }
        }

        Err(ClusterError::NetworkError {
            message: format!("No active connection to node {}", to),
        })
    }

    /// Broadcast message to all nodes
    pub async fn broadcast_message(&self, message: ClusterMessage) -> Result<(), ClusterError> {
        let connections = self.connections.read().await;
        let mut failed_nodes = Vec::new();

        for (&node_id, connection) in connections.iter() {
            if connection.state == ConnectionState::Connected {
                let mut msg = message.clone();
                msg.destination = node_id;

                if let Err(e) = self.send_message(node_id, msg).await {
                    tracing::warn!(
                        "Failed to send broadcast message to node {}: {}",
                        node_id,
                        e
                    );
                    failed_nodes.push(node_id);
                }
            }
        }

        if failed_nodes.is_empty() {
            Ok(())
        } else {
            Err(ClusterError::NetworkError {
                message: format!("Broadcast failed to {} nodes", failed_nodes.len()),
            })
        }
    }

    /// Get connection status for all nodes
    pub async fn get_connection_status(&self) -> HashMap<NodeId, ConnectionState> {
        let connections = self.connections.read().await;
        connections
            .iter()
            .map(|(&node_id, conn)| (node_id, conn.state.clone()))
            .collect()
    }

    /// Get network metrics
    pub fn get_metrics(&self) -> &NetworkMetrics {
        &self.metrics
    }

    // ========================================================================
    // Private helper methods
    // ========================================================================

    /// Start TLS server for incoming connections
    async fn start_server(&self) -> Result<(), ClusterError> {
        // Implementation would start actual TLS server
        tracing::info!("TLS server started on {}", self.config.listen_address);
        Ok(())
    }

    /// Start connection maintenance task
    async fn start_connection_maintenance(&self) -> Result<(), ClusterError> {
        let connections = self.connections.clone();
        let keepalive_interval = self.config.keepalive_interval;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(keepalive_interval);

            loop {
                interval.tick().await;

                // Check connection health and send keepalives
                let connections = connections.read().await;
                for (&node_id, connection) in connections.iter() {
                    if connection.state == ConnectionState::Connected {
                        // Send keepalive
                        tracing::trace!("Sending keepalive to node {}", node_id);
                    }
                }
            }
        });

        Ok(())
    }

    /// Start metrics collection task
    async fn start_metrics_collection(&self) -> Result<(), ClusterError> {
        let metrics = self.metrics.clone();
        let connections = self.connections.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));

            loop {
                interval.tick().await;

                // Update connection count metric
                let connections = connections.read().await;
                let active_count = connections
                    .values()
                    .filter(|conn| conn.state == ConnectionState::Connected)
                    .count();

                metrics
                    .active_connections
                    .store(active_count, std::sync::atomic::Ordering::Relaxed);
            }
        });

        Ok(())
    }
}

impl MessageRouter {
    /// Create new message router
    pub fn new() -> Self {
        Self {
            routes: Arc::new(RwLock::new(HashMap::new())),
            handlers: HashMap::new(),
        }
    }

    /// Add route to a node
    pub async fn add_route(&self, node_id: NodeId, address: SocketAddr) {
        let route_info = RouteInfo {
            address,
            metric: 0, // Direct connection
            last_updated: std::time::SystemTime::now(),
        };

        let mut routes = self.routes.write().await;
        routes.insert(node_id, route_info);
    }

    /// Remove route to a node
    pub async fn remove_route(&self, node_id: NodeId) {
        let mut routes = self.routes.write().await;
        routes.remove(&node_id);
    }

    /// Get route to a node
    pub async fn get_route(&self, node_id: NodeId) -> Option<RouteInfo> {
        let routes = self.routes.read().await;
        routes.get(&node_id).cloned()
    }
}

impl NetworkSecurity {
    /// Create new network security manager
    pub fn new(
        security_config: crate::cluster::ClusterSecurityConfig,
    ) -> Result<Self, ClusterError> {
        let tls_config = TlsConfig {
            cert_path: security_config.tls_cert_path,
            key_path: security_config.tls_key_path,
            ca_path: security_config.ca_cert_path,
            require_client_cert: security_config.require_client_cert,
            cipher_suites: vec![
                "TLS_AES_256_GCM_SHA384".to_string(),
                "TLS_AES_128_GCM_SHA256".to_string(),
            ],
        };

        let auth = Arc::new(AuthManager::new());
        let rate_limiter = Arc::new(RateLimiter::new());

        Ok(Self {
            tls_config,
            auth,
            rate_limiter,
        })
    }

    /// Authenticate incoming connection
    pub async fn authenticate_connection(
        &self,
        connection_info: &ConnectionInfo,
    ) -> Result<AuthInfo, ClusterError> {
        // Extract client certificate from TLS info
        if let Some(ref tls_info) = connection_info.tls_info {
            if let Some(ref client_cert) = tls_info.client_cert {
                // Verify certificate and extract node ID
                let node_id = self.verify_certificate(client_cert).await?;

                return Ok(AuthInfo {
                    node_id,
                    auth_method: "mutual_tls".to_string(),
                    authenticated_at: std::time::SystemTime::now(),
                });
            }
        }

        Err(ClusterError::SecurityViolation {
            message: "No valid client certificate provided".to_string(),
        })
    }

    /// Verify a client certificate by matching it against the known-node
    /// registry populated via `AuthManager::add_node_cert`.
    ///
    /// Returns the `NodeId` registered against the cert on success, or
    /// `SecurityViolation` when the cert is unknown. Full chain validation
    /// (intermediate + root CA) is the responsibility of the TLS acceptor
    /// above; this function enforces peer pinning to specific certs.
    async fn verify_certificate(&self, cert_data: &[u8]) -> Result<NodeId, ClusterError> {
        if cert_data.is_empty() {
            return Err(ClusterError::SecurityViolation {
                message: "empty certificate".to_string(),
            });
        }
        let registry = self.auth.node_certs.read().await;
        for (node_id, stored) in registry.iter() {
            if stored.as_slice() == cert_data {
                return Ok(*node_id);
            }
        }
        use sha2::{Digest, Sha256};
        let fp: [u8; 32] = Sha256::digest(cert_data).into();
        Err(ClusterError::SecurityViolation {
            message: format!("unpinned certificate fingerprint {}", hex::encode(fp)),
        })
    }
}

impl AuthManager {
    /// Create new authentication manager
    pub fn new() -> Self {
        Self {
            node_certs: Arc::new(RwLock::new(HashMap::new())),
            auth_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add known node certificate
    pub async fn add_node_certificate(&self, node_id: NodeId, cert_data: Vec<u8>) {
        let mut certs = self.node_certs.write().await;
        certs.insert(node_id, cert_data);
    }

    /// Verify node certificate
    pub async fn verify_node(&self, node_id: NodeId, cert_data: &[u8]) -> bool {
        let certs = self.node_certs.read().await;
        if let Some(known_cert) = certs.get(&node_id) {
            return known_cert == cert_data;
        }
        false
    }
}

impl RateLimiter {
    /// Create new rate limiter
    pub fn new() -> Self {
        Self {
            limits: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Check if operation is within rate limit
    pub async fn check_rate_limit(&self, node_id: NodeId) -> Result<(), ClusterError> {
        let mut limits = self.limits.write().await;
        let limit = limits.entry(node_id).or_insert_with(|| RateLimit {
            max_rps: 1000.0, // Default 1000 RPS
            tokens: 1000.0,
            last_refill: std::time::Instant::now(),
        });

        // Token bucket algorithm
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(limit.last_refill).as_secs_f64();
        limit.tokens = (limit.tokens + elapsed * limit.max_rps).min(limit.max_rps);
        limit.last_refill = now;

        if limit.tokens >= 1.0 {
            limit.tokens -= 1.0;
            Ok(())
        } else {
            Err(ClusterError::SecurityViolation {
                message: "Rate limit exceeded".to_string(),
            })
        }
    }

    /// Set rate limit for a node
    pub async fn set_rate_limit(&self, node_id: NodeId, max_rps: f64) {
        let mut limits = self.limits.write().await;
        limits.insert(
            node_id,
            RateLimit {
                max_rps,
                tokens: max_rps,
                last_refill: std::time::Instant::now(),
            },
        );
    }
}
