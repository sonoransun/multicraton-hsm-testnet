// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company

//! HSM Clustering for High Availability
//!
//! This module implements distributed HSM clustering using Raft consensus for:
//! - Multi-node key replication
//! - Automatic leader election and failover
//! - Distributed coordination of cryptographic operations
//! - Split-brain protection and network partition tolerance
//!
//! The clustering implementation ensures that key material is securely replicated
//! across multiple HSM nodes while maintaining PKCS#11 compliance and strong
//! security guarantees.

#![warn(missing_docs)]

pub mod consensus;
pub mod coordinator;
pub mod membership;
pub mod network;
pub mod replication;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use thiserror::Error;
use tokio::sync::RwLock;

use crate::core::HsmCore;
use crate::error::{HsmError, HsmResult};
use crate::store::object::StoredObject;

/// Unique identifier for cluster nodes
pub type NodeId = u64;

/// Unique identifier for Raft terms
pub type Term = u64;

/// Unique identifier for log entries
pub type LogIndex = u64;

/// Cluster configuration and topology
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfig {
    /// This node's ID
    pub node_id: NodeId,
    /// This node's network address
    pub listen_address: SocketAddr,
    /// Initial cluster members
    pub initial_members: Vec<NodeInfo>,
    /// Raft configuration
    pub raft_config: RaftConfig,
    /// Security configuration
    pub security_config: ClusterSecurityConfig,
    /// Replication settings
    pub replication_config: ReplicationConfig,
}

/// Information about a cluster node
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeInfo {
    /// Unique node identifier
    pub id: NodeId,
    /// Network address for communication
    pub address: SocketAddr,
    /// Node role in the cluster
    pub role: NodeRole,
    /// Last known heartbeat timestamp
    pub last_heartbeat: Option<SystemTime>,
    /// Node health status
    pub health_status: NodeHealthStatus,
    /// Supported HSM capabilities
    pub capabilities: NodeCapabilities,
}

/// Role of a node in the cluster
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NodeRole {
    /// Can become leader and serve read/write requests
    Voting,
    /// Cannot become leader but can serve read requests
    NonVoting,
    /// Temporarily excluded from consensus
    Learner,
}

/// Health status of a cluster node
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NodeHealthStatus {
    /// Node is healthy and responsive
    Healthy,
    /// Node is responding but with degraded performance
    Degraded,
    /// Node is not responding to health checks
    Unreachable,
    /// Node has been manually removed from cluster
    Removed,
}

/// HSM capabilities of a cluster node
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeCapabilities {
    /// Supported cryptographic algorithms
    pub algorithms: Vec<String>,
    /// Maximum number of concurrent operations
    pub max_concurrent_ops: u32,
    /// Available hardware acceleration
    pub hardware_acceleration: Vec<String>,
    /// FIPS compliance level
    pub fips_level: Option<String>,
    /// Post-quantum cryptography support
    pub pqc_support: bool,
}

/// Raft consensus configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaftConfig {
    /// Election timeout range (milliseconds)
    pub election_timeout_ms: (u64, u64),
    /// Heartbeat interval (milliseconds)
    pub heartbeat_interval_ms: u64,
    /// Maximum log entries per append
    pub max_append_entries: usize,
    /// Log compaction threshold
    pub compaction_threshold: u64,
    /// Snapshot creation interval
    pub snapshot_interval: Duration,
}

impl Default for RaftConfig {
    fn default() -> Self {
        Self {
            election_timeout_ms: (150, 300),
            heartbeat_interval_ms: 50,
            max_append_entries: 100,
            compaction_threshold: 10000,
            snapshot_interval: Duration::from_secs(3600), // 1 hour
        }
    }
}

/// Cluster security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterSecurityConfig {
    /// TLS certificate for inter-node communication
    pub tls_cert_path: String,
    /// TLS private key
    pub tls_key_path: String,
    /// Certificate authority for peer verification
    pub ca_cert_path: String,
    /// Enable mutual TLS authentication
    pub require_client_cert: bool,
    /// Key encryption settings for replication
    pub replication_encryption: ReplicationEncryption,
    /// Network security settings
    pub network_security: NetworkSecurityConfig,
}

/// Key replication encryption settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationEncryption {
    /// Encryption algorithm for key material in transit
    pub algorithm: String,
    /// Key derivation function for replication keys
    pub kdf: String,
    /// Additional authenticated data for encryption
    pub aad: Vec<u8>,
}

/// Network security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSecurityConfig {
    /// Allowed IP address ranges
    pub allowed_networks: Vec<String>,
    /// Rate limiting configuration
    pub rate_limits: RateLimitConfig,
    /// DDoS protection settings
    pub ddos_protection: DdosProtectionConfig,
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum requests per second per node
    pub max_requests_per_second: u32,
    /// Burst capacity for request spikes
    pub burst_capacity: u32,
    /// Rate limit window duration
    pub window_duration: Duration,
}

/// DDoS protection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdosProtectionConfig {
    /// Enable connection throttling
    pub enable_throttling: bool,
    /// Maximum concurrent connections per IP
    pub max_connections_per_ip: u32,
    /// Connection establishment rate limit
    pub connection_rate_limit: u32,
}

/// Key replication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationConfig {
    /// Replication strategy
    pub strategy: ReplicationStrategy,
    /// Number of replicas for each key
    pub replica_count: usize,
    /// Consistency level required for operations
    pub consistency_level: ConsistencyLevel,
    /// Conflict resolution strategy
    pub conflict_resolution: ConflictResolution,
}

/// Key replication strategy
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReplicationStrategy {
    /// All writes must be replicated to majority before acknowledgment
    Synchronous,
    /// Local write with background replication
    Asynchronous,
    /// Critical keys synchronous, bulk keys asynchronous
    Hybrid,
}

/// Consistency level for distributed operations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConsistencyLevel {
    /// Operation succeeds if majority of nodes agree
    Quorum,
    /// Operation must succeed on all available nodes
    All,
    /// Operation succeeds if any node confirms
    One,
    /// Operation succeeds if local node confirms (unsafe)
    Local,
}

/// Conflict resolution strategy for concurrent modifications
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConflictResolution {
    /// Last writer wins based on timestamp
    LastWriterWins,
    /// Reject conflicting operations
    Reject,
    /// Use vector clocks for causal ordering
    VectorClock,
    /// Custom conflict resolution function
    Custom(String),
}

/// Cluster operation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterOperationResult {
    /// Operation success status
    pub success: bool,
    /// Number of nodes that acknowledged the operation
    pub nodes_confirmed: usize,
    /// Total nodes in cluster
    pub total_nodes: usize,
    /// Operation latency
    pub latency: Duration,
    /// Any warnings or errors from individual nodes
    pub node_responses: HashMap<NodeId, NodeOperationResult>,
}

/// Result from individual node operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeOperationResult {
    /// Node ID
    pub node_id: NodeId,
    /// Operation success
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
    /// Operation latency
    pub latency: Duration,
}

/// HSM cluster manager coordinating distributed operations
pub struct HsmCluster {
    /// Configuration for this cluster
    config: ClusterConfig,
    /// Local HSM core instance
    local_hsm: Arc<HsmCore>,
    /// Raft consensus engine
    consensus: Arc<RwLock<dyn consensus::ConsensusEngine + Send + Sync>>,
    /// Key replication manager
    replication: Arc<replication::ReplicationManager>,
    /// Cluster membership manager
    membership: Arc<membership::MembershipManager>,
    /// Network communication layer
    network: Arc<network::NetworkManager>,
    /// Operation coordinator
    coordinator: Arc<coordinator::OperationCoordinator>,
    /// Cluster metrics
    metrics: Arc<ClusterMetrics>,
}

/// Cluster performance and health metrics
#[derive(Debug, Default)]
pub struct ClusterMetrics {
    /// Number of successful operations
    pub successful_operations: std::sync::atomic::AtomicU64,
    /// Number of failed operations
    pub failed_operations: std::sync::atomic::AtomicU64,
    /// Average operation latency (nanoseconds)
    pub average_latency_ns: std::sync::atomic::AtomicU64,
    /// Number of leadership changes
    pub leadership_changes: std::sync::atomic::AtomicU64,
    /// Current cluster size
    pub cluster_size: std::sync::atomic::AtomicUsize,
    /// Number of network partitions detected
    pub network_partitions: std::sync::atomic::AtomicU64,
    /// Data replication lag (milliseconds)
    pub replication_lag_ms: std::sync::atomic::AtomicU64,
}

/// Errors that can occur in cluster operations
#[derive(Debug, Error)]
pub enum ClusterError {
    /// Network communication error
    #[error("Network error: {message}")]
    NetworkError { message: String },

    /// Consensus algorithm error
    #[error("Consensus error: {message}")]
    ConsensusError { message: String },

    /// Key replication error
    #[error("Replication error: {message}")]
    ReplicationError { message: String },

    /// Configuration error
    #[error("Configuration error: {message}")]
    ConfigurationError { message: String },

    /// Security violation
    #[error("Security violation: {message}")]
    SecurityViolation { message: String },

    /// Operation timeout
    #[error("Operation timeout after {duration:?}")]
    Timeout { duration: Duration },

    /// Insufficient replicas for operation
    #[error("Insufficient replicas: need {required}, have {available}")]
    InsufficientReplicas { required: usize, available: usize },

    /// Split brain scenario detected
    #[error("Split brain detected: multiple leaders in term {term}")]
    SplitBrain { term: Term },

    /// Incompatible cluster version
    #[error("Version mismatch: local={local_version}, remote={remote_version}")]
    VersionMismatch {
        local_version: String,
        remote_version: String,
    },
}

/// Convert cluster errors to HSM errors
impl From<ClusterError> for HsmError {
    fn from(err: ClusterError) -> Self {
        match err {
            ClusterError::NetworkError { .. } => HsmError::DeviceError,
            ClusterError::ConsensusError { .. } => HsmError::GeneralError,
            ClusterError::ReplicationError { .. } => HsmError::DeviceError,
            ClusterError::ConfigurationError { .. } => HsmError::ArgumentsBad,
            ClusterError::SecurityViolation { .. } => HsmError::UserNotLoggedIn,
            ClusterError::Timeout { .. } => HsmError::DeviceError,
            ClusterError::InsufficientReplicas { .. } => HsmError::DeviceError,
            ClusterError::SplitBrain { .. } => HsmError::GeneralError,
            ClusterError::VersionMismatch { .. } => HsmError::DeviceError,
        }
    }
}

impl HsmCluster {
    /// Create a new HSM cluster instance
    pub async fn new(config: ClusterConfig, local_hsm: Arc<HsmCore>) -> Result<Self, ClusterError> {
        // Initialize consensus engine
        let consensus = Arc::new(RwLock::new(
            consensus::RaftConsensus::new(config.clone()).await?,
        ));

        // Initialize replication manager
        let replication = Arc::new(
            replication::ReplicationManager::new(config.clone(), local_hsm.clone()).await?,
        );

        // Initialize membership manager
        let membership = Arc::new(membership::MembershipManager::new(config.clone()).await?);

        // Initialize network manager
        let network = Arc::new(network::NetworkManager::new(config.clone()).await?);

        // Initialize operation coordinator
        let coordinator = Arc::new(
            coordinator::OperationCoordinator::new(
                config.clone(),
                consensus.clone(),
                replication.clone(),
                membership.clone(),
            )
            .await?,
        );

        Ok(Self {
            config,
            local_hsm,
            consensus,
            replication,
            membership,
            network,
            coordinator,
            metrics: Arc::new(ClusterMetrics::default()),
        })
    }

    /// Start the cluster and join the network
    pub async fn start(&mut self) -> Result<(), ClusterError> {
        tracing::info!("Starting HSM cluster node {}", self.config.node_id);

        // Start network layer
        self.network.start().await?;

        // Start consensus engine
        {
            let mut consensus = self.consensus.write().await;
            consensus.start().await?;
        }

        // Start replication manager
        self.replication.start().await?;

        // Join cluster if not the first node
        if !self.config.initial_members.is_empty() {
            self.join_cluster().await?;
        }

        tracing::info!(
            "HSM cluster node {} started successfully",
            self.config.node_id
        );
        Ok(())
    }

    /// Stop the cluster gracefully
    pub async fn stop(&mut self) -> Result<(), ClusterError> {
        tracing::info!("Stopping HSM cluster node {}", self.config.node_id);

        // Stop accepting new operations
        self.coordinator.stop_accepting_operations().await?;

        // Stop consensus engine
        {
            let mut consensus = self.consensus.write().await;
            consensus.stop().await?;
        }

        // Stop replication manager
        self.replication.stop().await?;

        // Stop network layer
        self.network.stop().await?;

        tracing::info!(
            "HSM cluster node {} stopped successfully",
            self.config.node_id
        );
        Ok(())
    }

    /// Generate a key pair with cluster replication
    pub async fn distributed_generate_keypair(
        &self,
        algorithm: &str,
        key_size: Option<u32>,
        replicas: Option<usize>,
    ) -> Result<ClusterOperationResult, ClusterError> {
        self.coordinator
            .coordinate_key_generation(
                algorithm,
                key_size,
                replicas.unwrap_or(self.config.replication_config.replica_count),
            )
            .await
    }

    /// Perform distributed signature operation
    pub async fn distributed_sign(
        &self,
        key_handle: u64,
        data: &[u8],
        mechanism: u32,
    ) -> Result<ClusterOperationResult, ClusterError> {
        self.coordinator
            .coordinate_sign_operation(key_handle, data, mechanism)
            .await
    }

    /// Check cluster health and status
    pub async fn get_cluster_status(&self) -> Result<ClusterStatus, ClusterError> {
        let membership_status = self.membership.get_membership_status().await?;
        let consensus_status = {
            let consensus = self.consensus.read().await;
            consensus.get_status().await?
        };
        let replication_status = self.replication.get_replication_status().await?;

        Ok(ClusterStatus {
            node_id: self.config.node_id,
            cluster_size: membership_status.total_nodes,
            healthy_nodes: membership_status.healthy_nodes,
            current_leader: consensus_status.current_leader,
            current_term: consensus_status.current_term,
            replication_lag: replication_status.max_lag,
            metrics: self.get_metrics().await,
        })
    }

    /// Get cluster performance metrics
    pub async fn get_metrics(&self) -> ClusterMetrics {
        ClusterMetrics {
            successful_operations: std::sync::atomic::AtomicU64::new(
                self.metrics
                    .successful_operations
                    .load(std::sync::atomic::Ordering::Relaxed),
            ),
            failed_operations: std::sync::atomic::AtomicU64::new(
                self.metrics
                    .failed_operations
                    .load(std::sync::atomic::Ordering::Relaxed),
            ),
            average_latency_ns: std::sync::atomic::AtomicU64::new(
                self.metrics
                    .average_latency_ns
                    .load(std::sync::atomic::Ordering::Relaxed),
            ),
            leadership_changes: std::sync::atomic::AtomicU64::new(
                self.metrics
                    .leadership_changes
                    .load(std::sync::atomic::Ordering::Relaxed),
            ),
            cluster_size: std::sync::atomic::AtomicUsize::new(
                self.metrics
                    .cluster_size
                    .load(std::sync::atomic::Ordering::Relaxed),
            ),
            network_partitions: std::sync::atomic::AtomicU64::new(
                self.metrics
                    .network_partitions
                    .load(std::sync::atomic::Ordering::Relaxed),
            ),
            replication_lag_ms: std::sync::atomic::AtomicU64::new(
                self.metrics
                    .replication_lag_ms
                    .load(std::sync::atomic::Ordering::Relaxed),
            ),
        }
    }

    // ========================================================================
    // Private helper methods
    // ========================================================================

    /// Join an existing cluster
    async fn join_cluster(&self) -> Result<(), ClusterError> {
        for member in &self.config.initial_members {
            match self.attempt_join_through_node(member).await {
                Ok(_) => {
                    tracing::info!("Successfully joined cluster through node {}", member.id);
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!("Failed to join through node {}: {}", member.id, e);
                    continue;
                }
            }
        }

        Err(ClusterError::NetworkError {
            message: "Failed to join cluster through any initial member".to_string(),
        })
    }

    /// Attempt to join cluster through a specific node
    async fn attempt_join_through_node(&self, node: &NodeInfo) -> Result<(), ClusterError> {
        // Implementation would involve:
        // 1. Establish secure connection to the node
        // 2. Send join request with authentication
        // 3. Receive current cluster configuration
        // 4. Synchronize initial state
        // 5. Start participating in consensus

        // Placeholder implementation
        self.network.connect_to_node(node.clone()).await?;
        self.membership.request_join(node.id).await?;

        Ok(())
    }
}

/// Current status of the cluster
#[derive(Debug, Clone)]
pub struct ClusterStatus {
    /// This node's ID
    pub node_id: NodeId,
    /// Total number of nodes in cluster
    pub cluster_size: usize,
    /// Number of healthy nodes
    pub healthy_nodes: usize,
    /// Current Raft leader
    pub current_leader: Option<NodeId>,
    /// Current Raft term
    pub current_term: Term,
    /// Maximum replication lag across all nodes
    pub replication_lag: Duration,
    /// Performance metrics
    pub metrics: ClusterMetrics,
}
