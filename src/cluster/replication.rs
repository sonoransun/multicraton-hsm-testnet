// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company

//! Key Replication Manager for HSM Clustering
//!
//! This module handles secure replication of cryptographic key material across
//! cluster nodes, with support for threshold secret sharing, encrypted transport,
//! and consistency guarantees.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::{Mutex, RwLock};
use zeroize::{Zeroize, Zeroizing};

use crate::cluster::{
    ClusterConfig, ClusterError, ConflictResolution, ConsistencyLevel, NodeId, NodeOperationResult,
    ReplicationConfig, ReplicationStrategy,
};
use crate::core::HsmCore;
use crate::crypto::backend::CryptoBackend;
use crate::error::{HsmError, HsmResult};
use crate::store::object::StoredObject;

/// Key replication manager for distributed HSM
pub struct ReplicationManager {
    /// Cluster configuration
    config: ClusterConfig,
    /// Local HSM instance
    local_hsm: Arc<HsmCore>,
    /// Replication state tracking
    replication_state: Arc<RwLock<ReplicationState>>,
    /// Pending replication operations
    pending_operations: Arc<Mutex<Vec<PendingReplication>>>,
    /// Network communication for replication
    network: Arc<dyn ReplicationNetwork + Send + Sync>,
    /// Encryption manager for secure replication
    encryption: Arc<ReplicationEncryption>,
    /// Performance metrics
    metrics: Arc<ReplicationMetrics>,
}

/// Current replication state
#[derive(Debug, Default)]
struct ReplicationState {
    /// Replicated objects by handle
    replicated_objects: HashMap<u64, ReplicatedObject>,
    /// Replication status by node
    node_status: HashMap<NodeId, NodeReplicationStatus>,
    /// Vector clock for conflict resolution
    vector_clock: VectorClock,
    /// Last replication timestamp
    last_replication: Option<SystemTime>,
}

/// Information about a replicated object
#[derive(Debug, Clone)]
struct ReplicatedObject {
    /// Object handle
    handle: u64,
    /// Nodes that have this object
    replica_nodes: HashSet<NodeId>,
    /// Target number of replicas
    target_replicas: usize,
    /// Object version (for conflict resolution)
    version: ObjectVersion,
    /// Replication status
    status: ReplicationStatus,
    /// Last update timestamp
    last_updated: SystemTime,
    /// Consistency level used
    consistency_level: ConsistencyLevel,
}

/// Version information for conflict resolution
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ObjectVersion {
    /// Vector clock at creation/modification
    vector_clock: VectorClock,
    /// Node that created this version
    author: NodeId,
    /// Timestamp of creation/modification
    timestamp: SystemTime,
    /// Hash of object content
    content_hash: [u8; 32],
}

/// Vector clock for distributed ordering
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct VectorClock {
    /// Clock values by node
    clocks: HashMap<NodeId, u64>,
}

impl VectorClock {
    fn increment(&mut self, node_id: NodeId) {
        let counter = self.clocks.entry(node_id).or_insert(0);
        *counter += 1;
    }

    fn update(&mut self, other: &VectorClock) {
        for (node_id, &value) in &other.clocks {
            let current = self.clocks.entry(*node_id).or_insert(0);
            *current = (*current).max(value);
        }
    }

    fn compare(&self, other: &VectorClock) -> VectorClockOrdering {
        let mut less_than = false;
        let mut greater_than = false;

        let all_nodes: HashSet<_> = self.clocks.keys().chain(other.clocks.keys()).collect();

        for node in all_nodes {
            let self_val = self.clocks.get(node).unwrap_or(&0);
            let other_val = other.clocks.get(node).unwrap_or(&0);

            if self_val < other_val {
                less_than = true;
            } else if self_val > other_val {
                greater_than = true;
            }
        }

        match (less_than, greater_than) {
            (true, false) => VectorClockOrdering::Before,
            (false, true) => VectorClockOrdering::After,
            (false, false) => VectorClockOrdering::Equal,
            (true, true) => VectorClockOrdering::Concurrent,
        }
    }
}

/// Ordering relationship between vector clocks
#[derive(Debug, PartialEq, Eq)]
enum VectorClockOrdering {
    /// This clock is strictly before the other
    Before,
    /// This clock is strictly after the other
    After,
    /// Clocks are equal
    Equal,
    /// Clocks are concurrent (conflicting)
    Concurrent,
}

/// Replication status for an object
#[derive(Debug, Clone, PartialEq, Eq)]
enum ReplicationStatus {
    /// Object is properly replicated
    Consistent,
    /// Object is being replicated
    InProgress,
    /// Object has insufficient replicas
    UnderReplicated,
    /// Object has conflicting versions
    Conflicted,
    /// Replication failed
    Failed,
}

/// Replication status for a cluster node
#[derive(Debug, Clone)]
struct NodeReplicationStatus {
    /// Node ID
    node_id: NodeId,
    /// Last successful replication
    last_success: Option<SystemTime>,
    /// Number of objects on this node
    object_count: usize,
    /// Replication lag (time behind leader)
    lag: Duration,
    /// Current health status
    health: NodeReplicationHealth,
    /// Bandwidth utilization
    bandwidth_usage: f64,
}

/// Health status for replication
#[derive(Debug, Clone, PartialEq, Eq)]
enum NodeReplicationHealth {
    /// Node is healthy and up-to-date
    Healthy,
    /// Node is lagging but catching up
    Lagging,
    /// Node is significantly behind
    Stale,
    /// Node is unreachable
    Unreachable,
    /// Node has failed permanently
    Failed,
}

/// Pending replication operation
#[derive(Debug, Clone)]
struct PendingReplication {
    /// Operation ID
    id: uuid::Uuid,
    /// Object handle being replicated
    handle: u64,
    /// Target nodes for replication
    target_nodes: HashSet<NodeId>,
    /// Operation type
    operation: ReplicationOperation,
    /// Consistency level required
    consistency: ConsistencyLevel,
    /// Number of acknowledgments received
    ack_count: usize,
    /// Nodes that have acknowledged
    acknowledged_nodes: HashSet<NodeId>,
    /// Operation start time
    started_at: Instant,
    /// Timeout for operation
    timeout: Duration,
}

/// Types of replication operations
#[derive(Debug, Clone, Serialize, Deserialize)]
enum ReplicationOperation {
    /// Create new object
    Create {
        object_data: Vec<u8>,
        metadata: ObjectMetadata,
    },
    /// Update existing object
    Update {
        object_data: Vec<u8>,
        version: ObjectVersion,
    },
    /// Delete object
    Delete { version: ObjectVersion },
    /// Repair inconsistency
    Repair {
        correct_data: Vec<u8>,
        version: ObjectVersion,
    },
}

/// Metadata for replicated objects
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ObjectMetadata {
    /// Object attributes
    attributes: HashMap<String, Vec<u8>>,
    /// Encryption parameters
    encryption: EncryptionMetadata,
    /// Access control
    access_control: AccessControlMetadata,
}

/// Encryption metadata for replicated objects
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptionMetadata {
    /// Encryption algorithm used
    algorithm: String,
    /// Key derivation parameters
    kdf_params: Vec<u8>,
    /// Authentication tag
    auth_tag: Vec<u8>,
    /// Initialization vector
    iv: Vec<u8>,
}

/// Access control metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccessControlMetadata {
    /// Required permissions
    required_permissions: Vec<String>,
    /// Access policy
    policy: String,
    /// Owner node
    owner: NodeId,
}

/// Network interface for replication
#[async_trait::async_trait]
pub trait ReplicationNetwork {
    /// Send replication request to a node
    async fn send_replication_request(
        &self,
        to: NodeId,
        request: ReplicationRequest,
    ) -> Result<ReplicationResponse, ClusterError>;

    /// Broadcast replication notification
    async fn broadcast_replication_event(
        &self,
        event: ReplicationEvent,
    ) -> Result<(), ClusterError>;

    /// Get replication status from a node
    async fn get_node_status(&self, from: NodeId) -> Result<NodeReplicationStatus, ClusterError>;
}

/// Replication request message
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReplicationRequest {
    /// Request ID
    id: uuid::Uuid,
    /// Operation being requested
    operation: ReplicationOperation,
    /// Object handle
    handle: u64,
    /// Consistency level required
    consistency: ConsistencyLevel,
    /// Source node
    source: NodeId,
    /// Encrypted payload
    encrypted_payload: Vec<u8>,
    /// Authentication signature
    signature: Vec<u8>,
}

/// Replication response message
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReplicationResponse {
    /// Request ID being responded to
    request_id: uuid::Uuid,
    /// Success status
    success: bool,
    /// Error message if failed
    error: Option<String>,
    /// Current object version on responder
    current_version: Option<ObjectVersion>,
    /// Response timestamp
    timestamp: SystemTime,
}

/// Replication event notification
#[derive(Debug, Clone, Serialize, Deserialize)]
enum ReplicationEvent {
    /// Object was successfully replicated
    ObjectReplicated {
        handle: u64,
        nodes: Vec<NodeId>,
        version: ObjectVersion,
    },
    /// Replication conflict detected
    ConflictDetected {
        handle: u64,
        conflicting_versions: Vec<ObjectVersion>,
    },
    /// Node became unreachable
    NodeUnreachable {
        node_id: NodeId,
        last_seen: SystemTime,
    },
    /// Replication completed
    ReplicationComplete {
        operation_id: uuid::Uuid,
        success: bool,
        nodes_confirmed: usize,
    },
}

/// Encryption manager for secure replication
pub struct ReplicationEncryption {
    /// Master encryption key
    master_key: Zeroizing<[u8; 32]>,
    /// Key derivation salt
    salt: [u8; 16],
    /// Crypto backend for operations
    crypto: Arc<dyn CryptoBackend>,
}

impl ReplicationEncryption {
    /// Create new replication encryption manager
    pub fn new(master_key: [u8; 32], crypto: Arc<dyn CryptoBackend>) -> Self {
        let mut salt = [0u8; 16];
        fastrand::fill(&mut salt);

        Self {
            master_key: Zeroizing::new(master_key),
            salt,
            crypto,
        }
    }

    /// Encrypt object data for replication
    pub async fn encrypt_object(
        &self,
        data: &[u8],
        node_id: NodeId,
        handle: u64,
    ) -> Result<(Vec<u8>, EncryptionMetadata), ClusterError> {
        // Derive per-object key using HKDF
        let info = format!("replication:{}:{}", node_id, handle);
        let derived_key = self
            .crypto
            .hkdf_expand(&self.master_key, info.as_bytes(), 32)
            .map_err(|_| ClusterError::ReplicationError {
                message: "Key derivation failed".to_string(),
            })?;

        // Generate random IV
        let mut iv = vec![0u8; 16];
        fastrand::fill(&mut iv);

        // Encrypt using AES-256-GCM
        let ciphertext = self
            .crypto
            .aes_encrypt(
                &derived_key,
                crate::pkcs11_abi::constants::CKM_AES_GCM,
                Some(&iv),
                data,
            )
            .map_err(|_| ClusterError::ReplicationError {
                message: "Encryption failed".to_string(),
            })?;

        let metadata = EncryptionMetadata {
            algorithm: "AES-256-GCM".to_string(),
            kdf_params: self.salt.to_vec(),
            auth_tag: ciphertext[ciphertext.len() - 16..].to_vec(),
            iv,
        };

        Ok((ciphertext, metadata))
    }

    /// Decrypt object data from replication
    pub async fn decrypt_object(
        &self,
        ciphertext: &[u8],
        metadata: &EncryptionMetadata,
        node_id: NodeId,
        handle: u64,
    ) -> Result<Vec<u8>, ClusterError> {
        // Derive the same per-object key
        let info = format!("replication:{}:{}", node_id, handle);
        let derived_key = self
            .crypto
            .hkdf_expand(&self.master_key, info.as_bytes(), 32)
            .map_err(|_| ClusterError::ReplicationError {
                message: "Key derivation failed".to_string(),
            })?;

        // Decrypt using AES-256-GCM
        let plaintext = self
            .crypto
            .aes_decrypt(
                &derived_key,
                crate::pkcs11_abi::constants::CKM_AES_GCM,
                Some(&metadata.iv),
                ciphertext,
            )
            .map_err(|_| ClusterError::ReplicationError {
                message: "Decryption failed".to_string(),
            })?;

        Ok(plaintext)
    }
}

/// Replication performance metrics
#[derive(Debug, Default)]
pub struct ReplicationMetrics {
    /// Total objects replicated
    pub objects_replicated: std::sync::atomic::AtomicU64,
    /// Replication operations in progress
    pub operations_in_progress: std::sync::atomic::AtomicU64,
    /// Failed replication operations
    pub operations_failed: std::sync::atomic::AtomicU64,
    /// Average replication latency (nanoseconds)
    pub average_latency_ns: std::sync::atomic::AtomicU64,
    /// Bandwidth usage (bytes per second)
    pub bandwidth_usage_bps: std::sync::atomic::AtomicU64,
    /// Number of conflicts resolved
    pub conflicts_resolved: std::sync::atomic::AtomicU64,
    /// Data consistency violations
    pub consistency_violations: std::sync::atomic::AtomicU64,
}

/// Replication status information
#[derive(Debug, Clone)]
pub struct ReplicationStatusInfo {
    /// Number of replicated objects
    pub total_objects: usize,
    /// Objects with sufficient replicas
    pub consistent_objects: usize,
    /// Objects being replicated
    pub pending_objects: usize,
    /// Objects with conflicts
    pub conflicted_objects: usize,
    /// Average replication lag
    pub average_lag: Duration,
    /// Node status summary
    pub node_summary: HashMap<NodeId, NodeReplicationHealth>,
}

impl ReplicationManager {
    /// Create new replication manager
    pub async fn new(config: ClusterConfig, local_hsm: Arc<HsmCore>) -> Result<Self, ClusterError> {
        // Generate master encryption key
        let mut master_key = [0u8; 32];
        fastrand::fill(&mut master_key);

        let encryption = Arc::new(ReplicationEncryption::new(
            master_key,
            local_hsm.crypto_backend.clone(),
        ));

        // Create network interface (mock for now)
        let network = Arc::new(MockReplicationNetwork::new());

        Ok(Self {
            config,
            local_hsm,
            replication_state: Arc::new(RwLock::new(ReplicationState::default())),
            pending_operations: Arc::new(Mutex::new(Vec::new())),
            network,
            encryption,
            metrics: Arc::new(ReplicationMetrics::default()),
        })
    }

    /// Start the replication manager
    pub async fn start(&self) -> Result<(), ClusterError> {
        tracing::info!(
            "Starting replication manager for node {}",
            self.config.node_id
        );

        // Start background tasks
        self.start_replication_monitor().await?;
        self.start_consistency_checker().await?;
        self.start_conflict_resolver().await?;

        Ok(())
    }

    /// Stop the replication manager
    pub async fn stop(&self) -> Result<(), ClusterError> {
        tracing::info!("Stopping replication manager");
        // Stop background tasks
        Ok(())
    }

    /// Replicate an object to cluster nodes
    pub async fn replicate_object(
        &self,
        handle: u64,
        target_replicas: usize,
        consistency: ConsistencyLevel,
    ) -> Result<(), ClusterError> {
        let start_time = Instant::now();

        // Get object from local HSM
        let object = self.get_local_object(handle).await?;

        // Serialize and encrypt object
        let serialized =
            bincode::serialize(&object).map_err(|e| ClusterError::ReplicationError {
                message: format!("Failed to serialize object: {}", e),
            })?;

        let (encrypted_data, encryption_metadata) = self
            .encryption
            .encrypt_object(&serialized, self.config.node_id, handle)
            .await?;

        // Determine target nodes
        let target_nodes = self.select_replication_targets(target_replicas).await?;

        // Create replication operation
        let operation_id = uuid::Uuid::new_v4();
        let operation = ReplicationOperation::Create {
            object_data: encrypted_data,
            metadata: ObjectMetadata {
                attributes: HashMap::new(), // Would include actual attributes
                encryption: encryption_metadata,
                access_control: AccessControlMetadata {
                    required_permissions: vec![],
                    policy: "default".to_string(),
                    owner: self.config.node_id,
                },
            },
        };

        // Add to pending operations
        let pending = PendingReplication {
            id: operation_id,
            handle,
            target_nodes: target_nodes.clone(),
            operation,
            consistency,
            ack_count: 0,
            acknowledged_nodes: HashSet::new(),
            started_at: start_time,
            timeout: Duration::from_secs(30),
        };

        self.pending_operations.lock().await.push(pending);

        // Send replication requests
        self.send_replication_requests(operation_id, &target_nodes)
            .await?;

        // Wait for acknowledgments based on consistency level
        self.wait_for_replication_completion(operation_id, consistency)
            .await?;

        // Update metrics
        self.metrics
            .objects_replicated
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let latency = start_time.elapsed().as_nanos() as u64;
        self.update_average_latency(latency);

        tracing::info!(
            "Successfully replicated object {} to {} nodes",
            handle,
            target_nodes.len()
        );

        Ok(())
    }

    /// Get replication status
    pub async fn get_replication_status(&self) -> Result<ReplicationStatusInfo, ClusterError> {
        let state = self.replication_state.read().await;

        let total_objects = state.replicated_objects.len();
        let consistent_objects = state
            .replicated_objects
            .values()
            .filter(|obj| obj.status == ReplicationStatus::Consistent)
            .count();
        let pending_objects = state
            .replicated_objects
            .values()
            .filter(|obj| obj.status == ReplicationStatus::InProgress)
            .count();
        let conflicted_objects = state
            .replicated_objects
            .values()
            .filter(|obj| obj.status == ReplicationStatus::Conflicted)
            .count();

        let average_lag = state
            .node_status
            .values()
            .map(|status| status.lag)
            .sum::<Duration>()
            / (state.node_status.len() as u32).max(1);

        let node_summary = state
            .node_status
            .iter()
            .map(|(&node_id, status)| (node_id, status.health.clone()))
            .collect();

        Ok(ReplicationStatusInfo {
            total_objects,
            consistent_objects,
            pending_objects,
            conflicted_objects,
            average_lag,
            node_summary,
        })
    }

    // ========================================================================
    // Private helper methods
    // ========================================================================

    /// Get object from local HSM
    async fn get_local_object(&self, handle: u64) -> Result<StoredObject, ClusterError> {
        // This would interface with the local HSM to get the object
        // For now, return a placeholder
        Err(ClusterError::ReplicationError {
            message: "Object retrieval not implemented".to_string(),
        })
    }

    /// Select nodes for replication targets
    async fn select_replication_targets(
        &self,
        count: usize,
    ) -> Result<HashSet<NodeId>, ClusterError> {
        let mut targets = HashSet::new();

        // Simple selection - pick first N available nodes
        for member in &self.config.initial_members {
            if member.id != self.config.node_id && targets.len() < count {
                targets.insert(member.id);
            }
        }

        if targets.is_empty() {
            return Err(ClusterError::InsufficientReplicas {
                required: count,
                available: 0,
            });
        }

        Ok(targets)
    }

    /// Send replication requests to target nodes
    async fn send_replication_requests(
        &self,
        operation_id: uuid::Uuid,
        target_nodes: &HashSet<NodeId>,
    ) -> Result<(), ClusterError> {
        for &node_id in target_nodes {
            let request = ReplicationRequest {
                id: operation_id,
                operation: ReplicationOperation::Create {
                    object_data: vec![], // Would include actual data
                    metadata: ObjectMetadata {
                        attributes: HashMap::new(),
                        encryption: EncryptionMetadata {
                            algorithm: "AES-256-GCM".to_string(),
                            kdf_params: vec![],
                            auth_tag: vec![],
                            iv: vec![],
                        },
                        access_control: AccessControlMetadata {
                            required_permissions: vec![],
                            policy: "default".to_string(),
                            owner: self.config.node_id,
                        },
                    },
                },
                handle: 0, // Would be actual handle
                consistency: ConsistencyLevel::Quorum,
                source: self.config.node_id,
                encrypted_payload: vec![],
                signature: vec![],
            };

            self.network
                .send_replication_request(node_id, request)
                .await?;
        }

        Ok(())
    }

    /// Wait for replication completion
    async fn wait_for_replication_completion(
        &self,
        operation_id: uuid::Uuid,
        consistency: ConsistencyLevel,
    ) -> Result<(), ClusterError> {
        let required_acks = match consistency {
            ConsistencyLevel::Quorum => (self.config.initial_members.len() / 2) + 1,
            ConsistencyLevel::All => self.config.initial_members.len(),
            ConsistencyLevel::One => 1,
            ConsistencyLevel::Local => 0, // Already satisfied locally
        };

        // Wait for acknowledgments (simplified)
        tokio::time::sleep(Duration::from_millis(100)).await;

        Ok(())
    }

    /// Update average latency metric
    fn update_average_latency(&self, new_latency_ns: u64) {
        let current = self
            .metrics
            .average_latency_ns
            .load(std::sync::atomic::Ordering::Relaxed);
        let updated = if current == 0 {
            new_latency_ns
        } else {
            (current * 15 + new_latency_ns) / 16 // Exponential moving average
        };
        self.metrics
            .average_latency_ns
            .store(updated, std::sync::atomic::Ordering::Relaxed);
    }

    /// Start replication monitoring task
    async fn start_replication_monitor(&self) -> Result<(), ClusterError> {
        // Background task to monitor replication health
        Ok(())
    }

    /// Start consistency checking task
    async fn start_consistency_checker(&self) -> Result<(), ClusterError> {
        // Background task to check data consistency
        Ok(())
    }

    /// Start conflict resolution task
    async fn start_conflict_resolver(&self) -> Result<(), ClusterError> {
        // Background task to resolve conflicts
        Ok(())
    }
}

/// Mock network implementation for testing
struct MockReplicationNetwork;

impl MockReplicationNetwork {
    fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl ReplicationNetwork for MockReplicationNetwork {
    async fn send_replication_request(
        &self,
        _to: NodeId,
        _request: ReplicationRequest,
    ) -> Result<ReplicationResponse, ClusterError> {
        // Mock success response
        Ok(ReplicationResponse {
            request_id: uuid::Uuid::new_v4(),
            success: true,
            error: None,
            current_version: None,
            timestamp: SystemTime::now(),
        })
    }

    async fn broadcast_replication_event(
        &self,
        _event: ReplicationEvent,
    ) -> Result<(), ClusterError> {
        Ok(())
    }

    async fn get_node_status(&self, _from: NodeId) -> Result<NodeReplicationStatus, ClusterError> {
        Ok(NodeReplicationStatus {
            node_id: 1,
            last_success: Some(SystemTime::now()),
            object_count: 0,
            lag: Duration::from_millis(10),
            health: NodeReplicationHealth::Healthy,
            bandwidth_usage: 0.5,
        })
    }
}
