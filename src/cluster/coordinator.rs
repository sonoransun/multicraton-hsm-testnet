// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company

//! Operation Coordinator for HSM Clustering
//!
//! This module coordinates distributed cryptographic operations across the
//! cluster, ensuring consistency, security, and high availability.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

use crate::cluster::consensus::ConsensusEngine;
use crate::cluster::membership::MembershipManager;
use crate::cluster::replication::ReplicationManager;
use crate::cluster::{
    ClusterConfig, ClusterError, ClusterOperationResult, ConsistencyLevel, NodeId,
    NodeOperationResult, ReplicationStrategy,
};

/// Operation coordinator for distributed HSM operations
pub struct OperationCoordinator {
    /// Cluster configuration
    config: ClusterConfig,
    /// Consensus engine reference
    consensus: Arc<RwLock<dyn ConsensusEngine + Send + Sync>>,
    /// Replication manager reference
    replication: Arc<ReplicationManager>,
    /// Membership manager reference
    membership: Arc<MembershipManager>,
    /// Pending distributed operations
    pending_operations: Arc<Mutex<HashMap<Uuid, PendingOperation>>>,
    /// Operation metrics
    metrics: Arc<CoordinatorMetrics>,
    /// Accepting new operations flag
    accepting_operations: Arc<RwLock<bool>>,
}

/// A pending distributed operation
#[derive(Debug, Clone)]
struct PendingOperation {
    /// Operation ID
    id: Uuid,
    /// Operation type
    operation_type: DistributedOperationType,
    /// Initiator node
    initiator: NodeId,
    /// Target nodes for operation
    target_nodes: HashSet<NodeId>,
    /// Required consistency level
    consistency: ConsistencyLevel,
    /// Timeout for operation
    timeout: Duration,
    /// Operation start time
    started_at: Instant,
    /// Current phase of operation
    current_phase: OperationPhase,
    /// Responses received from nodes
    responses: HashMap<NodeId, OperationResponse>,
    /// Operation context data
    context: OperationContext,
}

/// Types of distributed operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DistributedOperationType {
    /// Key generation across cluster
    KeyGeneration {
        algorithm: String,
        key_size: Option<u32>,
        attributes: HashMap<String, Vec<u8>>,
    },
    /// Distributed signature operation
    DistributedSign {
        key_handle: u64,
        data: Vec<u8>,
        mechanism: u32,
    },
    /// Key replication operation
    KeyReplication {
        source_handle: u64,
        target_nodes: Vec<NodeId>,
    },
    /// Distributed key derivation
    DistributedDerive {
        base_key_handle: u64,
        derivation_params: DerivationParams,
    },
    /// Threshold signature operation
    ThresholdSign {
        threshold: usize,
        total_shares: usize,
        key_handles: Vec<u64>,
        data: Vec<u8>,
    },
    /// Distributed key backup
    KeyBackup {
        key_handles: Vec<u64>,
        backup_destination: BackupDestination,
    },
}

/// Key derivation parameters for distributed operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerivationParams {
    /// Derivation mechanism
    pub mechanism: String,
    /// Derivation data
    pub data: Vec<u8>,
    /// Additional parameters
    pub params: HashMap<String, Vec<u8>>,
}

/// Backup destination for key backup operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BackupDestination {
    /// Backup to cluster nodes
    ClusterNodes { node_count: usize },
    /// Backup to external storage
    ExternalStorage {
        endpoint: String,
        credentials: Vec<u8>,
    },
    /// Backup to offline storage
    OfflineStorage { identifier: String },
}

/// Phases of a distributed operation
#[derive(Debug, Clone, PartialEq, Eq)]
enum OperationPhase {
    /// Initializing operation
    Initializing,
    /// Waiting for consensus
    Consensus,
    /// Executing on nodes
    Execution,
    /// Committing results
    Commit,
    /// Operation completed
    Completed,
    /// Operation failed
    Failed,
    /// Operation aborted
    Aborted,
}

/// Response from a node for an operation
#[derive(Debug, Clone)]
struct OperationResponse {
    /// Node that sent the response
    node_id: NodeId,
    /// Response success status
    success: bool,
    /// Response data
    data: Vec<u8>,
    /// Error message if failed
    error: Option<String>,
    /// Response timestamp
    timestamp: SystemTime,
    /// Response latency
    latency: Duration,
}

/// Operation context data
#[derive(Debug, Clone)]
struct OperationContext {
    /// Operation-specific data
    data: HashMap<String, Vec<u8>>,
    /// Security context
    security: SecurityContext,
    /// Performance tracking
    performance: PerformanceContext,
}

/// Security context for operations
#[derive(Debug, Clone)]
struct SecurityContext {
    /// Required permissions
    required_permissions: Vec<String>,
    /// Access policy
    access_policy: String,
    /// Audit requirements
    audit_level: AuditLevel,
    /// Encryption requirements
    encryption_level: EncryptionLevel,
}

/// Performance tracking context
#[derive(Debug, Clone, Default)]
struct PerformanceContext {
    /// Phase timings
    phase_timings: HashMap<String, Duration>,
    /// Network round trips
    network_round_trips: u32,
    /// Data transferred (bytes)
    bytes_transferred: u64,
}

/// Audit level requirements
#[derive(Debug, Clone, PartialEq, Eq)]
enum AuditLevel {
    /// No special audit requirements
    None,
    /// Standard audit logging
    Standard,
    /// Enhanced audit with full traceability
    Enhanced,
    /// Compliance-grade audit
    Compliance,
}

/// Encryption level requirements
#[derive(Debug, Clone, PartialEq, Eq)]
enum EncryptionLevel {
    /// Standard encryption
    Standard,
    /// Enhanced encryption
    Enhanced,
    /// FIPS-compliant encryption
    Fips,
    /// Custom encryption requirements
    Custom(String),
}

/// Coordinator performance metrics
#[derive(Debug, Default)]
pub struct CoordinatorMetrics {
    /// Total operations coordinated
    pub total_operations: std::sync::atomic::AtomicU64,
    /// Successful operations
    pub successful_operations: std::sync::atomic::AtomicU64,
    /// Failed operations
    pub failed_operations: std::sync::atomic::AtomicU64,
    /// Average operation latency (nanoseconds)
    pub avg_operation_latency_ns: std::sync::atomic::AtomicU64,
    /// Operations by type
    pub operations_by_type: Arc<Mutex<HashMap<String, u64>>>,
    /// Current pending operations
    pub pending_operations_count: std::sync::atomic::AtomicU64,
}

impl OperationCoordinator {
    /// Create new operation coordinator
    pub async fn new(
        config: ClusterConfig,
        consensus: Arc<RwLock<dyn ConsensusEngine + Send + Sync>>,
        replication: Arc<ReplicationManager>,
        membership: Arc<MembershipManager>,
    ) -> Result<Self, ClusterError> {
        Ok(Self {
            config,
            consensus,
            replication,
            membership,
            pending_operations: Arc::new(Mutex::new(HashMap::new())),
            metrics: Arc::new(CoordinatorMetrics::default()),
            accepting_operations: Arc::new(RwLock::new(true)),
        })
    }

    /// Coordinate distributed key generation
    pub async fn coordinate_key_generation(
        &self,
        algorithm: &str,
        key_size: Option<u32>,
        replica_count: usize,
    ) -> Result<ClusterOperationResult, ClusterError> {
        let operation_id = Uuid::new_v4();
        let start_time = Instant::now();

        tracing::info!(
            "Starting distributed key generation: {} {:?}",
            algorithm,
            key_size
        );

        // Check if we're accepting operations
        if !*self.accepting_operations.read().await {
            return Err(ClusterError::OperationRejected {
                reason: "Coordinator not accepting operations".to_string(),
            });
        }

        // Select target nodes for key generation
        let target_nodes = self.select_target_nodes(replica_count).await?;

        // Create operation context
        let operation = PendingOperation {
            id: operation_id,
            operation_type: DistributedOperationType::KeyGeneration {
                algorithm: algorithm.to_string(),
                key_size,
                attributes: HashMap::new(),
            },
            initiator: self.config.node_id,
            target_nodes: target_nodes.clone(),
            consistency: ConsistencyLevel::Quorum,
            timeout: Duration::from_secs(30),
            started_at: start_time,
            current_phase: OperationPhase::Initializing,
            responses: HashMap::new(),
            context: OperationContext {
                data: HashMap::new(),
                security: SecurityContext {
                    required_permissions: vec!["key_generation".to_string()],
                    access_policy: "default".to_string(),
                    audit_level: AuditLevel::Standard,
                    encryption_level: EncryptionLevel::Standard,
                },
                performance: PerformanceContext::default(),
            },
        };

        // Add to pending operations
        {
            let mut pending = self.pending_operations.lock().await;
            pending.insert(operation_id, operation);
        }

        // Execute distributed operation
        let result = self.execute_distributed_operation(operation_id).await?;

        // Clean up
        {
            let mut pending = self.pending_operations.lock().await;
            pending.remove(&operation_id);
        }

        // Update metrics
        self.update_operation_metrics(&result, start_time.elapsed())
            .await;

        tracing::info!(
            "Completed distributed key generation in {:?}",
            start_time.elapsed()
        );

        Ok(result)
    }

    /// Coordinate distributed signature operation
    pub async fn coordinate_sign_operation(
        &self,
        key_handle: u64,
        data: &[u8],
        mechanism: u32,
    ) -> Result<ClusterOperationResult, ClusterError> {
        let operation_id = Uuid::new_v4();
        let start_time = Instant::now();

        tracing::info!("Starting distributed sign operation for key {}", key_handle);

        // Check if we're accepting operations
        if !*self.accepting_operations.read().await {
            return Err(ClusterError::OperationRejected {
                reason: "Coordinator not accepting operations".to_string(),
            });
        }

        // Find nodes that have this key
        let key_nodes = self.find_key_replicas(key_handle).await?;
        if key_nodes.is_empty() {
            return Err(ClusterError::InsufficientReplicas {
                required: 1,
                available: 0,
            });
        }

        // Create operation
        let operation = PendingOperation {
            id: operation_id,
            operation_type: DistributedOperationType::DistributedSign {
                key_handle,
                data: data.to_vec(),
                mechanism,
            },
            initiator: self.config.node_id,
            target_nodes: key_nodes,
            consistency: ConsistencyLevel::One, // Only need one signature
            timeout: Duration::from_secs(10),
            started_at: start_time,
            current_phase: OperationPhase::Initializing,
            responses: HashMap::new(),
            context: OperationContext {
                data: HashMap::new(),
                security: SecurityContext {
                    required_permissions: vec!["sign".to_string()],
                    access_policy: "default".to_string(),
                    audit_level: AuditLevel::Enhanced, // Enhanced audit for signatures
                    encryption_level: EncryptionLevel::Standard,
                },
                performance: PerformanceContext::default(),
            },
        };

        // Add to pending operations
        {
            let mut pending = self.pending_operations.lock().await;
            pending.insert(operation_id, operation);
        }

        // Execute operation
        let result = self.execute_distributed_operation(operation_id).await?;

        // Clean up
        {
            let mut pending = self.pending_operations.lock().await;
            pending.remove(&operation_id);
        }

        // Update metrics
        self.update_operation_metrics(&result, start_time.elapsed())
            .await;

        tracing::info!(
            "Completed distributed sign operation in {:?}",
            start_time.elapsed()
        );

        Ok(result)
    }

    /// Coordinate threshold signature operation
    pub async fn coordinate_threshold_sign(
        &self,
        threshold: usize,
        total_shares: usize,
        key_handles: Vec<u64>,
        data: &[u8],
    ) -> Result<ClusterOperationResult, ClusterError> {
        let operation_id = Uuid::new_v4();
        let start_time = Instant::now();

        tracing::info!(
            "Starting threshold signature: {}/{} shares for {} keys",
            threshold,
            total_shares,
            key_handles.len()
        );

        // Validate threshold parameters
        if threshold > total_shares || threshold == 0 {
            return Err(ClusterError::ConfigurationError {
                message: format!("Invalid threshold: {}/{}", threshold, total_shares),
            });
        }

        if key_handles.len() < total_shares {
            return Err(ClusterError::InsufficientReplicas {
                required: total_shares,
                available: key_handles.len(),
            });
        }

        // Find nodes with key shares
        let mut share_nodes = HashSet::new();
        for &handle in &key_handles {
            let nodes = self.find_key_replicas(handle).await?;
            share_nodes.extend(nodes);
        }

        // Ensure we have enough nodes for threshold
        if share_nodes.len() < threshold {
            return Err(ClusterError::InsufficientReplicas {
                required: threshold,
                available: share_nodes.len(),
            });
        }

        // Create threshold operation
        let operation = PendingOperation {
            id: operation_id,
            operation_type: DistributedOperationType::ThresholdSign {
                threshold,
                total_shares,
                key_handles,
                data: data.to_vec(),
            },
            initiator: self.config.node_id,
            target_nodes: share_nodes,
            consistency: ConsistencyLevel::Custom(threshold), // Need threshold responses
            timeout: Duration::from_secs(30),
            started_at: start_time,
            current_phase: OperationPhase::Initializing,
            responses: HashMap::new(),
            context: OperationContext {
                data: HashMap::new(),
                security: SecurityContext {
                    required_permissions: vec!["threshold_sign".to_string()],
                    access_policy: "threshold".to_string(),
                    audit_level: AuditLevel::Compliance, // Highest audit level
                    encryption_level: EncryptionLevel::Enhanced,
                },
                performance: PerformanceContext::default(),
            },
        };

        // Add to pending operations
        {
            let mut pending = self.pending_operations.lock().await;
            pending.insert(operation_id, operation);
        }

        // Execute threshold operation
        let result = self.execute_threshold_operation(operation_id).await?;

        // Clean up
        {
            let mut pending = self.pending_operations.lock().await;
            pending.remove(&operation_id);
        }

        // Update metrics
        self.update_operation_metrics(&result, start_time.elapsed())
            .await;

        tracing::info!(
            "Completed threshold signature in {:?}",
            start_time.elapsed()
        );

        Ok(result)
    }

    /// Stop accepting new operations
    pub async fn stop_accepting_operations(&self) -> Result<(), ClusterError> {
        *self.accepting_operations.write().await = false;

        // Wait for pending operations to complete
        let max_wait = Duration::from_secs(60);
        let start = Instant::now();

        while start.elapsed() < max_wait {
            let pending_count = {
                let pending = self.pending_operations.lock().await;
                pending.len()
            };

            if pending_count == 0 {
                break;
            }

            tracing::info!(
                "Waiting for {} pending operations to complete",
                pending_count
            );
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        Ok(())
    }

    /// Get coordinator metrics
    pub async fn get_metrics(&self) -> CoordinatorMetrics {
        let operations_by_type = {
            let ops = self.metrics.operations_by_type.lock().await;
            ops.clone()
        };

        CoordinatorMetrics {
            total_operations: std::sync::atomic::AtomicU64::new(
                self.metrics
                    .total_operations
                    .load(std::sync::atomic::Ordering::Relaxed),
            ),
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
            avg_operation_latency_ns: std::sync::atomic::AtomicU64::new(
                self.metrics
                    .avg_operation_latency_ns
                    .load(std::sync::atomic::Ordering::Relaxed),
            ),
            operations_by_type: Arc::new(Mutex::new(operations_by_type)),
            pending_operations_count: std::sync::atomic::AtomicU64::new(
                self.metrics
                    .pending_operations_count
                    .load(std::sync::atomic::Ordering::Relaxed),
            ),
        }
    }

    // ========================================================================
    // Private helper methods
    // ========================================================================

    /// Select target nodes for an operation
    async fn select_target_nodes(&self, count: usize) -> Result<HashSet<NodeId>, ClusterError> {
        let healthy_nodes = self.membership.get_healthy_voting_nodes().await?;

        if healthy_nodes.len() < count {
            return Err(ClusterError::InsufficientReplicas {
                required: count,
                available: healthy_nodes.len(),
            });
        }

        // Select nodes using round-robin or other strategy
        let selected: HashSet<NodeId> = healthy_nodes
            .into_iter()
            .take(count)
            .map(|node| node.id)
            .collect();

        Ok(selected)
    }

    /// Find nodes that have replicas of a key
    async fn find_key_replicas(&self, _key_handle: u64) -> Result<HashSet<NodeId>, ClusterError> {
        // This would query the replication manager to find which nodes have the key
        // For now, return all healthy nodes
        let healthy_nodes = self.membership.get_healthy_voting_nodes().await?;
        let node_ids = healthy_nodes.into_iter().map(|node| node.id).collect();
        Ok(node_ids)
    }

    /// Execute a distributed operation
    async fn execute_distributed_operation(
        &self,
        operation_id: Uuid,
    ) -> Result<ClusterOperationResult, ClusterError> {
        // Implementation would:
        // 1. Get consensus on operation
        // 2. Send requests to target nodes
        // 3. Collect responses
        // 4. Apply consistency rules
        // 5. Return result

        // Simplified mock implementation
        tokio::time::sleep(Duration::from_millis(100)).await;

        Ok(ClusterOperationResult {
            success: true,
            nodes_confirmed: 3,
            total_nodes: 3,
            latency: Duration::from_millis(100),
            node_responses: HashMap::new(),
        })
    }

    /// Execute a threshold operation
    async fn execute_threshold_operation(
        &self,
        operation_id: Uuid,
    ) -> Result<ClusterOperationResult, ClusterError> {
        // Implementation would:
        // 1. Coordinate threshold signature protocol
        // 2. Collect partial signatures from nodes
        // 3. Combine signatures when threshold is reached
        // 4. Return combined result

        // Simplified mock implementation
        tokio::time::sleep(Duration::from_millis(200)).await;

        Ok(ClusterOperationResult {
            success: true,
            nodes_confirmed: 2, // Threshold reached
            total_nodes: 3,
            latency: Duration::from_millis(200),
            node_responses: HashMap::new(),
        })
    }

    /// Update operation metrics
    async fn update_operation_metrics(&self, result: &ClusterOperationResult, duration: Duration) {
        self.metrics
            .total_operations
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        if result.success {
            self.metrics
                .successful_operations
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else {
            self.metrics
                .failed_operations
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }

        // Update average latency
        let latency_ns = duration.as_nanos() as u64;
        let current_avg = self
            .metrics
            .avg_operation_latency_ns
            .load(std::sync::atomic::Ordering::Relaxed);
        let new_avg = if current_avg == 0 {
            latency_ns
        } else {
            (current_avg * 15 + latency_ns) / 16 // Exponential moving average
        };
        self.metrics
            .avg_operation_latency_ns
            .store(new_avg, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Extended consistency level for threshold operations
impl ConsistencyLevel {
    /// Custom consistency level with specific count
    const fn Custom(count: usize) -> Self {
        // This is a placeholder - actual implementation would extend the enum
        ConsistencyLevel::Quorum
    }
}

/// Extended cluster error for coordinator
impl ClusterError {
    /// Operation was rejected
    pub fn operation_rejected(reason: String) -> Self {
        ClusterError::ConfigurationError { message: reason }
    }
}
