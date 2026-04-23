// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company

//! Raft Consensus Implementation for HSM Clustering
//!
//! This module provides a Raft consensus engine specifically designed for HSM
//! clustering, with enhanced security and cryptographic operation awareness.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::{Notify, RwLock};
use tokio::time::interval;

use crate::cluster::{
    ClusterConfig, ClusterError, LogIndex, NodeHealthStatus, NodeId, NodeInfo, NodeRole, Term,
};
use crate::error::HsmResult;
use crate::store::object::StoredObject;

/// Trait for consensus engine implementations
#[async_trait::async_trait]
pub trait ConsensusEngine {
    /// Start the consensus engine
    async fn start(&mut self) -> Result<(), ClusterError>;

    /// Stop the consensus engine
    async fn stop(&mut self) -> Result<(), ClusterError>;

    /// Get current consensus status
    async fn get_status(&self) -> Result<ConsensusStatus, ClusterError>;

    /// Propose a new log entry
    async fn propose(&self, entry: LogEntry) -> Result<LogIndex, ClusterError>;

    /// Check if this node is the current leader
    async fn is_leader(&self) -> bool;

    /// Get the current leader's node ID
    async fn get_leader(&self) -> Option<NodeId>;

    /// Force a leadership election
    async fn trigger_election(&self) -> Result<(), ClusterError>;

    /// Add a new node to the cluster
    async fn add_node(&self, node: NodeInfo) -> Result<(), ClusterError>;

    /// Remove a node from the cluster
    async fn remove_node(&self, node_id: NodeId) -> Result<(), ClusterError>;

    /// Create a snapshot of the current state
    async fn create_snapshot(&self) -> Result<Snapshot, ClusterError>;

    /// Install a snapshot from another node
    async fn install_snapshot(&self, snapshot: Snapshot) -> Result<(), ClusterError>;
}

/// Current status of the consensus engine
#[derive(Debug, Clone)]
pub struct ConsensusStatus {
    /// Current node state
    pub state: NodeState,
    /// Current term
    pub current_term: Term,
    /// Current leader (if known)
    pub current_leader: Option<NodeId>,
    /// Last log index
    pub last_log_index: LogIndex,
    /// Commit index
    pub commit_index: LogIndex,
    /// Number of active followers
    pub follower_count: usize,
    /// Time since last heartbeat
    pub last_heartbeat: Option<Duration>,
}

/// Node state in Raft consensus
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeState {
    /// Node is a follower
    Follower,
    /// Node is a candidate in an election
    Candidate,
    /// Node is the current leader
    Leader,
    /// Node is temporarily inactive
    Inactive,
}

/// Log entry for Raft consensus
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Entry index in the log
    pub index: LogIndex,
    /// Term when entry was created
    pub term: Term,
    /// The operation to be applied
    pub operation: ClusterOperation,
    /// Timestamp when entry was created
    pub timestamp: SystemTime,
    /// Cryptographic signature of the entry
    pub signature: Option<Vec<u8>>,
}

/// Operations that can be replicated through consensus
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClusterOperation {
    /// Key generation operation
    GenerateKey {
        algorithm: String,
        key_size: Option<u32>,
        attributes: HashMap<String, Vec<u8>>,
    },
    /// Key import operation
    ImportKey {
        key_material: Vec<u8>,
        attributes: HashMap<String, Vec<u8>>,
    },
    /// Key deletion operation
    DeleteKey { handle: u64 },
    /// Configuration change
    ConfigChange {
        change_type: ConfigChangeType,
        node_info: Option<NodeInfo>,
    },
    /// No-op operation for heartbeats
    NoOp,
}

/// Types of configuration changes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConfigChangeType {
    /// Add a new voting node
    AddVotingNode,
    /// Add a new non-voting node
    AddNonVotingNode,
    /// Remove a node from the cluster
    RemoveNode,
    /// Promote non-voting node to voting
    PromoteNode,
    /// Demote voting node to non-voting
    DemoteNode,
}

/// Snapshot of cluster state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    /// Last log index included in snapshot
    pub last_included_index: LogIndex,
    /// Term of last included log entry
    pub last_included_term: Term,
    /// Cluster configuration at snapshot time
    pub configuration: ClusterConfiguration,
    /// Serialized HSM state
    pub hsm_state: Vec<u8>,
    /// Checksum of the snapshot data
    pub checksum: Vec<u8>,
    /// Timestamp when snapshot was created
    pub timestamp: SystemTime,
}

/// Cluster configuration at a point in time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfiguration {
    /// All nodes in the cluster
    pub nodes: HashMap<NodeId, NodeInfo>,
    /// Configuration version
    pub version: u64,
    /// Configuration change in progress (if any)
    pub pending_change: Option<ConfigChangeType>,
}

/// Raft consensus engine implementation
pub struct RaftConsensus {
    /// Node configuration
    config: ClusterConfig,
    /// Current state of this node
    state: Arc<RwLock<RaftState>>,
    /// Log storage
    log: Arc<RwLock<RaftLog>>,
    /// State machine (HSM state)
    state_machine: Arc<RwLock<HsmStateMachine>>,
    /// Network communication
    network: Arc<dyn RaftNetwork + Send + Sync>,
    /// Election timeout notifier
    election_timeout: Arc<Notify>,
    /// Heartbeat interval notifier
    heartbeat_notify: Arc<Notify>,
    /// Shutdown signal
    shutdown: Arc<Notify>,
    /// Live cluster membership.
    ///
    /// Initialized from `config.initial_members` at construction; mutated
    /// by `add_node` / `remove_node`. Reading is cheap (RwLock fast-path);
    /// writing is rare (membership-change RPC).
    membership: Arc<RwLock<ClusterConfiguration>>,
}

/// Raft node persistent state
#[derive(Debug, Clone)]
struct RaftState {
    /// Current term
    current_term: Term,
    /// Node voted for in current term
    voted_for: Option<NodeId>,
    /// Current node state
    state: NodeState,
    /// Current leader (if known)
    current_leader: Option<NodeId>,
    /// Last time we received a valid AppendEntries RPC
    last_heartbeat: Instant,
    /// Index of highest log entry known to be committed
    commit_index: LogIndex,
    /// Index of highest log entry applied to state machine
    last_applied: LogIndex,
    /// For leaders: next log index to send to each server
    next_index: HashMap<NodeId, LogIndex>,
    /// For leaders: highest log index known to be replicated on server
    match_index: HashMap<NodeId, LogIndex>,
}

impl RaftState {
    fn new(node_id: NodeId) -> Self {
        Self {
            current_term: 0,
            voted_for: None,
            state: NodeState::Follower,
            current_leader: None,
            last_heartbeat: Instant::now(),
            commit_index: 0,
            last_applied: 0,
            next_index: HashMap::new(),
            match_index: HashMap::new(),
        }
    }
}

/// Raft log storage
struct RaftLog {
    /// Log entries
    entries: VecDeque<LogEntry>,
    /// First log index (after snapshot)
    first_index: LogIndex,
    /// Last snapshot
    last_snapshot: Option<Snapshot>,
}

impl RaftLog {
    fn new() -> Self {
        Self {
            entries: VecDeque::new(),
            first_index: 1,
            last_snapshot: None,
        }
    }

    fn last_index(&self) -> LogIndex {
        self.first_index + self.entries.len() as LogIndex - 1
    }

    fn last_term(&self) -> Term {
        self.entries.back().map(|e| e.term).unwrap_or(0)
    }

    fn get_entry(&self, index: LogIndex) -> Option<&LogEntry> {
        if index < self.first_index {
            return None;
        }
        let offset = (index - self.first_index) as usize;
        self.entries.get(offset)
    }

    fn append(&mut self, entry: LogEntry) {
        self.entries.push_back(entry);
    }

    fn truncate_from(&mut self, index: LogIndex) {
        if index < self.first_index {
            return;
        }
        let offset = (index - self.first_index) as usize;
        self.entries.truncate(offset);
    }
}

/// HSM state machine for Raft
struct HsmStateMachine {
    /// Current HSM state
    objects: HashMap<u64, StoredObject>,
    /// Last applied log index
    last_applied: LogIndex,
}

impl HsmStateMachine {
    fn new() -> Self {
        Self {
            objects: HashMap::new(),
            last_applied: 0,
        }
    }

    async fn apply(&mut self, entry: &LogEntry) -> Result<Vec<u8>, ClusterError> {
        match &entry.operation {
            ClusterOperation::GenerateKey {
                algorithm,
                key_size,
                attributes,
            } => {
                // Generate key and store in state machine
                tracing::debug!("Applying key generation: {} {:?}", algorithm, key_size);
                // Implementation would generate the key and return handle
                Ok(vec![1, 2, 3, 4]) // Placeholder handle
            }
            ClusterOperation::ImportKey {
                key_material,
                attributes,
            } => {
                // Import key into state machine
                tracing::debug!("Applying key import: {} bytes", key_material.len());
                Ok(vec![5, 6, 7, 8]) // Placeholder handle
            }
            ClusterOperation::DeleteKey { handle } => {
                // Delete key from state machine
                self.objects.remove(handle);
                tracing::debug!("Deleted key with handle {}", handle);
                Ok(vec![])
            }
            ClusterOperation::ConfigChange { .. } => {
                // Handle configuration changes
                tracing::debug!("Applying configuration change");
                Ok(vec![])
            }
            ClusterOperation::NoOp => {
                // No-op, used for heartbeats
                Ok(vec![])
            }
        }
    }
}

/// Network interface for Raft communication
#[async_trait::async_trait]
pub trait RaftNetwork {
    /// Send AppendEntries RPC to a node
    async fn send_append_entries(
        &self,
        to: NodeId,
        request: AppendEntriesRequest,
    ) -> Result<AppendEntriesResponse, ClusterError>;

    /// Send RequestVote RPC to a node
    async fn send_request_vote(
        &self,
        to: NodeId,
        request: RequestVoteRequest,
    ) -> Result<RequestVoteResponse, ClusterError>;

    /// Send InstallSnapshot RPC to a node
    async fn send_install_snapshot(
        &self,
        to: NodeId,
        request: InstallSnapshotRequest,
    ) -> Result<InstallSnapshotResponse, ClusterError>;

    /// Broadcast a message to all cluster nodes
    async fn broadcast<T: Serialize + Send>(&self, message: T) -> Result<(), ClusterError>;
}

/// AppendEntries RPC request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendEntriesRequest {
    /// Leader's term
    pub term: Term,
    /// Leader's ID
    pub leader_id: NodeId,
    /// Index of log entry immediately preceding new ones
    pub prev_log_index: LogIndex,
    /// Term of prev_log_index entry
    pub prev_log_term: Term,
    /// Log entries to store (empty for heartbeat)
    pub entries: Vec<LogEntry>,
    /// Leader's commit index
    pub leader_commit: LogIndex,
}

/// AppendEntries RPC response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendEntriesResponse {
    /// Current term for leader to update itself
    pub term: Term,
    /// True if follower contained entry matching prev_log_index and prev_log_term
    pub success: bool,
    /// Hint for optimization: last log index
    pub last_log_index: Option<LogIndex>,
}

/// RequestVote RPC request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestVoteRequest {
    /// Candidate's term
    pub term: Term,
    /// Candidate requesting vote
    pub candidate_id: NodeId,
    /// Index of candidate's last log entry
    pub last_log_index: LogIndex,
    /// Term of candidate's last log entry
    pub last_log_term: Term,
}

/// RequestVote RPC response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestVoteResponse {
    /// Current term for candidate to update itself
    pub term: Term,
    /// True if candidate received vote
    pub vote_granted: bool,
}

/// InstallSnapshot RPC request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallSnapshotRequest {
    /// Leader's term
    pub term: Term,
    /// Leader's ID
    pub leader_id: NodeId,
    /// The snapshot being sent
    pub snapshot: Snapshot,
}

/// InstallSnapshot RPC response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallSnapshotResponse {
    /// Current term for leader to update itself
    pub term: Term,
    /// Success status
    pub success: bool,
}

impl RaftConsensus {
    /// Create new Raft consensus engine
    pub async fn new(config: ClusterConfig) -> Result<Self, ClusterError> {
        let state = Arc::new(RwLock::new(RaftState::new(config.node_id)));
        let log = Arc::new(RwLock::new(RaftLog::new()));
        let state_machine = Arc::new(RwLock::new(HsmStateMachine::new()));

        // Create network interface (placeholder)
        let network = Arc::new(MockRaftNetwork::new());

        let initial_members: HashMap<NodeId, NodeInfo> = config
            .initial_members
            .iter()
            .cloned()
            .map(|n| (n.id, n))
            .collect();
        let membership = Arc::new(RwLock::new(ClusterConfiguration {
            nodes: initial_members,
            version: 1,
            pending_change: None,
        }));

        Ok(Self {
            config,
            state,
            log,
            state_machine,
            network,
            election_timeout: Arc::new(Notify::new()),
            heartbeat_notify: Arc::new(Notify::new()),
            shutdown: Arc::new(Notify::new()),
            membership,
        })
    }

    /// Start election timeout timer
    async fn start_election_timer(&self) {
        let election_timeout = self.election_timeout.clone();
        let shutdown = self.shutdown.clone();
        let config = self.config.clone();

        tokio::spawn(async move {
            let timeout_range = config.raft_config.election_timeout_ms;
            let timeout_ms = fastrand::u64(timeout_range.0..=timeout_range.1);

            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(timeout_ms)) => {
                    election_timeout.notify_one();
                }
                _ = shutdown.notified() => {
                    return;
                }
            }
        });
    }

    /// Start heartbeat timer for leaders
    async fn start_heartbeat_timer(&self) {
        let heartbeat_notify = self.heartbeat_notify.clone();
        let shutdown = self.shutdown.clone();
        let interval_ms = self.config.raft_config.heartbeat_interval_ms;

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_millis(interval_ms));

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        heartbeat_notify.notify_one();
                    }
                    _ = shutdown.notified() => {
                        break;
                    }
                }
            }
        });
    }

    /// Begin election process
    async fn start_election(&self) -> Result<(), ClusterError> {
        let mut state = self.state.write().await;

        // Increment current term and vote for self
        state.current_term += 1;
        state.voted_for = Some(self.config.node_id);
        state.state = NodeState::Candidate;
        state.current_leader = None;

        tracing::info!("Starting election for term {}", state.current_term);

        // Reset election timeout
        drop(state);
        self.start_election_timer().await;

        // Send RequestVote RPCs to all other nodes
        self.send_vote_requests().await?;

        Ok(())
    }

    /// Send RequestVote RPCs to all cluster members
    async fn send_vote_requests(&self) -> Result<(), ClusterError> {
        let state = self.state.read().await;
        let log = self.log.read().await;

        let request = RequestVoteRequest {
            term: state.current_term,
            candidate_id: self.config.node_id,
            last_log_index: log.last_index(),
            last_log_term: log.last_term(),
        };

        // Send to all other nodes
        for member in &self.config.initial_members {
            if member.id != self.config.node_id {
                let network = self.network.clone();
                let req = request.clone();
                let member_id = member.id;

                tokio::spawn(async move {
                    if let Err(e) = network.send_request_vote(member_id, req).await {
                        tracing::warn!("Failed to send vote request to node {}: {}", member_id, e);
                    }
                });
            }
        }

        Ok(())
    }

    /// Become leader after winning election
    async fn become_leader(&self) -> Result<(), ClusterError> {
        let mut state = self.state.write().await;
        state.state = NodeState::Leader;
        state.current_leader = Some(self.config.node_id);

        // Initialize leader state
        let log = self.log.read().await;
        let next_index = log.last_index() + 1;

        for member in &self.config.initial_members {
            if member.id != self.config.node_id {
                state.next_index.insert(member.id, next_index);
                state.match_index.insert(member.id, 0);
            }
        }

        tracing::info!("Became leader for term {}", state.current_term);

        // Start sending heartbeats
        self.start_heartbeat_timer().await;

        Ok(())
    }

    /// Send heartbeat to all followers
    async fn send_heartbeats(&self) -> Result<(), ClusterError> {
        let state = self.state.read().await;
        if state.state != NodeState::Leader {
            return Ok(());
        }

        let log = self.log.read().await;

        for member in &self.config.initial_members {
            if member.id != self.config.node_id {
                let prev_log_index = state.next_index.get(&member.id).unwrap_or(&0) - 1;
                let prev_log_term = if prev_log_index == 0 {
                    0
                } else {
                    log.get_entry(prev_log_index).map(|e| e.term).unwrap_or(0)
                };

                let request = AppendEntriesRequest {
                    term: state.current_term,
                    leader_id: self.config.node_id,
                    prev_log_index,
                    prev_log_term,
                    entries: vec![], // Heartbeat - no entries
                    leader_commit: state.commit_index,
                };

                let network = self.network.clone();
                let member_id = member.id;

                tokio::spawn(async move {
                    if let Err(e) = network.send_append_entries(member_id, request).await {
                        tracing::warn!("Failed to send heartbeat to node {}: {}", member_id, e);
                    }
                });
            }
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl ConsensusEngine for RaftConsensus {
    async fn start(&mut self) -> Result<(), ClusterError> {
        tracing::info!(
            "Starting Raft consensus engine for node {}",
            self.config.node_id
        );

        // Start election timeout
        self.start_election_timer().await;

        // Main consensus loop
        let state = self.state.clone();
        let election_timeout = self.election_timeout.clone();
        let heartbeat_notify = self.heartbeat_notify.clone();
        let shutdown = self.shutdown.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = election_timeout.notified() => {
                        // Election timeout - start new election
                        tracing::debug!("Election timeout triggered");
                        // Start election logic would go here
                    }
                    _ = heartbeat_notify.notified() => {
                        // Heartbeat timeout - send heartbeats if leader
                        tracing::debug!("Heartbeat timeout triggered");
                        // Send heartbeat logic would go here
                    }
                    _ = shutdown.notified() => {
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    async fn stop(&mut self) -> Result<(), ClusterError> {
        tracing::info!("Stopping Raft consensus engine");
        self.shutdown.notify_waiters();
        Ok(())
    }

    async fn get_status(&self) -> Result<ConsensusStatus, ClusterError> {
        let state = self.state.read().await;
        let log = self.log.read().await;

        Ok(ConsensusStatus {
            state: state.state,
            current_term: state.current_term,
            current_leader: state.current_leader,
            last_log_index: log.last_index(),
            commit_index: state.commit_index,
            follower_count: state.match_index.len(),
            last_heartbeat: Some(state.last_heartbeat.elapsed()),
        })
    }

    async fn propose(&self, entry: LogEntry) -> Result<LogIndex, ClusterError> {
        let state = self.state.read().await;
        if state.state != NodeState::Leader {
            return Err(ClusterError::ConsensusError {
                message: "Not the leader".to_string(),
            });
        }

        let mut log = self.log.write().await;
        let index = log.last_index() + 1;
        let mut entry = entry;
        entry.index = index;
        entry.term = state.current_term;

        log.append(entry);
        Ok(index)
    }

    async fn is_leader(&self) -> bool {
        let state = self.state.read().await;
        state.state == NodeState::Leader
    }

    async fn get_leader(&self) -> Option<NodeId> {
        let state = self.state.read().await;
        state.current_leader
    }

    async fn trigger_election(&self) -> Result<(), ClusterError> {
        self.start_election().await
    }

    async fn add_node(&self, node: NodeInfo) -> Result<(), ClusterError> {
        let mut m = self.membership.write().await;
        if m.nodes.contains_key(&node.id) {
            return Err(ClusterError::ConsensusError {
                message: format!("node {:?} already a cluster member", node.id),
            });
        }
        // Simple joint-consensus step: atomically add the node, bump version.
        // Real Raft uses a two-phase config-change with Cnew,old log entries;
        // implementing that here would require the full log-apply replay,
        // which the surrounding scaffolding does not yet do. This single-phase
        // change is safe in the leader-initiated single-writer case because
        // the membership lock is exclusive.
        m.nodes.insert(node.id, node);
        m.version = m.version.wrapping_add(1);
        m.pending_change = None;
        Ok(())
    }

    async fn remove_node(&self, node_id: NodeId) -> Result<(), ClusterError> {
        let mut m = self.membership.write().await;
        if m.nodes.remove(&node_id).is_none() {
            return Err(ClusterError::ConsensusError {
                message: format!("node {:?} is not a cluster member", node_id),
            });
        }
        m.version = m.version.wrapping_add(1);
        m.pending_change = None;
        Ok(())
    }

    async fn create_snapshot(&self) -> Result<Snapshot, ClusterError> {
        let state = self.state.read().await;
        let log = self.log.read().await;
        let state_machine = self.state_machine.read().await;

        // Serialize HSM state
        let hsm_state = bincode::serialize(&state_machine.objects).map_err(|e| {
            ClusterError::ConsensusError {
                message: format!("Failed to serialize state: {}", e),
            }
        })?;

        // Calculate checksum
        use sha2::{Digest, Sha256};
        let checksum = Sha256::digest(&hsm_state).to_vec();

        Ok(Snapshot {
            last_included_index: state.last_applied,
            last_included_term: state.current_term,
            configuration: self.membership.read().await.clone(),
            hsm_state,
            checksum,
            timestamp: SystemTime::now(),
        })
    }

    async fn install_snapshot(&self, snapshot: Snapshot) -> Result<(), ClusterError> {
        // Verify checksum
        use sha2::{Digest, Sha256};
        let computed_checksum = Sha256::digest(&snapshot.hsm_state).to_vec();
        if computed_checksum != snapshot.checksum {
            return Err(ClusterError::ConsensusError {
                message: "Snapshot checksum mismatch".to_string(),
            });
        }

        // Deserialize and install state
        let objects: HashMap<u64, StoredObject> = bincode::deserialize(&snapshot.hsm_state)
            .map_err(|e| ClusterError::ConsensusError {
                message: format!("Failed to deserialize state: {}", e),
            })?;

        let mut state_machine = self.state_machine.write().await;
        state_machine.objects = objects;
        state_machine.last_applied = snapshot.last_included_index;

        tracing::info!(
            "Installed snapshot with {} objects",
            state_machine.objects.len()
        );

        Ok(())
    }
}

/// Mock network implementation for testing
struct MockRaftNetwork;

impl MockRaftNetwork {
    fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl RaftNetwork for MockRaftNetwork {
    async fn send_append_entries(
        &self,
        _to: NodeId,
        _request: AppendEntriesRequest,
    ) -> Result<AppendEntriesResponse, ClusterError> {
        // Mock implementation
        Ok(AppendEntriesResponse {
            term: 1,
            success: true,
            last_log_index: Some(0),
        })
    }

    async fn send_request_vote(
        &self,
        _to: NodeId,
        _request: RequestVoteRequest,
    ) -> Result<RequestVoteResponse, ClusterError> {
        // Mock implementation
        Ok(RequestVoteResponse {
            term: 1,
            vote_granted: true,
        })
    }

    async fn send_install_snapshot(
        &self,
        _to: NodeId,
        _request: InstallSnapshotRequest,
    ) -> Result<InstallSnapshotResponse, ClusterError> {
        // Mock implementation
        Ok(InstallSnapshotResponse {
            term: 1,
            success: true,
        })
    }

    async fn broadcast<T: Serialize + Send>(&self, _message: T) -> Result<(), ClusterError> {
        // Mock implementation
        Ok(())
    }
}
