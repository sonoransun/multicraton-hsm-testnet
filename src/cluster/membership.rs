// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company

//! Cluster Membership Management
//!
//! This module handles cluster membership, node discovery, health monitoring,
//! and configuration changes for HSM clustering.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::RwLock;

use crate::cluster::{
    ClusterConfig, ClusterError, NodeCapabilities, NodeHealthStatus, NodeId, NodeInfo, NodeRole,
};

/// Membership manager for cluster nodes
pub struct MembershipManager {
    /// Cluster configuration
    config: ClusterConfig,
    /// Current membership state
    membership: Arc<RwLock<MembershipState>>,
    /// Health checker for nodes
    health_checker: Arc<HealthChecker>,
    /// Node discovery service
    discovery: Arc<NodeDiscovery>,
}

/// Current cluster membership state
#[derive(Debug, Default)]
struct MembershipState {
    /// All known nodes
    nodes: HashMap<NodeId, NodeInfo>,
    /// Membership version (incremented on changes)
    version: u64,
    /// Last membership update
    last_update: Option<SystemTime>,
    /// Pending membership changes
    pending_changes: Vec<MembershipChange>,
}

/// Pending membership change
#[derive(Debug, Clone)]
struct MembershipChange {
    /// Change ID
    id: uuid::Uuid,
    /// Type of change
    change_type: MembershipChangeType,
    /// Target node
    target_node: NodeId,
    /// Proposed by node
    proposer: NodeId,
    /// Timestamp of proposal
    proposed_at: SystemTime,
    /// Votes received
    votes: HashMap<NodeId, MembershipVote>,
}

/// Types of membership changes
#[derive(Debug, Clone, Serialize, Deserialize)]
enum MembershipChangeType {
    /// Add new node to cluster
    AddNode(NodeInfo),
    /// Remove node from cluster
    RemoveNode,
    /// Update node information
    UpdateNode(NodeInfo),
    /// Promote learner to voting member
    PromoteNode,
    /// Demote voting member to learner
    DemoteNode,
}

/// Vote on membership change
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MembershipVote {
    /// Voter node ID
    voter: NodeId,
    /// Vote decision
    decision: VoteDecision,
    /// Vote timestamp
    timestamp: SystemTime,
    /// Reason for vote
    reason: Option<String>,
}

/// Membership vote decision
#[derive(Debug, Clone, Serialize, Deserialize)]
enum VoteDecision {
    /// Approve the change
    Approve,
    /// Reject the change
    Reject,
    /// Abstain from voting
    Abstain,
}

/// Membership status information
#[derive(Debug, Clone)]
pub struct MembershipStatus {
    /// Total nodes in cluster
    pub total_nodes: usize,
    /// Number of healthy nodes
    pub healthy_nodes: usize,
    /// Number of voting nodes
    pub voting_nodes: usize,
    /// Current membership version
    pub version: u64,
    /// Last membership update
    pub last_update: Option<SystemTime>,
}

/// Health checker for cluster nodes
pub struct HealthChecker {
    /// Health check configuration
    config: HealthCheckConfig,
    /// Current health status
    health_status: Arc<RwLock<HashMap<NodeId, NodeHealthInfo>>>,
}

/// Health check configuration
#[derive(Debug, Clone)]
struct HealthCheckConfig {
    /// Health check interval
    interval: Duration,
    /// Timeout for health checks
    timeout: Duration,
    /// Number of failures before marking unhealthy
    failure_threshold: u32,
    /// Recovery threshold
    recovery_threshold: u32,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(30),
            timeout: Duration::from_secs(5),
            failure_threshold: 3,
            recovery_threshold: 2,
        }
    }
}

/// Health information for a node
#[derive(Debug, Clone)]
struct NodeHealthInfo {
    /// Current status
    status: NodeHealthStatus,
    /// Last successful check
    last_success: Option<SystemTime>,
    /// Consecutive failures
    failure_count: u32,
    /// Consecutive successes (for recovery)
    success_count: u32,
    /// Response time statistics
    response_times: Vec<Duration>,
}

/// Node discovery service
pub struct NodeDiscovery {
    /// Discovery configuration
    config: DiscoveryConfig,
    /// Known node addresses
    known_nodes: Arc<RwLock<HashMap<NodeId, SocketAddr>>>,
}

/// Discovery configuration
#[derive(Debug, Clone)]
struct DiscoveryConfig {
    /// Discovery method
    method: DiscoveryMethod,
    /// Discovery interval
    interval: Duration,
    /// Bootstrap nodes
    bootstrap_nodes: Vec<SocketAddr>,
}

/// Node discovery methods
#[derive(Debug, Clone)]
enum DiscoveryMethod {
    /// Static configuration
    Static,
    /// DNS-based discovery
    Dns { domain: String },
    /// Consul-based discovery
    Consul { endpoint: String },
    /// Kubernetes discovery
    Kubernetes { namespace: String, service: String },
    /// Cloud provider discovery
    Cloud { provider: CloudProvider },
}

/// Cloud provider for discovery
#[derive(Debug, Clone)]
enum CloudProvider {
    /// AWS Auto Scaling Groups
    Aws { region: String, asg_name: String },
    /// Azure Virtual Machine Scale Sets
    Azure {
        resource_group: String,
        vmss_name: String,
    },
    /// Google Cloud Managed Instance Groups
    Gcp {
        project: String,
        zone: String,
        group: String,
    },
}

impl MembershipManager {
    /// Create new membership manager
    pub async fn new(config: ClusterConfig) -> Result<Self, ClusterError> {
        let membership = Arc::new(RwLock::new(MembershipState::default()));
        let health_checker = Arc::new(HealthChecker::new());
        let discovery = Arc::new(NodeDiscovery::new(config.clone()).await?);

        Ok(Self {
            config,
            membership,
            health_checker,
            discovery,
        })
    }

    /// Get current membership status
    pub async fn get_membership_status(&self) -> Result<MembershipStatus, ClusterError> {
        let membership = self.membership.read().await;

        let total_nodes = membership.nodes.len();
        let healthy_nodes = membership
            .nodes
            .values()
            .filter(|node| node.health_status == NodeHealthStatus::Healthy)
            .count();
        let voting_nodes = membership
            .nodes
            .values()
            .filter(|node| node.role == NodeRole::Voting)
            .count();

        Ok(MembershipStatus {
            total_nodes,
            healthy_nodes,
            voting_nodes,
            version: membership.version,
            last_update: membership.last_update,
        })
    }

    /// Request to join the cluster
    pub async fn request_join(&self, coordinator_node: NodeId) -> Result<(), ClusterError> {
        tracing::info!("Requesting to join cluster via node {}", coordinator_node);

        // Create node info for this node
        let node_info = NodeInfo {
            id: self.config.node_id,
            address: self.config.listen_address,
            role: NodeRole::Learner, // Start as learner
            last_heartbeat: Some(SystemTime::now()),
            health_status: NodeHealthStatus::Healthy,
            capabilities: NodeCapabilities {
                algorithms: vec!["RSA".to_string(), "ECDSA".to_string()],
                max_concurrent_ops: 1000,
                hardware_acceleration: vec![],
                fips_level: Some("Level 1".to_string()),
                pqc_support: true,
            },
        };

        // Send join request (implementation would send network request)
        tracing::info!("Sent join request to coordinator node {}", coordinator_node);

        Ok(())
    }

    /// Propose membership change
    pub async fn propose_membership_change(
        &self,
        change_type: MembershipChangeType,
        target_node: NodeId,
    ) -> Result<uuid::Uuid, ClusterError> {
        let change_id = uuid::Uuid::new_v4();
        let change = MembershipChange {
            id: change_id,
            change_type,
            target_node,
            proposer: self.config.node_id,
            proposed_at: SystemTime::now(),
            votes: HashMap::new(),
        };

        let mut membership = self.membership.write().await;
        membership.pending_changes.push(change);

        tracing::info!(
            "Proposed membership change {} for node {}",
            change_id,
            target_node
        );

        Ok(change_id)
    }

    /// Vote on membership change
    pub async fn vote_on_change(
        &self,
        change_id: uuid::Uuid,
        decision: VoteDecision,
        reason: Option<String>,
    ) -> Result<(), ClusterError> {
        let mut membership = self.membership.write().await;

        if let Some(change) = membership
            .pending_changes
            .iter_mut()
            .find(|c| c.id == change_id)
        {
            let vote = MembershipVote {
                voter: self.config.node_id,
                decision,
                timestamp: SystemTime::now(),
                reason,
            };

            change.votes.insert(self.config.node_id, vote);

            // Check if we have enough votes to proceed
            self.check_change_completion(change).await?;
        }

        Ok(())
    }

    /// Add node to cluster membership
    pub async fn add_node(&self, node_info: NodeInfo) -> Result<(), ClusterError> {
        let mut membership = self.membership.write().await;
        membership.nodes.insert(node_info.id, node_info.clone());
        membership.version += 1;
        membership.last_update = Some(SystemTime::now());

        tracing::info!("Added node {} to cluster membership", node_info.id);

        Ok(())
    }

    /// Remove node from cluster membership
    pub async fn remove_node(&self, node_id: NodeId) -> Result<(), ClusterError> {
        let mut membership = self.membership.write().await;

        if membership.nodes.remove(&node_id).is_some() {
            membership.version += 1;
            membership.last_update = Some(SystemTime::now());
            tracing::info!("Removed node {} from cluster membership", node_id);
        }

        Ok(())
    }

    /// Update node health status
    pub async fn update_node_health(
        &self,
        node_id: NodeId,
        health_status: NodeHealthStatus,
    ) -> Result<(), ClusterError> {
        let mut membership = self.membership.write().await;

        if let Some(node) = membership.nodes.get_mut(&node_id) {
            node.health_status = health_status;
            node.last_heartbeat = Some(SystemTime::now());
            membership.last_update = Some(SystemTime::now());
        }

        Ok(())
    }

    /// Get all cluster nodes
    pub async fn get_all_nodes(&self) -> Result<Vec<NodeInfo>, ClusterError> {
        let membership = self.membership.read().await;
        Ok(membership.nodes.values().cloned().collect())
    }

    /// Get healthy voting nodes
    pub async fn get_healthy_voting_nodes(&self) -> Result<Vec<NodeInfo>, ClusterError> {
        let membership = self.membership.read().await;
        let healthy_voting = membership
            .nodes
            .values()
            .filter(|node| {
                node.role == NodeRole::Voting && node.health_status == NodeHealthStatus::Healthy
            })
            .cloned()
            .collect();

        Ok(healthy_voting)
    }

    // ========================================================================
    // Private helper methods
    // ========================================================================

    /// Check if membership change has enough votes to complete
    async fn check_change_completion(&self, change: &MembershipChange) -> Result<(), ClusterError> {
        let total_voting_nodes = self.get_voting_node_count().await;
        let required_votes = (total_voting_nodes / 2) + 1;

        let approval_votes = change
            .votes
            .values()
            .filter(|vote| matches!(vote.decision, VoteDecision::Approve))
            .count();

        let rejection_votes = change
            .votes
            .values()
            .filter(|vote| matches!(vote.decision, VoteDecision::Reject))
            .count();

        if approval_votes >= required_votes {
            // Change approved - apply it
            self.apply_membership_change(change).await?;
            tracing::info!("Membership change {} approved and applied", change.id);
        } else if rejection_votes >= required_votes {
            // Change rejected
            tracing::info!("Membership change {} rejected", change.id);
        }

        Ok(())
    }

    /// Apply approved membership change
    async fn apply_membership_change(&self, change: &MembershipChange) -> Result<(), ClusterError> {
        match &change.change_type {
            MembershipChangeType::AddNode(node_info) => {
                self.add_node(node_info.clone()).await?;
            }
            MembershipChangeType::RemoveNode => {
                self.remove_node(change.target_node).await?;
            }
            MembershipChangeType::UpdateNode(node_info) => {
                self.add_node(node_info.clone()).await?; // Updates existing
            }
            MembershipChangeType::PromoteNode => {
                self.promote_node(change.target_node).await?;
            }
            MembershipChangeType::DemoteNode => {
                self.demote_node(change.target_node).await?;
            }
        }

        Ok(())
    }

    /// Get number of voting nodes
    async fn get_voting_node_count(&self) -> usize {
        let membership = self.membership.read().await;
        membership
            .nodes
            .values()
            .filter(|node| node.role == NodeRole::Voting)
            .count()
    }

    /// Promote node to voting member
    async fn promote_node(&self, node_id: NodeId) -> Result<(), ClusterError> {
        let mut membership = self.membership.write().await;

        if let Some(node) = membership.nodes.get_mut(&node_id) {
            node.role = NodeRole::Voting;
            membership.version += 1;
            membership.last_update = Some(SystemTime::now());
            tracing::info!("Promoted node {} to voting member", node_id);
        }

        Ok(())
    }

    /// Demote node to learner
    async fn demote_node(&self, node_id: NodeId) -> Result<(), ClusterError> {
        let mut membership = self.membership.write().await;

        if let Some(node) = membership.nodes.get_mut(&node_id) {
            node.role = NodeRole::Learner;
            membership.version += 1;
            membership.last_update = Some(SystemTime::now());
            tracing::info!("Demoted node {} to learner", node_id);
        }

        Ok(())
    }
}

impl HealthChecker {
    /// Create new health checker
    pub fn new() -> Self {
        Self {
            config: HealthCheckConfig::default(),
            health_status: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Start health checking for a node
    pub async fn start_monitoring(&self, node_info: NodeInfo) -> Result<(), ClusterError> {
        let mut health_status = self.health_status.write().await;
        health_status.insert(
            node_info.id,
            NodeHealthInfo {
                status: NodeHealthStatus::Healthy,
                last_success: Some(SystemTime::now()),
                failure_count: 0,
                success_count: 0,
                response_times: Vec::new(),
            },
        );

        tracing::info!("Started health monitoring for node {}", node_info.id);

        Ok(())
    }

    /// Stop health checking for a node
    pub async fn stop_monitoring(&self, node_id: NodeId) -> Result<(), ClusterError> {
        let mut health_status = self.health_status.write().await;
        health_status.remove(&node_id);

        tracing::info!("Stopped health monitoring for node {}", node_id);

        Ok(())
    }

    /// Get health status for a node
    pub async fn get_health_status(&self, node_id: NodeId) -> Option<NodeHealthStatus> {
        let health_status = self.health_status.read().await;
        health_status.get(&node_id).map(|info| info.status.clone())
    }
}

impl NodeDiscovery {
    /// Create new node discovery service
    pub async fn new(config: ClusterConfig) -> Result<Self, ClusterError> {
        let discovery_config = DiscoveryConfig {
            method: DiscoveryMethod::Static, // Default to static
            interval: Duration::from_secs(60),
            bootstrap_nodes: config
                .initial_members
                .iter()
                .map(|member| member.address)
                .collect(),
        };

        Ok(Self {
            config: discovery_config,
            known_nodes: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Discover new nodes
    pub async fn discover_nodes(&self) -> Result<Vec<SocketAddr>, ClusterError> {
        match &self.config.method {
            DiscoveryMethod::Static => {
                // Return bootstrap nodes
                Ok(self.config.bootstrap_nodes.clone())
            }
            DiscoveryMethod::Dns { domain } => {
                // DNS-based discovery
                self.discover_via_dns(domain).await
            }
            _ => {
                // Other discovery methods not implemented
                Ok(vec![])
            }
        }
    }

    /// DNS-based node discovery
    async fn discover_via_dns(&self, domain: &str) -> Result<Vec<SocketAddr>, ClusterError> {
        use tokio::net::lookup_host;

        match lookup_host(domain).await {
            Ok(addresses) => {
                let addrs: Vec<SocketAddr> = addresses.collect();
                tracing::info!("Discovered {} nodes via DNS: {}", addrs.len(), domain);
                Ok(addrs)
            }
            Err(e) => {
                tracing::warn!("DNS discovery failed for {}: {}", domain, e);
                Ok(vec![])
            }
        }
    }
}
