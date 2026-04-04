# Cluster Administration Commands

## Overview
Future cluster administration commands for `craton-hsm-admin`.
These require gRPC connectivity via the `--remote <address>` flag.

## Commands

### cluster status
Show cluster state, node role, Raft term, and member list.
```
craton-hsm-admin cluster status --remote 127.0.0.1:5696
```

### cluster members
List all known cluster members with addresses, roles, and health.

### cluster join
Tell a node to join an existing cluster via a known peer.
```
craton-hsm-admin cluster join --remote 127.0.0.1:5696 --peer 127.0.0.1:5697
```

### cluster leave
Gracefully remove a node from the cluster.

### cluster health
Detailed health: consensus lag, replication status, network partitions.

## Required Proto Changes
New `ClusterService` or extensions to `HsmService`:
- `GetClusterStatus(ClusterStatusRequest) returns (ClusterStatusResponse)`
- `ListMembers(ListMembersRequest) returns (ListMembersResponse)`
- `JoinCluster(JoinClusterRequest) returns (JoinClusterResponse)`
- `LeaveCluster(LeaveClusterRequest) returns (LeaveClusterResponse)`
- `GetClusterHealth(ClusterHealthRequest) returns (ClusterHealthResponse)`

## Authentication
All cluster admin commands require mTLS client certificate authentication.
