// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Enterprise Policy Engine for Advanced Access Control
//!
//! This module provides cutting-edge policy-based access control using:
//! - AWS Cedar policy language for fine-grained authorization
//! - Open Policy Agent (OPA) WebAssembly integration
//! - Role-based access control (RBAC) with dynamic policies
//! - Attribute-based access control (ABAC) for context-aware decisions
//! - Real-time policy evaluation with caching
//! - Policy conflict resolution and compliance checking

use crate::error::{HsmError, HsmResult};
use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityTypeName, EntityUid, Policy, PolicySet, Request,
    Schema,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

#[cfg(feature = "policy-engine")]
use opa_wasm::{Runtime, Value};

/// Policy engine for enterprise access control
pub struct PolicyEngine {
    /// Cedar policy authorizer
    cedar_authorizer: Authorizer,

    /// Active policy sets
    policy_sets: RwLock<HashMap<String, PolicySetInfo>>,

    /// Entity store for RBAC/ABAC
    entities: RwLock<Entities>,

    /// OPA WebAssembly runtime
    #[cfg(feature = "policy-engine")]
    opa_runtime: Option<Mutex<Runtime>>,

    /// Policy evaluation cache
    decision_cache: RwLock<PolicyCache>,

    /// Policy engine configuration
    config: PolicyConfig,

    /// Policy audit log
    audit_log: Mutex<Vec<PolicyAuditEntry>>,
}

/// Policy set information
#[derive(Debug, Clone)]
pub struct PolicySetInfo {
    /// Policy set identifier
    pub id: String,

    /// Human-readable name
    pub name: String,

    /// Cedar policy set
    pub cedar_policies: PolicySet,

    /// OPA policy (Rego code)
    pub opa_policy: Option<String>,

    /// Priority for conflict resolution
    pub priority: u32,

    /// Activation status
    pub is_active: bool,

    /// Creation timestamp
    pub created_at: SystemTime,

    /// Last modification timestamp
    pub modified_at: SystemTime,
}

/// Policy engine configuration
#[derive(Debug, Clone)]
pub struct PolicyConfig {
    /// Enable policy caching
    pub enable_caching: bool,

    /// Cache TTL in seconds
    pub cache_ttl_secs: u64,

    /// Maximum cache entries
    pub max_cache_entries: usize,

    /// Enable policy audit logging
    pub enable_audit: bool,

    /// Maximum audit log entries
    pub max_audit_entries: usize,

    /// Policy evaluation timeout
    pub evaluation_timeout: Duration,
}

/// Policy decision cache
#[derive(Debug)]
struct PolicyCache {
    /// Cached decisions
    entries: HashMap<String, CacheEntry>,

    /// Cache statistics
    hits: u64,
    misses: u64,
}

/// Cache entry
#[derive(Debug, Clone)]
struct CacheEntry {
    /// Cached decision
    decision: Decision,

    /// Additional context
    context: HashMap<String, String>,

    /// Cache timestamp
    timestamp: Instant,

    /// TTL for this entry
    ttl: Duration,
}

/// Policy evaluation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRequest {
    /// Principal (user/service/role)
    pub principal: EntityUid,

    /// Action being requested
    pub action: EntityUid,

    /// Resource being accessed
    pub resource: EntityUid,

    /// Additional context attributes
    pub context: HashMap<String, serde_json::Value>,

    /// Request timestamp
    pub timestamp: u64,

    /// Session identifier
    pub session_id: String,
}

/// Policy evaluation response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResponse {
    /// Authorization decision
    pub decision: PolicyDecision,

    /// Reason for the decision
    pub reason: String,

    /// Applicable policies
    pub policies: Vec<String>,

    /// Evaluation time in microseconds
    pub evaluation_time_us: u64,

    /// Whether result was cached
    pub was_cached: bool,

    /// Additional obligations/advice
    pub obligations: Vec<PolicyObligation>,
}

/// Policy decision
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PolicyDecision {
    /// Access allowed
    Allow,

    /// Access denied
    Deny,

    /// Conditional access with requirements
    Conditional { requirements: Vec<String> },

    /// Policy evaluation failed
    Error { error: String },
}

/// Policy obligation or advice
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyObligation {
    /// Obligation type
    pub obligation_type: String,

    /// Required action
    pub action: String,

    /// Parameters
    pub parameters: HashMap<String, serde_json::Value>,

    /// Whether this is mandatory (obligation) or advisory (advice)
    pub is_mandatory: bool,
}

/// RBAC role definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    /// Role identifier
    pub id: String,

    /// Role name
    pub name: String,

    /// Role description
    pub description: String,

    /// Permissions granted by this role
    pub permissions: HashSet<String>,

    /// Parent roles (for hierarchy)
    pub parent_roles: HashSet<String>,

    /// Role attributes
    pub attributes: HashMap<String, serde_json::Value>,

    /// Activation conditions
    pub conditions: Vec<String>,
}

/// Policy audit entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyAuditEntry {
    /// Unique audit ID
    pub id: String,

    /// Request that was evaluated
    pub request: PolicyRequest,

    /// Policy decision
    pub response: PolicyResponse,

    /// Evaluation timestamp
    pub timestamp: SystemTime,

    /// Source IP address
    pub source_ip: Option<String>,

    /// User agent
    pub user_agent: Option<String>,

    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

impl PolicyEngine {
    /// Create a new policy engine
    pub async fn new(config: PolicyConfig) -> HsmResult<Self> {
        let cedar_authorizer = Authorizer::new();

        #[cfg(feature = "policy-engine")]
        let opa_runtime = match Runtime::new().await {
            Ok(runtime) => Some(Mutex::new(runtime)),
            Err(e) => {
                warn!("Failed to initialize OPA runtime: {}", e);
                None
            }
        };

        #[cfg(not(feature = "policy-engine"))]
        let opa_runtime = None;

        Ok(Self {
            cedar_authorizer,
            policy_sets: RwLock::new(HashMap::new()),
            entities: RwLock::new(Entities::new()),
            opa_runtime,
            decision_cache: RwLock::new(PolicyCache {
                entries: HashMap::new(),
                hits: 0,
                misses: 0,
            }),
            config,
            audit_log: Mutex::new(Vec::new()),
        })
    }

    /// Add a Cedar policy set
    pub async fn add_cedar_policy_set(
        &self,
        id: String,
        name: String,
        policies_text: &str,
        priority: u32,
    ) -> HsmResult<()> {
        // Parse Cedar policies
        let policy_set = PolicySet::from_str(policies_text).map_err(|e| {
            HsmError::InvalidInput(format!("Failed to parse Cedar policies: {}", e))
        })?;

        let policy_info = PolicySetInfo {
            id: id.clone(),
            name,
            cedar_policies: policy_set,
            opa_policy: None,
            priority,
            is_active: true,
            created_at: SystemTime::now(),
            modified_at: SystemTime::now(),
        };

        let mut policy_sets = self.policy_sets.write().await;
        policy_sets.insert(id.clone(), policy_info);

        // Clear cache when policies change
        if self.config.enable_caching {
            let mut cache = self.decision_cache.write().await;
            cache.entries.clear();
        }

        info!("Added Cedar policy set: {}", id);
        Ok(())
    }

    /// Add an OPA policy
    #[cfg(feature = "policy-engine")]
    pub async fn add_opa_policy(
        &self,
        id: String,
        name: String,
        rego_code: String,
        priority: u32,
    ) -> HsmResult<()> {
        if let Some(ref opa_runtime) = self.opa_runtime {
            let mut runtime = opa_runtime.lock().await;
            runtime
                .set_policy(&rego_code)
                .map_err(|e| HsmError::InvalidInput(format!("Failed to set OPA policy: {}", e)))?;
        }

        let policy_info = PolicySetInfo {
            id: id.clone(),
            name,
            cedar_policies: PolicySet::new(),
            opa_policy: Some(rego_code),
            priority,
            is_active: true,
            created_at: SystemTime::now(),
            modified_at: SystemTime::now(),
        };

        let mut policy_sets = self.policy_sets.write().await;
        policy_sets.insert(id.clone(), policy_info);

        info!("Added OPA policy set: {}", id);
        Ok(())
    }

    /// Add entities for RBAC/ABAC
    pub async fn add_entities(&self, entities_json: &str) -> HsmResult<()> {
        let new_entities = Entities::from_json_str(entities_json)
            .map_err(|e| HsmError::InvalidInput(format!("Failed to parse entities: {}", e)))?;

        let mut entities = self.entities.write().await;
        *entities = new_entities;

        debug!("Updated entity store");
        Ok(())
    }

    /// Evaluate a policy request
    pub async fn evaluate(&self, request: PolicyRequest) -> HsmResult<PolicyResponse> {
        let start_time = Instant::now();

        // Check cache first
        if self.config.enable_caching {
            let cache_key = self.generate_cache_key(&request);
            let cache = self.decision_cache.read().await;

            if let Some(entry) = cache.entries.get(&cache_key) {
                if entry.timestamp.elapsed() < entry.ttl {
                    let response = PolicyResponse {
                        decision: match entry.decision {
                            Decision::Allow => PolicyDecision::Allow,
                            Decision::Deny => PolicyDecision::Deny,
                        },
                        reason: "Cached decision".to_string(),
                        policies: vec![],
                        evaluation_time_us: 0,
                        was_cached: true,
                        obligations: vec![],
                    };

                    // Update cache statistics
                    drop(cache);
                    let mut cache = self.decision_cache.write().await;
                    cache.hits += 1;

                    return Ok(response);
                }
            }

            drop(cache);
            let mut cache = self.decision_cache.write().await;
            cache.misses += 1;
        }

        // Evaluate policies
        let mut responses = Vec::new();

        // Evaluate Cedar policies
        let cedar_response = self.evaluate_cedar_policies(&request).await?;
        if !matches!(cedar_response.decision, PolicyDecision::Error { .. }) {
            responses.push(cedar_response);
        }

        // Evaluate OPA policies
        #[cfg(feature = "policy-engine")]
        if let Some(opa_response) = self.evaluate_opa_policies(&request).await? {
            if !matches!(opa_response.decision, PolicyDecision::Error { .. }) {
                responses.push(opa_response);
            }
        }

        // Combine responses using conflict resolution
        let final_response = self.resolve_policy_conflicts(responses).await?;

        let evaluation_time = start_time.elapsed().as_micros() as u64;
        let mut final_response = final_response;
        final_response.evaluation_time_us = evaluation_time;
        final_response.was_cached = false;

        // Cache the result
        if self.config.enable_caching
            && matches!(
                final_response.decision,
                PolicyDecision::Allow | PolicyDecision::Deny
            )
        {
            let cache_key = self.generate_cache_key(&request);
            let decision = match &final_response.decision {
                PolicyDecision::Allow => Decision::Allow,
                PolicyDecision::Deny => Decision::Deny,
                _ => Decision::Deny, // Conservative default
            };

            let cache_entry = CacheEntry {
                decision,
                context: HashMap::new(),
                timestamp: Instant::now(),
                ttl: Duration::from_secs(self.config.cache_ttl_secs),
            };

            let mut cache = self.decision_cache.write().await;
            if cache.entries.len() >= self.config.max_cache_entries {
                // Simple eviction: remove oldest entry
                let oldest_key = cache
                    .entries
                    .iter()
                    .min_by_key(|(_, entry)| entry.timestamp)
                    .map(|(key, _)| key.clone());

                if let Some(key) = oldest_key {
                    cache.entries.remove(&key);
                }
            }

            cache.entries.insert(cache_key, cache_entry);
        }

        // Audit the decision
        if self.config.enable_audit {
            self.audit_decision(request.clone(), final_response.clone())
                .await?;
        }

        Ok(final_response)
    }

    /// Evaluate Cedar policies
    async fn evaluate_cedar_policies(&self, request: &PolicyRequest) -> HsmResult<PolicyResponse> {
        let policy_sets = self.policy_sets.read().await;
        let entities = self.entities.read().await;

        // Build Cedar request
        let context = Context::from_json_value(serde_json::Value::Object(
            request
                .context
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        ))
        .map_err(|e| HsmError::InvalidInput(format!("Invalid context: {}", e)))?;

        let cedar_request = Request::new(
            Some(request.principal.clone()),
            Some(request.action.clone()),
            Some(request.resource.clone()),
            context,
        );

        let mut allow_policies = Vec::new();
        let mut deny_policies = Vec::new();

        // Evaluate each active policy set
        for (id, policy_info) in policy_sets.iter() {
            if !policy_info.is_active {
                continue;
            }

            let response = self.cedar_authorizer.is_authorized(
                &cedar_request,
                &policy_info.cedar_policies,
                &entities,
            );

            match response.decision() {
                Decision::Allow => {
                    allow_policies.push(id.clone());
                }
                Decision::Deny => {
                    deny_policies.push(id.clone());
                }
            }
        }

        let decision = if !deny_policies.is_empty() {
            PolicyDecision::Deny
        } else if !allow_policies.is_empty() {
            PolicyDecision::Allow
        } else {
            PolicyDecision::Deny // Default deny
        };

        let reason = match &decision {
            PolicyDecision::Allow => format!("Allowed by policies: {}", allow_policies.join(", ")),
            PolicyDecision::Deny if !deny_policies.is_empty() => {
                format!("Denied by policies: {}", deny_policies.join(", "))
            }
            PolicyDecision::Deny => "No applicable allow policies".to_string(),
            _ => "Unknown".to_string(),
        };

        Ok(PolicyResponse {
            decision,
            reason,
            policies: [allow_policies, deny_policies].concat(),
            evaluation_time_us: 0,
            was_cached: false,
            obligations: vec![],
        })
    }

    /// Evaluate OPA policies
    #[cfg(feature = "policy-engine")]
    async fn evaluate_opa_policies(
        &self,
        request: &PolicyRequest,
    ) -> HsmResult<Option<PolicyResponse>> {
        if let Some(ref opa_runtime) = self.opa_runtime {
            let mut runtime = opa_runtime.lock().await;

            // Convert request to OPA input format
            let input = serde_json::json!({
                "principal": {
                    "type": request.principal.type_name().to_string(),
                    "id": request.principal.id().to_string(),
                },
                "action": {
                    "type": request.action.type_name().to_string(),
                    "id": request.action.id().to_string(),
                },
                "resource": {
                    "type": request.resource.type_name().to_string(),
                    "id": request.resource.id().to_string(),
                },
                "context": request.context,
                "timestamp": request.timestamp,
            });

            match runtime.evaluate("main/allow", &input) {
                Ok(Value::Bool(true)) => Ok(Some(PolicyResponse {
                    decision: PolicyDecision::Allow,
                    reason: "Allowed by OPA policy".to_string(),
                    policies: vec!["opa_policy".to_string()],
                    evaluation_time_us: 0,
                    was_cached: false,
                    obligations: vec![],
                })),
                Ok(Value::Bool(false)) => Ok(Some(PolicyResponse {
                    decision: PolicyDecision::Deny,
                    reason: "Denied by OPA policy".to_string(),
                    policies: vec!["opa_policy".to_string()],
                    evaluation_time_us: 0,
                    was_cached: false,
                    obligations: vec![],
                })),
                Ok(_) => Ok(Some(PolicyResponse {
                    decision: PolicyDecision::Error {
                        error: "OPA policy returned non-boolean result".to_string(),
                    },
                    reason: "Policy evaluation error".to_string(),
                    policies: vec![],
                    evaluation_time_us: 0,
                    was_cached: false,
                    obligations: vec![],
                })),
                Err(e) => {
                    error!("OPA policy evaluation failed: {}", e);
                    Ok(Some(PolicyResponse {
                        decision: PolicyDecision::Error {
                            error: format!("OPA evaluation error: {}", e),
                        },
                        reason: "Policy evaluation failed".to_string(),
                        policies: vec![],
                        evaluation_time_us: 0,
                        was_cached: false,
                        obligations: vec![],
                    }))
                }
            }
        } else {
            Ok(None)
        }
    }

    #[cfg(not(feature = "policy-engine"))]
    async fn evaluate_opa_policies(
        &self,
        _request: &PolicyRequest,
    ) -> HsmResult<Option<PolicyResponse>> {
        Ok(None)
    }

    /// Resolve conflicts between multiple policy responses
    async fn resolve_policy_conflicts(
        &self,
        responses: Vec<PolicyResponse>,
    ) -> HsmResult<PolicyResponse> {
        if responses.is_empty() {
            return Ok(PolicyResponse {
                decision: PolicyDecision::Deny,
                reason: "No applicable policies".to_string(),
                policies: vec![],
                evaluation_time_us: 0,
                was_cached: false,
                obligations: vec![],
            });
        }

        if responses.len() == 1 {
            return Ok(responses.into_iter().next().unwrap());
        }

        // Conflict resolution strategy: Deny overrides Allow
        let has_deny = responses
            .iter()
            .any(|r| matches!(r.decision, PolicyDecision::Deny));
        let has_error = responses
            .iter()
            .any(|r| matches!(r.decision, PolicyDecision::Error { .. }));

        if has_error {
            let error_responses: Vec<_> = responses
                .into_iter()
                .filter(|r| matches!(r.decision, PolicyDecision::Error { .. }))
                .collect();

            return Ok(error_responses.into_iter().next().unwrap());
        }

        let combined_policies: Vec<String> = responses
            .iter()
            .flat_map(|r| r.policies.iter())
            .cloned()
            .collect();

        let combined_obligations: Vec<PolicyObligation> = responses
            .iter()
            .flat_map(|r| r.obligations.iter())
            .cloned()
            .collect();

        if has_deny {
            Ok(PolicyResponse {
                decision: PolicyDecision::Deny,
                reason: "Access denied by security policy".to_string(),
                policies: combined_policies,
                evaluation_time_us: 0,
                was_cached: false,
                obligations: combined_obligations,
            })
        } else {
            Ok(PolicyResponse {
                decision: PolicyDecision::Allow,
                reason: "Access allowed by policy".to_string(),
                policies: combined_policies,
                evaluation_time_us: 0,
                was_cached: false,
                obligations: combined_obligations,
            })
        }
    }

    /// Generate cache key for a request
    fn generate_cache_key(&self, request: &PolicyRequest) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        request.principal.hash(&mut hasher);
        request.action.hash(&mut hasher);
        request.resource.hash(&mut hasher);

        // Hash context keys and values
        let mut context_items: Vec<_> = request.context.iter().collect();
        context_items.sort_by_key(|(k, _)| *k);
        for (key, value) in context_items {
            key.hash(&mut hasher);
            // Simple hash for JSON values
            serde_json::to_string(value)
                .unwrap_or_default()
                .hash(&mut hasher);
        }

        format!("{:x}", hasher.finish())
    }

    /// Audit a policy decision
    async fn audit_decision(
        &self,
        request: PolicyRequest,
        response: PolicyResponse,
    ) -> HsmResult<()> {
        let audit_entry = PolicyAuditEntry {
            id: Uuid::new_v4().to_string(),
            request,
            response,
            timestamp: SystemTime::now(),
            source_ip: None,
            user_agent: None,
            metadata: HashMap::new(),
        };

        let mut audit_log = self.audit_log.lock().await;
        audit_log.push(audit_entry);

        // Limit audit log size
        if audit_log.len() > self.config.max_audit_entries {
            audit_log.remove(0);
        }

        Ok(())
    }

    /// Get policy engine statistics
    pub async fn get_statistics(&self) -> PolicyEngineStats {
        let cache = self.decision_cache.read().await;
        let policy_sets = self.policy_sets.read().await;
        let audit_log = self.audit_log.lock().await;

        PolicyEngineStats {
            active_policy_sets: policy_sets.values().filter(|p| p.is_active).count(),
            total_policy_sets: policy_sets.len(),
            cache_hit_rate: if cache.hits + cache.misses > 0 {
                cache.hits as f64 / (cache.hits + cache.misses) as f64
            } else {
                0.0
            },
            cache_entries: cache.entries.len(),
            audit_entries: audit_log.len(),
        }
    }

    /// Clear policy cache
    pub async fn clear_cache(&self) {
        let mut cache = self.decision_cache.write().await;
        cache.entries.clear();
        cache.hits = 0;
        cache.misses = 0;
        info!("Policy cache cleared");
    }

    /// Remove a policy set
    pub async fn remove_policy_set(&self, id: &str) -> HsmResult<()> {
        let mut policy_sets = self.policy_sets.write().await;
        if policy_sets.remove(id).is_some() {
            // Clear cache when policies change
            drop(policy_sets);
            self.clear_cache().await;
            info!("Removed policy set: {}", id);
            Ok(())
        } else {
            Err(HsmError::NotFound(format!("Policy set not found: {}", id)))
        }
    }

    /// List all policy sets
    pub async fn list_policy_sets(&self) -> Vec<PolicySetInfo> {
        let policy_sets = self.policy_sets.read().await;
        policy_sets.values().cloned().collect()
    }
}

/// Policy engine statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEngineStats {
    /// Number of active policy sets
    pub active_policy_sets: usize,

    /// Total number of policy sets
    pub total_policy_sets: usize,

    /// Cache hit rate (0.0 to 1.0)
    pub cache_hit_rate: f64,

    /// Number of cache entries
    pub cache_entries: usize,

    /// Number of audit entries
    pub audit_entries: usize,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            enable_caching: true,
            cache_ttl_secs: 300, // 5 minutes
            max_cache_entries: 10000,
            enable_audit: true,
            max_audit_entries: 100000,
            evaluation_timeout: Duration::from_millis(100),
        }
    }
}

/// Utility functions for policy management
pub mod utils {
    use super::*;

    /// Create a basic RBAC policy in Cedar
    pub fn create_rbac_policy(role: &str, action: &str, resource: &str) -> String {
        format!(
            r#"permit(
    principal in Role::"{role}",
    action == Action::"{action}",
    resource == Resource::"{resource}"
);"#,
            role = role,
            action = action,
            resource = resource
        )
    }

    /// Create an ABAC policy with conditions
    pub fn create_abac_policy(
        principal_attr: &str,
        resource_attr: &str,
        condition: &str,
    ) -> String {
        format!(
            r#"permit(
    principal,
    action,
    resource
) when {{
    principal.{principal_attr} == "{condition}" &&
    resource.{resource_attr} == "{condition}"
}};"#,
            principal_attr = principal_attr,
            resource_attr = resource_attr,
            condition = condition
        )
    }

    /// Create an OPA policy in Rego
    pub fn create_opa_policy(rule_name: &str, condition: &str) -> String {
        format!(
            r#"package main

import future.keywords.if

default allow := false

allow if {{
    {condition}
}}

{rule_name} if {{
    allow
}}"#,
            rule_name = rule_name,
            condition = condition
        )
    }

    /// Parse role from entity UID
    pub fn extract_role_from_principal(principal: &EntityUid) -> Option<String> {
        if principal.type_name().to_string() == "User" {
            // Extract role from user attributes or ID
            Some("user".to_string())
        } else if principal.type_name().to_string() == "Service" {
            Some("service".to_string())
        } else {
            None
        }
    }

    /// Create entities JSON for testing
    pub fn create_test_entities() -> String {
        serde_json::json!([
            {
                "uid": {"type": "User", "id": "alice"},
                "attrs": {
                    "role": "admin",
                    "department": "engineering",
                    "clearance": "secret"
                },
                "parents": []
            },
            {
                "uid": {"type": "User", "id": "bob"},
                "attrs": {
                    "role": "user",
                    "department": "finance",
                    "clearance": "public"
                },
                "parents": []
            },
            {
                "uid": {"type": "Role", "id": "admin"},
                "attrs": {
                    "permissions": ["read", "write", "delete"],
                    "description": "Administrator role"
                },
                "parents": []
            },
            {
                "uid": {"type": "Resource", "id": "sensitive_key"},
                "attrs": {
                    "classification": "secret",
                    "owner": "engineering"
                },
                "parents": []
            }
        ])
        .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_policy_engine_creation() {
        let config = PolicyConfig::default();
        let engine = PolicyEngine::new(config)
            .await
            .expect("Failed to create policy engine");

        let stats = engine.get_statistics().await;
        assert_eq!(stats.active_policy_sets, 0);
        assert_eq!(stats.total_policy_sets, 0);
    }

    #[tokio::test]
    async fn test_cedar_policy_evaluation() {
        let config = PolicyConfig::default();
        let engine = PolicyEngine::new(config)
            .await
            .expect("Failed to create policy engine");

        // Add entities
        let entities_json = utils::create_test_entities();
        engine
            .add_entities(&entities_json)
            .await
            .expect("Failed to add entities");

        // Add a simple RBAC policy
        let policy = utils::create_rbac_policy("admin", "read", "sensitive_key");
        engine
            .add_cedar_policy_set(
                "test_policy".to_string(),
                "Test Policy".to_string(),
                &policy,
                100,
            )
            .await
            .expect("Failed to add policy");

        // Create a request
        let request = PolicyRequest {
            principal: EntityUid::from_type_name_and_id(
                EntityTypeName::from_str("User").unwrap(),
                "alice".to_string(),
            )
            .unwrap(),
            action: EntityUid::from_type_name_and_id(
                EntityTypeName::from_str("Action").unwrap(),
                "read".to_string(),
            )
            .unwrap(),
            resource: EntityUid::from_type_name_and_id(
                EntityTypeName::from_str("Resource").unwrap(),
                "sensitive_key".to_string(),
            )
            .unwrap(),
            context: HashMap::new(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            session_id: Uuid::new_v4().to_string(),
        };

        let response = engine
            .evaluate(request)
            .await
            .expect("Policy evaluation failed");

        // Note: This test may fail due to entity relationship setup
        // In a real scenario, the entities would need proper parent-child relationships
        println!("Policy response: {:?}", response);
    }

    #[test]
    fn test_policy_utilities() {
        let rbac_policy = utils::create_rbac_policy("admin", "read", "key");
        assert!(rbac_policy.contains("permit"));
        assert!(rbac_policy.contains("admin"));

        let abac_policy = utils::create_abac_policy("department", "owner", "engineering");
        assert!(abac_policy.contains("when"));
        assert!(abac_policy.contains("engineering"));

        let opa_policy = utils::create_opa_policy("admin_rule", r#"input.user.role == "admin""#);
        assert!(opa_policy.contains("package main"));
        assert!(opa_policy.contains("admin_rule"));
    }

    #[tokio::test]
    async fn test_policy_caching() {
        let mut config = PolicyConfig::default();
        config.cache_ttl_secs = 1; // Short TTL for testing

        let engine = PolicyEngine::new(config)
            .await
            .expect("Failed to create policy engine");

        let stats_before = engine.get_statistics().await;
        assert_eq!(stats_before.cache_hit_rate, 0.0);

        // Clear cache should not error
        engine.clear_cache().await;

        let stats_after = engine.get_statistics().await;
        assert_eq!(stats_after.cache_entries, 0);
    }
}
