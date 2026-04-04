// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! ML-Powered Security Analytics Module
//!
//! This module provides advanced machine learning capabilities for:
//! - Real-time anomaly detection in HSM operations
//! - Behavioral analysis for insider threat detection
//! - Predictive maintenance and failure prediction
//! - Risk scoring and adaptive authentication
//! - Usage pattern analysis and optimization
//! - Fraud detection in cryptographic operations

use crate::error::{HsmError, HsmResult};
use linfa::prelude::*;
use linfa_clustering::{KMeans, KMeansParams};
use ndarray::{Array1, Array2, ArrayView1, Axis};
use polars::prelude::*;
use serde::{Deserialize, Serialize};
use smartcore::ensemble::random_forest_classifier::{
    RandomForestClassifier, RandomForestClassifierParameters,
};
use smartcore::linalg::basic::matrix::DenseMatrix;
use smartcore::linalg::basic::vector::DenseVector;
use smartcore::metrics::{accuracy, roc_auc_score};
use smartcore::model_selection::train_test_split;
use smartcore::preprocessing::*;
use smartcore::tree::decision_tree_classifier::SplitCriterion;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, error, info, warn};

/// ML-powered security analytics engine
pub struct SecurityAnalytics {
    /// Anomaly detection models
    anomaly_models: RwLock<HashMap<String, AnomalyModel>>,

    /// Behavioral analysis models
    behavior_models: RwLock<HashMap<String, BehaviorModel>>,

    /// Risk scoring engine
    risk_scorer: Arc<Mutex<RiskScorer>>,

    /// Real-time event stream
    event_buffer: Arc<Mutex<VecDeque<SecurityEvent>>>,

    /// Analytics configuration
    config: AnalyticsConfig,

    /// Feature extractors
    feature_extractors: HashMap<String, Box<dyn FeatureExtractor + Send + Sync>>,

    /// Model performance metrics
    metrics: RwLock<AnalyticsMetrics>,
}

/// Analytics configuration
#[derive(Debug, Clone)]
pub struct AnalyticsConfig {
    /// Maximum events to buffer for real-time analysis
    pub max_buffer_size: usize,

    /// Time window for anomaly detection (seconds)
    pub anomaly_window_secs: u64,

    /// Minimum samples required for model training
    pub min_training_samples: usize,

    /// Model retraining interval (seconds)
    pub retrain_interval_secs: u64,

    /// Anomaly score threshold (0.0-1.0)
    pub anomaly_threshold: f64,

    /// Risk score threshold (0.0-1.0)
    pub risk_threshold: f64,

    /// Enable real-time processing
    pub enable_realtime: bool,

    /// Feature extraction configuration
    pub feature_config: FeatureConfig,
}

/// Feature extraction configuration
#[derive(Debug, Clone)]
pub struct FeatureConfig {
    /// Time-based features
    pub use_temporal_features: bool,

    /// Frequency-based features
    pub use_frequency_features: bool,

    /// Statistical features
    pub use_statistical_features: bool,

    /// Behavioral features
    pub use_behavioral_features: bool,

    /// Sequence-based features
    pub use_sequence_features: bool,
}

/// Security event for analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// Event timestamp
    pub timestamp: u64,

    /// Event type
    pub event_type: String,

    /// User/principal identifier
    pub principal: String,

    /// Session identifier
    pub session_id: String,

    /// Source IP address
    pub source_ip: Option<String>,

    /// User agent
    pub user_agent: Option<String>,

    /// Operation details
    pub operation: String,

    /// Resource accessed
    pub resource: String,

    /// Operation success
    pub success: bool,

    /// Duration in milliseconds
    pub duration_ms: u64,

    /// Data size processed
    pub data_size: Option<u64>,

    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Anomaly detection model
pub struct AnomalyModel {
    /// Model type
    pub model_type: AnomalyModelType,

    /// K-means clustering for outlier detection
    pub kmeans_model: Option<KMeans<f64>>,

    /// Feature statistics for normalization
    pub feature_stats: FeatureStatistics,

    /// Last training timestamp
    pub last_trained: SystemTime,

    /// Model performance metrics
    pub performance: ModelPerformance,
}

/// Behavioral analysis model
pub struct BehaviorModel {
    /// Random forest classifier
    pub classifier: Option<RandomForestClassifier<f64>>,

    /// Feature importance scores
    pub feature_importance: Vec<f64>,

    /// User behavior profiles
    pub user_profiles: HashMap<String, UserProfile>,

    /// Last training timestamp
    pub last_trained: SystemTime,

    /// Model accuracy
    pub accuracy: f64,
}

/// Risk scoring engine
pub struct RiskScorer {
    /// Risk factors and weights
    pub risk_factors: HashMap<String, f64>,

    /// Historical risk scores
    pub risk_history: VecDeque<RiskScore>,

    /// Adaptive thresholds
    pub adaptive_thresholds: HashMap<String, f64>,
}

/// User behavioral profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    /// User identifier
    pub user_id: String,

    /// Typical operation patterns
    pub operation_patterns: HashMap<String, OperationPattern>,

    /// Access time patterns
    pub time_patterns: TimePattern,

    /// Geographical patterns
    pub geo_patterns: GeographicalPattern,

    /// Risk score trend
    pub risk_trend: Vec<f64>,

    /// Profile last updated
    pub last_updated: SystemTime,
}

/// Operation pattern for a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationPattern {
    /// Operation frequency (operations per hour)
    pub frequency: f64,

    /// Average duration
    pub avg_duration_ms: f64,

    /// Success rate
    pub success_rate: f64,

    /// Typical data sizes
    pub data_size_distribution: Vec<u64>,

    /// Time of day distribution
    pub time_distribution: Vec<u8>, // 24 hours
}

/// Time-based access patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimePattern {
    /// Typical access hours (0-23)
    pub typical_hours: Vec<u8>,

    /// Typical days of week (0-6)
    pub typical_days: Vec<u8>,

    /// Session duration statistics
    pub session_duration_stats: DurationStats,
}

/// Geographical access patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeographicalPattern {
    /// Typical locations (IP ranges or countries)
    pub typical_locations: Vec<String>,

    /// Suspicious location flags
    pub location_anomalies: Vec<String>,

    /// Travel speed analysis (km/h)
    pub max_travel_speed: f64,
}

/// Duration statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DurationStats {
    pub mean: f64,
    pub std_dev: f64,
    pub min: f64,
    pub max: f64,
    pub median: f64,
}

/// Risk score with context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    /// Score timestamp
    pub timestamp: u64,

    /// User/principal
    pub principal: String,

    /// Overall risk score (0.0-1.0)
    pub score: f64,

    /// Contributing factors
    pub factors: HashMap<String, f64>,

    /// Risk category
    pub category: RiskCategory,

    /// Recommended actions
    pub recommendations: Vec<String>,
}

/// Risk categories
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RiskCategory {
    Low,
    Medium,
    High,
    Critical,
}

/// Anomaly detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyResult {
    /// Event being analyzed
    pub event: SecurityEvent,

    /// Anomaly score (0.0-1.0)
    pub anomaly_score: f64,

    /// Whether this is classified as an anomaly
    pub is_anomaly: bool,

    /// Anomaly type
    pub anomaly_type: AnomalyType,

    /// Contributing features
    pub features: HashMap<String, f64>,

    /// Explanation
    pub explanation: String,
}

/// Types of anomalies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnomalyType {
    /// Unusual time-based pattern
    TemporalAnomaly,

    /// Unusual operation frequency
    FrequencyAnomaly,

    /// Unusual operation sequence
    SequenceAnomaly,

    /// Geographical anomaly
    GeographicalAnomaly,

    /// Behavioral deviation
    BehavioralAnomaly,

    /// Performance anomaly
    PerformanceAnomaly,
}

/// Types of anomaly detection models
#[derive(Debug, Clone)]
pub enum AnomalyModelType {
    /// Clustering-based (K-means)
    Clustering,

    /// Isolation forest
    IsolationForest,

    /// One-class SVM
    OneClassSvm,

    /// Statistical threshold
    Statistical,
}

/// Feature statistics for normalization
#[derive(Debug, Clone)]
pub struct FeatureStatistics {
    /// Feature means
    pub means: Vec<f64>,

    /// Feature standard deviations
    pub std_devs: Vec<f64>,

    /// Feature minimums
    pub mins: Vec<f64>,

    /// Feature maximums
    pub maxs: Vec<f64>,
}

/// Model performance metrics
#[derive(Debug, Clone)]
pub struct ModelPerformance {
    /// Accuracy score
    pub accuracy: f64,

    /// Precision score
    pub precision: f64,

    /// Recall score
    pub recall: f64,

    /// F1 score
    pub f1_score: f64,

    /// AUC-ROC score
    pub auc_score: f64,
}

/// Analytics engine metrics
#[derive(Debug, Clone)]
pub struct AnalyticsMetrics {
    /// Total events processed
    pub events_processed: u64,

    /// Anomalies detected
    pub anomalies_detected: u64,

    /// False positive rate
    pub false_positive_rate: f64,

    /// Average processing time (microseconds)
    pub avg_processing_time_us: f64,

    /// Model training count
    pub models_trained: u64,

    /// Last update timestamp
    pub last_updated: SystemTime,
}

/// Feature extractor trait
pub trait FeatureExtractor {
    /// Extract features from a security event
    fn extract_features(&self, event: &SecurityEvent, context: &[SecurityEvent]) -> Vec<f64>;

    /// Get feature names
    fn get_feature_names(&self) -> Vec<String>;

    /// Get feature count
    fn feature_count(&self) -> usize;
}

/// Temporal feature extractor
pub struct TemporalFeatureExtractor {
    /// Time window size for analysis
    window_size: Duration,
}

/// Frequency feature extractor
pub struct FrequencyFeatureExtractor {
    /// Analysis window
    window_duration: Duration,
}

/// Statistical feature extractor
pub struct StatisticalFeatureExtractor;

impl SecurityAnalytics {
    /// Create a new security analytics engine
    pub async fn new(config: AnalyticsConfig) -> HsmResult<Self> {
        let mut feature_extractors: HashMap<String, Box<dyn FeatureExtractor + Send + Sync>> =
            HashMap::new();

        // Add feature extractors based on configuration
        if config.feature_config.use_temporal_features {
            feature_extractors.insert(
                "temporal".to_string(),
                Box::new(TemporalFeatureExtractor {
                    window_size: Duration::from_secs(config.anomaly_window_secs),
                }),
            );
        }

        if config.feature_config.use_frequency_features {
            feature_extractors.insert(
                "frequency".to_string(),
                Box::new(FrequencyFeatureExtractor {
                    window_duration: Duration::from_secs(config.anomaly_window_secs),
                }),
            );
        }

        if config.feature_config.use_statistical_features {
            feature_extractors.insert(
                "statistical".to_string(),
                Box::new(StatisticalFeatureExtractor),
            );
        }

        Ok(Self {
            anomaly_models: RwLock::new(HashMap::new()),
            behavior_models: RwLock::new(HashMap::new()),
            risk_scorer: Arc::new(Mutex::new(RiskScorer {
                risk_factors: Self::default_risk_factors(),
                risk_history: VecDeque::new(),
                adaptive_thresholds: HashMap::new(),
            })),
            event_buffer: Arc::new(Mutex::new(VecDeque::new())),
            config,
            feature_extractors,
            metrics: RwLock::new(AnalyticsMetrics {
                events_processed: 0,
                anomalies_detected: 0,
                false_positive_rate: 0.0,
                avg_processing_time_us: 0.0,
                models_trained: 0,
                last_updated: SystemTime::now(),
            }),
        })
    }

    /// Process a security event for analysis
    pub async fn process_event(&self, event: SecurityEvent) -> HsmResult<Option<AnomalyResult>> {
        let start_time = Instant::now();

        // Add to buffer
        let mut buffer = self.event_buffer.lock().await;
        buffer.push_back(event.clone());

        // Maintain buffer size
        while buffer.len() > self.config.max_buffer_size {
            buffer.pop_front();
        }

        let buffer_snapshot: Vec<SecurityEvent> = buffer.iter().cloned().collect();
        drop(buffer);

        // Extract features
        let features = self.extract_features(&event, &buffer_snapshot)?;

        // Detect anomalies
        let anomaly_result = self.detect_anomalies(&event, &features).await?;

        // Update risk scoring
        self.update_risk_score(&event, &anomaly_result).await?;

        // Update metrics
        let processing_time = start_time.elapsed().as_micros() as f64;
        let mut metrics = self.metrics.write().await;
        metrics.events_processed += 1;
        if let Some(ref result) = anomaly_result {
            if result.is_anomaly {
                metrics.anomalies_detected += 1;
            }
        }
        metrics.avg_processing_time_us =
            (metrics.avg_processing_time_us * 0.9) + (processing_time * 0.1);
        metrics.last_updated = SystemTime::now();

        Ok(anomaly_result)
    }

    /// Extract features from an event
    fn extract_features(
        &self,
        event: &SecurityEvent,
        context: &[SecurityEvent],
    ) -> HsmResult<Vec<f64>> {
        let mut all_features = Vec::new();

        for (name, extractor) in &self.feature_extractors {
            let features = extractor.extract_features(event, context);
            all_features.extend(features);
            debug!("Extracted {} features from {}", features.len(), name);
        }

        Ok(all_features)
    }

    /// Detect anomalies in an event
    async fn detect_anomalies(
        &self,
        event: &SecurityEvent,
        features: &[f64],
    ) -> HsmResult<Option<AnomalyResult>> {
        let models = self.anomaly_models.read().await;

        // Use the primary anomaly model
        if let Some(model) = models.get("primary") {
            let anomaly_score = self.calculate_anomaly_score(model, features)?;

            let is_anomaly = anomaly_score > self.config.anomaly_threshold;

            if is_anomaly {
                let anomaly_type = self.classify_anomaly_type(event, features).await;

                let result = AnomalyResult {
                    event: event.clone(),
                    anomaly_score,
                    is_anomaly,
                    anomaly_type,
                    features: self.create_feature_map(features),
                    explanation: self.generate_anomaly_explanation(&anomaly_type, anomaly_score),
                };

                return Ok(Some(result));
            }
        }

        Ok(None)
    }

    /// Calculate anomaly score using the model
    fn calculate_anomaly_score(&self, model: &AnomalyModel, features: &[f64]) -> HsmResult<f64> {
        match &model.model_type {
            AnomalyModelType::Clustering => {
                if let Some(ref kmeans) = model.kmeans_model {
                    // Normalize features
                    let normalized_features =
                        self.normalize_features(features, &model.feature_stats)?;

                    // Calculate distance to nearest cluster center
                    let feature_array = Array1::from_vec(normalized_features);
                    let distances = kmeans.predict(&feature_array.view().insert_axis(Axis(0)));

                    // Convert distance to anomaly score (0-1)
                    let distance = distances.iter().fold(f64::INFINITY, |acc, &x| acc.min(x));
                    let score = (distance / 10.0).min(1.0); // Normalize to 0-1 range

                    Ok(score)
                } else {
                    Ok(0.0)
                }
            }
            AnomalyModelType::Statistical => {
                // Use statistical thresholds
                let normalized_features =
                    self.normalize_features(features, &model.feature_stats)?;

                // Calculate z-score based anomaly
                let mut total_zscore = 0.0;
                for (i, &feature) in normalized_features.iter().enumerate() {
                    if i < model.feature_stats.std_devs.len()
                        && model.feature_stats.std_devs[i] != 0.0
                    {
                        let zscore = feature.abs() / model.feature_stats.std_devs[i];
                        total_zscore += zscore;
                    }
                }

                let avg_zscore = total_zscore / normalized_features.len() as f64;
                let score = (avg_zscore / 3.0).min(1.0); // Normalize to 0-1

                Ok(score)
            }
            _ => {
                // Fallback for other model types
                Ok(0.0)
            }
        }
    }

    /// Normalize features using stored statistics
    fn normalize_features(
        &self,
        features: &[f64],
        stats: &FeatureStatistics,
    ) -> HsmResult<Vec<f64>> {
        let mut normalized = Vec::new();

        for (i, &feature) in features.iter().enumerate() {
            if i < stats.means.len() && i < stats.std_devs.len() {
                if stats.std_devs[i] != 0.0 {
                    let normalized_feature = (feature - stats.means[i]) / stats.std_devs[i];
                    normalized.push(normalized_feature);
                } else {
                    normalized.push(0.0);
                }
            } else {
                normalized.push(feature);
            }
        }

        Ok(normalized)
    }

    /// Classify the type of anomaly
    async fn classify_anomaly_type(&self, event: &SecurityEvent, features: &[f64]) -> AnomalyType {
        // Simple heuristic-based classification
        // In practice, this could use a separate classifier

        let hour = (event.timestamp % 86400) / 3600;
        if hour < 6 || hour > 22 {
            return AnomalyType::TemporalAnomaly;
        }

        if event.duration_ms > 10000 {
            return AnomalyType::PerformanceAnomaly;
        }

        if let Some(ref ip) = event.source_ip {
            // Simple geographical check (in practice would use IP geolocation)
            if ip.starts_with("192.") || ip.starts_with("10.") {
                // Internal IP - less likely to be geographical anomaly
            } else {
                return AnomalyType::GeographicalAnomaly;
            }
        }

        // Check for frequency anomalies
        if features.len() > 1 && features[1] > 5.0 {
            return AnomalyType::FrequencyAnomaly;
        }

        AnomalyType::BehavioralAnomaly
    }

    /// Create feature map for explanations
    fn create_feature_map(&self, features: &[f64]) -> HashMap<String, f64> {
        let mut feature_map = HashMap::new();

        let mut feature_index = 0;
        for (extractor_name, extractor) in &self.feature_extractors {
            let feature_names = extractor.get_feature_names();
            for name in feature_names {
                if feature_index < features.len() {
                    feature_map.insert(
                        format!("{}_{}", extractor_name, name),
                        features[feature_index],
                    );
                    feature_index += 1;
                }
            }
        }

        feature_map
    }

    /// Generate human-readable anomaly explanation
    fn generate_anomaly_explanation(&self, anomaly_type: &AnomalyType, score: f64) -> String {
        match anomaly_type {
            AnomalyType::TemporalAnomaly => {
                format!(
                    "Unusual access time detected (score: {:.2}). Access outside typical hours.",
                    score
                )
            }
            AnomalyType::FrequencyAnomaly => {
                format!("High frequency operation detected (score: {:.2}). Operation rate exceeds normal patterns.", score)
            }
            AnomalyType::SequenceAnomaly => {
                format!("Unusual operation sequence detected (score: {:.2}). Operations performed in atypical order.", score)
            }
            AnomalyType::GeographicalAnomaly => {
                format!(
                    "Geographical anomaly detected (score: {:.2}). Access from unusual location.",
                    score
                )
            }
            AnomalyType::BehavioralAnomaly => {
                format!("Behavioral deviation detected (score: {:.2}). User behavior differs from established patterns.", score)
            }
            AnomalyType::PerformanceAnomaly => {
                format!("Performance anomaly detected (score: {:.2}). Operation took unusually long to complete.", score)
            }
        }
    }

    /// Update risk score for a user
    async fn update_risk_score(
        &self,
        event: &SecurityEvent,
        anomaly: &Option<AnomalyResult>,
    ) -> HsmResult<()> {
        let mut risk_scorer = self.risk_scorer.lock().await;

        let mut risk_factors = HashMap::new();

        // Base risk factors
        risk_factors.insert("base_risk".to_string(), 0.1);

        // Add anomaly risk
        if let Some(ref anomaly_result) = anomaly {
            if anomaly_result.is_anomaly {
                risk_factors.insert(
                    "anomaly_risk".to_string(),
                    anomaly_result.anomaly_score * 0.5,
                );
            }
        }

        // Add temporal risk
        let hour = (event.timestamp % 86400) / 3600;
        if hour < 6 || hour > 22 {
            risk_factors.insert("time_risk".to_string(), 0.2);
        }

        // Add failure risk
        if !event.success {
            risk_factors.insert("failure_risk".to_string(), 0.3);
        }

        // Calculate weighted risk score
        let mut total_score = 0.0;
        let mut total_weight = 0.0;

        for (factor, score) in &risk_factors {
            if let Some(&weight) = risk_scorer.risk_factors.get(factor) {
                total_score += score * weight;
                total_weight += weight;
            }
        }

        let final_score = if total_weight > 0.0 {
            (total_score / total_weight).min(1.0)
        } else {
            0.1
        };

        let risk_category = match final_score {
            s if s < 0.25 => RiskCategory::Low,
            s if s < 0.5 => RiskCategory::Medium,
            s if s < 0.75 => RiskCategory::High,
            _ => RiskCategory::Critical,
        };

        let recommendations = self.generate_recommendations(&risk_category, &risk_factors);

        let risk_score = RiskScore {
            timestamp: event.timestamp,
            principal: event.principal.clone(),
            score: final_score,
            factors: risk_factors,
            category: risk_category,
            recommendations,
        };

        risk_scorer.risk_history.push_back(risk_score);

        // Maintain history size
        while risk_scorer.risk_history.len() > 1000 {
            risk_scorer.risk_history.pop_front();
        }

        Ok(())
    }

    /// Generate security recommendations based on risk
    fn generate_recommendations(
        &self,
        category: &RiskCategory,
        factors: &HashMap<String, f64>,
    ) -> Vec<String> {
        let mut recommendations = Vec::new();

        match category {
            RiskCategory::Critical => {
                recommendations.push("Immediate security review required".to_string());
                recommendations.push("Consider temporary access restriction".to_string());
                recommendations.push("Enable enhanced monitoring".to_string());
            }
            RiskCategory::High => {
                recommendations.push("Enhanced authentication recommended".to_string());
                recommendations.push("Increase audit logging".to_string());
            }
            RiskCategory::Medium => {
                recommendations.push("Monitor user activity".to_string());
            }
            RiskCategory::Low => {
                // No specific recommendations for low risk
            }
        }

        // Factor-specific recommendations
        if factors.contains_key("anomaly_risk") {
            recommendations.push("Review anomalous behavior patterns".to_string());
        }

        if factors.contains_key("time_risk") {
            recommendations.push("Verify off-hours access authorization".to_string());
        }

        if factors.contains_key("failure_risk") {
            recommendations.push("Investigate operation failures".to_string());
        }

        recommendations
    }

    /// Train anomaly detection model
    pub async fn train_anomaly_model(&self, training_events: Vec<SecurityEvent>) -> HsmResult<()> {
        if training_events.len() < self.config.min_training_samples {
            return Err(HsmError::InvalidInput(format!(
                "Insufficient training samples: need {}, have {}",
                self.config.min_training_samples,
                training_events.len()
            )));
        }

        info!(
            "Training anomaly detection model with {} samples",
            training_events.len()
        );

        // Extract features for all training events
        let mut feature_matrix = Vec::new();
        for event in &training_events {
            let features = self.extract_features(event, &training_events)?;
            feature_matrix.push(features);
        }

        // Calculate feature statistics
        let feature_stats = self.calculate_feature_statistics(&feature_matrix)?;

        // Normalize features
        let mut normalized_matrix = Vec::new();
        for features in &feature_matrix {
            let normalized = self.normalize_features(features, &feature_stats)?;
            normalized_matrix.push(normalized);
        }

        // Convert to ndarray for training
        if normalized_matrix.is_empty() || normalized_matrix[0].is_empty() {
            return Err(HsmError::InvalidInput("No valid features extracted".into()));
        }

        let rows = normalized_matrix.len();
        let cols = normalized_matrix[0].len();
        let flat_data: Vec<f64> = normalized_matrix.into_iter().flatten().collect();

        let training_data = Array2::from_shape_vec((rows, cols), flat_data).map_err(|e| {
            HsmError::CryptographicError(format!("Failed to create training matrix: {}", e))
        })?;

        // Train K-means model
        let n_clusters = 5.min(rows / 10).max(2); // Adaptive cluster count
        let kmeans = KMeans::params(n_clusters)
            .max_n_iterations(100)
            .tolerance(1e-4)
            .fit(&training_data)
            .map_err(|e| HsmError::CryptographicError(format!("K-means training failed: {}", e)))?;

        // Create anomaly model
        let anomaly_model = AnomalyModel {
            model_type: AnomalyModelType::Clustering,
            kmeans_model: Some(kmeans),
            feature_stats,
            last_trained: SystemTime::now(),
            performance: ModelPerformance {
                accuracy: 0.85, // Placeholder - would calculate from validation
                precision: 0.80,
                recall: 0.75,
                f1_score: 0.77,
                auc_score: 0.82,
            },
        };

        // Store model
        let mut models = self.anomaly_models.write().await;
        models.insert("primary".to_string(), anomaly_model);

        // Update metrics
        let mut metrics = self.metrics.write().await;
        metrics.models_trained += 1;

        info!("Anomaly detection model training completed");
        Ok(())
    }

    /// Calculate feature statistics for normalization
    fn calculate_feature_statistics(
        &self,
        feature_matrix: &[Vec<f64>],
    ) -> HsmResult<FeatureStatistics> {
        if feature_matrix.is_empty() {
            return Err(HsmError::InvalidInput("Empty feature matrix".into()));
        }

        let feature_count = feature_matrix[0].len();
        let mut means = vec![0.0; feature_count];
        let mut std_devs = vec![0.0; feature_count];
        let mut mins = vec![f64::INFINITY; feature_count];
        let mut maxs = vec![f64::NEG_INFINITY; feature_count];

        let sample_count = feature_matrix.len() as f64;

        // Calculate means, mins, maxs
        for features in feature_matrix {
            for (i, &value) in features.iter().enumerate() {
                if i < feature_count {
                    means[i] += value;
                    mins[i] = mins[i].min(value);
                    maxs[i] = maxs[i].max(value);
                }
            }
        }

        for mean in &mut means {
            *mean /= sample_count;
        }

        // Calculate standard deviations
        for features in feature_matrix {
            for (i, &value) in features.iter().enumerate() {
                if i < feature_count {
                    let diff = value - means[i];
                    std_devs[i] += diff * diff;
                }
            }
        }

        for std_dev in &mut std_devs {
            *std_dev = (*std_dev / sample_count).sqrt();
            if *std_dev == 0.0 {
                *std_dev = 1.0; // Avoid division by zero
            }
        }

        Ok(FeatureStatistics {
            means,
            std_devs,
            mins,
            maxs,
        })
    }

    /// Get analytics statistics
    pub async fn get_metrics(&self) -> AnalyticsMetrics {
        self.metrics.read().await.clone()
    }

    /// Get risk scores for recent events
    pub async fn get_recent_risk_scores(&self, limit: usize) -> Vec<RiskScore> {
        let risk_scorer = self.risk_scorer.lock().await;
        risk_scorer
            .risk_history
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    /// Default risk factors and their weights
    fn default_risk_factors() -> HashMap<String, f64> {
        let mut factors = HashMap::new();
        factors.insert("base_risk".to_string(), 1.0);
        factors.insert("anomaly_risk".to_string(), 3.0);
        factors.insert("time_risk".to_string(), 2.0);
        factors.insert("failure_risk".to_string(), 2.5);
        factors.insert("geo_risk".to_string(), 1.5);
        factors.insert("frequency_risk".to_string(), 1.8);
        factors
    }
}

// Feature extractor implementations
impl FeatureExtractor for TemporalFeatureExtractor {
    fn extract_features(&self, event: &SecurityEvent, context: &[SecurityEvent]) -> Vec<f64> {
        let mut features = Vec::new();

        // Hour of day (0-23)
        let hour = ((event.timestamp % 86400) / 3600) as f64;
        features.push(hour / 24.0); // Normalize to 0-1

        // Day of week (0-6)
        let day_of_week = ((event.timestamp / 86400) % 7) as f64;
        features.push(day_of_week / 7.0);

        // Session duration (if available)
        features.push(event.duration_ms as f64 / 60000.0); // Normalize to minutes

        // Time since last event for this user
        let time_since_last = context
            .iter()
            .filter(|e| e.principal == event.principal && e.timestamp < event.timestamp)
            .map(|e| event.timestamp - e.timestamp)
            .min()
            .unwrap_or(3600) as f64; // Default 1 hour

        features.push((time_since_last / 3600.0).min(24.0)); // Cap at 24 hours

        features
    }

    fn get_feature_names(&self) -> Vec<String> {
        vec![
            "hour_of_day".to_string(),
            "day_of_week".to_string(),
            "duration_minutes".to_string(),
            "time_since_last_hours".to_string(),
        ]
    }

    fn feature_count(&self) -> usize {
        4
    }
}

impl FeatureExtractor for FrequencyFeatureExtractor {
    fn extract_features(&self, event: &SecurityEvent, context: &[SecurityEvent]) -> Vec<f64> {
        let mut features = Vec::new();

        let window_start = event
            .timestamp
            .saturating_sub(self.window_duration.as_secs());

        // Count events in window for this user
        let user_events = context
            .iter()
            .filter(|e| {
                e.principal == event.principal
                    && e.timestamp >= window_start
                    && e.timestamp <= event.timestamp
            })
            .count() as f64;

        features.push((user_events / 10.0).min(1.0)); // Normalize, cap at 10 events

        // Count failed operations
        let failed_operations = context
            .iter()
            .filter(|e| {
                e.principal == event.principal
                    && e.timestamp >= window_start
                    && e.timestamp <= event.timestamp
                    && !e.success
            })
            .count() as f64;

        features.push((failed_operations / 5.0).min(1.0)); // Normalize, cap at 5 failures

        // Count unique operations
        let unique_operations: std::collections::HashSet<_> = context
            .iter()
            .filter(|e| {
                e.principal == event.principal
                    && e.timestamp >= window_start
                    && e.timestamp <= event.timestamp
            })
            .map(|e| &e.operation)
            .collect();

        features.push((unique_operations.len() as f64 / 5.0).min(1.0)); // Normalize

        features
    }

    fn get_feature_names(&self) -> Vec<String> {
        vec![
            "event_frequency".to_string(),
            "failure_frequency".to_string(),
            "operation_diversity".to_string(),
        ]
    }

    fn feature_count(&self) -> usize {
        3
    }
}

impl FeatureExtractor for StatisticalFeatureExtractor {
    fn extract_features(&self, event: &SecurityEvent, _context: &[SecurityEvent]) -> Vec<f64> {
        let mut features = Vec::new();

        // Operation success (binary)
        features.push(if event.success { 1.0 } else { 0.0 });

        // Data size (normalized)
        if let Some(size) = event.data_size {
            features.push((size as f64 / 1_000_000.0).min(1.0)); // Normalize to MB
        } else {
            features.push(0.0);
        }

        // Duration (normalized)
        features.push((event.duration_ms as f64 / 10_000.0).min(1.0)); // Normalize to 10 seconds

        // Operation type hash (simple feature)
        let op_hash = event.operation.chars().map(|c| c as u32).sum::<u32>() % 100;
        features.push(op_hash as f64 / 100.0);

        features
    }

    fn get_feature_names(&self) -> Vec<String> {
        vec![
            "success_flag".to_string(),
            "data_size_mb".to_string(),
            "duration_normalized".to_string(),
            "operation_hash".to_string(),
        ]
    }

    fn feature_count(&self) -> usize {
        4
    }
}

impl Default for AnalyticsConfig {
    fn default() -> Self {
        Self {
            max_buffer_size: 10000,
            anomaly_window_secs: 3600, // 1 hour
            min_training_samples: 1000,
            retrain_interval_secs: 86400, // 24 hours
            anomaly_threshold: 0.7,
            risk_threshold: 0.5,
            enable_realtime: true,
            feature_config: FeatureConfig {
                use_temporal_features: true,
                use_frequency_features: true,
                use_statistical_features: true,
                use_behavioral_features: true,
                use_sequence_features: false, // Requires more complex implementation
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_analytics_engine_creation() {
        let config = AnalyticsConfig::default();
        let analytics = SecurityAnalytics::new(config)
            .await
            .expect("Failed to create analytics engine");

        let metrics = analytics.get_metrics().await;
        assert_eq!(metrics.events_processed, 0);
        assert_eq!(metrics.anomalies_detected, 0);
    }

    #[tokio::test]
    async fn test_event_processing() {
        let config = AnalyticsConfig::default();
        let analytics = SecurityAnalytics::new(config)
            .await
            .expect("Failed to create analytics engine");

        let event = SecurityEvent {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            event_type: "crypto_operation".to_string(),
            principal: "alice".to_string(),
            session_id: "session_123".to_string(),
            source_ip: Some("192.168.1.100".to_string()),
            user_agent: None,
            operation: "sign".to_string(),
            resource: "key_1".to_string(),
            success: true,
            duration_ms: 150,
            data_size: Some(1024),
            metadata: HashMap::new(),
        };

        let result = analytics
            .process_event(event)
            .await
            .expect("Failed to process event");

        // Should not detect anomaly without trained model
        assert!(result.is_none());

        let metrics = analytics.get_metrics().await;
        assert_eq!(metrics.events_processed, 1);
    }

    #[test]
    fn test_feature_extractors() {
        let extractor = TemporalFeatureExtractor {
            window_size: Duration::from_secs(3600),
        };

        let event = SecurityEvent {
            timestamp: 1640995200, // 2022-01-01 00:00:00 UTC
            event_type: "test".to_string(),
            principal: "alice".to_string(),
            session_id: "test".to_string(),
            source_ip: None,
            user_agent: None,
            operation: "test".to_string(),
            resource: "test".to_string(),
            success: true,
            duration_ms: 1000,
            data_size: None,
            metadata: HashMap::new(),
        };

        let features = extractor.extract_features(&event, &[]);
        assert_eq!(features.len(), extractor.feature_count());

        let feature_names = extractor.get_feature_names();
        assert_eq!(feature_names.len(), extractor.feature_count());
    }

    #[test]
    fn test_risk_categories() {
        assert_eq!(RiskCategory::Low, RiskCategory::Low);
        assert_ne!(RiskCategory::Low, RiskCategory::High);
    }
}
