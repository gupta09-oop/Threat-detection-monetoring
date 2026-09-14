/**
 * TypeScript domain models for Sh4d0w_St4lk3r SOC Frontend.
 * Matches backend schemas exactly.
 */

export type EntityType = 'USER' | 'IP' | 'HOST' | 'GLOBAL';

export type RiskSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type AlertStatus = 'NEW' | 'ACKNOWLEDGED' | 'ESCALATED' | 'CLOSED';

export type CaseStatus = 'OPEN' | 'INVESTIGATING' | 'RESOLVED' | 'DISMISSED';

export type EvidenceStrength = 'LOW' | 'MODERATE' | 'STRONG' | 'CONCLUSIVE';

export interface CanonicalEvent {
  event_id: string;
  timestamp: string;
  source_type: 'AUTH' | 'NETWORK' | 'SYSTEM';
  event_type: string;
  result: string;
  source_ip?: string | null;
  destination_ip?: string | null;
  user_id?: string | null;
  device_id?: string | null;
  action?: string | null;
  port?: number | null;
  protocol?: string | null;
  bytes?: number | null;
  geo?: Record<string, any> | null;
  metadata: Record<string, any>;
}

export interface ContributorDetail {
  score: number;
  maximum: number;
  explanation: string;
  [key: string]: any;
}

export interface StatisticalContributor extends ContributorDetail {
  evidence: string;
  evaluated_feature_count?: number;
  anomalous_feature_count?: number;
  features?: Array<{
    feature_name: string;
    score: number;
    is_anomalous: boolean;
    status: string;
    explanation: string;
  }>;
}

export interface IsolationForestContributor extends ContributorDetail {
  evidence: string;
  raw_decision_score?: number | null;
  normalized_anomaly_score?: number | null;
  top_feature_deviations?: Array<{
    feature_name: string;
    feature_value: number;
    deviation_score: number;
    direction: string;
  }>;
}

export interface ClusteringContributor extends ContributorDetail {
  evidence: string;
  assigned_cluster_id?: number | null;
  cluster_distance?: number | null;
  threshold_distance?: number | null;
  distance_ratio?: number | null;
  pca_coordinates?: [number, number] | null;
}

export interface DeterministicRulesContributor extends ContributorDetail {
  rule_count?: number;
  rules?: Array<{
    rule_id: string;
    score: number;
    is_anomalous: boolean;
    explanation: string;
  }>;
}

export interface CorrelationContributor extends ContributorDetail {
  evidence_strength: string;
  anomalous_detector_count?: number;
  independent_detector_count?: number;
}

export interface ContributorBreakdown {
  statistical: StatisticalContributor;
  isolation_forest: IsolationForestContributor;
  behavioral_clustering: ClusteringContributor;
  deterministic_rules: DeterministicRulesContributor;
  cross_entity_correlation: CorrelationContributor;
  final_score: number;
  severity: RiskSeverity;
}

export interface RiskScoreResult {
  risk_id: string;
  timestamp: string;
  entity_type: EntityType;
  entity_id: string;
  snapshot_id?: string | null;
  window_seconds?: number | null;
  final_score: number;
  severity: RiskSeverity;
  statistical_contribution: number;
  isolation_forest_contribution: number;
  clustering_contribution: number;
  rules_contribution: number;
  correlation_contribution: number;
  evidence_strength: EvidenceStrength | string;
  contributor_breakdown: ContributorBreakdown;
  explanation: string;
  source_fusion_id?: string | null;
  details: Record<string, any>;
}

export const ANALYST_ROSTER = [
  'Arjun Mehta',
  'Priya Sharma',
  'Rahul Verma',
  'Neha Kapoor',
] as const;

export type SyntheticAnalyst = typeof ANALYST_ROSTER[number];

export type ResolutionOutcome =
  | 'Confirmed Threat'
  | 'False Positive'
  | 'Benign Activity'
  | 'Other';

export interface AnalystNote {
  id?: string;
  analyst: string;
  timestamp: string;
  text: string;
}

export interface AlertResult {
  alert_id: string;
  risk_id: string;
  timestamp: string;
  entity_type: EntityType;
  entity_id: string;
  source_type?: string | null;
  severity: RiskSeverity;
  risk_score: number;
  title: string;
  summary: string;
  explanation: string;
  contributor_breakdown: ContributorBreakdown;
  evidence_strength: EvidenceStrength | string;
  contributing_detectors: string[];
  fusion_id?: string | null;
  snapshot_id?: string | null;
  case_id?: string | null;
  status: AlertStatus;
  occurrence_count: number;
  dedup_key: string;
  created_at: string;
  updated_at: string;
  assigned_analyst?: string | null;
  resolution?: string | null;
  resolution_notes?: string | null;
  details: Record<string, any>;
}

export interface CaseResult {
  case_id: string;
  entity_type: EntityType;
  entity_id: string;
  title: string;
  summary: string;
  opened_at: string;
  updated_at: string;
  status: CaseStatus;
  severity: RiskSeverity;
  total_risk_score: number;
  alert_count: number;
  kill_chain_stages: string[];
  affected_entities: {
    accounts?: string[];
    source_ips?: string[];
    devices?: string[];
    destination_ips?: string[];
    ports?: string[];
  };
  evidence_summary: Record<string, any>;
  risk_history: Array<{
    timestamp: string;
    score: number;
    severity: string;
    alert_id?: string;
  }>;
  assigned_to?: string | null;
  assigned_analyst?: string | null;
  resolution?: string | null;
  resolution_notes?: string | null;
}


export interface TimelineItem {
  item_id: string;
  timestamp: string;
  evidence_type: string;
  source: string;
  severity?: string | null;
  risk_score?: number | null;
  explanation: string;
  related_alert_id?: string | null;
  related_risk_id?: string | null;
  related_fusion_id?: string | null;
  details: Record<string, any>;
}

export interface HealthResponse {
  status: string;
  service: string;
  version: string;
}

export interface SimulationStatusResponse {
  running: boolean;
  scenario?: string | null;
  progress: number;
  events_generated: number;
  current_stage: string;
  started_at?: string | null;
  elapsed_seconds: number;
  completed: boolean;
  last_result?: {
    scenario?: string;
    events_generated?: number;
    alerts_created?: number;
    cases_created?: number;
    peak_risk_score?: number;
    latest_risk_score?: number;
    severity?: string;
    evidence_strength?: string;
    contributing_detectors?: string[];
    isolation_forest_evaluated?: boolean;
    clustering_evaluated?: boolean;
    explanation?: string;
  } | null;
  error?: string | null;
}

export interface SimulationStartRequest {
  scenario: string;
  seed?: number;
  duration_seconds?: number;
  intensity?: 'low' | 'normal' | 'high';
}

export interface SimulationStopResponse {
  success: boolean;
  message: string;
}

export interface ThreatReportResponse {
  report_header: {
    platform: string;
    title: string;
    report_id: string;
    generated_at: string;
  };
  incident_info: {
    incident_type: string;
    incident_id: string;
    title: string;
    attack_classification: string;
    severity: string;
    status: string;
    assigned_analyst?: string | null;
    resolution?: string | null;
    resolution_notes?: string | null;
  };
  risk_summary: {
    risk_score: number;
    max_score: number;
    severity: string;
    evidence_strength: string;
  };
  risk_breakdown: {
    statistical_baseline: { score: number; maximum: number; explanation: string };
    isolation_forest: { score: number; maximum: number; explanation: string };
    behavioral_clustering: { score: number; maximum: number; explanation: string };
    deterministic_rules: { score: number; maximum: number; explanation: string };
    cross_entity_correlation: { score: number; maximum: number; explanation: string };
    final_score: number;
  };
  detection_evidence: {
    contributing_detectors: string[];
    rationale: string;
    detector_states: Record<string, boolean>;
    anomalous_features: any[];
  };
  affected_entities: {
    target_entity_id: string;
    entity_type: string;
    source_ips: string[];
    accounts: string[];
    devices: string[];
    destination_ips: string[];
    ports: string[];
  };
  incident_timeline: Array<{
    timestamp: string;
    evidence_type: string;
    source: string;
    severity?: string | null;
    risk_score?: number | null;
    explanation: string;
  }>;
  investigation: {
    assigned_analyst?: string | null;
    analyst_notes: Array<{ analyst: string; timestamp: string; text: string }>;
    checklist_guidance: string[];
  };
  resolution: {
    resolution?: string | null;
    resolution_notes?: string | null;
    resolved_by?: string | null;
    final_status: string;
  };
  recommendations: string[];
}

