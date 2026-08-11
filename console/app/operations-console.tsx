"use client";

import type { FormEvent, ReactNode } from "react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

type ViewKey = "overview" | "incidents" | "assets" | "malware" | "traces" | "models" | "rules" | "response" | "system";

type ConsoleMetrics = {
  host_total: number;
  host_degraded: number;
  incident_open: number;
  detection_open: number;
  response_pending_approval: number;
  response_running: number;
  malware_quarantined: number;
  model_human_review: number;
  notification_pending: number;
};

type IncidentSummary = {
  incident_id: string;
  host_id: string | null;
  status: string;
  severity: string;
  attack_state: string;
  risk_score: number;
  assurance: string;
  summary: string | null;
  last_seen: string;
};

type IncidentEvidenceRef = {
  evidence_id: string;
  event_id: string;
  event_type: string;
  event_time: string;
  host_id: string;
  raw_ref: string;
  integrity_sha256: string | null;
  source_time_quality: string;
  is_late: boolean;
};

type IncidentTimelineEntry = {
  timeline_id: string;
  event_time: string;
  category: string;
  summary: string;
  evidence_event_ids: string[];
  assurance: string;
};

type IncidentClaim = {
  claim_id: string;
  category: string;
  statement: string;
  epistemic_status: string;
  verification_status: string;
  evidence_event_ids: string[];
  support_score: number;
  contradiction_score: number;
};

type IncidentEntity = {
  entity_id: string;
  entity_type: string;
  canonical_key: string;
  attributes: Record<string, unknown>;
  first_seen: string;
  last_seen: string;
};

type IncidentEdge = {
  edge_id: string;
  source_entity_id: string;
  target_entity_id: string;
  relationship: string;
  first_seen: string;
  last_seen: string;
  evidence_event_ids: string[];
  evidence_count: number;
};

type IncidentInvestigation = {
  schema_version: "0.1.0";
  tenant_id: string;
  incident_id: string;
  revision: number;
  primary_host_id: string;
  status: string;
  severity: string;
  confidence: number;
  risk_score: number;
  attack_state: string;
  summary: string | null;
  assurance: string;
  first_seen: string;
  last_seen: string;
  full_query_ref: string;
  aggregate_metrics: Record<string, unknown>;
  counts: {
    detections: number;
    source_evidence: number;
    indexed_evidence: number;
    timeline: number;
    claims: number;
    entities: number;
    edges: number;
  };
  evidence: IncidentEvidenceRef[];
  data_reductions: Array<{
    reduction_id: string;
    input_count: number;
    retained_count: number;
    dropped_count: number;
    full_query_ref: string;
  }>;
  timeline: IncidentTimelineEntry[];
  claims: IncidentClaim[];
  entities: IncidentEntity[];
  edges: IncidentEdge[];
  truncated_sections: string[];
};

type NormalizedEvent = {
  id: string;
  tenant_id: string;
  event_id: string;
  source_event_id: string | null;
  event_type: string;
  event_time: string;
  ingest_time: string;
  source_time_quality: string;
  status: string;
  revision: number;
  raw_ref: string;
  payload: Record<string, unknown>;
  labels: Record<string, unknown>;
  extensions: Record<string, unknown>;
};

type IncidentEvidenceDetail = {
  schema_version: "0.1.0";
  tenant_id: string;
  incident_id: string;
  revision: number;
  evidence: IncidentEvidenceRef;
  normalized_event: NormalizedEvent;
};

type TraceEvidenceRef = {
  trace_evidence_id: string;
  incident_id: string;
  incident_revision: number;
  incident_evidence_id: string;
  event_id: string;
  event_type: string;
  event_time: string;
  host_id: string;
  source_time_quality: string;
  is_late: boolean;
};

type TraceStep = {
  step_id: string;
  kind: string;
  event_time: string;
  source_host_id: string;
  target_host_id: string | null;
  summary: string;
  attack_state: string;
  evidence_count: number;
  evidence_ids: string[];
};

type TraceEntity = {
  entity_id: string;
  entity_type: string;
  canonical_key: string;
  first_seen: string;
  last_seen: string;
};

type TraceEdge = {
  edge_id: string;
  source_entity_id: string;
  target_entity_id: string;
  relationship: string;
  first_seen: string;
  last_seen: string;
  evidence_count: number;
  evidence_ids: string[];
  confidence: number;
};

type TraceTechnique = {
  technique_id: string;
  name: string;
  tactic: string;
  mapping_version: "p10-attack-map-v0.1.0";
  epistemic_status: string;
  evidence_count: number;
  evidence_ids: string[];
  source_rule_count: number;
  source_rule_ids: string[];
};

type TraceInfrastructureCluster = {
  cluster_id: string;
  observable_type: string;
  canonical_value: string;
  host_count: number;
  host_ids: string[];
  incident_count: number;
  incident_ids: string[];
  evidence_count: number;
  evidence_ids: string[];
  similarity_basis: "exact_observable_match";
};

type TraceInvestigation = {
  schema_version: "0.1.0";
  tenant_id: string;
  trace_id: string;
  revision: number;
  revision_reason: string;
  seed_incident_id: string;
  first_seen: string;
  last_seen: string;
  attack_state: string;
  counts: {
    source_incidents: number;
    evidence: number;
    key_path: number;
    impacted_hosts: number;
    infrastructure_clusters: number;
    techniques: number;
    entities: number;
    edges: number;
  };
  source_incidents: Array<{
    incident_id: string;
    revision: number;
    primary_host_id: string;
    severity: string;
    attack_state: string;
    first_seen: string;
    last_seen: string;
  }>;
  initial_access: TraceStep | null;
  key_path: TraceStep[];
  impacted_host_ids: string[];
  infrastructure_clusters: TraceInfrastructureCluster[];
  techniques: TraceTechnique[];
  evidence: TraceEvidenceRef[];
  entities: TraceEntity[];
  edges: TraceEdge[];
  identity_attribution_status: "not_attributed";
  identity_assertion_count: 0;
  identity_attribution_reason: "no_verified_identity_evidence";
  attribution_limitations: string[];
  raw_ref_included: false;
  raw_evidence_bytes_included: false;
  interactive_graph_query_available: false;
  investigation_export_available: false;
  truncated_sections: string[];
};

type HostSummary = {
  host_id: string;
  hostname: string;
  distro: string | null;
  kernel: string | null;
  criticality: string;
  agent_id: string | null;
  agent_version: string | null;
  agent_version_reported_at: string | null;
  freshness_status: string;
  freshness_lag_seconds: number | null;
};

type MalwareSummary = {
  sample_id: string;
  sha256: string;
  filename: string | null;
  media_type: string;
  size: number;
  status: string;
  created_at: string;
};

type MalwareTaskSummary = {
  task_id: string;
  sample_id: string;
  status: string;
  attempt_count: number;
  max_attempts: number;
  last_error_code: string | null;
  has_report: boolean;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
};

type MalwareEngineSummary = {
  source_id: string;
  kind: string;
  status: string;
  signal: string;
  confidence: number;
  matched_rules: string[];
  malware_type_candidates: string[];
  family_candidates: string[];
  observations: string[];
  error_code: string | null;
  matched_rule_count: number;
  malware_type_candidate_count: number;
  family_candidate_count: number;
  observation_count: number;
  truncated_fields: string[];
};

type MalwareContextSummary = {
  context_id: string;
  source_sample_id: string;
  host_id: string | null;
  creator_process: string | null;
  executor_process: string | null;
  parent_process: string | null;
  source_url: string | null;
  destination_path: string | null;
  persistence_mechanism: string | null;
  evidence_event_ids: string[];
  evidence_event_count: number;
  evidence_truncated: boolean;
  observed_at: string;
};

type MalwareInvestigation = {
  schema_version: "0.1.0";
  tenant_id: string;
  sample: MalwareSummary;
  updated_at: string;
  counts: {
    tasks: number;
    same_hash_contexts: number;
    engine_results: number;
    profile_strings: number;
    archive_entries: number;
  };
  tasks: MalwareTaskSummary[];
  analysis: null | {
    task_id: string;
    disposition: string;
    confidence: number;
    malware_type: string;
    families: Array<{ family: string; status: string; supporting_sources: string[] }>;
    cleanup_advice: string[];
    dynamic_analysis_status: string;
    dynamic_analysis_reason: string;
    sandbox_report_id: string | null;
    warnings: string[];
    completed_at: string;
    profile: {
      sha256: string;
      size: number;
      declared_media_type: string | null;
      detected_media_type: string;
      kind: string;
      signatures: string[];
      entropy: number;
      architecture: string | null;
      executable_format: string | null;
      interpreter: string | null;
      archive: null | {
        format: string;
        declared_entry_count: number;
        inspected_entry_count: number;
        total_uncompressed_size: number;
        truncated: boolean;
        violations: string[];
        violation_count: number;
        violations_truncated: boolean;
      };
      warnings: string[];
      signature_count: number;
      warning_count: number;
      truncated_fields: string[];
    };
    engine_results: MalwareEngineSummary[];
    family_count: number;
    cleanup_advice_count: number;
    warning_count: number;
    truncated_fields: string[];
  };
  same_hash_contexts: MalwareContextSummary[];
  truncated_sections: string[];
};

type RuleTenantMetrics = {
  hit_count: number;
  governed_hit_count: number;
  legacy_hit_count: number;
  open_hit_count: number;
  distinct_host_count: number;
  shadow_observation_count: number;
  shadow_distinct_host_count: number;
  feedback_total: number;
  true_positive_feedback: number;
  false_positive_feedback: number;
  benign_feedback: number;
  needs_review_feedback: number;
  last_hit_at: string | null;
  last_shadow_at: string | null;
};

type RuleQualityMetrics = {
  precision: number | null;
  recall: number | null;
  false_positives_per_host_day: number | null;
  attack_attempt_success_error_rate: number | null;
  mttd_seconds: number | null;
  missing_source_sensitivity: number | null;
  performance_ms_per_1000_events: number | null;
};

type RuleGovernanceEntry = {
  rule_id: string;
  version: string;
  title: string;
  owner: string;
  lifecycle_stage: string;
  runtime_state: string;
  emission_scope: string;
  runtime_emits_persisted_detections: boolean;
  formal_release_gate_closed: boolean;
  lifecycle_rule_version: string | null;
  lifecycle_sequence: number | null;
  manifest_sha256: string | null;
  signing_key_id: string | null;
  catalog_digest_matches: boolean | null;
  canary_host_ids: string[];
  canary_host_count: number;
  validation_evidence_count: number;
  manifest_issued_at: string | null;
  manifest_expires_at: string | null;
  manifest_applied_at: string | null;
  data_sources: string[];
  test_datasets: string[];
  expected_false_positives: string[];
  technique_ids: string[];
  suppression_conditions: string[];
  rollback_plan: string;
  runtime_note: string;
  tenant_metrics: RuleTenantMetrics;
  quality_metrics: RuleQualityMetrics;
};

type HistoricalRuleVersion = {
  rule_id: string;
  version: string;
  registered_current_version: boolean;
  tenant_metrics: RuleTenantMetrics;
};

type IntelligenceCacheEntry = {
  cache_id: string;
  kind: string;
  indicator: string;
  lookup_hash: string;
  source: string;
  cache_state: string;
  payload_fields: string[];
  payload_field_count: number;
  payload_fields_truncated: boolean;
  fetched_at: string;
  expires_at: string | null;
};

type RuleIntelligenceOperations = {
  schema_version: "0.1.0";
  tenant_id: string;
  generated_at: string;
  counts: {
    registered_rules: number;
    persisted_rule_versions: number;
    historical_rule_versions: number;
    intelligence_entries: number;
    governed_detections: number;
    legacy_detections: number;
    shadow_observations: number;
  };
  rules: RuleGovernanceEntry[];
  historical_rule_versions: HistoricalRuleVersion[];
  intelligence_cache: IntelligenceCacheEntry[];
  truncated_sections: string[];
  lifecycle_enforcement_available: true;
  managed_ioc_lifecycle_available: false;
};

type ModelRunSummary = {
  run_id: string;
  incident_id: string;
  provider: string;
  model: string;
  role: string;
  status: string;
  latency_ms: number;
  cost_usd: number;
  created_at: string;
};

type ModelProviderConfiguration = {
  enabled: boolean;
  provider: string;
  model_name: string | null;
  api_key_state: string;
  base_url_state: string;
  configuration_complete: boolean;
  credential_validity: "not_tested";
  health_status: "not_probed";
  enabled_roles: string[];
  supports_tools: boolean;
  supports_json_schema: boolean;
  model_context_tokens: number;
  max_response_bytes: number;
  provider_timeout_seconds: number;
  provider_max_retries: number;
  circuit_failure_threshold: number;
  circuit_recovery_seconds: number;
  max_context_tokens: number;
  max_output_tokens: number;
  max_tool_calls: number;
  max_model_runs_per_incident: number;
  max_verifier_slots: number;
  adjudicator_enabled: boolean;
  max_reviews_per_minute: number;
  max_cost_usd_per_incident: number;
};

type ModelRunAggregate = {
  provider: string;
  model: string;
  role: string;
  run_count: number;
  completed_count: number;
  failed_count: number;
  circuit_open_count: number;
  failure_rate: number;
  average_latency_ms: number;
  total_input_tokens: number;
  total_output_tokens: number;
  total_cost_usd: number;
  total_retries: number;
  total_tool_calls: number;
  last_run_at: string;
};

type ModelReviewMetrics = {
  task_count: number;
  skipped_count: number;
  completed_count: number;
  model_unavailable_count: number;
  invalid_output_count: number;
  budget_exceeded_count: number;
  require_human_status_count: number;
  verification_required_count: number;
  human_review_required_count: number;
  deterministic_only_count: number;
  unreviewed_count: number;
  basic_count: number;
  enhanced_count: number;
  high_count: number;
  last_review_at: string | null;
};

type ModelOperations = {
  schema_version: "0.1.0";
  tenant_id: string;
  generated_at: string;
  counts: {
    review_tasks: number;
    model_runs: number;
    aggregate_groups: number;
  };
  provider_configuration: ModelProviderConfiguration;
  review_metrics: ModelReviewMetrics;
  review_quality: {
    labeled_performance_available: false;
    labeled_outcome_count: 0;
    precision: null;
    recall: null;
    ground_truth_agreement: null;
    false_positive_rate: null;
  };
  run_aggregates: ModelRunAggregate[];
  recent_runs: ModelRunSummary[];
  truncated_sections: string[];
  provider_health_probe_available: false;
  credential_validation_available: false;
  labeled_feedback_linkage_available: false;
};

type SystemOperations = {
  schema_version: "0.1.0";
  tenant_id: string;
  generated_at: string;
  tenant: {
    tenant_id: string;
    name: string;
    created_at: string;
    credential_counts: {
      total: number;
      active: number;
      expired: number;
      revoked: number;
    };
  };
  credentials: Array<{
    credential_id: string;
    tenant_id: string;
    roles: string[];
    lifecycle: "active" | "expired" | "revoked";
    created_at: string;
    expires_at: string | null;
    revoked_at: string | null;
  }>;
  agent_queue: {
    heartbeat_hosts_total: number;
    aggregated_hosts: number;
    queued_count: number;
    inflight_count: number;
    corrupt_count: number;
    stored_bytes: number;
    dropped_p0: 0;
    dropped_p1: number;
    dropped_p2: number;
    dropped_p3: number;
    protection_mode_hosts: number;
    latest_heartbeat_received_at: string | null;
  };
  agent_versions: {
    source: "self_reported_heartbeat";
    binary_integrity_verified: false;
    bound_hosts_total: number;
    reported_hosts: number;
    unreported_hosts: number;
    distinct_versions: number;
    version_groups: Array<{
      version: string;
      host_count: number;
      latest_reported_at: string;
    }>;
  };
  work_queues: {
    raw_events_total: number;
    normalize_pending: number;
    normalize_done: number;
    normalize_failed: number;
    malware_tasks_total: number;
    malware_queued: number;
    malware_leased: number;
    malware_completed: number;
    malware_failed: number;
    response_actions_total: number;
    response_pending_approval: number;
    response_approved: number;
    response_queued: number;
    response_executing: number;
    response_rollback_queued: number;
    response_rolling_back: number;
    response_terminal: number;
    notifications_total: number;
    notifications_pending: number;
    notifications_delivering: number;
    notifications_retry_scheduled: number;
    notifications_delivered: number;
    notifications_dead_letter: number;
  };
  storage_records: {
    raw_events: number;
    normalized_events: number;
    evidence_objects: number;
    malware_samples: number;
    audit_records: number;
  };
  errors: {
    total: number;
    normalize_failed: number;
    event_dlq_records: number;
    agent_queue_corrupt: number;
    malware_failed: number;
    response_failed: number;
    notifications_dead_letter: number;
  };
  freshness: {
    tracked_hosts: number;
    fresh: number;
    stale: number;
    degraded: number;
    unknown: number;
    lag_sample_count: number;
    average_lag_seconds: number | null;
    maximum_lag_seconds: number | null;
    updated_at: string | null;
  };
  versions: {
    application_version: string;
    database_migration_version: string | null;
    database_schema_compatibility: "not_evaluated";
  };
  upgrade: {
    status: "not_implemented";
    agent_rollout_available: false;
    automatic_rollback_available: false;
    offline_package_inventory_available: false;
    signed_artifact_inventory_available: false;
    backup_restore_evidence_available: false;
  };
  availability: {
    message_broker_metrics_available: false;
    backlog_age_metrics_available: false;
    database_capacity_metrics_available: false;
    object_storage_capacity_metrics_available: false;
    dependency_health_probes_available: false;
    deployment_inventory_available: false;
    agent_version_inventory_available: true;
    agent_version_binary_integrity_verification_available: false;
    human_user_directory_available: false;
  };
  truncated_sections: string[];
};

type ResponsePlan = {
  action_id: string;
  tenant_id: string;
  incident_id: string;
  incident_revision: number;
  action: string;
  tier: string;
  status: string;
  target: ResponseTarget;
  target_identity_sha256: string;
  evidence_ids: string[];
  reason: string;
  operation: string;
  adapter: string;
  requested_by: string;
  approval_count: number;
  policy: {
    required_approvals: number;
    rollback_required: boolean;
    rollback_supported: boolean;
    target_revalidation_required: boolean;
    execution_verification_required: boolean;
    business_confirmation_required: boolean;
    reasons: string[];
  };
  ttl_seconds: number | null;
  created_at: string;
  expires_at: string | null;
  queued_at: string | null;
  completed_at: string | null;
};

type ResponseTarget = {
  target_type: string;
  host_id: string;
  expected_agent_id: string;
  [key: string]: unknown;
};

type ResponseApproval = {
  approval_id: string;
  decision: string;
  approver: string;
  comment: string;
  business_confirmation: boolean;
  created_at: string;
};

type ResponseResult = {
  status: string;
  adapter: string;
  operation_reference: string;
  verification_passed: boolean;
  error_code: string | null;
};

type ResponseExecution = {
  execution_id: string;
  attempt: number;
  status: string;
  result: ResponseResult;
  started_at: string;
  completed_at: string;
};

type ResponseRollback = {
  rollback_id: string;
  execution_id: string;
  reason: string;
  requested_by: string;
  status: string;
  result: ResponseResult;
  started_at: string;
  completed_at: string;
};

type ResponseEvent = {
  sequence: number;
  from_status: string | null;
  to_status: string;
  actor: string;
  reason: string;
  created_at: string;
};

type ResponseActionDetail = {
  plan: ResponsePlan;
  approvals: ResponseApproval[];
  executions: ResponseExecution[];
  rollbacks: ResponseRollback[];
  events: ResponseEvent[];
};

type ErrorEnvelope = {
  detail?: string;
  code?: string;
  error?: {
    message?: string;
    details?: { reason?: string };
  };
};

type ConsoleSnapshot = {
  schema_version: "0.1.0";
  tenant_id: string;
  generated_at: string;
  metrics: ConsoleMetrics;
  incidents: IncidentSummary[];
  hosts: HostSummary[];
  malware: MalwareSummary[];
  model_runs: ModelRunSummary[];
  response_actions: ResponsePlan[];
};

const NAV_ITEMS: Array<{ key: ViewKey; label: string; glyph: string }> = [
  { key: "overview", label: "安全总览", glyph: "01" },
  { key: "incidents", label: "事件研判", glyph: "02" },
  { key: "assets", label: "资产态势", glyph: "03" },
  { key: "malware", label: "恶意文件", glyph: "04" },
  { key: "traces", label: "攻击溯源", glyph: "05" },
  { key: "models", label: "模型审核", glyph: "06" },
  { key: "rules", label: "规则与情报", glyph: "07" },
  { key: "response", label: "响应审批", glyph: "08" },
  { key: "system", label: "系统运营", glyph: "09" },
];

const VIEW_COPY: Record<ViewKey, { eyebrow: string; title: string; description: string }> = {
  overview: {
    eyebrow: "Security posture",
    title: "安全运营总览",
    description: "从确定性事实到 Incident、模型审核与受控响应，保持每一步可回溯。",
  },
  incidents: {
    eyebrow: "Incident review",
    title: "事件研判",
    description: "按风险、攻击状态与证据保证等级查看当前租户的事件队列。",
  },
  assets: {
    eyebrow: "Asset posture",
    title: "资产态势",
    description: "聚合主机关键度、Agent 绑定、发行版与数据新鲜度。",
  },
  malware: {
    eyebrow: "Malware evidence",
    title: "恶意文件",
    description: "查看隔离样本的哈希、来源元数据与独立分析状态。",
  },
  traces: {
    eyebrow: "Technical attribution",
    title: "攻击溯源",
    description: "沿证据闭合的跨主机路径核对入口、横向关系、影响范围与明确的归因限制。",
  },
  models: {
    eyebrow: "AI assurance",
    title: "模型审核",
    description: "观察 Analyzer、Verifier 与 Adjudicator 的延迟、成本和审核结果。",
  },
  rules: {
    eyebrow: "Rule governance",
    title: "规则与情报运营",
    description: "核对规则版本、生命周期缺口、租户命中与反馈，并只读查看有界情报缓存元数据。",
  },
  response: {
    eyebrow: "Controlled response",
    title: "响应审批",
    description: "追踪固定动作的策略门控、审批计数与执行状态。",
  },
  system: {
    eyebrow: "System operations",
    title: "系统运营",
    description: "核对租户持久状态、Agent 队列、错误、版本与尚未实现的运维能力。",
  },
};

const EMPTY_METRICS: ConsoleMetrics = {
  host_total: 0,
  host_degraded: 0,
  incident_open: 0,
  detection_open: 0,
  response_pending_approval: 0,
  response_running: 0,
  malware_quarantined: 0,
  model_human_review: 0,
  notification_pending: 0,
};

export function OperationsConsole() {
  const [view, setView] = useState<ViewKey>("overview");
  const [token, setToken] = useState("");
  const [snapshot, setSnapshot] = useState<ConsoleSnapshot | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [csrfNonce, setCsrfNonce] = useState("");
  const csrfNonceRef = useRef("");

  const loadSnapshot = useCallback(
    async (candidate = token) => {
      const credential = candidate.trim();
      if (!credential) {
        setError("请输入具备控制台读取权限的操作员令牌。");
        return;
      }
      setBusy(true);
      setError(null);
      try {
        const response = await fetch("/api/platform/snapshot?limit=20", {
          headers: { authorization: `Bearer ${credential}` },
          cache: "no-store",
        });
        const payload = (await response.json()) as ConsoleSnapshot | { detail?: string };
        if (!response.ok) {
          const detail = "detail" in payload ? payload.detail : undefined;
          throw new Error(detail || `控制面返回 HTTP ${response.status}`);
        }
        setSnapshot(payload as ConsoleSnapshot);
        if (!csrfNonceRef.current) {
          try {
            const writeSessionResponse = await fetch("/api/platform/write-session", {
              headers: { authorization: `Bearer ${credential}` },
              cache: "no-store",
            });
            const writeSessionPayload: unknown = await writeSessionResponse.json();
            if (
              !writeSessionResponse.ok
              || !isRecord(writeSessionPayload)
              || typeof writeSessionPayload.csrf_nonce !== "string"
            ) {
              setError(`只读连接成功，但写入会话不可用：${apiErrorMessage(writeSessionPayload, writeSessionResponse.status)}`);
            } else {
              csrfNonceRef.current = writeSessionPayload.csrf_nonce;
              setCsrfNonce(writeSessionPayload.csrf_nonce);
            }
          } catch {
            setError("只读连接成功，但无法建立受保护的写入会话。");
          }
        }
      } catch (caught) {
        setSnapshot(null);
        csrfNonceRef.current = "";
        setCsrfNonce("");
        setError(caught instanceof Error ? caught.message : "无法读取控制面快照。");
      } finally {
        setBusy(false);
      }
    },
    [token],
  );

  useEffect(() => {
    if (!snapshot || !token.trim()) return;
    const interval = window.setInterval(() => {
      if (document.visibilityState === "visible") void loadSnapshot();
    }, 30_000);
    return () => window.clearInterval(interval);
  }, [loadSnapshot, snapshot, token]);

  const metrics = snapshot?.metrics ?? EMPTY_METRICS;
  const copy = VIEW_COPY[view];
  const connected = snapshot !== null;

  const riskCounts = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const incident of snapshot?.incidents ?? []) {
      const key = incident.severity.toLowerCase();
      if (key in counts) counts[key as keyof typeof counts] += 1;
    }
    return counts;
  }, [snapshot]);

  const disconnect = () => {
    setSnapshot(null);
    setToken("");
    setError(null);
    csrfNonceRef.current = "";
    setCsrfNonce("");
  };

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    void loadSnapshot(token);
  };

  let content: ReactNode;
  if (view === "overview") {
    content = (
      <Overview
        snapshot={snapshot}
        riskCounts={riskCounts}
        connected={connected}
      />
    );
  } else if (view === "incidents") {
    content = (
      <IncidentWorkspace
        incidents={snapshot?.incidents ?? []}
        key={snapshot?.tenant_id ?? "locked"}
        token={token}
      />
    );
  } else if (view === "assets") {
    content = <AssetTable hosts={snapshot?.hosts ?? []} />;
  } else if (view === "malware") {
    content = (
      <MalwareWorkspace
        key={snapshot?.tenant_id ?? "locked"}
        samples={snapshot?.malware ?? []}
        token={token}
      />
    );
  } else if (view === "traces") {
    content = (
      <TraceWorkspace
        incidents={snapshot?.incidents ?? []}
        key={snapshot?.tenant_id ?? "locked"}
        token={token}
      />
    );
  } else if (view === "models") {
    content = (
      <ModelOperationsWorkspace
        key={snapshot?.tenant_id ?? "locked"}
        token={token}
      />
    );
  } else if (view === "rules") {
    content = (
      <RulesIntelligenceWorkspace
        key={snapshot?.tenant_id ?? "locked"}
        token={token}
      />
    );
  } else if (view === "response") {
    content = (
      <ResponseWorkspace
        actions={snapshot?.response_actions ?? []}
        csrfNonce={csrfNonce}
        key={csrfNonce || "locked"}
        onChanged={() => loadSnapshot()}
        token={token}
      />
    );
  } else {
    content = (
      <SystemOperationsWorkspace
        key={snapshot?.tenant_id ?? "locked"}
        token={token}
      />
    );
  }

  return (
    <div className="console-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark" aria-hidden="true">BT</div>
          <div className="brand-copy">
            <strong>AI-SOC</strong>
            <span>Evidence Operations</span>
          </div>
        </div>
        <div className="nav-label">Workspace</div>
        <nav className="nav-list" aria-label="控制台导航">
          {NAV_ITEMS.map((item) => (
            <button
              className="nav-item"
              data-active={view === item.key}
              key={item.key}
              onClick={() => setView(item.key)}
              type="button"
            >
              <span className="nav-glyph" aria-hidden="true">{item.glyph}</span>
              <span className="nav-name">{item.label}</span>
            </button>
          ))}
        </nav>
        <div className="sidebar-footer">
          <div className="connection-mini">
            <span className="status-dot" data-live={connected} aria-hidden="true" />
            <div>
              <strong>{connected ? "控制面已连接" : "等待安全连接"}</strong>
              <span>{snapshot?.tenant_id ?? "Operator session locked"}</span>
            </div>
          </div>
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <div className="heading">
            <div className="eyebrow">{copy.eyebrow}</div>
            <h1>{copy.title}</h1>
            <p>{copy.description}</p>
          </div>
          <div className="toolbar">
            <button
              className="quiet-button"
              disabled={!connected || busy}
              onClick={() => void loadSnapshot()}
              type="button"
            >
              {busy ? "同步中" : "刷新快照"}
            </button>
            {connected && (
              <button className="lock-button" onClick={disconnect} type="button">
                锁定会话
              </button>
            )}
          </div>
        </header>

        {!connected && (
          <section className="connect-card" aria-labelledby="connect-title">
            <div className="connect-copy">
              <div className="eyebrow">Memory-only credential</div>
              <h2 id="connect-title">连接租户控制面</h2>
              <p>令牌仅保留在当前页面内存，不写入浏览器存储；关闭或锁定页面后即清除。</p>
            </div>
            <form className="connect-form" onSubmit={submit}>
              <label className="sr-only" htmlFor="operator-token">操作员 API 令牌</label>
              <input
                autoComplete="off"
                className="token-input"
                id="operator-token"
                name="operator-token"
                onChange={(event) => setToken(event.target.value)}
                placeholder="粘贴 responder / approver / auditor 令牌"
                spellCheck={false}
                type="password"
                value={token}
              />
              <button className="primary-button" disabled={busy} type="submit">
                {busy ? "验证中" : "安全连接"}
              </button>
            </form>
          </section>
        )}

        {error && <div className="error-banner" role="alert">{error}</div>}

        <MetricGrid metrics={metrics} connected={connected} />

        <div className="view-summary">
          <span>{connected ? `租户 ${snapshot.tenant_id}` : "未加载任何租户数据"}</span>
          <span className="live-stamp">
            <span className="status-dot" data-live={connected} aria-hidden="true" />
            {connected ? `快照 ${formatTime(snapshot.generated_at)}` : "数据源已锁定"}
          </span>
        </div>

        {content}
      </main>
    </div>
  );
}

function MetricGrid({ metrics, connected }: { metrics: ConsoleMetrics; connected: boolean }) {
  const cards = [
    ["开放事件", metrics.incident_open, "alert", "Incident"],
    ["降级资产", metrics.host_degraded, "warn", `${metrics.host_total} hosts`],
    ["待审批", metrics.response_pending_approval, "warn", "Policy gate"],
    ["响应执行", metrics.response_running, "good", "Action runner"],
    ["隔离样本", metrics.malware_quarantined, "alert", "Quarantine"],
    ["人工复核", metrics.model_human_review, "warn", "AI assurance"],
  ] as const;
  return (
    <section className="metrics-grid" aria-label="安全指标">
      {cards.map(([label, value, tone, foot]) => (
        <article className="metric-card" data-tone={connected ? tone : undefined} key={label}>
          <span className="metric-label">{label}</span>
          <strong className="metric-value">{value.toString().padStart(2, "0")}</strong>
          <span className="metric-foot">{connected ? foot : "Awaiting data"}</span>
        </article>
      ))}
    </section>
  );
}

function Overview({
  snapshot,
  riskCounts,
  connected,
}: {
  snapshot: ConsoleSnapshot | null;
  riskCounts: Record<"critical" | "high" | "medium" | "low", number>;
  connected: boolean;
}) {
  const incidents = snapshot?.incidents ?? [];
  const maximum = Math.max(1, ...Object.values(riskCounts));
  return (
    <div className="dashboard-grid">
      <div>
        <section className="panel">
          <PanelHeader title="高优先级事件" note="当前 Incident revision" />
          <IncidentTable incidents={incidents.slice(0, 7)} embedded />
        </section>
        <section className="panel">
          <PanelHeader title="响应队列" note="审批与执行状态" />
          <ResponseTable actions={(snapshot?.response_actions ?? []).slice(0, 6)} embedded />
        </section>
      </div>
      <div>
        <section className="panel">
          <PanelHeader title="风险分布" note={connected ? `${incidents.length} recent` : "locked"} />
          <div className="panel-body risk-stack">
            {(["critical", "high", "medium", "low"] as const).map((key) => (
              <div className="risk-row" key={key}>
                <span>{severityLabel(key)}</span>
                <div className="risk-track">
                  <div
                    className="risk-fill"
                    data-tone={toneForSeverity(key)}
                    style={{ width: `${(riskCounts[key] / maximum) * 100}%` }}
                  />
                </div>
                <span className="risk-count">{riskCounts[key]}</span>
              </div>
            ))}
          </div>
        </section>
        <section className="panel">
          <PanelHeader title="资产新鲜度" note={`${snapshot?.hosts.length ?? 0} visible`} />
          <div className="panel-body asset-list">
            {(snapshot?.hosts ?? []).slice(0, 6).map((host) => (
              <div className="asset-row" key={host.host_id}>
                <div className="asset-id">
                  <strong>{host.hostname}</strong>
                  <span>{host.distro ?? "unknown distro"} · {host.kernel ?? "kernel unknown"}</span>
                </div>
                <StatusPill value={host.freshness_status} />
              </div>
            ))}
            {!snapshot?.hosts.length && <EmptyState text="连接控制面后显示资产心跳与新鲜度。" />}
          </div>
        </section>
      </div>
    </div>
  );
}

function IncidentWorkspace({ incidents, token }: { incidents: IncidentSummary[]; token: string }) {
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [detail, setDetail] = useState<IncidentInvestigation | null>(null);
  const [evidenceDetail, setEvidenceDetail] = useState<IncidentEvidenceDetail | null>(null);
  const [activeSection, setActiveSection] = useState<"timeline" | "evidence" | "claims" | "graph">("timeline");
  const [detailBusy, setDetailBusy] = useState(false);
  const [evidenceBusy, setEvidenceBusy] = useState(false);
  const [workspaceError, setWorkspaceError] = useState<string | null>(null);

  const loadInvestigation = async (incidentId: string) => {
    setSelectedIncidentId(incidentId);
    setDetailBusy(true);
    setWorkspaceError(null);
    setDetail(null);
    setEvidenceDetail(null);
    try {
      const response = await fetch(
        `/api/platform/incident-detail?incident_id=${encodeURIComponent(incidentId)}`,
        {
          headers: { authorization: `Bearer ${token.trim()}` },
          cache: "no-store",
        },
      );
      const payload: unknown = await response.json();
      if (!response.ok || !isIncidentInvestigation(payload)) {
        throw new Error(response.ok ? "控制面返回的 Incident 调查详情格式无效。" : apiErrorMessage(payload, response.status));
      }
      setDetail(payload);
      setActiveSection("timeline");
    } catch (caught) {
      setWorkspaceError(caught instanceof Error ? caught.message : "无法读取 Incident 调查详情。");
    } finally {
      setDetailBusy(false);
    }
  };

  const loadEvidence = async (evidenceId: string) => {
    if (!selectedIncidentId) return;
    setEvidenceBusy(true);
    setWorkspaceError(null);
    setEvidenceDetail(null);
    try {
      const query = new URLSearchParams({
        incident_id: selectedIncidentId,
        evidence_id: evidenceId,
      });
      const response = await fetch(`/api/platform/incident-evidence?${query}`, {
        headers: { authorization: `Bearer ${token.trim()}` },
        cache: "no-store",
      });
      const payload: unknown = await response.json();
      if (!response.ok || !isIncidentEvidenceDetail(payload)) {
        throw new Error(response.ok ? "控制面返回的证据详情格式无效。" : apiErrorMessage(payload, response.status));
      }
      setEvidenceDetail(payload);
    } catch (caught) {
      setWorkspaceError(caught instanceof Error ? caught.message : "无法读取归属证据详情。");
    } finally {
      setEvidenceBusy(false);
    }
  };

  return (
    <div className="incident-workspace">
      <section className="panel">
        <PanelHeader title="Incident 队列" note={`${incidents.length} records · bounded investigation`} />
        <IncidentTable
          embedded
          incidents={incidents}
          onSelect={(incidentId) => void loadInvestigation(incidentId)}
          selectedIncidentId={selectedIncidentId}
        />
      </section>
      <section className="panel investigation-panel" aria-live="polite">
        <PanelHeader
          title="Incident 调查工作区"
          note={detail ? `${detail.incident_id} · revision ${detail.revision}` : "tenant + revision scoped"}
        />
        {workspaceError && <div className="inline-message" data-tone="critical" role="alert">{workspaceError}</div>}
        {detailBusy && <div className="empty-state">正在锁定当前 revision 并加载有界调查视图…</div>}
        {!detailBusy && !detail && <EmptyState text="选择一个 Incident，查看时间线、证据、Claim 与实体关系。" />}
        {!detailBusy && detail && (
          <IncidentInvestigationDetail
            activeSection={activeSection}
            detail={detail}
            evidenceBusy={evidenceBusy}
            evidenceDetail={evidenceDetail}
            onEvidence={(evidenceId) => void loadEvidence(evidenceId)}
            onSection={setActiveSection}
          />
        )}
      </section>
    </div>
  );
}

function IncidentInvestigationDetail({
  activeSection,
  detail,
  evidenceBusy,
  evidenceDetail,
  onEvidence,
  onSection,
}: {
  activeSection: "timeline" | "evidence" | "claims" | "graph";
  detail: IncidentInvestigation;
  evidenceBusy: boolean;
  evidenceDetail: IncidentEvidenceDetail | null;
  onEvidence: (evidenceId: string) => void;
  onSection: (section: "timeline" | "evidence" | "claims" | "graph") => void;
}) {
  const sections = [
    ["timeline", "时间线", detail.counts.timeline],
    ["evidence", "证据", detail.counts.indexed_evidence],
    ["claims", "Claims", detail.counts.claims],
    ["graph", "实体关系", detail.counts.entities + detail.counts.edges],
  ] as const;

  return (
    <div className="investigation-body">
      <div className="investigation-hero">
        <div>
          <div className="eyebrow">{detail.primary_host_id} · {detail.assurance}</div>
          <h3>{detail.summary || "无摘要"}</h3>
          <p>{attackStateLabel(detail.attack_state)} · first {formatTime(detail.first_seen)} · last {formatTime(detail.last_seen)}</p>
        </div>
        <div className="investigation-risk">
          <span>Risk</span>
          <strong>{detail.risk_score}</strong>
          <span>{severityLabel(detail.severity)}</span>
        </div>
      </div>

      <div className="investigation-facts">
        <DetailRow label="状态" value={statusLabel(detail.status)} />
        <DetailRow label="置信度" value={`${Math.round(detail.confidence * 100)}%`} />
        <DetailRow label="Detection" value={String(detail.counts.detections)} />
        <DetailRow label="源证据" value={String(detail.counts.source_evidence)} />
        <DetailRow label="索引证据" value={String(detail.counts.indexed_evidence)} />
        <DetailRow label="查询引用" value={detail.full_query_ref} mono />
      </div>

      {detail.truncated_sections.length > 0 && (
        <div className="bounded-notice">
          当前控制台视图已对 {detail.truncated_sections.join("、")} 应用固定上限；完整范围保留在查询引用中。
        </div>
      )}

      <nav className="investigation-tabs" aria-label="Incident 调查分区">
        {sections.map(([key, label, count]) => (
          <button data-active={activeSection === key} key={key} onClick={() => onSection(key)} type="button">
            {label}<span>{count}</span>
          </button>
        ))}
      </nav>

      {activeSection === "timeline" && (
        <section className="investigation-section">
          {detail.timeline.map((item) => (
            <div className="investigation-timeline-row" key={item.timeline_id}>
              <span className="timeline-marker" data-tone={toneForStatus(item.assurance)} />
              <div>
                <div className="timeline-heading"><strong>{item.summary}</strong><span>{formatTime(item.event_time)}</span></div>
                <p>{item.category.replaceAll("_", " ")} · {statusLabel(item.assurance)}</p>
                <code>{item.evidence_event_ids.map(compactHash).join(", ")}</code>
              </div>
            </div>
          ))}
          {!detail.timeline.length && <EmptyState text="当前 revision 没有时间线记录。" />}
        </section>
      )}

      {activeSection === "evidence" && (
        <section className="investigation-section evidence-layout">
          <div className="table-scroll">
            <table className="data-table">
              <thead><tr><th>证据</th><th>类型 / 主机</th><th>时间质量</th><th>事件时间</th><th>详情</th></tr></thead>
              <tbody>{detail.evidence.map((item) => (
                <tr key={item.evidence_id}>
                  <td><span className="strong mono">{item.evidence_id}</span><span className="subline mono">{compactHash(item.event_id)}</span></td>
                  <td>{item.event_type}<span className="subline mono">{item.host_id}</span></td>
                  <td><StatusPill value={item.is_late ? "late" : item.source_time_quality} /></td>
                  <td>{formatTime(item.event_time)}</td>
                  <td><button className="row-action" onClick={() => onEvidence(item.evidence_id)} type="button">查看事实</button></td>
                </tr>
              ))}</tbody>
            </table>
            {!detail.evidence.length && <EmptyState text="当前 revision 没有可见证据索引。" />}
          </div>
          {evidenceBusy && <div className="evidence-detail empty-state">正在验证证据成员关系…</div>}
          {!evidenceBusy && evidenceDetail && <EvidenceDetailCard detail={evidenceDetail} />}
          {!evidenceBusy && !evidenceDetail && <div className="evidence-detail empty-state">选择一条证据查看 normalized fact；原始对象字节不会加载到浏览器。</div>}
        </section>
      )}

      {activeSection === "claims" && (
        <section className="investigation-section claim-grid">
          {detail.claims.map((claim) => (
            <article className="claim-card" key={claim.claim_id}>
              <div><span className="eyebrow">{claim.category}</span><StatusPill value={claim.verification_status} /></div>
              <p>{claim.statement}</p>
              <div className="claim-scores">
                <span>support {(claim.support_score * 100).toFixed(0)}%</span>
                <span>contradiction {(claim.contradiction_score * 100).toFixed(0)}%</span>
                <span>{claim.epistemic_status}</span>
              </div>
              <code>{claim.evidence_event_ids.map(compactHash).join(", ")}</code>
            </article>
          ))}
          {!detail.claims.length && <EmptyState text="当前 revision 没有 Claim。" />}
        </section>
      )}

      {activeSection === "graph" && (
        <section className="investigation-section graph-grid">
          <div>
            <h4>实体 · {detail.entities.length}/{detail.counts.entities}</h4>
            <div className="entity-list">
              {detail.entities.map((entity) => (
                <div className="entity-row" key={entity.entity_id}>
                  <span className="pill">{entity.entity_type}</span>
                  <div><strong>{entity.canonical_key}</strong><span>{entity.entity_id}</span></div>
                </div>
              ))}
              {!detail.entities.length && <EmptyState text="没有可见实体。" />}
            </div>
          </div>
          <div>
            <h4>关系 · {detail.edges.length}/{detail.counts.edges}</h4>
            <div className="entity-list">
              {detail.edges.map((edge) => (
                <div className="edge-row" key={edge.edge_id}>
                  <code>{compactHash(edge.source_entity_id)}</code>
                  <span>{edge.relationship.replaceAll("_", " ")}</span>
                  <code>{compactHash(edge.target_entity_id)}</code>
                  <small>{edge.evidence_count} evidence</small>
                </div>
              ))}
              {!detail.edges.length && <EmptyState text="可见实体之间没有关系边。" />}
            </div>
          </div>
        </section>
      )}

      {detail.data_reductions.length > 0 && (
        <section className="reduction-strip" aria-label="数据缩减审计">
          {detail.data_reductions.map((item) => (
            <span key={item.reduction_id}>{item.input_count} input → {item.retained_count} retained · {item.dropped_count} reduced</span>
          ))}
        </section>
      )}
    </div>
  );
}

function EvidenceDetailCard({ detail }: { detail: IncidentEvidenceDetail }) {
  const event = detail.normalized_event;
  return (
    <aside className="evidence-detail">
      <div className="evidence-detail-header">
        <div><span className="eyebrow">Membership verified</span><strong>{event.event_type}</strong></div>
        <StatusPill value={event.status} />
      </div>
      <DetailRow label="Event ID" value={event.event_id} mono />
      <DetailRow label="Normalized ID" value={event.id} mono />
      <DetailRow label="Event time" value={formatTime(event.event_time)} />
      <DetailRow label="Ingest time" value={formatTime(event.ingest_time)} />
      <DetailRow label="Revision" value={String(event.revision)} />
      <DetailRow label="Integrity" value={detail.evidence.integrity_sha256 ? compactHash(detail.evidence.integrity_sha256) : "not recorded"} mono />
      <div className="json-block"><span>payload</span><pre>{JSON.stringify(event.payload, null, 2)}</pre></div>
      {Object.keys(event.labels).length > 0 && <div className="json-block"><span>labels</span><pre>{JSON.stringify(event.labels, null, 2)}</pre></div>}
      {Object.keys(event.extensions).length > 0 && <div className="json-block"><span>extensions</span><pre>{JSON.stringify(event.extensions, null, 2)}</pre></div>}
      <div className="raw-ref"><span>raw_ref</span><code>{event.raw_ref}</code></div>
    </aside>
  );
}

function IncidentTable({
  incidents,
  embedded = false,
  onSelect,
  selectedIncidentId,
}: {
  incidents: IncidentSummary[];
  embedded?: boolean;
  onSelect?: (incidentId: string) => void;
  selectedIncidentId?: string | null;
}) {
  const table = (
    <div className="table-scroll">
      <table className="data-table">
        <thead><tr><th>事件</th><th>风险</th><th>攻击状态</th><th>保证等级</th><th>最近活动</th>{onSelect && <th>调查</th>}</tr></thead>
        <tbody>
          {incidents.map((incident) => (
            <tr key={incident.incident_id}>
              <td><span className="strong mono">{incident.incident_id}</span><span className="subline">{incident.summary || incident.host_id || "无摘要"}</span></td>
              <td><span className="pill" data-tone={toneForSeverity(incident.severity)}>{severityLabel(incident.severity)} · {incident.risk_score}</span></td>
              <td>{attackStateLabel(incident.attack_state)}</td>
              <td>{incident.assurance}</td>
              <td>{formatTime(incident.last_seen)}</td>
              {onSelect && <td><button className="row-action" data-selected={selectedIncidentId === incident.incident_id} onClick={() => onSelect(incident.incident_id)} type="button">{selectedIncidentId === incident.incident_id ? "已选择" : "调查"}</button></td>}
            </tr>
          ))}
        </tbody>
      </table>
      {!incidents.length && <EmptyState text="当前没有可显示的 Incident。" />}
    </div>
  );
  return embedded ? table : <section className="panel"><PanelHeader title="Incident 队列" note={`${incidents.length} records`} />{table}</section>;
}

function AssetTable({ hosts }: { hosts: HostSummary[] }) {
  return (
    <section className="panel">
      <PanelHeader title="受管资产" note={`${hosts.length} records`} />
      <div className="table-scroll"><table className="data-table">
        <thead><tr><th>主机</th><th>发行版 / 内核</th><th>关键度</th><th>Agent / 版本</th><th>新鲜度</th></tr></thead>
        <tbody>{hosts.map((host) => <tr key={host.host_id}>
          <td><span className="strong">{host.hostname}</span><span className="subline mono">{host.host_id}</span></td>
          <td>{host.distro ?? "unknown"}<span className="subline">{host.kernel ?? "kernel unknown"}</span></td>
          <td><StatusPill value={host.criticality} /></td>
          <td><span className="mono">{host.agent_id ?? "not bound"}</span><span className="subline mono">{host.agent_version && host.agent_version_reported_at ? `v${host.agent_version} · ${formatTime(host.agent_version_reported_at)}` : "version unreported"}</span></td>
          <td><StatusPill value={host.freshness_status} /></td>
        </tr>)}</tbody>
      </table>{!hosts.length && <EmptyState text="当前没有可显示的资产。" />}</div>
    </section>
  );
}

function MalwareWorkspace({ samples, token }: { samples: MalwareSummary[]; token: string }) {
  const [selectedSampleId, setSelectedSampleId] = useState<string | null>(null);
  const [detail, setDetail] = useState<MalwareInvestigation | null>(null);
  const [activeSection, setActiveSection] = useState<"analysis" | "contexts" | "tasks">("analysis");
  const [detailBusy, setDetailBusy] = useState(false);
  const [workspaceError, setWorkspaceError] = useState<string | null>(null);

  const loadInvestigation = async (sampleId: string) => {
    setSelectedSampleId(sampleId);
    setDetailBusy(true);
    setWorkspaceError(null);
    setDetail(null);
    try {
      const response = await fetch(
        `/api/platform/malware-detail?sample_id=${encodeURIComponent(sampleId)}`,
        {
          headers: { authorization: `Bearer ${token.trim()}` },
          cache: "no-store",
        },
      );
      const payload: unknown = await response.json();
      if (!response.ok || !isMalwareInvestigation(payload)) {
        throw new Error(
          response.ok
            ? "控制面返回的恶意文件上下文格式无效。"
            : apiErrorMessage(payload, response.status),
        );
      }
      setDetail(payload);
      setActiveSection("analysis");
    } catch (caught) {
      setWorkspaceError(caught instanceof Error ? caught.message : "无法读取恶意文件上下文。");
    } finally {
      setDetailBusy(false);
    }
  };

  return (
    <div className="malware-workspace">
      <section className="panel">
        <PanelHeader title="隔离与分析队列" note={`${samples.length} records · metadata only`} />
        <MalwareTable
          embedded
          onSelect={(sampleId) => void loadInvestigation(sampleId)}
          samples={samples}
          selectedSampleId={selectedSampleId}
        />
      </section>
      <section className="panel malware-detail-panel" aria-live="polite">
        <PanelHeader
          title="恶意文件上下文"
          note={detail ? detail.sample.sample_id : "tenant + hash scoped"}
        />
        {workspaceError && <div className="inline-message" data-tone="critical" role="alert">{workspaceError}</div>}
        {detailBusy && <div className="empty-state">正在锁定样本元数据并加载有界分析上下文…</div>}
        {!detailBusy && !detail && <EmptyState text="选择一个样本，查看分析结论、引擎证据、同哈希上下文与任务历史。" />}
        {!detailBusy && detail && (
          <MalwareInvestigationDetail
            activeSection={activeSection}
            detail={detail}
            onSection={setActiveSection}
          />
        )}
      </section>
    </div>
  );
}

function MalwareTable({
  embedded = false,
  onSelect,
  samples,
  selectedSampleId,
}: {
  embedded?: boolean;
  onSelect?: (sampleId: string) => void;
  samples: MalwareSummary[];
  selectedSampleId?: string | null;
}) {
  const table = (
    <div className="table-scroll"><table className="data-table">
      <thead><tr><th>样本</th><th>SHA-256</th><th>类型</th><th>大小</th><th>状态</th><th>接收时间</th>{onSelect && <th>分析</th>}</tr></thead>
      <tbody>{samples.map((sample) => <tr key={sample.sample_id}>
        <td><span className="strong">{sample.filename ?? "unnamed sample"}</span><span className="subline mono">{sample.sample_id}</span></td>
        <td className="mono">{compactHash(sample.sha256)}</td>
        <td>{sample.media_type}</td><td>{formatBytes(sample.size)}</td>
        <td><StatusPill value={sample.status} /></td><td>{formatTime(sample.created_at)}</td>
        {onSelect && <td><button className="row-action" data-selected={selectedSampleId === sample.sample_id} onClick={() => onSelect(sample.sample_id)} type="button">{selectedSampleId === sample.sample_id ? "已选择" : "上下文"}</button></td>}
      </tr>)}</tbody>
    </table>{!samples.length && <EmptyState text="当前没有可显示的隔离样本。" />}</div>
  );
  return embedded ? table : <section className="panel"><PanelHeader title="隔离与分析队列" note={`${samples.length} records`} />{table}</section>;
}

function MalwareInvestigationDetail({
  activeSection,
  detail,
  onSection,
}: {
  activeSection: "analysis" | "contexts" | "tasks";
  detail: MalwareInvestigation;
  onSection: (section: "analysis" | "contexts" | "tasks") => void;
}) {
  const analysis = detail.analysis;
  const sections = [
    ["analysis", "分析证据", detail.counts.engine_results],
    ["contexts", "同哈希上下文", detail.counts.same_hash_contexts],
    ["tasks", "任务历史", detail.counts.tasks],
  ] as const;
  return (
    <div className="investigation-body">
      <div className="investigation-hero malware-hero">
        <div>
          <div className="eyebrow">SHA-256 · {compactHash(detail.sample.sha256)}</div>
          <h3>{detail.sample.filename ?? "unnamed sample"}</h3>
          <p>{detail.sample.media_type} · {formatBytes(detail.sample.size)} · updated {formatTime(detail.updated_at)}</p>
        </div>
        <div className="malware-verdict">
          <span>Disposition</span>
          <StatusPill value={analysis?.disposition ?? detail.sample.status} />
          <strong>{analysis ? `${Math.round(analysis.confidence * 100)}%` : "pending"}</strong>
        </div>
      </div>

      <div className="investigation-facts">
        <DetailRow label="样本状态" value={statusLabel(detail.sample.status)} />
        <DetailRow label="恶意类型" value={analysis?.malware_type ?? "尚无结论"} />
        <DetailRow label="引擎结果" value={String(detail.counts.engine_results)} />
        <DetailRow label="同哈希上下文" value={String(detail.counts.same_hash_contexts)} />
        <DetailRow label="扫描任务" value={String(detail.counts.tasks)} />
        <DetailRow label="样本 ID" value={detail.sample.sample_id} mono />
      </div>

      <div className="bounded-notice">
        控制台仅展示租户内元数据与有界分析投影；不会返回 quarantine_ref、样本字节、静态字符串或归档条目。
        {detail.truncated_sections.length > 0 && ` 已缩减：${detail.truncated_sections.join("、")}。`}
      </div>

      <nav className="investigation-tabs" aria-label="恶意文件调查分区">
        {sections.map(([key, label, count]) => (
          <button data-active={activeSection === key} key={key} onClick={() => onSection(key)} type="button">
            {label}<span>{count}</span>
          </button>
        ))}
      </nav>

      {activeSection === "analysis" && (
        <section className="investigation-section malware-analysis-section">
          {!analysis && <EmptyState text="当前样本还没有完成且可验证的分析报告。" />}
          {analysis && (
            <>
              <div className="malware-analysis-grid">
                <DetailCard title="静态文件画像">
                  <DetailRow label="检测类型" value={analysis.profile.detected_media_type} />
                  <DetailRow label="文件种类" value={analysis.profile.kind} />
                  <DetailRow label="熵" value={analysis.profile.entropy.toFixed(3)} />
                  <DetailRow label="架构" value={analysis.profile.architecture ?? "unknown"} />
                  <DetailRow label="可执行格式" value={analysis.profile.executable_format ?? "not detected"} />
                  <DetailRow label="解释器" value={analysis.profile.interpreter ?? "not detected"} mono />
                  {analysis.profile.archive && (
                    <>
                      <DetailRow label="归档格式" value={analysis.profile.archive.format} />
                      <DetailRow label="归档检查" value={`${analysis.profile.archive.inspected_entry_count}/${analysis.profile.archive.declared_entry_count} entries`} />
                      <DetailRow label="展开大小" value={formatBytes(analysis.profile.archive.total_uncompressed_size)} />
                    </>
                  )}
                </DetailCard>
                <DetailCard title="结论与动态分析">
                  <DetailRow label="完成时间" value={formatTime(analysis.completed_at)} />
                  <DetailRow label="动态状态" value={statusLabel(analysis.dynamic_analysis_status)} />
                  <DetailRow label="沙箱报告" value={analysis.sandbox_report_id ?? "not imported"} mono />
                  <p className="detail-copy">{analysis.dynamic_analysis_reason}</p>
                </DetailCard>
              </div>
              {(analysis.families.length > 0 || analysis.profile.signatures.length > 0) && (
                <div className="malware-tag-strip">
                  {analysis.families.map((family) => <span key={family.family}>{family.family} · {family.status} · {family.supporting_sources.join("+")}</span>)}
                  {analysis.profile.signatures.map((signature) => <span key={signature}>{signature}</span>)}
                </div>
              )}
              {(analysis.truncated_fields.length > 0
                || analysis.profile.truncated_fields.length > 0
                || (analysis.profile.archive?.violations_truncated ?? false)) && (
                <div className="bounded-notice">
                  报告子字段已按固定上限缩减：{[
                    ...analysis.truncated_fields,
                    ...analysis.profile.truncated_fields.map((item) => `profile.${item}`),
                    ...(analysis.profile.archive?.violations_truncated ? ["archive.violations"] : []),
                  ].join("、")}。
                </div>
              )}
              <div className="engine-grid">
                {analysis.engine_results.map((engine) => (
                  <article className="engine-card" key={engine.source_id}>
                    <div><div><span className="eyebrow">{engine.kind}</span><strong>{engine.source_id}</strong></div><StatusPill value={engine.status === "completed" ? engine.signal : engine.status} /></div>
                    <p>confidence {Math.round(engine.confidence * 100)}%{engine.error_code ? ` · ${engine.error_code}` : ""}</p>
                    {engine.matched_rules.length > 0 && <code>rules: {engine.matched_rules.join(", ")}</code>}
                    {engine.family_candidates.length > 0 && <code>family: {engine.family_candidates.join(", ")}</code>}
                    {engine.malware_type_candidates.length > 0 && <code>type: {engine.malware_type_candidates.join(", ")}</code>}
                    {engine.observations.length > 0 && <ul>{engine.observations.map((item) => <li key={item}>{item}</li>)}</ul>}
                    {engine.truncated_fields.length > 0 && <small>字段已缩减：{engine.truncated_fields.join("、")}</small>}
                  </article>
                ))}
              </div>
              {!analysis.engine_results.length && <EmptyState text="报告没有可见的引擎索引。" />}
              {(analysis.cleanup_advice.length > 0 || analysis.warnings.length > 0 || analysis.profile.warnings.length > 0) && (
                <div className="malware-notes">
                  {[...analysis.warnings, ...analysis.profile.warnings, ...analysis.cleanup_advice].map((item) => <span key={item}>{item}</span>)}
                </div>
              )}
            </>
          )}
        </section>
      )}

      {activeSection === "contexts" && (
        <section className="investigation-section context-grid">
          {detail.same_hash_contexts.map((context) => (
            <article className="context-card" key={context.context_id}>
              <div><div><span className="eyebrow">{context.host_id ?? "host unknown"}</span><strong>{context.destination_path ?? "path not recorded"}</strong></div><span>{formatTime(context.observed_at)}</span></div>
              <DetailRow label="执行进程" value={context.executor_process ?? "not recorded"} mono />
              <DetailRow label="创建进程" value={context.creator_process ?? "not recorded"} mono />
              <DetailRow label="父进程" value={context.parent_process ?? "not recorded"} mono />
              <DetailRow label="持久化" value={context.persistence_mechanism ?? "not observed"} />
              <div className="context-source"><span>source_url</span><code>{context.source_url ?? "not recorded"}</code></div>
              <div className="context-evidence"><span>{context.evidence_event_count} evidence</span><code>{context.evidence_event_ids.map(compactHash).join(", ") || "none"}</code></div>
              {context.evidence_truncated && <small>证据 ID 已按固定上限缩减。</small>}
              <small>source sample {context.source_sample_id}</small>
            </article>
          ))}
          {!detail.same_hash_contexts.length && <EmptyState text="租户内没有同哈希文件上下文。" />}
        </section>
      )}

      {activeSection === "tasks" && (
        <section className="investigation-section table-scroll">
          <table className="data-table">
            <thead><tr><th>任务</th><th>状态</th><th>尝试</th><th>报告</th><th>错误</th><th>完成时间</th></tr></thead>
            <tbody>{detail.tasks.map((task) => (
              <tr key={task.task_id}>
                <td className="mono">{task.task_id}</td><td><StatusPill value={task.status} /></td>
                <td>{task.attempt_count}/{task.max_attempts}</td><td>{task.has_report ? "validated" : "none"}</td>
                <td>{task.last_error_code ?? "—"}</td><td>{task.completed_at ? formatTime(task.completed_at) : "—"}</td>
              </tr>
            ))}</tbody>
          </table>
          {!detail.tasks.length && <EmptyState text="当前样本没有扫描任务。" />}
        </section>
      )}
    </div>
  );
}

function TraceWorkspace({ incidents, token }: { incidents: IncidentSummary[]; token: string }) {
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [detail, setDetail] = useState<TraceInvestigation | null>(null);
  const [detailBusy, setDetailBusy] = useState(false);
  const [workspaceError, setWorkspaceError] = useState<string | null>(null);

  const loadTrace = async (incidentId: string) => {
    setSelectedIncidentId(incidentId);
    setDetailBusy(true);
    setWorkspaceError(null);
    setDetail(null);
    try {
      const response = await fetch(
        `/api/platform/trace-detail?incident_id=${encodeURIComponent(incidentId)}`,
        {
          headers: { authorization: `Bearer ${token.trim()}` },
          cache: "no-store",
        },
      );
      const payload: unknown = await response.json();
      if (!response.ok || !isTraceInvestigation(payload)) {
        throw new Error(
          response.status === 404
            ? "所选 Incident 尚未生成当前攻击溯源快照。"
            : response.ok
              ? "控制面返回的攻击溯源投影格式无效。"
              : apiErrorMessage(payload, response.status),
        );
      }
      setDetail(payload);
    } catch (caught) {
      setWorkspaceError(caught instanceof Error ? caught.message : "无法读取攻击溯源投影。");
    } finally {
      setDetailBusy(false);
    }
  };

  if (!token.trim()) {
    return <section className="panel"><EmptyState text="连接控制面后按 Incident 读取租户内攻击溯源。" /></section>;
  }

  return (
    <div className="trace-workspace">
      <section className="panel">
        <PanelHeader title="溯源种子 Incident" note={`${incidents.length} records · current seed trace`} />
        <IncidentTable
          embedded
          incidents={incidents}
          onSelect={(incidentId) => void loadTrace(incidentId)}
          selectedIncidentId={selectedIncidentId}
        />
      </section>
      <section className="panel trace-detail-panel" aria-live="polite">
        <PanelHeader
          title="跨主机技术溯源"
          note={detail ? `${detail.trace_id} · rev ${detail.revision}` : "evidence-closed bounded projection"}
        />
        {workspaceError && <div className="inline-message" data-tone="critical" role="alert">{workspaceError}</div>}
        {detailBusy && <div className="empty-state">正在锁定当前 trace revision 并验证快照完整性…</div>}
        {!detailBusy && !detail && <EmptyState text="选择一个 Incident，查看初始入口、关键路径、影响范围、技术映射与归因限制。" />}
        {!detailBusy && detail && <TraceInvestigationDetail detail={detail} />}
      </section>
    </div>
  );
}

function TraceInvestigationDetail({ detail }: { detail: TraceInvestigation }) {
  const path = detail.initial_access
    ? [detail.initial_access, ...detail.key_path.filter((item) => item.step_id !== detail.initial_access?.step_id)]
    : detail.key_path;
  return (
    <div className="investigation-body trace-investigation-body">
      <div className="investigation-hero">
        <div>
          <div className="eyebrow">Seed {detail.seed_incident_id} · {detail.revision_reason}</div>
          <h3>{attackStateLabel(detail.attack_state)}</h3>
          <p>{formatTime(detail.first_seen)} → {formatTime(detail.last_seen)} · {detail.counts.source_incidents} source Incidents</p>
        </div>
        <div className="investigation-risk">
          <span>Impacted</span>
          <strong>{detail.counts.impacted_hosts}</strong>
          <span>Hosts</span>
        </div>
      </div>

      <section className="rule-operations-summary" aria-label="攻击溯源摘要">
        <article><span>关键路径</span><strong>{detail.counts.key_path}</strong><small>{detail.key_path.length} visible</small></article>
        <article><span>图实体</span><strong>{detail.counts.entities}</strong><small>{detail.counts.edges} edges</small></article>
        <article><span>ATT&amp;CK 技术</span><strong>{detail.counts.techniques}</strong><small>evidence mapped</small></article>
        <article data-tone="warning"><span>身份归因</span><strong>0</strong><small>{detail.identity_attribution_status}</small></article>
      </section>

      <div className="bounded-notice trace-boundary-notice">
        本页只显示当前租户、当前 trace revision 的技术关联与有界 evidence pointer；不包含 raw_ref、原始证据字节或实体 attributes。
        身份断言固定为 0。交互式任意图查询和调查导出尚未接入控制台。
        {detail.truncated_sections.length > 0 && ` 已缩减：${detail.truncated_sections.join("、")}。`}
      </div>

      <section className="panel trace-inner-panel">
        <PanelHeader title="初始入口与关键路径" note={`${path.length}/${detail.counts.key_path + (detail.initial_access ? 1 : 0)} visible steps`} />
        <div className="investigation-section">
          {path.map((item) => (
            <div className="investigation-timeline-row" key={item.step_id}>
              <span className="timeline-marker" data-tone={toneForStatus(item.attack_state)} />
              <div>
                <div className="timeline-heading"><strong>{item.summary}</strong><span>{formatTime(item.event_time)}</span></div>
                <p>{item.kind.replaceAll("_", " ")} · {item.source_host_id}{item.target_host_id ? ` → ${item.target_host_id}` : ""}</p>
                <code>{item.evidence_ids.map(compactHash).join(", ") || `${item.evidence_count} evidence · sample omitted`}</code>
              </div>
            </div>
          ))}
          {!path.length && <EmptyState text="当前 trace 没有关键路径步骤。" />}
        </div>
      </section>

      <section className="panel trace-inner-panel">
        <PanelHeader title="证据闭合关系图" note={`${detail.entities.length}/${detail.counts.entities} entities · ${detail.edges.length}/${detail.counts.edges} edges`} />
        <div className="investigation-section graph-grid">
          <div>
            <h4>实体</h4>
            <div className="entity-list">
              {detail.entities.map((entity) => (
                <div className="entity-row" key={entity.entity_id}>
                  <span className="pill">{entity.entity_type}</span>
                  <div><strong>{entity.canonical_key}</strong><span>{entity.entity_id}</span></div>
                </div>
              ))}
            </div>
          </div>
          <div>
            <h4>关系</h4>
            <div className="entity-list">
              {detail.edges.map((edge) => (
                <div className="edge-row" key={edge.edge_id}>
                  <code>{compactHash(edge.source_entity_id)}</code>
                  <span>{edge.relationship.replaceAll("_", " ")}</span>
                  <code>{compactHash(edge.target_entity_id)}</code>
                  <small>{edge.evidence_count} evidence · {(edge.confidence * 100).toFixed(0)}%</small>
                </div>
              ))}
              {!detail.edges.length && <EmptyState text="当前可见实体之间没有关系边。" />}
            </div>
          </div>
        </div>
      </section>

      <section className="model-operations-grid trace-analysis-grid">
        <DetailCard title="影响范围与源 Incident">
          <DetailRow label="Impacted Hosts" value={detail.impacted_host_ids.join(", ")} mono />
          {detail.source_incidents.map((item) => (
            <DetailRow
              key={`${item.incident_id}:${item.revision}`}
              label={`${severityLabel(item.severity)} · rev ${item.revision}`}
              value={`${item.incident_id} · ${item.primary_host_id}`}
              mono
            />
          ))}
        </DetailCard>
        <DetailCard title="ATT&CK 技术映射">
          {detail.techniques.map((item) => (
            <DetailRow
              key={item.technique_id}
              label={`${item.technique_id} · ${item.tactic}`}
              value={`${item.name} · ${item.epistemic_status} · ${item.evidence_count} evidence`}
            />
          ))}
          {!detail.techniques.length && <DetailRow label="Mappings" value="none" />}
        </DetailCard>
        <DetailCard title="基础设施精确聚类">
          {detail.infrastructure_clusters.map((item) => (
            <DetailRow
              key={item.cluster_id}
              label={item.observable_type}
              value={`${item.canonical_value} · ${item.host_count} hosts / ${item.incident_count} Incidents`}
              mono
            />
          ))}
          {!detail.infrastructure_clusters.length && <DetailRow label="Clusters" value="none" />}
        </DetailCard>
      </section>

      <section className="panel trace-inner-panel">
        <PanelHeader title="Trace evidence pointer" note={`${detail.evidence.length}/${detail.counts.evidence} visible · no raw_ref`} />
        <div className="table-scroll"><table className="data-table">
          <thead><tr><th>Trace evidence</th><th>Incident evidence</th><th>类型 / 主机</th><th>时间质量</th><th>事件时间</th></tr></thead>
          <tbody>{detail.evidence.map((item) => (
            <tr key={item.trace_evidence_id}>
              <td><span className="strong mono">{item.trace_evidence_id}</span><span className="subline mono">{compactHash(item.event_id)}</span></td>
              <td><span className="strong mono">{item.incident_evidence_id}</span><span className="subline mono">{item.incident_id} · rev {item.incident_revision}</span></td>
              <td>{item.event_type}<span className="subline mono">{item.host_id}</span></td>
              <td><StatusPill value={item.is_late ? "late" : item.source_time_quality} /></td>
              <td>{formatTime(item.event_time)}</td>
            </tr>
          ))}</tbody>
        </table></div>
      </section>

      <section className="bounded-notice">
        <strong>归因限制：</strong> {detail.attribution_limitations.join("；")}。当前结论只允许技术路径、TTP 与精确 observable 关联；不得据此输出真实组织或个人身份。
      </section>
    </div>
  );
}

async function fetchModelOperations(credential: string): Promise<ModelOperations> {
  const response = await fetch("/api/platform/model-operations", {
    headers: { authorization: `Bearer ${credential}` },
    cache: "no-store",
  });
  const payload: unknown = await response.json();
  if (!response.ok || !isModelOperations(payload)) {
    throw new Error(
      response.ok
        ? "控制面返回的模型运营投影格式无效。"
        : apiErrorMessage(payload, response.status),
    );
  }
  return payload;
}

function ModelOperationsWorkspace({ token }: { token: string }) {
  const [operations, setOperations] = useState<ModelOperations | null>(null);
  const [workspaceBusy, setWorkspaceBusy] = useState(true);
  const [workspaceError, setWorkspaceError] = useState<string | null>(null);

  const loadOperations = useCallback(async () => {
    const credential = token.trim();
    if (!credential) {
      setOperations(null);
      return;
    }
    setWorkspaceBusy(true);
    setWorkspaceError(null);
    try {
      setOperations(await fetchModelOperations(credential));
    } catch (caught) {
      setOperations(null);
      setWorkspaceError(caught instanceof Error ? caught.message : "无法读取模型运营投影。");
    } finally {
      setWorkspaceBusy(false);
    }
  }, [token]);

  useEffect(() => {
    const credential = token.trim();
    let active = true;
    if (!credential) return undefined;
    void fetchModelOperations(credential)
      .then((payload) => {
        if (active) setOperations(payload);
      })
      .catch((caught: unknown) => {
        if (active) {
          setOperations(null);
          setWorkspaceError(caught instanceof Error ? caught.message : "无法读取模型运营投影。");
        }
      })
      .finally(() => {
        if (active) setWorkspaceBusy(false);
      });
    return () => {
      active = false;
    };
  }, [token]);

  if (!token.trim()) {
    return <section className="panel"><EmptyState text="连接控制面后读取模型配置状态与租户运行指标。" /></section>;
  }
  if (workspaceBusy && !operations) {
    return <section className="panel"><EmptyState text="正在聚合模型角色、成本、延迟、失败与审核状态…" /></section>;
  }
  if (workspaceError) {
    return (
      <section className="panel">
        <div className="inline-message" data-tone="critical" role="alert">{workspaceError}</div>
        <div className="panel-body"><button className="quiet-button" onClick={() => void loadOperations()} type="button">重新读取</button></div>
      </section>
    );
  }
  if (!operations) {
    return <section className="panel"><EmptyState text="当前没有模型运营数据。" /></section>;
  }

  const configuration = operations.provider_configuration;
  const review = operations.review_metrics;
  const failedRuns = operations.run_aggregates.reduce(
    (total, item) => total + item.failed_count + item.circuit_open_count,
    0,
  );
  const totalCost = operations.run_aggregates.reduce(
    (total, item) => total + item.total_cost_usd,
    0,
  );
  return (
    <div className="model-operations-workspace">
      <section className="rule-operations-summary" aria-label="模型运营状态">
        <article data-tone={configuration.enabled ? undefined : "warning"}><span>Review Gate</span><strong>{configuration.enabled ? "已启用" : "已关闭"}</strong><small>{configuration.provider}</small></article>
        <article><span>模型调用</span><strong>{operations.counts.model_runs}</strong><small>{operations.counts.aggregate_groups} provider/model/role groups</small></article>
        <article data-tone={failedRuns > 0 ? "warning" : undefined}><span>失败 / Circuit</span><strong>{failedRuns}</strong><small>tenant persisted runs</small></article>
        <article><span>累计成本</span><strong>${totalCost.toFixed(4)}</strong><small>{operations.counts.review_tasks} review tasks</small></article>
      </section>

      <div className="bounded-notice model-truth-notice">
        本页不返回 API key、base URL 或模型请求/响应内容。Key 仅显示是否配置；credential validity 与
        Provider health 尚未执行主动探测。平台也没有 ground-truth label/feedback linkage，Precision、
        Recall、agreement 与 false-positive rate 保持未测量，不能从成功率或人工复核数推断。
      </div>

      <section className="panel">
        <PanelHeader title="Provider 与策略配置" note={`generated ${formatTime(operations.generated_at)}`} />
        <div className="model-operations-grid">
          <DetailCard title="Provider state">
            <DetailRow label="Review Gate" value={configuration.enabled ? "enabled" : "disabled"} />
            <DetailRow label="Provider" value={configuration.provider} />
            <DetailRow label="Model" value={configuration.model_name ?? "not configured"} mono />
            <DetailRow label="API key" value={configuration.api_key_state} />
            <DetailRow label="Base URL" value={configuration.base_url_state} />
            <DetailRow label="Config complete" value={yesNo(configuration.configuration_complete)} />
            <DetailRow label="Credential validity" value={configuration.credential_validity} />
            <DetailRow label="Provider health" value={configuration.health_status} />
          </DetailCard>
          <DetailCard title="Roles & capabilities">
            <DetailRow label="Enabled roles" value={configuration.enabled_roles.join(", ") || "none"} />
            <DetailRow label="Tool calls" value={yesNo(configuration.supports_tools)} />
            <DetailRow label="JSON Schema" value={yesNo(configuration.supports_json_schema)} />
            <DetailRow label="Verifier slots" value={String(configuration.max_verifier_slots)} />
            <DetailRow label="Adjudicator" value={configuration.adjudicator_enabled ? "policy enabled" : "disabled"} />
            <DetailRow label="Model context" value={`${configuration.model_context_tokens} tokens`} />
            <DetailRow label="Response bound" value={formatBytes(configuration.max_response_bytes)} />
          </DetailCard>
          <DetailCard title="Budgets & resilience">
            <DetailRow label="Incident context" value={`${configuration.max_context_tokens} tokens`} />
            <DetailRow label="Output" value={`${configuration.max_output_tokens} tokens`} />
            <DetailRow label="Runs / Incident" value={String(configuration.max_model_runs_per_incident)} />
            <DetailRow label="Tools / Incident" value={String(configuration.max_tool_calls)} />
            <DetailRow label="Cost / Incident" value={`$${configuration.max_cost_usd_per_incident.toFixed(4)}`} />
            <DetailRow label="Reviews / minute" value={String(configuration.max_reviews_per_minute)} />
            <DetailRow label="Timeout" value={`${configuration.provider_timeout_seconds}s`} />
            <DetailRow label="Retries" value={String(configuration.provider_max_retries)} />
            <DetailRow label="Circuit" value={`${configuration.circuit_failure_threshold} failures / ${configuration.circuit_recovery_seconds}s`} />
          </DetailCard>
        </div>
      </section>

      <section className="panel">
        <PanelHeader title="审核运行结果" note={`${review.task_count} tenant tasks`} />
        <div className="model-review-grid">
          <DetailCard title="Execution status">
            <DetailRow label="Completed" value={String(review.completed_count)} />
            <DetailRow label="Skipped" value={String(review.skipped_count)} />
            <DetailRow label="Unavailable" value={String(review.model_unavailable_count)} />
            <DetailRow label="Invalid output" value={String(review.invalid_output_count)} />
            <DetailRow label="Budget exceeded" value={String(review.budget_exceeded_count)} />
            <DetailRow label="Require human" value={String(review.require_human_status_count)} />
          </DetailCard>
          <DetailCard title="Assurance & review">
            <DetailRow label="Deterministic only" value={String(review.deterministic_only_count)} />
            <DetailRow label="Unreviewed" value={String(review.unreviewed_count)} />
            <DetailRow label="Basic" value={String(review.basic_count)} />
            <DetailRow label="Enhanced" value={String(review.enhanced_count)} />
            <DetailRow label="High" value={String(review.high_count)} />
            <DetailRow label="Verification required" value={String(review.verification_required_count)} />
            <DetailRow label="Human review required" value={String(review.human_review_required_count)} />
          </DetailCard>
          <DetailCard title="Labeled performance">
            <DetailRow label="Feedback linkage" value="unavailable" />
            <DetailRow label="Labeled outcomes" value="0" />
            <DetailRow label="Precision" value="未测量" />
            <DetailRow label="Recall" value="未测量" />
            <DetailRow label="Agreement" value="未测量" />
            <DetailRow label="False-positive rate" value="未测量" />
            <DetailRow label="Last review" value={review.last_review_at ? formatTime(review.last_review_at) : "none"} />
          </DetailCard>
        </div>
      </section>

      <section className="panel">
        <PanelHeader title="Provider / Model / Role 聚合" note={`${operations.counts.aggregate_groups} groups · tenant only`} />
        <div className="table-scroll"><table className="data-table">
          <thead><tr><th>Provider / Model / Role</th><th>Runs</th><th>Failure rate</th><th>Average latency</th><th>Tokens</th><th>Cost</th><th>Retry / Tools</th><th>Last run</th></tr></thead>
          <tbody>{operations.run_aggregates.map((item) => (
            <tr key={`${item.provider}/${item.model}/${item.role}`}>
              <td><span className="strong">{item.role} · {item.provider}</span><span className="subline mono">{item.model}</span></td>
              <td>{item.run_count}<span className="subline">{item.completed_count} completed · {item.failed_count} failed · {item.circuit_open_count} circuit</span></td>
              <td><StatusPill value={item.failure_rate === 0 ? "success" : item.failure_rate >= 0.5 ? "failed" : "review"} /> <span className="mono">{(item.failure_rate * 100).toFixed(1)}%</span></td>
              <td>{item.average_latency_ms.toFixed(1)} ms</td>
              <td>{item.total_input_tokens + item.total_output_tokens}<span className="subline">in {item.total_input_tokens} / out {item.total_output_tokens}</span></td>
              <td>${item.total_cost_usd.toFixed(4)}</td>
              <td>{item.total_retries} / {item.total_tool_calls}</td>
              <td>{formatTime(item.last_run_at)}</td>
            </tr>
          ))}</tbody>
        </table>{!operations.run_aggregates.length && <EmptyState text="当前租户没有持久化模型调用。" />}</div>
      </section>

      <ModelTable runs={operations.recent_runs} />
      {operations.truncated_sections.length > 0 && (
        <div className="bounded-notice">投影已按固定上限缩减：{operations.truncated_sections.join("、")}。</div>
      )}
    </div>
  );
}

async function fetchSystemOperations(credential: string): Promise<SystemOperations> {
  const response = await fetch("/api/platform/system-operations", {
    headers: { authorization: `Bearer ${credential}` },
    cache: "no-store",
  });
  const payload: unknown = await response.json();
  if (!response.ok || !isSystemOperations(payload)) {
    throw new Error(
      response.ok
        ? "控制面返回的系统运营投影格式无效。"
        : apiErrorMessage(payload, response.status),
    );
  }
  return payload;
}

function SystemOperationsWorkspace({ token }: { token: string }) {
  const [operations, setOperations] = useState<SystemOperations | null>(null);
  const [workspaceBusy, setWorkspaceBusy] = useState(true);
  const [workspaceError, setWorkspaceError] = useState<string | null>(null);

  const loadOperations = useCallback(async () => {
    const credential = token.trim();
    if (!credential) {
      setOperations(null);
      return;
    }
    setWorkspaceBusy(true);
    setWorkspaceError(null);
    try {
      setOperations(await fetchSystemOperations(credential));
    } catch (caught) {
      setOperations(null);
      setWorkspaceError(caught instanceof Error ? caught.message : "无法读取系统运营投影。");
    } finally {
      setWorkspaceBusy(false);
    }
  }, [token]);

  useEffect(() => {
    const credential = token.trim();
    let active = true;
    if (!credential) return undefined;
    void fetchSystemOperations(credential)
      .then((payload) => {
        if (active) setOperations(payload);
      })
      .catch((caught: unknown) => {
        if (active) {
          setOperations(null);
          setWorkspaceError(caught instanceof Error ? caught.message : "无法读取系统运营投影。");
        }
      })
      .finally(() => {
        if (active) setWorkspaceBusy(false);
      });
    return () => {
      active = false;
    };
  }, [token]);

  if (!token.trim()) {
    return <section className="panel"><EmptyState text="使用 auditor 或 tenant_admin 凭据连接后读取系统运营状态。" /></section>;
  }
  if (workspaceBusy && !operations) {
    return <section className="panel"><EmptyState text="正在聚合租户工作状态、Agent 队列、错误与版本…" /></section>;
  }
  if (workspaceError) {
    return (
      <section className="panel">
        <div className="inline-message" data-tone="critical" role="alert">{workspaceError}</div>
        <div className="panel-body"><button className="quiet-button" onClick={() => void loadOperations()} type="button">重新读取</button></div>
      </section>
    );
  }
  if (!operations) {
    return <section className="panel"><EmptyState text="当前没有系统运营数据。" /></section>;
  }

  const queue = operations.agent_queue;
  const work = operations.work_queues;
  const errors = operations.errors;
  const freshness = operations.freshness;
  const agentVersions = operations.agent_versions;
  const credentials = operations.tenant.credential_counts;
  return (
    <div className="model-operations-workspace">
      <section className="rule-operations-summary" aria-label="系统运营状态">
        <article data-tone={queue.queued_count > 0 ? "warning" : undefined}><span>Agent 待发送</span><strong>{queue.queued_count}</strong><small>{queue.aggregated_hosts}/{queue.heartbeat_hosts_total} heartbeat hosts</small></article>
        <article data-tone={work.normalize_pending > 0 ? "warning" : undefined}><span>待标准化</span><strong>{work.normalize_pending}</strong><small>{work.raw_events_total} persisted raw events</small></article>
        <article data-tone={errors.total > 0 ? "warning" : undefined}><span>错误记录</span><strong>{errors.total}</strong><small>component occurrence sum</small></article>
        <article><span>操作凭据</span><strong>{credentials.active}</strong><small>{credentials.total} total · tenant only</small></article>
      </section>

      <div className="bounded-notice model-truth-notice">
        本页仅显示当前租户的持久化状态与最近 Agent heartbeat 中的有界 queue telemetry；它不是 NATS/JetStream
        broker depth、backlog age、数据库/对象存储容量或依赖健康探测。Credential 列表不包含 token/digest，
        也不等同于 human user directory。Agent 版本由当前绑定身份的 heartbeat 自报，不是已验证的二进制或签名
        制品证明。读取仅允许 auditor 或 tenant_admin。
      </div>

      <section className="panel">
        <PanelHeader title="Agent 与工作状态" note={`generated ${formatTime(operations.generated_at)}`} />
        <div className="model-operations-grid">
          <DetailCard title="Latest Agent queue telemetry">
            <DetailRow label="Heartbeat hosts" value={`${queue.aggregated_hosts} / ${queue.heartbeat_hosts_total}`} />
            <DetailRow label="Queued / inflight" value={`${queue.queued_count} / ${queue.inflight_count}`} />
            <DetailRow label="Corrupt" value={String(queue.corrupt_count)} />
            <DetailRow label="Local stored bytes" value={formatBytes(queue.stored_bytes)} />
            <DetailRow label="Dropped P0/P1/P2/P3" value={`${queue.dropped_p0}/${queue.dropped_p1}/${queue.dropped_p2}/${queue.dropped_p3}`} />
            <DetailRow label="Protection mode hosts" value={String(queue.protection_mode_hosts)} />
            <DetailRow label="Latest received" value={queue.latest_heartbeat_received_at ? formatTime(queue.latest_heartbeat_received_at) : "none"} />
          </DetailCard>
          <DetailCard title="Normalize & malware work states">
            <DetailRow label="Normalize pending" value={String(work.normalize_pending)} />
            <DetailRow label="Normalize done" value={String(work.normalize_done)} />
            <DetailRow label="Normalize failed" value={String(work.normalize_failed)} />
            <DetailRow label="Malware queued / leased" value={`${work.malware_queued} / ${work.malware_leased}`} />
            <DetailRow label="Malware completed" value={String(work.malware_completed)} />
            <DetailRow label="Malware failed" value={String(work.malware_failed)} />
          </DetailCard>
          <DetailCard title="Response & notification states">
            <DetailRow label="Response pending / approved" value={`${work.response_pending_approval} / ${work.response_approved}`} />
            <DetailRow label="Response queued / executing" value={`${work.response_queued} / ${work.response_executing}`} />
            <DetailRow label="Rollback queued / running" value={`${work.response_rollback_queued} / ${work.response_rolling_back}`} />
            <DetailRow label="Response terminal" value={String(work.response_terminal)} />
            <DetailRow label="Notification pending / delivering" value={`${work.notifications_pending} / ${work.notifications_delivering}`} />
            <DetailRow label="Notification retry / DLQ" value={`${work.notifications_retry_scheduled} / ${work.notifications_dead_letter}`} />
          </DetailCard>
        </div>
      </section>

      <section className="panel">
        <PanelHeader title="存储记录、错误与数据新鲜度" note="tenant persisted rows; not physical capacity" />
        <div className="model-review-grid">
          <DetailCard title="Persisted record inventory">
            <DetailRow label="Raw / normalized events" value={`${operations.storage_records.raw_events} / ${operations.storage_records.normalized_events}`} />
            <DetailRow label="Evidence objects" value={String(operations.storage_records.evidence_objects)} />
            <DetailRow label="Malware samples" value={String(operations.storage_records.malware_samples)} />
            <DetailRow label="Audit records" value={String(operations.storage_records.audit_records)} />
            <DetailRow label="Database capacity" value="unavailable" />
            <DetailRow label="Object-store capacity" value="unavailable" />
          </DetailCard>
          <DetailCard title="Persisted error occurrences">
            <DetailRow label="Normalize failed" value={String(errors.normalize_failed)} />
            <DetailRow label="Event DLQ records" value={String(errors.event_dlq_records)} />
            <DetailRow label="Agent corrupt queue rows" value={String(errors.agent_queue_corrupt)} />
            <DetailRow label="Malware failed" value={String(errors.malware_failed)} />
            <DetailRow label="Response failed" value={String(errors.response_failed)} />
            <DetailRow label="Notification dead letter" value={String(errors.notifications_dead_letter)} />
          </DetailCard>
          <DetailCard title="Event freshness">
            <DetailRow label="Tracked hosts" value={String(freshness.tracked_hosts)} />
            <DetailRow label="Fresh / stale" value={`${freshness.fresh} / ${freshness.stale}`} />
            <DetailRow label="Degraded / unknown" value={`${freshness.degraded} / ${freshness.unknown}`} />
            <DetailRow label="Lag samples" value={String(freshness.lag_sample_count)} />
            <DetailRow label="Average lag" value={freshness.average_lag_seconds === null ? "unavailable" : `${freshness.average_lag_seconds.toFixed(2)}s`} />
            <DetailRow label="Maximum lag" value={freshness.maximum_lag_seconds === null ? "unavailable" : `${freshness.maximum_lag_seconds.toFixed(2)}s`} />
            <DetailRow label="Updated" value={freshness.updated_at ? formatTime(freshness.updated_at) : "none"} />
          </DetailCard>
        </div>
      </section>

      <section className="panel">
        <PanelHeader title="版本与升级边界" note="observed version; compatibility not evaluated" />
        <div className="model-operations-grid">
          <DetailCard title="Runtime & database">
            <DetailRow label="Application" value={operations.versions.application_version} mono />
            <DetailRow label="Database migration" value={operations.versions.database_migration_version ?? "unavailable"} mono />
            <DetailRow label="Schema compatibility" value={operations.versions.database_schema_compatibility} />
            <DetailRow label="Deployment inventory" value="unavailable" />
            <DetailRow label="Agent versions reported" value={`${agentVersions.reported_hosts} / ${agentVersions.bound_hosts_total}`} />
            <DetailRow label="Distinct Agent versions" value={String(agentVersions.distinct_versions)} />
            <DetailRow label="Binary integrity" value="not verified" />
          </DetailCard>
          <DetailCard title="Self-reported Agent versions">
            {agentVersions.version_groups.map((item) => (
              <DetailRow key={item.version} label={`v${item.version}`} value={`${item.host_count} hosts · ${formatTime(item.latest_reported_at)}`} />
            ))}
            {!agentVersions.version_groups.length && <DetailRow label="Version groups" value="none reported" />}
            <DetailRow label="Unreported bound hosts" value={String(agentVersions.unreported_hosts)} />
            <DetailRow label="Source" value={agentVersions.source} />
          </DetailCard>
          <DetailCard title="Upgrade & recovery">
            <DetailRow label="Upgrade orchestration" value={operations.upgrade.status} />
            <DetailRow label="Agent rollout" value="unavailable" />
            <DetailRow label="Automatic rollback" value="unavailable" />
            <DetailRow label="Offline packages" value="unavailable" />
            <DetailRow label="Signed artifacts" value="unavailable" />
            <DetailRow label="Backup/restore evidence" value="unavailable" />
          </DetailCard>
          <DetailCard title="Active telemetry gaps">
            <DetailRow label="Broker metrics" value="unavailable" />
            <DetailRow label="Backlog age" value="unavailable" />
            <DetailRow label="Database capacity" value="unavailable" />
            <DetailRow label="Object storage capacity" value="unavailable" />
            <DetailRow label="Dependency probes" value="unavailable" />
            <DetailRow label="Human user directory" value="unavailable" />
          </DetailCard>
        </div>
      </section>

      <section className="panel">
        <PanelHeader title="当前租户与操作凭据" note={`${operations.tenant.name} · created ${formatTime(operations.tenant.created_at)}`} />
        <div className="table-scroll"><table className="data-table">
          <thead><tr><th>Credential</th><th>Roles</th><th>Lifecycle</th><th>Created</th><th>Expires</th><th>Revoked</th></tr></thead>
          <tbody>{operations.credentials.map((item) => (
            <tr key={item.credential_id}>
              <td className="mono">{item.credential_id}</td>
              <td>{item.roles.join(", ")}</td>
              <td><StatusPill value={item.lifecycle} /></td>
              <td>{formatTime(item.created_at)}</td>
              <td>{item.expires_at ? formatTime(item.expires_at) : "none"}</td>
              <td>{item.revoked_at ? formatTime(item.revoked_at) : "none"}</td>
            </tr>
          ))}</tbody>
        </table>{!operations.credentials.length && <EmptyState text="当前租户没有操作凭据记录。" />}</div>
      </section>

      {operations.truncated_sections.length > 0 && (
        <div className="bounded-notice">投影已按固定上限缩减：{operations.truncated_sections.join("、")}。</div>
      )}
    </div>
  );
}

function ModelTable({ runs }: { runs: ModelRunSummary[] }) {
  return (
    <section className="panel">
      <PanelHeader title="模型运行审计" note={`${runs.length} records`} />
      <div className="table-scroll"><table className="data-table">
        <thead><tr><th>角色 / Provider</th><th>模型</th><th>Incident</th><th>状态</th><th>延迟</th><th>成本</th></tr></thead>
        <tbody>{runs.map((run) => <tr key={run.run_id}>
          <td><span className="strong">{run.role}</span><span className="subline">{run.provider}</span></td>
          <td>{run.model}</td><td className="mono">{run.incident_id}</td>
          <td><StatusPill value={run.status} /></td><td>{run.latency_ms} ms</td><td>${run.cost_usd.toFixed(4)}</td>
        </tr>)}</tbody>
      </table>{!runs.length && <EmptyState text="当前没有可显示的模型审核记录。" />}</div>
    </section>
  );
}

async function fetchRuleIntelligenceOperations(credential: string): Promise<RuleIntelligenceOperations> {
  const response = await fetch("/api/platform/rules-intelligence", {
    headers: { authorization: `Bearer ${credential}` },
    cache: "no-store",
  });
  const payload: unknown = await response.json();
  if (!response.ok || !isRuleIntelligenceOperations(payload)) {
    throw new Error(
      response.ok
        ? "控制面返回的规则与情报投影格式无效。"
        : apiErrorMessage(payload, response.status),
    );
  }
  return payload;
}

function RulesIntelligenceWorkspace({ token }: { token: string }) {
  const [operations, setOperations] = useState<RuleIntelligenceOperations | null>(null);
  const [workspaceBusy, setWorkspaceBusy] = useState(true);
  const [workspaceError, setWorkspaceError] = useState<string | null>(null);

  const loadOperations = useCallback(async () => {
    const credential = token.trim();
    if (!credential) {
      setOperations(null);
      return;
    }
    setWorkspaceBusy(true);
    setWorkspaceError(null);
    try {
      setOperations(await fetchRuleIntelligenceOperations(credential));
    } catch (caught) {
      setOperations(null);
      setWorkspaceError(caught instanceof Error ? caught.message : "无法读取规则与情报运营投影。");
    } finally {
      setWorkspaceBusy(false);
    }
  }, [token]);

  useEffect(() => {
    const credential = token.trim();
    let active = true;
    if (!credential) return undefined;
    void fetchRuleIntelligenceOperations(credential)
      .then((payload) => {
        if (active) setOperations(payload);
      })
      .catch((caught: unknown) => {
        if (active) {
          setOperations(null);
          setWorkspaceError(caught instanceof Error ? caught.message : "无法读取规则与情报运营投影。");
        }
      })
      .finally(() => {
        if (active) setWorkspaceBusy(false);
      });
    return () => {
      active = false;
    };
  }, [token]);

  if (!token.trim()) {
    return <section className="panel"><EmptyState text="连接控制面后读取规则治理和情报缓存元数据。" /></section>;
  }
  if (workspaceBusy && !operations) {
    return <section className="panel"><EmptyState text="正在核对运行时规则注册表、租户命中与有界情报缓存…" /></section>;
  }
  if (workspaceError) {
    return (
      <section className="panel">
        <div className="inline-message" data-tone="critical" role="alert">{workspaceError}</div>
        <div className="panel-body"><button className="quiet-button" onClick={() => void loadOperations()} type="button">重新读取</button></div>
      </section>
    );
  }
  if (!operations) {
    return <section className="panel"><EmptyState text="当前没有规则与情报运营数据。" /></section>;
  }

  return (
    <div className="rule-operations-workspace">
      <section className="rule-operations-summary" aria-label="规则治理状态">
        <article><span>注册规则</span><strong>{operations.counts.registered_rules}</strong><small>全部显示</small></article>
        <article><span>持久化版本</span><strong>{operations.counts.persisted_rule_versions}</strong><small>{operations.counts.historical_rule_versions} historical</small></article>
        <article><span>生命周期执行</span><strong>已启用</strong><small>{operations.counts.governed_detections} governed · {operations.counts.shadow_observations} shadow</small></article>
        <article data-tone="warning"><span>IOC 生命周期</span><strong>不可用</strong><small>{operations.counts.intelligence_entries} cache entries</small></article>
      </section>

      <div className="bounded-notice rule-governance-warning">
        DetectionWorker 仅依据当前租户经 Ed25519 验证的签名状态执行：Shadow 只记录观察，Canary
        仅对签名 Host 范围告警，Released 对租户 Host 告警；缺失、过期、版本漂移或摘要不匹配均关闭告警。
        本页只读，不提供无签名发布或生命周期写入控件；{operations.counts.legacy_detections} 条历史 detection
        未绑定治理 manifest，保留为 legacy 记录。
      </div>

      <section className="panel">
        <PanelHeader title="规则治理目录" note={`${operations.rules.length} current versions · ${formatTime(operations.generated_at)}`} />
        <div className="rule-card-grid">
          {operations.rules.map((rule) => <RuleGovernanceCard key={`${rule.rule_id}@${rule.version}`} rule={rule} />)}
        </div>
      </section>

      <section className="panel">
        <PanelHeader title="历史持久化规则版本" note={`${operations.counts.historical_rule_versions} tenant versions`} />
        <div className="table-scroll"><table className="data-table">
          <thead><tr><th>规则 / 版本</th><th>命中</th><th>开放</th><th>主机</th><th>反馈</th><th>最后命中</th></tr></thead>
          <tbody>{operations.historical_rule_versions.map((item) => (
            <tr key={`${item.rule_id}@${item.version}`}>
              <td><span className="strong mono">{item.rule_id}</span><span className="subline">version {item.version} · not registered</span></td>
              <td>{item.tenant_metrics.hit_count}</td><td>{item.tenant_metrics.open_hit_count}</td>
              <td>{item.tenant_metrics.distinct_host_count}</td><td>{item.tenant_metrics.feedback_total}</td>
              <td>{item.tenant_metrics.last_hit_at ? formatTime(item.tenant_metrics.last_hit_at) : "—"}</td>
            </tr>
          ))}</tbody>
        </table>{!operations.historical_rule_versions.length && <EmptyState text="当前租户没有历史规则版本命中。" />}</div>
      </section>

      <section className="panel">
        <PanelHeader title="情报缓存可见性" note={`${operations.counts.intelligence_entries} entries · metadata only`} />
        <div className="bounded-notice intelligence-boundary">
          这是租户范围的 enrichment cache 可见性，不是受管 IOC 生命周期。Indicator 按不可信文本渲染；
          任意 payload 值不会发送到浏览器，只显示有界字段名。
        </div>
        <div className="table-scroll"><table className="data-table">
          <thead><tr><th>Indicator</th><th>类型 / 来源</th><th>缓存状态</th><th>Payload 字段名</th><th>获取 / 过期</th></tr></thead>
          <tbody>{operations.intelligence_cache.map((item) => (
            <tr key={item.cache_id}>
              <td><code className="untrusted-indicator">{item.indicator}</code><span className="subline mono">sha256 {compactHash(item.lookup_hash)}</span></td>
              <td><span className="strong">{item.kind}</span><span className="subline">{item.source}</span></td>
              <td><StatusPill value={item.cache_state} /></td>
              <td><code className="payload-field-list">{item.payload_fields.join(", ") || "none"}</code><span className="subline">{item.payload_field_count} fields{item.payload_fields_truncated ? " · truncated" : ""}</span></td>
              <td>{formatTime(item.fetched_at)}<span className="subline">{item.expires_at ? formatTime(item.expires_at) : "no expiry"}</span></td>
            </tr>
          ))}</tbody>
        </table>{!operations.intelligence_cache.length && <EmptyState text="当前租户没有 enrichment cache 记录。" />}</div>
      </section>

      {operations.truncated_sections.length > 0 && (
        <div className="bounded-notice">投影已按固定上限缩减：{operations.truncated_sections.join("、")}。</div>
      )}
    </div>
  );
}

function RuleGovernanceCard({ rule }: { rule: RuleGovernanceEntry }) {
  const metrics = rule.tenant_metrics;
  const quality = rule.quality_metrics;
  const qualityEntries = [
    ["Precision", formatOptionalPercent(quality.precision)],
    ["Recall", formatOptionalPercent(quality.recall)],
    ["FP / host-day", formatOptionalNumber(quality.false_positives_per_host_day)],
    ["Attempt/success error", formatOptionalPercent(quality.attack_attempt_success_error_rate)],
    ["MTTD", quality.mttd_seconds === null ? "未测量" : `${quality.mttd_seconds.toFixed(1)} s`],
    ["Missing-source sensitivity", formatOptionalPercent(quality.missing_source_sensitivity)],
    ["ms / 1k events", formatOptionalNumber(quality.performance_ms_per_1000_events)],
  ] as const;
  return (
    <article className="rule-governance-card">
      <header>
        <div><span className="eyebrow">{rule.rule_id} · v{rule.version}</span><h3>{rule.title}</h3></div>
        <StatusPill value={rule.lifecycle_stage} />
      </header>
      <div className="rule-runtime-mismatch" data-active={rule.runtime_state !== "current" && rule.runtime_state !== "absent"}>
        Runtime {rule.runtime_state} · effective scope {rule.emission_scope}
      </div>
      <div className="rule-metric-strip">
        <span><strong>{metrics.hit_count}</strong> hits</span><span><strong>{metrics.open_hit_count}</strong> open</span>
        <span><strong>{metrics.distinct_host_count}</strong> hosts</span><span><strong>{metrics.shadow_observation_count}</strong> shadow</span>
      </div>
      <div className="rule-detail-grid">
        <div><span>Owner</span><strong>{rule.owner}</strong></div>
        <div><span>Last hit</span><strong>{metrics.last_hit_at ? formatTime(metrics.last_hit_at) : "none"}</strong></div>
        <div><span>Feedback</span><strong>TP {metrics.true_positive_feedback} · FP {metrics.false_positive_feedback} · benign {metrics.benign_feedback} · review {metrics.needs_review_feedback}</strong></div>
        <div><span>ATT&CK</span><strong>{rule.technique_ids.join(", ")}</strong></div>
        <div><span>Governed / legacy</span><strong>{metrics.governed_hit_count} / {metrics.legacy_hit_count}</strong></div>
        <div><span>Manifest</span><strong>{rule.manifest_sha256 ? compactHash(rule.manifest_sha256) : "absent"}</strong></div>
        <div><span>Signing key</span><strong>{rule.signing_key_id ?? "absent"}</strong></div>
        <div><span>Sequence / version</span><strong>{rule.lifecycle_sequence ?? "—"} / {rule.lifecycle_rule_version ?? "—"}</strong></div>
        <div><span>Catalog digest</span><strong>{rule.catalog_digest_matches === null ? "absent" : rule.catalog_digest_matches ? "match" : "mismatch"}</strong></div>
        <div><span>Validation evidence</span><strong>{rule.validation_evidence_count} datasets</strong></div>
        <div><span>Canary scope</span><strong>{rule.canary_host_count} Hosts</strong></div>
        <div><span>Manifest expiry</span><strong>{rule.manifest_expires_at ? formatTime(rule.manifest_expires_at) : "absent"}</strong></div>
      </div>
      <div className="rule-tag-strip">
        {rule.data_sources.map((item) => <span key={item}>{item}</span>)}
      </div>
      <div className="rule-governance-sections">
        <RuleTextList label="Datasets" values={rule.test_datasets} />
        <RuleTextList label="Expected false positives" values={rule.expected_false_positives} />
        <RuleTextList label="Suppression conditions" values={rule.suppression_conditions} />
        {rule.canary_host_ids.length > 0 && <RuleTextList label="Canary Host sample" values={rule.canary_host_ids} />}
      </div>
      <div className="rule-note"><span>Rollback</span><p>{rule.rollback_plan}</p></div>
      <div className="rule-note"><span>Runtime truth</span><p>{rule.runtime_note}</p></div>
      <div className="quality-grid">
        {qualityEntries.map(([label, value]) => <div key={label}><span>{label}</span><strong>{value}</strong></div>)}
      </div>
    </article>
  );
}

function RuleTextList({ label, values }: { label: string; values: string[] }) {
  return <div><span>{label}</span><ul>{values.map((item) => <li key={item}>{item}</li>)}</ul></div>;
}

function ResponseWorkspace({
  actions,
  csrfNonce,
  onChanged,
  token,
}: {
  actions: ResponsePlan[];
  csrfNonce: string;
  onChanged: () => Promise<void>;
  token: string;
}) {
  const [selectedActionId, setSelectedActionId] = useState<string | null>(null);
  const [detail, setDetail] = useState<ResponseActionDetail | null>(null);
  const [detailBusy, setDetailBusy] = useState(false);
  const [mutationBusy, setMutationBusy] = useState(false);
  const [workspaceError, setWorkspaceError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [approvalComment, setApprovalComment] = useState("");
  const [businessConfirmation, setBusinessConfirmation] = useState(false);
  const [queueConfirmed, setQueueConfirmed] = useState(false);
  const [rollbackReason, setRollbackReason] = useState("");
  const [rollbackConfirmed, setRollbackConfirmed] = useState(false);

  const loadDetail = useCallback(async (actionId: string) => {
    setSelectedActionId(actionId);
    setDetailBusy(true);
    setWorkspaceError(null);
    setSuccess(null);
    try {
      const response = await fetch(
        `/api/platform/response-detail?action_id=${encodeURIComponent(actionId)}`,
        {
          headers: { authorization: `Bearer ${token.trim()}` },
          cache: "no-store",
        },
      );
      const payload: unknown = await response.json();
      if (!response.ok || !isResponseActionDetail(payload)) {
        throw new Error(response.ok ? "控制面返回的响应详情格式无效。" : apiErrorMessage(payload, response.status));
      }
      setDetail(payload);
      setApprovalComment("");
      setBusinessConfirmation(false);
      setQueueConfirmed(false);
      setRollbackReason("");
      setRollbackConfirmed(false);
    } catch (caught) {
      setDetail(null);
      setWorkspaceError(caught instanceof Error ? caught.message : "无法读取响应动作详情。");
    } finally {
      setDetailBusy(false);
    }
  }, [token]);

  const submitMutation = async (
    endpoint: "/api/platform/response-approval" | "/api/platform/response-execute" | "/api/platform/response-rollback",
    body: Record<string, unknown>,
    successMessage: string,
  ) => {
    if (!csrfNonce || !selectedActionId) {
      setWorkspaceError("控制台写入会话尚未就绪，请刷新页面后重试。");
      return;
    }
    setMutationBusy(true);
    setWorkspaceError(null);
    setSuccess(null);
    try {
      const response = await fetch(endpoint, {
        method: "POST",
        headers: {
          authorization: `Bearer ${token.trim()}`,
          "content-type": "application/json",
          "x-aisoc-csrf": csrfNonce,
        },
        body: JSON.stringify({ action_id: selectedActionId, ...body }),
        cache: "no-store",
      });
      const payload: unknown = await response.json();
      if (!response.ok || !isResponseActionDetail(payload)) {
        throw new Error(response.ok ? "控制面返回的写入结果格式无效。" : apiErrorMessage(payload, response.status));
      }
      setDetail(payload);
      setSuccess(successMessage);
      setApprovalComment("");
      setBusinessConfirmation(false);
      setQueueConfirmed(false);
      setRollbackReason("");
      setRollbackConfirmed(false);
      await onChanged();
    } catch (caught) {
      setWorkspaceError(caught instanceof Error ? caught.message : "响应动作写入失败。");
    } finally {
      setMutationBusy(false);
    }
  };

  const submitApproval = (decision: "approve" | "reject") => submitMutation(
    "/api/platform/response-approval",
    {
      decision,
      comment: approvalComment,
      business_confirmation: decision === "approve" && businessConfirmation,
    },
    decision === "approve" ? "审批决定已记录。" : "拒绝决定已记录。",
  );

  const queueExecution = () => submitMutation(
    "/api/platform/response-execute",
    { idempotency_key: `console-execute-${crypto.randomUUID()}` },
    "动作已提交至受控执行队列。",
  );

  const requestRollback = () => submitMutation(
    "/api/platform/response-rollback",
    {
      reason: rollbackReason,
      idempotency_key: `console-rollback-${crypto.randomUUID()}`,
    },
    "回滚请求已提交至受控队列。",
  );

  return (
    <div className="response-workspace">
      <section className="panel">
        <PanelHeader title="响应动作" note={`${actions.length} records · select one to inspect`} />
        <ResponseTable
          actions={actions}
          onSelect={(actionId) => void loadDetail(actionId)}
          selectedActionId={selectedActionId}
        />
      </section>

      <section className="panel response-detail-panel" aria-live="polite">
        <PanelHeader
          title="响应详情与审批控制"
          note={detail ? detail.plan.action_id : "backend RBAC remains authoritative"}
        />
        {workspaceError && <div className="inline-message" data-tone="critical" role="alert">{workspaceError}</div>}
        {success && <div className="inline-message" data-tone="good" role="status">{success}</div>}
        {detailBusy && <div className="empty-state">正在读取不可变审计轨迹…</div>}
        {!detailBusy && !detail && <EmptyState text="选择一个响应动作，查看目标、策略、审批、执行和回滚轨迹。" />}
        {!detailBusy && detail && (
          <ResponseDetail
            approvalComment={approvalComment}
            businessConfirmation={businessConfirmation}
            detail={detail}
            mutationBusy={mutationBusy}
            onApprovalComment={setApprovalComment}
            onBusinessConfirmation={setBusinessConfirmation}
            onQueue={() => void queueExecution()}
            onQueueConfirmed={setQueueConfirmed}
            onRollback={() => void requestRollback()}
            onRollbackConfirmed={setRollbackConfirmed}
            onRollbackReason={setRollbackReason}
            onSubmitApproval={(decision) => void submitApproval(decision)}
            queueConfirmed={queueConfirmed}
            rollbackConfirmed={rollbackConfirmed}
            rollbackReason={rollbackReason}
          />
        )}
      </section>
    </div>
  );
}

function ResponseDetail({
  approvalComment,
  businessConfirmation,
  detail,
  mutationBusy,
  onApprovalComment,
  onBusinessConfirmation,
  onQueue,
  onQueueConfirmed,
  onRollback,
  onRollbackConfirmed,
  onRollbackReason,
  onSubmitApproval,
  queueConfirmed,
  rollbackConfirmed,
  rollbackReason,
}: {
  approvalComment: string;
  businessConfirmation: boolean;
  detail: ResponseActionDetail;
  mutationBusy: boolean;
  onApprovalComment: (value: string) => void;
  onBusinessConfirmation: (value: boolean) => void;
  onQueue: () => void;
  onQueueConfirmed: (value: boolean) => void;
  onRollback: () => void;
  onRollbackConfirmed: (value: boolean) => void;
  onRollbackReason: (value: string) => void;
  onSubmitApproval: (decision: "approve" | "reject") => void;
  queueConfirmed: boolean;
  rollbackConfirmed: boolean;
  rollbackReason: string;
}) {
  const { plan } = detail;
  const canDecide = plan.status === "pending_approval";
  const canQueue = plan.status === "approved";
  const canRollback = plan.status === "succeeded" && plan.policy.rollback_required && plan.policy.rollback_supported;
  const targetEntries = Object.entries(plan.target).filter(([key]) => key !== "target_type");

  return (
    <div className="response-detail-body">
      <div className="detail-hero">
        <div>
          <div className="eyebrow">{plan.operation} · {plan.adapter}</div>
          <h3>{actionLabel(plan.action)}</h3>
          <p>{plan.reason}</p>
        </div>
        <StatusPill value={plan.status} />
      </div>

      <div className="detail-grid">
        <DetailCard title="策略门控">
          <DetailRow label="响应等级" value={plan.tier.toUpperCase().slice(0, 2)} />
          <DetailRow label="审批进度" value={`${plan.approval_count}/${plan.policy.required_approvals}`} />
          <DetailRow label="目标重验证" value={yesNo(plan.policy.target_revalidation_required)} />
          <DetailRow label="执行后验证" value={yesNo(plan.policy.execution_verification_required)} />
          <DetailRow label="可验证回滚" value={yesNo(plan.policy.rollback_supported)} />
          <DetailRow label="业务确认" value={yesNo(plan.policy.business_confirmation_required)} />
        </DetailCard>
        <DetailCard title="绑定目标">
          {targetEntries.map(([key, value]) => (
            <DetailRow key={key} label={key.replaceAll("_", " ")} value={formatTargetValue(value)} mono />
          ))}
          <DetailRow label="identity SHA-256" value={compactHash(plan.target_identity_sha256)} mono />
        </DetailCard>
        <DetailCard title="请求与证据">
          <DetailRow label="Incident" value={`${plan.incident_id} · rev ${plan.incident_revision}`} mono />
          <DetailRow label="请求者" value={plan.requested_by} mono />
          <DetailRow label="创建" value={formatTime(plan.created_at)} />
          <DetailRow label="到期" value={plan.expires_at ? formatTime(plan.expires_at) : "不适用"} />
          <DetailRow label="证据" value={plan.evidence_ids.map(compactHash).join(", ")} mono />
        </DetailCard>
      </div>

      <div className="policy-reasons">
        {plan.policy.reasons.map((reason) => <span className="pill" key={reason}>{reason.replaceAll("_", " ")}</span>)}
      </div>

      <section className="control-card" aria-label="响应动作控制">
        <div className="control-copy">
          <strong>显式操作门禁</strong>
          <span>浏览器仅提交请求；租户 RBAC、自审批隔离、状态机和执行开关由控制面再次验证。</span>
        </div>
        {canDecide && (
          <form className="control-form" onSubmit={(event) => { event.preventDefault(); onSubmitApproval("approve"); }}>
            <label htmlFor="approval-comment">审批意见</label>
            <textarea
              id="approval-comment"
              maxLength={512}
              onChange={(event) => onApprovalComment(event.target.value)}
              placeholder="记录批准或拒绝所依据的证据与边界"
              required
              value={approvalComment}
            />
            {plan.policy.business_confirmation_required && (
              <CheckControl
                checked={businessConfirmation}
                label="已取得并记录业务影响确认（仅批准时生效）"
                onChange={onBusinessConfirmation}
              />
            )}
            <div className="control-actions">
              <button
                className="primary-button"
                disabled={mutationBusy || !approvalComment.trim() || (plan.policy.business_confirmation_required && !businessConfirmation)}
                type="submit"
              >
                记录批准
              </button>
              <button
                className="danger-button"
                disabled={mutationBusy || !approvalComment.trim()}
                onClick={() => onSubmitApproval("reject")}
                type="button"
              >
                记录拒绝
              </button>
            </div>
          </form>
        )}
        {canQueue && (
          <div className="control-form">
            <CheckControl
              checked={queueConfirmed}
              label="已核对目标身份、Agent 绑定、TTL、影响范围与回滚要求"
              onChange={onQueueConfirmed}
            />
            <button className="primary-button" disabled={mutationBusy || !queueConfirmed} onClick={onQueue} type="button">
              排队执行
            </button>
          </div>
        )}
        {canRollback && (
          <form className="control-form" onSubmit={(event) => { event.preventDefault(); onRollback(); }}>
            <label htmlFor="rollback-reason">回滚原因</label>
            <textarea
              id="rollback-reason"
              maxLength={512}
              onChange={(event) => onRollbackReason(event.target.value)}
              placeholder="说明回滚触发条件与预期恢复状态"
              required
              value={rollbackReason}
            />
            <CheckControl
              checked={rollbackConfirmed}
              label="已确认该动作成功完成，且当前目标仍满足回滚前置条件"
              onChange={onRollbackConfirmed}
            />
            <button className="danger-button" disabled={mutationBusy || !rollbackConfirmed || !rollbackReason.trim()} type="submit">
              请求回滚
            </button>
          </form>
        )}
        {!canDecide && !canQueue && !canRollback && (
          <div className="control-idle">当前状态没有可由控制台发起的操作。详情和审计轨迹仍可读取。</div>
        )}
      </section>

      <div className="audit-grid">
        <AuditCard title={`审批记录 · ${detail.approvals.length}`} empty="尚无审批记录。">
          {detail.approvals.map((approval) => (
            <AuditItem
              key={approval.approval_id}
              meta={`${approval.approver} · ${formatTime(approval.created_at)}`}
              status={approval.decision}
              text={approval.comment}
            />
          ))}
        </AuditCard>
        <AuditCard title={`执行记录 · ${detail.executions.length}`} empty="尚无执行记录。">
          {detail.executions.map((execution) => (
            <AuditItem
              key={execution.execution_id}
              meta={`attempt ${execution.attempt} · ${execution.result.operation_reference}`}
              status={execution.status}
              text={execution.result.verification_passed ? "post-check verified" : execution.result.error_code ?? "verification unavailable"}
            />
          ))}
        </AuditCard>
        <AuditCard title={`回滚记录 · ${detail.rollbacks.length}`} empty="尚无回滚记录。">
          {detail.rollbacks.map((rollback) => (
            <AuditItem
              key={rollback.rollback_id}
              meta={`${rollback.requested_by} · ${rollback.result.operation_reference}`}
              status={rollback.status}
              text={rollback.reason}
            />
          ))}
        </AuditCard>
      </div>

      <section className="event-timeline" aria-label="响应状态时间线">
        <h4>不可变状态事件 · {detail.events.length}</h4>
        {detail.events.map((event) => (
          <div className="event-row" key={event.sequence}>
            <span className="event-sequence">{event.sequence.toString().padStart(2, "0")}</span>
            <div>
              <strong>{event.from_status ? `${statusLabel(event.from_status)} → ` : ""}{statusLabel(event.to_status)}</strong>
              <span>{event.reason.replaceAll("_", " ")} · {event.actor} · {formatTime(event.created_at)}</span>
            </div>
          </div>
        ))}
      </section>
    </div>
  );
}

function DetailCard({ children, title }: { children: ReactNode; title: string }) {
  return <section className="detail-card"><h4>{title}</h4>{children}</section>;
}

function DetailRow({ label, mono = false, value }: { label: string; mono?: boolean; value: string }) {
  return <div className="detail-row"><span>{label}</span><strong className={mono ? "mono" : undefined}>{value}</strong></div>;
}

function CheckControl({ checked, label, onChange }: { checked: boolean; label: string; onChange: (value: boolean) => void }) {
  return <label className="check-control"><input checked={checked} onChange={(event) => onChange(event.target.checked)} type="checkbox" /><span>{label}</span></label>;
}

function AuditCard({ children, empty, title }: { children: ReactNode; empty: string; title: string }) {
  const hasItems = Array.isArray(children) ? children.length > 0 : Boolean(children);
  return <section className="audit-card"><h4>{title}</h4>{hasItems ? children : <span className="audit-empty">{empty}</span>}</section>;
}

function AuditItem({ meta, status, text }: { meta: string; status: string; text: string }) {
  return <div className="audit-item"><div><StatusPill value={status} /><span>{meta}</span></div><p>{text}</p></div>;
}

function ResponseTable({
  actions,
  embedded = false,
  onSelect,
  selectedActionId,
}: {
  actions: ResponsePlan[];
  embedded?: boolean;
  onSelect?: (actionId: string) => void;
  selectedActionId?: string | null;
}) {
  const table = (
    <div className="table-scroll">
      <table className="data-table">
        <thead><tr><th>动作</th><th>Incident</th><th>等级</th><th>审批</th><th>状态</th><th>创建时间</th>{onSelect && <th>详情</th>}</tr></thead>
        <tbody>{actions.map((action) => <tr key={action.action_id}>
          <td><span className="strong">{actionLabel(action.action)}</span><span className="subline">{action.reason}</span></td>
          <td className="mono">{action.incident_id}</td><td>{action.tier.toUpperCase().slice(0, 2)}</td>
          <td>{action.approval_count}/{action.policy.required_approvals}</td><td><StatusPill value={action.status} /></td><td>{formatTime(action.created_at)}</td>
          {onSelect && <td><button className="row-action" data-selected={selectedActionId === action.action_id} onClick={() => onSelect(action.action_id)} type="button">{selectedActionId === action.action_id ? "已选择" : "查看"}</button></td>}
        </tr>)}</tbody>
      </table>
      {!actions.length && <EmptyState text="当前没有可显示的响应动作。" />}
    </div>
  );
  return embedded ? table : <section className="panel"><PanelHeader title="响应动作" note={`${actions.length} records`} />{table}</section>;
}

function PanelHeader({ title, note }: { title: string; note: string }) {
  return <div className="panel-header"><h2 className="panel-title">{title}</h2><span className="panel-note">{note}</span></div>;
}

function EmptyState({ text }: { text: string }) {
  return <div className="empty-state">{text}</div>;
}

function StatusPill({ value }: { value: string }) {
  return <span className="pill" data-tone={toneForStatus(value)}>{statusLabel(value)}</span>;
}

function toneForSeverity(value: string): "critical" | "warning" | "good" | undefined {
  const severity = value.toLowerCase();
  if (severity === "critical" || severity === "high") return "critical";
  if (severity === "medium") return "warning";
  if (severity === "low") return "good";
  return undefined;
}

function toneForStatus(value: string): "critical" | "warning" | "good" | undefined {
  const status = value.toLowerCase();
  if (/failed|rejected|revoked|critical|degraded|expired|deprecated|contradicted|unsupported|untrusted/.test(status)) return "critical";
  if (/pending|queued|review|stale|draft|shadow|canary|no_expiry|high|medium|late|skew|unknown|inferred/.test(status)) return "warning";
  if (/success|approved|complete|fresh|released|low|rolled_back|supported|trusted|observed|active/.test(status)) return "good";
  return undefined;
}

function severityLabel(value: string): string {
  return ({ critical: "严重", high: "高危", medium: "中危", low: "低危" } as Record<string, string>)[value.toLowerCase()] ?? value;
}

function statusLabel(value: string): string {
  return ({ fresh: "新鲜", no_expiry: "无过期时间", stale: "延迟", degraded: "降级", unknown: "未知", trusted: "可信", untrusted: "不可信", skew_detected: "时钟偏差", late: "迟到", draft: "草案", shadow: "影子", canary: "金丝雀", released: "已发布", deprecated: "已弃用", supported: "已支持", contradicted: "已反驳", unsupported: "无支持", observed: "已观察", inferred: "推断", not_attributed: "未归因", active: "有效", revoked: "已吊销", pending_approval: "待审批", approve: "批准", approved: "已批准", reject: "拒绝", rejected: "已拒绝", queued: "已排队", executing: "执行中", succeeded: "已完成", verification_failed: "验证失败", failed: "失败", rollback_queued: "回滚已排队", rolling_back: "回滚中", rolled_back: "已回滚", rollback_failed: "回滚失败", cancelled: "已取消", expired: "已过期" } as Record<string, string>)[value] ?? value.replaceAll("_", " ");
}

function attackStateLabel(value: string): string {
  return ({ normal: "正常", suspicious: "可疑", attack_attempt: "攻击尝试", suspected_success: "疑似成功", confirmed_compromise: "确认失陷", remediated: "已处置" } as Record<string, string>)[value] ?? value.replaceAll("_", " ");
}

function actionLabel(value: string): string {
  return ({ collect_evidence: "采集证据", temporary_block_ip: "临时封禁 IP", isolate_file: "隔离文件", terminate_process: "终止进程", disable_account: "禁用账号", isolate_host: "隔离主机" } as Record<string, string>)[value] ?? value.replaceAll("_", " ");
}

function compactHash(value: string): string {
  return value.length > 20 ? `${value.slice(0, 12)}…${value.slice(-8)}` : value;
}

function formatBytes(value: number): string {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}

function formatTime(value: string): string {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return "invalid time";
  return new Intl.DateTimeFormat("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false }).format(parsed);
}

function formatOptionalPercent(value: number | null): string {
  return value === null ? "未测量" : `${(value * 100).toFixed(1)}%`;
}

function formatOptionalNumber(value: number | null): string {
  return value === null ? "未测量" : value.toFixed(3);
}

function yesNo(value: boolean): string {
  return value ? "是" : "否";
}

function formatTargetValue(value: unknown): string {
  if (Array.isArray(value)) return value.map((item) => String(item)).join(", ");
  if (typeof value === "boolean") return yesNo(value);
  if (typeof value === "string" || typeof value === "number") return String(value);
  return "unsupported value";
}

function isResponseActionDetail(value: unknown): value is ResponseActionDetail {
  if (!isRecord(value) || !isRecord(value.plan)) return false;
  return typeof value.plan.action_id === "string"
    && /^rsa_[a-f0-9]{32}$/.test(value.plan.action_id)
    && typeof value.plan.status === "string"
    && Array.isArray(value.approvals)
    && Array.isArray(value.executions)
    && Array.isArray(value.rollbacks)
    && Array.isArray(value.events);
}

function isIncidentInvestigation(value: unknown): value is IncidentInvestigation {
  if (!isRecord(value) || !isRecord(value.counts)) return false;
  return typeof value.incident_id === "string"
    && /^inc_[a-f0-9]{32}$/.test(value.incident_id)
    && typeof value.revision === "number"
    && typeof value.counts.indexed_evidence === "number"
    && Array.isArray(value.evidence)
    && Array.isArray(value.timeline)
    && Array.isArray(value.claims)
    && Array.isArray(value.entities)
    && Array.isArray(value.edges)
    && Array.isArray(value.truncated_sections);
}

function isIncidentEvidenceDetail(value: unknown): value is IncidentEvidenceDetail {
  if (!isRecord(value) || !isRecord(value.evidence) || !isRecord(value.normalized_event)) return false;
  return typeof value.incident_id === "string"
    && /^inc_[a-f0-9]{32}$/.test(value.incident_id)
    && typeof value.evidence.evidence_id === "string"
    && /^evi_[a-f0-9]{24}$/.test(value.evidence.evidence_id)
    && typeof value.normalized_event.event_id === "string"
    && isRecord(value.normalized_event.payload)
    && isRecord(value.normalized_event.labels)
    && isRecord(value.normalized_event.extensions);
}

function isTraceInvestigation(value: unknown): value is TraceInvestigation {
  if (!isRecord(value) || !isRecord(value.counts)) return false;
  const sectionNames = [
    "source_incidents",
    "evidence",
    "key_path",
    "impacted_hosts",
    "infrastructure_clusters",
    "techniques",
    "entities",
    "edges",
  ] as const;
  const sections = [
    [value.counts.source_incidents, value.source_incidents, 50],
    [value.counts.evidence, value.evidence, 100],
    [value.counts.key_path, value.key_path, 100],
    [value.counts.impacted_hosts, value.impacted_host_ids, 100],
    [value.counts.infrastructure_clusters, value.infrastructure_clusters, 50],
    [value.counts.techniques, value.techniques, 50],
    [value.counts.entities, value.entities, 200],
    [value.counts.edges, value.edges, 400],
  ] as const;
  if (
    value.schema_version !== "0.1.0"
    || typeof value.tenant_id !== "string"
    || typeof value.trace_id !== "string"
    || !/^trc_[a-f0-9]{32}$/.test(value.trace_id)
    || typeof value.seed_incident_id !== "string"
    || !/^inc_[a-f0-9]{32}$/.test(value.seed_incident_id)
    || typeof value.revision !== "number"
    || !Number.isInteger(value.revision)
    || value.revision < 1
    || typeof value.revision_reason !== "string"
    || typeof value.first_seen !== "string"
    || typeof value.last_seen !== "string"
    || typeof value.attack_state !== "string"
    || !Array.isArray(value.truncated_sections)
    || !isStringArray(value.truncated_sections)
    || !Array.isArray(value.attribution_limitations)
    || !isStringArray(value.attribution_limitations)
    || value.attribution_limitations.length < 1
    || value.attribution_limitations.length > 16
    || value.attribution_limitations.some((item) => item.length < 1 || item.length > 512)
    || value.identity_attribution_status !== "not_attributed"
    || value.identity_assertion_count !== 0
    || value.identity_attribution_reason !== "no_verified_identity_evidence"
    || "identity_assertions" in value
    || "identity_attribution" in value
    || "raw_ref" in value
    || value.raw_ref_included !== false
    || value.raw_evidence_bytes_included !== false
    || value.interactive_graph_query_available !== false
    || value.investigation_export_available !== false
    || sections.some(([total, items, limit]) => (
      typeof total !== "number"
      || !Number.isInteger(total)
      || total < 0
      || !Array.isArray(items)
      || items.length > limit
      || total < items.length
    ))
  ) return false;

  const expectedTruncated = sectionNames.filter((name, index) => (
    Number(value.counts[name]) > (sections[index][1] as unknown[]).length
  ));
  if (
    expectedTruncated.length !== value.truncated_sections.length
    || expectedTruncated.some((name, index) => value.truncated_sections[index] !== name)
  ) return false;

  if (
    !Array.isArray(value.source_incidents)
    || !value.source_incidents.some((item) => isRecord(item) && item.incident_id === value.seed_incident_id)
    || !value.source_incidents.every((item) => (
      isRecord(item)
      && typeof item.incident_id === "string"
      && /^inc_[a-f0-9]{32}$/.test(item.incident_id)
      && typeof item.revision === "number"
      && typeof item.primary_host_id === "string"
      && typeof item.severity === "string"
      && typeof item.attack_state === "string"
      && typeof item.first_seen === "string"
      && typeof item.last_seen === "string"
    ))
    || !Array.isArray(value.impacted_host_ids)
    || !isStringArray(value.impacted_host_ids)
    || [...value.impacted_host_ids].sort().some((item, index) => item !== value.impacted_host_ids[index])
    || new Set(value.impacted_host_ids).size !== value.impacted_host_ids.length
  ) return false;

  const evidencePattern = /^tev_[a-f0-9]{24}$/;
  if (
    !Array.isArray(value.evidence)
    || value.evidence.length < 1
    || !value.evidence.every((item) => (
      isRecord(item)
      && !("raw_ref" in item)
      && typeof item.trace_evidence_id === "string"
      && evidencePattern.test(item.trace_evidence_id)
      && typeof item.incident_id === "string"
      && /^inc_[a-f0-9]{32}$/.test(item.incident_id)
      && typeof item.incident_revision === "number"
      && typeof item.incident_evidence_id === "string"
      && /^evi_[a-f0-9]{24}$/.test(item.incident_evidence_id)
      && typeof item.event_id === "string"
      && typeof item.event_type === "string"
      && item.event_type.length <= 128
      && typeof item.event_time === "string"
      && typeof item.host_id === "string"
      && typeof item.source_time_quality === "string"
      && typeof item.is_late === "boolean"
    ))
  ) return false;
  const evidenceIds = new Set(value.evidence.map((item) => item.trace_evidence_id));
  if (evidenceIds.size !== value.evidence.length) return false;

  const stepValid = (item: unknown): item is TraceStep => (
    isRecord(item)
    && typeof item.step_id === "string"
    && /^tst_[a-f0-9]{24}$/.test(item.step_id)
    && typeof item.kind === "string"
    && typeof item.event_time === "string"
    && typeof item.source_host_id === "string"
    && (item.target_host_id === null || typeof item.target_host_id === "string")
    && typeof item.summary === "string"
    && typeof item.attack_state === "string"
    && typeof item.evidence_count === "number"
    && Array.isArray(item.evidence_ids)
    && isStringArray(item.evidence_ids)
    && item.evidence_ids.length <= 8
    && item.evidence_ids.length <= item.evidence_count
    && item.evidence_ids.every((identifier) => evidencePattern.test(identifier) && evidenceIds.has(identifier))
  );
  if (
    !(value.initial_access === null || stepValid(value.initial_access))
    || !Array.isArray(value.key_path)
    || !value.key_path.every(stepValid)
  ) return false;

  if (
    !Array.isArray(value.entities)
    || !value.entities.every((item) => (
      isRecord(item)
      && !("attributes" in item)
      && typeof item.entity_id === "string"
      && /^tge_[a-f0-9]{24}$/.test(item.entity_id)
      && typeof item.entity_type === "string"
      && typeof item.canonical_key === "string"
      && typeof item.first_seen === "string"
      && typeof item.last_seen === "string"
    ))
  ) return false;
  const entityIds = new Set(value.entities.map((item) => item.entity_id));
  if (entityIds.size !== value.entities.length) return false;
  if (
    !Array.isArray(value.edges)
    || !value.edges.every((item) => (
      isRecord(item)
      && typeof item.edge_id === "string"
      && /^ted_[a-f0-9]{24}$/.test(item.edge_id)
      && typeof item.source_entity_id === "string"
      && entityIds.has(item.source_entity_id)
      && typeof item.target_entity_id === "string"
      && entityIds.has(item.target_entity_id)
      && typeof item.relationship === "string"
      && typeof item.first_seen === "string"
      && typeof item.last_seen === "string"
      && typeof item.evidence_count === "number"
      && Array.isArray(item.evidence_ids)
      && isStringArray(item.evidence_ids)
      && item.evidence_ids.length <= 8
      && item.evidence_ids.length <= item.evidence_count
      && item.evidence_ids.every((identifier) => evidencePattern.test(identifier) && evidenceIds.has(identifier))
      && typeof item.confidence === "number"
      && item.confidence >= 0
      && item.confidence <= 1
    ))
  ) return false;

  const boundedReferencesValid = (item: unknown, idFields: string[]): boolean => (
    isRecord(item)
    && idFields.every((field) => (
      Array.isArray(item[field])
      && isStringArray(item[field])
      && item[field].length <= 8
    ))
    && Array.isArray(item.evidence_ids)
    && item.evidence_ids.every((identifier) => evidencePattern.test(identifier) && evidenceIds.has(identifier))
  );
  return Array.isArray(value.techniques)
    && value.techniques.every((item) => (
      boundedReferencesValid(item, ["evidence_ids", "source_rule_ids"])
      && isRecord(item)
      && typeof item.technique_id === "string"
      && /^T[0-9]{4}(\.[0-9]{3})?$/.test(item.technique_id)
      && typeof item.name === "string"
      && typeof item.tactic === "string"
      && item.mapping_version === "p10-attack-map-v0.1.0"
      && typeof item.epistemic_status === "string"
      && typeof item.evidence_count === "number"
      && typeof item.source_rule_count === "number"
      && (item.evidence_ids as unknown[]).length <= item.evidence_count
      && (item.source_rule_ids as unknown[]).length <= item.source_rule_count
      && (item.source_rule_ids as string[]).every((identifier) => (
        identifier.length >= 1 && identifier.length <= 128
      ))
    ))
    && Array.isArray(value.infrastructure_clusters)
    && value.infrastructure_clusters.every((item) => (
      boundedReferencesValid(item, ["host_ids", "incident_ids", "evidence_ids"])
      && isRecord(item)
      && typeof item.cluster_id === "string"
      && /^icl_[a-f0-9]{24}$/.test(item.cluster_id)
      && typeof item.observable_type === "string"
      && typeof item.canonical_value === "string"
      && typeof item.host_count === "number"
      && typeof item.incident_count === "number"
      && typeof item.evidence_count === "number"
      && item.similarity_basis === "exact_observable_match"
      && (item.host_ids as unknown[]).length <= item.host_count
      && (item.incident_ids as unknown[]).length <= item.incident_count
      && (item.evidence_ids as unknown[]).length <= item.evidence_count
    ));
}

function isMalwareInvestigation(value: unknown): value is MalwareInvestigation {
  if (!isRecord(value) || !isRecord(value.sample) || !isRecord(value.counts)) return false;
  const analysisValid = value.analysis === null || (
    isRecord(value.analysis)
    && isRecord(value.analysis.profile)
    && typeof value.analysis.task_id === "string"
    && /^scan_[a-f0-9]{32}$/.test(value.analysis.task_id)
    && Array.isArray(value.analysis.engine_results)
    && Array.isArray(value.analysis.families)
  );
  return typeof value.sample.sample_id === "string"
    && /^smp_[a-f0-9]{32}$/.test(value.sample.sample_id)
    && typeof value.sample.sha256 === "string"
    && /^[a-f0-9]{64}$/.test(value.sample.sha256)
    && typeof value.counts.tasks === "number"
    && typeof value.counts.same_hash_contexts === "number"
    && typeof value.counts.engine_results === "number"
    && Array.isArray(value.tasks)
    && Array.isArray(value.same_hash_contexts)
    && Array.isArray(value.truncated_sections)
    && analysisValid;
}

function isSystemOperations(value: unknown): value is SystemOperations {
  if (
    !isRecord(value)
    || !isRecord(value.tenant)
    || !isRecord(value.tenant.credential_counts)
    || !isRecord(value.agent_queue)
    || !isRecord(value.agent_versions)
    || !isRecord(value.work_queues)
    || !isRecord(value.storage_records)
    || !isRecord(value.errors)
    || !isRecord(value.freshness)
    || !isRecord(value.versions)
    || !isRecord(value.upgrade)
    || !isRecord(value.availability)
  ) return false;
  const numericValues = [
    value.tenant.credential_counts.total,
    value.tenant.credential_counts.active,
    value.tenant.credential_counts.expired,
    value.tenant.credential_counts.revoked,
    value.agent_queue.heartbeat_hosts_total,
    value.agent_queue.aggregated_hosts,
    value.agent_queue.queued_count,
    value.agent_queue.inflight_count,
    value.agent_queue.corrupt_count,
    value.agent_queue.stored_bytes,
    value.agent_queue.dropped_p1,
    value.agent_queue.dropped_p2,
    value.agent_queue.dropped_p3,
    value.agent_queue.protection_mode_hosts,
    value.agent_versions.bound_hosts_total,
    value.agent_versions.reported_hosts,
    value.agent_versions.unreported_hosts,
    value.agent_versions.distinct_versions,
    ...Object.values(value.work_queues),
    ...Object.values(value.storage_records),
    ...Object.values(value.errors),
    value.freshness.tracked_hosts,
    value.freshness.fresh,
    value.freshness.stale,
    value.freshness.degraded,
    value.freshness.unknown,
    value.freshness.lag_sample_count,
  ];
  const credentialShape = Array.isArray(value.credentials)
    && value.credentials.every((item) => (
      isRecord(item)
      && typeof item.credential_id === "string"
      && /^cred_[a-f0-9]{32}$/.test(item.credential_id)
      && typeof item.tenant_id === "string"
      && isStringArray(item.roles)
      && ["active", "expired", "revoked"].includes(String(item.lifecycle))
      && typeof item.created_at === "string"
      && (item.expires_at === null || typeof item.expires_at === "string")
      && (item.revoked_at === null || typeof item.revoked_at === "string")
    ));
  const versionGroupsValid = Array.isArray(value.agent_versions.version_groups)
    && value.agent_versions.version_groups.length <= 50
    && value.agent_versions.version_groups.every((item) => (
      isRecord(item)
      && typeof item.version === "string"
      && /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/.test(item.version)
      && typeof item.host_count === "number"
      && Number.isInteger(item.host_count)
      && item.host_count >= 1
      && typeof item.latest_reported_at === "string"
    ));
  const visibleVersionHosts = versionGroupsValid
    ? value.agent_versions.version_groups.reduce((total, item) => total + Number(item.host_count), 0)
    : -1;
  return value.schema_version === "0.1.0"
    && typeof value.tenant_id === "string"
    && typeof value.generated_at === "string"
    && value.tenant.tenant_id === value.tenant_id
    && typeof value.tenant.name === "string"
    && typeof value.tenant.created_at === "string"
    && credentialShape
    && versionGroupsValid
    && numericValues.every((item) => typeof item === "number" && Number.isFinite(item) && item >= 0)
    && value.agent_queue.dropped_p0 === 0
    && (value.agent_queue.latest_heartbeat_received_at === null || typeof value.agent_queue.latest_heartbeat_received_at === "string")
    && value.agent_versions.source === "self_reported_heartbeat"
    && value.agent_versions.binary_integrity_verified === false
    && value.agent_versions.bound_hosts_total === value.agent_versions.reported_hosts + value.agent_versions.unreported_hosts
    && value.agent_versions.distinct_versions >= value.agent_versions.version_groups.length
    && (value.agent_versions.distinct_versions === value.agent_versions.version_groups.length
      ? visibleVersionHosts === value.agent_versions.reported_hosts
      : visibleVersionHosts < value.agent_versions.reported_hosts)
    && (value.freshness.average_lag_seconds === null || typeof value.freshness.average_lag_seconds === "number")
    && (value.freshness.maximum_lag_seconds === null || typeof value.freshness.maximum_lag_seconds === "number")
    && (value.freshness.updated_at === null || typeof value.freshness.updated_at === "string")
    && typeof value.versions.application_version === "string"
    && (value.versions.database_migration_version === null || typeof value.versions.database_migration_version === "string")
    && value.versions.database_schema_compatibility === "not_evaluated"
    && value.upgrade.status === "not_implemented"
    && value.upgrade.agent_rollout_available === false
    && value.upgrade.automatic_rollback_available === false
    && value.upgrade.offline_package_inventory_available === false
    && value.upgrade.signed_artifact_inventory_available === false
    && value.upgrade.backup_restore_evidence_available === false
    && value.availability.message_broker_metrics_available === false
    && value.availability.backlog_age_metrics_available === false
    && value.availability.database_capacity_metrics_available === false
    && value.availability.object_storage_capacity_metrics_available === false
    && value.availability.dependency_health_probes_available === false
    && value.availability.deployment_inventory_available === false
    && value.availability.agent_version_inventory_available === true
    && value.availability.agent_version_binary_integrity_verification_available === false
    && value.availability.human_user_directory_available === false
    && isStringArray(value.truncated_sections);
}

function isModelOperations(value: unknown): value is ModelOperations {
  if (
    !isRecord(value)
    || !isRecord(value.counts)
    || !isRecord(value.review_quality)
  ) return false;
  return value.schema_version === "0.1.0"
    && typeof value.tenant_id === "string"
    && typeof value.generated_at === "string"
    && typeof value.counts.review_tasks === "number"
    && typeof value.counts.model_runs === "number"
    && typeof value.counts.aggregate_groups === "number"
    && isModelProviderConfiguration(value.provider_configuration)
    && isModelReviewMetrics(value.review_metrics)
    && value.review_quality.labeled_performance_available === false
    && value.review_quality.labeled_outcome_count === 0
    && value.review_quality.precision === null
    && value.review_quality.recall === null
    && value.review_quality.ground_truth_agreement === null
    && value.review_quality.false_positive_rate === null
    && Array.isArray(value.run_aggregates)
    && value.run_aggregates.every(isModelRunAggregate)
    && Array.isArray(value.recent_runs)
    && value.recent_runs.every(isModelRunSummary)
    && isStringArray(value.truncated_sections)
    && value.provider_health_probe_available === false
    && value.credential_validation_available === false
    && value.labeled_feedback_linkage_available === false;
}

function isModelProviderConfiguration(value: unknown): value is ModelProviderConfiguration {
  if (!isRecord(value)) return false;
  return typeof value.enabled === "boolean"
    && typeof value.provider === "string"
    && (value.model_name === null || typeof value.model_name === "string")
    && typeof value.api_key_state === "string"
    && typeof value.base_url_state === "string"
    && typeof value.configuration_complete === "boolean"
    && value.credential_validity === "not_tested"
    && value.health_status === "not_probed"
    && isStringArray(value.enabled_roles)
    && typeof value.supports_tools === "boolean"
    && typeof value.supports_json_schema === "boolean"
    && typeof value.adjudicator_enabled === "boolean"
    && [
      value.model_context_tokens,
      value.max_response_bytes,
      value.provider_timeout_seconds,
      value.provider_max_retries,
      value.circuit_failure_threshold,
      value.circuit_recovery_seconds,
      value.max_context_tokens,
      value.max_output_tokens,
      value.max_tool_calls,
      value.max_model_runs_per_incident,
      value.max_verifier_slots,
      value.max_reviews_per_minute,
      value.max_cost_usd_per_incident,
    ].every((item) => typeof item === "number" && Number.isFinite(item));
}

function isModelReviewMetrics(value: unknown): value is ModelReviewMetrics {
  if (!isRecord(value)) return false;
  return [
    value.task_count,
    value.skipped_count,
    value.completed_count,
    value.model_unavailable_count,
    value.invalid_output_count,
    value.budget_exceeded_count,
    value.require_human_status_count,
    value.verification_required_count,
    value.human_review_required_count,
    value.deterministic_only_count,
    value.unreviewed_count,
    value.basic_count,
    value.enhanced_count,
    value.high_count,
  ].every((item) => typeof item === "number" && Number.isFinite(item))
    && (value.last_review_at === null || typeof value.last_review_at === "string");
}

function isModelRunAggregate(value: unknown): value is ModelRunAggregate {
  if (!isRecord(value)) return false;
  return typeof value.provider === "string"
    && typeof value.model === "string"
    && typeof value.role === "string"
    && typeof value.last_run_at === "string"
    && [
      value.run_count,
      value.completed_count,
      value.failed_count,
      value.circuit_open_count,
      value.failure_rate,
      value.average_latency_ms,
      value.total_input_tokens,
      value.total_output_tokens,
      value.total_cost_usd,
      value.total_retries,
      value.total_tool_calls,
    ].every((item) => typeof item === "number" && Number.isFinite(item));
}

function isModelRunSummary(value: unknown): value is ModelRunSummary {
  return isRecord(value)
    && typeof value.run_id === "string"
    && typeof value.incident_id === "string"
    && typeof value.provider === "string"
    && typeof value.model === "string"
    && typeof value.role === "string"
    && typeof value.status === "string"
    && typeof value.latency_ms === "number"
    && typeof value.cost_usd === "number"
    && typeof value.created_at === "string";
}

function isRuleIntelligenceOperations(value: unknown): value is RuleIntelligenceOperations {
  if (!isRecord(value) || !isRecord(value.counts)) return false;
  return value.schema_version === "0.1.0"
    && typeof value.tenant_id === "string"
    && typeof value.generated_at === "string"
    && typeof value.counts.registered_rules === "number"
    && typeof value.counts.persisted_rule_versions === "number"
    && typeof value.counts.historical_rule_versions === "number"
    && typeof value.counts.intelligence_entries === "number"
    && typeof value.counts.governed_detections === "number"
    && typeof value.counts.legacy_detections === "number"
    && typeof value.counts.shadow_observations === "number"
    && Array.isArray(value.rules)
    && value.rules.every(isRuleGovernanceEntry)
    && Array.isArray(value.historical_rule_versions)
    && value.historical_rule_versions.every(isHistoricalRuleVersion)
    && Array.isArray(value.intelligence_cache)
    && value.intelligence_cache.every(isIntelligenceCacheEntry)
    && isStringArray(value.truncated_sections)
    && value.lifecycle_enforcement_available === true
    && value.managed_ioc_lifecycle_available === false;
}

function isRuleGovernanceEntry(value: unknown): value is RuleGovernanceEntry {
  if (!isRecord(value)) return false;
  return typeof value.rule_id === "string"
    && typeof value.version === "string"
    && typeof value.title === "string"
    && typeof value.owner === "string"
    && typeof value.lifecycle_stage === "string"
    && typeof value.runtime_state === "string"
    && typeof value.emission_scope === "string"
    && typeof value.runtime_emits_persisted_detections === "boolean"
    && typeof value.formal_release_gate_closed === "boolean"
    && (typeof value.lifecycle_rule_version === "string" || value.lifecycle_rule_version === null)
    && (typeof value.lifecycle_sequence === "number" || value.lifecycle_sequence === null)
    && (typeof value.manifest_sha256 === "string" || value.manifest_sha256 === null)
    && (typeof value.signing_key_id === "string" || value.signing_key_id === null)
    && (typeof value.catalog_digest_matches === "boolean" || value.catalog_digest_matches === null)
    && isStringArray(value.canary_host_ids)
    && typeof value.canary_host_count === "number"
    && typeof value.validation_evidence_count === "number"
    && (typeof value.manifest_issued_at === "string" || value.manifest_issued_at === null)
    && (typeof value.manifest_expires_at === "string" || value.manifest_expires_at === null)
    && (typeof value.manifest_applied_at === "string" || value.manifest_applied_at === null)
    && isStringArray(value.data_sources)
    && isStringArray(value.test_datasets)
    && isStringArray(value.expected_false_positives)
    && isStringArray(value.technique_ids)
    && isStringArray(value.suppression_conditions)
    && typeof value.rollback_plan === "string"
    && typeof value.runtime_note === "string"
    && isRuleTenantMetrics(value.tenant_metrics)
    && isRuleQualityMetrics(value.quality_metrics);
}

function isHistoricalRuleVersion(value: unknown): value is HistoricalRuleVersion {
  return isRecord(value)
    && typeof value.rule_id === "string"
    && typeof value.version === "string"
    && typeof value.registered_current_version === "boolean"
    && isRuleTenantMetrics(value.tenant_metrics);
}

function isIntelligenceCacheEntry(value: unknown): value is IntelligenceCacheEntry {
  return isRecord(value)
    && typeof value.cache_id === "string"
    && typeof value.kind === "string"
    && typeof value.indicator === "string"
    && typeof value.lookup_hash === "string"
    && typeof value.source === "string"
    && typeof value.cache_state === "string"
    && isStringArray(value.payload_fields)
    && typeof value.payload_field_count === "number"
    && typeof value.payload_fields_truncated === "boolean"
    && typeof value.fetched_at === "string"
    && (value.expires_at === null || typeof value.expires_at === "string");
}

function isRuleTenantMetrics(value: unknown): value is RuleTenantMetrics {
  if (!isRecord(value)) return false;
  return [
    value.hit_count,
    value.governed_hit_count,
    value.legacy_hit_count,
    value.open_hit_count,
    value.distinct_host_count,
    value.shadow_observation_count,
    value.shadow_distinct_host_count,
    value.feedback_total,
    value.true_positive_feedback,
    value.false_positive_feedback,
    value.benign_feedback,
    value.needs_review_feedback,
  ].every((item) => typeof item === "number")
    && (value.last_hit_at === null || typeof value.last_hit_at === "string")
    && (value.last_shadow_at === null || typeof value.last_shadow_at === "string");
}

function isRuleQualityMetrics(value: unknown): value is RuleQualityMetrics {
  if (!isRecord(value)) return false;
  return [
    value.precision,
    value.recall,
    value.false_positives_per_host_day,
    value.attack_attempt_success_error_rate,
    value.mttd_seconds,
    value.missing_source_sensitivity,
    value.performance_ms_per_1000_events,
  ].every((item) => item === null || typeof item === "number");
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function apiErrorMessage(value: unknown, status: number): string {
  if (!isRecord(value)) return `控制面返回 HTTP ${status}`;
  const envelope = value as ErrorEnvelope;
  return envelope.error?.details?.reason
    ?? envelope.error?.message
    ?? envelope.detail
    ?? `控制面返回 HTTP ${status}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
