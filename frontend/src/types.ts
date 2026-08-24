export type RunMode = "simulate" | "execute";
export type AutonomyLevel = "off" | "assist" | "auto";
export type SafetyTier = "safe" | "controlled" | "restricted";
export type Outcome = "success" | "partial" | "blocked" | "failed";

export interface ContractPort {
  name: string;
  type: string;
  required?: boolean;
  multiple?: boolean;
  description?: string;
}

export interface ParameterSpec {
  name: string;
  type: "string" | "integer" | "number" | "boolean" | "string_list";
  required?: boolean;
  default?: unknown;
  minimum?: number;
  maximum?: number;
  enum?: Array<string | number>;
  description?: string;
}

export interface Provenance {
  source?: string;
  reference?: string;
  license?: string;
  derived?: boolean;
  notes?: string;
}

export interface Behavior {
  id: string;
  title: string;
  purpose: string;
  execution_state: string;
  safety_tier: SafetyTier;
  platforms: string[];
  techniques: string[];
  capabilities: string[];
  inputs: ContractPort[];
  outputs: ContractPort[];
  parameters: ParameterSpec[];
  simulation_id?: string | null;
  action_ids: string[];
  telemetry: string[];
  detection_hints: string[];
  compatible_behaviors?: string[];
  provenance?: Provenance;
  limitations: string[];
}

export interface ActionDefinition {
  id: string;
  title: string;
  purpose: string;
  safety_tier: SafetyTier;
  capabilities: string[];
  platforms: string[];
  inputs: ContractPort[];
  outputs: ContractPort[];
  parameters: ParameterSpec[];
  mutates?: boolean;
  cleanup_action_id?: string | null;
  provenance?: Provenance;
}

export interface RunnerProfile {
  id: string;
  mode: RunMode;
  environment_type: string;
  platforms: string[];
  scope: string[];
  network_allowlist: string[];
  capabilities: string[];
  safety_tiers: SafetyTier[];
  approval_required: boolean;
  enabled_actions: string[];
  blocked_actions: string[];
  cleanup_policy: string;
  budgets: Record<string, number>;
  secrets: string[] | Record<string, { env: string }>;
  runner_binary?: string | { env: string };
  sandbox_root?: string | { env: string };
}

export interface CatalogResponse {
  schema_version: string;
  modes: RunMode[];
  ai: {
    enabled: boolean;
    independent_of_mode: boolean;
    authority: string;
    autonomy?: AutonomyLevel;
    autonomy_levels?: AutonomyLevel[];
    active_provider?: string;
    fallback_provider?: string;
    providers?: Array<{
      provider_id: string;
      kind: string;
      model: string;
      timeout_seconds?: number;
      max_retries?: number;
      max_output_tokens?: number;
      credential_reference?: string | null;
      health?: { state?: string; message?: string; credential_available?: boolean; fallback_provider_id?: string | null };
      proposal_application?: string;
    }>;
    /** Legacy compatibility for older catalog payloads. */
    levels?: AutonomyLevel[];
    provider_health?: string;
  };
  behaviors: Behavior[];
  actions: ActionDefinition[];
  runner_profiles: RunnerProfile[];
}

export interface ArtifactBinding {
  from_step: string;
  artifact: string;
}

export interface ScenarioStep {
  id: string;
  behavior_id: string;
  parameters: Record<string, unknown>;
  inputs: Record<string, ArtifactBinding>;
  alternates: string[];
}

export interface ScenarioEdge {
  from_step: string;
  outcome: Outcome;
  to_step: string;
}

export interface Scenario {
  schema_version: "bluefire.scenario.v1" | string;
  id: string;
  title: string;
  purpose: string;
  start: string;
  steps: ScenarioStep[];
  edges: ScenarioEdge[];
  provenance: Provenance;
  limitations: string[];
  layout?: Record<string, { x: number; y: number }>;
}

export interface ManagedSetting<T = unknown> {
  key: string;
  value: T;
  updated_at: string;
}

export interface ScenarioVersion {
  scenario_id: string;
  title: string;
  version: number;
  digest: string;
  created_at: string;
  updated_at?: string;
  document: Scenario;
}

export type ManagedResourceRoute = "actions" | "collectors" | "comparisons" | "detections" | "detection-backends" | "model-providers" | "plugins" | "research-sources" | "runners" | "runner-profiles";

export interface ManagedResource<T extends Record<string, unknown> = Record<string, unknown>> {
  kind: string;
  id: string;
  status: string;
  digest: string;
  created_at: string;
  updated_at: string;
  document: T;
}

export interface PluginInventory {
  schema_version: "bluefire.plugin-inventory.v1" | string;
  lifecycle: string;
  manifest_count: number;
  active_manifest_ids: string[];
  health: { state: string; message: string };
  executable_loading: false;
  dynamic_actions: false;
  python_entry_points: false;
}

export interface ManagedResourceList<T extends Record<string, unknown> = Record<string, unknown>> {
  schema_version: string;
  kind: string;
  resources: Array<ManagedResource<T>>;
  inventory?: PluginInventory;
}

export interface RuntimeResourceResult<T extends Record<string, unknown> = Record<string, unknown>> {
  schema_version: string;
  resource: ManagedResource<T>;
  health?: { state?: string; message?: string };
  inventory?: PluginInventory;
  registration?: "metadata_only" | string;
  executable_loading?: false;
  dynamic_actions?: false;
}

export interface RunnerProbe {
  schema_version: "bluefire.runner-probe.v1" | string;
  profile_id: string;
  version: string | null;
  platform: "linux" | "macos" | "windows" | null;
  actions: Array<{ action_id: string; version?: string; readiness?: string }>;
  health: { state: "ready" | "degraded" | "unavailable" | string; message: string; missing_actions?: string[] };
}

export interface EvidenceRecord {
  schema_version?: string;
  evidence_id?: string;
  id?: string;
  run_id?: string;
  step_id?: string;
  behavior_id?: string;
  action_id?: string | null;
  provenance: "synthetic" | "executed" | "observed" | "control_blocked" | "counterfactual" | "unknown" | string;
  producer?: string;
  runner_profile_id?: string | null;
  environment?: Record<string, unknown>;
  timestamp?: string;
  parent_evidence_ids?: string[];
  content?: Record<string, unknown>;
  content_hash?: string;
  record_hash?: string;
  confidence?: number;
  limitations?: string[];
  target_scope_ref?: string;
  // Legacy UI/demo fields remain optional for older bundles.
  kind?: string;
  summary?: string;
  fields?: Record<string, unknown>;
}

export interface DetectionCandidate {
  id?: string;
  candidate_id?: string;
  title?: string;
  behavior_id?: string;
  state: "hypothesis" | "parsed" | "fixture_exercised" | "observed_exercised" | "benign_evaluated" | "rejected" | string;
  language?: string;
  summary?: string;
  evidence_ids?: string[];
  target_language?: "internal" | "sigma" | "yara" | "yara-l" | "spl" | string;
  logsource?: Record<string, unknown>;
  selection?: Record<string, unknown>;
  provenance?: Record<string, unknown>;
  validation?: Record<string, unknown>;
  rule_source?: string | null;
  parser_backend?: { name?: string; version?: string };
  malicious_fixtures?: Array<Record<string, unknown>>;
  benign_fixtures?: Array<Record<string, unknown>>;
  observed_evidence_ids?: string[];
  predicted_fields?: string[];
  observed_fields?: string[];
  field_drift?: Record<string, string[]>;
  lifecycle_history?: Array<{ sequence?: number; action?: string; prior_state?: string; current_state?: string; outcome?: string; timestamp?: string; run_id?: string | null }>;
}

export interface DetectionLabHealth {
  schema_version: "bluefire.detection-lab-health.v1" | string;
  ready: boolean;
  persistence_ready: boolean;
  candidate_resources: number;
  invalid_candidate_resources: number;
  languages: Record<string, { ready: boolean; authoritative: boolean; backend: string; version?: string | null; lifecycle_ceiling?: string }>;
  limits: { source_bytes: number; fixture_bytes: number; fixtures_per_action: number; evidence_per_action: number; notes_per_action: number };
}

export type DetectionResource = ManagedResource<DetectionCandidate & Record<string, unknown>>;

export interface DetectionResourceEnvelope {
  schema_version: "bluefire.detection-resource.v1" | string;
  candidate: DetectionResource;
}

export interface RunStep {
  step_id: string;
  behavior_id?: string;
  action_id?: string | null;
  simulation_id?: string | null;
  status: string;
  execution_disposition?: string;
  planner_decision_id?: string;
  artifacts?: unknown[];
  evidence_ids?: string[];
  telemetry?: string[];
}

export interface RunRecord {
  schema_version?: string;
  run_id: string;
  scenario_id?: string;
  mode: RunMode;
  status: string;
  created_at?: string;
  finalized_at?: string;
  objective?: string;
  objective_reached?: boolean;
  runner_profile_id?: string | null;
  ai_enabled?: boolean;
  autonomy?: AutonomyLevel;
  autonomy_level?: AutonomyLevel;
  ai_provider?: string | Record<string, unknown>;
  steps: RunStep[];
  evidence?: { records: EvidenceRecord[]; schema_version?: string };
  detections?: { candidates: DetectionCandidate[]; schema_version?: string };
  policy?: Record<string, unknown>;
  plan?: Record<string, unknown>;
  profile?: Record<string, unknown>;
  cleanup?: Record<string, unknown> | boolean;
  planner_decisions?: unknown[];
  approval_pause?: Record<string, unknown> | null;
  events?: unknown[];
  manifest?: Record<string, unknown>;
  limitations?: string[];
  replay?: Record<string, unknown> | null;
  scenario?: Scenario;
  target_scope?: { scope_refs?: string[] };
  is_demo?: boolean;
}

export type JobState = "queued" | "planning" | "awaiting_approval" | "running" | "paused" | "cancelling" | "cancelled" | "completed" | "failed" | "interrupted";

export interface RunJob {
  schema_version: "bluefire.job.v1" | string;
  job_id: string;
  kind: string;
  state: JobState;
  request?: Record<string, unknown>;
  progress: Record<string, unknown>;
  result_ref?: string | null;
  error?: { code?: string; message?: string; exception_type?: string } | null;
  created_at?: string;
  updated_at?: string;
  is_demo?: boolean;
  approval_request?: Record<string, unknown> | null;
}

export interface RunJobSubmission {
  schema_version: "bluefire.run-job-submission.v1" | string;
  job: RunJob;
  approval_request?: Record<string, unknown> | null;
  preflight?: PreflightReport | null;
}

export interface JobApprovalResult {
  schema_version: "bluefire.job-approval.v1" | string;
  job: RunJob;
  approval_request?: Record<string, unknown> | null;
}

export interface JobRetryResult extends RunJobSubmission {
  schema_version: "bluefire.job-retry.v1" | string;
  retry_of_job_id: string;
  source_job: RunJob;
}

export interface AIProposal {
  schema_version?: string;
  proposal_id: string;
  proposal_type: "no_change" | "request_approval" | "stop" | "select_registered" | "select_next_node" | "change_parameters" | "select_registered_action" | "retry_registered" | string;
  selected_step_id: string | null;
  selected_behavior_id: string | null;
  selected_action_id: string | null;
  selected_edge?: { from_step: string; outcome: string; to_step: string } | null;
  parameter_changes?: Array<{ name: string; value: unknown }>;
  rationale?: string;
  alternatives?: unknown[];
  confidence?: number;
  requires_operator_review?: boolean;
}

export interface AIProposalReview {
  schema_version: "bluefire.ai-proposal-review.v1" | string;
  proposal_record_id: string;
  job_id: string;
  source_run_id: string;
  source_proposal_id: string;
  state_digest: string;
  plan_digest: string;
  proposal_digest: string;
  status: "pending" | "accepted" | "rejected" | string;
  record: {
    application_status?: string;
    allowed_step_ids?: string[];
    allowed_behavior_ids?: string[];
    allowed_action_ids?: string[];
    allowed_edges?: Array<{ from_step: string; outcome: string; to_step: string }>;
    allowed_parameter_schemas?: Record<string, Record<string, unknown>>;
    retryable_step_ids?: string[];
    proposal?: AIProposal;
  };
  resolution?: Record<string, unknown> | null;
  created_at: string;
  decided_at?: string | null;
  decided_by?: string | null;
}

export interface AIProposalReviewList {
  schema_version: "bluefire.ai-proposal-review-list.v1" | string;
  job_id: string;
  proposals: AIProposalReview[];
}

export interface AIProposalDecisionResult {
  schema_version: "bluefire.ai-proposal-decision.v1" | string;
  job: RunJob;
  proposal: AIProposalReview;
  approval_request?: Record<string, unknown> | null;
}

export interface AIGraphDraftResult {
  schema_version: "bluefire.ai-graph-draft-result.v1" | string;
  draft_id: string;
  saved: false;
  scenario: Scenario;
  rationale: string;
  assumptions: string[];
  audit: {
    schema_version?: string;
    unsaved: true;
    request_id?: string;
    objective_digest?: string;
    provider?: {
      requested_provider_id?: string | null;
      effective_provider_id?: string;
      model?: string;
      response_id?: string | null;
      attempts?: number;
      used_fallback?: boolean;
      fallback_reason?: string | null;
      usage?: Record<string, unknown> | null;
    };
    bounds?: Record<string, unknown>;
    allowlist?: Record<string, unknown>;
    selected_behavior_ids?: string[];
    parameter_fields?: Record<string, unknown>;
    normalization?: Record<string, unknown>;
    validation?: Record<string, unknown>;
  };
}

export interface RunEventPage {
  schema_version: "bluefire.event-page.v1" | string;
  run_id: string;
  after_sequence: number;
  next_sequence: number;
  has_more: boolean;
  items: Array<Record<string, unknown> & { sequence: number }>;
}

export interface ComparisonSummary {
  run_id: string;
  mode?: RunMode;
  profile_id?: string;
  path: string[];
  outcomes: Record<string, string>;
  first_blocked_step?: string | null;
  objective_reached?: boolean;
  evidence_provenance?: Record<string, number>;
  detection_states?: Record<string, number>;
  telemetry?: string[];
  controls?: string[];
  cleanup_success?: boolean | null;
  counterfactual_steps?: string[];
}

export interface ComparisonDelta {
  from_run_id: string;
  to_run_id: string;
  first_path_divergence?: number | null;
  first_blocked_changed?: boolean;
  objective_changed?: boolean;
  cleanup_changed?: boolean;
  evidence_delta?: Record<string, number>;
  detection_delta?: Record<string, number>;
  telemetry_added?: string[];
  telemetry_removed?: string[];
  controls_added?: string[];
  controls_removed?: string[];
}

export interface ComparisonResponse {
  comparison_id: string;
  baseline_run_id: string;
  run_ids: string[];
  summaries: ComparisonSummary[];
  deltas: ComparisonDelta[];
}

export interface RunConfiguration {
  mode: RunMode;
  autonomy: AutonomyLevel;
  provider: string;
  model: string;
  endpoint: string;
  profileId: string;
  runnerIds: string[];
  scopeRefs: string[];
  safetyTier: SafetyTier;
  approvalPolicy: "profile" | "every_restricted" | "every_action";
  approved: boolean;
  approvedBy: string;
  maxSeconds: number;
  maxSteps: number;
  maxBytes: number;
  collectors: string[];
  detectionBackends: string[];
  cleanupPolicy: "always" | "on_success" | "manual";
  counterfactual: "disabled" | "after_block" | "always_preview";
  fixtureMode: boolean;
  actionImplementations: Record<string, string>;
}

export interface PreflightReport {
  schema_version?: string;
  ready: boolean;
  status: string;
  runner_profile?: string | null;
  autonomy?: AutonomyLevel;
  scope?: unknown;
  capabilities?: string[];
  safety_tier?: string;
  approval?: string;
  cleanup?: unknown;
  findings?: Array<string | { message?: string; code?: string }>;
  plan?: Record<string, unknown>;
  approval_binding?: ApprovalBinding | null;
  approval_envelope?: ApprovalEnvelope | null;
}

export interface ApprovalBinding {
  state_digest: string;
  plan_digest: string;
  target_scope_digest: string;
  profile_id: string;
  maximum_tier: string;
}

export interface ApprovalEnvelopeAction {
  action_id: string;
  contract_digest: string;
  contract: Record<string, unknown>;
}

export interface ApprovalEnvelopeOption {
  behavior_id: string;
  is_primary: boolean;
  contract_digest: string;
  contract: Record<string, unknown>;
  resolved_parameters: Record<string, unknown>;
  actions: ApprovalEnvelopeAction[];
}

export interface ApprovalEnvelope {
  schema_version: string;
  scenario_id: string;
  envelope_digest: string;
  steps: Array<{ step_id: string; options: ApprovalEnvelopeOption[] }>;
}
