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

export interface ActionPackageManifest {
  package_id: string;
  version: string;
  compatibility: {
    minimum_bluefire_version: string;
    maximum_bluefire_version_exclusive: string;
  };
  license: { spdx_id: string; notice: string };
  provenance: {
    publisher_id: string;
    source: string;
    reference: string;
    revision: string;
  };
  platforms: string[];
  capabilities: string[];
  safety_tiers: SafetyTier[];
  behavior_ids: string[];
  action_ids: string[];
}

export interface ActionPackageTrustSummary {
  state: "trusted" | "suspended" | "revoked" | string;
  source: string;
  publisher_id: string;
  key_id: string;
  key_fingerprint: string;
  trusted_by: string;
  trusted_at: string;
  event_sequence: number;
  updated_at: string;
  provenance: Record<string, unknown>;
}

export interface ActionPackageInstallation {
  schema_version: "bluefire.action-package-installation.v1" | string;
  package_id: string;
  version: string;
  status: "active" | "installed" | "superseded" | "removed" | string;
  package_digest: string;
  content_digest: string;
  publisher_id: string;
  key_id: string;
  signer_fingerprint: string;
  manifest: ActionPackageManifest;
  installed_by: string;
  installed_at: string;
  installed_head: boolean;
  active: boolean;
  active_version: string | null;
  active_generation: number | null;
  catalog_generation: number;
  catalog_digest: string;
  trust: ActionPackageTrustSummary;
  activation?: Record<string, unknown> | null;
  tombstone?: { package_digest: string; removed_by: string; reason: string; removed_at: string } | null;
}

export interface ActionPackagePublisherTrust {
  schema_version: "bluefire.action-package-publisher-trust.v1" | string;
  publisher_id: string;
  key_id: string;
  public_key_b64u: string;
  key_fingerprint: string;
  provenance: Record<string, unknown>;
  trust_state: "trusted" | "suspended" | "revoked" | string;
  trust_source: "local_operator" | string;
  trust_event_sequence: number;
  trust_updated_at: string;
  trusted_by: string;
  trusted_at: string;
}

export interface ActionPackageCatalog {
  schema_version: string;
  generation: number;
  catalog_digest: string;
  authority_digest?: string;
  built_in_catalog_digest?: string;
  packages: Array<Record<string, unknown>>;
  action_bindings?: Array<Record<string, unknown>>;
}

export interface ActionPackageActivationEvent {
  schema_version?: string;
  generation: number;
  event_type?: string;
  package_id?: string;
  version?: string;
  package_digest?: string;
  actor?: string;
  reason?: string;
  created_at?: string;
  catalog_digest?: string;
  [key: string]: unknown;
}

export interface ActionPackageInventory {
  schema_version: "bluefire.action-package-inventory.v1" | string;
  packages: ActionPackageInstallation[];
  publishers: ActionPackagePublisherTrust[];
  catalog: ActionPackageCatalog;
  activation_events: ActionPackageActivationEvent[];
  execution_boundary?: "signed-reviewed-opcodes-only" | string;
}

export interface ActionPackagePublisherEnrollment {
  publisher_id: string;
  key_id: string;
  public_key: string;
  provenance: Record<string, unknown>;
  trusted_by: string;
}

export interface ActionPackageCatalogIdentity {
  package_digest: string;
  expected_catalog_generation: number;
  expected_catalog_digest: string;
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

export interface RunnerLifecycleStatus {
  schema_version: "bluefire.runner-lifecycle-status.v1" | string;
  state: "unbootstrapped" | "stopped" | "ready" | "stale" | "unavailable" | string;
  runner_id: string;
  profile_id: string | null;
  loopback_only: true;
  enrollment: "absent" | "active" | "revoked" | "unavailable" | string;
  process: "absent" | "authenticated" | "stale" | "unavailable" | string;
  runner: {
    source?: string;
    product_version?: string;
    runner_version?: string;
    platform?: string;
    architecture?: string;
    managed_binary?: boolean;
    managed_sandbox?: boolean;
    inventory_schema?: string;
    action_sdk_version?: string;
    receipt_protocol?: string;
  } | null;
  health: {
    transport?: string;
    tls?: string;
    runner_binary_digest?: string;
    inventory_digest?: string;
    accepting_execute?: boolean;
  } | null;
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

export interface PublicBaselineReference {
  schema_version: "bluefire.public-baseline.v1";
  research_source_id: string;
  source_digest: string;
  pin: string;
  version: string;
  license: string;
  license_review: "reviewed" | "conditional" | "prohibited";
  relationship: "imported" | "adapted" | "inspired" | "comparative";
  use_classification?: "reference_only" | "metadata_import" | "clean_reimplementation" | "external_adapter" | "compatible_code_adaptation" | "incompatible_or_restricted";
  use: "comparison";
}

export interface DetectionLifecycleRecord {
  sequence?: number;
  action?: string;
  from_state?: string | null;
  to_state?: string;
  outcome?: string;
  input_digest?: string;
  recorded_at?: string;
  run_id?: string | null;
  /** Legacy compatibility for v1 or run-linked candidate rows. */
  prior_state?: string;
  current_state?: string;
  timestamp?: string;
}

export interface DetectionCandidate {
  schema_version?: "bluefire.detection-candidate.v1" | "bluefire.detection-candidate.v2" | string;
  id?: string;
  candidate_id?: string;
  revision?: number;
  revision_root_id?: string;
  parent_candidate_id?: string | null;
  revision_kind?: "origin" | "clone" | "tune" | string;
  definition_digest?: string;
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
  public_baselines?: PublicBaselineReference[];
  malicious_fixture_ids?: string[];
  malicious_fixtures?: Array<Record<string, unknown>>;
  benign_fixture_ids?: string[];
  benign_fixtures?: Array<Record<string, unknown>>;
  observed_evidence_ids?: string[];
  known_misses?: string[];
  false_positive_notes?: string[];
  tuning_decisions?: string[];
  match_count?: number;
  benign_match_count?: number;
  rejection_reason?: string | null;
  predicted_fields?: string[];
  observed_fields?: string[];
  field_drift?: Record<string, string[]>;
  lifecycle_history?: DetectionLifecycleRecord[];
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

export interface DetectionCloneRequest {
  reason: string;
  title?: string;
  provenance?: Record<string, unknown>;
  known_misses?: string[];
  public_baselines?: PublicBaselineReference[];
  predicted_fields?: string[];
}

export interface DetectionTuneRequest extends DetectionCloneRequest {
  selection: Record<string, unknown>;
  logsource?: Record<string, unknown>;
}

export interface DetectionSetDelta {
  added: string[];
  removed: string[];
  unchanged: string[];
}

export interface DetectionComparisonIdentity {
  candidate_id: string;
  revision: number;
  revision_kind: string;
  state: string;
  definition_digest: string;
}

export interface DetectionComparisonResponse {
  schema_version: "bluefire.detection-comparison.v1" | string;
  comparison_id: string;
  revision_root_id: string;
  baseline: DetectionComparisonIdentity;
  candidate: DetectionComparisonIdentity;
  deltas: {
    source: {
      changed: boolean;
      provenance: { baseline_digest: string; candidate_digest: string; changed: boolean };
      public_baselines: {
        changed: boolean;
        added: PublicBaselineReference[];
        removed: PublicBaselineReference[];
        modified: Array<{ research_source_id: string; baseline: PublicBaselineReference; candidate: PublicBaselineReference }>;
      };
    };
    rule: {
      changed: boolean;
      changed_fields: string[];
      baseline: { target_language: string; logsource_digest: string; selection_digest: string; rule_source_digest: string | null };
      candidate: { target_language: string; logsource_digest: string; selection_digest: string; rule_source_digest: string | null };
    };
    fields: {
      changed: boolean;
      predicted: DetectionSetDelta;
      observed: DetectionSetDelta;
      drift: { changed: boolean; baseline: Record<string, string[]>; candidate: Record<string, string[]> };
    };
    lifecycle: {
      changed: boolean;
      baseline_state: string;
      candidate_state: string;
      baseline_actions: string[];
      candidate_actions: string[];
      baseline_history_digest: string;
      candidate_history_digest: string;
    };
    fixtures: {
      changed: boolean;
      added_fixture_ids: string[];
      removed_fixture_ids: string[];
      changed_fixture_ids: string[];
      fixture_ids: DetectionSetDelta;
      baseline_match_count: number;
      candidate_match_count: number;
    };
    observed: {
      changed: boolean;
      evidence_ids: DetectionSetDelta;
      run_ids: DetectionSetDelta;
    };
    benign: {
      changed: boolean;
      added_fixture_ids: string[];
      removed_fixture_ids: string[];
      changed_fixture_ids: string[];
      fixture_ids: DetectionSetDelta;
      notes: DetectionSetDelta;
      baseline_match_count: number;
      candidate_match_count: number;
    };
  };
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
  outcome_counts?: Record<string, number>;
  first_blocked_step?: string | null;
  objective_reached?: boolean;
  evidence_provenance?: Record<string, number>;
  evidence_details?: {
    producer_counts?: Record<string, number>;
    observed_artifacts?: Array<Record<string, unknown>>;
    evidence_gaps?: Array<Record<string, unknown>>;
  };
  detection_states?: Record<string, number>;
  detection_matches?: number;
  benign_matches?: number;
  telemetry?: string[];
  controls?: string[];
  cleanup_success?: boolean | null;
  policy_states?: Record<string, number>;
  autonomy?: AutonomyLevel | string;
  ai_provider_id?: string | null;
  ai_proposal_count?: number;
  ai_applications?: Record<string, number>;
  remaining_budgets?: Record<string, number>;
  duration_ms?: number | null;
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
  evidence_detail_delta?: {
    observed_artifacts_added?: Array<Record<string, unknown>>;
    observed_artifacts_removed?: Array<Record<string, unknown>>;
    observed_artifacts_changed?: Array<Record<string, unknown>>;
    evidence_gaps_added?: Array<Record<string, unknown>>;
    evidence_gaps_removed?: Array<Record<string, unknown>>;
    producer_delta?: Record<string, number>;
  };
  detection_delta?: Record<string, number>;
  detection_match_delta?: number;
  benign_match_delta?: number;
  outcome_delta?: Record<string, number>;
  telemetry_added?: string[];
  telemetry_removed?: string[];
  controls_added?: string[];
  controls_removed?: string[];
  autonomy_changed?: boolean;
  ai_provider_changed?: boolean;
  ai_proposal_delta?: number;
  duration_delta_ms?: number | null;
  assessment?: "improved" | "regressed" | "mixed" | "no_material_change" | string;
  signals?: string[];
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
  collectors?: string[];
  collector_binding?: Record<string, unknown>;
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
