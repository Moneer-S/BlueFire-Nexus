import type { AIGraphDraftResult, AIProposalDecisionResult, AIProposalReview, AIProposalReviewList, AutonomyLevel, CatalogResponse, ComparisonResponse, DetectionCloneRequest, DetectionComparisonResponse, DetectionLabHealth, DetectionResource, DetectionResourceEnvelope, DetectionTuneRequest, JobApprovalResult, JobRetryResult, ManagedResource, ManagedResourceList, ManagedResourceRoute, ManagedSetting, PreflightReport, RunnerLifecycleStatus, RunnerProbe, RunConfiguration, RunEventPage, RunJob, RunJobSubmission, RunRecord, RuntimeResourceResult, Scenario, ScenarioVersion } from "../types";
import { compareDemoRuns, demoCatalog, demoRuns, demoScenario } from "./demo";

const API_ROOT = "/api/v1";
const BROWSER_BOOTSTRAP_FRAGMENT_KEY = "bluefire-session";
const BROWSER_BOOTSTRAP_HEADER = "X-BlueFire-Browser-Bootstrap";
const BROWSER_CAPABILITY = /^[A-Za-z0-9_-]{64}$/;
const RUNNER_TRUST_MUTATION_TIMEOUT_MS = 135_000;
const SYNCHRONOUS_REPLAY_TIMEOUT_MS = 180_000;
export const DEMO_MODE = import.meta.env.VITE_DEMO_MODE === "true";
export const BROWSER_SESSION_RELAUNCH_MESSAGE = "This local browser session is unavailable. Close this tab and relaunch BlueFire with `bluefire ui`.";

export class ApiError extends Error {
  constructor(message: string, public readonly code = "request_failed", public readonly details?: unknown, public readonly status?: number) {
    super(message);
    this.name = "ApiError";
  }
}

function consumeBrowserBootstrapFragment(): string | null {
  const prefix = `#${BROWSER_BOOTSTRAP_FRAGMENT_KEY}=`;
  if (!window.location.hash.startsWith(prefix)) return null;

  const capability = window.location.hash.slice(prefix.length);
  // A fragment is browser-local and is never sent in an HTTP request. Remove it
  // before the first fetch, including malformed and failed bootstrap attempts.
  window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}`);
  if (!BROWSER_CAPABILITY.test(capability)) throw new Error("invalid browser bootstrap fragment");
  return capability;
}

export async function establishBrowserSession(): Promise<void> {
  if (DEMO_MODE) return;
  try {
    const capability = consumeBrowserBootstrapFragment();
    let response = await fetch(`${API_ROOT}/session`, {
      method: capability === null ? "GET" : "POST",
      credentials: "same-origin",
      cache: "no-store",
      referrerPolicy: "no-referrer",
      headers: capability === null
        ? { Accept: "application/json" }
        : { Accept: "application/json", [BROWSER_BOOTSTRAP_HEADER]: capability },
    });
    // Reopening the one-use launch URL in the same browser may replay the
    // fragment while the HttpOnly session is still valid. Reuse that session
    // without exposing it to JavaScript.
    if (!response.ok && capability !== null) {
      response = await fetch(`${API_ROOT}/session`, {
        method: "GET",
        credentials: "same-origin",
        cache: "no-store",
        referrerPolicy: "no-referrer",
        headers: { Accept: "application/json" },
      });
    }
    if (!response.ok) throw new Error("browser session refused");
  } catch {
    throw new ApiError(BROWSER_SESSION_RELAUNCH_MESSAGE, "browser_session_unavailable", undefined, 401);
  }
}

async function request<T>(path: string, options: RequestInit = {}, timeoutMs = 20_000): Promise<T> {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(`${API_ROOT}${path}`, {
      ...options,
      credentials: "same-origin",
      signal: controller.signal,
      headers: { Accept: "application/json", ...(options.body ? { "Content-Type": "application/json" } : {}), ...options.headers },
    });
    const payload = await response.json().catch(() => null) as any;
    if (!response.ok) throw new ApiError(payload?.error?.message ?? `Request failed (${response.status})`, payload?.error?.code, payload?.error?.details, response.status);
    return payload as T;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if (error instanceof DOMException && error.name === "AbortError") throw new ApiError("The local service did not respond before the timeout.", "request_timeout");
    throw new ApiError(error instanceof Error ? error.message : "The local service is unavailable.", "service_unavailable");
  } finally {
    window.clearTimeout(timeout);
  }
}

type CanonicalRunList = {
  schema_version?: string;
  runs: RunRecord[];
  unavailable_run_count: number;
};

function isFinalizedRunRecord(value: unknown): value is RunRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const run = value as Partial<RunRecord>;
  return typeof run.run_id === "string"
    && (run.mode === "simulate" || run.mode === "execute")
    && typeof run.status === "string"
    && typeof run.finalized_at === "string"
    && Array.isArray(run.steps);
}

function canonicalRunList(payload: unknown): CanonicalRunList {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) throw new ApiError("Run history response was invalid.", "invalid_run_history");
  const envelope = payload as { schema_version?: unknown; runs?: unknown };
  if (!Array.isArray(envelope.runs)) throw new ApiError("Run history response was invalid.", "invalid_run_history");
  const runs = envelope.runs.filter(isFinalizedRunRecord);
  return {
    ...(typeof envelope.schema_version === "string" ? { schema_version: envelope.schema_version } : {}),
    runs,
    unavailable_run_count: envelope.runs.length - runs.length,
  };
}

function graphDocument(scenario: Scenario) {
  return {
    scenario: { ...scenario, layout: undefined },
    layout: { schema_version: "bluefire.layout.v1", nodes: Object.entries(scenario.layout ?? {}).map(([id, position]) => ({ id, ...position })) },
  };
}

export function buildRunPayload(scenario: Scenario, config: RunConfiguration) {
  return {
    ...graphDocument(scenario), mode: config.mode, autonomy: config.autonomy,
    ai_provider_id: config.provider || null, runner_profile_id: config.profileId || null,
    target_scope: { scope_refs: config.scopeRefs },
    ...(config.mode === "execute" && Object.keys(config.actionImplementations).length ? { action_implementations: { ...config.actionImplementations } } : {}),
  };
}

const demoJobs = new Map<string, RunJob>();
const demoSettings = new Map<string, ManagedSetting>();
const demoScenarioVersions = new Map<string, ScenarioVersion>();
const demoResources = new Map<string, ManagedResource>();

export interface ReplayPayloadOptions {
  strategy: "exact" | "from_node" | "swap" | "parameters";
  fromStep?: string;
  swapStep?: string;
  swapBehavior?: string;
  profile?: string;
  autonomy?: AutonomyLevel | "preserve";
  provider?: string;
  defenseChange?: string;
  parameterOverrides?: Record<string, Record<string, unknown>>;
  targetScope?: string[];
  approval?: { confirmed: true; approved_by: string };
  actionImplementations?: Record<string, string>;
}

export function buildReplayPayload(options: ReplayPayloadOptions): Record<string, unknown> {
  const executionReview = {
    ...(options.targetScope ? { target_scope: { scope_refs: options.targetScope } } : {}),
    ...(options.approval ? { approval: options.approval } : {}),
    ...(options.strategy !== "exact" && options.actionImplementations && Object.keys(options.actionImplementations).length ? { action_implementations: options.actionImplementations } : {}),
  };
  if (options.strategy === "exact") return { exact: true, ...executionReview };
  return {
    exact: false,
    from_step_id: options.strategy === "from_node" ? options.fromStep || null : null,
    swap_step_id: options.strategy === "swap" ? options.swapStep || null : null,
    swap_behavior_id: options.strategy === "swap" ? options.swapBehavior || null : null,
    runner_profile_id: options.profile || null,
    autonomy: options.autonomy && options.autonomy !== "preserve" ? options.autonomy : null,
    ai_provider_id: options.provider || null,
    defense_change: options.defenseChange || null,
    parameter_overrides: options.strategy === "parameters" ? options.parameterOverrides ?? {} : null,
    ...executionReview,
  };
}

export const api = {
  async aiDraft(objective: string, providerId?: string | null, maxNodes = 8, maxEdges = 16): Promise<AIGraphDraftResult> {
    if (DEMO_MODE) {
      const count = Math.max(1, Math.min(maxNodes, demoScenario.steps.length)); const steps = structuredClone(demoScenario.steps.slice(0, count)); const ids = new Set(steps.map((step) => step.id)); const edges = structuredClone(demoScenario.edges.filter((edge) => ids.has(edge.from_step) && ids.has(edge.to_step)).slice(0, maxEdges));
      return { schema_version: "bluefire.ai-graph-draft-result.v1", draft_id: `ai-draft-demo-${Date.now()}`, saved: false, scenario: { ...structuredClone(demoScenario), title: objective.slice(0, 80), purpose: objective, start: steps[0]!.id, steps, edges, layout: undefined }, rationale: "Sanitized demo control-plane draft using registered behavior contracts.", assumptions: ["Demo mode did not call an external model.", "Operator review is required before saving or running."], audit: { schema_version: "bluefire.ai-graph-draft-audit.v1", unsaved: true, provider: { requested_provider_id: providerId ?? null, effective_provider_id: "deterministic-offline.v1", model: "deterministic-planner.v1", attempts: 1, used_fallback: true, fallback_reason: "demo_mode", usage: null }, bounds: { max_nodes: maxNodes, max_edges: maxEdges }, selected_behavior_ids: steps.map((step) => step.behavior_id) } };
    }
    return request("/ai/drafts", { method: "POST", body: JSON.stringify({ objective, ...(providerId ? { provider_id: providerId } : {}), max_nodes: maxNodes, max_edges: maxEdges }) });
  },
  async catalog(): Promise<CatalogResponse> { return DEMO_MODE ? structuredClone(demoCatalog) : request("/catalog"); },
  async scenarios(): Promise<{ scenarios: Scenario[] }> { return DEMO_MODE ? { scenarios: [structuredClone(demoScenario)] } : request("/scenarios"); },
  async settings(): Promise<{ schema_version: string; settings: ManagedSetting[] }> {
    return DEMO_MODE ? { schema_version: "bluefire.setting-list.v1", settings: structuredClone([...demoSettings.values()]) } : request("/settings");
  },
  async saveSetting<T>(key: string, value: T): Promise<{ schema_version: string; setting: ManagedSetting<T> }> {
    if (DEMO_MODE) {
      const setting = { key, value: structuredClone(value), updated_at: new Date().toISOString() };
      demoSettings.set(key, setting);
      return { schema_version: "bluefire.setting.v1", setting };
    }
    return request(`/settings/${encodeURIComponent(key)}`, { method: "POST", body: JSON.stringify({ value }) });
  },
  async scenarioVersions(): Promise<{ schema_version: string; scenarios: ScenarioVersion[] }> {
    return DEMO_MODE ? { schema_version: "bluefire.scenario-version-list.v1", scenarios: structuredClone([...demoScenarioVersions.values()]) } : request("/scenario-versions");
  },
  async saveScenarioVersion(scenario: Scenario): Promise<{ schema_version: string; scenario: ScenarioVersion }> {
    const { layout: _layout, ...canonicalScenario } = scenario;
    void _layout;
    if (DEMO_MODE) {
      const previous = demoScenarioVersions.get(scenario.id);
      const saved: ScenarioVersion = { scenario_id: scenario.id, title: scenario.title, version: (previous?.version ?? 0) + 1, digest: `demo-${scenario.id}-${Date.now()}`, created_at: previous?.created_at ?? new Date().toISOString(), updated_at: new Date().toISOString(), document: structuredClone(canonicalScenario) as Scenario };
      demoScenarioVersions.set(scenario.id, saved);
      return { schema_version: "bluefire.scenario-version.v1", scenario: structuredClone(saved) };
    }
    return request("/scenario-versions", { method: "POST", body: JSON.stringify({ scenario: canonicalScenario }) });
  },
  async resources<T extends Record<string, unknown> = Record<string, unknown>>(kind: ManagedResourceRoute): Promise<ManagedResourceList<T>> {
    if (DEMO_MODE) {
      const resources = structuredClone([...demoResources.values()].filter((item) => item.kind === kind)) as Array<ManagedResource<T>>;
      const inventory = kind === "plugins" ? { schema_version: "bluefire.plugin-inventory.v1", lifecycle: "declarative-manifest-only", manifest_count: resources.length, active_manifest_ids: resources.filter((item) => item.status === "active").map((item) => item.id), health: { state: "ready", message: "Sanitized demo metadata inventory." }, executable_loading: false as const, dynamic_actions: false as const, python_entry_points: false as const } : undefined;
      return { schema_version: "bluefire.resource-list.v1", kind, resources, inventory };
    }
    return request(`/resources/${kind}`);
  },
  async saveResource<T extends Record<string, unknown>>(kind: ManagedResourceRoute, id: string, document: T, status = "draft"): Promise<{ schema_version: string; resource: ManagedResource<T> }> {
    if (DEMO_MODE) {
      const key = `${kind}:${id}`; const previous = demoResources.get(key); const now = new Date().toISOString();
      const pluginStatus = kind === "plugins"
        ? previous?.status === "inactive" ? "inactive"
          : document.enabled !== true ? "disabled"
            : document.trust === "untrusted" ? "review_required" : "ready"
        : status;
      const resource: ManagedResource<T> = { kind, id, document: structuredClone(document), status: pluginStatus, digest: `demo-${id}-${Date.now()}`, created_at: previous?.created_at ?? now, updated_at: now };
      demoResources.set(key, resource);
      return { schema_version: "bluefire.resource.v1", resource: structuredClone(resource) };
    }
    const body = kind === "plugins" ? { document } : { document, status };
    return request(`/resources/${kind}/${encodeURIComponent(id)}`, { method: "POST", body: JSON.stringify(body) });
  },
  async activateResource(kind: "runner-profiles" | "model-providers" | "plugins", id: string): Promise<RuntimeResourceResult> {
    if (DEMO_MODE) return demoRuntimeResource(kind, id, "active");
    return request(`/resources/${kind}/${encodeURIComponent(id)}/activate`, { method: "POST", body: JSON.stringify({}) });
  },
  async deactivateResource(kind: "runner-profiles" | "model-providers" | "plugins", id: string): Promise<RuntimeResourceResult> {
    if (DEMO_MODE) return demoRuntimeResource(kind, id, "inactive");
    return request(`/resources/${kind}/${encodeURIComponent(id)}/deactivate`, { method: "POST", body: JSON.stringify({}) });
  },
  async probeRunnerProfile(id: string): Promise<RunnerProbe> {
    if (DEMO_MODE) return { schema_version: "bluefire.runner-probe.v1", profile_id: id, version: null, platform: null, actions: [], health: { state: "unavailable", message: "Demo mode never probes a local runner." } };
    return request(`/resources/runner-profiles/${encodeURIComponent(id)}/probe`, { method: "POST", body: JSON.stringify({}) });
  },
  async runnerStatus(): Promise<RunnerLifecycleStatus> {
    if (DEMO_MODE) return { schema_version: "bluefire.runner-lifecycle-status.v1", state: "unavailable", runner_id: "bluefire-rust-runner.v1", profile_id: null, loopback_only: true, enrollment: "absent", process: "absent", runner: null, health: null };
    return request("/runner");
  },
  async bootstrapRunner(profileId?: string, allowUpgrade = false): Promise<RunnerLifecycleStatus> {
    if (DEMO_MODE) throw new ApiError("Demo mode cannot bootstrap a local runner.", "demo_runner_lifecycle_refused", undefined, 409);
    return request("/runner/bootstrap", { method: "POST", body: JSON.stringify({ ...(profileId ? { profile_id: profileId } : {}), ...(allowUpgrade ? { allow_upgrade: true } : {}) }) }, 120_000);
  },
  async startRunner(profileId?: string): Promise<RunnerLifecycleStatus> {
    if (DEMO_MODE) throw new ApiError("Demo mode cannot start a local runner.", "demo_runner_lifecycle_refused", undefined, 409);
    return request("/runner/start", { method: "POST", body: JSON.stringify(profileId ? { profile_id: profileId } : {}) }, 45_000);
  },
  async stopRunner(profileId?: string): Promise<RunnerLifecycleStatus> {
    if (DEMO_MODE) throw new ApiError("Demo mode cannot stop a local runner.", "demo_runner_lifecycle_refused", undefined, 409);
    return request("/runner/stop", { method: "POST", body: JSON.stringify(profileId ? { profile_id: profileId } : {}) }, 45_000);
  },
  async revokeRunner(): Promise<RunnerLifecycleStatus> {
    if (DEMO_MODE) throw new ApiError("Demo mode cannot revoke local runner trust.", "demo_runner_lifecycle_refused", undefined, 409);
    return request("/runner/revoke", { method: "POST", body: JSON.stringify({}) }, RUNNER_TRUST_MUTATION_TIMEOUT_MS);
  },
  async removeRunner(confirmRunnerId: string): Promise<RunnerLifecycleStatus> {
    if (DEMO_MODE) throw new ApiError("Demo mode cannot remove local runner trust.", "demo_runner_lifecycle_refused", undefined, 409);
    return request("/runner/remove", { method: "POST", body: JSON.stringify({ confirm_runner_id: confirmRunnerId }) }, RUNNER_TRUST_MUTATION_TIMEOUT_MS);
  },
  async detectionHealth(): Promise<DetectionLabHealth> {
    if (DEMO_MODE) return { schema_version: "bluefire.detection-lab-health.v1", ready: true, persistence_ready: true, candidate_resources: [...demoResources.values()].filter((item) => item.kind === "detections").length, invalid_candidate_resources: 0, languages: { internal: { ready: true, authoritative: true, backend: "demo-structured-matcher", version: "fixture" }, sigma: { ready: false, authoritative: false, backend: "pySigma", version: null }, yara: { ready: false, authoritative: false, backend: "YARA-Python", version: null }, spl: { ready: true, authoritative: false, backend: "structural-only", version: "fixture", lifecycle_ceiling: "hypothesis" } }, limits: { source_bytes: 262144, fixture_bytes: 1048576, fixtures_per_action: 128, evidence_per_action: 128, notes_per_action: 128 } };
    return request("/detection-lab/health");
  },
  async detections(): Promise<{ schema_version: string; candidates: DetectionResource[] }> {
    if (DEMO_MODE) return { schema_version: "bluefire.detection-list.v1", candidates: structuredClone([...demoResources.values()].filter((item) => item.kind === "detections")) as DetectionResource[] };
    return request("/detections");
  },
  async detection(candidateId: string): Promise<DetectionResourceEnvelope> {
    if (DEMO_MODE) {
      const resource = demoResources.get(`detections:${candidateId}`) as DetectionResource | undefined;
      if (!resource) throw new ApiError("Demo detection candidate was not found.", "detection_not_found", undefined, 404);
      return { schema_version: "bluefire.detection-resource.v1", candidate: structuredClone(resource) };
    }
    return request(`/detections/${encodeURIComponent(candidateId)}`);
  },
  async upsertDetection(document: Record<string, unknown>): Promise<DetectionResourceEnvelope> {
    if (DEMO_MODE) {
      const identity = `detection-demo-${Date.now()}`; const now = new Date().toISOString();
      const resource = { kind: "detections", id: identity, status: "hypothesis", digest: `demo-${identity}`, created_at: now, updated_at: now, document: { ...structuredClone(document), candidate_id: identity, state: "hypothesis", lifecycle_history: [{ sequence: 1, action: "hypothesis_upsert", current_state: "hypothesis", outcome: "created", timestamp: now }] } } as DetectionResource;
      demoResources.set(`detections:${identity}`, resource);
      return { schema_version: "bluefire.detection-resource.v1", candidate: structuredClone(resource) };
    }
    return request("/detections", { method: "POST", body: JSON.stringify(document) });
  },
  async detectionAction(candidateId: string, action: "parse" | "exercise-fixtures" | "exercise-observed" | "evaluate-benign" | "reject", body: Record<string, unknown>): Promise<DetectionResourceEnvelope> {
    if (DEMO_MODE) throw new ApiError("Demo candidates do not run parser, fixture, evidence, or rejection lifecycle actions.", "demo_detection_action_refused", undefined, 409);
    return request(`/detections/${encodeURIComponent(candidateId)}/${action}`, { method: "POST", body: JSON.stringify(body) });
  },
  async cloneDetection(candidateId: string, body: DetectionCloneRequest): Promise<DetectionResourceEnvelope> {
    if (DEMO_MODE) throw new ApiError("Demo candidates cannot create durable immutable revisions.", "demo_detection_revision_refused", undefined, 409);
    return request(`/detections/${encodeURIComponent(candidateId)}/clone`, { method: "POST", body: JSON.stringify(body) });
  },
  async tuneDetection(candidateId: string, body: DetectionTuneRequest): Promise<DetectionResourceEnvelope> {
    if (DEMO_MODE) throw new ApiError("Demo candidates cannot create durable immutable revisions.", "demo_detection_revision_refused", undefined, 409);
    return request(`/detections/${encodeURIComponent(candidateId)}/tune`, { method: "POST", body: JSON.stringify(body) });
  },
  async compareDetections(baselineCandidateId: string, candidateId: string): Promise<DetectionComparisonResponse> {
    if (DEMO_MODE) throw new ApiError("Demo candidates cannot produce durable revision comparisons.", "demo_detection_comparison_refused", undefined, 409);
    return request(`/detections/${encodeURIComponent(baselineCandidateId)}/compare`, { method: "POST", body: JSON.stringify({ candidate_id: candidateId }) });
  },
  async runs(): Promise<CanonicalRunList> {
    if (DEMO_MODE) return { runs: structuredClone(demoRuns), unavailable_run_count: 0 };
    return canonicalRunList(await request<unknown>("/runs"));
  },
  async runDetail(runId: string): Promise<RunRecord> {
    if (DEMO_MODE) {
      const run = demoRuns.find((item) => item.run_id === runId);
      if (!run) throw new ApiError("Demo run was not found.", "run_not_found", undefined, 404);
      return structuredClone(run);
    }
    const run = await request<unknown>(`/runs/${encodeURIComponent(runId)}`);
    if (!isFinalizedRunRecord(run)) throw new ApiError("Run is not available as a finalized canonical record.", "run_not_finalized", undefined, 409);
    return run;
  },
  async validate(scenario: Scenario): Promise<{ valid: boolean; issues: unknown[] }> {
    if (DEMO_MODE) return { valid: scenario.steps.length > 0 && scenario.steps.some((step) => step.id === scenario.start), issues: [] };
    return request("/scenarios/validate", { method: "POST", body: JSON.stringify(graphDocument(scenario)) });
  },
  async preflight(scenario: Scenario, config: RunConfiguration): Promise<PreflightReport> {
    if (DEMO_MODE) {
      if (config.mode === "execute") return { ready: false, status: "demo_only", runner_profile: config.profileId || null, scope: { scope_refs: config.scopeRefs }, capabilities: [], safety_tier: config.safetyTier, approval: config.approved ? "previewed" : "required", cleanup: { policy: config.cleanupPolicy }, findings: ["Demo mode previews Execute configuration but never dispatches runner effects."] };
      return { ready: true, status: "ready", runner_profile: config.profileId || "sandbox-simulate.v1", scope: { scope_refs: config.scopeRefs }, capabilities: [...new Set(demoCatalog.behaviors.flatMap((item) => item.capabilities))], safety_tier: config.safetyTier, approval: "not_required", cleanup: { policy: config.cleanupPolicy }, findings: ["Seeded Simulate preflight. No external effects will occur."] };
    }
    return request("/runs/preflight", { method: "POST", body: JSON.stringify(buildRunPayload(scenario, config)) });
  },
  async submitRun(scenario: Scenario, config: RunConfiguration): Promise<RunJobSubmission> {
    if (DEMO_MODE) {
      if (config.mode === "execute") throw new ApiError("Demo mode cannot dispatch Execute actions.", "demo_execute_refused", undefined, 409);
      const run = structuredClone(demoRuns[0]!);
      const job: RunJob = { schema_version: "bluefire.job.v1", job_id: `job-demo-${Date.now()}`, kind: "scenario.run", state: "completed", request: {}, progress: { phase: "completed", run_id: run.run_id, completed_steps: run.steps.length }, result_ref: run.run_id, created_at: new Date().toISOString(), updated_at: new Date().toISOString(), is_demo: true };
      demoJobs.set(job.job_id, job);
      return { schema_version: "bluefire.run-job-submission.v1", job, approval_request: null, preflight: null };
    }
    return request("/runs", { method: "POST", body: JSON.stringify(buildRunPayload(scenario, config)) });
  },
  async job(jobId: string): Promise<RunJob> {
    if (DEMO_MODE) {
      const job = demoJobs.get(jobId);
      if (!job) throw new ApiError("Demo job was not found.", "job_not_found", undefined, 404);
      return structuredClone(job);
    }
    return request(`/jobs/${encodeURIComponent(jobId)}`);
  },
  async runEvents(runId: string, afterSequence = 0, limit = 250): Promise<RunEventPage> {
    if (DEMO_MODE) {
      const run = demoRuns.find((item) => item.run_id === runId);
      if (!run) throw new ApiError("Demo run was not found.", "run_not_found", undefined, 404);
      const events = (run.events ?? []).map((event, index) => ({ ...(event as Record<string, unknown>), sequence: Number((event as Record<string, unknown>).sequence ?? index + 1) })).filter((event) => event.sequence > afterSequence).slice(0, limit);
      return { schema_version: "bluefire.event-page.v1", run_id: runId, after_sequence: afterSequence, next_sequence: events.at(-1)?.sequence ?? afterSequence, has_more: false, items: events };
    }
    return request(`/runs/${encodeURIComponent(runId)}/events?after_sequence=${afterSequence}&limit=${limit}`);
  },
  async approveJob(jobId: string, approvedBy: string): Promise<JobApprovalResult> {
    if (DEMO_MODE) throw new ApiError("Demo mode cannot approve an Execute job.", "demo_execute_refused", undefined, 409);
    return request(`/jobs/${encodeURIComponent(jobId)}/approval`, { method: "POST", body: JSON.stringify({ approved_by: approvedBy }) });
  },
  async retryJob(jobId: string): Promise<JobRetryResult> {
    if (DEMO_MODE) throw new ApiError("Demo jobs are immutable fixtures and cannot be retried.", "demo_retry_refused", undefined, 409);
    return request(`/jobs/${encodeURIComponent(jobId)}/retry`, { method: "POST", body: JSON.stringify({}) });
  },
  async proposalReviews(jobId: string): Promise<AIProposalReviewList> {
    if (DEMO_MODE) return { schema_version: "bluefire.ai-proposal-review-list.v1", job_id: jobId, proposals: [] };
    return request(`/jobs/${encodeURIComponent(jobId)}/proposals`);
  },
  async proposalReview(jobId: string, proposalRecordId: string): Promise<AIProposalReview> {
    if (DEMO_MODE) throw new ApiError("Demo mode has no durable proposal review.", "proposal_not_found", undefined, 404);
    return request(`/jobs/${encodeURIComponent(jobId)}/proposals/${encodeURIComponent(proposalRecordId)}`);
  },
  async decideProposal(jobId: string, review: AIProposalReview, decidedBy: string, decision: "accept" | "reject"): Promise<AIProposalDecisionResult> {
    if (DEMO_MODE) throw new ApiError("Demo mode cannot decide a proposal.", "demo_proposal_refused", undefined, 409);
    return request(`/jobs/${encodeURIComponent(jobId)}/proposals/${encodeURIComponent(review.proposal_record_id)}/${decision}`, { method: "POST", body: JSON.stringify({ decided_by: decidedBy, state_digest: review.state_digest, plan_digest: review.plan_digest, proposal_digest: review.proposal_digest }) });
  },
  async controlJob(jobId: string, action: "pause" | "resume" | "cancel"): Promise<RunJob> {
    if (DEMO_MODE) {
      const job = demoJobs.get(jobId);
      if (!job) throw new ApiError("Demo job was not found.", "job_not_found", undefined, 404);
      return structuredClone(job);
    }
    return request(`/jobs/${encodeURIComponent(jobId)}/${action}`, { method: "POST", body: JSON.stringify({}) });
  },
  async replay(runId: string, body: Record<string, unknown>): Promise<RunRecord> {
    if (DEMO_MODE) return { ...structuredClone(demoRuns[0]!), run_id: `demo-replay-${Date.now()}`, replay: { source_run_id: runId, ...body }, is_demo: true };
    // The endpoint returns only after the seeded 120-second Execute budget,
    // bounded readiness/control work, persistence, and indexing complete.
    return request(`/runs/${encodeURIComponent(runId)}/replays`, { method: "POST", body: JSON.stringify(body) }, SYNCHRONOUS_REPLAY_TIMEOUT_MS);
  },
  async compare(runIds: string[]): Promise<ComparisonResponse> {
    if (DEMO_MODE) return compareDemoRuns(runIds);
    return request("/comparisons", { method: "POST", body: JSON.stringify({ run_ids: runIds }) });
  },
};

function demoRuntimeResource(kind: "runner-profiles" | "model-providers" | "plugins", id: string, status: "active" | "inactive"): RuntimeResourceResult {
  const key = `${kind}:${id}`;
  const current = demoResources.get(key);
  if (!current) throw new ApiError("Demo resource was not found.", "resource_not_found", undefined, 404);
  if (kind === "plugins" && status === "active") {
    const digest = (current.document.integrity as Record<string, unknown> | undefined)?.digest;
    if (current.document.enabled !== true || !["reviewed", "trusted"].includes(String(current.document.trust)) || typeof digest !== "string" || digest === "0".repeat(64)) {
      throw new ApiError("The demo manifest is not eligible for metadata-only activation.", "plugin_activation_refused", undefined, 409);
    }
  }
  const resource = { ...current, status, updated_at: new Date().toISOString() };
  demoResources.set(key, resource);
  const inventory = kind === "plugins" ? { schema_version: "bluefire.plugin-inventory.v1", lifecycle: "declarative-manifest-only", manifest_count: [...demoResources.values()].filter((item) => item.kind === "plugins").length, active_manifest_ids: [...demoResources.values()].filter((item) => item.kind === "plugins" && item.status === "active").map((item) => item.id), health: { state: "ready", message: "Sanitized demo metadata inventory." }, executable_loading: false as const, dynamic_actions: false as const, python_entry_points: false as const } : undefined;
  return { schema_version: kind === "plugins" ? "bluefire.plugin-activation.v1" : "bluefire.resource-activation.v1", resource, inventory, registration: kind === "plugins" ? "metadata_only" : undefined, executable_loading: kind === "plugins" ? false : undefined, dynamic_actions: kind === "plugins" ? false : undefined };
}
