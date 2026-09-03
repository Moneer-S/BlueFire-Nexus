import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "../src/App";
import { demoCatalog, demoRuns, demoScenario } from "../src/lib/demo";
import { ProductProvider, UI_PREFERENCE_SCHEMA_VERSION } from "../src/state/ProductContext";
import type { ComparisonResponse, DetectionComparisonResponse, DetectionResource, PreflightReport, PublicBaselineReference, RunJob } from "../src/types";

const envelopeBehavior = demoCatalog.behaviors.find((item) => item.execution_state === "action")!;
const envelopeAction = demoCatalog.actions.find((item) => item.id === envelopeBehavior.action_ids[0])!;
const executePreflight: PreflightReport = {
  ready: false,
  status: "approval_required",
  runner_profile: "sandbox-execute.v1",
  autonomy: "off",
  scope: { scope_refs: ["sandbox.workspace"] },
  safety_tier: "controlled",
  approval: "required",
  cleanup: { policy: "always", action_id: "sandbox.cleanup.v1" },
  findings: ["Explicit operator approval is required."],
  plan: { mode: "execute", runner_profile_id: "sandbox-execute.v1", steps: [{ step_id: "place_fixture", behavior_id: envelopeBehavior.id, action_id: envelopeAction.id, parameters: {}, inputs: {}, expected_outputs: ["fixture"], required_capabilities: envelopeAction.capabilities }], edges: [] },
  approval_binding: { state_digest: "state-digest-test", plan_digest: "plan-digest-test", target_scope_digest: "scope-digest-test", profile_id: "sandbox-execute.v1", maximum_tier: "controlled" },
  approval_envelope: { schema_version: "bluefire.approval-envelope.v1", scenario_id: demoScenario.id, envelope_digest: "envelope-digest-test", steps: [{ step_id: "place_fixture", options: [{ behavior_id: envelopeBehavior.id, is_primary: true, contract_digest: "behavior-digest-test", contract: envelopeBehavior as unknown as Record<string, unknown>, resolved_parameters: {}, actions: [{ action_id: envelopeAction.id, contract_digest: "action-digest-test", contract: envelopeAction as unknown as Record<string, unknown> }] }] }] },
};
const executeApprovalRequest = { approval_id: "approval-test", status: "pending", expires_at: "2030-01-01T00:00:00Z", ...executePreflight.approval_binding! } as const;
const executeJob = { schema_version: "bluefire.job.v1", job_id: "job-0123456789abcdef0123456789abcdef", kind: "scenario.run", state: "awaiting_approval", request: { approval_request_id: executeApprovalRequest.approval_id }, progress: { phase: "awaiting_approval", approval_request_id: executeApprovalRequest.approval_id }, result_ref: null, error: null } as const;
const activeJobStorageKey = "bluefire.local.active-job-id.v1";
const proposalJob = { ...executeJob, job_id: "job-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", progress: { phase: "awaiting_approval", approval_kind: "ai_proposal", proposal_record_id: "proposal-review-0123456789abcdef0123456789abcdef" } } as const;
let activeJobInventory: RunJob[] = [];
const proposalReview = { schema_version: "bluefire.ai-proposal-review.v1", proposal_record_id: "proposal-review-0123456789abcdef0123456789abcdef", job_id: proposalJob.job_id, source_run_id: "run-source", source_proposal_id: "proposal-source", state_digest: "sha256:" + "1".repeat(64), plan_digest: "sha256:" + "2".repeat(64), proposal_digest: "sha256:" + "3".repeat(64), status: "pending", record: { allowed_step_ids: ["discover"], allowed_behavior_ids: ["endpoint.discovery.system.v1"], proposal: { proposal_id: "proposal-source", proposal_type: "select_registered", selected_step_id: "discover", selected_behavior_id: "endpoint.discovery.system.v1", selected_action_id: null, rationale: "Registered compatible alternate" } }, resolution: null, created_at: "2030-01-01T00:00:00Z" } as const;
const richComparison: ComparisonResponse = {
  comparison_id: "comparison-0123456789abcdef0123456789abcdef",
  baseline_run_id: demoRuns[0]!.run_id,
  run_ids: [demoRuns[0]!.run_id, demoRuns[1]!.run_id],
  summaries: [
    {
      run_id: demoRuns[0]!.run_id, mode: "simulate", profile_id: "sandbox-simulate.v1", path: ["discover", "transport"], outcomes: { discover: "success", transport: "blocked" }, outcome_counts: { blocked: 1, success: 1 }, first_blocked_step: "transport", objective_reached: false,
      evidence_provenance: { observed: 1, synthetic: 2 }, detection_states: { fixture_exercised: 1 }, detection_matches: 1, benign_matches: 2, telemetry: ["dns.query"], controls: ["egress.observe"], cleanup_success: true, policy_states: { allowed: 2 }, autonomy: "off", ai_provider_id: "deterministic-offline.v1", ai_proposal_count: 0, ai_applications: { not_applied: 0 }, remaining_budgets: { steps: 20, seconds: 90 }, duration_ms: 1_500, counterfactual_steps: [],
    },
    {
      run_id: demoRuns[1]!.run_id, mode: "simulate", profile_id: "sandbox-simulate.v1", path: ["discover", "transport"], outcomes: { discover: "success", transport: "success" }, outcome_counts: { success: 2 }, first_blocked_step: null, objective_reached: true,
      evidence_provenance: { observed: 3, synthetic: 1 }, detection_states: { benign_evaluated: 1, observed_exercised: 2 }, detection_matches: 3, benign_matches: 1, telemetry: ["dns.query", "process.start"], controls: ["egress.observe", "egress.block"], cleanup_success: true, policy_states: { allowed: 1, blocked: 1 }, autonomy: "assist", ai_provider_id: "registered-provider.v1", ai_proposal_count: 2, ai_applications: { applied: 1, refused: 1 }, remaining_budgets: { steps: 17, seconds: 71 }, duration_ms: 1_250, counterfactual_steps: ["transport"],
    },
  ],
  deltas: [{
    from_run_id: demoRuns[0]!.run_id, to_run_id: demoRuns[1]!.run_id, first_path_divergence: null, first_blocked_changed: true, objective_changed: true, cleanup_changed: false,
    evidence_delta: { observed: 2, synthetic: -1 }, detection_delta: { observed_exercised: 2 }, detection_match_delta: 2, benign_match_delta: -1, outcome_delta: { blocked: -1, success: 1 }, telemetry_added: ["process.start"], telemetry_removed: [], controls_added: ["egress.block"], controls_removed: [], autonomy_changed: true, ai_provider_changed: true, ai_proposal_delta: 2, duration_delta_ms: -250, assessment: "improved", signals: ["objective_recovered", "detection_matches_increased"],
  }],
};

const publicBaseline: PublicBaselineReference = {
  schema_version: "bluefire.public-baseline.v2",
  research_source_id: "mitre.attack.v1",
  source_digest: `sha256:${"a".repeat(64)}`,
  pin: "attack-enterprise-v19.2",
  version: "19.2",
  exact_ref: "attack-enterprise-v19.2",
  retrieved_at: "2030-01-01",
  license: "Terms of Use",
  file_level_license_review: "Framework and matrix metadata reviewed; no rule text copied.",
  trademark_considerations: "MITRE marks retained only in attribution metadata.",
  license_review: "reviewed",
  relationship: "comparative",
  use_classification: "reference_only",
  use: "comparison",
  attribution: "MITRE ATT&CK source metadata retained for comparison.",
  security_review: "Reference metadata is not fetched, synchronized, or executed.",
  last_verified_at: "2030-01-01",
  update_status: "current",
};
const detectionOriginId = "detection-111111111111111111111111";
const detectionTuneId = "detection-222222222222222222222222";
const detectionOrigin: DetectionResource = {
  kind: "detection",
  id: detectionOriginId,
  status: "benign_evaluated",
  digest: `sha256:${"b".repeat(64)}`,
  created_at: "2030-01-01T00:00:00Z",
  updated_at: "2030-01-01T00:05:00Z",
  document: {
    schema_version: "bluefire.detection-candidate.v2",
    candidate_id: detectionOriginId,
    revision: 1,
    revision_root_id: detectionOriginId,
    parent_candidate_id: null,
    revision_kind: "origin",
    definition_digest: `sha256:${"c".repeat(64)}`,
    behavior_id: "sandbox.collection.stage.v1",
    title: "Staged file observation",
    target_language: "internal",
    logsource: { category: "file_event", product: "generic" },
    selection: { artifact_type: "file_observation", "path|contains": "staged/" },
    parser_backend: { name: "structured-matcher", version: "1.0" },
    public_baselines: [],
    malicious_fixture_ids: ["malicious-1"],
    observed_evidence_ids: ["evidence-old"],
    benign_fixture_ids: ["benign-1"],
    known_misses: ["Renamed staging roots"],
    false_positive_notes: ["Temporary build staging"],
    tuning_decisions: [],
    state: "benign_evaluated",
    provenance: { source: "operator-authored", license: "Review required" },
    match_count: 1,
    benign_match_count: 1,
    rejection_reason: null,
    rule_source: null,
    validation: { parsed: true },
    predicted_fields: ["artifact_type", "path"],
    observed_fields: ["artifact_type", "path"],
    field_drift: {},
    malicious_fixtures: [],
    benign_fixtures: [],
    lifecycle_history: [{ sequence: 1, action: "hypothesis_upsert", from_state: null, to_state: "hypothesis", outcome: "created", input_digest: `sha256:${"d".repeat(64)}`, recorded_at: "2030-01-01T00:00:00Z" }],
  },
};
const detectionTune: DetectionResource = {
  ...detectionOrigin,
  id: detectionTuneId,
  digest: `sha256:${"e".repeat(64)}`,
  updated_at: "2030-01-01T00:06:00Z",
  document: {
    ...detectionOrigin.document,
    candidate_id: detectionTuneId,
    revision: 2,
    parent_candidate_id: detectionOriginId,
    revision_kind: "tune",
    definition_digest: `sha256:${"f".repeat(64)}`,
    title: "Narrowed staged file observation",
    selection: { artifact_type: "file_observation", "path|startswith": "staged/" },
    public_baselines: [publicBaseline],
    malicious_fixture_ids: ["malicious-1", "malicious-2"],
    observed_evidence_ids: ["evidence-old", "evidence-new"],
    benign_fixture_ids: ["benign-1", "benign-2"],
    tuning_decisions: ["Narrow the staged-path match."],
    match_count: 2,
    benign_match_count: 0,
    predicted_fields: ["artifact_type", "path", "destination_ip"],
    observed_fields: ["artifact_type", "path", "destination_ip"],
    field_drift: { destination_ip: ["dst_ip"] },
    lifecycle_history: [...(detectionOrigin.document.lifecycle_history ?? []), { sequence: 2, action: "revision_tune", from_state: "benign_evaluated", to_state: "benign_evaluated", outcome: "created", input_digest: `sha256:${"1".repeat(64)}`, recorded_at: "2030-01-01T00:06:00Z" }],
  },
};
const detectionComparison: DetectionComparisonResponse = {
  schema_version: "bluefire.detection-comparison.v1",
  comparison_id: "detection-comparison-0123456789abcdef",
  revision_root_id: detectionOriginId,
  baseline: { candidate_id: detectionOriginId, revision: 1, revision_kind: "origin", state: "benign_evaluated", definition_digest: detectionOrigin.document.definition_digest! },
  candidate: { candidate_id: detectionTuneId, revision: 2, revision_kind: "tune", state: "benign_evaluated", definition_digest: detectionTune.document.definition_digest! },
  deltas: {
    source: { changed: true, provenance: { baseline_digest: `sha256:${"2".repeat(64)}`, candidate_digest: `sha256:${"3".repeat(64)}`, changed: false }, public_baselines: { changed: true, added: [publicBaseline], removed: [], modified: [] } },
    rule: { changed: true, changed_fields: ["selection"], baseline: { target_language: "internal", logsource_digest: `sha256:${"4".repeat(64)}`, selection_digest: `sha256:${"5".repeat(64)}`, rule_source_digest: null }, candidate: { target_language: "internal", logsource_digest: `sha256:${"4".repeat(64)}`, selection_digest: `sha256:${"6".repeat(64)}`, rule_source_digest: null } },
    fields: { changed: true, predicted: { added: ["destination_ip"], removed: [], unchanged: ["artifact_type", "path"] }, observed: { added: ["destination_ip"], removed: [], unchanged: ["artifact_type", "path"] }, drift: { changed: true, baseline: {}, candidate: { destination_ip: ["dst_ip"] } } },
    lifecycle: { changed: true, baseline_state: "benign_evaluated", candidate_state: "benign_evaluated", baseline_actions: ["hypothesis_upsert"], candidate_actions: ["hypothesis_upsert", "revision_tune"], baseline_history_digest: `sha256:${"7".repeat(64)}`, candidate_history_digest: `sha256:${"8".repeat(64)}` },
    fixtures: { changed: true, added_fixture_ids: ["malicious-2"], removed_fixture_ids: [], changed_fixture_ids: ["malicious-1"], fixture_ids: { added: ["malicious-2"], removed: [], unchanged: ["malicious-1"] }, baseline_match_count: 1, candidate_match_count: 2 },
    observed: { changed: true, evidence_ids: { added: ["evidence-new"], removed: [], unchanged: ["evidence-old"] }, run_ids: { added: ["run-new"], removed: ["run-old"], unchanged: [] } },
    benign: { changed: true, added_fixture_ids: ["benign-2"], removed_fixture_ids: [], changed_fixture_ids: ["benign-1"], fixture_ids: { added: ["benign-2"], removed: [], unchanged: ["benign-1"] }, notes: { added: ["No ordinary staging match"], removed: [], unchanged: ["Temporary build staging"] }, baseline_match_count: 1, candidate_match_count: 0 },
  },
};

function json(value: unknown) {
  return new Response(JSON.stringify(value), { status: 200, headers: { "Content-Type": "application/json" } });
}

function renderApp(path = "/", client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })) {
  return render(<QueryClientProvider client={client}><ProductProvider><MemoryRouter initialEntries={[path]}><App /></MemoryRouter></ProductProvider></QueryClientProvider>);
}

describe("product application", () => {
  beforeEach(() => {
    window.localStorage.clear();
    activeJobInventory = [];
    vi.stubGlobal("scrollTo", vi.fn());
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      if (path.endsWith("/catalog")) return json(demoCatalog);
      if (path.endsWith("/scenarios")) return json({ scenarios: [demoScenario] });
      if (path.endsWith("/scenario-versions")) return json({ schema_version: "bluefire.scenario-version-list.v1", scenarios: [] });
      if (path.endsWith("/detection-lab/health")) return json({ schema_version: "bluefire.detection-lab-health.v1", ready: true, persistence_ready: true, candidate_resources: 0, invalid_candidate_resources: 0, languages: {}, limits: {} });
      if (path.endsWith("/resources/research-sources")) return json({ schema_version: "bluefire.resource-list.v1", kind: "research-sources", resources: [{ schema_version: "bluefire.resource.v1", kind: "research-sources", id: "mitre.attack.v1", status: "pinned", digest: publicBaseline.source_digest, created_at: "2030-01-01T00:00:00Z", updated_at: "2030-01-01T00:00:00Z", document: { schema_version: "bluefire.research-source.v1", name: "MITRE ATT&CK", source_type: "behavior_reference", project: "MITRE ATT&CK", authority: "MITRE", reference_url: "https://attack.mitre.org/versions/v19/", version: "19.2", pin: "attack-enterprise-v19.2", exact_ref: "attack-enterprise-v19.2", retrieved_at: "2030-01-01", license: "Terms of Use", license_url: "https://www.mitre.org/legal-notices", file_level_license_review: "Framework and matrix metadata reviewed; no rule text copied.", trademark_considerations: "MITRE marks retained only in attribution metadata.", relationship: "comparative", use_classification: "reference_only", license_review: "reviewed", uses: ["comparison", "research_reference"], imported_paths: [], cache_policy: "metadata_only", executable_content: false, attribution: "MITRE ATT&CK source metadata retained for comparison.", security_review: "Reference metadata is not fetched, synchronized, or executed.", last_verified_at: "2030-01-01", update_status: "current", transformation_history: "Metadata-only comparison reference.", notes: "No remote content is fetched by the UI fixture." } }] });
      if (path.endsWith(`/detections/${detectionOriginId}/compare`)) return json(detectionComparison);
      if (path.endsWith(`/detections/${detectionOriginId}/clone`) || path.endsWith(`/detections/${detectionOriginId}/tune`)) return json({ schema_version: "bluefire.detection-resource.v1", candidate: detectionTune });
      if (path.endsWith("/detections")) return json({ schema_version: "bluefire.detection-list.v1", candidates: [detectionOrigin, detectionTune] });
      if (path.includes("/resources/")) return json({ schema_version: "bluefire.resource-list.v1", kind: "test", resources: [] });
      if (path.endsWith("/settings")) return json({ schema_version: "bluefire.setting-list.v1", settings: [] });
      if (path.endsWith("/settings/ui.preferences")) return json({ schema_version: "bluefire.setting.v1", setting: { key: "ui.preferences", value: JSON.parse(String(init?.body)).value, updated_at: "2030-01-01T00:00:00Z" } });
      if (path.endsWith("/ai/drafts")) return json({ schema_version: "bluefire.ai-graph-draft-result.v1", draft_id: "ai-draft-test", saved: false, scenario: { ...demoScenario, title: "Registered draft", layout: undefined }, rationale: "Normalized from registered contracts.", assumptions: ["Operator review required."], audit: { schema_version: "bluefire.ai-graph-draft-audit.v1", unsaved: true, provider: { effective_provider_id: "deterministic-offline.v1", model: "deterministic-planner.v1", used_fallback: false }, selected_behavior_ids: demoScenario.steps.map((step) => step.behavior_id), normalization: { artifact_bindings_added: 4 }, validation: { registered_behaviors_only: true } } });
      if (path.endsWith("/runs/preflight")) return json(executePreflight);
      if (path.endsWith("/runs") && init?.method === "POST") { activeJobInventory = [executeJob]; return json({ schema_version: "bluefire.run-job-submission.v1", job: executeJob, approval_request: executeApprovalRequest, preflight: executePreflight }); }
      if (path.endsWith("/comparisons")) return json(richComparison);
      const runDetailMatch = path.match(/\/runs\/([^/?]+)$/);
      if (runDetailMatch) {
        const runId = decodeURIComponent(runDetailMatch[1]!);
        const run = demoRuns.find((item) => item.run_id === runId);
        if (run) return json(run);
      }
      if (path.endsWith("/proposals")) return json({ schema_version: "bluefire.ai-proposal-review-list.v1", job_id: proposalJob.job_id, proposals: [proposalReview] });
      if (path.endsWith("/accept")) return json({ schema_version: "bluefire.ai-proposal-decision.v1", job: { ...proposalJob, progress: { phase: "awaiting_approval", approval_kind: "ai_proposal_execute", approval_request_id: "approval-fresh", proposal_record_id: proposalReview.proposal_record_id } }, proposal: { ...proposalReview, status: "accepted", resolution: { decision: "accepted", approval_request_id: "approval-fresh", continuation: { execute_approval_binding_digest: "sha256:" + "4".repeat(64), selected_behavior_id: "endpoint.discovery.system.v1" } } }, approval_request: { approval_id: "approval-fresh", status: "pending", state_digest: "sha256:" + "5".repeat(64), plan_digest: "sha256:" + "6".repeat(64), target_scope_digest: "sha256:" + "7".repeat(64), profile_id: "sandbox-execute.v1", maximum_tier: "controlled", expires_at: "2030-01-01T00:00:00Z" } });
      if (path.includes("/proposals/")) return json(proposalReview);
      if (path.endsWith("/jobs")) return json({ schema_version: "bluefire.active-job-list.v1", jobs: activeJobInventory });
      if (path.includes(`/jobs/${proposalJob.job_id}`)) return json(proposalJob);
      const inventoryJob = activeJobInventory.find((job) => path.endsWith(`/jobs/${job.job_id}`));
      if (inventoryJob) return json({ ...inventoryJob, approval_request: inventoryJob.state === "awaiting_approval" ? executeApprovalRequest : null });
      if (path.includes("/jobs/")) return json({ ...executeJob, approval_request: executeApprovalRequest });
      if (path.endsWith("/runs")) return json({ runs: demoRuns });
      throw new Error(`Unhandled test request: ${path}`);
    }));
  });
  afterEach(() => vi.unstubAllGlobals());

  it("renders mission control and routes every research source link", async () => {
    const user = userEvent.setup();
    renderApp();
    expect(await screen.findByRole("heading", { name: "Design the path. Observe the defense." })).toBeVisible();
    expect(await screen.findByRole("img", { name: "Local service connected" })).toBeVisible();
    await user.click(screen.getByRole("link", { name: /Research Sources/i }));
    expect(await screen.findByRole("heading", { name: "Research sources" })).toBeVisible();
    expect(screen.getByRole("heading", { name: "MITRE ATT&CK" })).toBeVisible();
    expect(screen.getByText("19.2")).toBeVisible();
    expect(screen.getByText(/Immutable references, no blind imports/i)).toBeVisible();
  });

  it("creates a local scenario draft before navigating to Builder", async () => {
    const user = userEvent.setup();
    renderApp("/scenarios");

    expect(await screen.findByRole("heading", { name: "Reusable security experiments" })).toBeVisible();
    await user.click(screen.getByRole("button", { name: "New scenario" }));
    await waitFor(() => expect(document.querySelector<HTMLInputElement>(".dialog-content input")).not.toBeNull());
    const title = document.querySelector<HTMLInputElement>(".dialog-content input")!;
    await user.clear(title);
    await user.type(title, "Gate 08 local draft");
    await user.click(screen.getByRole("button", { name: "Create draft" }));

    expect(await screen.findByRole("heading", { name: "Compose a typed adaptive graph" })).toBeVisible();
    expect(screen.getByText("Start with a registered behavior")).toBeVisible();
    expect(screen.getByDisplayValue("Gate 08 local draft")).toBeVisible();
  });

  it("rejects malformed imported scenario members without persisting them", async () => {
    const user = userEvent.setup();
    renderApp("/scenarios");
    expect(await screen.findByRole("heading", { name: "Reusable security experiments" })).toBeVisible();
    const input = screen.getByLabelText("Import scenario JSON file");
    const firstStep = structuredClone(demoScenario.steps[0]!);

    await user.upload(input, new File([JSON.stringify({ ...demoScenario, steps: [{ ...firstStep, inputs: null }] })], "null-inputs.json", { type: "application/json" }));
    expect(await screen.findByText(/steps\[0\]\.inputs must be an object/)).toBeVisible();

    await user.upload(input, new File([JSON.stringify({ ...demoScenario, edges: [null] })], "null-edge.json", { type: "application/json" }));
    expect(await screen.findByText(/edges\[0\] must be an object/)).toBeVisible();

    await user.upload(input, new File([JSON.stringify({ ...demoScenario, steps: [{ ...firstStep, parameters: { record_count: { toString: null, valueOf: null } } }] })], "object-parameter.json", { type: "application/json" }));
    expect(await screen.findByText(/parameters\.record_count must be a string, finite number, boolean, or string array/)).toBeVisible();
    await waitFor(() => expect(JSON.parse(window.localStorage.getItem("bluefire.local.scenario.v1") ?? "{}").title).toBe(demoScenario.title));
    await user.click(screen.getByRole("link", { name: /^Scenario Builder$/ }));
    expect(await screen.findByRole("heading", { name: "Compose a typed adaptive graph" })).toBeVisible();
    expect(screen.getByDisplayValue(demoScenario.title)).toBeVisible();
  });

  it("replaces the stale demo fallback with a registered production scenario", async () => {
    const canonicalScenario = {
      ...structuredClone(demoScenario),
      id: "scenario.registered.production.v1",
      title: "Registered production scenario",
      start: "place_fixture",
      steps: [structuredClone(demoScenario.steps[0]!)],
      edges: [],
    };
    const productionCatalog = {
      ...demoCatalog,
      behaviors: demoCatalog.behaviors.filter((item) => item.id !== "sandbox.program.fixed.v1"),
    };
    const fetchMock = vi.mocked(fetch);
    const fallback = fetchMock.getMockImplementation()!;
    fetchMock.mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      if (path.endsWith("/catalog")) return json(productionCatalog);
      if (path.endsWith("/scenarios")) return json({ scenarios: [canonicalScenario] });
      return fallback(input, init);
    });

    renderApp("/builder");

    expect(await screen.findByDisplayValue("Registered production scenario")).toBeVisible();
    expect(screen.queryByDisplayValue(demoScenario.title)).not.toBeInTheDocument();
  });

  it("guides first-run users through honest local readiness and Simulate", async () => {
    const user = userEvent.setup();
    renderApp("/getting-started");

    expect(await screen.findByRole("heading", { name: "Prove the safe path first" })).toBeVisible();
    expect(screen.getByText("A canonical first run exists")).toBeVisible();
    expect(screen.getByText("Control plane")).toBeVisible();
    expect(screen.getByText("Deterministic Simulate")).toBeVisible();
    expect(screen.getByText("Not proven")).toBeVisible();
    expect(screen.getByText(/fresh identity\/inventory\/sandbox probe/i)).toBeVisible();

    await user.click(screen.getByRole("link", { name: /Configure Simulate/i }));
    expect(await screen.findByRole("heading", { name: "Preflight every path. Observe every decision." })).toBeVisible();
    expect(window.scrollTo).toHaveBeenCalled();
  });

  it("opens recent runs in a reload-safe canonical review URL", async () => {
    const user = userEvent.setup();
    const firstRender = renderApp();
    const run = demoRuns[0]!;
    const reviewLink = await screen.findByRole("link", { name: `Review run ${run.objective} (${run.run_id})` });
    expect(reviewLink).toHaveAttribute("href", `/runs/${encodeURIComponent(run.run_id)}`);
    await user.click(reviewLink);
    expect(await screen.findByRole("heading", { name: "Canonical run review" })).toBeVisible();
    expect(screen.getByRole("link", { name: "Back to run workspace" })).toHaveAttribute("href", "/runs");
    const rawSummary = screen.getByText("Show raw reproducibility metadata");
    expect(rawSummary.closest("details")).not.toHaveAttribute("open");
    const detailCalls = () => vi.mocked(fetch).mock.calls.filter(([input]) => String(input).endsWith(`/runs/${encodeURIComponent(run.run_id)}`)).length;
    expect(detailCalls()).toBe(1);

    firstRender.unmount();
    renderApp(`/runs/${encodeURIComponent(run.run_id)}`);
    expect(await screen.findByRole("heading", { name: "Canonical run review" })).toBeVisible();
    expect(detailCalls()).toBe(2);
  });

  it("renders the complete canonical comparison contract with technical data collapsed", async () => {
    const user = userEvent.setup();
    renderApp("/compare");
    expect(await screen.findByRole("heading", { name: "Measure what changed" })).toBeVisible();
    const runSelectors = screen.getAllByRole("checkbox");
    expect(runSelectors).toHaveLength(2);
    await user.click(runSelectors[0]!);
    await user.click(runSelectors[1]!);
    await user.click(screen.getByRole("button", { name: "Compare selected" }));

    expect(await screen.findByText("Material deltas")).toBeVisible();
    expect(screen.getByRole("link", { name: "Review baseline run summary" })).toHaveAttribute("href", `/runs/${encodeURIComponent(demoRuns[0]!.run_id)}`);
    expect(screen.getByText("Observed: 3, Synthetic: 1")).toBeVisible();
    expect(screen.getByText("Benign evaluated: 1, Observed exercised: 2")).toBeVisible();
    expect(screen.getByText("Allowed: 1, Blocked: 1")).toBeVisible();
    expect(screen.getByText("2 · Applied: 1, Refused: 1")).toBeVisible();
    expect(screen.getByText("Steps: 17, Seconds: 71")).toBeVisible();
    expect(screen.getByText("1.25 s")).toBeVisible();
    expect(screen.getAllByText("Transport").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Objective recovered, Detection matches increased").length).toBeGreaterThan(0);
    expect(screen.getByText("Observed +2, Synthetic -1")).toBeVisible();
    expect(screen.getByText("Observed exercised +2")).toBeVisible();
    expect(screen.getByText("Blocked -1, Success +1")).toBeVisible();
    expect(screen.getByText("−250 ms")).toBeVisible();
    expect(screen.getAllByText("Detection match delta").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Benign match delta").length).toBeGreaterThan(0);
    const technicalSummary = screen.getByText("Show technical comparison delta");
    expect(technicalSummary.closest("details")).not.toHaveAttribute("open");
  });

  it("keeps an in-flight replay record out of canonical comparison without crashing", async () => {
    const fetchMock = vi.mocked(fetch);
    const fallback = fetchMock.getMockImplementation()!;
    fetchMock.mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      if (path.endsWith("/runs") && init?.method !== "POST") return json({ schema_version: "bluefire.run-list.v1", runs: [{ schema_version: "1.0", run_id: "run-20300101T000000Z-aaaaaaaaaaaaaaaa", status: "created", created_at: "2030-01-01T00:00:00Z" }, ...demoRuns] });
      return fallback(input, init);
    });

    renderApp("/compare");
    expect(await screen.findByRole("heading", { name: "Measure what changed" })).toBeVisible();
    expect(screen.getByText("Unavailable run records excluded")).toBeVisible();
    expect(screen.getByText(/1 in-flight, interrupted, or integrity-failed run record is unavailable/)).toBeVisible();
    expect(screen.getAllByRole("checkbox")).toHaveLength(2);
  });

  it("binds the independent filesystem collector into Execute replay preflight", async () => {
    const user = userEvent.setup();
    const executeRun = {
      ...demoRuns[0]!,
      run_id: "run-20300101T000000Z-bbbbbbbbbbbbbbbb",
      mode: "execute" as const,
      runner_profile_id: "sandbox-execute.v1",
      target_scope: { scope_refs: ["sandbox.workspace"] },
      scenario: demoScenario,
      is_demo: false,
    };
    const fetchMock = vi.mocked(fetch);
    const fallback = fetchMock.getMockImplementation()!;
    let resolveFirstPreflight!: (response: Response) => void;
    const firstPreflight = new Promise<Response>((resolve) => { resolveFirstPreflight = resolve; });
    let preflightAttempts = 0;
    fetchMock.mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      if (path.endsWith("/runs") && init?.method !== "POST") {
        return json({ schema_version: "bluefire.run-list.v1", runs: [executeRun] });
      }
      if (path.endsWith(`/runs/${encodeURIComponent(executeRun.run_id)}`)) {
        return json(executeRun);
      }
      if (path.endsWith("/runs/preflight") && preflightAttempts++ === 0) return firstPreflight;
      return fallback(input, init);
    });

    renderApp("/compare");
    expect(await screen.findByRole("heading", { name: "Measure what changed" })).toBeVisible();
    await user.selectOptions(screen.getByLabelText("Source run"), executeRun.run_id);
    await waitFor(() => expect(screen.getByLabelText("Exact target scope")).toHaveValue("sandbox.workspace"));
    await user.click(screen.getByRole("button", { name: "Run prospective base-plan check" }));
    await waitFor(() => expect(fetchMock.mock.calls.some(([input]) => String(input).endsWith("/runs/preflight"))).toBe(true));
    const targetScope = screen.getByLabelText("Exact target scope");
    await user.clear(targetScope);
    await user.type(targetScope, "sandbox.changed");
    resolveFirstPreflight(json(executePreflight));
    await waitFor(() => expect(screen.getByRole("button", { name: "Run prospective base-plan check" })).toBeEnabled());
    expect(screen.getByRole("checkbox", { name: /I approve this reviewed Execute replay request once/ })).toBeDisabled();

    await waitFor(() => {
      const preflightCall = fetchMock.mock.calls.find(([input]) => String(input).endsWith("/runs/preflight"));
      expect(preflightCall).toBeDefined();
      expect(JSON.parse(String((preflightCall?.[1] as RequestInit).body))).toMatchObject({
        mode: "execute",
        collectors: ["collector.filesystem.sandbox.v1"],
      });
    });
    await user.click(screen.getByRole("button", { name: "Run prospective base-plan check" }));
    await waitFor(() => expect(screen.getByRole("checkbox", { name: /I approve this reviewed Execute replay request once/ })).toBeEnabled());
  });

  it("reviews immutable detection revisions, pinned public baselines, and complete deltas", async () => {
    const user = userEvent.setup();
    renderApp("/detection-lab");
    expect(await screen.findByRole("heading", { name: "Detection Lab" })).toBeVisible();
    await user.click(screen.getByRole("tab", { name: "Revisions" }));

    expect(screen.getByText("Immutable revision rule")).toBeVisible();
    expect(screen.getAllByText(/Revision 1 · Origin/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Revision 2 · Tune/).length).toBeGreaterThan(0);
    expect(screen.getAllByText("MITRE ATT&CK").length).toBeGreaterThan(0);
    expect(screen.getAllByText(/19\.2 · attack-enterprise-v19\.2/).length).toBeGreaterThan(0);
    expect(screen.getAllByRole("radio").filter((item) => item.getAttribute("name") === "detection-revision-kind")).toHaveLength(2);
    await user.click(screen.getByRole("radio", { name: /Tune rule behavior/i }));
    expect(screen.getByRole("textbox", { name: /Tuned selection JSON/ })).toBeVisible();
    await user.click(screen.getByRole("radio", { name: /Clone unchanged rule behavior/i }));
    const baselineChoice = screen.getByRole("checkbox", { name: /MITRE ATT&CK/i });
    await user.click(baselineChoice);
    expect(await screen.findByText("Source handling")).toBeVisible();
    await user.type(screen.getByRole("textbox", { name: /Required research reason/ }), "Branch reviewed source attribution.");
    await user.click(screen.getByRole("button", { name: "Create immutable clone" }));
    await waitFor(() => expect(vi.mocked(fetch).mock.calls.some(([input]) => String(input).endsWith(`/detections/${detectionOriginId}/clone`))).toBe(true));
    const cloneCall = vi.mocked(fetch).mock.calls.find(([input]) => String(input).endsWith(`/detections/${detectionOriginId}/clone`));
    const cloneBody = JSON.parse(String((cloneCall?.[1] as RequestInit).body));
    expect(cloneBody.reason).toBe("Branch reviewed source attribution.");
    expect(cloneBody.public_baselines).toEqual([publicBaseline]);
    expect(cloneBody).not.toHaveProperty("selection");
    expect(cloneBody).not.toHaveProperty("logsource");

    await user.click(screen.getByRole("button", { name: /^Staged file observation/ }));
    await user.click(screen.getByRole("tab", { name: "Revisions" }));
    const compareButton = screen.getByRole("button", { name: "Compare immutable revisions" });
    await waitFor(() => expect(compareButton).toBeEnabled());
    await user.click(compareButton);

    expect(await screen.findByLabelText("Detection revision comparison")).toBeVisible();
    expect(screen.getByText(/7 of 7 delta categories changed/)).toBeVisible();
    expect(screen.getByText("Source attribution")).toBeVisible();
    expect(screen.getByText("Rule definition")).toBeVisible();
    expect(screen.getByText("Field coverage")).toBeVisible();
    expect(screen.getByText("Lifecycle proof")).toBeVisible();
    expect(screen.getByText("Observed evidence")).toBeVisible();
    expect(screen.getByText("Benign evaluation")).toBeVisible();
    expect(screen.getAllByText("Destination ip").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Evidence-new").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Run-old").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Temporary build staging").length).toBeGreaterThan(0);
    const rawSummary = screen.getByText("Show raw detection comparison");
    expect(rawSummary.closest("details")).not.toHaveAttribute("open");
  }, 15_000);

  it("exposes exactly two effect modes and three independent autonomy levels", async () => {
    renderApp("/runs");
    expect(await screen.findByRole("heading", { name: "Preflight every path. Observe every decision." })).toBeVisible();
    expect(screen.getAllByRole("radio").filter((item) => item.getAttribute("name") === "run-mode")).toHaveLength(2);
    expect(screen.getAllByRole("radio").filter((item) => item.getAttribute("name") === "autonomy")).toHaveLength(3);
    expect(screen.getByText("Profile-owned enforcement")).toBeInTheDocument();
    expect(screen.getByText("Builder handoff")).toBeVisible();
    expect(screen.getByText("Not run for this handoff")).toBeVisible();
    expect(screen.getByRole("heading", { name: "No active job" })).toBeVisible();
    expect(screen.queryByText("Job submission in progress")).not.toBeInTheDocument();
    expect(screen.queryByText("Planning request submitted")).not.toBeInTheDocument();
  });

  it("locks Execute approval until the complete bound envelope is rendered", async () => {
    const user = userEvent.setup();
    renderApp("/runs");
    expect(await screen.findByRole("heading", { name: "Preflight every path. Observe every decision." })).toBeVisible();
    await user.click(screen.getByRole("radio", { name: /Execute/ }));
    await user.click(screen.getByText("Policy, approval & budgets"));
    const approval = screen.getByRole("checkbox", { name: /I reviewed this exact displayed Execute envelope/ });
    const operator = screen.getByRole("textbox", { name: /Prepared operator label/ });
    expect(approval).toBeDisabled();
    expect(operator).toBeDisabled();

    await user.click(screen.getByRole("button", { name: "Run preflight" }));
    expect(await screen.findByRole("region", { name: "Complete Execute approval envelope" })).toBeVisible();
    expect(screen.getByText("Primary and alternate behavior contracts")).toBeVisible();
    expect(screen.getAllByText("state-digest-test").length).toBeGreaterThan(0);
    expect(screen.getAllByText("plan-digest-test").length).toBeGreaterThan(0);
    expect(screen.getAllByText("scope-digest-test").length).toBeGreaterThan(0);
    expect(screen.getAllByText("envelope-digest-test").length).toBeGreaterThan(0);
    expect(screen.getByText("Full deterministic action contract")).toBeVisible();
    expect(approval).toBeEnabled();
    expect(operator).toBeEnabled();

    await user.click(approval);
    await user.type(operator, "prepared-operator");
    await user.click(screen.getByRole("button", { name: "Create approval-gated job" }));
    expect(await screen.findByRole("region", { name: "Durable Execute job approval" })).toBeVisible();
    const durableApproval = screen.getByRole("checkbox", { name: /I approve this exact immutable job envelope once/ });
    const durableOperator = screen.getByRole("textbox", { name: "Operator identity for this job" });
    expect(durableApproval).toBeEnabled();
    expect(durableApproval).not.toBeChecked();
    expect(durableOperator).toHaveValue("");
    expect(window.localStorage.getItem(activeJobStorageKey)).toBe(executeJob.job_id);
  }, 15_000);

  it("restores an awaiting-approval job after remount and clears its terminal pointer", async () => {
    activeJobInventory = [executeJob];
    window.localStorage.setItem(activeJobStorageKey, executeJob.job_id);

    const firstMount = renderApp("/runs");
    expect(await screen.findByRole("heading", { name: executeJob.job_id })).toBeVisible();
    expect(await screen.findByRole("region", { name: "Durable Execute job approval" })).toBeVisible();
    expect(screen.getByRole("checkbox", { name: /I approve this exact immutable job envelope once/ })).toBeEnabled();
    expect(screen.getByRole("textbox", { name: "Operator identity for this job" })).toHaveValue("");
    expect(window.localStorage.getItem(activeJobStorageKey)).toBe(executeJob.job_id);
    expect(vi.mocked(fetch).mock.calls.some(([input, init]) => String(input).endsWith("/runs/preflight") && init?.method === "POST")).toBe(true);
    firstMount.unmount();

    const secondMount = renderApp("/runs");
    expect(await screen.findByRole("heading", { name: executeJob.job_id })).toBeVisible();
    expect(await screen.findByRole("region", { name: "Durable Execute job approval" })).toBeVisible();
    expect(screen.getByRole("checkbox", { name: /I approve this exact immutable job envelope once/ })).not.toBeChecked();
    expect(screen.getByRole("textbox", { name: "Operator identity for this job" })).toHaveValue("");
    secondMount.unmount();

    const fetchMock = vi.mocked(fetch);
    const defaultImplementation = fetchMock.getMockImplementation()!;
    fetchMock.mockImplementation(async (input, init) => {
      if (String(input).endsWith(`/jobs/${executeJob.job_id}`) && !init?.method) {
        activeJobInventory = [];
        return json({ ...executeJob, state: "cancelled", progress: { phase: "cancelled" }, approval_request: null });
      }
      return defaultImplementation(input, init);
    });

    const terminalMount = renderApp("/runs");
    await waitFor(() => expect(window.localStorage.getItem(activeJobStorageKey)).toBeNull());
    terminalMount.unmount();

    const exactJobRequests = () => fetchMock.mock.calls.filter(([input, init]) => String(input).endsWith(`/jobs/${executeJob.job_id}`) && !init?.method).length;
    const terminalRequestCount = exactJobRequests();
    renderApp("/runs");
    expect(await screen.findByRole("heading", { name: "No active job" })).toBeVisible();
    expect(exactJobRequests()).toBe(terminalRequestCount);
  });

  it("restores an interrupted stored job omitted from fresh active inventory", async () => {
    const interruptedJob: RunJob = { ...executeJob, state: "interrupted", progress: { phase: "interrupted" }, approval_request: null };
    window.localStorage.setItem(activeJobStorageKey, interruptedJob.job_id);
    const fetchMock = vi.mocked(fetch);
    const defaultImplementation = fetchMock.getMockImplementation()!;
    let resolveDetail!: (response: Response) => void;
    let detailRequests = 0;
    fetchMock.mockImplementation((input, init) => {
      if (String(input).endsWith(`/jobs/${interruptedJob.job_id}`) && !init?.method) {
        detailRequests += 1;
        if (detailRequests === 1) return new Promise<Response>((resolve) => { resolveDetail = resolve; });
        return Promise.resolve(json(interruptedJob));
      }
      return defaultImplementation(input, init);
    });

    const firstMount = renderApp("/runs");
    await screen.findByRole("heading", { name: "Preflight every path. Observe every decision." });
    await waitFor(() => expect(resolveDetail).toBeTypeOf("function"));
    expect(window.localStorage.getItem(activeJobStorageKey)).toBe(interruptedJob.job_id);
    expect(screen.getByRole("button", { name: "Run preflight" })).toBeDisabled();

    await act(async () => { resolveDetail(json(interruptedJob)); });
    expect(await screen.findByRole("heading", { name: interruptedJob.job_id })).toBeVisible();
    expect(screen.getByRole("button", { name: "Retry as replacement" })).toBeVisible();
    expect(window.localStorage.getItem(activeJobStorageKey)).toBe(interruptedJob.job_id);
    firstMount.unmount();

    renderApp("/runs");
    expect(await screen.findByRole("heading", { name: interruptedJob.job_id })).toBeVisible();
    expect(screen.getByRole("button", { name: "Retry as replacement" })).toBeVisible();
    expect(window.localStorage.getItem(activeJobStorageKey)).toBe(interruptedJob.job_id);
    expect(fetchMock.mock.calls.filter(([input, init]) => String(input).endsWith(`/jobs/${interruptedJob.job_id}`) && !init?.method)).toHaveLength(2);
  });

  it("loads a completed result when inventory releases the slot before final detail", async () => {
    const runningJob: RunJob = { ...executeJob, state: "running", progress: { phase: "running" } };
    const completedRun = demoRuns[0]!;
    const completedJob: RunJob = { ...runningJob, state: "completed", progress: { phase: "completed", run_id: completedRun.run_id }, result_ref: completedRun.run_id };
    activeJobInventory = [runningJob];
    const fetchMock = vi.mocked(fetch);
    const defaultImplementation = fetchMock.getMockImplementation()!;
    let releaseControllerSlot = false;
    let inventoryReleased = false;
    let resolveFinalDetail: (() => void) | undefined;
    fetchMock.mockImplementation((input, init) => {
      const path = String(input);
      if (path.endsWith(`/jobs/${runningJob.job_id}`) && !init?.method && releaseControllerSlot) {
        return new Promise<Response>((resolve) => { resolveFinalDetail = () => resolve(json(completedJob)); });
      }
      if (path.endsWith("/jobs") && releaseControllerSlot) {
        inventoryReleased = true;
        activeJobInventory = [];
        return Promise.resolve(json({ schema_version: "bluefire.active-job-list.v1", jobs: [] }));
      }
      return defaultImplementation(input, init);
    });

    renderApp("/runs");
    expect(await screen.findByRole("heading", { name: runningJob.job_id })).toBeVisible();
    releaseControllerSlot = true;
    await waitFor(() => expect(inventoryReleased && Boolean(resolveFinalDetail)).toBe(true));
    expect(screen.getByRole("heading", { name: runningJob.job_id })).toBeVisible();
    expect(window.localStorage.getItem(activeJobStorageKey)).toBe(runningJob.job_id);

    resolveFinalDetail!();
    expect(await screen.findByRole("heading", { name: completedRun.run_id })).toBeVisible();
    expect(window.localStorage.getItem(activeJobStorageKey)).toBeNull();
  });

  it("does not re-offer a terminal job from a stale inventory snapshot", async () => {
    const runningJob: RunJob = { ...executeJob, state: "running", progress: { phase: "running" } };
    const cancelledJob: RunJob = { ...runningJob, state: "cancelled", progress: { phase: "cancelled" } };
    activeJobInventory = [runningJob];
    window.localStorage.setItem(activeJobStorageKey, runningJob.job_id);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
    const fetchMock = vi.mocked(fetch);
    const defaultImplementation = fetchMock.getMockImplementation()!;
    let terminalDetail = false;
    fetchMock.mockImplementation((input, init) => {
      if (String(input).endsWith(`/jobs/${runningJob.job_id}`) && !init?.method && terminalDetail) return Promise.resolve(json(cancelledJob));
      return defaultImplementation(input, init);
    });

    renderApp("/runs", client);
    expect(await screen.findByRole("heading", { name: runningJob.job_id })).toBeVisible();
    terminalDetail = true;
    await client.refetchQueries({ queryKey: ["job", runningJob.job_id], exact: true });
    await waitFor(() => expect(window.localStorage.getItem(activeJobStorageKey)).toBeNull());
    expect(screen.getByRole("heading", { name: runningJob.job_id })).toBeVisible();
    expect(screen.queryByRole("combobox", { name: "Active durable job" })).not.toBeInTheDocument();
  });

  it("keeps a known-terminal job suppressed after selecting another job", async () => {
    const runningJob: RunJob = { ...executeJob, state: "running", progress: { phase: "running" }, created_at: "2030-01-01T00:00:00Z" };
    const alternateJob: RunJob = { ...executeJob, job_id: "job-66666666666666666666666666666666", state: "paused", progress: { phase: "paused" }, created_at: "2030-01-02T00:00:00Z" };
    const cancelledJob: RunJob = { ...runningJob, state: "cancelled", progress: { phase: "cancelled" } };
    activeJobInventory = [runningJob, alternateJob];
    window.localStorage.setItem(activeJobStorageKey, runningJob.job_id);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
    const fetchMock = vi.mocked(fetch);
    const defaultImplementation = fetchMock.getMockImplementation()!;
    let terminalDetail = false;
    fetchMock.mockImplementation((input, init) => {
      if (String(input).endsWith(`/jobs/${runningJob.job_id}`) && !init?.method && terminalDetail) return Promise.resolve(json(cancelledJob));
      return defaultImplementation(input, init);
    });

    const user = userEvent.setup();
    renderApp("/runs", client);
    expect(await screen.findByRole("heading", { name: runningJob.job_id })).toBeVisible();
    terminalDetail = true;
    await client.refetchQueries({ queryKey: ["job", runningJob.job_id], exact: true });
    const selector = await screen.findByRole("combobox", { name: "Active durable job" });
    expect(screen.queryByRole("option", { name: new RegExp(runningJob.job_id) })).not.toBeInTheDocument();
    await user.selectOptions(selector, alternateJob.job_id);
    expect(await screen.findByRole("heading", { name: alternateJob.job_id })).toBeVisible();
    expect(screen.queryByRole("option", { name: new RegExp(runningJob.job_id) })).not.toBeInTheDocument();
  });

  it("suppresses a terminal job whose detached detail request finishes after selection changes", async () => {
    const runningJob: RunJob = { ...executeJob, state: "running", progress: { phase: "running" }, created_at: "2030-01-01T00:00:00Z" };
    const alternateJob: RunJob = { ...executeJob, job_id: "job-23232323232323232323232323232323", state: "paused", progress: { phase: "paused" }, created_at: "2030-01-02T00:00:00Z" };
    const cancelledJob: RunJob = { ...runningJob, state: "cancelled", progress: { phase: "cancelled" }, updated_at: "2030-01-03T00:00:00Z" };
    activeJobInventory = [runningJob, alternateJob];
    window.localStorage.setItem(activeJobStorageKey, runningJob.job_id);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
    const fetchMock = vi.mocked(fetch);
    const defaultImplementation = fetchMock.getMockImplementation()!;
    let resolveSourceDetail!: (response: Response) => void;
    fetchMock.mockImplementation((input, init) => {
      if (String(input).endsWith(`/jobs/${runningJob.job_id}`) && !init?.method) return new Promise<Response>((resolve) => { resolveSourceDetail = resolve; });
      return defaultImplementation(input, init);
    });

    const user = userEvent.setup();
    renderApp("/runs", client);
    const selector = await screen.findByRole("combobox", { name: "Active durable job" });
    await waitFor(() => expect(resolveSourceDetail).toBeTypeOf("function"));
    expect(screen.getByRole("heading", { name: runningJob.job_id })).toBeVisible();
    await user.selectOptions(selector, alternateJob.job_id);
    expect(await screen.findByRole("heading", { name: alternateJob.job_id })).toBeVisible();

    await act(async () => { resolveSourceDetail(json(cancelledJob)); });
    await waitFor(() => expect(client.getQueryData<RunJob>(["job", runningJob.job_id])?.state).toBe("cancelled"));
    await waitFor(() => expect(screen.queryByRole("option", { name: new RegExp(runningJob.job_id) })).not.toBeInTheDocument());
    expect(screen.getByRole("heading", { name: alternateJob.job_id })).toBeVisible();
    expect(window.localStorage.getItem(activeJobStorageKey)).toBe(alternateJob.job_id);
  });

  it("does not let a reattached stale detail request roll back fresher inventory", async () => {
    const originalJob: RunJob = { ...executeJob, state: "running", progress: { phase: "running" }, created_at: "2030-01-01T00:00:00Z", updated_at: "2030-01-01T00:00:00.000100Z" };
    const refreshedJob: RunJob = { ...originalJob, state: "paused", progress: { phase: "paused" }, updated_at: "2030-01-01T00:00:00.000900Z" };
    const alternateJob: RunJob = { ...executeJob, job_id: "job-67676767676767676767676767676767", state: "paused", progress: { phase: "paused" }, created_at: "2030-01-02T00:00:00Z", updated_at: "2030-01-02T00:00:00Z" };
    activeJobInventory = [originalJob, alternateJob];
    window.localStorage.setItem(activeJobStorageKey, originalJob.job_id);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
    const fetchMock = vi.mocked(fetch);
    const defaultImplementation = fetchMock.getMockImplementation()!;
    let resolveOriginalDetail!: (response: Response) => void;
    fetchMock.mockImplementation((input, init) => {
      if (String(input).endsWith(`/jobs/${originalJob.job_id}`) && !init?.method) return new Promise<Response>((resolve) => { resolveOriginalDetail = resolve; });
      return defaultImplementation(input, init);
    });

    const user = userEvent.setup();
    renderApp("/runs", client);
    let selector = await screen.findByRole("combobox", { name: "Active durable job" });
    await waitFor(() => expect(resolveOriginalDetail).toBeTypeOf("function"));
    await user.selectOptions(selector, alternateJob.job_id);
    expect(await screen.findByRole("heading", { name: alternateJob.job_id })).toBeVisible();

    activeJobInventory = [refreshedJob, alternateJob];
    await client.refetchQueries({ queryKey: ["active-jobs"], exact: true });
    selector = await screen.findByRole("combobox", { name: "Active durable job" });
    await user.selectOptions(selector, refreshedJob.job_id);
    expect(await screen.findByRole("heading", { name: refreshedJob.job_id })).toBeVisible();
    expect(screen.getByRole("button", { name: "Resume" })).toBeEnabled();

    await act(async () => { resolveOriginalDetail(json(originalJob)); });
    await waitFor(() => expect(client.getQueryState(["job", originalJob.job_id])?.fetchStatus).toBe("idle"));
    expect(client.getQueryData<RunJob>(["job", originalJob.job_id])).toMatchObject({ state: "paused", updated_at: refreshedJob.updated_at });
    expect(screen.getByRole("button", { name: "Resume" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Pause" })).toBeDisabled();
  });

  it("records a late terminal control response after selection changes", async () => {
    const runningJob: RunJob = { ...executeJob, state: "running", progress: { phase: "running" }, created_at: "2030-01-01T00:00:00Z" };
    const alternateJob: RunJob = { ...executeJob, job_id: "job-34343434343434343434343434343434", state: "paused", progress: { phase: "paused" }, created_at: "2030-01-02T00:00:00Z" };
    const cancelledJob: RunJob = { ...runningJob, state: "cancelled", progress: { phase: "cancelled" }, updated_at: "2030-01-03T00:00:00Z" };
    activeJobInventory = [runningJob, alternateJob];
    window.localStorage.setItem(activeJobStorageKey, runningJob.job_id);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
    const fetchMock = vi.mocked(fetch);
    const defaultImplementation = fetchMock.getMockImplementation()!;
    let resolveCancel!: (response: Response) => void;
    fetchMock.mockImplementation((input, init) => {
      if (String(input).endsWith(`/jobs/${runningJob.job_id}/cancel`) && init?.method === "POST") return new Promise<Response>((resolve) => { resolveCancel = resolve; });
      return defaultImplementation(input, init);
    });

    const user = userEvent.setup();
    renderApp("/runs", client);
    const selector = await screen.findByRole("combobox", { name: "Active durable job" });
    expect(await screen.findByRole("heading", { name: runningJob.job_id })).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(resolveCancel).toBeTypeOf("function"));
    await user.selectOptions(selector, alternateJob.job_id);
    expect(await screen.findByRole("heading", { name: alternateJob.job_id })).toBeVisible();

    await act(async () => { resolveCancel(json(cancelledJob)); });
    await waitFor(() => expect(client.isMutating()).toBe(0));
    await waitFor(() => expect(screen.queryByRole("option", { name: new RegExp(runningJob.job_id) })).not.toBeInTheDocument());
    expect(screen.getByRole("heading", { name: alternateJob.job_id })).toBeVisible();
    expect(window.localStorage.getItem(activeJobStorageKey)).toBe(alternateJob.job_id);
  });

  it("fails closed while active-job inventory is pending or unavailable", async () => {
    const fetchMock = vi.mocked(fetch);
    const defaultImplementation = fetchMock.getMockImplementation()!;
    let resolveInventory!: (response: Response) => void;
    const pendingInventory = new Promise<Response>((resolve) => { resolveInventory = resolve; });
    fetchMock.mockImplementation((input, init) => String(input).endsWith("/jobs") ? pendingInventory : defaultImplementation(input, init));

    renderApp("/runs");
    expect(await screen.findByRole("heading", { name: "Preflight every path. Observe every decision." })).toBeVisible();
    expect(screen.getByRole("button", { name: "Run preflight" })).toBeDisabled();

    resolveInventory(new Response(JSON.stringify({ error: { code: "active_job_inventory_unavailable", message: "Inventory unavailable." } }), { status: 503, headers: { "Content-Type": "application/json" } }));
    expect(await screen.findByText(/New preflight and submission remain disabled/)).toBeVisible();
    expect(screen.getByRole("button", { name: "Run preflight" })).toBeDisabled();
  });

  it("requires a fresh post-mount inventory before trusting cached emptiness", async () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
    client.setQueryData(["active-jobs"], { schema_version: "bluefire.active-job-list.v1", jobs: [] });
    const fetchMock = vi.mocked(fetch);
    const defaultImplementation = fetchMock.getMockImplementation()!;
    let resolveInventory!: (response: Response) => void;
    const pendingInventory = new Promise<Response>((resolve) => { resolveInventory = resolve; });
    fetchMock.mockImplementation((input, init) => String(input).endsWith("/jobs") ? pendingInventory : defaultImplementation(input, init));

    renderApp("/runs", client);
    expect(await screen.findByRole("heading", { name: "Preflight every path. Observe every decision." })).toBeVisible();
    expect(screen.getByRole("button", { name: "Run preflight" })).toBeDisabled();

    resolveInventory(json({ schema_version: "bluefire.active-job-list.v1", jobs: [] }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Run preflight" })).toBeEnabled());
  });

  it("keeps a failed inventory closed after a job detail becomes terminal", async () => {
    const runningJob: RunJob = { ...executeJob, state: "running", progress: { phase: "running" } };
    const cancelledJob: RunJob = { ...runningJob, state: "cancelled", progress: { phase: "cancelled" } };
    activeJobInventory = [runningJob];
    window.localStorage.setItem(activeJobStorageKey, runningJob.job_id);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
    const fetchMock = vi.mocked(fetch);
    const defaultImplementation = fetchMock.getMockImplementation()!;
    let inventoryOutage = false;
    let terminalDetail = false;
    fetchMock.mockImplementation((input, init) => {
      const path = String(input);
      if (path.endsWith("/jobs") && inventoryOutage) return Promise.resolve(new Response(JSON.stringify({ error: { code: "active_job_inventory_unavailable", message: "Inventory unavailable." } }), { status: 503, headers: { "Content-Type": "application/json" } }));
      if (path.endsWith(`/jobs/${runningJob.job_id}`) && !init?.method && terminalDetail) return Promise.resolve(json(cancelledJob));
      return defaultImplementation(input, init);
    });

    renderApp("/runs", client);
    expect(await screen.findByRole("heading", { name: runningJob.job_id })).toBeVisible();
    inventoryOutage = true;
    await client.refetchQueries({ queryKey: ["active-jobs"], exact: true });
    expect(await screen.findByText(/New preflight and submission remain disabled/)).toBeVisible();

    terminalDetail = true;
    await client.refetchQueries({ queryKey: ["job", runningJob.job_id], exact: true });
    await waitFor(() => expect(window.localStorage.getItem(activeJobStorageKey)).toBeNull());
    expect(screen.getByRole("button", { name: "Run preflight" })).toBeDisabled();

    inventoryOutage = false;
    activeJobInventory = [];
    await client.refetchQueries({ queryKey: ["active-jobs"], exact: true });
    await waitFor(() => expect(screen.getByRole("button", { name: "Run preflight" })).toBeEnabled());
    expect(screen.queryByText(/New preflight and submission remain disabled/)).not.toBeInTheDocument();
  });

  it("clears a stored job only after fresh detail confirms it is missing", async () => {
    const staleJobId = "job-cccccccccccccccccccccccccccccccc";
    window.localStorage.setItem(activeJobStorageKey, staleJobId);
    const fetchMock = vi.mocked(fetch);
    const defaultImplementation = fetchMock.getMockImplementation()!;
    let resolveMissing!: (response: Response) => void;
    fetchMock.mockImplementation((input, init) => {
      if (String(input).endsWith(`/jobs/${staleJobId}`) && !init?.method) return new Promise<Response>((resolve) => { resolveMissing = resolve; });
      return defaultImplementation(input, init);
    });

    renderApp("/runs");
    await screen.findByRole("heading", { name: "Preflight every path. Observe every decision." });
    await waitFor(() => expect(resolveMissing).toBeTypeOf("function"));
    expect(window.localStorage.getItem(activeJobStorageKey)).toBe(staleJobId);
    expect(screen.getByRole("button", { name: "Run preflight" })).toBeDisabled();

    await act(async () => { resolveMissing(new Response(JSON.stringify({ error: { code: "job_not_found", message: "Job was not found." } }), { status: 404, headers: { "Content-Type": "application/json" } })); });
    await waitFor(() => expect(screen.getByRole("button", { name: "Run preflight" })).toBeEnabled());
    expect(window.localStorage.getItem(activeJobStorageKey)).toBeNull();
    expect(fetchMock.mock.calls.filter(([input, init]) => String(input).endsWith(`/jobs/${staleJobId}`) && !init?.method)).toHaveLength(1);
  });

  it("does not revive a cached stored job after fresh detail reports it missing", async () => {
    const staleJob: RunJob = { ...executeJob, job_id: "job-abababababababababababababababab", state: "running", progress: { phase: "running" } };
    window.localStorage.setItem(activeJobStorageKey, staleJob.job_id);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
    client.setQueryData(["job", staleJob.job_id], staleJob);
    const fetchMock = vi.mocked(fetch);
    const defaultImplementation = fetchMock.getMockImplementation()!;
    let resolveMissing!: (response: Response) => void;
    fetchMock.mockImplementation((input, init) => {
      if (String(input).endsWith(`/jobs/${staleJob.job_id}`) && !init?.method) return new Promise<Response>((resolve) => { resolveMissing = resolve; });
      return defaultImplementation(input, init);
    });

    renderApp("/runs", client);
    await screen.findByRole("heading", { name: "Preflight every path. Observe every decision." });
    await waitFor(() => expect(resolveMissing).toBeTypeOf("function"));
    expect(screen.getByRole("heading", { name: "No active job" })).toBeVisible();
    expect(screen.queryByRole("button", { name: "Pause" })).not.toBeEnabled();
    expect(screen.getByRole("button", { name: "Run preflight" })).toBeDisabled();

    await act(async () => { resolveMissing(new Response(JSON.stringify({ error: { code: "job_not_found", message: "Job was not found." } }), { status: 404, headers: { "Content-Type": "application/json" } })); });
    await waitFor(() => expect(window.localStorage.getItem(activeJobStorageKey)).toBeNull());
    expect(screen.queryByRole("heading", { name: staleJob.job_id })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Run preflight" })).toBeEnabled();
  });

  it("does not grant mutable authority to a stored nonterminal job outside controller inventory", async () => {
    window.localStorage.setItem(activeJobStorageKey, executeJob.job_id);
    const fetchMock = vi.mocked(fetch);
    const defaultImplementation = fetchMock.getMockImplementation()!;
    fetchMock.mockImplementation((input, init) => {
      if (String(input).endsWith(`/jobs/${executeJob.job_id}`) && !init?.method) return Promise.resolve(json({ ...executeJob, approval_request: executeApprovalRequest }));
      return defaultImplementation(input, init);
    });

    renderApp("/runs");
    await screen.findByRole("heading", { name: "Preflight every path. Observe every decision." });
    expect(await screen.findByText(/Mutable controls remain disabled while ownership is reconciled/)).toBeVisible();
    expect(screen.getByRole("heading", { name: "No active job" })).toBeVisible();
    expect(screen.getByRole("button", { name: "Pause" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Cancel" })).toBeDisabled();
    expect(screen.queryByRole("region", { name: "Durable Execute job approval" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Run preflight" })).toBeDisabled();
    expect(window.localStorage.getItem(activeJobStorageKey)).toBe(executeJob.job_id);
  });

  it("disables interrupted replacement while another controller job is active", async () => {
    const interruptedJob: RunJob = { ...executeJob, job_id: "job-cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", state: "interrupted", progress: { phase: "interrupted" }, approval_request: null };
    const otherJob: RunJob = { ...executeJob, job_id: "job-dedededededededededededededededede", state: "paused", progress: { phase: "paused" } };
    activeJobInventory = [otherJob];
    window.localStorage.setItem(activeJobStorageKey, interruptedJob.job_id);
    const fetchMock = vi.mocked(fetch);
    const defaultImplementation = fetchMock.getMockImplementation()!;
    fetchMock.mockImplementation((input, init) => {
      if (String(input).endsWith(`/jobs/${interruptedJob.job_id}`) && !init?.method) return Promise.resolve(json(interruptedJob));
      return defaultImplementation(input, init);
    });

    renderApp("/runs");
    expect(await screen.findByRole("heading", { name: interruptedJob.job_id })).toBeVisible();
    expect(screen.getByRole("button", { name: "Retry as replacement" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Retry as replacement" })).toHaveAttribute("title", "Retry requires a fresh empty active-job inventory");
    expect(screen.getByRole("combobox", { name: "Active durable job" })).toBeVisible();
  });

  it("does not apply cached job authority before a fresh exact detail response", async () => {
    const runningJob: RunJob = { ...executeJob, state: "running", progress: { phase: "running" } };
    activeJobInventory = [runningJob];
    window.localStorage.setItem(activeJobStorageKey, runningJob.job_id);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: 15_000 }, mutations: { retry: false } } });
    client.setQueryData(["job", runningJob.job_id], { ...executeJob, approval_request: executeApprovalRequest });
    client.setQueryData(["job-preflight", runningJob.job_id, executeApprovalRequest.approval_id], { jobId: runningJob.job_id, report: executePreflight });
    const fetchMock = vi.mocked(fetch);
    const defaultImplementation = fetchMock.getMockImplementation()!;
    let resolveDetail: (() => void) | undefined;
    fetchMock.mockImplementation((input, init) => {
      if (String(input).endsWith(`/jobs/${runningJob.job_id}`) && !init?.method) return new Promise<Response>((resolve) => { resolveDetail = () => resolve(json(runningJob)); });
      return defaultImplementation(input, init);
    });

    renderApp("/runs", client);
    await waitFor(() => expect(resolveDetail).toBeTypeOf("function"));
    expect(await screen.findByRole("button", { name: "Pause" })).toBeEnabled();
    expect(screen.queryByRole("region", { name: "Durable Execute job approval" })).not.toBeInTheDocument();

    resolveDetail!();
    await waitFor(() => expect(screen.getByRole("button", { name: "Pause" })).toBeEnabled());
    expect(screen.queryByRole("region", { name: "Durable Execute job approval" })).not.toBeInTheDocument();
  });

  it("selects every controller-owned job and resets approval inputs between jobs", async () => {
    const pausedJob: RunJob = { ...executeJob, job_id: "job-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", state: "paused", progress: { phase: "paused" }, created_at: "2030-01-02T00:00:00Z" };
    activeJobInventory = [{ ...executeJob, created_at: "2030-01-01T00:00:00Z" }, pausedJob];
    window.localStorage.setItem(activeJobStorageKey, executeJob.job_id);
    const user = userEvent.setup();

    renderApp("/runs");
    const selector = await screen.findByRole("combobox", { name: "Active durable job" });
    expect(selector).toHaveValue(executeJob.job_id);
    const approval = await screen.findByRole("checkbox", { name: /I approve this exact immutable job envelope once/ });
    const operator = screen.getByRole("textbox", { name: "Operator identity for this job" });
    await user.click(approval);
    await user.type(operator, "must-not-cross-job-boundary");

    await user.selectOptions(selector, pausedJob.job_id);
    expect(await screen.findByRole("heading", { name: pausedJob.job_id })).toBeVisible();
    expect(window.localStorage.getItem(activeJobStorageKey)).toBe(pausedJob.job_id);
    expect(screen.queryByRole("region", { name: "Durable Execute job approval" })).not.toBeInTheDocument();

    await user.selectOptions(selector, executeJob.job_id);
    expect(await screen.findByRole("heading", { name: executeJob.job_id })).toBeVisible();
    expect(await screen.findByRole("checkbox", { name: /I approve this exact immutable job envelope once/ })).not.toBeChecked();
    expect(screen.getByRole("textbox", { name: "Operator identity for this job" })).toHaveValue("");
  }, 10_000);

  it("does not apply an earlier approval result to a newly selected job", async () => {
    const secondJob: RunJob = { ...executeJob, job_id: "job-77777777777777777777777777777777", created_at: "2030-01-02T00:00:00Z" };
    activeJobInventory = [{ ...executeJob, created_at: "2030-01-01T00:00:00Z" }, secondJob];
    window.localStorage.setItem(activeJobStorageKey, executeJob.job_id);
    const fetchMock = vi.mocked(fetch);
    const defaultImplementation = fetchMock.getMockImplementation()!;
    let resolveApproval!: (response: Response) => void;
    let approvalRequested = false;
    fetchMock.mockImplementation((input, init) => {
      if (String(input).endsWith(`/jobs/${executeJob.job_id}/approval`) && init?.method === "POST") {
        approvalRequested = true;
        return new Promise<Response>((resolve) => { resolveApproval = resolve; });
      }
      return defaultImplementation(input, init);
    });

    const user = userEvent.setup();
    const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
    renderApp("/runs", client);
    const selector = await screen.findByRole("combobox", { name: "Active durable job" });
    const firstApproval = await screen.findByRole("checkbox", { name: /I approve this exact immutable job envelope once/ });
    await user.click(firstApproval);
    await user.type(screen.getByRole("textbox", { name: "Operator identity for this job" }), "operator-a");
    await user.click(screen.getByRole("button", { name: "Approve and release job" }));
    expect(approvalRequested).toBe(true);

    await user.selectOptions(selector, secondJob.job_id);
    expect(await screen.findByRole("heading", { name: secondJob.job_id })).toBeVisible();
    const secondApproval = await screen.findByRole("checkbox", { name: /I approve this exact immutable job envelope once/ });
    const secondOperator = screen.getByRole("textbox", { name: "Operator identity for this job" });
    expect(secondApproval).toBeDisabled();
    expect(secondOperator).toBeDisabled();

    resolveApproval(json({ schema_version: "bluefire.job-approval.v1", job: { ...executeJob, state: "running", progress: { phase: "running" } }, approval_request: { ...executeApprovalRequest, status: "consumed" } }));
    await waitFor(() => expect(client.isMutating()).toBe(0));
    await waitFor(() => expect(secondApproval).toBeEnabled());
    expect(secondApproval).not.toBeChecked();
    expect(secondOperator).toHaveValue("");
    expect(screen.getByRole("heading", { name: secondJob.job_id })).toBeVisible();
  });

  it("does not let an older detail response roll back a successful approval", async () => {
    const runningJob: RunJob = { ...executeJob, state: "running", progress: { phase: "running" }, approval_request: { ...executeApprovalRequest, status: "consumed" } };
    activeJobInventory = [executeJob];
    window.localStorage.setItem(activeJobStorageKey, executeJob.job_id);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
    const fetchMock = vi.mocked(fetch);
    const defaultImplementation = fetchMock.getMockImplementation()!;
    let deferNextDetail = false;
    let resolveOldDetail: (() => void) | undefined;
    fetchMock.mockImplementation((input, init) => {
      const path = String(input);
      if (path.endsWith(`/jobs/${executeJob.job_id}`) && !init?.method && deferNextDetail) {
        deferNextDetail = false;
        return new Promise<Response>((resolve) => { resolveOldDetail = () => resolve(json({ ...executeJob, approval_request: executeApprovalRequest })); });
      }
      if (path.endsWith(`/jobs/${executeJob.job_id}/approval`) && init?.method === "POST") {
        activeJobInventory = [runningJob];
        return Promise.resolve(json({ schema_version: "bluefire.job-approval.v1", job: runningJob, approval_request: runningJob.approval_request }));
      }
      return defaultImplementation(input, init);
    });

    const user = userEvent.setup();
    renderApp("/runs", client);
    const approval = await screen.findByRole("checkbox", { name: /I approve this exact immutable job envelope once/ });
    await waitFor(() => expect(approval).toBeEnabled());
    await user.click(approval);
    await user.type(screen.getByRole("textbox", { name: "Operator identity for this job" }), "operator-a");
    deferNextDetail = true;
    const oldDetailRequest = client.refetchQueries({ queryKey: ["job", executeJob.job_id], exact: true });
    await waitFor(() => expect(resolveOldDetail).toBeTypeOf("function"));

    await user.click(screen.getByRole("button", { name: "Approve and release job" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Pause" })).toBeEnabled());
    expect(screen.queryByRole("region", { name: "Durable Execute job approval" })).not.toBeInTheDocument();

    resolveOldDetail!();
    await oldDetailRequest;
    await waitFor(() => expect(screen.getByRole("button", { name: "Pause" })).toBeEnabled());
    expect(screen.queryByRole("region", { name: "Durable Execute job approval" })).not.toBeInTheDocument();
  });

  it("keeps a newer sub-millisecond detail snapshot after an older mutation response", async () => {
    const awaitingJob: RunJob = { ...executeJob, created_at: "2030-01-01T00:00:00.000001Z", updated_at: "2030-01-01T00:00:00.000050Z" };
    const alternateJob: RunJob = { ...executeJob, job_id: "job-45454545454545454545454545454545", state: "paused", progress: { phase: "paused" }, created_at: "2030-01-02T00:00:00Z", updated_at: "2030-01-02T00:00:00Z" };
    const newerDetail: RunJob = { ...awaitingJob, state: "cancelling", progress: { phase: "cancelling" }, updated_at: "2030-01-01T00:00:00.000900Z", approval_request: { ...executeApprovalRequest, status: "consumed" } };
    const olderApproval: RunJob = { ...awaitingJob, state: "running", progress: { phase: "running" }, updated_at: "2030-01-01T00:00:00.000100Z", approval_request: { ...executeApprovalRequest, status: "consumed" } };
    activeJobInventory = [awaitingJob, alternateJob];
    window.localStorage.setItem(activeJobStorageKey, awaitingJob.job_id);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
    const fetchMock = vi.mocked(fetch);
    const defaultImplementation = fetchMock.getMockImplementation()!;
    let resolveApproval!: (response: Response) => void;
    let serveNewerDetail = false;
    fetchMock.mockImplementation((input, init) => {
      const path = String(input);
      if (path.endsWith(`/jobs/${awaitingJob.job_id}/approval`) && init?.method === "POST") return new Promise<Response>((resolve) => { resolveApproval = resolve; });
      if (path.endsWith(`/jobs/${awaitingJob.job_id}`) && !init?.method && serveNewerDetail) return Promise.resolve(json(newerDetail));
      return defaultImplementation(input, init);
    });

    const user = userEvent.setup();
    renderApp("/runs", client);
    const selector = await screen.findByRole("combobox", { name: "Active durable job" });
    const approval = await screen.findByRole("checkbox", { name: /I approve this exact immutable job envelope once/ });
    await waitFor(() => expect(approval).toBeEnabled());
    await user.click(approval);
    await user.type(screen.getByRole("textbox", { name: "Operator identity for this job" }), "operator-a");
    await user.click(screen.getByRole("button", { name: "Approve and release job" }));
    await waitFor(() => expect(resolveApproval).toBeTypeOf("function"));

    serveNewerDetail = true;
    await client.refetchQueries({ queryKey: ["job", awaitingJob.job_id], exact: true });
    await waitFor(() => expect(client.getQueryData<RunJob>(["job", awaitingJob.job_id])?.state).toBe("cancelling"));
    await user.selectOptions(selector, alternateJob.job_id);
    expect(await screen.findByRole("heading", { name: alternateJob.job_id })).toBeVisible();

    await act(async () => { resolveApproval(json({ schema_version: "bluefire.job-approval.v1", job: olderApproval, approval_request: olderApproval.approval_request })); });
    await waitFor(() => expect(client.isMutating()).toBe(0));
    expect(client.getQueryData<RunJob>(["job", awaitingJob.job_id])).toMatchObject({ state: "cancelling", updated_at: newerDetail.updated_at });
    expect(screen.getByRole("heading", { name: alternateJob.job_id })).toBeVisible();
  });

  it("offers an alternate job while missing final detail is still pending", async () => {
    const sourceJob: RunJob = { ...executeJob, state: "running", progress: { phase: "running" }, created_at: "2030-01-01T00:00:00Z" };
    const alternateJob: RunJob = { ...executeJob, job_id: "job-99999999999999999999999999999999", state: "paused", progress: { phase: "paused" }, created_at: "2030-01-02T00:00:00Z" };
    const completedJob: RunJob = { ...sourceJob, state: "completed", progress: { phase: "completed", run_id: demoRuns[0]!.run_id }, result_ref: demoRuns[0]!.run_id };
    activeJobInventory = [sourceJob];
    window.localStorage.setItem(activeJobStorageKey, sourceJob.job_id);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
    const fetchMock = vi.mocked(fetch);
    const defaultImplementation = fetchMock.getMockImplementation()!;
    let deferFinalDetail = false;
    let resolveFinalDetail: (() => void) | undefined;
    fetchMock.mockImplementation((input, init) => {
      const path = String(input);
      if (path.endsWith(`/jobs/${sourceJob.job_id}`) && !init?.method && deferFinalDetail) return new Promise<Response>((resolve) => { resolveFinalDetail = () => resolve(json(completedJob)); });
      return defaultImplementation(input, init);
    });

    const user = userEvent.setup();
    renderApp("/runs", client);
    expect(await screen.findByRole("heading", { name: sourceJob.job_id })).toBeVisible();
    deferFinalDetail = true;
    activeJobInventory = [alternateJob];
    await client.refetchQueries({ queryKey: ["active-jobs"], exact: true });
    await waitFor(() => expect(resolveFinalDetail).toBeTypeOf("function"));

    const selector = await screen.findByRole("combobox", { name: "Active durable job" });
    await user.selectOptions(selector, alternateJob.job_id);
    expect(await screen.findByRole("heading", { name: alternateJob.job_id })).toBeVisible();
    resolveFinalDetail!();
    await waitFor(() => expect(window.localStorage.getItem(activeJobStorageKey)).toBe(alternateJob.job_id));
    expect(screen.getByRole("heading", { name: alternateJob.job_id })).toBeVisible();
  });

  it("does not let a late retry response replace a newly selected active job", async () => {
    const sourceJob: RunJob = { ...executeJob, job_id: "job-dddddddddddddddddddddddddddddddd", state: "running", progress: { phase: "running" }, created_at: "2030-01-01T00:00:00Z" };
    const selectedJob: RunJob = { ...executeJob, job_id: "job-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", state: "paused", progress: { phase: "paused" }, created_at: "2030-01-02T00:00:00Z" };
    const interruptedJob: RunJob = { ...sourceJob, state: "interrupted", progress: { phase: "interrupted" } };
    const replacementJob: RunJob = { ...executeJob, job_id: "job-ffffffffffffffffffffffffffffffff", created_at: "2030-01-03T00:00:00Z" };
    activeJobInventory = [sourceJob];
    window.localStorage.setItem(activeJobStorageKey, sourceJob.job_id);
    const fetchMock = vi.mocked(fetch);
    const defaultImplementation = fetchMock.getMockImplementation()!;
    let resolveRetry!: (response: Response) => void;
    let retryRequested = false;
    fetchMock.mockImplementation((input, init) => {
      const path = String(input);
      if (path.endsWith(`/jobs/${sourceJob.job_id}`) && !init?.method) {
        activeJobInventory = [];
        return Promise.resolve(json(interruptedJob));
      }
      if (path.endsWith(`/jobs/${sourceJob.job_id}/retry`) && init?.method === "POST") {
        retryRequested = true;
        return new Promise<Response>((resolve) => { resolveRetry = resolve; });
      }
      return defaultImplementation(input, init);
    });

    const user = userEvent.setup();
    const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
    renderApp("/runs", client);
    const retry = await screen.findByRole("button", { name: "Retry as replacement" });
    await client.refetchQueries({ queryKey: ["active-jobs"], exact: true });
    await waitFor(() => expect(retry).toBeEnabled());
    await user.click(retry);
    expect(retryRequested).toBe(true);

    activeJobInventory = [selectedJob];
    await client.refetchQueries({ queryKey: ["active-jobs"], exact: true });
    const selector = await screen.findByRole("combobox", { name: "Active durable job" });
    await user.selectOptions(selector, selectedJob.job_id);
    expect(await screen.findByRole("heading", { name: selectedJob.job_id })).toBeVisible();

    resolveRetry(json({ schema_version: "bluefire.job-retry.v1", retry_of_job_id: sourceJob.job_id, source_job: interruptedJob, job: replacementJob, approval_request: executeApprovalRequest, preflight: executePreflight }));
    await waitFor(() => expect(window.localStorage.getItem(activeJobStorageKey)).toBe(selectedJob.job_id));
    expect(screen.getByRole("heading", { name: selectedJob.job_id })).toBeVisible();
    expect(screen.queryByRole("heading", { name: replacementJob.job_id })).not.toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Durable Execute job approval" })).not.toBeInTheDocument();
  });

  it("keeps an active job controllable while retrying a refused approval review", async () => {
    activeJobInventory = [executeJob];
    const fetchMock = vi.mocked(fetch);
    const defaultImplementation = fetchMock.getMockImplementation()!;
    let attempts = 0;
    fetchMock.mockImplementation(async (input, init) => {
      if (String(input).endsWith("/runs/preflight") && ++attempts === 1) return json({ ...executePreflight, ready: false, status: "refused", approval_binding: null, approval_envelope: null, findings: ["Runner readiness is temporarily unavailable."] });
      return defaultImplementation(input, init);
    });

    const user = userEvent.setup();
    renderApp("/runs");
    expect(await screen.findByRole("heading", { name: executeJob.job_id })).toBeVisible();
    const retry = await screen.findByRole("button", { name: "Retry approval review" });
    expect(screen.getByRole("button", { name: "Cancel" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Approve and release job" })).toBeDisabled();

    await user.click(retry);
    expect(await screen.findByRole("checkbox", { name: /I approve this exact immutable job envelope once/ })).toBeEnabled();
    expect(attempts).toBe(2);
  });

  it("persists and imports only the strict three-field UI preference schema", async () => {
    const user = userEvent.setup();
    renderApp("/settings");
    expect(await screen.findByRole("heading", { name: "Settings" })).toBeVisible();
    await user.selectOptions(screen.getByRole("combobox", { name: "Effect mode" }), "execute");
    await user.selectOptions(screen.getByRole("combobox", { name: "AI autonomy" }), "auto");
    await user.click(screen.getByRole("button", { name: "Save settings" }));
    expect(await screen.findByText(/Preferences saved durably/)).toBeVisible();
    const call = vi.mocked(fetch).mock.calls.find(([input]) => String(input).endsWith("/settings/ui.preferences"));
    const body = JSON.parse(String((call?.[1] as RequestInit).body));
    expect(body.value).toEqual({ schema_version: UI_PREFERENCE_SCHEMA_VERSION, theme: "dark", effect_mode: "execute", autonomy: "auto" });
    expect(JSON.parse(window.localStorage.getItem("bluefire.local.run-config.v1") ?? "{}")).toEqual(body.value);

    const importInput = screen.getByLabelText("Import UI preferences file");
    await user.upload(importInput, new File([JSON.stringify({ ...body.value, profileId: "must-not-import", endpoint: "https://must-not-import.invalid" })], "authority.json", { type: "application/json" }));
    expect(await screen.findByText(/Unsupported preference fields were not applied: profileId, endpoint/)).toBeVisible();
    expect(screen.getByRole("combobox", { name: "Effect mode" })).toHaveValue("execute");

    await user.upload(importInput, new File([JSON.stringify({ schema_version: UI_PREFERENCE_SCHEMA_VERSION, theme: "light", effect_mode: "simulate", autonomy: "assist" })], "preferences.json", { type: "application/json" }));
    expect(await screen.findByText(/No authority fields were accepted/)).toBeVisible();
    expect(screen.getByRole("combobox", { name: "Effect mode" })).toHaveValue("simulate");
    expect(screen.getByRole("combobox", { name: "AI autonomy" })).toHaveValue("assist");
    await waitFor(() => expect(JSON.parse(window.localStorage.getItem("bluefire.local.run-config.v1") ?? "{}")).toEqual({ schema_version: UI_PREFERENCE_SCHEMA_VERSION, theme: "light", effect_mode: "simulate", autonomy: "assist" }));
  });

  it("follows live operating-system color changes after leaving settings without browser storage", async () => {
    const user = userEvent.setup();
    let colorSchemeListener: ((event: MediaQueryListEvent) => void) | undefined;
    const addEventListener = vi.fn((type: string, listener: EventListenerOrEventListenerObject) => {
      if (type === "change" && typeof listener === "function") {
        colorSchemeListener = listener as (event: MediaQueryListEvent) => void;
      }
    });
    const removeEventListener = vi.fn();
    vi.mocked(window.matchMedia).mockReturnValue({
      matches: false,
      media: "(prefers-color-scheme: light)",
      onchange: null,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      addEventListener,
      removeEventListener,
      dispatchEvent: vi.fn(),
    });
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => { throw new DOMException("denied", "SecurityError"); });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => { throw new DOMException("denied", "SecurityError"); });

    const view = renderApp("/settings");
    expect(await screen.findByRole("heading", { name: "Settings" })).toBeVisible();
    await user.click(screen.getByRole("button", { name: /^System/ }));

    expect(document.documentElement.dataset.theme).toBe("dark");
    expect(addEventListener).toHaveBeenCalledWith("change", expect.any(Function));
    expect(colorSchemeListener).toBeDefined();
    await user.click(screen.getByRole("link", { name: /^Scenario Builder$/ }));
    expect(await screen.findByRole("heading", { name: "Compose a typed adaptive graph" })).toBeVisible();
    act(() => colorSchemeListener!({ matches: true } as MediaQueryListEvent));
    expect(document.documentElement.dataset.theme).toBe("light");

    view.unmount();
    expect(removeEventListener).toHaveBeenCalledWith("change", colorSchemeListener);
  });

  it("reviews a server-normalized graph draft before importing it", async () => {
    const user = userEvent.setup();
    renderApp("/ai-planner");
    expect(await screen.findByRole("heading", { name: "AI Planner" })).toBeVisible();
    const objective = screen.getByRole("textbox", { name: "Experiment objective" });
    await user.clear(objective);
    await user.type(objective, "Validate a bounded registered graph");
    await user.click(screen.getByRole("button", { name: "Generate registered draft" }));
    expect(await screen.findByText("Not saved · not authorized")).toBeVisible();
    expect(screen.getByText("Normalized from registered contracts.")).toBeVisible();
    expect(screen.getAllByText("deterministic-offline.v1").length).toBeGreaterThan(0);
    const call = vi.mocked(fetch).mock.calls.find(([input]) => String(input).endsWith("/ai/drafts"));
    expect(JSON.parse(String((call?.[1] as RequestInit).body))).toMatchObject({ objective: "Validate a bounded registered graph", max_nodes: 8, max_edges: 16 });
  });

  it("keeps proposal acceptance separate from a fresh unchecked Execute approval", async () => {
    const user = userEvent.setup();
    renderApp("/ai-planner");
    expect(await screen.findByRole("heading", { name: "AI Planner" })).toBeVisible();
    await user.type(screen.getByRole("textbox", { name: "Job ID" }), proposalJob.job_id);
    expect(await screen.findByText("Bounded runtime proposal")).toBeVisible();
    await user.click(screen.getByRole("checkbox", { name: /I reviewed these exact three digests/ }));
    await user.type(screen.getByRole("textbox", { name: "Proposal reviewer identity" }), "reviewer-a");
    await user.click(screen.getByRole("button", { name: "Accept registered continuation" }));
    expect(await screen.findByText("Fresh Execute approval after proposal acceptance")).toBeVisible();
    const fresh = screen.getByRole("checkbox", { name: /I approve this exact proposal-continuation envelope once/ });
    expect(fresh).not.toBeChecked();
    expect(screen.getByRole("button", { name: "Approve and release continuation" })).toBeDisabled();
  }, 15_000);
});
