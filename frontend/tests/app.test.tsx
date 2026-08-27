import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "../src/App";
import { demoCatalog, demoRuns, demoScenario } from "../src/lib/demo";
import { ProductProvider, UI_PREFERENCE_SCHEMA_VERSION } from "../src/state/ProductContext";
import type { ComparisonResponse, DetectionComparisonResponse, DetectionResource, PreflightReport, PublicBaselineReference } from "../src/types";

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
const executeJob = { schema_version: "bluefire.job.v1", job_id: "job-0123456789abcdef0123456789abcdef", kind: "scenario.run", state: "awaiting_approval", request: {}, progress: { phase: "awaiting_approval" }, result_ref: null, error: null } as const;
const proposalJob = { ...executeJob, job_id: "job-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", progress: { phase: "awaiting_approval", approval_kind: "ai_proposal", proposal_record_id: "proposal-review-0123456789abcdef0123456789abcdef" } } as const;
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

function renderApp(path = "/") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<QueryClientProvider client={client}><ProductProvider><MemoryRouter initialEntries={[path]}><App /></MemoryRouter></ProductProvider></QueryClientProvider>);
}

describe("product application", () => {
  beforeEach(() => {
    window.localStorage.clear();
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
      if (path.endsWith("/runs") && init?.method === "POST") return json({ schema_version: "bluefire.run-job-submission.v1", job: executeJob, approval_request: { approval_id: "approval-test", expires_at: "2030-01-01T00:00:00Z" }, preflight: executePreflight });
      if (path.endsWith("/comparisons")) return json(richComparison);
      const runDetailMatch = path.match(/\/runs\/([^/?]+)$/);
      if (runDetailMatch) {
        const runId = decodeURIComponent(runDetailMatch[1]!);
        const run = demoRuns.find((item) => item.run_id === runId);
        if (run) return json(run);
      }
      if (path.endsWith("/proposals")) return json({ schema_version: "bluefire.ai-proposal-review-list.v1", job_id: proposalJob.job_id, proposals: [proposalReview] });
      if (path.endsWith("/accept")) return json({ schema_version: "bluefire.ai-proposal-decision.v1", job: { ...proposalJob, progress: { phase: "awaiting_approval", approval_kind: "ai_proposal_execute", proposal_record_id: proposalReview.proposal_record_id } }, proposal: { ...proposalReview, status: "accepted", resolution: { decision: "accepted", continuation: { execute_approval_binding_digest: "sha256:" + "4".repeat(64), selected_behavior_id: "endpoint.discovery.system.v1" } } }, approval_request: { approval_id: "approval-fresh", state_digest: "sha256:" + "5".repeat(64), plan_digest: "sha256:" + "6".repeat(64), target_scope_digest: "sha256:" + "7".repeat(64), profile_id: "sandbox-execute.v1", maximum_tier: "controlled", expires_at: "2030-01-01T00:00:00Z" } });
      if (path.includes("/proposals/")) return json(proposalReview);
      if (path.includes(`/jobs/${proposalJob.job_id}`)) return json(proposalJob);
      if (path.includes("/jobs/")) return json(executeJob);
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
