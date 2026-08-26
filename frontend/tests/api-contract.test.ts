import { afterEach, describe, expect, it, vi } from "vitest";
import { api, buildReplayPayload, buildRunPayload } from "../src/lib/api";
import { demoRuns, demoScenario } from "../src/lib/demo";
import type { RunConfiguration } from "../src/types";

const configuration: RunConfiguration = {
  mode: "execute",
  autonomy: "auto",
  provider: "openai-responses.v1",
  model: "display-only-model",
  endpoint: "https://must-not-cross.example.invalid",
  profileId: "sandbox-execute.v1",
  runnerIds: ["browser-cannot-select-runner"],
  scopeRefs: ["sandbox.workspace"],
  safetyTier: "restricted",
  approvalPolicy: "every_action",
  approved: true,
  approvedBy: "operator-a",
  maxSeconds: 45,
  maxSteps: 8,
  maxBytes: 4096,
  collectors: ["filesystem-observer"],
  detectionBackends: ["sigma"],
  cleanupPolicy: "manual",
  counterfactual: "always_preview",
  fixtureMode: true,
  actionImplementations: { place_fixture: "sandbox.fixture.create.v1" },
};

describe("control-plane request contracts", () => {
  afterEach(() => vi.unstubAllGlobals());
  it("sends exact autonomy and provider IDs without unsupported browser preferences", () => {
    const payload = buildRunPayload(demoScenario, configuration);

    expect(payload).toMatchObject({
      mode: "execute",
      autonomy: "auto",
      ai_provider_id: "openai-responses.v1",
      runner_profile_id: "sandbox-execute.v1",
      target_scope: { scope_refs: ["sandbox.workspace"] },
    });
    expect(payload.scenario).toMatchObject({ id: demoScenario.id, title: demoScenario.title });
    expect(payload.scenario.provenance).toEqual({ source: "BlueFire seeded demo", reference: demoScenario.id, license: "MIT", derived: false, notes: "Synthetic and sanitized." });
    expect(payload).not.toHaveProperty("ai_enabled");
    expect(payload).not.toHaveProperty("autonomy_level");
    expect(payload).not.toHaveProperty("provider");
    expect(payload).not.toHaveProperty("approval");
    expect(payload).not.toHaveProperty("budgets");
    expect(payload).not.toHaveProperty("collectors");
    expect(payload).not.toHaveProperty("detection_backends");
    expect(payload).not.toHaveProperty("cleanup_policy");
    expect(payload).not.toHaveProperty("counterfactual_policy");
    expect(payload.action_implementations).toEqual({ place_fixture: "sandbox.fixture.create.v1" });
  });

  it("omits action implementations entirely for Simulate", () => {
    const payload = buildRunPayload(demoScenario, { ...configuration, mode: "simulate" });
    expect(payload).not.toHaveProperty("action_implementations");
  });

  it("keeps exact replay free of variants while retaining its fresh Execute boundary", () => {
    expect(buildReplayPayload({
      strategy: "exact",
      profile: "changed-profile",
      autonomy: "auto",
      provider: "changed-provider",
      defenseChange: "ignored for exact",
      targetScope: ["sandbox.workspace"],
      approval: { confirmed: true, approved_by: "operator-a" },
      actionImplementations: { place_fixture: "sandbox.fixture.create.v1" },
    })).toEqual({ exact: true, target_scope: { scope_refs: ["sandbox.workspace"] }, approval: { confirmed: true, approved_by: "operator-a" } });
  });

  it("uses canonical replay autonomy and provider fields", () => {
    expect(buildReplayPayload({
      strategy: "swap",
      swapStep: "discover",
      swapBehavior: "sandbox.discovery.metadata.v1",
      profile: "sandbox-simulate.v1",
      autonomy: "off",
      provider: "deterministic-offline.v1",
      defenseChange: "New process policy",
    })).toEqual({
      exact: false,
      from_step_id: null,
      swap_step_id: "discover",
      swap_behavior_id: "sandbox.discovery.metadata.v1",
      runner_profile_id: "sandbox-simulate.v1",
      autonomy: "off",
      ai_provider_id: "deterministic-offline.v1",
      defense_change: "New process policy",
      parameter_overrides: null,
    });
  });

  it("binds strict parameter and Execute replay review fields", () => {
    expect(buildReplayPayload({ strategy: "parameters", parameterOverrides: { place_fixture: { record_count: 3 } }, targetScope: ["sandbox.workspace"], approval: { confirmed: true, approved_by: "operator-b" }, actionImplementations: { place_fixture: "sandbox.fixture.create.v1" } })).toMatchObject({
      exact: false,
      parameter_overrides: { place_fixture: { record_count: 3 } },
      target_scope: { scope_refs: ["sandbox.workspace"] },
      approval: { confirmed: true, approved_by: "operator-b" },
      action_implementations: { place_fixture: "sandbox.fixture.create.v1" },
    });
  });

  it("gives the synchronous replay boundary a bounded 75-second timeout", async () => {
    const timeoutSpy = vi.spyOn(window, "setTimeout");
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(demoRuns[0]), { status: 200, headers: { "Content-Type": "application/json" } })));
    await api.replay("run-source", { exact: true });
    expect(timeoutSpy).toHaveBeenCalledWith(expect.any(Function), 75_000);
    timeoutSpy.mockRestore();
  });

  it("uses the durable job submission, approval, polling, and control routes", async () => {
    const job = { schema_version: "bluefire.job.v1", job_id: "job-0123456789abcdef0123456789abcdef", kind: "scenario.run", state: "awaiting_approval", progress: { phase: "awaiting_approval" }, result_ref: null, error: null } as const;
    const fetchMock = vi.fn(async (input: RequestInfo | URL, _init?: RequestInit) => {
      void _init;
      const path = String(input);
      const payload = path.includes("/events?") ? { schema_version: "bluefire.event-page.v1", run_id: "run-test", after_sequence: 4, next_sequence: 4, has_more: false, items: [] } : path.endsWith("/runs") ? { schema_version: "bluefire.run-job-submission.v1", job, approval_request: null, preflight: null } : path.endsWith("/approval") ? { schema_version: "bluefire.job-approval.v1", job: { ...job, state: "running" }, approval_request: null } : path.endsWith("/pause") ? { ...job, state: "running" } : job;
      return new Response(JSON.stringify(payload), { status: path.endsWith("/runs") || path.endsWith("/approval") || path.endsWith("/pause") ? 202 : 200, headers: { "Content-Type": "application/json" } });
    });
    vi.stubGlobal("fetch", fetchMock);

    await api.submitRun(demoScenario, configuration);
    await api.job(job.job_id);
    await api.runEvents("run-test", 4, 100);
    await api.approveJob(job.job_id, "operator-a");
    await api.controlJob(job.job_id, "pause");

    expect(fetchMock.mock.calls.map(([input]) => String(input))).toEqual([
      "/api/v1/runs",
      `/api/v1/jobs/${job.job_id}`,
      "/api/v1/runs/run-test/events?after_sequence=4&limit=100",
      `/api/v1/jobs/${job.job_id}/approval`,
      `/api/v1/jobs/${job.job_id}/pause`,
    ]);
    const submission = JSON.parse(String((fetchMock.mock.calls[0]?.[1] as RequestInit).body));
    const approval = JSON.parse(String((fetchMock.mock.calls[3]?.[1] as RequestInit).body));
    expect(submission).not.toHaveProperty("approval");
    expect(approval).toEqual({ approved_by: "operator-a" });
  });

  it("uses exact managed-runner lifecycle routes and confirmation bodies", async () => {
    const status = { schema_version: "bluefire.runner-lifecycle-status.v1", state: "stopped", runner_id: "bluefire-rust-runner.v1", profile_id: "sandbox-execute.v1", loopback_only: true, enrollment: "active", process: "absent", runner: null, health: null } as const;
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => {
      void _input; void _init;
      return new Response(JSON.stringify(status), { status: 200, headers: { "Content-Type": "application/json" } });
    });
    vi.stubGlobal("fetch", fetchMock);

    await api.runnerStatus();
    await api.bootstrapRunner("sandbox-execute.v1", true);
    await api.startRunner("sandbox-execute.v1");
    await api.stopRunner("sandbox-execute.v1");
    await api.revokeRunner();
    await api.removeRunner("bluefire-rust-runner.v1");

    expect(fetchMock.mock.calls.map(([input]) => String(input))).toEqual([
      "/api/v1/runner",
      "/api/v1/runner/bootstrap",
      "/api/v1/runner/start",
      "/api/v1/runner/stop",
      "/api/v1/runner/revoke",
      "/api/v1/runner/remove",
    ]);
    const bodies = fetchMock.mock.calls.slice(1).map(([, init]) => JSON.parse(String((init as RequestInit).body)));
    expect(bodies).toEqual([
      { profile_id: "sandbox-execute.v1", allow_upgrade: true },
      { profile_id: "sandbox-execute.v1" },
      { profile_id: "sandbox-execute.v1" },
      {},
      { confirm_runner_id: "bluefire-rust-runner.v1" },
    ]);
  });

  it("persists secret-safe settings, versioned scenarios, and allowlisted resources", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, _init?: RequestInit) => {
      void _init;
      const path = String(input);
      const payload = path.endsWith("/settings") ? { schema_version: "bluefire.setting-list.v1", settings: [] }
        : path.endsWith("/scenario-versions") ? { schema_version: "bluefire.scenario-version.v1", scenario: { scenario_id: demoScenario.id, version: 2, digest: "digest", document: demoScenario } }
        : path.endsWith("/runner-profiles") ? { schema_version: "bluefire.resource-list.v1", kind: "runner_profile", resources: [] }
        : path.includes("/runner-profiles/") ? { schema_version: "bluefire.resource.v1", resource: { id: "local.profile.v1", status: "draft", document: { mode: "simulate" } } }
        : { schema_version: "bluefire.setting.v1", setting: { key: "ui.preferences", value: {}, updated_at: "2030-01-01T00:00:00Z" } };
      return new Response(JSON.stringify(payload), { status: 200, headers: { "Content-Type": "application/json" } });
    });
    vi.stubGlobal("fetch", fetchMock);

    await api.settings();
    await api.saveSetting("ui.preferences", { schema_version: "bluefire.ui-preferences.v1", theme: "dark", effect_mode: "simulate", autonomy: "off" });
    await api.saveScenarioVersion({ ...demoScenario, layout: { place_fixture: { x: 10, y: 20 } } });
    await api.resources("runner-profiles");
    await api.saveResource("runner-profiles", "local.profile.v1", { mode: "simulate" }, "draft");

    expect(fetchMock.mock.calls.map(([input]) => String(input))).toEqual([
      "/api/v1/settings",
      "/api/v1/settings/ui.preferences",
      "/api/v1/scenario-versions",
      "/api/v1/resources/runner-profiles",
      "/api/v1/resources/runner-profiles/local.profile.v1",
    ]);
    expect(JSON.parse(String((fetchMock.mock.calls[1]?.[1] as RequestInit).body))).toEqual({ value: { schema_version: "bluefire.ui-preferences.v1", theme: "dark", effect_mode: "simulate", autonomy: "off" } });
    const savedScenario = JSON.parse(String((fetchMock.mock.calls[2]?.[1] as RequestInit).body));
    expect(savedScenario.scenario).not.toHaveProperty("layout");
    expect(JSON.parse(String((fetchMock.mock.calls[4]?.[1] as RequestInit).body))).toEqual({ document: { mode: "simulate" }, status: "draft" });
  });

  it("uses exact runtime-resource, retry, proposal, plugin, and Detection Lab contracts", async () => {
    const review = { schema_version: "bluefire.ai-proposal-review.v1", proposal_record_id: "proposal-review-0123456789abcdef0123456789abcdef", job_id: "job-0123456789abcdef0123456789abcdef", source_run_id: "run-source", source_proposal_id: "proposal-source", state_digest: `sha256:${"1".repeat(64)}`, plan_digest: `sha256:${"2".repeat(64)}`, proposal_digest: `sha256:${"3".repeat(64)}`, status: "pending", record: {}, created_at: "2030-01-01T00:00:00Z" } as const;
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input); let payload: unknown = {};
      if (path.endsWith("/proposals")) payload = { schema_version: "bluefire.ai-proposal-review-list.v1", job_id: review.job_id, proposals: [review] };
      else if (path.includes("/proposals/")) payload = path.endsWith("/accept") ? { schema_version: "bluefire.ai-proposal-decision.v1", job: { job_id: review.job_id, state: "running", progress: {} }, proposal: { ...review, status: "accepted" } } : review;
      else if (path.endsWith("/retry")) payload = { schema_version: "bluefire.job-retry.v1", retry_of_job_id: review.job_id, source_job: {}, job: { job_id: "job-retry", state: "queued", progress: {} } };
      else if (path.endsWith("/probe")) payload = { schema_version: "bluefire.runner-probe.v1", profile_id: "local.profile.v1", version: "1.0.0", platform: "linux", actions: [], health: { state: "ready", message: "Ready" } };
      else if (path.endsWith("/detections") && init?.method === "POST") payload = { schema_version: "bluefire.detection-resource.v1", candidate: { id: "detection-test", status: "hypothesis", document: {} } };
      return new Response(JSON.stringify(payload), { status: 200, headers: { "Content-Type": "application/json" } });
    });
    vi.stubGlobal("fetch", fetchMock);

    await api.aiDraft("Validate registered graph drafting", "deterministic-offline.v1", 6, 10);
    await api.activateResource("runner-profiles", "local.profile.v1");
    await api.deactivateResource("model-providers", "provider.local.v1");
    await api.probeRunnerProfile("local.profile.v1");
    await api.saveResource("plugins", "plugin.local.v1", { schema_version: "bluefire.plugin.v1" });
    await api.activateResource("plugins", "plugin.local.v1");
    await api.retryJob(review.job_id);
    await api.proposalReviews(review.job_id);
    await api.proposalReview(review.job_id, review.proposal_record_id);
    await api.decideProposal(review.job_id, review, "reviewer", "accept");
    await api.detectionHealth();
    await api.detections();
    await api.upsertDetection({ behavior_id: "sandbox.collection.stage.v1" });
    await api.detectionAction("detection-0123456789abcdef0123", "parse", {});
    await api.cloneDetection("detection-0123456789abcdef0123", { reason: "Branch reviewed source attribution.", title: "Reviewed clone" });
    await api.tuneDetection("detection-0123456789abcdef0123", { reason: "Narrow the staged-path match.", selection: { "path|startswith": "staged/" }, logsource: { category: "file_event", product: "generic" } });
    await api.compareDetections("detection-0123456789abcdef0123", "detection-fedcba9876543210fedc");

    const paths = fetchMock.mock.calls.map(([input]) => String(input));
    expect(paths).toContain("/api/v1/ai/drafts");
    expect(paths).toContain("/api/v1/resources/runner-profiles/local.profile.v1/activate");
    expect(paths).toContain("/api/v1/resources/model-providers/provider.local.v1/deactivate");
    expect(paths).toContain("/api/v1/resources/runner-profiles/local.profile.v1/probe");
    expect(paths).toContain(`/api/v1/jobs/${review.job_id}/retry`);
    expect(paths).toContain(`/api/v1/jobs/${review.job_id}/proposals/${review.proposal_record_id}/accept`);
    expect(paths).toContain("/api/v1/detection-lab/health");
    expect(paths).toContain("/api/v1/detections/detection-0123456789abcdef0123/parse");
    expect(paths).toContain("/api/v1/detections/detection-0123456789abcdef0123/clone");
    expect(paths).toContain("/api/v1/detections/detection-0123456789abcdef0123/tune");
    expect(paths).toContain("/api/v1/detections/detection-0123456789abcdef0123/compare");
    const pluginSave = fetchMock.mock.calls.find(([input]) => String(input).endsWith("/resources/plugins/plugin.local.v1") && !(String(input).endsWith("/activate")));
    expect(JSON.parse(String((pluginSave?.[1] as RequestInit).body))).toEqual({ document: { schema_version: "bluefire.plugin.v1" } });
    const decisionCall = fetchMock.mock.calls.find(([input]) => String(input).endsWith("/accept"));
    expect(JSON.parse(String((decisionCall?.[1] as RequestInit).body))).toEqual({ decided_by: "reviewer", state_digest: review.state_digest, plan_digest: review.plan_digest, proposal_digest: review.proposal_digest });
    const draftCall = fetchMock.mock.calls.find(([input]) => String(input).endsWith("/ai/drafts"));
    expect(JSON.parse(String((draftCall?.[1] as RequestInit).body))).toEqual({ objective: "Validate registered graph drafting", provider_id: "deterministic-offline.v1", max_nodes: 6, max_edges: 10 });
    const cloneCall = fetchMock.mock.calls.find(([input]) => String(input).endsWith("/detections/detection-0123456789abcdef0123/clone"));
    const tuneCall = fetchMock.mock.calls.find(([input]) => String(input).endsWith("/detections/detection-0123456789abcdef0123/tune"));
    const compareCall = fetchMock.mock.calls.find(([input]) => String(input).endsWith("/detections/detection-0123456789abcdef0123/compare"));
    expect(JSON.parse(String((cloneCall?.[1] as RequestInit).body))).toEqual({ reason: "Branch reviewed source attribution.", title: "Reviewed clone" });
    expect(JSON.parse(String((tuneCall?.[1] as RequestInit).body))).toEqual({ reason: "Narrow the staged-path match.", selection: { "path|startswith": "staged/" }, logsource: { category: "file_event", product: "generic" } });
    expect(JSON.parse(String((compareCall?.[1] as RequestInit).body))).toEqual({ candidate_id: "detection-fedcba9876543210fedc" });
  });
});
