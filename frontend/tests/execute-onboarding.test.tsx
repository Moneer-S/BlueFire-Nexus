import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { GUIDED_EXECUTE_PROFILE_ID, GUIDED_EXECUTE_SCENARIO_ID, isCompletedGuidedExecuteRun } from "../src/components/ExecuteOnboarding";
import { demoCatalog, demoScenario } from "../src/lib/demo";
import { RunsPage } from "../src/pages/Runs";
import { ProductProvider } from "../src/state/ProductContext";
import type { CatalogResponse, PreflightReport, RunJob, RunRecord, RunnerLifecycleStatus, RunnerProfile, Scenario } from "../src/types";

function json(value: unknown) {
  return new Response(JSON.stringify(value), { status: 200, headers: { "Content-Type": "application/json" } });
}

const baseExecuteProfile = demoCatalog.runner_profiles.find((profile) => profile.id === "sandbox-execute.v1")!;
const guidedProfile: RunnerProfile = {
  ...baseExecuteProfile,
  id: GUIDED_EXECUTE_PROFILE_ID,
  scope: ["sandbox.workspace"],
  network_allowlist: [],
  safety_tiers: ["safe", "restricted"],
  budgets: { max_steps: 4, max_seconds: 30, max_artifacts: 16, max_bytes: 1_048_576 },
};
const catalog: CatalogResponse = { ...demoCatalog, runner_profiles: [...demoCatalog.runner_profiles, guidedProfile] };
const guidedScenario: Scenario = {
  ...structuredClone(demoScenario),
  id: GUIDED_EXECUTE_SCENARIO_ID,
  title: "Restricted Persistence Detection Canary",
  purpose: "Write one fixed non-executable marker inside the bound sandbox workspace, observe it independently, then clean it up.",
};
const envelopeBehavior = demoCatalog.behaviors.find((item) => item.execution_state === "action")!;
const envelopeAction = demoCatalog.actions.find((item) => item.id === envelopeBehavior.action_ids[0])!;
const preflight: PreflightReport = {
  ready: false,
  status: "approval_required",
  runner_profile: GUIDED_EXECUTE_PROFILE_ID,
  autonomy: "off",
  scope: { scope_refs: ["sandbox.workspace"] },
  safety_tier: "restricted",
  approval: "required",
  cleanup: { policy: "always", action_id: "sandbox.cleanup.v1" },
  collectors: ["collector.filesystem.sandbox.v1"],
  plan: { mode: "execute", runner_profile_id: GUIDED_EXECUTE_PROFILE_ID, steps: [{ step_id: "place_fixture", behavior_id: envelopeBehavior.id, action_id: envelopeAction.id, parameters: {}, inputs: {}, expected_outputs: ["workspace"], required_capabilities: envelopeAction.capabilities }], edges: [] },
  approval_binding: { state_digest: "state-guided", plan_digest: "plan-guided", target_scope_digest: "scope-guided", profile_id: GUIDED_EXECUTE_PROFILE_ID, maximum_tier: "restricted" },
  approval_envelope: { schema_version: "bluefire.approval-envelope.v1", scenario_id: GUIDED_EXECUTE_SCENARIO_ID, envelope_digest: "envelope-guided", steps: [{ step_id: "place_fixture", options: [{ behavior_id: envelopeBehavior.id, is_primary: true, contract_digest: "behavior-guided", contract: envelopeBehavior as unknown as Record<string, unknown>, resolved_parameters: {}, actions: [{ action_id: envelopeAction.id, contract_digest: "action-guided", contract: envelopeAction as unknown as Record<string, unknown> }] }] }] },
};

const unbootstrapped: RunnerLifecycleStatus = { schema_version: "bluefire.runner-lifecycle-status.v1", state: "unbootstrapped", runner_id: "bluefire-rust-runner.v1", profile_id: null, loopback_only: true, enrollment: "absent", process: "absent", runner: null, health: null };
const stopped: RunnerLifecycleStatus = { ...unbootstrapped, state: "stopped", profile_id: GUIDED_EXECUTE_PROFILE_ID, enrollment: "active" };
const ready: RunnerLifecycleStatus = { ...stopped, state: "ready", process: "authenticated", health: { transport: "mutual-tls-loopback", tls: "TLSv1.3", accepting_execute: true } };
const approvalRequest = { approval_id: "approval-guided", status: "pending", expires_at: "2030-01-01T00:05:00Z", ...preflight.approval_binding! };
const awaitingJob: RunJob = { schema_version: "bluefire.job.v1", job_id: "job-guided-0123456789abcdef01234567", kind: "scenario.run", state: "awaiting_approval", request: { approval_request_id: approvalRequest.approval_id }, progress: { phase: "awaiting_approval" }, result_ref: null, error: null, created_at: "2030-01-01T00:00:00Z", updated_at: "2030-01-01T00:00:00Z" };
const completedRun: RunRecord = {
  schema_version: "bluefire.run.v1",
  run_id: "run-20300101T000001Z-guided0123456789",
  scenario_id: GUIDED_EXECUTE_SCENARIO_ID,
  runner_profile_id: GUIDED_EXECUTE_PROFILE_ID,
  mode: "execute",
  status: "completed",
  finalized_at: "2030-01-01T00:00:02Z",
  objective_reached: true,
  steps: [{ step_id: "place_fixture", status: "success" }, { step_id: "cleanup", status: "success" }],
  evidence: { records: [{ provenance: "executed", producer: "bluefire-rust-runner", content: { artifact_type: "runner_result" } }, { provenance: "observed", producer: "collector.filesystem.sandbox.v1", content: { collector_id: "collector.filesystem.sandbox.v1", artifact_type: "file_observation", path: "restricted/persistence-marker.json" } }] },
  cleanup: { attempted: true, success: true, outstanding_receipt_count: 0 },
  is_demo: false,
};

describe("guided local Execute onboarding", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("advances only through packaged runner, seeded scenario, preflight, fresh approval, and release", async () => {
    let runner = unbootstrapped;
    let job = awaitingJob;
    const calls: string[] = [];
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      if (path.endsWith("/catalog")) return json(catalog);
      if (path.endsWith("/scenarios")) return json({ scenarios: [guidedScenario] });
      if (path.endsWith("/runner/bootstrap") && init?.method === "POST") { calls.push("bootstrap"); runner = stopped; return json(runner); }
      if (path.endsWith("/runner/start") && init?.method === "POST") { calls.push("start"); runner = ready; return json(runner); }
      if (path.endsWith("/runner")) return json(runner);
      if (path.endsWith("/runs/preflight")) { calls.push("preflight"); return json(preflight); }
      if (path.endsWith("/runs") && init?.method === "POST") { calls.push("submit"); return json({ schema_version: "bluefire.run-job-submission.v1", job, approval_request: approvalRequest, preflight }); }
      if (path.endsWith(`/jobs/${job.job_id}/approval`) && init?.method === "POST") { calls.push("approve"); job = { ...job, state: "running", progress: { phase: "running" }, updated_at: "2030-01-01T00:00:01Z" }; return json({ schema_version: "bluefire.job-approval.v1", job, approval_request: { ...approvalRequest, status: "consumed" } }); }
      if (path.endsWith(`/jobs/${job.job_id}`)) { if (job.state === "running") job = { ...job, state: "completed", progress: { phase: "completed" }, result_ref: completedRun.run_id, updated_at: "2030-01-01T00:00:02Z" }; return json(job); }
      if (path.endsWith(`/runs/${completedRun.run_id}`)) return json(completedRun);
      if (path.endsWith("/runs")) return json({ runs: [] });
      throw new Error(`Unhandled test request: ${path}`);
    });
    vi.stubGlobal("fetch", fetchMock);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
    const user = userEvent.setup();
    render(<QueryClientProvider client={client}><ProductProvider><MemoryRouter><RunsPage /></MemoryRouter></ProductProvider></QueryClientProvider>);

    const guide = await screen.findByRole("region", { name: "Guided local Execute" });
    expect(guide).toBeVisible();
    expect(within(guide).getByRole("button", { name: "Verify & enroll local runner" })).toBeEnabled();
    expect(within(guide).queryByRole("button", { name: "Use seeded restricted canary" })).not.toBeInTheDocument();

    await user.click(within(guide).getByRole("button", { name: "Verify & enroll local runner" }));
    expect(await within(guide).findByRole("button", { name: "Start authenticated runner" })).toBeEnabled();
    await user.click(within(guide).getByRole("button", { name: "Start authenticated runner" }));
    expect(await within(guide).findByRole("button", { name: "Use seeded restricted canary" })).toBeEnabled();

    await user.click(within(guide).getByRole("button", { name: "Use seeded restricted canary" }));
    expect(await within(guide).findByRole("button", { name: "Run guided preflight" })).toBeEnabled();
    expect(screen.getByRole("radio", { name: /Execute/ })).toBeChecked();
    expect(screen.getByRole("combobox", { name: "Runner profile" })).toHaveValue(GUIDED_EXECUTE_PROFILE_ID);
    expect(screen.getByRole("textbox", { name: /Target scope/ })).toHaveValue("sandbox.workspace");

    await user.click(within(guide).getByRole("button", { name: "Run guided preflight" }));
    expect(await within(guide).findByRole("button", { name: "Review exact envelope" })).toBeEnabled();
    const localReview = screen.getByRole("checkbox", { name: /I reviewed this exact displayed Execute envelope/ });
    const preparedOperator = screen.getByRole("textbox", { name: /Prepared operator label/ });
    expect(localReview).toBeEnabled();
    expect(preparedOperator).toBeEnabled();
    await user.click(localReview);
    await user.type(preparedOperator, "prepared-operator");

    expect(await within(guide).findByRole("button", { name: "Create approval-gated job" })).toBeEnabled();
    await user.click(within(guide).getByRole("button", { name: "Create approval-gated job" }));
    expect(await screen.findByRole("region", { name: "Durable Execute job approval" })).toBeVisible();
    expect(within(guide).getByRole("button", { name: "Review one-time approval" })).toBeEnabled();
    expect(within(guide).queryByText("Released")).not.toBeInTheDocument();
    expect(calls).toEqual(["bootstrap", "start", "preflight", "submit"]);

    const durableReview = screen.getByRole("checkbox", { name: /I approve this exact immutable job envelope once/ });
    const durableOperator = screen.getByRole("textbox", { name: "Operator identity for this job" });
    expect(durableReview).not.toBeChecked();
    await user.click(durableReview);
    await user.type(durableOperator, "release-operator");
    await user.click(screen.getByRole("button", { name: "Approve and release job" }));

    await waitFor(() => expect(calls).toEqual(["bootstrap", "start", "preflight", "submit", "approve"]));
    expect(await screen.findByText("Released")).toBeVisible();
    await waitFor(() => expect(within(guide).getAllByText("Completed").length).toBeGreaterThanOrEqual(2));
    const submitCall = fetchMock.mock.calls.find(([input, init]) => String(input).endsWith("/runs") && init?.method === "POST");
    const submitted = JSON.parse(String(submitCall?.[1]?.body));
    expect(submitted).toMatchObject({ scenario: { id: GUIDED_EXECUTE_SCENARIO_ID }, mode: "execute", autonomy: "off", runner_profile_id: GUIDED_EXECUTE_PROFILE_ID, target_scope: { scope_refs: ["sandbox.workspace"] }, collectors: ["collector.filesystem.sandbox.v1"] });
  }, 15_000);

  it("does not mark a terminal job complete without canonical observation and cleanup proof", () => {
    const completedJob: RunJob = { ...awaitingJob, state: "completed", result_ref: completedRun.run_id, progress: { phase: "completed" } };
    expect(isCompletedGuidedExecuteRun(completedJob, completedRun)).toBe(true);
    expect(isCompletedGuidedExecuteRun(completedJob, { ...completedRun, objective_reached: false })).toBe(false);
    expect(isCompletedGuidedExecuteRun(completedJob, { ...completedRun, evidence: { records: [] } })).toBe(false);
    expect(isCompletedGuidedExecuteRun(completedJob, { ...completedRun, evidence: { records: completedRun.evidence!.records.map((record) => record.provenance === "observed" ? { ...record, content: { ...record.content, path: "some-other-file.json" } } : record) } })).toBe(false);
    expect(isCompletedGuidedExecuteRun(completedJob, { ...completedRun, evidence: { records: completedRun.evidence!.records.map((record) => record.provenance === "observed" ? { ...record, producer: "sandbox-observer.v1" } : record) } })).toBe(false);
    expect(isCompletedGuidedExecuteRun(completedJob, { ...completedRun, evidence: { records: completedRun.evidence!.records.map((record) => record.provenance === "observed" ? { ...record, content: { ...record.content, collector_id: "collector.unbound.v1" } } : record) } })).toBe(false);
    expect(isCompletedGuidedExecuteRun(completedJob, { ...completedRun, cleanup: { attempted: true, success: true, outstanding_receipt_count: 1 } })).toBe(false);
  });

  it.each([
    ["pending request ID mismatch", { ...awaitingJob, request: { approval_request_id: "approval-other" }, progress: { phase: "awaiting_approval", approval_request_id: "approval-other" } }, approvalRequest],
    ["immutable request ID conflict", { ...awaitingJob, request: { approval_request_id: "approval-other" } }, approvalRequest],
    ["progress request ID conflict", { ...awaitingJob, progress: { phase: "awaiting_approval", approval_request_id: "approval-other" } }, approvalRequest],
    ["one preflight binding field drift", awaitingJob, { ...approvalRequest, state_digest: "state-drifted" }],
  ])("keeps durable approval controls disabled for %s", async (_case, mismatchedJob, mismatchedApproval) => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      if (path.endsWith("/catalog")) return json(catalog);
      if (path.endsWith("/scenarios")) return json({ scenarios: [guidedScenario] });
      if (path.endsWith("/runner")) return json(ready);
      if (path.endsWith("/runs/preflight")) return json(preflight);
      if (path.endsWith("/runs") && init?.method === "POST") return json({ schema_version: "bluefire.run-job-submission.v1", job: mismatchedJob, approval_request: mismatchedApproval, preflight });
      if (path.endsWith(`/jobs/${mismatchedJob.job_id}`)) return json(mismatchedJob);
      if (path.endsWith("/runs")) return json({ runs: [] });
      throw new Error(`Unhandled test request: ${path}`);
    });
    vi.stubGlobal("fetch", fetchMock);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
    const user = userEvent.setup();
    render(<QueryClientProvider client={client}><ProductProvider><MemoryRouter><RunsPage /></MemoryRouter></ProductProvider></QueryClientProvider>);

    const guide = await screen.findByRole("region", { name: "Guided local Execute" });
    await user.click(await within(guide).findByRole("button", { name: "Use seeded restricted canary" }));
    await user.click(within(guide).getByRole("button", { name: "Run guided preflight" }));
    const localReview = await screen.findByRole("checkbox", { name: /I reviewed this exact displayed Execute envelope/ });
    await user.click(localReview);
    await user.type(screen.getByRole("textbox", { name: /Prepared operator label/ }), "prepared-operator");
    await user.click(await within(guide).findByRole("button", { name: "Create approval-gated job" }));

    const durableReview = await screen.findByRole("checkbox", { name: /I approve this exact immutable job envelope once/ });
    expect(durableReview).toBeDisabled();
    expect(screen.getByRole("textbox", { name: "Operator identity for this job" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Approve and release job" })).toBeDisabled();
  });

  it("discards a deferred run preflight after the intent changes", async () => {
    let resolvePreflight!: (response: Response) => void;
    const pendingPreflight = new Promise<Response>((resolve) => { resolvePreflight = resolve; });
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      if (path.endsWith("/catalog")) return json(catalog);
      if (path.endsWith("/scenarios")) return json({ scenarios: [guidedScenario] });
      if (path.endsWith("/runner")) return json(ready);
      if (path.endsWith("/runs/preflight")) return pendingPreflight;
      if (path.endsWith("/runs")) return json({ runs: [] });
      throw new Error(`Unhandled test request: ${path}`);
    });
    vi.stubGlobal("fetch", fetchMock);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
    const user = userEvent.setup();
    render(<QueryClientProvider client={client}><ProductProvider><MemoryRouter><RunsPage /></MemoryRouter></ProductProvider></QueryClientProvider>);

    const guide = await screen.findByRole("region", { name: "Guided local Execute" });
    await user.click(await within(guide).findByRole("button", { name: "Use seeded restricted canary" }));
    await user.click(within(guide).getByRole("button", { name: "Run guided preflight" }));
    const targetScope = screen.getByRole("textbox", { name: /Target scope/ });
    await user.clear(targetScope);
    await user.type(targetScope, "sandbox.changed");
    resolvePreflight(json(preflight));

    await waitFor(() => expect(screen.getByRole("button", { name: "Run preflight" })).toBeEnabled());
    expect(screen.getByRole("checkbox", { name: /I reviewed this exact displayed Execute envelope/, hidden: true })).toBeDisabled();
    expect(screen.queryByRole("region", { name: "Complete Execute approval envelope" })).not.toBeInTheDocument();
  });
});
