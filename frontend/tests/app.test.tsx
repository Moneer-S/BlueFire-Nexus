import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "../src/App";
import { demoCatalog, demoRuns, demoScenario } from "../src/lib/demo";
import { ProductProvider } from "../src/state/ProductContext";
import type { PreflightReport } from "../src/types";

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
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      if (path.endsWith("/catalog")) return json(demoCatalog);
      if (path.endsWith("/scenarios")) return json({ scenarios: [demoScenario] });
      if (path.endsWith("/scenario-versions")) return json({ schema_version: "bluefire.scenario-version-list.v1", scenarios: [] });
      if (path.includes("/resources/")) return json({ schema_version: "bluefire.resource-list.v1", kind: "test", resources: [] });
      if (path.endsWith("/settings")) return json({ schema_version: "bluefire.setting-list.v1", settings: [] });
      if (path.endsWith("/settings/ui.preferences")) return json({ schema_version: "bluefire.setting.v1", setting: { key: "ui.preferences", value: JSON.parse(String(init?.body)).value, updated_at: "2030-01-01T00:00:00Z" } });
      if (path.endsWith("/ai/drafts")) return json({ schema_version: "bluefire.ai-graph-draft-result.v1", draft_id: "ai-draft-test", saved: false, scenario: { ...demoScenario, title: "Registered draft", layout: undefined }, rationale: "Normalized from registered contracts.", assumptions: ["Operator review required."], audit: { schema_version: "bluefire.ai-graph-draft-audit.v1", unsaved: true, provider: { effective_provider_id: "deterministic-offline.v1", model: "deterministic-planner.v1", used_fallback: false }, selected_behavior_ids: demoScenario.steps.map((step) => step.behavior_id), normalization: { artifact_bindings_added: 4 }, validation: { registered_behaviors_only: true } } });
      if (path.endsWith("/runs/preflight")) return json(executePreflight);
      if (path.endsWith("/runs") && init?.method === "POST") return json({ schema_version: "bluefire.run-job-submission.v1", job: executeJob, approval_request: { approval_id: "approval-test", expires_at: "2030-01-01T00:00:00Z" }, preflight: executePreflight });
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
    await user.click(screen.getByRole("link", { name: /Research Sources/i }));
    expect(await screen.findByRole("heading", { name: "Research sources" })).toBeVisible();
    expect(screen.getByText(/Not synchronized/i)).toBeVisible();
  });

  it("exposes exactly two effect modes and three independent autonomy levels", async () => {
    renderApp("/runs");
    expect(await screen.findByRole("heading", { name: "Preflight every path. Observe every decision." })).toBeVisible();
    expect(screen.getAllByRole("radio").filter((item) => item.getAttribute("name") === "run-mode")).toHaveLength(2);
    expect(screen.getAllByRole("radio").filter((item) => item.getAttribute("name") === "autonomy")).toHaveLength(3);
    expect(screen.getByText("Profile-owned enforcement")).toBeInTheDocument();
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

  it("saves durable UI defaults without approval identity or browser endpoints", async () => {
    const user = userEvent.setup();
    renderApp("/settings");
    expect(await screen.findByRole("heading", { name: "Settings" })).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Save settings" }));
    expect(await screen.findByText(/Settings saved durably/)).toBeVisible();
    const call = vi.mocked(fetch).mock.calls.find(([input]) => String(input).endsWith("/settings/ui.preferences"));
    const body = JSON.parse(String((call?.[1] as RequestInit).body));
    expect(body.value.run_defaults).not.toHaveProperty("approved");
    expect(body.value.run_defaults).not.toHaveProperty("approvedBy");
    expect(body.value.run_defaults).not.toHaveProperty("endpoint");
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
  });
});
