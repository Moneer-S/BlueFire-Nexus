import type { ComponentProps } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { CanonicalPlanReview } from "../src/components/CanonicalPlanReview";
import { ProposalReviewWorkspace } from "../src/components/ProposalReview";
import { ProviderSetup } from "../src/components/ProviderSetup";
import { api } from "../src/lib/api";
import * as approvalReview from "../src/lib/approvalReview";
import { demoCatalog, demoScenario } from "../src/lib/demo";
import { AIPlannerPage } from "../src/pages/AIPlanner";
import { ProductProvider } from "../src/state/ProductContext";
import type { AIProposalReview, RunJob } from "../src/types";

vi.mock("../src/components/ProviderSetup", () => ({ ProviderSetup: vi.fn(() => null) }));
vi.mock("../src/components/CanonicalPlanReview", async (original) => {
  const module = await original<typeof import("../src/components/CanonicalPlanReview")>();
  const { createElement } = await import("react");
  return { ...module, CanonicalPlanReview: vi.fn((props: ComponentProps<typeof module.CanonicalPlanReview>) => createElement(module.CanonicalPlanReview, props)) };
});
vi.mock("../src/components/ProposalReview", async (original) => {
  const module = await original<typeof import("../src/components/ProposalReview")>();
  return { ...module, ProposalReviewWorkspace: vi.fn(module.ProposalReviewWorkspace) };
});

function continuation() {
  const jobId = "job-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const proposalId = "proposal-review-render-boundary";
  const binding = { state_digest: "reviewed-state", plan_digest: "reviewed-plan", target_scope_digest: "reviewed-scope", profile_id: "sandbox-execute.v1", maximum_tier: "controlled" };
  const request = { approval_id: "approval-current", status: "pending", expires_at: new Date(Date.now() + 60_000).toISOString(), ...binding };
  const behavior = demoCatalog.behaviors.find((item) => item.execution_state === "action")!;
  const action = demoCatalog.actions.find((item) => item.id === behavior.action_ids[0])!;
  const job: RunJob = {
    schema_version: "bluefire.job.v1", job_id: jobId, kind: "scenario.run", state: "awaiting_approval",
    request: { approval_request_id: "approval-original" }, approval_request: request,
    progress: { approval_kind: "ai_proposal_execute", approval_request_id: request.approval_id, proposal_record_id: proposalId },
  };
  const review: AIProposalReview = {
    schema_version: "bluefire.ai-proposal-review.v1", job_id: jobId, proposal_record_id: proposalId, source_run_id: "run-original", source_proposal_id: "proposal-original",
    state_digest: "proposal-state", plan_digest: "proposal-plan", proposal_digest: "proposal-reviewed", status: "accepted", created_at: new Date().toISOString(),
    record: { proposal: { proposal_id: "proposal-original", proposal_type: "select_registered", selected_step_id: "reviewed_step", selected_behavior_id: behavior.id, selected_action_id: null, rationale: "Reviewed registered continuation" } },
    resolution: { approval_request_id: request.approval_id, continuation: { continuation_plan_digest: binding.plan_digest, execute_approval_binding_digest: "continuation-reviewed" } },
    execute_approval_review: {
      schema_version: "bluefire.continuation-approval-review.v1", job_id: jobId, proposal_record_id: proposalId, approval_request_id: request.approval_id,
      preflight: {
        ready: false, status: "approval_required", approval_binding: binding,
        plan: { mode: "execute", steps: [{ step_id: "reviewed_step", behavior_id: behavior.id, action_id: action.id }], edges: [] },
        approval_envelope: { schema_version: "bluefire.approval-envelope.v1", scenario_id: demoScenario.id, envelope_digest: "envelope-reviewed", steps: [{ step_id: "reviewed_step", options: [{ behavior_id: behavior.id, is_primary: true, contract_digest: "behavior-reviewed", contract: behavior as unknown as Record<string, unknown>, resolved_parameters: {}, actions: [{ action_id: action.id, contract_digest: "action-reviewed", contract: action as unknown as Record<string, unknown> }] }] }] },
      },
    },
  };
  return { job, review };
}

it("keeps provider and review presentation stable during typing while checking current approval expiry", async () => {
  const user = userEvent.setup();
  const { job, review } = continuation();
  const validate = vi.spyOn(approvalReview, "continuationApprovalPreflight");
  const approve = vi.spyOn(api, "approveJob");
  vi.spyOn(api, "job").mockResolvedValue(job);
  vi.spyOn(api, "proposalReviews").mockResolvedValue({ schema_version: "bluefire.ai-proposal-review-list.v1", job_id: job.job_id, proposals: [review] });
  vi.spyOn(api, "proposalReview").mockResolvedValue(review);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity, gcTime: Infinity } } });
  client.setQueryData(["catalog"], demoCatalog);
  const view = render(<QueryClientProvider client={client}><ProductProvider><MemoryRouter initialEntries={["/ai-planner?view=audit"]}><AIPlannerPage /></MemoryRouter></ProductProvider></QueryClientProvider>);
  try {
    const providerRenders = vi.mocked(ProviderSetup).mock.calls.length;
    await user.type(screen.getByRole("textbox", { name: "Job ID" }), job.job_id);
    await screen.findByRole("region", { name: "Canonical preflight plan" });
    expect(vi.mocked(ProviderSetup).mock.calls).toHaveLength(providerRenders);
    const planRenders = vi.mocked(CanonicalPlanReview).mock.calls.length;
    const proposalRenders = vi.mocked(ProposalReviewWorkspace).mock.calls.length;
    const validations = validate.mock.calls.length;
    const operator = screen.getByRole("textbox", { name: "Operator identity for fresh Execute approval" });
    const identity = "Reviewed operator";
    await user.type(operator, identity);
    expect(operator).toHaveValue(identity);
    expect(vi.mocked(ProviderSetup).mock.calls).toHaveLength(providerRenders);
    expect(vi.mocked(CanonicalPlanReview).mock.calls).toHaveLength(planRenders);
    expect(vi.mocked(ProposalReviewWorkspace).mock.calls).toHaveLength(proposalRenders);
    expect(validate.mock.calls.length - validations).toBeGreaterThanOrEqual(identity.length);

    const changedReview = structuredClone(review);
    changedReview.execute_approval_review!.preflight.approval_envelope!.steps[0]!.options[0]!.contract.title = "Updated reviewed method";
    await act(async () => { client.setQueryData(["job-proposal", job.job_id, review.proposal_record_id, job.progress.approval_request_id], changedReview); });
    await waitFor(() => expect(screen.getAllByText("Updated reviewed method").length).toBeGreaterThan(0));
    expect(vi.mocked(CanonicalPlanReview).mock.calls.length).toBeGreaterThan(planRenders);

    vi.spyOn(Date, "now").mockReturnValue(Date.parse(String(job.approval_request!.expires_at)));
    await user.type(operator, "!");
    expect(screen.getByRole("region", { name: "Canonical preflight plan" })).toBeVisible();
    expect(screen.getByRole("button", { name: "Approve and release continuation" })).toBeDisabled();
    expect(screen.getByText("Approval review expired")).toBeVisible();
    expect(approve).not.toHaveBeenCalled();
  } finally {
    view.unmount(); client.clear();
  }
});

const deadlineClients: QueryClient[] = [];
afterEach(() => { deadlineClients.splice(0).forEach((client) => client.clear()); vi.useRealTimers(); });
async function openTimedContinuation(expiresAt?: string | null) {
  vi.useFakeTimers();
  vi.setSystemTime(new Date("2030-01-01T12:00:00Z"));
  const { job, review } = continuation();
  job.approval_request!.expires_at = expiresAt === undefined ? new Date(Date.now() + 10_000).toISOString() : expiresAt;
  const deadline = Date.parse(String(job.approval_request!.expires_at));
  const approve = vi.spyOn(api, "approveJob");
  vi.spyOn(api, "job").mockResolvedValue(job);
  vi.spyOn(api, "proposalReviews").mockResolvedValue({ schema_version: "bluefire.ai-proposal-review-list.v1", job_id: job.job_id, proposals: [review] });
  vi.spyOn(api, "proposalReview").mockResolvedValue(review);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity, gcTime: Infinity, refetchOnWindowFocus: false } } });
  deadlineClients.push(client); client.setQueryData(["catalog"], demoCatalog);
  const view = render(<QueryClientProvider client={client}><ProductProvider><MemoryRouter initialEntries={["/ai-planner?view=audit"]}><AIPlannerPage/></MemoryRouter></ProductProvider></QueryClientProvider>);
  fireEvent.change(screen.getByRole("textbox", { name: "Job ID" }), { target: { value: job.job_id } });
  await act(async () => { await vi.advanceTimersByTimeAsync(200); });
  for (let turn = 0; turn < 5; turn += 1) await act(async () => { await vi.advanceTimersByTimeAsync(5); });
  expect(screen.getByRole("region", { name: "Canonical preflight plan" })).toBeVisible();
  if (expiresAt === undefined) {
    fireEvent.click(screen.getByRole("checkbox", { name: /I approve this exact proposal-continuation envelope once/ }));
    fireEvent.change(screen.getByRole("textbox", { name: "Operator identity for fresh Execute approval" }), { target: { value: "Reviewer" } });
    expect(screen.getByRole("button", { name: "Approve and release continuation" })).toBeEnabled();
  }
  return { ...view, approve, deadline, job };
}

it.each(["idle", "resume", "click"])("expires Planner approval on %s while retaining its exact review and cancellation link", async (arrival) => {
  const view = await openTimedContinuation();
  try {
    const plans = vi.mocked(CanonicalPlanReview).mock.calls.length;
    const providers = vi.mocked(ProviderSetup).mock.calls.length;
    if (arrival === "idle") await act(async () => { await vi.advanceTimersByTimeAsync(view.deadline - Date.now()); });
    else {
      // The wall clock advances while scheduled timers have not resumed.
      vi.setSystemTime(view.deadline + 1);
      if (arrival === "resume") fireEvent(window, new Event("pageshow"));
      else fireEvent.click(screen.getByRole("button", { name: "Approve and release continuation" }));
    }
    expect(screen.getByText("Approval review expired")).toBeVisible();
    expect(screen.getByRole("region", { name: "Canonical preflight plan" })).toBeVisible();
    expect(screen.getByRole("checkbox", { name: /I approve this exact proposal-continuation envelope once/ })).toBeDisabled();
    expect(screen.getByRole("textbox", { name: "Operator identity for fresh Execute approval" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Approve and release continuation" })).toBeDisabled();
    expect(screen.getByRole("link", { name: "Open this job in Runs to inspect or cancel" })).toHaveAttribute("href", `/runs?job=${view.job.job_id}`);
    expect(vi.mocked(CanonicalPlanReview).mock.calls).toHaveLength(plans);
    expect(vi.mocked(ProviderSetup).mock.calls).toHaveLength(providers);
    expect(view.approve).not.toHaveBeenCalled();
  } finally { view.unmount(); }
});

it.each([null, "not-a-deadline", "2099"])("keeps malformed Planner expiry (%s) read-only without discarding the canonical plan", async (expiresAt) => {
  const view = await openTimedContinuation(expiresAt);
  try {
    expect(screen.getByText("Approval deadline unavailable")).toBeVisible();
    expect(screen.getByRole("region", { name: "Canonical preflight plan" })).toBeVisible();
    expect(screen.getByRole("button", { name: "Approve and release continuation" })).toBeDisabled();
    expect(screen.getByRole("checkbox", { name: /I approve this exact proposal-continuation envelope once/ })).toBeDisabled();
    expect(screen.getByRole("link", { name: "Open this job in Runs to inspect or cancel" })).toHaveAttribute("href", `/runs?job=${view.job.job_id}`);
    expect(view.approve).not.toHaveBeenCalled();
  } finally { view.unmount(); }
});
