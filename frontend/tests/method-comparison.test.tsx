import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Link, MemoryRouter, useLocation, useSearchParams } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { MethodComparison } from "../src/components/MethodComparison";
import { api, type ReplayPreparation } from "../src/lib/api";
import { demoCatalog, demoRuns, demoScenario } from "../src/lib/demo";
import { matchesMethodPending, methodComparisonLink, methodJobId, methodProposal, readMethodPending, settleMethodPending, storeMethodPending, type MethodContext, type MethodPending, type MethodProposal } from "../src/lib/method-comparison";
import type { DetectionResource, RunJob } from "../src/types";

const digest = `sha256:${"a".repeat(64)}`;
const source = { ...demoRuns[0]!, run_id: "run-owned", mode: "execute" as const };
const provider = { provider_id: "local-method-model", kind: "openai_chat_completions", model: "chosen-model" };
const detector: DetectionResource = { kind: "detections", id: "rule-owned", digest, status: "parsed", created_at: "2030-01-01", updated_at: "2030-01-01", document: { title: "Observed collection", revision: 2, target_language: "sqlite", state: "parsed", rule_source: "SELECT fixture_id FROM logs" } };
const context: MethodContext = { schema_version: "bluefire.method-comparison-context.v1", source_binding_digest: digest, source_run: { run_id: source.run_id, mode: "execute", finalized_at: "2030-01-01", manifest_digest: digest, evidence_digest: digest, observed_records_digest: digest, observed_count: 1, evidence_count: 2, excluded_provenance_counts: { executed: 1 } }, options: [{ option_id: "method-archive", step_id: "collect", behavior_from: "records.v1", behavior_to: "archive.v1", title_from: "Record collection", title: "Whole-file collection" }], replay_extent: "full", replay_autonomy: "off" };
const childSubmission = "11234567-89ab-4def-8123-456789abcdef";
function saved(): MethodPending { return { sourceId: source.run_id, request: { submission_id: "01234567-89ab-4def-8123-456789abcdef", source_binding_digest: digest, selected_step_id: "collect", candidate_id: detector.id, candidate_resource_digest: digest, question: "Does the rule detect the other collection method?", source_case_role: "attack", provider_id: provider.provider_id, autonomy: "assist" } }; }
function proposalJob(pending = saved()): RunJob {
  const payload = { exact: false, swap_step_id: "collect", swap_behavior_id: "archive.v1", autonomy: "off", target_scope: { scope_refs: ["sandbox.workspace"] } };
  const prepared: ReplayPreparation = { schema_version: "bluefire.replay-preparation.v1", preparation_id: "replay-preparation-bound", preparation_context: {}, binding: { source: { run_id: source.run_id }, replay_request: payload }, replay_request: payload, replay_extent: "full", scenario: demoScenario, lineage: {}, effects_started: false, approval_created: false, preflight: { ready: false, status: "approval_required" } };
  const boundDetector = { candidate_id: detector.id, resource_digest: digest, definition_digest: digest, target_language: "sqlite" };
  const option = context.options[0]!;
  const proposal: MethodProposal = { schema_version: "bluefire.method-comparison-proposal.v1", proposal_digest: digest, source_run: context.source_run, detector: boundDetector, option_id: option.option_id, option, replay_preparation: prepared, reason: "Test the same records through another method.\nRetain independent limitations.", evidence_refs: ["observed-1"], limitations: ["Owned test fixture"], comparison_limitations: ["Exploratory comparison, not independent validation."], provider: { ...provider, usage: {} }, scope: { scope_refs: ["sandbox.workspace"] }, profile: { id: "sandbox-execute.v1" }, changes: { step_id: "collect", behavior: { from: "records.v1", to: "archive.v1" }, runtime_autonomy: { from: "assist", to: "off" } }, replay_extent: "full", replay_autonomy: "off" };
  return { schema_version: "bluefire.job.v1", job_id: methodJobId(pending.request.submission_id), kind: "replay.ai.propose", state: "completed", request: { source_run_id: source.run_id, submitted_request: pending.request, source_run: context.source_run, detector: boundDetector, options: [{ ...option, replay_preparation: prepared }], replay_submission_id: childSubmission }, progress: { proposal } };
}
function replayJob(parent: RunJob): RunJob { return { schema_version: "bluefire.job.v1", job_id: methodJobId(childSubmission), kind: "scenario.replay", state: "awaiting_approval", request: { source_run_id: source.run_id, method_comparison: { proposal_job_id: parent.job_id, proposal_digest: digest } }, progress: {} }; }
function Harness() { const [params] = useSearchParams(); return <><output aria-label="Current route">{useLocation().search}</output><Link to={`/compare?source=run-other${params.get("method_job") ? `&method_job=${params.get("method_job")}` : ""}`}>Choose another source</Link><MethodComparison sourceId={params.get("source") ?? ""} runs={[source]} catalog={{ ...demoCatalog, ai: { ...demoCatalog.ai, active_provider: provider.provider_id, providers: [provider] } }} /></>; }
function mount(initial?: RunJob, child?: RunJob) {
  vi.spyOn(api, "methodComparisonContext").mockResolvedValue(context);
  vi.spyOn(api, "detections").mockResolvedValue({ schema_version: "v1", candidates: [detector] });
  const jobs = new Map([initial, child].filter((item): item is RunJob => Boolean(item)).map((job) => [job.job_id, job]));
  vi.spyOn(api, "job").mockImplementation(async (id) => { const job = jobs.get(id); if (!job) throw new Error("Not found"); return structuredClone(job); });
  const send = vi.spyOn(api, "suggestMethodComparison").mockImplementation(async (sourceId, request) => { const job = proposalJob({ sourceId, request }); jobs.set(job.job_id, job); return { job }; });
  const effect = vi.spyOn(api, "submitReplay");
  const approve = vi.spyOn(api, "approveJob");
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[`/compare?source=${source.run_id}${initial ? `&method_job=${initial.job_id}` : ""}`]}><Harness /></MemoryRouter></QueryClientProvider>);
  return { user: userEvent.setup(), send, effect, approve, jobs };
}

it("sends no model request in Off and preserves the full bounded Assist intent", async () => {
  const { user, send, effect, approve } = mount();
  await user.click(screen.getByRole("button", { name: "Set up method test" }));
  await user.selectOptions(await screen.findByLabelText("Step to vary"), "collect");
  await user.selectOptions(screen.getByLabelText("Saved rule to evaluate"), detector.id);
  await user.type(screen.getByLabelText("Question for this method test"), "Compare collection methods");
  expect(screen.getByRole("button", { name: "Propose method test" })).toBeDisabled();
  expect(send).not.toHaveBeenCalled();
  await user.selectOptions(screen.getByLabelText("Method AI mode"), "assist");
  await user.click(screen.getByRole("button", { name: "Propose method test" }));
  expect(await screen.findByRole("heading", { name: "Review the method change" })).toHaveFocus();
  expect(send).toHaveBeenCalledOnce();
  expect(send.mock.calls[0]).toEqual([source.run_id, expect.objectContaining({ autonomy: "assist", selected_step_id: "collect", candidate_id: detector.id, candidate_resource_digest: digest, source_binding_digest: digest })]);
  expect(screen.getByText(/Assist → Off/)).toBeVisible();
  expect(effect).not.toHaveBeenCalled(); expect(approve).not.toHaveBeenCalled();
});

it("accepts the exact reviewed method and hands Execute to separate approval", async () => {
  const parent = proposalJob(), child = replayJob(parent);
  const { user, jobs, effect, approve } = mount(parent);
  const decide = vi.spyOn(api, "decideMethodComparison").mockImplementation(async (_id, body) => { const updated = structuredClone(parent); updated.progress.decision = body; jobs.set(parent.job_id, updated); jobs.set(child.job_id, child); return { proposal_job: updated, replay_job: child, decision: body }; });
  await screen.findByRole("heading", { name: "Review the method change" });
  expect(screen.getByRole("button", { name: "Accept method and prepare approval" })).toBeDisabled();
  await user.type(screen.getByLabelText("Method reviewed by"), "reviewer");
  await user.click(screen.getByRole("button", { name: "Accept method and prepare approval" }));
  expect(await screen.findByRole("link", { name: "Review and approve this replay" })).toHaveAttribute("href", `/runs?job=${child.job_id}`);
  expect(decide).toHaveBeenCalledWith(parent.job_id, { proposal_digest: digest, decision: "accept", reviewed_by: "reviewer" });
  expect(effect).not.toHaveBeenCalled(); expect(approve).not.toHaveBeenCalled();
});

it("restores the same accepted Auto operation without another model call or approval", async () => {
  const parent = proposalJob({ ...saved(), request: { ...saved().request, autonomy: "auto" } });
  parent.progress.decision = { proposal_digest: digest, decision: "accept", reviewed_by: "policy", basis: "auto_policy" };
  const { send, approve } = mount(parent, replayJob(parent));
  expect(await screen.findByRole("link", { name: "Review and approve this replay" })).toBeVisible();
  expect(screen.queryByLabelText("Method reviewed by")).not.toBeInTheDocument();
  expect(send).not.toHaveBeenCalled(); expect(approve).not.toHaveBeenCalled();
});

it("retains an uncertain request and retries the original identity after reload", async () => {
  const pending = saved(); storeMethodPending(pending);
  const { user, send } = mount();
  await user.click(await screen.findByRole("button", { name: "Retry original method request" }));
  await screen.findByRole("heading", { name: "Review the method change" });
  expect(send).toHaveBeenCalledWith(pending.sourceId, pending.request);
  expect(readMethodPending()).toBeUndefined();
});

it("keeps the proposal visible but blocks acceptance after source navigation", async () => {
  const { user } = mount(proposalJob());
  await screen.findByRole("heading", { name: "Review the method change" });
  await user.type(screen.getByLabelText("Method reviewed by"), "reviewer");
  await user.click(screen.getByRole("link", { name: "Choose another source" }));
  expect(screen.getByRole("heading", { name: "Review the method change" })).toBeVisible();
  expect(screen.getByRole("button", { name: "Accept method and prepare approval" })).toBeDisabled();
  await user.click(screen.getByRole("link", { name: "Open the bound source and method test" }));
  await waitFor(() => expect(screen.getByRole("button", { name: "Accept method and prepare approval" })).toBeEnabled());
});

it("recovers analysis against a retained child without replaying effects", async () => {
  const parent = proposalJob(), child = replayJob(parent);
  parent.progress.decision = { proposal_digest: digest, decision: "accept", reviewed_by: "reviewer" };
  child.state = "failed"; child.result_ref = "run-child"; child.error = { message: "Analysis interrupted" };
  parent.progress.replay_result = { replay_job_id: child.job_id, source: { ...context.source_run, run_id: "run-child" } };
  const { user, effect, send } = mount(parent, child);
  const recovered: RunJob = { schema_version: "bluefire.job.v1", job_id: "job-2123456789ab4def8123456789abcdef", kind: "replay.comparison.recover", state: "running", request: { proposal_job_id: parent.job_id, replay_job_id: child.job_id, retry_of_job_id: child.job_id }, progress: {} };
  const retry = vi.spyOn(api, "retryJob").mockResolvedValue({ schema_version: "bluefire.job-retry.v1", retry_of_job_id: child.job_id, source_job: child, job: recovered, approval_request: null, preflight: null });
  await user.click(await screen.findByRole("button", { name: "Recover comparison only" }));
  expect(await screen.findByText("Evaluating the retained runs")).toBeVisible();
  expect(retry).toHaveBeenCalledWith(child.job_id);
  expect(effect).not.toHaveBeenCalled(); expect(send).not.toHaveBeenCalled();
});

it("does not call a live progress handle a finalized replay", async () => {
  const parent = proposalJob(), child = replayJob(parent);
  parent.progress.decision = { proposal_digest: digest, decision: "accept", reviewed_by: "reviewer" };
  child.state = "running"; child.progress.run_id = "run-still-active";
  mount(parent, child);
  await screen.findByRole("link", { name: "Open saved replay job" });
  expect(screen.queryByText(/The finalized replay is retained/)).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Recover comparison only" })).not.toBeInTheDocument();
});

it("preserves unrelated or corrupt pending receipts and rejects mismatched response identities", () => {
  const pending = saved(); expect(storeMethodPending(pending)).toBe(true);
  expect(storeMethodPending({ ...pending, request: { ...pending.request, question: "Another intent" } })).toBe(false);
  const wrong = proposalJob(); wrong.request!.source_run_id = "another-run";
  expect(matchesMethodPending(wrong, pending)).toBe(false); expect(settleMethodPending(wrong)).toBe(false);
  sessionStorage.setItem("bluefire.method-comparison.pending.v1", "corrupt");
  expect(storeMethodPending(pending)).toBe(false);
});

it("rejects substituted prepared methods while accepting a multiline rationale", () => {
  const parent = proposalJob(); expect(methodProposal(parent)).toBeDefined();
  const proposal = structuredClone(parent.progress.proposal as MethodProposal);
  proposal.option.behavior_to = "unreviewed-method"; parent.progress.proposal = proposal;
  expect(methodProposal(parent)).toBeUndefined();
});

it("returns method-owned replay recovery to the same Compare operation", () => {
  const parent = proposalJob(), child = replayJob(parent);
  const path = methodComparisonLink(child)!;
  expect(new URLSearchParams(path.split("?")[1]).get("method_job")).toBe(parent.job_id);
  expect(new URLSearchParams(path.split("?")[1]).get("source")).toBe(source.run_id);
  expect(methodComparisonLink({ ...child, request: {} })).toBeUndefined();
});
