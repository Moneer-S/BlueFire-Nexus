import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Link, MemoryRouter, useLocation } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { DetectionAIRevision } from "../src/components/DetectionAIRevision";
import { api } from "../src/lib/api";
import { detectionJobId, detectionProposal, readDetectionAIReceipt, settleDetectionAIReceipt, storeDetectionAIReceipt, type DetectionAIProposal, type DetectionAIReceipt } from "../src/lib/detection-ai";
import { demoRuns } from "../src/lib/demo";
import type { DetectionResource, JobRetryResult, RunJob, RunRecord } from "../src/types";

const digest = `sha256:${"a".repeat(64)}`;
const resource: DetectionResource = { id: "rule-a", kind: "detection", status: "parsed", digest, created_at: "2030-01-01", updated_at: "2030-01-01", document: { title: "Collection rule", state: "parsed", target_language: "sqlite", rule_source: "SELECT evidence_id FROM observations WHERE retained_count > 9", revision: 1 } };
const sourceRun: RunRecord = { ...structuredClone(demoRuns[0]!), run_id: "run-observed", finalized_at: "2030-01-01", mode: "execute", is_demo: false, manifest: { schema_version: "bluefire.run-manifest.v1" }, evidence: { records: [1, 2].map((id) => ({ evidence_id: `observation-${id}`, run_id: "run-observed", provenance: "observed", producer: "collector", content: { retained_count: 3 } })) } };
const provider = { provider_id: "local-model", kind: "openai_chat_completions", model: "chosen-model" };
function receipt(): DetectionAIReceipt { return { candidateId: resource.id, request: { submission_id: "01234567-89ab-4def-8123-456789abcdef", run_id: sourceRun.run_id, parent_resource_digest: digest, question: "Find the missed collection", case_role: "attack", provider_id: provider.provider_id, autonomy: "assist" } }; }
function readyJob(saved = receipt()): RunJob {
  const parent = { candidate_id: resource.id, resource_digest: digest, definition_digest: digest, target_language: "sqlite", source: resource.document.rule_source! };
  const source = { run_id: sourceRun.run_id, manifest_digest: digest, evidence_digest: digest, observed_count: 2, evidence_count: 2, excluded_provenance_counts: {} };
  const proposal: DetectionAIProposal = { schema_version: "bluefire.detection-ai-proposal.v1", proposal_digest: digest, parent, source_run: source, source: "SELECT evidence_id\nFROM observations WHERE retained_count > 0", reason: "Include smaller collections.\nTest benign cases separately.", evidence_refs: ["observation-1"], limitations: ["Development evidence only"], provider: { ...provider, usage: {} }, provider_binding_digest: digest, context_digest: digest };
  return { schema_version: "bluefire.job.v1", job_id: detectionJobId(saved.request.submission_id), kind: "detection.ai.propose", state: "completed", request: { candidate_id: saved.candidateId, submitted_request: saved.request, parent, source_run: source, observed_ids: ["observation-1", "observation-2"], application_submission_id: "11234567-89ab-4def-8123-456789abcdef" }, progress: { proposal } };
}
function LocationProbe() { return <><label>Unrelated notes<input /></label><Link to={`/detection-lab?candidate=${resource.id}&candidate_scope=registry&run=${sourceRun.run_id}&ai_job=${readyJob().job_id}`}>Review rule revision</Link><output data-testid="location">{useLocation().search}</output><Link to="/detection-lab?ai_job=job-other">Open other work</Link></>; }
function mount(options: { jobId?: string; manualEdits?: boolean; selected?: DetectionResource; client?: QueryClient } = {}) {
  const client = options.client ?? new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[`/detection-lab${options.jobId ? `?ai_job=${options.jobId}` : ""}`]}><LocationProbe /><DetectionAIRevision resource={options.selected ?? resource} sourceRun={sourceRun} providers={[provider]} defaultProvider={provider.provider_id} manualEdits={options.manualEdits ?? false} /></MemoryRouter></QueryClientProvider>);
}

it("keeps Off silent and sends one bound request only after explicit Assist selection", async () => {
  const user = userEvent.setup();
  const send = vi.spyOn(api, "suggestDetectionRevision").mockImplementation(async (_id, body) => ({ job: readyJob({ candidateId: resource.id, request: body }) }));
  vi.spyOn(api, "job").mockRejectedValue(new Error("Not yet published"));
  mount();
  await user.click(screen.getByRole("button", { name: "Open assistance" }));
  await user.type(screen.getByRole("textbox", { name: /What should this rule detect better/ }), "Find the missed collection");
  expect(screen.getByRole("button", { name: "Propose rule revision" })).toBeDisabled();
  expect(send).not.toHaveBeenCalled();
  await user.selectOptions(screen.getByLabelText("Detection AI mode"), "assist");
  await user.click(screen.getByRole("button", { name: "Propose rule revision" }));
  expect(await screen.findByRole("heading", { name: "Review the proposed rule" })).toHaveFocus();
  expect(send).toHaveBeenCalledTimes(1);
  expect(send.mock.calls[0]![1]).toMatchObject({ run_id: sourceRun.run_id, parent_resource_digest: digest, provider_id: provider.provider_id, autonomy: "assist" });
  expect(screen.getByLabelText("Original rule source")).toHaveTextContent("retained_count > 9");
  expect(screen.getByLabelText("Proposed rule source")).toHaveTextContent("retained_count > 0");
  expect(screen.getByText("2 independent observations were supplied; the proposal cites 1.")).toBeVisible();
});

it("restores an uncertain request on reload and retries the exact UUID and body", async () => {
  const saved = receipt();
  expect(storeDetectionAIReceipt(saved)).toBe(true);
  vi.spyOn(api, "job").mockRejectedValue(new Error("Not yet found"));
  const send = vi.spyOn(api, "suggestDetectionRevision").mockResolvedValue({ job: readyJob(saved) });
  mount();
  await userEvent.setup().click(await screen.findByRole("button", { name: "Retry original request" }));
  await screen.findByRole("heading", { name: "Review the proposed rule" });
  expect(send).toHaveBeenCalledWith(saved.candidateId, saved.request);
  expect(readDetectionAIReceipt()).toBeUndefined();
});

it("does not clear a receipt for a mismatched job or a failed storage removal", () => {
  const saved = receipt();
  storeDetectionAIReceipt(saved);
  const other = readyJob();
  other.request!.candidate_id = "other-rule";
  expect(settleDetectionAIReceipt(other)).toBe(false);
  vi.spyOn(Storage.prototype, "removeItem").mockImplementation(() => { throw new Error("unavailable"); });
  expect(settleDetectionAIReceipt(readyJob())).toBe(false);
  expect(readDetectionAIReceipt()).toEqual(saved);
});

it("retains the first uncertain submission against a second intent", () => {
  const saved = receipt();
  expect(storeDetectionAIReceipt(saved)).toBe(true);
  expect(storeDetectionAIReceipt({ ...saved, request: { ...saved.request, question: "A different question" } })).toBe(false);
  expect(readDetectionAIReceipt()).toEqual(saved);
});

it("allows multiline source and explanations but rejects references outside the observed context", () => {
  const job = readyJob();
  expect(detectionProposal(job)?.source).toContain("\n");
  (job.progress.proposal as DetectionAIProposal).evidence_refs = ["synthetic-event"];
  expect(detectionProposal(job)).toBeUndefined();
});

it.each(["manual edits", "changed saved revision"])("blocks acceptance for %s without hiding the original proposal", async (change) => {
  const job = readyJob();
  vi.spyOn(api, "job").mockResolvedValue(job);
  const decide = vi.spyOn(api, "decideDetectionRevision");
  mount({ jobId: job.job_id, manualEdits: change === "manual edits", selected: change === "changed saved revision" ? { ...resource, digest: `sha256:${"b".repeat(64)}` } : resource });
  await screen.findByRole("heading", { name: "Review the proposed rule" });
  await userEvent.setup().type(screen.getByLabelText("Reviewed by"), "reviewer");
  expect(screen.getByRole("button", { name: "Accept, save and evaluate" })).toBeDisabled();
  expect(screen.getByLabelText("Original rule source")).toBeVisible();
  expect(decide).not.toHaveBeenCalled();
  await userEvent.setup().click(screen.getByRole("link", { name: "Open this proposal's rule and source" }));
  const restored = new URLSearchParams(screen.getByTestId("location").textContent!);
  expect(restored.get("candidate")).toBe(resource.id);
  expect(restored.get("run")).toBe(sourceRun.run_id);
  expect(restored.get("ai_job")).toBe(job.job_id);
});

it("shows draft readiness separately from accepted application and only links confirmed persisted results", async () => {
  const user = userEvent.setup();
  const job = readyJob();
  const appliedJob: RunJob = { schema_version: "bluefire.job.v1", job_id: detectionJobId(String(job.request!.application_submission_id)), kind: "detection.ai.apply", state: "completed", result_ref: "rule-child", progress: { application: { schema_version: "bluefire.detection-ai-application.v1", proposal_job_id: job.job_id, proposal_digest: digest, candidate_id: "rule-child", evaluation_id: "evaluation-child", run_id: sourceRun.run_id, development_case: true, applied_at: "2030-01-01" } } };
  vi.spyOn(api, "job").mockImplementation(async (id) => id === job.job_id ? job : appliedJob);
  const decide = vi.spyOn(api, "decideDetectionRevision").mockImplementation(async (_id, body) => { job.progress.decision = { schema_version: "bluefire.detection-ai-decision.v1", ...body, reviewed_at: "2030-01-01" }; return { proposal_job: job, application_job: appliedJob, decision: body }; });
  mount({ jobId: job.job_id });
  await screen.findByRole("heading", { name: "Review the proposed rule" });
  expect(screen.queryByText("Revision saved and evaluated")).not.toBeInTheDocument();
  await user.type(screen.getByLabelText("Reviewed by"), "reviewer");
  await user.click(screen.getByRole("button", { name: "Accept, save and evaluate" }));
  expect(await screen.findByRole("link", { name: "Open saved revision and its evaluations" })).toHaveAttribute("href", expect.stringContaining("candidate=rule-child"));
  expect(decide).toHaveBeenCalledWith(job.job_id, { proposal_digest: digest, parent_resource_digest: digest, decision: "accept", reviewed_by: "reviewer" });
  await waitFor(() => expect(screen.getByText("Revision saved and evaluated")).toBeInTheDocument());
});

it("restores accepted work after reload without re-sending the model request", async () => {
  const job = readyJob();
  job.progress.decision = { schema_version: "bluefire.detection-ai-decision.v1", proposal_digest: digest, parent_resource_digest: digest, decision: "accept", reviewed_by: "reviewer", reviewed_at: "2030-01-01" };
  vi.spyOn(api, "job").mockImplementation(async (id) => { if (id === job.job_id) return job; throw new Error("Reply lost after decision"); });
  const send = vi.spyOn(api, "suggestDetectionRevision");
  const decide = vi.spyOn(api, "decideDetectionRevision").mockResolvedValue({ proposal_job: job, application_job: null, decision: job.progress.decision as never });
  mount({ jobId: job.job_id });
  await userEvent.setup().click(await screen.findByRole("button", { name: "Recover accepted change" }));
  expect(decide).toHaveBeenCalledWith(job.job_id, { proposal_digest: digest, parent_resource_digest: digest, decision: "accept", reviewed_by: "reviewer" });
  expect(send).not.toHaveBeenCalled();
});

it.each(["failed", "cancelled"] as const)("shows an accepted application's %s outcome and permits a new request", async (state) => {
  const job = readyJob();
  job.progress.decision = { proposal_digest: digest, parent_resource_digest: digest, decision: "accept", reviewed_by: "reviewer" };
  const application: RunJob = { ...job, job_id: detectionJobId(String(job.request!.application_submission_id)), kind: "detection.ai.apply", state, progress: { operation_error: { message: "The selected parent changed before save." } }, error: { message: "execution callback failed" } };
  vi.spyOn(api, "job").mockImplementation(async (id) => id === job.job_id ? job : application);
  mount({ jobId: job.job_id });
  expect(await screen.findByText(`Save and evaluation ${state} · no saved result confirmed`)).toBeVisible();
  expect(screen.queryByText("Change accepted · saving and evaluating")).not.toBeInTheDocument();
  expect(screen.getByText(/The selected parent changed before save/)).toBeVisible();
  expect(screen.getByRole("button", { name: "Start another request" })).toBeEnabled();
});

it("keeps a different unresolved request reachable while reviewing another proposal", async () => {
  const saved = receipt();
  storeDetectionAIReceipt(saved);
  const other = readyJob({ ...saved, request: { ...saved.request, submission_id: "21234567-89ab-4def-8123-456789abcdef" } });
  vi.spyOn(api, "job").mockImplementation(async (id) => { if (id === other.job_id) return other; throw new Error("Original request not yet found"); });
  mount({ jobId: other.job_id });
  await screen.findByRole("heading", { name: "Review the proposed rule" });
  await userEvent.setup().click(screen.getByRole("button", { name: "Resume pending request" }));
  expect(await screen.findByRole("button", { name: "Retry original request" })).toBeVisible();
  expect(screen.getByTestId("location")).toHaveTextContent(detectionJobId(saved.request.submission_id));
  expect(readDetectionAIReceipt()).toEqual(saved);
});

it("does not let a late retry response replace the user's newer job navigation", async () => {
  const original: RunJob = { ...readyJob(), state: "interrupted", progress: {} };
  const other = { ...readyJob(), job_id: "job-other" };
  vi.spyOn(api, "job").mockImplementation(async (id) => id === original.job_id ? original : other);
  let resolve!: (result: JobRetryResult) => void;
  vi.spyOn(api, "retryJob").mockImplementation(() => new Promise((done) => { resolve = done; }));
  mount({ jobId: original.job_id });
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Retry interrupted work" }));
  await user.click(screen.getByRole("link", { name: "Open other work" }));
  await screen.findByRole("heading", { name: "Review the proposed rule" });
  await act(async () => resolve({ schema_version: "bluefire.job-retry.v1", retry_of_job_id: original.job_id, source_job: original, job: { ...original, job_id: "job-retry", state: "running", request: { ...original.request, retry_of_job_id: original.job_id } } }));
  expect(screen.getByTestId("location")).toHaveTextContent("ai_job=job-other");
});

it("opens and focuses an explicit AI review handoff in the already mounted lab", async () => {
  const job = readyJob();
  vi.spyOn(api, "job").mockResolvedValue(job);
  const send = vi.spyOn(api, "suggestDetectionRevision");
  const decide = vi.spyOn(api, "decideDetectionRevision");
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  mount({ client, manualEdits: true });
  const user = userEvent.setup();
  expect(screen.getByRole("button", { name: "Open assistance" })).toHaveAttribute("aria-expanded", "false");
  await user.click(screen.getByRole("link", { name: "Review rule revision" }));
  const heading = await screen.findByRole("heading", { name: "Review the proposed rule" });
  expect(heading).toBeVisible();
  expect(heading).toHaveFocus();
  await user.type(screen.getByRole("textbox", { name: "Unrelated notes" }), "Keep my draft");
  await user.click(screen.getByRole("link", { name: "Review rule revision" }));
  expect(heading).toHaveFocus();
  expect(screen.getByText(/There are unsaved manual edits/)).toBeVisible();
  expect(screen.getByRole("button", { name: "Accept, save and evaluate" })).toBeDisabled();
  await user.click(screen.getByRole("button", { name: "Hide assistance" }));
  await user.type(screen.getByRole("textbox", { name: "Unrelated notes" }), "Keep my focus");
  await act(async () => { await client.refetchQueries({ queryKey: ["job", job.job_id], exact: true }); });
  expect(screen.getByRole("button", { name: "Resume AI work" })).toHaveAttribute("aria-expanded", "false");
  expect(screen.getByRole("textbox", { name: "Unrelated notes" })).toHaveFocus();
  await user.click(screen.getByRole("link", { name: "Review rule revision" }));
  expect(await screen.findByRole("heading", { name: "Review the proposed rule" })).toHaveFocus();
  expect(screen.getByRole("button", { name: "Accept, save and evaluate" })).toBeDisabled();
  expect(send).not.toHaveBeenCalled();
  expect(decide).not.toHaveBeenCalled();
});

it("keeps unrelated receipt restoration closed and does not focus its background proposal", async () => {
  storeDetectionAIReceipt(receipt());
  let resolve!: (job: RunJob) => void;
  vi.spyOn(api, "job").mockImplementation(() => new Promise(done => { resolve = done; }));
  mount({ selected: { ...resource, id: "another-rule" } });
  const user = userEvent.setup();
  await user.type(screen.getByRole("textbox", { name: "Unrelated notes" }), "Other rule edits");
  await waitFor(() => expect(resolve).toBeTypeOf("function"));
  await act(async () => { resolve(readyJob()); });
  expect(screen.getByRole("button", { name: "Resume AI work" })).toHaveAttribute("aria-expanded", "false");
  expect(screen.queryByRole("heading", { name: "Review the proposed rule" })).not.toBeInTheDocument();
  expect(screen.getByRole("textbox", { name: "Unrelated notes" })).toHaveFocus();
  await user.click(screen.getByRole("link", { name: "Review rule revision" }));
  expect(await screen.findByRole("heading", { name: "Review the proposed rule" })).toHaveFocus();
});

it("preserves a manual close while an explicit linked proposal is still loading", async () => {
  let resolve!: (job: RunJob) => void;
  vi.spyOn(api, "job").mockImplementation(() => new Promise(done => { resolve = done; }));
  mount();
  const user = userEvent.setup();
  await user.click(screen.getByRole("link", { name: "Review rule revision" }));
  await user.click(await screen.findByRole("button", { name: "Hide assistance" }));
  await user.type(screen.getByRole("textbox", { name: "Unrelated notes" }), "Still editing");
  await act(async () => { resolve(readyJob()); });
  expect(screen.getByRole("button", { name: "Resume AI work" })).toHaveAttribute("aria-expanded", "false");
  expect(screen.queryByRole("heading", { name: "Review the proposed rule" })).not.toBeInTheDocument();
  expect(screen.getByRole("textbox", { name: "Unrelated notes" })).toHaveFocus();
});
