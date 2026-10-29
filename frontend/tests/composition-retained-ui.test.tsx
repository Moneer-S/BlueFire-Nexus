import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import * as Tooltip from "@radix-ui/react-tooltip";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { CompositionPage } from "../src/pages/Composition";
import { CompositionSetup } from "../src/components/CompositionReview";
import { compositionApi, type CompositionContext, type CompositionProposal } from "../src/lib/composition";
import type { CompositionEvidenceContext } from "../src/lib/composition-evidence";
import { compositionKnowledgeApi } from "../src/lib/composition-knowledge";
import { RECEIVER_RETAINED_PACK } from "../src/lib/composition-retained";
import { contextFixture, controlId, ownerId, proposalId, question, reviewFixture } from "./composition-fixture";
import { retainedFixture, retainedFreshRecoveryFixture, retainedObjectiveFixture, retainedRequestFixture, retainedReviewFixture } from "./composition-retained-fixture";

vi.mock("../src/components/CompositionGraph", () => ({ CompositionGraph: () => <div>Read-only graph</div> }));
vi.mock("../src/lib/api", () => ({ DEMO_MODE: false, request: vi.fn(), ApiError: class extends Error {}, api: { catalog: vi.fn(async () => ({ ai: { providers: [{ provider_id: "configured", kind: "openai", model: "configured-model" }] } })) } }));
const retentionChoice = () => screen.getByRole("checkbox", { name: "Keep generated results for reuse within this objective" });
const start = () => screen.getByRole("button", { name: "Start fresh attempt within grant" });
function mount(element: React.ReactNode = <CompositionPage />, path = `/composition?control=${controlId}&objective=${ownerId}&proposal=${proposalId}`) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return { client, ...render(<QueryClientProvider client={client}><Tooltip.Provider><MemoryRouter initialEntries={[path]}>{element}</MemoryRouter></Tooltip.Provider></QueryClientProvider>) };
}
beforeEach(() => {
  localStorage.clear(); const { objective, context, proposal, knowledge } = retainedFixture();
  vi.spyOn(compositionApi, "list").mockResolvedValue({ schema_version: "bluefire.composition-objective-list.v1", objectives: [{ owner_id: ownerId, title: question, status: "active", job_state: "completed" }] });
  vi.spyOn(compositionApi, "objective").mockResolvedValue(objective);
  vi.spyOn(compositionApi, "context").mockResolvedValue(context as CompositionContext);
  vi.spyOn(compositionApi, "proposal").mockResolvedValue(proposal);
  vi.spyOn(compositionKnowledgeApi, "read").mockResolvedValue(knowledge);
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

it("keeps retention off until explicitly chosen and reviews the exact new grant terms", async () => {
  const review = vi.spyOn(compositionApi, "review").mockResolvedValue(retainedReviewFixture());
  const submit = vi.fn();
  mount(<CompositionSetup control={controlId} disabled={false} onSubmit={submit} />);
  expect(retentionChoice()).not.toBeChecked();
  fireEvent.change(screen.getByLabelText("Objective question"), { target: { value: question } });
  fireEvent.click(retentionChoice());
  fireEvent.click(screen.getByRole("button", { name: "Review finite delegation" }));
  await screen.findByRole("button", { name: "Issue capability grant" });
  expect(review).toHaveBeenCalledWith(retainedRequestFixture());
  expect(screen.getByText(/sealed result remains until its source run bundle is deleted/)).toBeVisible();
  expect(screen.getByText(/Keep at most one successfully generated public JSONL result per attempt, up to 256 KiB/)).toBeVisible();
  expect(screen.getByText(/transfers can remain in task and transport records/)).toBeVisible();
  expect(screen.getByText(/Cleanup removes owned workspace files while preserving the sealed source/)).toBeVisible();
  fireEvent.change(screen.getByLabelText("Delegation reviewed by"), { target: { value: "operator" } });
  fireEvent.click(screen.getByRole("checkbox", { name: /I authorize the reviewed finite capabilities/ }));
  fireEvent.click(screen.getByRole("button", { name: "Issue capability grant" }));
  expect(submit).toHaveBeenCalledWith(expect.objectContaining({ kind: "grant", body: expect.objectContaining({ review: retainedRequestFixture() }) }));
  fireEvent.click(retentionChoice());
  expect(screen.queryByRole("button", { name: "Issue capability grant" })).not.toBeInTheDocument();
});

it("supports a new retained objective with no available source and a fresh graph", async () => {
  const objective = retainedObjectiveFixture();
  const base = contextFixture();
  const context: CompositionContext = { ...base, schema_version: "bluefire.retained-composition-proposal-context.v1", snapshot: objective.grant.document.snapshot, facts: { ...base.facts, prior_attempt_id: null }, retained_artifacts: { policy: retainedReviewFixture().retention!, availability: "none_available", available_sources: [] } };
  vi.mocked(compositionApi.objective).mockResolvedValue(objective);
  vi.mocked(compositionApi.context).mockResolvedValue(context);
  mount(<CompositionPage />, `/composition?control=${controlId}&objective=${ownerId}&pack=${RECEIVER_RETAINED_PACK}`);
  expect(await screen.findByRole("region", { name: "Available generated results" })).toHaveTextContent("No retained result is currently available");
  fireEvent.click(screen.getByRole("button", { name: "Review established graph" }));
  await waitFor(() => expect(start()).toBeEnabled());
  expect(screen.getByText(/requires separate authorization for/)).toHaveTextContent("Propose receiver graphs that keep and reuse generated results");
});

it("reopens a retained graph with readable exact source details and submits its unchanged graph", async () => {
  const { source, proposal } = retainedFixture();
  const submit = vi.spyOn(compositionApi, "submit").mockRejectedValue(new Error("Saved attempt confirmation pending"));
  mount();
  const captured = await screen.findByRole("region", { name: "Captured available results" });
  await waitFor(() => expect(start()).toBeEnabled());
  expect(screen.getAllByRole("region", { name: "Generated result kept before a later failure" })[0]).toHaveTextContent("Receiver delivery remains unknown");
  expect(screen.queryByText("Objective established")).not.toBeInTheDocument();
  const graph = screen.getByRole("region", { name: "Proposed graph steps" });
  expect(graph).toHaveTextContent("Retained result: Attempt 1 · Step stage");
  expect(graph).not.toHaveTextContent(source.source_ref);
  fireEvent.click(within(captured).getByText("Attempt 1 · Step stage · 128 bytes"));
  expect(within(captured).getByRole("link", { name: "Inspect retained source run" })).toHaveAttribute("href", `/runs/${source.run_id}`);
  expect(captured).toHaveTextContent(source.source_ref);
  expect(captured).toHaveTextContent(/does not establish current mutable access/);
  fireEvent.click(start());
  await waitFor(() => expect(submit).toHaveBeenCalledOnce());
  expect(submit.mock.calls[0]![0]).toMatchObject({ kind: "attempt", body: { proposal: proposal.proposal!.candidate, prior_attempt_id: proposal.proposal!.prior_attempt_id } });
});

it("keeps historical findings optional and restores captured retained history with its distinct purpose", async () => {
  const value = retainedFixture(true);
  vi.mocked(compositionApi.objective).mockResolvedValue(value.objective);
  vi.mocked(compositionApi.proposal).mockResolvedValue(value.proposal);
  const query = vi.spyOn(compositionApi, "evidenceContext").mockResolvedValue(value.context as CompositionEvidenceContext);
  mount();
  expect(await screen.findByRole("region", { name: "Captured historical reasoning" })).toBeInTheDocument();
  expect(screen.getByRole("checkbox", { name: "Use selected historical findings to reconsider earlier choices" })).toBeChecked();
  await waitFor(() => expect(start()).toBeEnabled());
  expect(query).toHaveBeenCalledWith(ownerId, value.prior, value.knowledge);
  expect(screen.getByText(/requires the separate model purpose/)).toHaveTextContent("Propose receiver graphs that keep and reuse generated results");
});

it("preserves captured source details after availability changes while blocking stale apply", async () => {
  const { context } = retainedFixture();
  mount();
  const captured = await screen.findByRole("region", { name: "Captured available results" });
  await waitFor(() => expect(start()).toBeEnabled());
  vi.mocked(compositionApi.context).mockResolvedValue({ ...context, schema_version: "bluefire.retained-composition-proposal-context.v1", context_digest: `sha256:${"f".repeat(64)}`, retained_artifacts: { ...context.retained_artifacts!, available_sources: [], availability: "none_available" } });
  fireEvent.click(screen.getByRole("button", { name: "Refresh available results" }));
  await waitFor(() => expect(start()).toBeDisabled());
  expect(captured).toBeInTheDocument();
  expect(await screen.findByRole("region", { name: "Available generated results" })).toHaveTextContent("No retained result is currently available");
  expect(screen.getByText("Candidate no longer matches current evidence")).toBeInTheDocument();
});

it("shows saved retained sources under closed authority without allowing another attempt", async () => {
  const { objective } = retainedFixture(); objective.grant.status = "paused";
  vi.mocked(compositionApi.objective).mockResolvedValue(objective);
  mount();
  await screen.findByRole("region", { name: "Captured available results" });
  expect(start()).toBeDisabled();
  expect(compositionApi.context).not.toHaveBeenCalled();
  expect(screen.getByRole("button", { name: "Revoke" })).toBeEnabled();
});

it("requires current availability of the exact captured source before reuse", async () => {
  const { context } = retainedFixture();
  mount();
  await screen.findByRole("region", { name: "Captured available results" });
  await waitFor(() => expect(start()).toBeEnabled());
  vi.mocked(compositionApi.context).mockResolvedValue({ ...context, schema_version: "bluefire.retained-composition-proposal-context.v1", retained_artifacts: { ...context.retained_artifacts!, available_sources: [], availability: "none_available" } });
  fireEvent.click(screen.getByRole("button", { name: "Refresh available results" }));
  expect(await screen.findByRole("region", { name: "Available generated results" })).toHaveTextContent("No retained result is currently available");
  await waitFor(() => expect(start()).toBeDisabled());
});

it("starts a new objective with retention off after viewing a retained objective", async () => {
  mount(<CompositionPage />, `/composition?control=${controlId}&objective=${ownerId}&proposal=${proposalId}&pack=${RECEIVER_RETAINED_PACK}`);
  await screen.findByRole("region", { name: "Captured available results" });
  fireEvent.click(screen.getByRole("button", { name: "New objective" }));
  await screen.findByRole("heading", { name: "New objective" });
  expect(retentionChoice()).not.toBeChecked();
  expect(screen.getByLabelText("Objective question")).toHaveValue("");
});

it("preserves the same explicit retained review selection when retrying its review", async () => {
  const review = vi.spyOn(compositionApi, "review").mockRejectedValueOnce(new Error("Review temporarily unavailable")).mockResolvedValueOnce(retainedReviewFixture());
  mount(<CompositionSetup control={controlId} pack={RECEIVER_RETAINED_PACK} initialRequest={retainedRequestFixture()} disabled={false} onSubmit={vi.fn()} />);
  expect(retentionChoice()).toBeChecked();
  fireEvent.click(screen.getByRole("button", { name: "Review finite delegation" }));
  await screen.findByText("Review temporarily unavailable");
  expect(retentionChoice()).toBeChecked();
  fireEvent.click(screen.getByRole("button", { name: "Review finite delegation" }));
  await screen.findByRole("button", { name: "Issue capability grant" });
  expect(review).toHaveBeenNthCalledWith(1, retainedRequestFixture());
  expect(review).toHaveBeenNthCalledWith(2, retainedRequestFixture());
});

it("preserves captured review on corrupt metadata while offering a separately reviewed objective", async () => {
  vi.mocked(compositionApi.context).mockRejectedValue(new Error("Sealed source metadata failed integrity validation"));
  const review = vi.spyOn(compositionApi, "review").mockResolvedValue(reviewFixture());
  const submit = vi.spyOn(compositionApi, "submit");
  mount();
  const captured = await screen.findByRole("region", { name: "Captured available results" });
  await screen.findByText("Sealed source metadata failed integrity validation");
  expect(captured).toBeInTheDocument();
  expect(start()).toBeDisabled();
  fireEvent.click(screen.getByRole("button", { name: "New objective" }));
  await screen.findByRole("heading", { name: "New objective" });
  expect(retentionChoice()).not.toBeChecked();
  fireEvent.change(screen.getByLabelText("Objective question"), { target: { value: question } });
  fireEvent.click(screen.getByRole("button", { name: "Review finite delegation" }));
  await screen.findByRole("button", { name: "Issue capability grant" });
  expect(review).toHaveBeenCalledWith({ control_owner_id: controlId, question, limits: null });
  expect(submit).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("link", { name: `Open objective: ${question}, Active` }));
  expect(await screen.findByRole("region", { name: "Captured available results" })).toBeInTheDocument();
  expect(start()).toBeDisabled();
});

it("offers an explicit fresh graph within the same objective when retained bytes are unavailable", async () => {
  const value = retainedFreshRecoveryFixture();
  vi.mocked(compositionApi.objective).mockResolvedValue(value.objective);
  vi.mocked(compositionApi.context).mockResolvedValue(value.currentContext);
  let saved: CompositionProposal | undefined;
  vi.mocked(compositionApi.proposal).mockImplementation(async id => id === proposalId ? value.proposal : saved!);
  const submit = vi.spyOn(compositionApi, "submit").mockImplementation(async operation => {
    saved = structuredClone(value.freshProposal);
    saved.job.job_id = operation.id;
    saved.job.request.submitted_request = operation.body;
    saved.proposal!.proposal_job_id = operation.id;
    return saved;
  });
  mount();
  const captured = await screen.findByRole("region", { name: "Captured available results" });
  expect(await screen.findByRole("region", { name: "Available generated results" })).toHaveTextContent("No retained result is currently available");
  await waitFor(() => expect(start()).toBeDisabled());
  expect(captured).toHaveTextContent("Attempt 1 · Step stage");
  expect(screen.getAllByRole("region", { name: "Generated result kept before a later failure" })[1]).toHaveTextContent("Recorded receiver decision: Policy refused.");
  fireEvent.change(screen.getByLabelText("Configured model provider"), { target: { value: "configured" } });
  const request = screen.getByRole("button", { name: "Request evidence-based revision" });
  await waitFor(() => expect(request).toBeEnabled());
  expect(submit).not.toHaveBeenCalled();
  fireEvent.click(request);
  await screen.findByRole("heading", { name: "Fresh generation within this objective" });
  await waitFor(() => expect(start()).toBeEnabled());
  expect(submit).toHaveBeenCalledOnce();
  expect(submit.mock.calls[0]![0]).toMatchObject({ kind: "proposal", owner: ownerId, control: controlId, body: { prior_attempt_id: value.prior, context_digest: value.currentContext.context_digest, provider_id: "configured" } });
  expect(submit.mock.calls[0]![0].body).not.toHaveProperty("source_ref");
  expect(screen.getByRole("region", { name: "Proposed graph steps" })).toHaveTextContent("redact_values: true");
  expect(saved!.proposal!.candidate.steps.some(step => "source_ref" in step.parameters)).toBe(false);
  expect(saved!.proposal!.candidate.steps.map(step => step.behavior_id)).toEqual(["sandbox.fixture.create.v1", "sandbox.fixture.transform.v1", "sandbox.discovery.list.v1", "sandbox.collection.stage.v1", "sandbox.peer.handoff.v1", "sandbox.cleanup.v1"]);
});
