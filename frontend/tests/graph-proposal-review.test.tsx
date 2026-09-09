import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { MemoryRouter, useLocation } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { GraphProposalReview } from "../src/components/GraphProposalReview";
import { api } from "../src/lib/api";
import { graphDocument, graphEditDocument, type GraphDecision, type GraphEditorDraft, type GraphEnvelope, type GraphValidation } from "../src/lib/graph-assistance";
import { ProductProvider, useProduct } from "../src/state/ProductContext";
import type { Scenario } from "../src/types";

const jobId = `job-${"a".repeat(32)}`;
const digest = (letter: string) => `sha256:${letter.repeat(64)}`;
function scenario(): Scenario {
  return { schema_version: "bluefire.scenario.v1", id: "scenario.proposed.v1", title: "Proposed experiment", purpose: "Inspect a bounded fixture", start: "inspect",
    steps: [{ id: "inspect", behavior_id: "observe.fixture.v1", parameters: { path: "fixture.txt" }, inputs: {}, alternates: [] }], edges: [],
    provenance: { source: "test", reference: "fixture", license: "MIT", derived: true }, limitations: ["Fixture only"], layout: { inspect: { x: 20, y: 40 } } };
}
function ready(): GraphEnvelope {
  return { review_ready: true, job: { schema_version: "bluefire.job.v1", job_id: jobId, kind: "graph.ai.propose", state: "completed", progress: {} }, application: null,
    proposal: { schema_version: "bluefire.graph-ai-proposal.v1", proposal_job_id: jobId, proposal_digest: digest("a"), context_digest: digest("b"), catalog_digest: digest("c"), base_scenario: null,
      scenario: graphDocument(scenario()), validation: { valid: true }, rationale: "A bounded observation graph", assumptions: ["The fixture is local"], limitations: ["Not executed"],
      provider: { effective_provider_id: "chosen-provider", model: "chosen-model", used_fallback: false, attempts: 1 } } };
}
function accepted(document = graphDocument(scenario())) {
  const envelope = ready();
  const decision: GraphDecision = { decision: "accept", proposal_digest: digest("a"), reviewed_digest: digest("d"), scenario: document };
  envelope.job.progress.decision = decision;
  envelope.application = { proposal_job_id: jobId, proposal_digest: digest("a"), reviewed_digest: digest("d"), operator_modified: true, scenario_id: document.id, version: 3, digest: digest("e") };
  const saved = { schema_version: "bluefire.scenario-version.v1", scenario: { scenario_id: document.id, version: 3, digest: digest("e"), title: document.title, created_at: "2030-01-01", document } };
  return { envelope, decision, saved };
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail; });
  return { promise, resolve, reject };
}

// The editor seam has the same controlled-document/readOnly contract as the native canvas.
// ProductProvider stays real so draft edits and later manual edits exercise actual active state.
function Editor({ draft }: { draft: GraphEditorDraft }) {
  return <main>{draft.details}<label>Review name<input value={draft.scenario.title} disabled={draft.readOnly} onChange={(event) => draft.setScenario({ ...draft.scenario, title: event.target.value })}/></label>
    <output aria-label="Review document">{JSON.stringify(draft.scenario)}</output>{draft.controls}</main>;
}
function Workspace() {
  const product = useProduct();
  const [reviewing, setReviewing] = useState(true);
  return <><output aria-label="Active name">{product.scenario.title}</output><output aria-label="Active dirty">{String(product.dirty)}</output><output aria-label="Current route">{useLocation().pathname}</output>
    <button onClick={() => product.setScenario({ ...product.scenario, title: "New manual work" }, true)}>Edit active graph</button>
    <button onClick={() => product.setScenario({ ...product.scenario, title: "" }, true)}>Clear active name</button>
    <button onClick={() => setReviewing(false)}>Leave proposal review</button>
    {reviewing ? <GraphProposalReview jobId={jobId} behaviors={[]} renderEditor={(draft) => <Editor draft={draft}/>}/> : <p>Current editor</p>}</>;
}
function mount() {
  if (!localStorage.getItem("bluefire.local.scenario.v1")) {
    const saved = JSON.stringify({ ...scenario(), id: "scenario.manual.v1", title: "Current manual experiment" });
    localStorage.setItem("bluefire.local.scenario.v1", saved);
    localStorage.setItem("bluefire.local.scenario-saved.v1", saved);
  }
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 }, mutations: { retry: false } } });
  return { client, ...render(<QueryClientProvider client={client}><MemoryRouter initialEntries={["/builder/proposal"]}><ProductProvider><Workspace/></ProductProvider></MemoryRouter></QueryClientProvider>) };
}
function mockReady(envelope = ready()) {
  vi.spyOn(api, "graphProposal").mockResolvedValue(envelope);
  const validate = vi.spyOn(api, "validateGraphProposal").mockImplementation(async (_id, body) => ({ ...body, reviewed_digest: digest("d"), validation: { valid: true } }));
  const review = vi.spyOn(api, "reviewGraphProposal").mockRejectedValue(new Error("Save response lost"));
  const immutable = vi.spyOn(api, "immutableScenarioVersion").mockResolvedValue(accepted().saved);
  return { validate, review, immutable };
}

it("edits and reloads a retained proposal without replacing the active graph", async () => {
  const mocks = mockReady();
  const first = mount();
  const input = await screen.findByRole("textbox", { name: "Review name" });
  await userEvent.type(input, " edited");
  expect(input).toHaveValue("Proposed experiment edited");
  expect(screen.getByLabelText("Active name")).toHaveTextContent("Current manual experiment");
  expect(screen.getByLabelText("Active dirty")).toHaveTextContent("false");
  expect(mocks.validate).not.toHaveBeenCalled();
  expect(mocks.review).not.toHaveBeenCalled();
  first.unmount();
  mount();
  expect(await screen.findByRole("textbox", { name: "Review name" })).toHaveValue("Proposed experiment edited");
  expect(screen.getByLabelText("Active name")).toHaveTextContent("Current manual experiment");
});

it("freezes the exact reviewed save across a lost response and reload, then retries without revalidation", async () => {
  const mocks = mockReady();
  const validation = deferred<GraphValidation>();
  mocks.validate.mockReturnValueOnce(validation.promise);
  const first = mount();
  await userEvent.type(await screen.findByRole("textbox", { name: "Review name" }), " edited");
  await userEvent.click(screen.getByRole("button", { name: "Save experiment" }));
  expect(screen.getByRole("textbox", { name: "Review name" })).toBeDisabled();
  const submitted = structuredClone(mocks.validate.mock.calls[0]![1]);
  expect(submitted.scenario.layout).toBeUndefined();
  await act(async () => validation.resolve({ ...submitted, reviewed_digest: digest("d"), validation: { valid: true } }));
  expect(await screen.findByText("Save response lost")).toBeVisible();
  const exact = structuredClone(mocks.review.mock.calls[0]![1]);
  expect(exact).toEqual({ decision: "accept", ...submitted, reviewed_digest: digest("d") });
  expect(screen.getByRole("textbox", { name: "Review name" })).toBeDisabled();
  first.unmount();
  const saved = accepted(submitted.scenario);
  mocks.review.mockResolvedValue(saved.envelope);
  mocks.immutable.mockResolvedValue(saved.saved);
  mount();
  await userEvent.click(await screen.findByRole("button", { name: "Retry saved decision" }));
  await screen.findByRole("button", { name: "Open saved experiment" });
  expect(mocks.validate).toHaveBeenCalledTimes(1);
  expect(mocks.review).toHaveBeenCalledTimes(2);
  expect(mocks.review.mock.calls[1]).toEqual([jobId, exact]);
  expect(screen.getByRole("textbox", { name: "Review name" })).toHaveValue("Proposed experiment edited");
  expect(screen.getByLabelText("Active name")).toHaveTextContent("Current manual experiment");
});

it.each(["proposal", "document", "digest", "invalid"])("refuses mismatched validation %s before requesting any save", async (mismatch) => {
  const mocks = mockReady();
  mocks.validate.mockImplementation(async (_id, body) => ({ proposal_digest: mismatch === "proposal" ? digest("f") : body.proposal_digest,
    scenario: mismatch === "document" ? { ...body.scenario, title: "Different graph" } : body.scenario,
    reviewed_digest: mismatch === "digest" ? "invalid" : digest("d"), validation: { valid: mismatch !== "invalid" } } as GraphValidation));
  mount();
  await userEvent.click(await screen.findByRole("button", { name: "Save experiment" }));
  expect(await screen.findByText(/Validation returned a different graph/)).toBeVisible();
  expect(mocks.review).not.toHaveBeenCalled();
  expect(screen.getByRole("textbox", { name: "Review name" })).toBeEnabled();
  expect(screen.getByLabelText("Active name")).toHaveTextContent("Current manual experiment");
});

it.each(["job", "decision", "application"])("retains the exact decision when the save response has a mismatched %s", async (mismatch) => {
  const mocks = mockReady();
  const saved = accepted();
  if (mismatch === "job") saved.envelope.job.job_id = `job-${"f".repeat(32)}`;
  if (mismatch === "decision") saved.envelope.job.progress.decision = { decision: "reject", proposal_digest: digest("a") };
  if (mismatch === "application") saved.envelope.application!.reviewed_digest = digest("f");
  mocks.review.mockResolvedValue(saved.envelope);
  mount();
  await userEvent.click(await screen.findByRole("button", { name: "Save experiment" }));
  await screen.findByRole("button", { name: "Retry saved decision" });
  expect(screen.getByRole("textbox", { name: "Review name" })).toBeDisabled();
  expect(screen.queryByRole("button", { name: "Open saved experiment" })).not.toBeInTheDocument();
  expect(mocks.immutable).not.toHaveBeenCalled();
  expect(screen.getByLabelText("Active name")).toHaveTextContent("Current manual experiment");
});

it.each(["version", "digest", "document identity"])("refuses a saved immutable version with mismatched %s", async (mismatch) => {
  const saved = accepted();
  const mocks = mockReady(saved.envelope);
  if (mismatch === "version") saved.saved.scenario.version = 4;
  if (mismatch === "digest") saved.saved.scenario.digest = digest("f");
  if (mismatch === "document identity") saved.saved.scenario.document.id = "scenario.other.v1";
  mocks.immutable.mockResolvedValue(saved.saved);
  mount();
  expect(await screen.findByText(/saved version does not match/)).toBeVisible();
  expect(screen.queryByRole("button", { name: "Open saved experiment" })).not.toBeInTheDocument();
  expect(screen.getByLabelText("Active name")).toHaveTextContent("Current manual experiment");
});

it("refetches the immutable version on Open and checks manual edits made during the request", async () => {
  const saved = accepted();
  const mocks = mockReady(saved.envelope);
  const opening = deferred<typeof saved.saved>();
  mocks.immutable.mockResolvedValueOnce(saved.saved).mockReturnValueOnce(opening.promise).mockResolvedValue(saved.saved);
  const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
  mount();
  await userEvent.click(await screen.findByRole("button", { name: "Open saved experiment" }));
  await userEvent.click(screen.getByRole("button", { name: "Edit active graph" }));
  await act(async () => opening.resolve(saved.saved));
  await waitFor(() => expect(confirm).toHaveBeenCalledTimes(1));
  expect(screen.getByLabelText("Active name")).toHaveTextContent("New manual work");
  expect(screen.getByLabelText("Current route")).toHaveTextContent("/builder/proposal");
  confirm.mockReturnValue(true);
  await userEvent.click(screen.getByRole("button", { name: "Open saved experiment" }));
  await waitFor(() => expect(screen.getByLabelText("Current route")).toHaveTextContent(/^\/builder$/));
  expect(screen.getByLabelText("Active name")).toHaveTextContent("Proposed experiment");
  expect(screen.getByLabelText("Active dirty")).toHaveTextContent("false");
  expect(mocks.immutable).toHaveBeenCalledTimes(3);
  expect(mocks.immutable).toHaveBeenLastCalledWith(saved.envelope.application!.scenario_id, 3);
  expect(mocks.review).not.toHaveBeenCalled();
});

it.each(["edited", "legacy"])("protects a reloaded %s active draft before opening a saved proposal", async (kind) => {
  mockReady(accepted().envelope);
  const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
  const first = mount();
  await screen.findByRole("button", { name: "Open saved experiment" });
  if (kind === "edited") await userEvent.click(screen.getByRole("button", { name: "Edit active graph" }));
  else localStorage.removeItem("bluefire.local.scenario-saved.v1");
  const original = localStorage.getItem("bluefire.local.scenario.v1");
  first.unmount();
  mount();
  expect(screen.getByLabelText("Active dirty")).toHaveTextContent("true");
  await userEvent.click(await screen.findByRole("button", { name: "Open saved experiment" }));
  await waitFor(() => expect(confirm).toHaveBeenCalledTimes(1));
  expect(localStorage.getItem("bluefire.local.scenario.v1")).toBe(original);
  expect(screen.getByLabelText("Current route")).toHaveTextContent("/builder/proposal");
  confirm.mockReturnValue(true);
  await userEvent.click(screen.getByRole("button", { name: "Open saved experiment" }));
  await waitFor(() => expect(screen.getByLabelText("Current route")).toHaveTextContent(/^\/builder$/));
  expect(screen.getByLabelText("Active name")).toHaveTextContent("Proposed experiment");
  expect(screen.getByLabelText("Active dirty")).toHaveTextContent("false");
  expect(localStorage.getItem("bluefire.local.scenario-saved.v1")).toBe(localStorage.getItem("bluefire.local.scenario.v1"));
});

it("does not open a mismatched response even after the first saved-version fetch was valid", async () => {
  const saved = accepted();
  const mocks = mockReady(saved.envelope);
  mocks.immutable.mockResolvedValueOnce(saved.saved).mockResolvedValueOnce({ ...saved.saved, scenario: { ...saved.saved.scenario, digest: digest("f") } });
  mount();
  await userEvent.click(await screen.findByRole("button", { name: "Open saved experiment" }));
  expect(await screen.findByText(/saved version does not match/)).toBeVisible();
  expect(screen.getByLabelText("Active name")).toHaveTextContent("Current manual experiment");
  expect(screen.getByLabelText("Current route")).toHaveTextContent("/builder/proposal");
});

it.each(["rejected", "stopped", "cancelled", "interrupted"])("keeps %s proposals inspectable and read-only", async (state) => {
  const envelope = ready();
  envelope.review_ready = false;
  if (state === "rejected") envelope.job.progress.decision = { decision: "reject", proposal_digest: digest("a") };
  else if (state === "stopped") envelope.job.progress.stopped = true;
  else envelope.job.state = state as "cancelled" | "interrupted";
  const mocks = mockReady(envelope);
  mount();
  expect(await screen.findByRole("textbox", { name: "Review name" })).toBeDisabled();
  expect(screen.getByRole("textbox", { name: "Review name" })).toHaveValue("Proposed experiment");
  expect(screen.queryByRole("button", { name: "Save experiment" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Decline proposal" })).not.toBeInTheDocument();
  expect(mocks.review).not.toHaveBeenCalled();
  expect(mocks.validate).not.toHaveBeenCalled();
});

it("does not replace active work if the operator leaves the review during an immutable-version fetch", async () => {
  const saved = accepted();
  const mocks = mockReady(saved.envelope);
  const opening = deferred<typeof saved.saved>();
  mocks.immutable.mockResolvedValueOnce(saved.saved).mockReturnValueOnce(opening.promise);
  const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
  mount();
  await userEvent.click(await screen.findByRole("button", { name: "Open saved experiment" }));
  await userEvent.click(screen.getByRole("button", { name: "Leave proposal review" }));
  await userEvent.click(screen.getByRole("button", { name: "Edit active graph" }));
  await act(async () => opening.resolve(saved.saved));
  expect(screen.getByLabelText("Active name")).toHaveTextContent("New manual work");
  expect(confirm).not.toHaveBeenCalled();
});



it.each(["planning", "paused"] as const)("polls a %s graph job until its retained proposal becomes available", async (state) => {
  const initial = ready();
  initial.job.state = state;
  initial.proposal = null;
  initial.review_ready = false;
  mockReady();
  const fetch = vi.mocked(api.graphProposal).mockResolvedValueOnce(initial).mockResolvedValue(ready());
  mount();
  expect(await screen.findByText(/Checking registered steps and preparing a graph for review/)).toBeVisible();
  expect(fetch).toHaveBeenCalledTimes(1);
  // The production poll is1500ms; wait across one interval, without clicking refetch.
  expect(await screen.findByRole("textbox", { name: "Review name" }, { timeout: 3000 })).toHaveValue("Proposed experiment");
  expect(fetch).toHaveBeenCalledTimes(2);
});

it("keeps a retained running proposal read-only until review readiness is durably confirmed", async () => {
  const envelope = ready();
  envelope.job.state = "running";
  envelope.review_ready = false;
  const mocks = mockReady(envelope);
  mount();
  expect(await screen.findByRole("textbox", { name: "Review name" })).toHaveValue("Proposed experiment");
  expect(screen.getByRole("textbox", { name: "Review name" })).toBeDisabled();
  expect(screen.getByRole("button", { name: "Save experiment" })).toBeDisabled();
  expect(screen.getByText(/proposal is still being finalized/)).toBeVisible();
  await userEvent.click(screen.getByRole("button", { name: "Save experiment" }));
  expect(mocks.validate).not.toHaveBeenCalled();
  expect(mocks.review).not.toHaveBeenCalled();
});

function readyStepEdit(): GraphEnvelope {
  const envelope = ready();
  const source = graphEditDocument({ ...scenario(), id: "scenario.manual.v1", title: "Current manual experiment" });
  envelope.proposal!.edit_source = { scenario: source, step_id: "inspect", dirty: true, digest: digest("f") };
  envelope.proposal!.scenario = { ...source, id: "scenario.proposed.v1", steps: [{ ...source.steps[0]!, parameters: { path: "changed.txt" } }] };
  envelope.job.request = { submitted_request: { selection: { kind: "graph", base_scenario: null, edit_step: { scenario: source, step_id: "inspect", dirty: true } } } };
  return envelope;
}
it("reviews exact step values and refuses changed working source across reload", async () => {
  const mocks = mockReady(readyStepEdit());
  const first = mount();
  const changes = await screen.findByRole("region", { name: "Selected step changes" });
  expect(changes).toHaveTextContent('"fixture.txt"'); expect(changes).toHaveTextContent('"changed.txt"');
  expect(screen.getByRole("button", { name: "Save experiment" })).toBeEnabled();
  await userEvent.click(screen.getByRole("button", { name: "Edit active graph" }));
  expect(screen.getByRole("alert")).toHaveTextContent("working graph changed");
  expect(screen.getByRole("button", { name: "Save experiment" })).toBeDisabled();
  first.unmount(); mount();
  expect(await screen.findByRole("button", { name: "Save experiment" })).toBeDisabled();
  expect(mocks.validate).not.toHaveBeenCalled(); expect(mocks.review).not.toHaveBeenCalled();
});
it("refuses a step save if working source changes during validation", async () => {
  const envelope = readyStepEdit(); const mocks = mockReady(envelope);
  const pending = deferred<GraphValidation>(); mocks.validate.mockReturnValue(pending.promise); mount();
  await userEvent.click(await screen.findByRole("button", { name: "Save experiment" }));
  await waitFor(() => expect(mocks.validate).toHaveBeenCalledOnce());
  await userEvent.click(screen.getByRole("button", { name: "Edit active graph" }));
  await act(async () => pending.resolve({ scenario: envelope.proposal!.scenario, proposal_digest: digest("a"), reviewed_digest: digest("d"), validation: { valid: true } }));
  expect(mocks.review).not.toHaveBeenCalled(); expect(screen.getByLabelText("Active name")).toHaveTextContent("New manual work");
});
it("refuses opening saved step work changed during the version read", async () => {
  const envelope = readyStepEdit(); const saved = accepted(envelope.proposal!.scenario);
  envelope.application = saved.envelope.application; envelope.job.progress.decision = saved.decision;
  const mocks = mockReady(envelope); mocks.immutable.mockResolvedValue(saved.saved); mount();
  await screen.findByRole("button", { name: "Open saved experiment" });
  const pending = deferred<typeof saved.saved>(); mocks.immutable.mockReturnValue(pending.promise);
  await userEvent.click(screen.getByRole("button", { name: "Open saved experiment" }));
  await userEvent.click(screen.getByRole("button", { name: "Edit active graph" }));
  await act(async () => pending.resolve(saved.saved));
  expect(screen.getByLabelText("Active name")).toHaveTextContent("New manual work");
  expect(screen.getByLabelText("Current route")).toHaveTextContent("/builder/proposal");
});

it("keeps native review usable when the working graph becomes incomplete", async () => {
  const mocks = mockReady(readyStepEdit()); mount();
  await screen.findByRole("button", { name: "Save experiment" });
  await userEvent.click(screen.getByRole("button", { name: "Clear active name" }));
  expect(screen.getByRole("button", { name: "Save experiment" })).toBeDisabled();
  expect(screen.getByRole("alert")).toHaveTextContent("working graph changed");
  expect(mocks.review).not.toHaveBeenCalled();
});


it("shows staging folder labels in selected-step review while retaining exact proposal values", async () => {
  const envelope = readyStepEdit();
  const source = envelope.proposal!.edit_source!.scenario;
  source.steps[0]!.behavior_id = "sandbox.collection.atomic-gzip.v1";
  source.steps[0]!.parameters = { stage_variant: "primary" };
  envelope.proposal!.scenario = { ...structuredClone(source), id: "scenario.proposed.v1" };
  envelope.proposal!.scenario.steps[0]!.parameters = { stage_variant: "heldout" };
  localStorage.setItem("bluefire.local.scenario.v1", JSON.stringify(source));
  const retained = JSON.stringify(envelope);
  const mocks = mockReady(envelope); mount();
  const changes = await screen.findByRole("region", { name: "Selected step changes" });
  expect(changes).toHaveTextContent("Main staging folder");
  expect(changes).toHaveTextContent("Alternate staging folder");
  await userEvent.click(screen.getByText("Exact parameter values"));
  expect(changes).toHaveTextContent('"stage_variant": "primary"');
  expect(changes).toHaveTextContent('"stage_variant": "heldout"');
  expect(JSON.stringify(envelope)).toBe(retained);
  expect(JSON.parse(screen.getByLabelText("Review document").textContent!).steps[0].parameters.stage_variant).toBe("heldout");
  expect(mocks.validate).not.toHaveBeenCalled(); expect(mocks.review).not.toHaveBeenCalled();
});
