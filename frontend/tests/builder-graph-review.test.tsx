import * as Tooltip from "@radix-ui/react-tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { api } from "../src/lib/api";
import { demoCatalog, demoScenario } from "../src/lib/demo";
import { graphDocument, type GraphEnvelope } from "../src/lib/graph-assistance";
import { BuilderPage } from "../src/pages/Builder";
import { ProductProvider } from "../src/state/ProductContext";

const jobId = `job-${"b".repeat(32)}`;
const digest = (letter: string) => `sha256:${letter.repeat(64)}`;
function fixture(): GraphEnvelope {
  const document = graphDocument(structuredClone(demoScenario));
  return { review_ready: true, job: { schema_version: "bluefire.job.v1", job_id: jobId, kind: "graph.ai.propose", state: "completed", progress: {} }, application: null,
    proposal: { schema_version: "bluefire.graph-ai-proposal.v1", proposal_job_id: jobId, proposal_digest: digest("a"), context_digest: digest("b"), catalog_digest: digest("c"), base_scenario: null,
      scenario: document, validation: { valid: true }, rationale: "Inspect a saved graph", assumptions: [], limitations: ["Not executed"],
      provider: { effective_provider_id: "chosen-provider", model: "chosen-model", used_fallback: false, attempts: 1 } } };
}
function mount(envelope: GraphEnvelope) {
  vi.spyOn(api, "graphProposal").mockResolvedValue(envelope);
  vi.spyOn(api, "catalog").mockResolvedValue(demoCatalog);
  const review = vi.spyOn(api, "reviewGraphProposal");
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  return { client, review, ...render(<QueryClientProvider client={client}><Tooltip.Provider><MemoryRouter initialEntries={[`/builder?graph_job=${jobId}`]}><ProductProvider><BuilderPage/></ProductProvider></MemoryRouter></Tooltip.Provider></QueryClientProvider>) };
}

it("keeps a saved canvas inspectable while preventing deletion and mutation affordances", async () => {
  const envelope = fixture();
  const document = envelope.proposal!.scenario;
  envelope.application = { proposal_job_id: jobId, proposal_digest: digest("a"), reviewed_digest: digest("d"), operator_modified: false, scenario_id: document.id, version: 3, digest: digest("e") };
  vi.spyOn(api, "immutableScenarioVersion").mockResolvedValue({ schema_version: "bluefire.scenario-version.v1", scenario: { scenario_id: document.id, version: 3, digest: digest("e"), title: document.title, created_at: "2030-01-01", document } });
  const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
  const view = mount(envelope);
  expect(await screen.findByRole("textbox", { name: "Experiment name" })).toBeDisabled();
  const before = view.container.querySelectorAll(".react-flow__node").length;
  expect(before).toBeGreaterThan(0);
  screen.getByLabelText("Scenario graph canvas").focus();
  await userEvent.keyboard("{Delete}");
  expect(confirm).not.toHaveBeenCalled();
  expect(view.container.querySelectorAll(".react-flow__node")).toHaveLength(before);
  for (const name of ["Delete selected node", "Duplicate selected node", "Paste node", "Auto-layout"]) expect(screen.getByRole("button", { name })).toBeDisabled();
  expect(screen.getByRole("button", { name: "Copy selected node" })).toBeEnabled();
  expect(screen.getByRole("button", { name: "Fit graph" })).toBeEnabled();
  await userEvent.click(screen.getByRole("button", { name: "Steps" }));
  const steps = within(screen.getByRole("list", { name: "Experiment steps" })).getAllByRole("button");
  await userEvent.click(steps[1]!);
  expect(steps[1]).toHaveAttribute("aria-pressed", "true");
  expect(screen.getByRole("button", { name: "Close step details" })).toBeEnabled();
  const inspector = view.container.querySelector("fieldset.graph-review-editor") as HTMLFieldSetElement;
  expect(inspector).toBeDisabled();
  for (const control of within(inspector).getAllByRole("combobox")) expect(control).toBeDisabled();
  expect(view.review).not.toHaveBeenCalled();
});

it("vetoes keyboard Undo and native deletion when an edited proposal becomes stopped", async () => {
  const envelope = fixture();
  const document = structuredClone(envelope.proposal!.scenario);
  document.layout = Object.fromEntries(document.steps.map((step, index) => [step.id, { x: 500 + index * 20, y: 500 + index * 20 }]));
  sessionStorage.setItem(`bluefire.graph-review.${jobId}`, JSON.stringify({ proposal_digest: digest("a"), scenario: document }));
  const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
  const view = mount(envelope);
  await screen.findByRole("textbox", { name: "Experiment name" });
  const first = () => view.container.querySelector(`.react-flow__node[data-id="${document.start}"]`) as HTMLElement;
  const originalPosition = first().style.transform;
  await userEvent.click(screen.getByRole("button", { name: "Auto-layout" }));
  const arrangedPosition = first().style.transform;
  expect(arrangedPosition).not.toBe(originalPosition);
  expect(screen.getByRole("button", { name: "Undo" })).toBeEnabled();
  const stopped = structuredClone(envelope);
  stopped.job.progress.stopped = true;
  stopped.review_ready = false;
  await act(async () => { view.client.setQueryData(["graph-proposal", jobId], stopped); });
  await screen.findByRole("heading", { name: "Proposal stopped" });
  expect(screen.getByRole("button", { name: "Undo" })).toBeDisabled();
  const canvas = screen.getByLabelText("Scenario graph canvas");
  canvas.focus();
  await userEvent.keyboard("{Control>}z{/Control}{Delete}");
  expect(first()).toBeInTheDocument();
  expect(first().style.transform).toBe(arrangedPosition);
  expect(confirm).not.toHaveBeenCalled();
  expect(screen.getByRole("button", { name: "Copy selected node" })).toBeEnabled();
  await userEvent.click(screen.getByRole("button", { name: "Show node inspector" }));
  expect(screen.getByRole("button", { name: "Close step details" })).toBeEnabled();
  expect(view.review).not.toHaveBeenCalled();
});

it("saves a durably review-ready interrupted proposal from the native editor without regenerating it", async () => {
  const envelope = fixture();
  envelope.job.state = "interrupted";
  envelope.review_ready = true;
  const generate = vi.spyOn(api, "submitAssistance").mockRejectedValue(new Error("Unexpected generation"));
  const retry = vi.spyOn(api, "retryJob").mockRejectedValue(new Error("Unexpected retry"));
  const validate = vi.spyOn(api, "validateGraphProposal").mockImplementation(async (_id, body) => ({ ...body, reviewed_digest: digest("d"), validation: { valid: true } }));
  const document = envelope.proposal!.scenario;
  vi.spyOn(api, "immutableScenarioVersion").mockResolvedValue({ schema_version: "bluefire.scenario-version.v1", scenario: { scenario_id: document.id, version: 3, digest: digest("e"), title: document.title, created_at: "2030-01-01", document } });
  const view = mount(envelope);
  view.review.mockImplementation(async (_id, decision) => {
    const result = structuredClone(envelope);
    result.job.progress.decision = decision;
    result.review_ready = false;
    result.application = { proposal_job_id: jobId, proposal_digest: digest("a"), reviewed_digest: digest("d"), operator_modified: false, scenario_id: document.id, version: 3, digest: digest("e") };
    return result;
  });
  expect(await screen.findByRole("textbox", { name: "Experiment name" })).toBeEnabled();
  await userEvent.click(screen.getByRole("button", { name: "Save experiment" }));
  await screen.findByRole("button", { name: "Open saved experiment" });
  expect(validate).toHaveBeenCalledTimes(1);
  expect(validate).toHaveBeenCalledWith(jobId, { proposal_digest: digest("a"), scenario: document });
  expect(view.review).toHaveBeenCalledTimes(1);
  expect(view.review).toHaveBeenCalledWith(jobId, { decision: "accept", proposal_digest: digest("a"), reviewed_digest: digest("d"), scenario: document });
  expect(generate).not.toHaveBeenCalled();
  expect(retry).not.toHaveBeenCalled();
});
