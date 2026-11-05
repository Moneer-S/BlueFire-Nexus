import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import * as Tooltip from "@radix-ui/react-tooltip";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { CompositionPage } from "../src/pages/Composition";
import { compositionApi, type CompositionContext } from "../src/lib/composition";
import { controlId, ownerId, proposalId, question } from "./composition-fixture";
import { retainedFreshRecoveryFixture } from "./composition-retained-fixture";

vi.mock("../src/components/CompositionGraph", () => ({ CompositionGraph: () => <div>Read-only graph</div> }));
vi.mock("../src/lib/api", () => ({ DEMO_MODE: false, request: vi.fn(), ApiError: class extends Error {}, api: { catalog: vi.fn(async () => ({ ai: { providers: [{ provider_id: "configured", kind: "openai", model: "configured-model" }] } })) } }));
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

function initialRetainedProposal() {
  const value = retainedFreshRecoveryFixture();
  value.objective.attempts = [];
  const proposal = value.freshProposal;
  const candidate = proposal.proposal!.candidate;
  candidate.title = "Initial retained graph";
  candidate.evidence_refs = ["policy"];
  candidate.steps.find(step => step.id === "prepare")!.parameters.redact_values = false;
  const context: CompositionContext = { ...value.currentContext, facts: { ...value.currentContext.facts, prior_attempt_id: null, facts: value.currentContext.facts.facts.filter(fact => fact.fact_id === "policy") }, initial_proposal: candidate, initial_scenario: proposal.proposal!.scenario };
  proposal.job.request.context = context;
  (proposal.job.request.submitted_request as Record<string, unknown>).prior_attempt_id = null;
  proposal.proposal!.prior_attempt_id = null;
  return { objective: value.objective, context, proposal };
}
function mount(value: ReturnType<typeof initialRetainedProposal>) {
  localStorage.clear();
  vi.spyOn(compositionApi, "list").mockResolvedValue({ schema_version: "bluefire.composition-objective-list.v1", objectives: [{ owner_id: ownerId, title: question, status: "active", job_state: "completed" }] });
  vi.spyOn(compositionApi, "objective").mockResolvedValue(value.objective);
  vi.spyOn(compositionApi, "context").mockResolvedValue(value.context);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(<QueryClientProvider client={client}><Tooltip.Provider><MemoryRouter initialEntries={[`/composition?control=${controlId}&objective=${ownerId}&proposal=${proposalId}`]}><CompositionPage /></MemoryRouter></Tooltip.Provider></QueryClientProvider>);
}

it("polls a retained candidate published before its job completes, then requires one operator dispatch", async () => {
  const value = initialRetainedProposal();
  const publishing = structuredClone(value.proposal);
  publishing.job.state = "running"; publishing.candidate_ready = false;
  const read = vi.spyOn(compositionApi, "proposal").mockResolvedValueOnce(publishing).mockResolvedValue(value.proposal);
  const submit = vi.spyOn(compositionApi, "submit").mockRejectedValue(new Error("Exact attempt confirmation pending"));
  mount(value);
  const start = await screen.findByRole("button", { name: "Start fresh attempt within grant" });
  expect(start).toBeDisabled();
  expect(screen.getByRole("button", { name: "Request AI graph" })).toBeDisabled();
  expect(submit).not.toHaveBeenCalled();
  await waitFor(() => expect(start).toBeEnabled(), { timeout: 3000 });
  expect(read).toHaveBeenCalledTimes(2);
  expect(submit).not.toHaveBeenCalled();
  fireEvent.click(start);
  await waitFor(() => expect(submit).toHaveBeenCalledOnce());
  expect(submit.mock.calls[0]![0]).toMatchObject({ kind: "attempt", owner: ownerId, body: { prior_attempt_id: null, proposal: value.proposal.proposal!.candidate } });
});

it("does not keep polling or enable a completed retained candidate that is not ready", async () => {
  const value = initialRetainedProposal(); value.proposal.candidate_ready = false;
  const read = vi.spyOn(compositionApi, "proposal").mockResolvedValue(value.proposal);
  const submit = vi.spyOn(compositionApi, "submit");
  mount(value);
  const start = await screen.findByRole("button", { name: "Start fresh attempt within grant" });
  await new Promise(resolve => setTimeout(resolve, 1500));
  expect(read).toHaveBeenCalledOnce();
  expect(start).toBeDisabled();
  fireEvent.click(start);
  expect(submit).not.toHaveBeenCalled();
});
