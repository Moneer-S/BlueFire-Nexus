import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import * as Tooltip from "@radix-ui/react-tooltip";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { CompositionPage } from "../src/pages/Composition";
import { compositionApi } from "../src/lib/composition";
import { contextFixture, controlId, objectiveFixture, ownerId, proposalFixture, proposalId, question } from "./composition-fixture";

vi.mock("../src/components/CompositionGraph", () => ({ CompositionGraph: () => <div>Read-only graph</div> }));
vi.mock("../src/lib/api", () => ({ DEMO_MODE: false, request: vi.fn(), ApiError: class extends Error {}, api: { catalog: vi.fn(async () => ({ ai: { providers: [{ provider_id: "configured", kind: "openai", model: "configured-model" }] } })) } }));
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

function initialProposal() {
  return { objective: objectiveFixture(), context: contextFixture(), proposal: proposalFixture() };
}
function mount(value: ReturnType<typeof initialProposal>) {
  localStorage.clear();
  vi.spyOn(compositionApi, "list").mockResolvedValue({ schema_version: "bluefire.composition-objective-list.v1", objectives: [{ owner_id: ownerId, title: question, status: "active", job_state: "completed" }] });
  vi.spyOn(compositionApi, "objective").mockResolvedValue(value.objective);
  vi.spyOn(compositionApi, "context").mockResolvedValue(value.context);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(<QueryClientProvider client={client}><Tooltip.Provider><MemoryRouter initialEntries={[`/composition?control=${controlId}&objective=${ownerId}&proposal=${proposalId}`]}><CompositionPage /></MemoryRouter></Tooltip.Provider></QueryClientProvider>);
}

it("polls a receiver candidate published before its job completes, then requires one operator dispatch", async () => {
  const value = initialProposal();
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

it("does not keep polling or enable a completed receiver candidate that is not ready", async () => {
  const value = initialProposal(); value.proposal.candidate_ready = false;
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
