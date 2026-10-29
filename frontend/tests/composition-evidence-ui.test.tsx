import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import * as Tooltip from "@radix-ui/react-tooltip";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { CompositionPage } from "../src/pages/Composition";
import { compositionApi, readCompositionPending } from "../src/lib/composition";
import { compositionKnowledgeApi } from "../src/lib/composition-knowledge";
import type { CompositionEvidenceContext } from "../src/lib/composition-evidence";
import { contextFixture, controlId, ownerId, proposalId } from "./composition-fixture";
import { evidenceFixture } from "./composition-evidence-fixture";
import { knowledgeResponse } from "./composition-knowledge-fixture";

vi.mock("../src/components/CompositionGraph", () => ({ CompositionGraph: () => <div>Read-only graph</div> }));
vi.mock("../src/lib/api", () => ({ DEMO_MODE: false, request: vi.fn(), ApiError: class extends Error {}, api: { catalog: vi.fn(async () => ({ ai: { providers: [{ provider_id: "configured", kind: "openai", model: "configured-model" }] } })) } }));
const historyOption = () => screen.getByRole("checkbox", { name: "Use selected historical findings to reconsider earlier choices" });
const requestButton = () => screen.getByRole("button", { name: "Request history-aware revision" });
function mount(proposal = false) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return { client, ...render(<QueryClientProvider client={client}><Tooltip.Provider><MemoryRouter initialEntries={[`/composition?control=${controlId}&objective=${ownerId}${proposal ? `&proposal=${proposalId}` : ""}`]}><CompositionPage /></MemoryRouter></Tooltip.Provider></QueryClientProvider>) };
}
beforeEach(() => {
  localStorage.clear();
  const { objective, context, proposal } = evidenceFixture();
  vi.spyOn(compositionApi, "list").mockResolvedValue({ schema_version: "bluefire.composition-objective-list.v1", objectives: [{ owner_id: ownerId, title: "Receiver objective", status: "active", job_state: "completed" }] });
  vi.spyOn(compositionApi, "objective").mockResolvedValue(objective);
  vi.spyOn(compositionApi, "context").mockResolvedValue(contextFixture());
  vi.spyOn(compositionApi, "evidenceContext").mockResolvedValue(context);
  vi.spyOn(compositionApi, "proposal").mockResolvedValue(proposal);
  vi.spyOn(compositionKnowledgeApi, "read").mockImplementation(async (value, ids) => knowledgeResponse(value, ids));
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

it("requests a distinct opt-in proposal from loaded older findings without using chat text", async () => {
  const submit = vi.spyOn(compositionApi, "submit").mockRejectedValue(new Error("Saved response pending"));
  const { objective, knowledge, prior, context } = evidenceFixture();
  mount();
  await screen.findByRole("heading", { name: "Evidence-driven revision" });
  expect(historyOption()).not.toBeChecked();
  expect(compositionApi.evidenceContext).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "Findings across attempts" }));
  await screen.findByRole("region", { name: "Findings from attempt 2" });
  fireEvent.click(screen.getByRole("checkbox", { name: "Attempt 2 Completed" }));
  fireEvent.click(screen.getByRole("button", { name: "Load selected findings" }));
  await screen.findByRole("region", { name: "Findings from attempt 1" });
  fireEvent.click(historyOption());
  fireEvent.change(screen.getByLabelText("Configured model provider"), { target: { value: "configured" } });
  await waitFor(() => expect(requestButton()).toBeEnabled());
  expect(compositionApi.evidenceContext).toHaveBeenLastCalledWith(ownerId, prior, knowledge);
  expect(screen.getByLabelText("Verified prior attempt")).toHaveValue(prior);
  expect(screen.getByText(/requires the separate model purpose/)).toBeVisible();
  fireEvent.click(requestButton());
  await waitFor(() => expect(submit).toHaveBeenCalledOnce());
  expect(submit.mock.calls[0]![0]).toMatchObject({ kind: "proposal", owner: ownerId, body: { schema_version: "bluefire.composition-evidence-proposal-request.v1", prior_attempt_id: prior, provider_id: "configured", attempt_ids: [objective.attempts[0]!.request.composition_attempt.attempt_id], knowledge_digest: knowledge.knowledge_digest, context_digest: context.context_digest } });
  expect(readCompositionPending()?.body).toEqual(submit.mock.calls[0]![0].body);
});

it("retains captured source reasoning after selection changes while blocking stale apply", async () => {
  const { context, knowledge } = evidenceFixture();
  vi.mocked(compositionApi.evidenceContext).mockImplementation(async (_owner, _prior, selected) => selected.attempts.length === 1 ? context : { ...context, context_digest: `sha256:${"f".repeat(64)}`, historical_context: { ...context.historical_context, attempts: selected.attempts, attempt_ids: selected.attempts.map(attempt => attempt.attempt_id), knowledge_digest: selected.knowledge_digest } });
  const submit = vi.spyOn(compositionApi, "submit");
  mount(true);
  const review = await screen.findByRole("region", { name: "Captured historical reasoning" });
  expect(review).toHaveTextContent(/do not establish current resource state/);
  expect(review).toHaveTextContent("Recheck the retained receiver before dispatch.");
  fireEvent.click(within(review).getByText("Earlier choice and source findings"));
  expect(within(review).getByRole("link", { name: "Open captured source run" })).toHaveAttribute("href", "/runs/run-history-1");
  expect(review).toHaveTextContent(knowledge.attempts[0]!.findings[0]!.finding_id);
  expect(historyOption()).toBeChecked();
  const start = screen.getByRole("button", { name: "Start fresh attempt within grant" });
  await waitFor(() => expect(start).toBeEnabled());
  fireEvent.click(screen.getByRole("button", { name: "Findings across attempts" }));
  await screen.findByRole("region", { name: "Findings from attempt 2" });
  await waitFor(() => expect(start).toBeDisabled());
  expect(review).toBeInTheDocument();
  fireEvent.click(start);
  expect(submit).not.toHaveBeenCalled();
});

it("preserves completed captured context and result across objective navigation", async () => {
  const other = `job-${"9".repeat(32)}`;
  const { objective } = evidenceFixture();
  const second = structuredClone(objective); second.owner.job_id = other; second.attempts = [];
  vi.mocked(compositionApi.objective).mockImplementation(async id => id === ownerId ? objective : second);
  vi.mocked(compositionApi.list).mockResolvedValue({ schema_version: "bluefire.composition-objective-list.v1", objectives: [{ owner_id: ownerId, title: "Receiver objective", status: "active", job_state: "completed" }, { owner_id: other, title: "Other objective", status: "active", job_state: "completed" }] });
  mount(true);
  await screen.findByRole("region", { name: "Captured historical reasoning" });
  fireEvent.click(screen.getByRole("link", { name: "Open objective: Other objective, Active" }));
  await screen.findByRole("heading", { name: "Initial graph" });
  expect(screen.queryByRole("region", { name: "Captured historical reasoning" })).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("link", { name: "Open objective: Receiver objective, Active" }));
  expect(await screen.findByRole("region", { name: "Captured historical reasoning" })).toHaveTextContent("Reconsider the original collection choice");
});

it("discards late historical context failures after Stop and keeps the captured reasoning", async () => {
  const { objective } = evidenceFixture();
  let fail!: (reason: Error) => void;
  vi.mocked(compositionApi.evidenceContext).mockReturnValue(new Promise<CompositionEvidenceContext>((_resolve, reject) => { fail = reject; }));
  vi.spyOn(compositionApi, "control").mockResolvedValue({ ...objective, grant: { ...objective.grant, status: "paused" } });
  mount(true);
  await screen.findByRole("region", { name: "Captured historical reasoning" });
  await waitFor(() => expect(compositionApi.evidenceContext).toHaveBeenCalledOnce());
  fireEvent.click(screen.getByRole("button", { name: "Stop" }));
  await screen.findByText("Paused");
  await act(async () => fail(new Error("Stale historical context failure")));
  expect(screen.queryByText("Stale historical context failure")).not.toBeInTheDocument();
  expect(screen.getByRole("region", { name: "Captured historical reasoning" })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Start fresh attempt within grant" })).toBeDisabled();
});

it("keeps an explicit mode change when a recovered proposal refreshes", async () => {
  const { proposal } = evidenceFixture();
  const { client } = mount(true);
  await screen.findByRole("region", { name: "Captured historical reasoning" });
  expect(historyOption()).toBeChecked();
  fireEvent.click(historyOption());
  vi.mocked(compositionApi.proposal).mockResolvedValue({ ...proposal, job: { ...proposal.job, progress: { refreshed: true } } });
  await act(async () => { await client.refetchQueries({ queryKey: ["composition-proposal", proposalId] }); });
  expect(historyOption()).not.toBeChecked();
  expect(screen.getByRole("region", { name: "Captured historical reasoning" })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Start fresh attempt within grant" })).toBeDisabled();
});

it("never applies a late historical context to a different objective", async () => {
  const { objective, context } = evidenceFixture();
  const other = `job-${"9".repeat(32)}`;
  const second = structuredClone(objective); second.owner.job_id = other; second.attempts = [];
  vi.mocked(compositionApi.objective).mockImplementation(async id => id === ownerId ? objective : second);
  vi.mocked(compositionApi.list).mockResolvedValue({ schema_version: "bluefire.composition-objective-list.v1", objectives: [{ owner_id: ownerId, title: "Receiver objective", status: "active", job_state: "completed" }, { owner_id: other, title: "Other objective", status: "active", job_state: "completed" }] });
  let finish!: (value: CompositionEvidenceContext) => void;
  vi.mocked(compositionApi.evidenceContext).mockReturnValue(new Promise(resolve => { finish = resolve; }));
  const submit = vi.spyOn(compositionApi, "submit");
  mount(true);
  await waitFor(() => expect(compositionApi.evidenceContext).toHaveBeenCalledOnce());
  fireEvent.click(screen.getByRole("link", { name: "Open objective: Other objective, Active" }));
  await screen.findByRole("heading", { name: "Initial graph" });
  await act(async () => finish(context));
  expect(screen.queryByRole("region", { name: "Captured historical reasoning" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Start fresh attempt within grant" })).not.toBeInTheDocument();
  expect(submit).not.toHaveBeenCalled();
});
