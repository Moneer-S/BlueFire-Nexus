import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import * as Tooltip from "@radix-ui/react-tooltip";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { CompositionSetup } from "../src/components/CompositionReview";
import { CompositionPage } from "../src/pages/Composition";
import { compositionApi, FILE_ACCESS_PACK, readCompositionPending, storeCompositionCancellation, storeCompositionControl, storeCompositionPending } from "../src/lib/composition";
import { fileAccessObjectiveFixture } from "./file-access-fixture";
import { attemptFixture, contextFixture, controlId, grantRequestFixture, objectiveFixture, ownerId, proposalFixture, proposalId, question, refusalFixture, reviewFixture, testDigest } from "./composition-fixture";

vi.mock("../src/components/CompositionGraph", () => ({ CompositionGraph: () => <div>Read-only graph</div> }));
vi.mock("../src/lib/api", () => ({ DEMO_MODE: false, request: vi.fn(), ApiError: class extends Error {}, api: { catalog: vi.fn(async () => ({ ai: { providers: [] } })) } }));
function mount(element: React.ReactNode, path = "/composition") { const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } }); return { ...render(<QueryClientProvider client={client}><Tooltip.Provider><MemoryRouter initialEntries={[path]}>{element}</MemoryRouter></Tooltip.Provider></QueryClientProvider>), client }; }
beforeEach(() => { localStorage.clear(); vi.spyOn(compositionApi, "list").mockResolvedValue({ schema_version: "bluefire.composition-objective-list.v1", objectives: [{ owner_id: ownerId, title: question, status: "active", job_state: "completed" }] }); vi.spyOn(compositionApi, "context").mockResolvedValue(contextFixture()); });
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

it("requires fresh finite review, unchecked acknowledgment and reviewer before issue", async () => {
  vi.spyOn(compositionApi, "review").mockResolvedValue(reviewFixture()); const onSubmit = vi.fn();
  mount(<CompositionSetup control={controlId} disabled={false} onSubmit={onSubmit} />);
  fireEvent.change(screen.getByRole("textbox", { name: "Objective question" }), { target: { value: question } });
  fireEvent.click(screen.getByRole("button", { name: "Review finite delegation" }));
  const grant = await screen.findByRole("button", { name: "Issue capability grant" });
  expect(grant).toBeDisabled(); expect(screen.getByRole("checkbox")).not.toBeChecked();
  expect(screen.getByText(/not a total-storage hard cap/)).toBeInTheDocument();
  fireEvent.click(screen.getByRole("checkbox")); expect(grant).toBeDisabled();
  fireEvent.change(screen.getByRole("textbox", { name: "Delegation reviewed by" }), { target: { value: "reviewer" } });
  fireEvent.click(grant); expect(onSubmit).toHaveBeenCalledOnce();
  expect(onSubmit.mock.calls[0]![0].body).toMatchObject({ review_digest: testDigest, reviewed_by: "reviewer", review: { control_owner_id: controlId, question, limits: null } });
});
it("opens saved objectives without needing an objective URL", async () => {
  mount(<CompositionPage />, `/composition?control=${controlId}`);
  const link = await screen.findByRole("link", { name: `Open objective: ${question}, Active` });
  expect(link).toHaveAttribute("href", `/composition?control=${controlId}&objective=${ownerId}`);
});
it("preserves the server's zero-edge lower bound when reviewing limits", async () => {
  const value = reviewFixture(); value.limits.max_edges_per_attempt = 0;
  vi.spyOn(compositionApi, "review").mockResolvedValue(value);
  mount(<CompositionSetup control={controlId} disabled={false} onSubmit={vi.fn()} />);
  fireEvent.change(screen.getByRole("textbox", { name: "Objective question" }), { target: { value: question } });
  fireEvent.click(screen.getByRole("button", { name: "Review finite delegation" }));
  fireEvent.click(await screen.findByRole("button", { name: "Adjust requested limits" }));
  const input = screen.getByLabelText("Edges per attempt");
  expect(input).toHaveAttribute("min", "0"); expect(input).toHaveValue(0);
});
it("reloads an unresolved exact attempt without automatically sending it", async () => {
  const submit = vi.spyOn(compositionApi, "submit"); vi.spyOn(compositionApi, "objective").mockResolvedValue(objectiveFixture());
  storeCompositionPending({ kind: "attempt", owner: ownerId, control: controlId, id: proposalId, body: { submission_id: "cccccccc-cccc-cccc-cccc-cccccccccccc", proposal: contextFixture().initial_proposal, prior_attempt_id: null } });
  mount(<CompositionPage />);
  await screen.findByText("Request confirmation pending");
  expect(submit).not.toHaveBeenCalled();
  expect(screen.getByRole("button", { name: "Retry exact submission" })).toBeInTheDocument();
});
it("leaves Stop and Revoke available when current state cannot be fetched", async () => {
  vi.spyOn(compositionApi, "objective").mockRejectedValue(new Error("transport unknown"));
  const control = vi.spyOn(compositionApi, "control").mockRejectedValue(new Error("response unknown"));
  mount(<CompositionPage />, `/composition?control=${controlId}&objective=${ownerId}`);
  await screen.findByText("Current objective unavailable");
  expect(screen.getByRole("button", { name: "Stop" })).toBeEnabled();
  fireEvent.click(screen.getByRole("button", { name: "Revoke" }));
  await waitFor(() => expect(control).toHaveBeenCalledWith(ownerId, "revoke"));
  await screen.findByText("Control request not confirmed");
  expect(screen.getByRole("button", { name: "Stop" })).toBeEnabled();
});
it("offers established initial graph without selecting a provider or mutating working graph", async () => {
  vi.spyOn(compositionApi, "objective").mockResolvedValue(objectiveFixture());
  mount(<CompositionPage />, `/composition?control=${controlId}&objective=${ownerId}`);
  fireEvent.click(await screen.findByRole("button", { name: "Review established graph" }));
  expect(await screen.findByRole("button", { name: "Start fresh attempt within grant" })).toBeEnabled();
  expect(screen.getByRole("button", { name: "Request AI graph" })).toBeDisabled();
  fireEvent.click(screen.getByRole("button", { name: "Inspect graph" }));
  expect(await screen.findByText("Read-only graph")).toBeInTheDocument();
});
it("keeps an unconfirmed Stop binding after reload even if the last server view is active", async () => {
  vi.spyOn(compositionApi, "objective").mockResolvedValue(objectiveFixture());
  storeCompositionControl(ownerId, "stop");
  mount(<CompositionPage />, `/composition?control=${controlId}&objective=${ownerId}`);
  await screen.findByText("Stop confirmation pending");
  expect(screen.queryByRole("button", { name: "Start fresh attempt within grant" })).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Retry exact control request" })).toBeEnabled();
});
it("does not execute a saved candidate against changed evidence", async () => {
  vi.spyOn(compositionApi, "objective").mockResolvedValue(objectiveFixture());
  vi.spyOn(compositionApi, "proposal").mockResolvedValue(proposalFixture());
  vi.mocked(compositionApi.context).mockResolvedValue({ ...contextFixture(), context_digest: `sha256:${"e".repeat(64)}` });
  mount(<CompositionPage />, `/composition?control=${controlId}&objective=${ownerId}&proposal=${proposalId}`);
  const start = await screen.findByRole("button", { name: "Start fresh attempt within grant" });
  expect(start).toBeDisabled(); expect(screen.getByText("Candidate no longer matches current evidence")).toBeInTheDocument();
});
it("never presents Continue as replay and leaves expired grants non-executable", async () => {
  const value = objectiveFixture(); value.grant.status = "paused";
  vi.spyOn(compositionApi, "objective").mockResolvedValue(value);
  mount(<CompositionPage />, `/composition?control=${controlId}&objective=${ownerId}`);
  await screen.findByRole("button", { name: "Continue objective" });
  expect(screen.getByText(/does not replay an interrupted attempt/)).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Start fresh attempt within grant" })).not.toBeInTheDocument();
});
it("retains unknown proposal cancellation across reload without sending or executing a late candidate", async () => {
  vi.spyOn(compositionApi, "objective").mockResolvedValue(objectiveFixture());
  vi.spyOn(compositionApi, "proposal").mockResolvedValue(proposalFixture());
  const cancel = vi.spyOn(compositionApi, "cancel"); const submit = vi.spyOn(compositionApi, "submit");
  storeCompositionCancellation(ownerId, proposalId);
  mount(<CompositionPage />, `/composition?control=${controlId}&objective=${ownerId}`);
  await screen.findByText("Proposal cancellation pending");
  expect(await screen.findByRole("button", { name: "Retry exact proposal cancellation" })).toBeEnabled();
  const start = await screen.findByRole("button", { name: "Start fresh attempt within grant" });
  expect(start).toBeDisabled();
  expect(cancel).not.toHaveBeenCalled(); expect(submit).not.toHaveBeenCalled();
});
it.each(["stop", "continue"] as const)("binds a late %s response to its original objective after navigation", async operation => {
  const a = objectiveFixture(); a.grant.status = operation === "continue" ? "paused" : "active";
  const b = objectiveFixture(); b.owner.job_id = `job-${"e".repeat(32)}`; b.grant.document.objective.question = "Second objective";
  const terminal = structuredClone(a); terminal.grant.status = operation === "continue" ? "active" : "paused";
  vi.mocked(compositionApi.list).mockResolvedValue({ schema_version: "bluefire.composition-objective-list.v1", objectives: [a, b].map(value => ({ owner_id: value.owner.job_id, title: value.grant.document.objective.question, status: value.grant.status, job_state: "completed" })) });
  vi.spyOn(compositionApi, "objective").mockImplementation(async id => id === ownerId ? a : b);
  let finish!: (value: typeof terminal) => void;
  const control = vi.spyOn(compositionApi, "control").mockReturnValue(new Promise(resolve => { finish = resolve; }));
  const { client } = mount(<CompositionPage />, `/composition?control=${controlId}&objective=${ownerId}`);
  fireEvent.click(await screen.findByRole("button", { name: operation === "stop" ? "Stop" : "Continue objective" }));
  await waitFor(() => expect(control).toHaveBeenCalledWith(ownerId, operation));
  fireEvent.click(await screen.findByRole("link", { name: "Open objective: Second objective, Active" }));
  await screen.findByRole("heading", { name: "Second objective" });
  await act(async () => finish(terminal));
  await waitFor(() => expect(screen.getByRole("heading", { name: "Second objective" })).toBeInTheDocument());
  expect(client.getQueryData(["composition-objective", b.owner.job_id])).toEqual(b);
  expect(client.getQueryData(["composition-objective", ownerId])).toEqual(terminal);
});
it("does not request revisions from an already established accepted attempt", async () => {
  const value = objectiveFixture(); value.attempts = [attemptFixture(true)];
  vi.spyOn(compositionApi, "objective").mockResolvedValue(value);
  mount(<CompositionPage />, `/composition?control=${controlId}&objective=${ownerId}`);
  expect(await screen.findByRole("option", { name: "Attempt 1: established" })).toBeDisabled();
  expect(screen.getByRole("button", { name: "Request evidence-based revision" })).toBeDisabled();
  expect(compositionApi.context).not.toHaveBeenCalled();
});
it.each(["allowed", "permission_denied", "unknown"] as const)("keeps the %s file-access attempt in the existing workspace without inventing revision authority", async decision => {
  vi.spyOn(compositionApi, "objective").mockResolvedValue(fileAccessObjectiveFixture(decision));
  const submit = vi.spyOn(compositionApi, "submit");
  mount(<CompositionPage />, `/composition?control=${controlId}&objective=${ownerId}&pack=${FILE_ACCESS_PACK}`);
  expect(await screen.findByRole("link", { name: "Review retained file-access control" })).toHaveAttribute("href", `/file-access?control=${controlId}`);
  expect(screen.getByRole("button", { name: "Stop" })).toBeEnabled();
  expect(screen.getByRole("button", { name: "Revoke" })).toBeEnabled();
  expect(screen.queryByRole("button", { name: /Request.*revision/ })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Start fresh attempt within grant" })).not.toBeInTheDocument();
  expect(compositionApi.context).not.toHaveBeenCalled(); expect(submit).not.toHaveBeenCalled();
});
it("recovers a stale-review refusal on reload and offers a new explicit review without replay", async () => {
  vi.spyOn(compositionApi, "objective").mockResolvedValue(refusalFixture());
  const submit = vi.spyOn(compositionApi, "submit"); const review = vi.spyOn(compositionApi, "review");
  storeCompositionPending({ kind: "grant", owner: ownerId, control: controlId, id: ownerId, body: grantRequestFixture() });
  mount(<CompositionPage />);
  await screen.findByText("Delegation refused");
  await waitFor(() => expect(readCompositionPending()).toBeUndefined());
  expect(screen.getByText("No capability grant or execution authority was issued.")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Review again" }));
  expect(await screen.findByRole("textbox", { name: "Objective question" })).toHaveValue(question);
  expect(screen.getByRole("button", { name: "Review finite delegation" })).toBeEnabled();
  expect(screen.queryByRole("button", { name: "Issue capability grant" })).not.toBeInTheDocument();
  expect(submit).not.toHaveBeenCalled(); expect(review).not.toHaveBeenCalled();
});
it("does not reopen a completed objective by selecting an earlier refusal", async () => {
  const value = objectiveFixture(); const success = attemptFixture(true);
  success.job_id = `job-${"e".repeat(32)}`; success.request.composition_attempt.attempt_id = `attempt-${"e".repeat(32)}`;
  value.attempts = [attemptFixture(), success];
  vi.spyOn(compositionApi, "objective").mockResolvedValue(value);
  mount(<CompositionPage />, `/composition?control=${controlId}&objective=${ownerId}`);
  const select = await screen.findByLabelText("Verified prior attempt");
  fireEvent.change(select, { target: { value: value.attempts[0]!.request.composition_attempt.attempt_id } });
  expect(screen.getByRole("button", { name: "Request evidence-based revision" })).toBeDisabled();
  expect(screen.getByText(/A settled verified attempt meets every reviewed success condition/)).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Stop" })).toBeEnabled(); expect(screen.getByRole("button", { name: "Revoke" })).toBeEnabled();
  expect(screen.getAllByRole("link", { name: "Inspect verified run evidence" })).toHaveLength(2);
  expect(compositionApi.context).not.toHaveBeenCalled();
});
it("keeps the complete objective accessible while its visual heading is collapsed", async () => {
  const value = objectiveFixture(); value.grant.document.objective.question = "Long reviewed objective ".repeat(80);
  vi.spyOn(compositionApi, "objective").mockResolvedValue(value);
  mount(<CompositionPage />, `/composition?control=${controlId}&objective=${ownerId}`);
  const heading = await screen.findByRole("heading", { level: 1, name: value.grant.document.objective.question.trim() });
  const expand = screen.getByRole("button", { name: "Show full objective question" });
  expect(expand).toHaveAttribute("aria-expanded", "false");
  expect(heading.closest(".composition-page")).not.toHaveClass("composition-objective-expanded");
  fireEvent.click(expand);
  expect(screen.getByRole("button", { name: "Collapse objective question" })).toHaveAttribute("aria-expanded", "true");
  expect(heading.closest(".composition-page")).toHaveClass("composition-objective-expanded");
  expect(screen.getByRole("button", { name: "Stop" })).toBeEnabled();
  fireEvent.click(screen.getByRole("button", { name: "Collapse objective question" }));
  expect(heading).toHaveTextContent(value.grant.document.objective.question.trim());
  expect(heading.closest(".composition-page")).not.toHaveClass("composition-objective-expanded");
});
it.each(["stop", "revoke"] as const)("discards a late context failure after %s without a new planning request", async operation => {
  let value = objectiveFixture();
  vi.spyOn(compositionApi, "objective").mockImplementation(async () => value);
  let rejectContext!: (reason: Error) => void;
  vi.mocked(compositionApi.context).mockReturnValueOnce(new Promise((_resolve, reject) => { rejectContext = reject; }));
  const control = vi.spyOn(compositionApi, "control").mockImplementation(async (_owner, action) => {
    value = structuredClone(value); value.grant.status = action === "continue" ? "active" : action === "stop" ? "paused" : "revoked"; return value;
  });
  const submit = vi.spyOn(compositionApi, "submit");
  mount(<CompositionPage />, `/composition?control=${controlId}&objective=${ownerId}`);
  await waitFor(() => expect(compositionApi.context).toHaveBeenCalledOnce());
  fireEvent.click(screen.getByRole("button", { name: operation === "stop" ? "Stop" : "Revoke" }));
  await waitFor(() => expect(control).toHaveBeenCalledWith(ownerId, operation));
  await screen.findByText(operation === "stop" ? "Paused" : "Revoked");
  await act(async () => rejectContext(new Error("Late context refusal after control change")));
  expect(screen.queryByText("Late context refusal after control change")).not.toBeInTheDocument();
  expect(screen.queryByText("Verifying current facts and capabilities")).not.toBeInTheDocument();
  expect(compositionApi.context).toHaveBeenCalledOnce();
  expect(submit).not.toHaveBeenCalled();
  if (operation === "stop") {
    fireEvent.click(await screen.findByRole("button", { name: "Continue objective" }));
    await waitFor(() => expect(compositionApi.context).toHaveBeenCalledTimes(2));
    fireEvent.click(await screen.findByRole("button", { name: "Review established graph" }));
    expect(await screen.findByRole("button", { name: "Start fresh attempt within grant" })).toBeEnabled();
    expect(submit).not.toHaveBeenCalled();
  }
});
it("still exposes a current active planning failure", async () => {
  vi.spyOn(compositionApi, "objective").mockResolvedValue(objectiveFixture());
  vi.mocked(compositionApi.context).mockRejectedValue(new Error("Current evidence cannot be verified"));
  mount(<CompositionPage />, `/composition?control=${controlId}&objective=${ownerId}`);
  await screen.findByText("Current evidence cannot be verified");
  expect(screen.getByRole("button", { name: "Request AI graph" })).toBeDisabled();
  expect(screen.getByRole("button", { name: "Stop" })).toBeEnabled();
});
