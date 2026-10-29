import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import * as Tooltip from "@radix-ui/react-tooltip";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { MemoryRouter, useLocation } from "react-router-dom";
import { CompositionSetup } from "../src/components/CompositionReview";
import { CompositionPage } from "../src/pages/Composition";
import { compositionApi, FILE_ACCESS_PACK, MACOS_FILE_ACCESS_PACK, readCompositionPending, storeCompositionCancellation, storeCompositionControl, storeCompositionPending } from "../src/lib/composition";
import { fileAccessApi } from "../src/lib/file-access";
import { fileAccessLinkageApi } from "../src/lib/file-access-linkage";
import { macOSControlFixture, macOSOwner, macOSStatusFixture } from "./macos-file-access-fixture";
import { macContextFixture, macObjectiveFixture, macRequestFixture, macReviewFixture } from "./macos-composition-fixture";
import { fileAccessObjectiveFixture } from "./file-access-fixture";
import { linkageFixture } from "./file-access-linkage-fixture";
import { attemptFixture, contextFixture, controlId, grantRequestFixture, objectiveFixture, ownerId, proposalFixture, proposalId, question, refusalFixture, reviewFixture, testDigest } from "./composition-fixture";

vi.mock("../src/components/CompositionGraph", () => ({ CompositionGraph: () => <div>Read-only graph</div> }));
vi.mock("../src/lib/api", () => ({ DEMO_MODE: false, request: vi.fn(), ApiError: class extends Error {}, api: { catalog: vi.fn(async () => ({ ai: { providers: [] } })) } }));
function CurrentLocation() { const location = useLocation(); return <output data-testid="current-location">{location.pathname}{location.search}</output>; }
function mount(element: React.ReactNode, path = "/composition", showLocation = false) { const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } }); return { ...render(<QueryClientProvider client={client}><Tooltip.Provider><MemoryRouter initialEntries={[path]}>{showLocation ? <CurrentLocation /> : null}{element}</MemoryRouter></Tooltip.Provider></QueryClientProvider>), client }; }
beforeEach(() => { localStorage.clear(); vi.spyOn(compositionApi, "list").mockResolvedValue({ schema_version: "bluefire.composition-objective-list.v1", objectives: [{ owner_id: ownerId, title: question, status: "active", job_state: "completed" }] }); vi.spyOn(compositionApi, "context").mockResolvedValue(contextFixture()); });
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

function macWorkspace(outcome: "none" | "settled" | "unknown" = "none") {
  vi.spyOn(fileAccessApi, "status").mockResolvedValue(macOSStatusFixture());
  vi.spyOn(fileAccessApi, "control").mockResolvedValue(macOSControlFixture("hardened"));
  const value = macObjectiveFixture(outcome);
  vi.spyOn(compositionApi, "objective").mockResolvedValue(value);
  vi.mocked(compositionApi.context).mockResolvedValue(macContextFixture());
  return value;
}

it("reviews Mac delegation with its distinct pack and original-request closure wording", async () => {
  vi.spyOn(compositionApi, "review").mockResolvedValue(macReviewFixture());
  const submit = vi.fn();
  mount(<CompositionSetup control={macOSOwner} pack={MACOS_FILE_ACCESS_PACK} disabled={false} onSubmit={submit} />);
  fireEvent.change(screen.getByLabelText("Objective question"), { target: { value: macRequestFixture().question } });
  fireEvent.click(screen.getByRole("button", { name: "Review finite delegation" }));
  await screen.findByRole("button", { name: "Issue capability grant" });
  expect(compositionApi.review).toHaveBeenCalledWith(macRequestFixture());
  expect(screen.getByText(/not independent telemetry/)).toBeInTheDocument();
  expect(screen.getByText(/not enrollment cleanup/)).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText("Delegation reviewed by"), { target: { value: "operator" } });
  fireEvent.click(screen.getByRole("checkbox"));
  fireEvent.click(screen.getByRole("button", { name: "Issue capability grant" }));
  expect(submit.mock.calls[0]![0]).toMatchObject({ kind: "grant", control: macOSOwner, body: { review: macRequestFixture() } });
});

it("dispatches only the reviewed backend initial Mac graph without AI planning", async () => {
  macWorkspace();
  const submit = vi.spyOn(compositionApi, "submit").mockRejectedValue(new Error("Response pending"));
  mount(<CompositionPage />, `/composition?control=${macOSOwner}&objective=${ownerId}&pack=${MACOS_FILE_ACCESS_PACK}`);
  fireEvent.click(await screen.findByRole("button", { name: "Review established graph" }));
  expect(screen.queryByLabelText("Configured model provider")).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Request AI graph" })).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Start fresh attempt within grant" }));
  await waitFor(() => expect(submit).toHaveBeenCalledOnce());
  expect(submit.mock.calls[0]![0]).toMatchObject({ kind: "attempt", control: macOSOwner, body: { proposal: macContextFixture().initial_proposal, prior_attempt_id: null } });
});

it.each(["settled", "unknown"] as const)("keeps a %s Mac attempt in history without another attempt or revision", async outcome => {
  macWorkspace(outcome);
  const submit = vi.spyOn(compositionApi, "submit");
  mount(<CompositionPage />, `/composition?control=${macOSOwner}&objective=${ownerId}&pack=${MACOS_FILE_ACCESS_PACK}`);
  await screen.findByRole("link", { name: "Review retained file-access control" });
  expect(screen.queryByRole("button", { name: /Start fresh attempt|Request.*graph|Request.*revision/ })).not.toBeInTheDocument();
  expect(compositionApi.context).not.toHaveBeenCalled();
  expect(screen.queryByText("Native cleanup")).not.toBeInTheDocument();
  expect(screen.getByText("Whole-enrollment cleanup")).toBeInTheDocument();
  if (outcome === "settled") {
    expect(screen.getByText("Not created")).toBeInTheDocument();
    expect(screen.getByText("Retained")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Inspect verified run evidence" })).toHaveAttribute("href", "/runs/run-proof");
  } else expect(screen.getByRole("link", { name: "Inspect finalized run evidence" })).toHaveAttribute("href", "/runs/run-proof");
  expect(submit).not.toHaveBeenCalled();
});

it("blocks new Mac dispatch throughout deferred status refresh but preserves Stop and Revoke", async () => {
  const value = macWorkspace();
  const submit = vi.spyOn(compositionApi, "submit");
  const control = vi.spyOn(compositionApi, "control").mockResolvedValue({ ...value, grant: { ...value.grant, status: "revoked" } });
  const { client } = mount(<CompositionPage />, `/composition?control=${macOSOwner}&objective=${ownerId}&pack=${MACOS_FILE_ACCESS_PACK}`);
  fireEvent.click(await screen.findByRole("button", { name: "Review established graph" }));
  const start = screen.getByRole("button", { name: "Start fresh attempt within grant" });
  expect(start).toBeEnabled();
  let resolveStatus!: (status: ReturnType<typeof macOSStatusFixture>) => void;
  vi.mocked(fileAccessApi.status).mockReturnValue(new Promise(resolve => { resolveStatus = resolve; }));
  void client.invalidateQueries({ queryKey: ["file-access-status"] });
  await waitFor(() => expect(start).toBeDisabled());
  fireEvent.click(start);
  expect(screen.getByRole("button", { name: "Stop" })).toBeEnabled();
  expect(screen.getByRole("button", { name: "Revoke" })).toBeEnabled();
  await act(async () => resolveStatus(macOSStatusFixture(false)));
  await screen.findByText("Original macOS workspace is read-only");
  expect(start).toBeDisabled();
  expect(submit).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "Revoke" }));
  await waitFor(() => expect(control).toHaveBeenCalledWith(ownerId, "revoke"));
});

it("refreshes saved objectives under the original control after Revoke", async () => {
  const value = objectiveFixture();
  vi.spyOn(compositionApi, "objective").mockResolvedValue(value);
  const control = vi.spyOn(compositionApi, "control").mockResolvedValue({
    ...value,
    grant: { ...value.grant, status: "revoked" },
  });
  const list = vi.mocked(compositionApi.list);
  mount(<CompositionPage />, `/composition?control=${controlId}&objective=${ownerId}`);

  await waitFor(() => expect(list).toHaveBeenCalledTimes(1));
  fireEvent.click(await screen.findByRole("button", { name: "Revoke" }));
  await screen.findByText("Revoked");
  await waitFor(() => expect(list).toHaveBeenCalledTimes(2));

  expect(control).toHaveBeenCalledWith(ownerId, "revoke");
  expect(list).toHaveBeenNthCalledWith(1, controlId);
  expect(list).toHaveBeenNthCalledWith(2, controlId);
});

it("retains pending Mac attempts for status checks without exact-submission replay", async () => {
  macWorkspace();
  storeCompositionPending({ kind: "attempt", owner: ownerId, control: macOSOwner, id: proposalId, body: { submission_id: "cccccccc-cccc-cccc-cccc-cccccccccccc", proposal: macContextFixture().initial_proposal, prior_attempt_id: null } });
  const submit = vi.spyOn(compositionApi, "submit");
  mount(<CompositionPage />);
  await screen.findByText("Request confirmation pending");
  expect(screen.getByRole("button", { name: "Check saved status" })).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Retry exact submission" })).not.toBeInTheDocument();
  expect(submit).not.toHaveBeenCalled();
});

it("keeps a Mac admission refusal readable without offering a grant while custody is unavailable", async () => {
  macWorkspace();
  vi.mocked(fileAccessApi.status).mockResolvedValue(macOSStatusFixture(false));
  const refusal = refusalFixture();
  refusal.owner.progress.submitted_request = { ...grantRequestFixture(), review: macRequestFixture() };
  vi.mocked(compositionApi.objective).mockResolvedValue(refusal);
  const submit = vi.spyOn(compositionApi, "submit");
  mount(<CompositionPage />, `/composition?control=${macOSOwner}&objective=${ownerId}&pack=${MACOS_FILE_ACCESS_PACK}`);
  await screen.findByText("Delegation refused");
  expect(screen.getByRole("button", { name: "Review again" })).toBeDisabled();
  expect(screen.getByText("No capability grant or execution authority was issued.")).toBeInTheDocument();
  expect(submit).not.toHaveBeenCalled();
});

it("keeps Mac Continue disabled without live custody while saved revocation remains available", async () => {
  const value = macWorkspace("unknown"); value.grant.status = "paused";
  vi.mocked(fileAccessApi.status).mockResolvedValue(macOSStatusFixture(false));
  mount(<CompositionPage />, `/composition?control=${macOSOwner}&objective=${ownerId}&pack=${MACOS_FILE_ACCESS_PACK}`);
  expect(await screen.findByRole("button", { name: "Continue objective" })).toBeDisabled();
  expect(screen.getByRole("button", { name: "Stop" })).toBeEnabled();
  expect(screen.getByRole("button", { name: "Revoke" })).toBeEnabled();
  expect(screen.getByRole("link", { name: "Inspect finalized run evidence" })).toBeInTheDocument();
});

it("does not obtain a new Mac graph from an expired original enrollment", async () => {
  macWorkspace();
  const status = macOSStatusFixture(); status.enrollment!.expires_at_ms = Date.now() - 1;
  vi.mocked(fileAccessApi.status).mockResolvedValue(status);
  const submit = vi.spyOn(compositionApi, "submit");
  mount(<CompositionPage />, `/composition?control=${macOSOwner}&objective=${ownerId}&pack=${MACOS_FILE_ACCESS_PACK}`);
  await screen.findByRole("heading", { name: "Verify the retained Mac control" });
  expect(screen.getByText("Original macOS workspace is read-only")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Review established graph" })).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Revoke" })).toBeEnabled();
  expect(compositionApi.context).not.toHaveBeenCalled(); expect(submit).not.toHaveBeenCalled();
});

it.each(["attempt", "continue"] as const)("refuses Mac %s at the exact grant expiry before the next UI clock tick", async operation => {
  const observed = Date.now();
  const clock = vi.spyOn(Date, "now").mockReturnValue(observed);
  const value = macWorkspace();
  value.grant.document.expires_at_ms = observed + 10_000;
  if (operation === "continue") value.grant.status = "paused";
  const submit = vi.spyOn(compositionApi, "submit");
  const control = vi.spyOn(compositionApi, "control").mockResolvedValue({ ...value, grant: { ...value.grant, status: "revoked" } });
  mount(<CompositionPage />, `/composition?control=${macOSOwner}&objective=${ownerId}&pack=${MACOS_FILE_ACCESS_PACK}`);
  if (operation === "attempt") fireEvent.click(await screen.findByRole("button", { name: "Review established graph" }));
  const button = await screen.findByRole("button", { name: operation === "attempt" ? "Start fresh attempt within grant" : "Continue objective" });
  await waitFor(() => expect(button).toBeEnabled());
  clock.mockReturnValue(value.grant.document.expires_at_ms);
  // No timer or render runs between the boundary crossing and this click.
  expect(button).toBeEnabled();
  fireEvent.click(button);
  expect(submit).not.toHaveBeenCalled(); expect(control).not.toHaveBeenCalled();
  expect(screen.getByRole("button", { name: "Stop" })).toBeEnabled();
  expect(screen.getByRole("button", { name: "Revoke" })).toBeEnabled();
  fireEvent.click(screen.getByRole("button", { name: "Revoke" }));
  await waitFor(() => expect(control).toHaveBeenCalledWith(ownerId, "revoke"));
});

it("allows initial Mac grant submission without a saved grant expiry", async () => {
  macWorkspace();
  vi.spyOn(compositionApi, "review").mockResolvedValue(macReviewFixture());
  const submit = vi.spyOn(compositionApi, "submit").mockRejectedValue(new Error("Response pending"));
  mount(<CompositionPage />, `/composition?control=${macOSOwner}&pack=${MACOS_FILE_ACCESS_PACK}`);
  const question = await screen.findByLabelText("Objective question");
  await waitFor(() => expect(question).toBeEnabled());
  fireEvent.change(question, { target: { value: macRequestFixture().question } });
  fireEvent.click(screen.getByRole("button", { name: "Review finite delegation" }));
  await screen.findByRole("button", { name: "Issue capability grant" });
  fireEvent.change(screen.getByLabelText("Delegation reviewed by"), { target: { value: "operator" } });
  fireEvent.click(screen.getByRole("checkbox"));
  fireEvent.click(screen.getByRole("button", { name: "Issue capability grant" }));
  await waitFor(() => expect(submit).toHaveBeenCalledOnce());
  expect(submit.mock.calls[0]![0]).toMatchObject({ kind: "grant", control: macOSOwner, body: { review: macRequestFixture() } });
});

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
it("reopens a saved same-context proposal and submits its exact candidate once", async () => {
  const objective = objectiveFixture();
  const proposal = proposalFixture();
  vi.spyOn(compositionApi, "objective").mockResolvedValue(objective);
  vi.spyOn(compositionApi, "proposal").mockResolvedValue(proposal);
  const submit = vi.spyOn(compositionApi, "submit").mockRejectedValue(new Error("Response pending"));
  const path = `/composition?control=${controlId}&objective=${ownerId}&proposal=${proposalId}`;
  const first = mount(<CompositionPage />, path);
  await waitFor(() => expect(screen.getByRole("button", { name: "Start fresh attempt within grant" })).toBeEnabled());
  first.unmount();
  vi.mocked(compositionApi.context).mockClear();
  mount(<CompositionPage />, path);
  const start = await screen.findByRole("button", { name: "Start fresh attempt within grant" });
  await waitFor(() => expect(start).toBeEnabled());
  expect(compositionApi.context).toHaveBeenCalledWith(ownerId, null);
  fireEvent.click(start);
  await waitFor(() => expect(submit).toHaveBeenCalledOnce());
  expect(submit.mock.calls[0]![0]).toMatchObject({ kind: "attempt", owner: ownerId, control: controlId, body: { proposal: proposal.proposal!.candidate, prior_attempt_id: null } });
  expect(readCompositionPending()?.kind).toBe("attempt");
});
it("keeps a reopened proposal disabled until fresh context resolves", async () => {
  vi.spyOn(compositionApi, "objective").mockResolvedValue(objectiveFixture());
  vi.spyOn(compositionApi, "proposal").mockResolvedValue(proposalFixture());
  let resolve!: (value: ReturnType<typeof contextFixture>) => void;
  vi.mocked(compositionApi.context).mockReturnValue(new Promise(done => { resolve = done; }));
  const submit = vi.spyOn(compositionApi, "submit");
  mount(<CompositionPage />, `/composition?control=${controlId}&objective=${ownerId}&proposal=${proposalId}`);
  const start = await screen.findByRole("button", { name: "Start fresh attempt within grant" });
  expect(start).toBeDisabled();
  fireEvent.click(start);
  expect(submit).not.toHaveBeenCalled();
  await act(async () => resolve(contextFixture()));
  await waitFor(() => expect(start).toBeEnabled());
});
it("keeps an unresolved saved proposal submission from dispatching an attempt", async () => {
  vi.spyOn(compositionApi, "objective").mockResolvedValue(objectiveFixture());
  const proposal = proposalFixture();
  // The loaded candidate is a different exact submission; pending must remain.
  proposal.job.request.submitted_request = { ...(proposal.job.request.submitted_request as Record<string, unknown>), context_digest: `sha256:${"e".repeat(64)}` };
  vi.spyOn(compositionApi, "proposal").mockResolvedValue(proposal);
  storeCompositionPending({ kind: "proposal", owner: ownerId, control: controlId, id: proposalId, body: proposalFixture().job.request.submitted_request as Record<string, unknown> });
  const submit = vi.spyOn(compositionApi, "submit");
  mount(<CompositionPage />, `/composition?control=${controlId}&objective=${ownerId}&proposal=${proposalId}`);
  const start = await screen.findByRole("button", { name: "Start fresh attempt within grant" });
  expect(start).toBeDisabled();
  fireEvent.click(start);
  expect(submit).not.toHaveBeenCalled();
  expect(readCompositionPending()?.kind).toBe("proposal");
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
it("focuses the selected later attempt after an earlier child failed", async () => {
  const { objective, attempt, value } = linkageFixture();
  const failed = structuredClone(attempt);
  failed.job_id = `job-${"e".repeat(32)}`;
  failed.request.composition_attempt.attempt_id = `attempt-${"e".repeat(32)}`;
  failed.request.composition_attempt.run_id = "run-failed";
  failed.state = "failed";
  delete failed.progress.verified_result;
  delete failed.progress.verified_result_digest;
  objective.attempts = [failed, attempt];
  vi.spyOn(compositionApi, "objective").mockResolvedValue(objective);
  vi.spyOn(fileAccessLinkageApi, "read").mockResolvedValue(value);

  mount(<CompositionPage />, `/composition?control=${controlId}&objective=${ownerId}&pack=${FILE_ACCESS_PACK}&attempt=${attempt.request.composition_attempt.attempt_id}`);

  const selectedRow = await screen.findByRole("listitem", { name: "Selected attempt comparison" });
  await waitFor(() => expect(document.activeElement).toBe(selectedRow));
  expect(within(selectedRow).getByRole("heading", { name: "Attempt 2" })).toBeInTheDocument();
  expect(within(selectedRow).queryByRole("heading", { name: "Attempt 1" })).not.toBeInTheDocument();
});
it("clears the old attempt selection when starting a new objective", async () => {
  const { objective, attempt, value } = linkageFixture();
  vi.spyOn(compositionApi, "objective").mockResolvedValue(objective);
  vi.spyOn(fileAccessLinkageApi, "read").mockResolvedValue(value);

  mount(<CompositionPage />, `/composition?control=${controlId}&objective=${ownerId}&pack=${FILE_ACCESS_PACK}&attempt=${attempt.request.composition_attempt.attempt_id}`, true);
  await screen.findByRole("region", { name: "Baseline and fresh retest" });
  fireEvent.click(screen.getByRole("button", { name: "New objective" }));
  expect(await screen.findByRole("textbox", { name: "Objective question" })).toBeInTheDocument();
  const current = new URL(screen.getByTestId("current-location").textContent!, "http://localhost");
  expect(current.searchParams.has("objective")).toBe(false);
  expect(current.searchParams.has("attempt")).toBe(false);
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

it.each([
  ["available", true, "This action can only close the exact original attempt"],
  ["unavailable", false, "The original process authority is unavailable"],
  ["unresolved", false, "The original close could not be verified"],
] as const)("renders macOS close recovery state %s without widening its action", async (state, actionable, message) => {
  const value = macWorkspace("unknown");
  value.attempts[0]!.progress.macos_recovery = { state, scope: "close_only" };
  mount(<CompositionPage />, `/composition?control=${macOSOwner}&objective=${ownerId}&pack=${MACOS_FILE_ACCESS_PACK}`);
  expect(await screen.findByText(new RegExp(message))).toBeVisible();
  const button = screen.queryByRole("button", { name: "Close undispatched attempt" });
  if (actionable) expect(button).toBeEnabled();
  else expect(button).not.toBeInTheDocument();
});

it("hides recovery action after a confirmed close", async () => {
  const value = macWorkspace("settled");
  value.attempts[0]!.progress.macos_recovery = { state: "closed", scope: "close_only" };
  mount(<CompositionPage />, `/composition?control=${macOSOwner}&objective=${ownerId}&pack=${MACOS_FILE_ACCESS_PACK}`);
  await screen.findByRole("heading", { name: "Capability grant" });
  expect(screen.queryByRole("button", { name: "Close undispatched attempt" })).not.toBeInTheDocument();
  expect(screen.queryByText("Attempt closure pending")).not.toBeInTheDocument();
});

it("shows pending and failed recovery honestly without retrying", async () => {
  const value = macWorkspace("unknown");
  value.attempts[0]!.progress.macos_recovery = { state: "available", scope: "close_only" };
  let rejectRecovery!: (error: Error) => void;
  const recover = vi.spyOn(compositionApi, "recover").mockReturnValue(new Promise((_resolve, reject) => { rejectRecovery = reject; }));
  mount(<CompositionPage />, `/composition?control=${macOSOwner}&objective=${ownerId}&pack=${MACOS_FILE_ACCESS_PACK}`);
  fireEvent.click(await screen.findByRole("button", { name: "Close undispatched attempt" }));
  expect(await screen.findByRole("button", { name: "Checking original close…" })).toBeDisabled();
  expect(recover).toHaveBeenCalledOnce();
  await act(async () => rejectRecovery(new Error("Original close response unavailable")));
  expect(await screen.findByText("Original close response unavailable")).toBeVisible();
  expect(screen.getByRole("button", { name: "Close undispatched attempt" })).toBeEnabled();
  expect(recover).toHaveBeenCalledOnce();
});

it("cancels an older objective read before publishing confirmed recovery", async () => {
  const value = macWorkspace("unknown");
  value.attempts[0]!.progress.macos_recovery = { state: "available", scope: "close_only" };
  const closed = structuredClone(value);
  closed.attempts[0]!.progress.settlement = "settled";
  closed.attempts[0]!.progress.macos_recovery = { state: "closed", scope: "close_only" };
  let finishRead!: (result: typeof value) => void;
  const objective = vi.spyOn(compositionApi, "objective")
    .mockResolvedValueOnce(value)
    .mockReturnValueOnce(new Promise(resolve => { finishRead = resolve; }));
  vi.spyOn(compositionApi, "recover").mockResolvedValue(closed);
  const { client } = mount(<CompositionPage />, `/composition?control=${macOSOwner}&objective=${ownerId}&pack=${MACOS_FILE_ACCESS_PACK}`);
  await screen.findByRole("button", { name: "Close undispatched attempt" });
  const staleRead = client.refetchQueries({ queryKey: ["composition-objective", ownerId], exact: true });
  await waitFor(() => expect(objective).toHaveBeenCalledTimes(2));
  fireEvent.click(screen.getByRole("button", { name: "Close undispatched attempt" }));
  await waitFor(() => expect(client.getQueryData(["composition-objective", ownerId])).toEqual(closed));
  await act(async () => finishRead(value));
  await staleRead;
  expect(client.getQueryData(["composition-objective", ownerId])).toEqual(closed);
  expect(screen.queryByRole("button", { name: "Close undispatched attempt" })).not.toBeInTheDocument();
});

it("still exposes a current active planning failure", async () => {
  vi.spyOn(compositionApi, "objective").mockResolvedValue(objectiveFixture());
  vi.mocked(compositionApi.context).mockRejectedValue(new Error("Current evidence cannot be verified"));
  mount(<CompositionPage />, `/composition?control=${controlId}&objective=${ownerId}`);
  await screen.findByText("Current evidence cannot be verified");
  expect(screen.getByRole("button", { name: "Request AI graph" })).toBeDisabled();
  expect(screen.getByRole("button", { name: "Stop" })).toBeEnabled();
});
