import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { ProductProvider } from "../src/state/ProductContext";
import { ReceiverTestProgress } from "../src/components/ReceiverTestProgress";
import { ReceiverDefensePage } from "../src/pages/ReceiverDefense";
import { api } from "../src/lib/api";
import { readReceiverPending, storeReceiverPending, type ReceiverPending } from "../src/lib/receiver-defense";
import type { ReceiverDefenseEnvelope } from "../src/lib/receiver-defense-types";
import { nativeReceiverFixture } from "./receiver-inline-run-fixture";
import { receiverFixture, receiverFixtureId } from "./receiver-defense-fixture";

function mountProgress(value = receiverFixture()) {
  const onPrepare = vi.fn(), onReview = vi.fn();
  const ui = (envelope: typeof value) => <MemoryRouter><button>Another workspace</button><ReceiverTestProgress envelope={envelope} disabled={false} onPrepare={onPrepare} onReview={onReview} /></MemoryRouter>;
  return { ...render(ui(value)), onPrepare, onReview, user: userEvent.setup(), ui };
}

it("requires a deliberate native review and never creates Execute approval itself", async () => {
  const approve = vi.spyOn(api, "approveJob");
  const { user, onReview } = mountProgress();
  const accept = screen.getByRole("button", { name: "Accept and review run approval" });
  expect(accept).toBeDisabled();
  await user.type(screen.getByLabelText("Reviewed by"), "lab operator");
  expect(accept).toBeDisabled();
  await user.click(screen.getByRole("checkbox")); await user.click(accept);
  expect(onReview).toHaveBeenCalledOnce();
  expect(onReview.mock.calls[0]![0]).toMatchObject({ phase: "baseline", decision: "accept", reviewed_by: "lab operator" });
  expect(approve).not.toHaveBeenCalled();
});

it("clears review acknowledgement and identity when a replacement preparation arrives", async () => {
  const original = receiverFixture();
  const { user, rerender, ui } = mountProgress(original);
  await user.type(screen.getByLabelText("Reviewed by"), "old reviewer"); await user.click(screen.getByRole("checkbox"));
  const fresh = structuredClone(original); fresh.phases[0]!.preparation!.preparation_digest = `sha256:${"9".repeat(64)}`;
  rerender(ui(fresh));
  expect(screen.getByLabelText("Reviewed by")).toHaveValue("");
  expect(screen.getByRole("checkbox")).not.toBeChecked();
  expect(screen.getByRole("button", { name: "Accept and review run approval" })).toBeDisabled();
});

it("refuses an expired review instead of silently preparing another receiver", async () => {
  const value = receiverFixture(); value.phases[0]!.preparation!.session.expires_at_ms = Date.now() - 1;
  const { onPrepare, onReview } = mountProgress(value);
  expect(screen.getByText(/This receiver review has expired/)).toBeVisible();
  expect(screen.getByRole("button", { name: "Accept and review run approval" })).toBeDisabled();
  expect(onPrepare).not.toHaveBeenCalled(); expect(onReview).not.toHaveBeenCalled();
});

it("preserves focus in another workspace when polling advances the phase", async () => {
  const { user, rerender, ui } = mountProgress();
  const other = screen.getByRole("button", { name: "Another workspace" }); await user.click(other);
  rerender(ui(receiverFixture("protected")));
  expect(other).toHaveFocus();
});

it("shows unavailable observation as unknown, with uncertain cleanup and no prevention claim", () => {
  mountProgress(receiverFixture("baseline", "insufficient"));
  expect(screen.getAllByText("Not enough evidence").length).toBeGreaterThan(0);
  expect(screen.getAllByText("Receiver shutdown uncertain").length).toBeGreaterThan(0);
  expect(screen.queryByText("Prevented by the receiver")).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /Prepare .* receiver/ })).not.toBeInTheDocument();
});

function pendingCreate(): ReceiverPending {
  return { kind: "create", id: receiverFixtureId, body: receiverFixture("baseline", "idle").job.request!.submitted_request as Extract<ReceiverPending, { kind: "create" }>["body"] };
}
function mountPage(ownerId = receiverFixtureId) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return { client, user: userEvent.setup(), ...render(<QueryClientProvider client={client}><ProductProvider><MemoryRouter initialEntries={[`/compare?receiver_job=${ownerId}`]}><ReceiverDefensePage /></MemoryRouter></ProductProvider></QueryClientProvider>) };
}

it.each([false, true])("keeps a refused submission readable and closes only its retained request, unavailable context=%s", async (unavailable) => {
  storeReceiverPending(pendingCreate());
  const refused: ReceiverDefenseEnvelope = receiverFixture("baseline", "idle");
  refused.admission = { accepted: false, problem: { code: "receiver_admission_refused", message: "The reviewed experiment changed before this test was saved." } };
  refused.job.progress.admission = structuredClone(refused.admission);
  refused.job.state = "failed";
  refused.status = "blocked";
  refused.can_start_new_test = true;
  refused.next_action = { kind: "wait", phase: "baseline", native_path: null };
  refused.phases.forEach((phase) => { phase.prepare_allowed = false; });
  if (unavailable) refused.context = null;
  else refused.context!.context_digest = `sha256:${"d".repeat(64)}`;
  refused.job.request!.context = structuredClone(refused.context);
  vi.spyOn(api, "receiverTest").mockResolvedValue(refused);
  const create = vi.spyOn(api, "createReceiverTest"), prepare = vi.spyOn(api, "prepareReceiver"), review = vi.spyOn(api, "reviewReceiver");
  mountPage();
  expect(await screen.findByText("This test needs a new review")).toBeVisible();
  expect(screen.getByText(refused.admission.problem!.message)).toBeVisible();
  await waitFor(() => expect(readReceiverPending()).toBeUndefined());
  expect(screen.getByRole("button", { name: "Set up another control test" })).toBeEnabled();
  expect(screen.queryByRole("button", { name: /Prepare .* receiver/ })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Accept and review run approval" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Retry this exact request" })).not.toBeInTheDocument();
  expect(create).not.toHaveBeenCalled(); expect(prepare).not.toHaveBeenCalled(); expect(review).not.toHaveBeenCalled();
});

it("keeps a pending request with its own test when another test URL is opened", async () => {
  storeReceiverPending(pendingCreate());
  const otherId = `job-${"e".repeat(32)}`;
  vi.spyOn(api, "receiverTest").mockRejectedValue(new Error("Other test unavailable"));
  const create = vi.spyOn(api, "createReceiverTest"), prepare = vi.spyOn(api, "prepareReceiver");
  mountPage(otherId);
  expect(await screen.findByRole("link", { name: "Return to the retained control test" })).toHaveAttribute("href", `/compare?receiver_job=${receiverFixtureId}`);
  expect(screen.queryByRole("button", { name: "Retry this exact request" })).not.toBeInTheDocument();
  expect(create).not.toHaveBeenCalled(); expect(prepare).not.toHaveBeenCalled();
  expect(readReceiverPending()?.id).toBe(receiverFixtureId);
});

it("compares protected outcomes separately from restoration after all three phases", () => {
  mountProgress(receiverFixture("restored", "completed"));
  expect(screen.getByRole("link", { name: "Compare baseline and protected run" })).toHaveAttribute("href", "/compare?source=run-baseline&replay=run-protected");
  expect(screen.getByRole("link", { name: "Check restoration against baseline" })).toHaveAttribute("href", "/compare?source=run-baseline&replay=run-restored");
});

it("a late review POST cannot reopen approval controls after Stop was confirmed", async () => {
  const prepared = receiverFixture();
  const accepted = receiverFixture("baseline", "approval");
  const decision = accepted.phases[0]!.decision!;
  storeReceiverPending({ kind: "review", id: receiverFixtureId, body: decision });
  const stopped = structuredClone(prepared);
  stopped.status = "stopped"; stopped.next_action = { kind: "stopped", phase: null, native_path: null }; stopped.can_start_new_test = true;
  stopped.job.progress.stopped = true;
  Object.assign(stopped.phases[0]!, { status: "stopped", review_ready: false, cleanup: { receiver: "verified_closed", run: "not_started" } });
  stopped.phases[0]!.receiver_job!.progress.receiver_closed = true;
  let didStop = false, resolveReview!: (value: typeof accepted) => void;
  vi.spyOn(api, "receiverTest").mockImplementation(async () => didStop ? stopped : prepared);
  vi.spyOn(api, "reviewReceiver").mockReturnValue(new Promise((resolve) => { resolveReview = resolve; }));
  vi.spyOn(api, "controlJob").mockImplementation(async () => { didStop = true; return stopped.job; });
  const { user } = mountPage();
  await screen.findByRole("button", { name: "Stop control test" });
  await user.click(screen.getByRole("button", { name: "Retry this exact request" }));
  await user.click(screen.getByRole("button", { name: "Stop control test" }));
  await screen.findByText("Control test stopped");
  await act(async () => resolveReview(accepted));
  await screen.findByRole("button", { name: "Close retained request after confirmed stop" });
  expect(screen.queryByRole("link", { name: "Review and approve this run" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Retry this exact request" })).not.toBeInTheDocument();
  expect(readReceiverPending()?.body.submission_id).toBe(decision.submission_id);
  await user.click(screen.getByRole("button", { name: "Close retained request after confirmed stop" }));
  expect(readReceiverPending()).toBeUndefined();
});

it("suppresses the approval action while a Stop response is still pending", async () => {
  const envelope = nativeReceiverFixture(); const child = envelope.phases[0]!.execution_job!;
  vi.spyOn(api, "receiverTest").mockResolvedValue(envelope);
  vi.spyOn(api, "activeJobs").mockResolvedValue({ schema_version: "bluefire.active-job-list.v1", jobs: [child] });
  vi.spyOn(api, "job").mockResolvedValue(child);
  let resolveStop!: (value: ReturnType<typeof receiverFixture>["job"]) => void;
  vi.spyOn(api, "controlJob").mockReturnValue(new Promise((resolve) => { resolveStop = resolve; }));
  const { user } = mountPage();
  await screen.findByRole("checkbox", { name: /I approve this exact immutable job envelope once/ });
  await user.click(screen.getByRole("button", { name: "Stop control test" }));
  expect(await screen.findByText("Stop requested")).toBeVisible();
  expect(screen.queryByRole("link", { name: "Review and approve this run" })).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Approve and release job" })).toBeDisabled();
  expect(screen.getByRole("button", { name: "Cancel" })).toBeEnabled();
  expect(screen.getByRole("link", { name: "Open this job in Runs" })).toBeVisible();
  await act(async () => resolveStop(receiverFixture().job));
});

it("recovers a retained submission through GET after reload without repeating any operation", async () => {
  storeReceiverPending(pendingCreate());
  vi.spyOn(api, "receiverTest").mockResolvedValue(receiverFixture("baseline", "idle"));
  const create = vi.spyOn(api, "createReceiverTest"), prepare = vi.spyOn(api, "prepareReceiver");
  mountPage();
  await screen.findByRole("button", { name: "Prepare baseline receiver" });
  await waitFor(() => expect(readReceiverPending()).toBeUndefined());
  expect(create).not.toHaveBeenCalled(); expect(prepare).not.toHaveBeenCalled();
});

it("does not send an exact retry until browser persistence succeeds", async () => {
  storeReceiverPending(pendingCreate());
  vi.spyOn(api, "receiverTest").mockRejectedValue(new Error("Not yet saved"));
  const create = vi.spyOn(api, "createReceiverTest").mockResolvedValue(receiverFixture("baseline", "idle"));
  const originalSet = Storage.prototype.setItem;
  const storage = vi.spyOn(Storage.prototype, "setItem").mockImplementation(function (this: Storage, key, value) { if (key.includes("receiver-defense.pending")) throw new Error("Storage unavailable"); originalSet.call(this, key, value); });
  const { user } = mountPage();
  await user.click(await screen.findByRole("button", { name: "Retry this exact request" }));
  await screen.findByText("Storage unavailable");
  expect(create).not.toHaveBeenCalled();
  storage.mockRestore();
  await user.click(screen.getByRole("button", { name: "Retry this exact request" }));
  await screen.findByRole("button", { name: "Prepare baseline receiver" });
  expect(create).toHaveBeenCalledOnce();
  expect(create).toHaveBeenCalledWith(pendingCreate().body);
});

it("a delayed prepublication GET failure cannot replace a confirmed POST", async () => {
  storeReceiverPending(pendingCreate());
  let rejectOld!: (error: Error) => void;
  const old = new Promise<ReturnType<typeof receiverFixture>>((_, reject) => { rejectOld = reject; });
  vi.spyOn(api, "receiverTest").mockReturnValueOnce(old).mockResolvedValue(receiverFixture("baseline", "idle"));
  const create = vi.spyOn(api, "createReceiverTest").mockResolvedValue(receiverFixture("baseline", "idle"));
  const { user } = mountPage();
  await user.click(screen.getByRole("button", { name: "Retry this exact request" }));
  await screen.findByRole("button", { name: "Prepare baseline receiver" });
  await act(async () => rejectOld(new Error("Old missing job response")));
  expect(screen.queryByText("Old missing job response")).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Prepare baseline receiver" })).toBeVisible();
  expect(create).toHaveBeenCalledOnce();
});
