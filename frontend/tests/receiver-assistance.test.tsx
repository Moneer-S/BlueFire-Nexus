import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { ExperimentAssistant } from "../src/components/ExperimentAssistant";
import { api } from "../src/lib/api";
import { readAssistanceReceipt, storeAssistanceReceipt, type ReceiverAssistanceRequest } from "../src/lib/assistance";
import { checkedReceiverAssistance, checkedReceiverAssistanceContext, type ReceiverAssistanceSelection } from "../src/lib/receiver-assistance";
import { AssistanceProvider, useAssistancePanel, usePublishReceiverSelection } from "../src/state/AssistanceContext";
import { ProductProvider } from "../src/state/ProductContext";
import { receiverAssistantFixture, receiverAssistantProvider as provider } from "./receiver-assistance-fixture";

function Selection({ selected, parent, owner }: { selected?: ReceiverAssistanceSelection; parent?: string; owner?: string }) {
  usePublishReceiverSelection(selected, "Public record handoff");
  const panel = useAssistancePanel();
  return parent ? <button onClick={() => panel?.openJob(parent, owner)}>Open owning Assistant</button> : null;
}
function mount(selected?: ReceiverAssistanceSelection, parent?: string, owner?: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  const tree = (value = selected) => <QueryClientProvider client={client}><MemoryRouter initialEntries={["/compare?receiver=1"]}><ProductProvider><AssistanceProvider><Selection selected={value} parent={parent} owner={owner} /><ExperimentAssistant providers={[provider]} /></AssistanceProvider></ProductProvider></MemoryRouter></QueryClientProvider>;
  const rendered = render(tree());
  return { ...rendered, client, change: (next: ReceiverAssistanceSelection) => rendered.rerender(tree(next)) };
}
async function open() { await userEvent.setup().click(screen.getByRole("button", { name: /^Assistant/ })); }
function deferred<T>() { let resolve!: (value: T) => void; let reject!: (error: Error) => void; const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }

it.each([false, true])("roundtrips contextual receiver selection and retained results, existing=%s", (existing) => {
  const fixture = receiverAssistantFixture(existing, true);
  expect(checkedReceiverAssistanceContext(fixture.context, fixture.request.selection)).toBe(fixture.context);
  const value = fixture.envelope();
  expect(checkedReceiverAssistance(value)).toBe(value);
  expect(storeAssistanceReceipt(fixture.request)).toBe(true);
  expect(readAssistanceReceipt()).toEqual(fixture.request);
});

it.each(["owner", "interpretation", "reference", "count", "phase digest", "approval link", "premature completion"])("refuses mismatched receiver %s without discarding the exact request", (kind) => {
  const fixture = receiverAssistantFixture();
  storeAssistanceReceipt(fixture.request);
  const value = fixture.envelope(), progress = value.turn.receiver_test!, analysis = progress.inspections[0]!;
  if (kind === "owner") progress.owner_job_id = `job-${"f".repeat(32)}`;
  if (kind === "interpretation") analysis.interpretation!.provider.provider_id = "another-provider";
  if (kind === "reference") analysis.interpretation!.findings[0]!.evidence_refs = ["receiver:protected:unrelated"];
  if (kind === "count") analysis.phases[0]!.record_count = 999;
  if (kind === "phase digest") analysis.phases[0]!.result_digest = `sha256:${"f".repeat(64)}`;
  if (kind === "approval link") value.turn.next_action = { kind: "approve_execute", native_path: `/runs?job=job-${"f".repeat(32)}` };
  if (kind === "premature completion") value.turn.status = "completed";
  expect(() => checkedReceiverAssistance(value)).toThrow(/does not match/);
  expect(readAssistanceReceipt()).toEqual(fixture.request);
});

it("keeps Off silent and publishes one exact graph, scope and runtime-Off request", async () => {
  const fixture = receiverAssistantFixture();
  const context = vi.spyOn(api, "assistanceReceiverContext").mockResolvedValue(fixture.context);
  const submit = vi.spyOn(api, "submitAssistance").mockImplementation(async (body) => fixture.envelope(body as ReceiverAssistanceRequest));
  vi.spyOn(api, "assistanceTurn").mockImplementation(async () => fixture.envelope(readAssistanceReceipt() as ReceiverAssistanceRequest));
  const native = vi.spyOn(api, "createReceiverTest");
  const prepare = vi.spyOn(api, "prepareReceiver");
  mount(fixture.request.selection);
  expect(context).not.toHaveBeenCalled();
  await open();
  expect(screen.getByRole("button", { name: "Start work" })).toBeDisabled();
  expect(submit).not.toHaveBeenCalled();
  const user = userEvent.setup();
  await user.selectOptions(screen.getByLabelText("Assistant mode"), "auto");
  await user.selectOptions(screen.getByLabelText("Assistant provider"), provider.provider_id);
  await user.type(screen.getByLabelText("What would you like to do?"), fixture.request.message);
  await user.dblClick(screen.getByRole("button", { name: "Start work" }));
  await screen.findByRole("heading", { name: "Your review is needed" });
  expect(submit).toHaveBeenCalledTimes(1);
  expect(submit.mock.calls[0]![0]).toMatchObject({ selection: fixture.request.selection, autonomy: "auto" });
  expect(native).not.toHaveBeenCalled(); expect(prepare).not.toHaveBeenCalled();
  expect(screen.queryByLabelText("Completed")).not.toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Open receiver preparation and review" })).toHaveAttribute("href", `/compare?receiver_job=${fixture.native.job.job_id}`);
});

it("reloads an existing-test analysis using GET only and separates model advice from native evidence", async () => {
  const fixture = receiverAssistantFixture(true);
  storeAssistanceReceipt(fixture.request);
  vi.spyOn(api, "assistanceTurn").mockResolvedValue(fixture.envelope());
  const post = vi.spyOn(api, "submitAssistance");
  const context = vi.spyOn(api, "assistanceReceiverContext");
  mount(receiverAssistantFixture().request.selection); await open();
  await screen.findByRole("heading", { name: "Work completed" });
  expect(screen.getByText("Existing receiver test · analysis only")).toBeInTheDocument();
  expect(screen.getByText(/does not own or stop the receiver test/)).toBeInTheDocument();
  expect(screen.getByText(/Model interpretation · configured-model/)).toBeInTheDocument();
  expect(screen.getByText(/Evidence: receiver:baseline:/)).toBeInTheDocument();
  expect(screen.getByText("Receiver accepted the records", { selector: "span" })).toBeInTheDocument();
  expect(post).not.toHaveBeenCalled(); expect(context).not.toHaveBeenCalled();
});

it("keeps pending publication from racing a not-found GET and recovers a lost response without resubmission", async () => {
  const fixture = receiverAssistantFixture();
  vi.spyOn(api, "assistanceReceiverContext").mockResolvedValue(fixture.context);
  const pending = deferred<ReturnType<typeof fixture.envelope>>();
  const post = vi.spyOn(api, "submitAssistance").mockReturnValue(pending.promise);
  const get = vi.spyOn(api, "assistanceTurn").mockImplementation(async () => fixture.envelope(readAssistanceReceipt() as ReceiverAssistanceRequest));
  mount(fixture.request.selection); await open();
  const user = userEvent.setup();
  await user.selectOptions(screen.getByLabelText("Assistant mode"), "assist");
  await user.selectOptions(screen.getByLabelText("Assistant provider"), provider.provider_id);
  await user.type(screen.getByLabelText("What would you like to do?"), fixture.request.message);
  await user.click(screen.getByRole("button", { name: "Start work" }));
  expect(readAssistanceReceipt()).toBeDefined(); expect(get).not.toHaveBeenCalled();
  await act(async () => pending.reject(new Error("Lost publication response")));
  await screen.findByRole("heading", { name: "Your review is needed" });
  expect(post).toHaveBeenCalledTimes(1); expect(get).toHaveBeenCalled();
});

it("does not apply delayed context after a different saved selection arrives", async () => {
  const fixture = receiverAssistantFixture(), pending = deferred<typeof fixture.context>();
  vi.spyOn(api, "assistanceReceiverContext").mockReturnValue(pending.promise);
  const post = vi.spyOn(api, "submitAssistance");
  const view = mount(fixture.request.selection); await open();
  view.change(receiverAssistantFixture(true).request.selection);
  await act(async () => pending.resolve(fixture.context));
  await screen.findByText("Context is unavailable");
  expect(screen.getByRole("button", { name: "Start work" })).toBeDisabled();
  expect(post).not.toHaveBeenCalled();
});

it("offers explicit failed-analysis recovery with one retained continuation identity and no replay", async () => {
  const fixture = receiverAssistantFixture(true), failed = fixture.envelope();
  const analysis = failed.turn.receiver_test!.inspections[0]!;
  analysis.interpretation = null; analysis.job.progress.interpretation = null; analysis.job.state = "failed";
  failed.turn.results = failed.turn.results.filter((row) => row.kind !== "receiver_inspection");
  failed.turn.status = "ready_to_continue"; failed.turn.can_start_new_turn = false;
  failed.turn.next_action = { kind: "continue", native_path: failed.turn.receiver_test!.native_path };
  storeAssistanceReceipt(fixture.request);
  vi.spyOn(api, "assistanceTurn").mockResolvedValue(failed);
  const pending = deferred<typeof failed>();
  const recover = vi.spyOn(api, "continueAssistance").mockReturnValue(pending.promise);
  const native = vi.spyOn(api, "prepareReceiver");
  mount(); await open();
  await screen.findByRole("button", { name: "Recover evidence analysis" });
  expect(recover).not.toHaveBeenCalled();
  const user = userEvent.setup();
  await user.dblClick(screen.getByRole("button", { name: "Recover evidence analysis" }));
  expect(recover).toHaveBeenCalledTimes(1); expect(native).not.toHaveBeenCalled();
  expect(JSON.parse(sessionStorage.getItem("bluefire.assistance.recovery.v1")!)).toMatchObject({ job_id: failed.job.job_id, context_digest: failed.turn.context_digest });
  await act(async () => pending.resolve(fixture.envelope()));
  await screen.findByRole("heading", { name: "Work completed" });
});

it("suppresses late cached approval and recovery actions after an uncertain Stop", async () => {
  const fixture = receiverAssistantFixture(), value = fixture.envelope();
  storeAssistanceReceipt(fixture.request);
  vi.spyOn(api, "assistanceTurn").mockResolvedValue(value);
  const stop = deferred<Awaited<ReturnType<typeof api.controlJob>>>();
  const control = vi.spyOn(api, "controlJob").mockReturnValue(stop.promise);
  const view = mount(); await open();
  await screen.findByRole("link", { name: "Open receiver preparation and review" });
  await userEvent.setup().click(screen.getByRole("button", { name: "Stop this operation" }));
  expect(control).toHaveBeenCalledWith(value.job.job_id, "cancel");
  await act(async () => { view.client.setQueryData(["assistance-turn", value.job.job_id], { ...value }); });
  expect(screen.queryByRole("link", { name: "Open receiver preparation and review" })).not.toBeInTheDocument();
  await act(async () => stop.reject(new Error("Stop response unavailable")));
  expect(screen.queryByRole("button", { name: "Recover evidence analysis" })).not.toBeInTheDocument();
});

it("refuses a saved owner backlink to an unrelated Assistant before adopting its receipt", async () => {
  const fixture = receiverAssistantFixture();
  vi.spyOn(api, "assistanceTurn").mockResolvedValue(fixture.envelope());
  const post = vi.spyOn(api, "submitAssistance");
  mount(undefined, fixture.envelope().job.job_id, `job-${"f".repeat(32)}`);
  await userEvent.setup().click(screen.getByRole("button", { name: "Open owning Assistant" }));
  await screen.findByText(/does not own the selected receiver test/);
  expect(readAssistanceReceipt()).toBeUndefined(); expect(post).not.toHaveBeenCalled();
});
