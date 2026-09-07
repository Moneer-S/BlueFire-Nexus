import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, useLocation } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { ExperimentAssistant } from "../src/components/ExperimentAssistant";
import { api } from "../src/lib/api";
import { assistanceJobId, assistancePath, readAssistanceReceipt, readAssistanceRecovery, storeAssistanceReceipt, type AssistanceContext, type AssistanceEnvelope, type AssistanceRequest } from "../src/lib/assistance";
import { AssistanceProvider, usePublishAssistanceSelection, type AssistanceSelection } from "../src/state/AssistanceContext";
import { ProductProvider } from "../src/state/ProductContext";

const digest = `sha256:${"a".repeat(64)}`;
const selection: AssistanceSelection = { runId: "run-observed", candidateId: "saved-rule", resourceDigest: digest, title: "Collection retention", manualEdits: false };
const provider = { provider_id: "chosen-provider", kind: "openai_chat_completions", model: "chosen-model" };
const source = { run_id: selection.runId, manifest_digest: digest, evidence_digest: digest, observed_count: 3, evidence_count: 4, excluded_provenance_counts: {}, mode: "execute", finalized_at: "2030-01-01", observed_records_digest: digest };
const context: AssistanceContext = { schema_version: "bluefire.assistance-context.v1", context_digest: digest,
  selected: { run_id: selection.runId, candidate_id: selection.candidateId, candidate_resource_digest: digest, title: selection.title, definition_digest: digest, target_language: "sqlite", source_binding: source },
  capabilities: [{ id: "detection.revise_and_evaluate", title: "Revise and evaluate the saved rule", available: true, supported_autonomy: ["assist"], reason: "Independent observations are available", native_path: "/detection-lab" }], limitations: ["Development evidence; evaluate independent benign cases separately."] };
function request(): AssistanceRequest { return { submission_id: "01234567-89ab-4def-8123-456789abcdef", context_digest: digest, run_id: selection.runId, candidate_id: selection.candidateId, candidate_resource_digest: digest, message: "Improve this rule, evaluate it, then try another method.", case_role: "attack", autonomy: "assist", provider_id: provider.provider_id }; }
function envelope(body = request(), status: AssistanceEnvelope["turn"]["status"] = "awaiting_review"): AssistanceEnvelope {
  return { job: { schema_version: "bluefire.job.v1", kind: "assistance.turn", job_id: assistanceJobId(body.submission_id), state: "completed", request: { submitted_request: body }, progress: {} },
    turn: { schema_version: "bluefire.assistance-turn.v1", status, can_start_new_turn: ["completed", "off", "cancelled"].includes(status), message: "Review the rule revision before it is saved and evaluated.", context_digest: body.context_digest,
      selected: { run_id: body.run_id, candidate_id: body.candidate_id, candidate_resource_digest: body.candidate_resource_digest },
      plan: [{ step_id: "revise", capability_id: "detection.revise_and_evaluate", title: "Improve and evaluate the rule", detector_ref: "selected", reason: "Check smaller observed collections." }, { step_id: "compare", capability_id: "method.compare_same_detector", title: "Try another collection method", detector_ref: "revised", reason: "Keep the revised detector fixed for comparison." }],
      active_child: { job_id: "job-rule", kind: "detection.ai.propose", state: "completed", step_id: "revise", native_path: "/detection-lab?candidate=saved-rule&run=run-observed&ai_job=job-rule" },
      next_action: { kind: "review_detection", label: "Review rule revision", native_path: "/detection-lab?candidate=saved-rule&run=run-observed&ai_job=job-rule" }, results: [], continuation: null, limitations: ["Execute requires fresh approval."] } };
}
function Selection({ value = selection }: { value?: AssistanceSelection }) {
  usePublishAssistanceSelection(value);
  const location = useLocation();
  return <output data-testid="location">{location.pathname}{location.search}</output>;
}
function mount(value = selection, client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })) {
  const tree = (next: AssistanceSelection) => <QueryClientProvider client={client}><MemoryRouter initialEntries={["/detection-lab"]}><ProductProvider><AssistanceProvider><Selection value={next} /><ExperimentAssistant providers={[provider]} /></AssistanceProvider></ProductProvider></MemoryRouter></QueryClientProvider>;
  const view = render(tree(value));
  return { ...view, client, changeSelection: (next: AssistanceSelection) => view.rerender(tree(next)) };
}
async function open() { await userEvent.setup().click(screen.getByRole("button", { name: /^Assistant/ })); }
async function compose() {
  const user = userEvent.setup();
  await open();
  await user.selectOptions(screen.getByLabelText("AI mode"), "assist");
  await user.selectOptions(screen.getByLabelText("Provider"), provider.provider_id);
  await user.type(screen.getByLabelText("What would you like to do?"), request().message);
  return user;
}

it("keeps Off silent, retrieves context only on opening, and submits one exact bound operation", async () => {
  const getContext = vi.spyOn(api, "assistanceContext").mockResolvedValue(context);
  const submit = vi.spyOn(api, "submitAssistance").mockImplementation(async (body) => envelope(body));
  vi.spyOn(api, "assistanceTurn").mockImplementation(async () => envelope(readAssistanceReceipt()!));
  mount();
  expect(getContext).not.toHaveBeenCalled(); expect(submit).not.toHaveBeenCalled();
  await open();
  await screen.findByText(selection.title);
  expect(screen.getByRole("button", { name: "Start work" })).toBeDisabled();
  expect(submit).not.toHaveBeenCalled();
  const user = userEvent.setup();
  await user.selectOptions(screen.getByLabelText("AI mode"), "assist");
  await user.selectOptions(screen.getByLabelText("Provider"), provider.provider_id);
  await user.type(screen.getByLabelText("What would you like to do?"), request().message);
  await user.dblClick(screen.getByRole("button", { name: "Start work" }));
  await screen.findByRole("heading", { name: "Your review is needed" });
  expect(submit).toHaveBeenCalledTimes(1);
  expect(submit.mock.calls[0]![0]).toEqual({ ...request(), submission_id: expect.any(String) });
  expect(readAssistanceReceipt()).toEqual(submit.mock.calls[0]![0]);
});

it.each(["manual edits", "stale resource"])("prevents a new request with %s", async (change) => {
  vi.spyOn(api, "assistanceContext").mockResolvedValue(change === "stale resource" ? { ...context, selected: { ...context.selected, candidate_resource_digest: `sha256:${"b".repeat(64)}` } } : context);
  const submit = vi.spyOn(api, "submitAssistance");
  mount({ ...selection, manualEdits: change === "manual edits" });
  await compose();
  expect(screen.getByRole("button", { name: "Start work" })).toBeDisabled();
  expect(submit).not.toHaveBeenCalled();
});

it("restores native review after reload without submitting again and returns focus on close", async () => {
  storeAssistanceReceipt(request());
  vi.spyOn(api, "assistanceTurn").mockResolvedValue(envelope());
  const submit = vi.spyOn(api, "submitAssistance");
  mount(); await open();
  await userEvent.setup().click(await screen.findByRole("link", { name: "Review rule revision" }));
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  expect(screen.getByTestId("location")).toHaveTextContent("ai_job=job-rule");
  await waitFor(() => expect(screen.getByRole("button", { name: /^Assistant/ })).toHaveFocus());
  expect(submit).not.toHaveBeenCalled();
  expect(readAssistanceReceipt()).toEqual(request());
});

it("rejects a mismatched recovery response and preserves the exact uncertain request", async () => {
  storeAssistanceReceipt(request());
  vi.spyOn(api, "assistanceTurn").mockResolvedValue(envelope({ ...request(), candidate_id: "other-rule" }));
  mount(); await open();
  await screen.findByText(/saved work does not match/i);
  expect(screen.queryByRole("link", { name: "Review rule revision" })).not.toBeInTheDocument();
  expect(readAssistanceReceipt()).toEqual(request());
});

it("retrying an uncertain submission sends its original request, even after navigation changes selection", async () => {
  storeAssistanceReceipt(request());
  vi.spyOn(api, "assistanceTurn").mockRejectedValue(new Error("Connection interrupted"));
  const submit = vi.spyOn(api, "submitAssistance").mockImplementation(async (body) => envelope(body));
  mount({ ...selection, candidateId: "other-rule" }); await open();
  await screen.findByText("Connection interrupted");
  await userEvent.setup().click(screen.getByRole("button", { name: "Retry original request" }));
  await screen.findByRole("heading", { name: "Your review is needed" });
  expect(submit).toHaveBeenCalledWith(request());
});

it("stopping requests cancellation without claiming cleanup has finished", async () => {
  storeAssistanceReceipt(request());
  const get = vi.spyOn(api, "assistanceTurn").mockResolvedValue(envelope());
  const stop = vi.spyOn(api, "controlJob").mockResolvedValue({ ...envelope().job, state: "cancelling" });
  mount(); await open();
  await screen.findByRole("heading", { name: "Your review is needed" });
  get.mockResolvedValue(envelope(request(), "cancelling"));
  await userEvent.setup().click(screen.getByRole("button", { name: "Stop this operation" }));
  await screen.findByRole("heading", { name: "Stopping · waiting for cleanup" });
  expect(screen.queryByRole("button", { name: "Start another request" })).not.toBeInTheDocument();
  expect(stop).toHaveBeenCalledWith(assistanceJobId(request().submission_id), "cancel");
});

it("keeps polling the durable turn after its planner job completed and displays the real saved result", async () => {
  storeAssistanceReceipt(request());
  vi.spyOn(api, "assistanceTurn").mockResolvedValue(envelope());
  const view = mount(); await open();
  await screen.findByRole("heading", { name: "Your review is needed" });
  const completed = envelope(request(), "completed");
  completed.turn.next_action = null; completed.turn.active_child = null;
  completed.turn.results = [{ kind: "method_comparison", step_id: "compare", candidate_id: "revised-rule", evaluation_ids: ["eval-source", "eval-replay"], run_ids: ["run-observed", "run-replay"], comparison_id: "comparison-one", native_path: "/compare?source=run-observed&replay=run-replay" }];
  vi.mocked(api.assistanceTurn).mockResolvedValue(completed);
  await act(async () => { await view.client.refetchQueries({ queryKey: ["assistance-turn"] }); });
  await screen.findByRole("heading", { name: "Work completed" });
  expect(screen.getByRole("link", { name: "Inspect saved result" })).toHaveAttribute("href", "/compare?source=run-observed&replay=run-replay");
  expect(screen.getByText("2 evaluations · 2 runs")).toBeInTheDocument();
});

it("retains a recovery request across reload and retries the same recovery UUID", async () => {
  storeAssistanceReceipt(request());
  const value = envelope(request(), "ready_to_continue");
  value.turn.next_action = { kind: "continue", label: "Recover saved work", native_path: null };
  vi.spyOn(api, "assistanceTurn").mockResolvedValue(value);
  const recover = vi.spyOn(api, "continueAssistance").mockRejectedValue(new Error("Connection interrupted"));
  const first = mount(); await open();
  await screen.findByRole("button", { name: "Recover saved work" });
  // Recovery uses this operation's retained authority, regardless of a new draft's mode.
  await userEvent.setup().click(await screen.findByRole("button", { name: "Recover saved work" }));
  await screen.findByText("Connection interrupted");
  const saved = readAssistanceRecovery()!;
  expect(saved).toBeDefined(); first.unmount();
  mount(); await open();
  await userEvent.setup().click(await screen.findByRole("button", { name: "Recover saved work" }));
  expect(recover).toHaveBeenLastCalledWith(saved.job_id, { submission_id: saved.submission_id, context_digest: saved.context_digest });
  expect(recover.mock.calls[0]).toEqual(recover.mock.calls[1]);
});

it("does not submit if its durable request cannot be saved", async () => {
  vi.spyOn(api, "assistanceContext").mockResolvedValue(context);
  const submit = vi.spyOn(api, "submitAssistance");
  mount(); const user = await compose();
  vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => { throw new Error("Storage unavailable"); });
  await user.click(screen.getByRole("button", { name: "Start work" }));
  await screen.findByText(/Enable browser session storage/);
  expect(submit).not.toHaveBeenCalled();
});

it("admits only internal native operation paths", () => {
  for (const path of ["https://evil.invalid", "//evil.invalid", "/\\evil.invalid", "/settings", "javascript:alert(1)", "/runs\n/unsafe", "/runs-other"]) expect(assistancePath(path)).toBeUndefined();
  expect(assistancePath("/runs/job-123?review=1")).toBe("/runs/job-123?review=1");
});

it("explains unsupported Auto before any request is submitted", async () => {
  vi.spyOn(api, "assistanceContext").mockResolvedValue(context);
  const submit = vi.spyOn(api, "submitAssistance");
  mount(); const user = await compose();
  await user.selectOptions(screen.getByLabelText("AI mode"), "auto");
  expect(screen.getByRole("button", { name: "Start work" })).toBeDisabled();
  expect(screen.getByText(/Auto is not supported for this workflow/)).toBeInTheDocument();
  expect(submit).not.toHaveBeenCalled();
});

it("refreshes blocked native work on reopen and does not offer replacement while its child can recover", async () => {
  storeAssistanceReceipt(request());
  const blocked = envelope(request(), "blocked");
  const get = vi.spyOn(api, "assistanceTurn").mockResolvedValue(blocked);
  mount(); await open();
  await screen.findByRole("heading", { name: "Work needs attention" });
  expect(screen.queryByRole("button", { name: "Start another request" })).not.toBeInTheDocument();
  await userEvent.setup().click(screen.getByRole("button", { name: "Close assistant" }));
  const completed = envelope(request(), "completed"); completed.turn.active_child = null; completed.turn.next_action = null;
  get.mockResolvedValue(completed);
  await open();
  await screen.findByRole("heading", { name: "Work completed" });
  expect(await screen.findByRole("button", { name: "Start another request" })).toBeEnabled();
});

it("requires a fresh settled snapshot before replacing a retained operation", async () => {
  storeAssistanceReceipt(request());
  const completed = envelope(request(), "completed"); completed.turn.active_child = null; completed.turn.next_action = null;
  const get = vi.spyOn(api, "assistanceTurn").mockResolvedValue(completed);
  mount(); await open();
  await screen.findByRole("heading", { name: "Work completed" });
  await waitFor(() => expect(screen.getByRole("button", { name: "Start another request" })).toBeEnabled());
  get.mockResolvedValue(envelope(request(), "awaiting_execute_approval"));
  await userEvent.setup().click(screen.getByRole("button", { name: "Start another request" }));
  await screen.findByRole("heading", { name: "Execute approval is needed" });
  expect(readAssistanceReceipt()).toEqual(request());
  expect(screen.queryByRole("button", { name: "Start work" })).not.toBeInTheDocument();
});

it("does not infer settlement from an integrity-blocked view with no visible child", async () => {
  storeAssistanceReceipt(request());
  const value = envelope(request(), "blocked"); value.turn.active_child = null; value.turn.next_action = null;
  value.turn.can_start_new_turn = false;
  vi.spyOn(api, "assistanceTurn").mockResolvedValue(value);
  mount(); await open();
  await screen.findByRole("heading", { name: "Work needs attention" });
  expect(screen.queryByRole("button", { name: "Start another request" })).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Stop this operation" })).toBeEnabled();
  expect(readAssistanceReceipt()).toEqual(request());
});
