import type { RunDetectionSelection } from "../src/lib/detection-creation";
import type { SavedGraphSelection } from "../src/lib/run-assistance";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, useLocation } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { ExperimentAssistant } from "../src/components/ExperimentAssistant";
import { api } from "../src/lib/api";
import { assistanceJobId, assistancePath, readAssistanceReceipt, readAssistanceRecovery, storeAssistanceReceipt, type AssistanceContext, type AssistanceEnvelope, type AssistanceRequest } from "../src/lib/assistance";
import { AssistanceProvider, useAssistancePanel, usePublishGraphAssistanceSelection, usePublishAssistanceSelection, usePublishSavedGraphSelection, usePublishRunDetectionSelection, type AssistanceSelection } from "../src/state/AssistanceContext";
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
      selected: "selection" in body ? body.selection : { run_id: body.run_id, candidate_id: body.candidate_id, candidate_resource_digest: body.candidate_resource_digest },
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

const graphContext: AssistanceContext = { schema_version: "bluefire.assistance-context.v1", context_digest: digest,
  selected: { kind: "graph", base_scenario: null }, capabilities: [{ id: "graph.propose_and_validate", title: "Plan and validate an experiment", available: true, supported_autonomy: ["assist", "auto"], reason: "Saving requires your review.", native_path: "/builder" }], limitations: ["Creates a separate experiment; no execution."] };
function GraphSelection() {
  usePublishGraphAssistanceSelection(true);
  const panel = useAssistancePanel();
  return <button onClick={() => panel?.setOpen(true)}>Plan with Assistant</button>;
}
function graphEnvelope(body: AssistanceRequest): AssistanceEnvelope {
  return { ...envelope(body), turn: { ...envelope(body).turn,
    message: "Review the proposed experiment in Builder.",
    plan: [{ step_id: "graph", capability_id: "graph.propose_and_validate", detector_ref: "none", title: "Build and validate", reason: "Use registered steps." }],
    active_child: { job_id: "job-1234567890abcdef1234567890abcdef", kind: "graph.ai.propose", state: "completed", step_id: "graph", native_path: "/builder?graph_job=job-1234567890abcdef1234567890abcdef" },
    next_action: { kind: "review_graph", label: "Review experiment", native_path: "/builder?graph_job=job-1234567890abcdef1234567890abcdef" } } };
}
function mountGraph() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<QueryClientProvider client={client}><MemoryRouter><ProductProvider><AssistanceProvider><GraphSelection /><ExperimentAssistant providers={[provider]} /></AssistanceProvider></ProductProvider></MemoryRouter></QueryClientProvider>);
}

it("opens the shared Assistant from Builder and retains a graph request without invented evidence IDs", async () => {
  const get = vi.spyOn(api, "assistanceGraphContext").mockResolvedValue(graphContext);
  const detection = vi.spyOn(api, "assistanceContext");
  const submit = vi.spyOn(api, "submitAssistance").mockImplementation(async (body) => graphEnvelope(body));
  vi.spyOn(api, "assistanceTurn").mockImplementation(async () => graphEnvelope(readAssistanceReceipt()!));
  mountGraph();
  expect(get).not.toHaveBeenCalled();
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: "Plan with Assistant" }));
  await screen.findByText("New experiment");
  expect(submit).not.toHaveBeenCalled();
  expect(screen.getByRole("button", { name: "Start work" })).toBeDisabled();
  expect(screen.queryByLabelText("Evidence case")).not.toBeInTheDocument();
  await user.selectOptions(screen.getByLabelText("AI mode"), "auto");
  await user.selectOptions(screen.getByLabelText("Provider"), provider.provider_id);
  await user.type(screen.getByLabelText("What would you like to do?"), "Discover the owned lab and collect its test records.");
  await user.dblClick(screen.getByRole("button", { name: "Start work" }));
  expect(await screen.findByRole("link", { name: "Review experiment" })).toHaveAttribute("href", expect.stringContaining("/builder?graph_job="));
  expect(submit).toHaveBeenCalledTimes(1);
  expect(submit.mock.calls[0]![0]).toEqual({ submission_id: expect.any(String), context_digest: digest, selection: { kind: "graph", base_scenario: null }, message: "Discover the owned lab and collect its test records.", autonomy: "auto", provider_id: provider.provider_id });
  expect(readAssistanceReceipt()).toEqual(submit.mock.calls[0]![0]);
  expect(detection).not.toHaveBeenCalled();
});

it("restores a saved graph result while another native selection is active without claiming execution", async () => {
  const body: AssistanceRequest = { submission_id: request().submission_id, context_digest: digest, selection: { kind: "graph", base_scenario: null }, message: "Create a collection experiment.", autonomy: "assist", provider_id: provider.provider_id };
  storeAssistanceReceipt(body);
  const saved = graphEnvelope(body);
  saved.turn.status = "completed"; saved.turn.can_start_new_turn = true; saved.turn.active_child = null; saved.turn.next_action = null;
  saved.turn.results = [{ kind: "graph_saved", step_id: "graph", proposal_job_id: "job-proposal", scenario_id: "experiment", version: 2, digest, operator_modified: true, native_path: "/builder?graph_job=job-proposal", execution_state: "not_run" }];
  vi.spyOn(api, "assistanceTurn").mockResolvedValue(saved);
  const submit = vi.spyOn(api, "submitAssistance");
  mount(); await open();
  await screen.findByText("Experiment saved");
  expect(screen.getByText(/Version 2 · Includes your edits · Not run/)).toBeInTheDocument();
  expect(screen.queryByText("Source rule and evidence")).not.toBeInTheDocument();
  expect(submit).not.toHaveBeenCalled();
});

it("rejects a graph receipt with an incomplete saved reference", () => {
  const body = { submission_id: request().submission_id, context_digest: digest, selection: { kind: "graph", base_scenario: { scenario_id: "example", version: 0, digest } }, message: "Draft a variation.", autonomy: "assist", provider_id: provider.provider_id };
  sessionStorage.setItem("bluefire.assistance.receipt.v1", JSON.stringify(body));
  expect(readAssistanceReceipt()).toBeUndefined();
});

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

it("waits for publication before reading a newly retained request, then keeps polling", async () => {
  vi.spyOn(api, "assistanceContext").mockResolvedValue(context);
  let publish!: (value: AssistanceEnvelope) => void;
  const submit = vi.spyOn(api, "submitAssistance").mockImplementation(() => new Promise((resolve) => { publish = resolve; }));
  const get = vi.spyOn(api, "assistanceTurn").mockImplementation(async () => envelope(readAssistanceReceipt()!));
  mount(); const user = await compose();
  await user.click(screen.getByRole("button", { name: "Start work" }));
  await waitFor(() => expect(submit).toHaveBeenCalledTimes(1));
  const saved = readAssistanceReceipt()!;
  expect(saved).toEqual(submit.mock.calls[0]![0]);
  expect(get).not.toHaveBeenCalled();
  await act(async () => { publish(envelope(saved, "planning")); });
  await screen.findByRole("heading", { name: "Your review is needed" });
  expect(get).toHaveBeenCalledWith(assistanceJobId(saved.submission_id));
  expect(screen.queryByText("Saved work could not be checked")).not.toBeInTheDocument();
  expect(readAssistanceReceipt()).toEqual(saved);
  expect(submit).toHaveBeenCalledTimes(1);
});

it("discards a delayed pre-publication 404 after an explicit exact-request retry succeeds", async () => {
  const body = request(); storeAssistanceReceipt(body);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  const key = ["assistance-turn", assistanceJobId(body.submission_id)];
  client.setQueryData(key, envelope(body, "planning"));
  const get = vi.spyOn(api, "assistanceTurn").mockRejectedValue(new Error("Assistance turn was not found (404)"));
  let publish!: (value: AssistanceEnvelope) => void;
  const submit = vi.spyOn(api, "submitAssistance").mockImplementation(() => new Promise((resolve) => { publish = resolve; }));
  mount(selection, client); await open();
  await screen.findByText("Saved work could not be checked");
  expect(submit).not.toHaveBeenCalled();
  let rejectOldRead!: (reason: Error) => void;
  get.mockImplementationOnce(() => new Promise((_resolve, reject) => { rejectOldRead = reject; })).mockResolvedValue(envelope(body));
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: "Try again" }));
  await waitFor(() => expect(rejectOldRead).toBeTypeOf("function"));
  await user.click(screen.getByRole("button", { name: "Retry original request" }));
  await waitFor(() => expect(submit).toHaveBeenCalledWith(body));
  await act(async () => { publish(envelope(body, "planning")); });
  await act(async () => { rejectOldRead(new Error("Delayed pre-publication 404")); });
  await waitFor(() => expect(screen.getByRole("heading", { name: "Your review is needed" })).toBeInTheDocument(), { timeout: 3500 });
  expect(client.getQueryState(key)?.error).toBeNull();
  expect(screen.queryByText("Saved work could not be checked")).not.toBeInTheDocument();
  expect(submit).toHaveBeenCalledTimes(1);
  expect(readAssistanceReceipt()).toEqual(body);
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


it.each([
  ["ready_to_continue", "Recovery needed"], ["blocked", "Needs attention"],
  ["cancelling", "Stopping"], ["awaiting_review", "Review needed"],
  ["awaiting_execute_approval", "Approval needed"], ["cancelled", "Stopped"],
] as const)("shows truthful %s status while the drawer is closed", async (status, label) => {
  storeAssistanceReceipt(request());
  vi.spyOn(api, "assistanceTurn").mockResolvedValue(envelope(request(), status));
  const contextRead = vi.spyOn(api, "assistanceContext");
  const continueWork = vi.spyOn(api, "continueAssistance");
  mount();
  expect(await screen.findByRole("button", { name: `Assistant: ${label}` })).toBeInTheDocument();
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  expect(contextRead).not.toHaveBeenCalled();
  expect(continueWork).not.toHaveBeenCalled();
});

it("labels cached work as status unavailable after refresh fails", async () => {
  storeAssistanceReceipt(request());
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  client.setQueryData(["assistance-turn", assistanceJobId(request().submission_id)], envelope(request(), "working"));
  vi.spyOn(api, "assistanceTurn").mockRejectedValue(new Error("Unit connection unavailable"));
  mount(selection, client);
  expect(await screen.findByRole("button", { name: "Assistant: Status unavailable" })).toBeInTheDocument();
  expect(readAssistanceReceipt()).toEqual(request());
});

it("keeps saved results and the exact turn when visiting runner setup and explicitly resuming", async () => {
  storeAssistanceReceipt(request());
  const value = envelope(request(), "ready_to_continue");
  value.turn.active_child = null;
  value.turn.next_action = { kind: "continue", label: "Recover next step", native_path: null };
  value.turn.recovery = { code: "runner_readiness_required", message: "Check the recorded runner.", profile_id: "sandbox-execute.v1", action: { label: "Check runner setup", native_path: "/runs?setup=execute" } };
  value.turn.results = [{ kind: "detection_revision", step_id: "revise", candidate_id: "saved-revision", evaluation_ids: ["evaluation-one"], run_ids: [selection.runId], comparison_id: null, native_path: "/detection-lab?candidate=saved-revision" }];
  vi.spyOn(api, "assistanceTurn").mockResolvedValue(value);
  const recover = vi.spyOn(api, "continueAssistance").mockResolvedValue(value);
  const submit = vi.spyOn(api, "submitAssistance");
  mount(); await open();
  await screen.findByText("Your rule revision and evaluation are saved.");
  const link = screen.getByRole("link", { name: "Check runner setup" });
  expect(link).toHaveAttribute("href", "/runs?setup=execute");
  await userEvent.setup().click(link);
  expect(screen.getByTestId("location")).toHaveTextContent("/runs?setup=execute");
  expect(readAssistanceReceipt()).toEqual(request());
  expect(recover).not.toHaveBeenCalled(); expect(submit).not.toHaveBeenCalled();
  await open();
  await userEvent.setup().click(await screen.findByRole("button", { name: "Resume saved turn" }));
  await waitFor(() => expect(recover).toHaveBeenCalledTimes(1));
  expect(recover).toHaveBeenCalledWith(assistanceJobId(request().submission_id), expect.objectContaining({ context_digest: request().context_digest }));
  expect(submit).not.toHaveBeenCalled();
  expect(readAssistanceReceipt()).toEqual(request());
});


it("updates a closed badge from running to recovery through read-only polling", async () => {
  storeAssistanceReceipt(request());
  const get = vi.spyOn(api, "assistanceTurn").mockResolvedValueOnce(envelope(request(), "working")).mockResolvedValue(envelope(request(), "ready_to_continue"));
  const recover = vi.spyOn(api, "continueAssistance");
  mount();
  await screen.findByRole("button", { name: "Assistant: Working" });
  await waitFor(() => expect(screen.getByRole("button", { name: "Assistant: Recovery needed" })).toBeInTheDocument(), { timeout: 3500 });
  expect(get.mock.calls.length).toBeGreaterThanOrEqual(2);
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  expect(recover).not.toHaveBeenCalled();
});

const savedGraph: SavedGraphSelection = { kind: "saved_graph", proposal_job_id: `job-${"a".repeat(32)}`,
  application: { proposal_job_id: `job-${"a".repeat(32)}`, proposal_digest: digest, reviewed_digest: digest, operator_modified: true, scenario_id: "saved.experiment.v1", version: 2, digest },
  run_intent: { mode: "execute", autonomy: "off", ai_provider_id: null, runner_profile_id: "sandbox-execute.v1", target_scope: { scope_refs: ["owned.selected.scope"] }, collectors: ["collector.filesystem.sandbox.v1"] } };
function SavedRunSelection() { usePublishSavedGraphSelection(savedGraph, "Reviewed experiment"); return null; }
it("retains the saved graph and exact runtime settings independently of Assistant choices", async () => {
  const context: AssistanceContext = { ...graphContext, selected: savedGraph, capabilities: [{ id: "run.saved_graph_and_inspect", title: "Run and inspect", available: true, supported_autonomy: ["assist", "auto"], reason: "", native_path: "/runs" }] };
  vi.spyOn(api, "assistanceRunContext").mockResolvedValue(context);
  const result = (body: AssistanceRequest): AssistanceEnvelope => ({ ...envelope(body), turn: { ...envelope(body).turn, plan: [{ step_id: "run", capability_id: "run.saved_graph_and_inspect", title: "Run and inspect", detector_ref: "none", reason: "Use the selected settings" }], active_child: null, next_action: { kind: "review_run", label: "Review this run", native_path: "/runs?assistance_job=job-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" } } });
  const submit = vi.spyOn(api, "submitAssistance").mockImplementation(async (body) => result(body));
  vi.spyOn(api, "assistanceTurn").mockImplementation(async () => result(readAssistanceReceipt()!));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter><ProductProvider><AssistanceProvider><SavedRunSelection /><ExperimentAssistant providers={[provider]} /></AssistanceProvider></ProductProvider></MemoryRouter></QueryClientProvider>);
  const user = userEvent.setup(); await open();
  await user.selectOptions(screen.getByLabelText("Assistant mode"), "assist");
  await user.selectOptions(screen.getByLabelText("Assistant provider"), provider.provider_id);
  await user.type(screen.getByLabelText("What would you like to do?"), "Run this version and inspect its observations.");
  await user.click(screen.getByRole("button", { name: "Start work" }));
  expect(await screen.findByRole("link", { name: "Review this run" })).toHaveAttribute("href", "/runs?assistance_job=job-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
  expect(submit).toHaveBeenCalledTimes(1);
  const submitted = submit.mock.calls[0]![0];
  expect(submitted).toMatchObject({ autonomy: "assist", provider_id: provider.provider_id, selection: savedGraph });
  expect(submitted).not.toHaveProperty("run_id");
  expect(readAssistanceReceipt()).toEqual(submitted);
  await user.click(screen.getByText("Submitted run settings"));
  expect(screen.getByText("owned.selected.scope")).toBeVisible();
  expect(screen.getByText("Off · No provider")).toBeVisible();
});

function OpenBoundOperation({ jobId }: { jobId: string }) { const panel = useAssistancePanel(); return <button onClick={() => panel?.openJob(jobId)}>Open run's Assistant work</button>; }
it("restores a directly linked parent from its saved request without submitting work", async () => {
  const body = request();
  vi.spyOn(api, "assistanceTurn").mockResolvedValue(envelope(body));
  const submit = vi.spyOn(api, "submitAssistance");
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter><ProductProvider><AssistanceProvider><OpenBoundOperation jobId={assistanceJobId(body.submission_id)} /><ExperimentAssistant providers={[provider]} /></AssistanceProvider></ProductProvider></MemoryRouter></QueryClientProvider>);
  await userEvent.setup().click(screen.getByRole("button", { name: "Open run's Assistant work" }));
  expect(await screen.findByRole("link", { name: "Review rule revision" })).toBeVisible();
  expect(readAssistanceReceipt()).toEqual(body);
  expect(submit).not.toHaveBeenCalled();
});

it("does not replace an existing saved operation when another run's parent is opened", async () => {
  const body = request(); storeAssistanceReceipt(body);
  const lookup = vi.spyOn(api, "assistanceTurn").mockResolvedValue(envelope(body));
  const other = `job-${"f".repeat(32)}`;
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter><ProductProvider><AssistanceProvider><OpenBoundOperation jobId={other} /><ExperimentAssistant providers={[provider]} /></AssistanceProvider></ProductProvider></MemoryRouter></QueryClientProvider>);
  await userEvent.setup().click(screen.getByRole("button", { name: "Open run's Assistant work" }));
  expect(await screen.findByText(/Another saved operation is open/)).toBeVisible();
  expect(readAssistanceReceipt()).toEqual(body);
  expect(lookup).not.toHaveBeenCalledWith(other);
});

const createSelection: RunDetectionSelection = { kind: "run_detection", run_id: "run-20300101T000000Z-1234567890abcdef", source_binding_digest: digest, behavior_id: "sandbox.collection.records.v1", target_language: "sqlite", case_role: "benign" };
function CreationSelection() { usePublishRunDetectionSelection(createSelection, "Collection observations"); return null; }
function mountCreation() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<QueryClientProvider client={client}><MemoryRouter><ProductProvider><AssistanceProvider><CreationSelection /><ExperimentAssistant providers={[provider]} /></AssistanceProvider></ProductProvider></MemoryRouter></QueryClientProvider>);
}
function creationContext(): AssistanceContext { return { ...graphContext, selected: createSelection, capabilities: [{ id: "detection.create_and_evaluate", title: "Create and evaluate a rule", available: true, supported_autonomy: ["assist", "auto"], reason: "Review source before saving.", native_path: "/detection-lab?create=1" }] }; }
it("carries the selected run, language, behavior and development case into initial rule creation without an existing candidate", async () => {
  const get = vi.spyOn(api, "assistanceDetectionContext").mockResolvedValue(creationContext());
  const old = vi.spyOn(api, "assistanceContext");
  const submit = vi.spyOn(api, "submitAssistance").mockImplementation(async (body) => ({ ...graphEnvelope(body), turn: { ...graphEnvelope(body).turn, selected: createSelection } }));
  vi.spyOn(api, "assistanceTurn").mockImplementation(async () => graphEnvelope(readAssistanceReceipt()!));
  mountCreation();
  const user = await compose();
  expect(get).toHaveBeenCalledWith(createSelection);
  expect(old).not.toHaveBeenCalled();
  expect(screen.queryByLabelText("Evidence case")).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Start work" }));
  await waitFor(() => expect(submit).toHaveBeenCalledTimes(1));
  expect(submit.mock.calls[0]![0]).toMatchObject({ selection: createSelection, autonomy: "assist", provider_id: provider.provider_id });
  expect(submit.mock.calls[0]![0]).not.toHaveProperty("candidate_id");
  expect(readAssistanceReceipt()).toEqual(submit.mock.calls[0]![0]);
});
it("keeps initial detection creation in Off without submitting model work", async () => {
  vi.spyOn(api, "assistanceDetectionContext").mockResolvedValue(creationContext());
  const submit = vi.spyOn(api, "submitAssistance");
  mountCreation(); await open();
  expect(await screen.findByText("Collection observations")).toBeVisible();
  expect(screen.getByRole("button", { name: "Start work" })).toBeDisabled();
  expect(submit).not.toHaveBeenCalled();
});
it("does not restore a creation request whose evidence case is relabeled as held-out", () => {
  const body = { ...request(), selection: { ...createSelection, case_role: "heldout" } };
  sessionStorage.setItem("bluefire.assistance.receipt.v1", JSON.stringify(body));
  expect(readAssistanceReceipt()).toBeUndefined();
});
