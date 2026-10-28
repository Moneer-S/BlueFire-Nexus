import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Link, MemoryRouter, Route, Routes } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { AdSmbAssistanceAction } from "../src/components/AdSmbAssistanceAction";
import { ExperimentAssistant } from "../src/components/ExperimentAssistant";
import { request, api } from "../src/lib/api";
import { checkedAdWorkflow } from "../src/lib/ad-smb";
import { adSmbAssistanceContext, adSmbAssistanceLimitations, adSmbAssistancePath, checkedAdSmbAssistanceContext, validAdSmbAssistanceSelection, type AdSmbAssistanceContext } from "../src/lib/ad-smb-assistance";
import { assistanceJobId, matchesAssistanceReceipt, readAssistanceReceipt, storeAssistanceReceipt, type AdSmbAssistanceRequest, type AssistanceEnvelope } from "../src/lib/assistance";
import { AssistanceProvider, useAssistancePanel, useAssistanceSelection } from "../src/state/AssistanceContext";
import { ProductProvider } from "../src/state/ProductContext";
import { adHash, adOwner, rawAdWorkflow } from "./ad-smb-fixture";
import { receiverAssistantProvider as provider } from "./receiver-assistance-fixture";

// Authored UI data; no AD task or model is executed by these tests.
vi.mock("../src/lib/api", async original => ({ ...await original<typeof import("../src/lib/api")>(), DEMO_MODE: false, request: vi.fn() }));
const workflow = checkedAdWorkflow(rawAdWorkflow({ phases: ["baseline"], allowed: [] }));
const selected = { kind: "ad_smb_workflow" as const, workflow_job_id: adOwner, result_digest: adHash };
function context(): AdSmbAssistanceContext {
  const operation = workflow.operations[0]!;
  return { schema_version: "bluefire.assistance-context.v1", selected, context_digest: `sha256:${"f".repeat(64)}`, analysis_only: true, capabilities: [], limitations: [...adSmbAssistanceLimitations],
    reference_summary: { schema_version: "bluefire.ad-smb-assistance-summary.v1", proof_scope: "saved_ad_workflow_only", provenance: workflow.environment.provenance, revision: workflow.revision, policy_state: workflow.policy, stopped: workflow.stopped, pending_operation: null, missing_phases: ["inspect", "harden", "retest", "rollback", "audit"], effective_access_claim: false,
      operations: [{ operation_job_id: operation.id, phase: "baseline", state: "completed", run_id: operation.runId,
        outcome: { state: operation.state, read_expectation: operation.expectation, distinct_local_contexts: operation.distinctContexts, audit_complete: null, evidence_digest: operation.digest, cleanup: operation.cleanup, authenticated_remote_reader: false, independent_observation: false, effective_access_claim: false },
        tasks: ["read_probe_primary", "read_legitimate_primary", "read_legitimate_health"].map((step, index) => ({ step, request_digest: adHash, task_id: `task-${index}`, original_digest: adHash, execution_digest: adHash, requested_at: "2026-10-18T15:00:00Z", provenance: "synthetic_fixture", dispatch: "attempted", cleanup: "verified",
          observation: { reader: index ? "legitimate" : "probe", purpose: index === 2 ? "health" : "primary", state: "bytes_matched", bytes_read: 24, local_cleanup: "verified", server_session_closed: null, authenticated_remote_reader: false, fresh_server_logon: false, independent_observation: false, effective_access_claim: false } })) }] } };
}
function body(): AdSmbAssistanceRequest { return { submission_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", selection: selected, context_digest: context().context_digest, message: "Explain the saved AD workflow and missing evidence.", autonomy: "assist", provider_id: provider.provider_id }; }
function envelope(original = body()): AssistanceEnvelope {
  return { job: { schema_version: "bluefire.job.v1", job_id: assistanceJobId(original.submission_id), kind: "assistance.turn", state: "completed", progress: {}, request: { submitted_request: original } },
    turn: { schema_version: "bluefire.assistance-turn.v1", status: "completed", can_start_new_turn: true, message: "The missing retest remains unknown.", context_digest: original.context_digest, selected: original.selection, plan: [], active_child: null, results: [], continuation: null, recovery: null, next_action: null, limitations: [...adSmbAssistanceLimitations] } } as AssistanceEnvelope;
}
function Probe() { const panel = useAssistancePanel(); return <><output aria-label="Saved selection">{JSON.stringify(useAssistanceSelection())}</output><output aria-label="Panel open">{String(panel?.open)}</output><output aria-label="Selection current">{String(panel?.selectionIsCurrent)}</output></>; }
function mount(source = true, keyed = false) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false }, mutations: { retry: false } } });
  const tree = (show: boolean, displayed = workflow) => <QueryClientProvider client={client}><MemoryRouter initialEntries={[show ? adSmbAssistancePath(selected) : "/runs"]}><ProductProvider><AssistanceProvider>{show ? <AdSmbAssistanceAction key={keyed ? displayed.id : undefined} workflow={displayed} /> : null}<Probe /><ExperimentAssistant providers={[provider]} /></AssistanceProvider></ProductProvider></MemoryRouter></QueryClientProvider>;
  const view = render(tree(source)); return { ...view, leave: () => view.rerender(tree(false)), show: (displayed: typeof workflow) => view.rerender(tree(true, displayed)) };
}
function mountJourney(path: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false }, mutations: { retry: false } } });
  return render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[path]}><ProductProvider><AssistanceProvider><Routes>
    <Route path="/ad-smb" element={<><AdSmbAssistanceAction workflow={workflow} /><Link to="/runs">Open Runs</Link></>} />
    <Route path="/runs" element={<p>Run history</p>} />
  </Routes><Probe /><ExperimentAssistant providers={[provider]} /></AssistanceProvider></ProductProvider></MemoryRouter></QueryClientProvider>);
}
it("accepts only an exact saved workflow source and read-only minimized summary", () => {
  expect(validAdSmbAssistanceSelection(selected)).toBe(true);
  for (const patch of [{ extra: true }, { workflow_job_id: "latest" }, { result_digest: "bad" }]) expect(validAdSmbAssistanceSelection({ ...selected, ...patch })).toBe(false);
  expect(adSmbAssistancePath(selected)).toBe(`/ad-smb?workflow=${adOwner}`);
  const value = context(); expect(checkedAdSmbAssistanceContext(value, adOwner, selected, workflow)).toBe(value);
  for (const patch of [{ capabilities: [{ id: "receiver.test_and_compare" }] }, { analysis_only: false }, { selected: { ...selected, result_digest: `sha256:${"b".repeat(64)}` } }, { limitations: [] }, { reference_summary: { ...value.reference_summary, raw_audit_xml: "private" } }]) expect(() => checkedAdSmbAssistanceContext({ ...value, ...patch }, adOwner, selected, workflow)).toThrow();
  expect(() => checkedAdSmbAssistanceContext(value, adOwner, selected, { ...workflow, revision: workflow.revision + 1 })).toThrow();
  expect(() => checkedAdSmbAssistanceContext(value, adOwner, selected, { ...workflow, operations: [{ ...workflow.operations[0]!, digest: `sha256:${"b".repeat(64)}` }] })).toThrow();
  const raw = context(); Object.assign(raw.reference_summary.operations[0]!.tasks[0]!.observation!, { file_contents: "private" });
  expect(() => checkedAdSmbAssistanceContext(raw, adOwner)).toThrow();
});
it("fetches the canonical saved source and refuses a stale persisted digest", async () => {
  vi.mocked(request).mockResolvedValue(context());
  await expect(adSmbAssistanceContext(adOwner, selected)).resolves.toMatchObject({ selected });
  expect(request).toHaveBeenCalledExactlyOnceWith(`/ad-smb/workflows/${adOwner}/assistance-context`);
  await expect(adSmbAssistanceContext(adOwner, { ...selected, result_digest: `sha256:${"b".repeat(64)}` })).rejects.toThrow(/unavailable or changed/);
});
it("keeps incomplete high-volume audit counts minimized and rejects overstated or raw audit payloads", () => {
  const value = context(), operation = value.reference_summary.operations[0]!;
  const normalization = { capture_state: "event_limit", window_start: "2026-10-18T15:00:00Z", window_end: "2026-10-18T15:01:00Z", reported_completeness: "truncated", input_events: 1000, duplicate_events: 0, limitations: ["Saved collector assertion."], classification_counts: [{ event_id: 5145 as const, audit_outcome: "failure" as const, binding: "matched" as const, count: 1000 }] };
  value.reference_summary.operations = [{ ...operation, phase: "audit", outcome: { ...operation.outcome, audit_complete: false, read_expectation: null }, tasks: [{ ...operation.tasks[0]!, step: "collect_audit", observation: { events: 1000, truncated: true, authenticated_source: false, independent_observation: false, effective_access_claim: false, normalization } }] }];
  value.reference_summary.missing_phases = ["inspect", "baseline", "harden", "retest", "rollback"];
  expect(checkedAdSmbAssistanceContext(value, adOwner)).toBe(value);
  expect(JSON.stringify(value).length).toBeLessThan(10000);
  for (const patch of [{ observations: [{ xml: "private" }] }, { reported_completeness: "complete" }, { classification_counts: [{ ...normalization.classification_counts[0], count: 0 }] }, { classification_counts: [{ ...normalization.classification_counts[0], count: 999 }] }]) {
    const changed = structuredClone(value); const observation = changed.reference_summary.operations[0]!.tasks[0]!.observation!;
    if ("normalization" in observation) Object.assign(observation.normalization!, patch);
    expect(() => checkedAdSmbAssistanceContext(changed, adOwner)).toThrow();
  }
});
it("retains exact receipts and rejects any AD execution or continuation in the explanation", () => {
  const original = body(), saved = envelope(); expect(storeAssistanceReceipt(original)).toBe(true); expect(readAssistanceReceipt()).toEqual(original); expect(matchesAssistanceReceipt(saved, original)).toBe(true);
  for (const patch of [{ plan: [{}] }, { active_child: {} }, { results: [{}] }, { recovery: {} }, { continuation: {} }, { receiver_test: {} }, { next_action: { kind: "continue", native_path: "/ad-smb" } }]) expect(matchesAssistanceReceipt({ ...saved, turn: { ...saved.turn, ...patch } } as never, original)).toBe(false);
});
it("opens by keyboard only after capture, preserves source through navigation/reload, and never dispatches", async () => {
  vi.mocked(request).mockResolvedValue(context()); const submit = vi.spyOn(api, "submitAssistance");
  const view = mount(), user = userEvent.setup();
  expect(request).not.toHaveBeenCalled();
  const button = screen.getByRole("button", { name: "Explain saved result" }); button.focus(); await user.keyboard("{Enter}");
  expect(await screen.findByRole("group", { name: "Saved AD workflow summary" })).toHaveTextContent("Synthetic fixture");
  expect(screen.queryByLabelText("Development activity")).not.toBeInTheDocument();
  await waitFor(() => expect(screen.getByLabelText("Selection current")).toHaveTextContent("true"));
  expect(sessionStorage.getItem("bluefire.assistance.selection.v1")).toContain(selected.result_digest);
  view.leave(); expect(await screen.findByRole("link", { name: "Reopen source" })).toHaveAttribute("href", adSmbAssistancePath(selected));
  expect(screen.getByRole("button", { name: "Start work" })).toBeDisabled(); view.unmount(); mount(false);
  expect(await screen.findByRole("link", { name: "Reopen source" })).toHaveAttribute("href", adSmbAssistancePath(selected)); expect(submit).not.toHaveBeenCalled();
});
it("does not publish a changed or unavailable result", async () => {
  vi.mocked(request).mockResolvedValue({ ...context(), reference_summary: { ...context().reference_summary, revision: workflow.revision + 1 } });
  mount(); await userEvent.setup().click(screen.getByRole("button", { name: "Explain saved result" }));
  expect(await screen.findByText("Saved explanation unavailable")).toBeVisible(); expect(screen.getByLabelText("Saved selection")).toBeEmptyDOMElement();
});
it("ignores a late preview after switching to another workflow at the same revision", async () => {
  let resolve!: (value: unknown) => void;
  const pending = new Promise(done => { resolve = done; }); vi.mocked(request).mockReturnValue(pending);
  const view = mount(); await userEvent.setup().click(screen.getByRole("button", { name: "Explain saved result" }));
  view.show({ ...workflow, id: `job-${"9".repeat(32)}` });
  await act(async () => { resolve(context()); await pending; });
  await waitFor(() => expect(screen.getByRole("button", { name: "Explain saved result" })).toBeEnabled());
  expect(screen.getByLabelText("Panel open")).toHaveTextContent("false"); expect(screen.getByLabelText("Saved selection")).toBeEmptyDOMElement();
});
it("does not open or publish from an old keyed workflow instance after its preview resolves", async () => {
  let resolve!: (value: unknown) => void;
  const pending = new Promise(done => { resolve = done; }); vi.mocked(request).mockReturnValue(pending);
  const view = mount(true, true); await userEvent.setup().click(screen.getByRole("button", { name: "Explain saved result" }));
  view.show({ ...workflow, id: `job-${"9".repeat(32)}` });
  expect(screen.getByRole("button", { name: "Explain saved result" })).toBeEnabled();
  await act(async () => { resolve(context()); await pending; });
  expect(screen.getByLabelText("Panel open")).toHaveTextContent("false"); expect(screen.getByLabelText("Saved selection")).toBeEmptyDOMElement();
});
it("ignores a preview after leaving the AD page and preserves its retained request", async () => {
  const original = body(); expect(storeAssistanceReceipt(original)).toBe(true);
  vi.spyOn(api, "assistanceTurn").mockResolvedValue(envelope(original));
  let resolve!: (value: unknown) => void;
  const pending = new Promise(done => { resolve = done; }); vi.mocked(request).mockReturnValue(pending);
  const view = mount(); await userEvent.setup().click(screen.getByRole("button", { name: "Explain saved result" }));
  view.leave(); expect(screen.queryByRole("button", { name: "Explain saved result" })).not.toBeInTheDocument();
  await act(async () => { resolve(context()); await pending; });
  expect(screen.getByLabelText("Panel open")).toHaveTextContent("false"); expect(screen.getByLabelText("Saved selection")).toBeEmptyDOMElement();
  expect(readAssistanceReceipt()).toEqual(original);
});
it("submits only the captured saved source through the shared analysis request", async () => {
  localStorage.setItem("bluefire.local.assistant-preferences.v1", JSON.stringify({ autonomy: "assist", provider: provider.provider_id, model: provider.model }));
  vi.mocked(request).mockResolvedValue(context());
  const submit = vi.spyOn(api, "submitAssistance").mockImplementation(async original => envelope(original as AdSmbAssistanceRequest));
  vi.spyOn(api, "assistanceTurn").mockImplementation(async () => envelope(readAssistanceReceipt() as AdSmbAssistanceRequest));
  mount(); const user = userEvent.setup(); await user.click(screen.getByRole("button", { name: "Explain saved result" }));
  await screen.findByRole("group", { name: "Saved AD workflow summary" }); await user.type(screen.getByRole("textbox", { name: "What would you like to do?" }), body().message);
  await user.click(screen.getByRole("button", { name: "Start work" }));
  await waitFor(() => expect(submit).toHaveBeenCalledOnce());
  expect(submit.mock.calls[0]![0]).toMatchObject({ selection: selected, context_digest: context().context_digest, autonomy: "assist", message: body().message });
  expect(await screen.findByRole("link", { name: "Saved AD workflow" })).toHaveAttribute("href", adSmbAssistancePath(selected));
});
it("retries an original retained AD request after reload without replacing its source", async () => {
  const original = body(); expect(storeAssistanceReceipt(original)).toBe(true);
  vi.spyOn(api, "assistanceTurn").mockRejectedValue(new Error("Disconnected"));
  const submit = vi.spyOn(api, "submitAssistance").mockImplementation(async requestBody => envelope(requestBody as AdSmbAssistanceRequest));
  mount(false); const user = userEvent.setup(); await user.click(screen.getByRole("button", { name: /^Assistant(?::|$)/ }));
  await user.click(await screen.findByRole("button", { name: "Retry original request" }));
  await waitFor(() => expect(submit).toHaveBeenCalledWith(original)); expect(readAssistanceReceipt()).toEqual(original);
});
it("reactivates the exact persisted source after leaving, reloading and reopening its saved AD view", async () => {
  vi.mocked(request).mockResolvedValue(context()); const user = userEvent.setup();
  const source = mountJourney(adSmbAssistancePath(selected));
  await user.click(screen.getByRole("button", { name: "Explain saved result" }));
  await screen.findByRole("group", { name: "Saved AD workflow summary" });
  await user.click(screen.getByRole("link", { name: "Open Runs" }));
  expect(await screen.findByRole("link", { name: "Reopen source" })).toBeVisible(); source.unmount();
  const reloaded = mountJourney("/runs");
  await user.click(await screen.findByRole("link", { name: "Reopen source" }));
  expect(await screen.findByRole("group", { name: "Saved AD workflow summary" })).toBeVisible();
  expect(screen.queryByRole("link", { name: "Reopen source" })).not.toBeInTheDocument();
  expect(screen.getByLabelText("Saved selection")).toHaveTextContent(JSON.stringify(selected));
  reloaded.unmount(); sessionStorage.setItem("bluefire.assistance.open.v1", "false");
  mountJourney(adSmbAssistancePath(selected));
  await waitFor(() => expect(screen.getByLabelText("Selection current")).toHaveTextContent("true"));
  expect(screen.getByLabelText("Panel open")).toHaveTextContent("false");
});
it("refuses a newer digest when reactivating persisted AD context and retains the original selection", async () => {
  sessionStorage.setItem("bluefire.assistance.selection.v1", JSON.stringify({ kind: "ad_smb", selected, title: "Saved AD share access", manualEdits: false }));
  sessionStorage.setItem("bluefire.assistance.open.v1", "true");
  vi.mocked(request).mockResolvedValue({ ...context(), selected: { ...selected, result_digest: `sha256:${"b".repeat(64)}` } });
  mountJourney(adSmbAssistancePath(selected));
  expect(await screen.findByText("Saved explanation unavailable")).toBeVisible();
  expect(screen.queryByRole("group", { name: "Saved AD workflow summary" })).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Start work" })).toBeDisabled();
  expect(screen.getByLabelText("Selection current")).toHaveTextContent("false");
  expect(screen.getByLabelText("Saved selection")).toHaveTextContent(JSON.stringify(selected));
  expect(JSON.parse(sessionStorage.getItem("bluefire.assistance.selection.v1")!).selected).toEqual(selected);
});
