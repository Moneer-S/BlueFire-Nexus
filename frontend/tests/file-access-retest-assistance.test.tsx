import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, useLocation } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { ExperimentAssistant } from "../src/components/ExperimentAssistant";
import { FileAccessRetestComparison } from "../src/components/FileAccessRetestComparison";
import { api, request } from "../src/lib/api";
import { assistanceJobId, matchesAssistanceReceipt, readAssistanceReceipt, storeAssistanceReceipt, type AssistanceEnvelope, type FileAccessRetestAssistanceRequest } from "../src/lib/assistance";
import { fileAccessLinkageApi } from "../src/lib/file-access-linkage";
import { checkedFileAccessRetestAssistanceContext, fileAccessRetestAssistanceContext, fileAccessRetestAssistanceLimitations, fileAccessRetestComparisonPath, fileAccessRetestSelection, validFileAccessRetestAssistanceSelection, type FileAccessRetestAssistanceContext } from "../src/lib/file-access-retest-assistance";
import { AssistanceProvider, useAssistancePanel, useAssistanceSelection } from "../src/state/AssistanceContext";
import { ProductProvider } from "../src/state/ProductContext";
import { linkageFixture } from "./file-access-linkage-fixture";
import { receiverAssistantProvider as provider } from "./receiver-assistance-fixture";

// Authored client interaction data; backend projection/provider tests are separate.
vi.mock("../src/lib/api", async importOriginal => ({ ...await importOriginal<typeof import("../src/lib/api")>(), DEMO_MODE: false, request: vi.fn() }));
const fixture = linkageFixture("unknown");
const selected = fileAccessRetestSelection(fixture.value as never, fixture.objective, fixture.attempt);
function context(state: "unknown" | "established" | "incomplete" | "owner-unknown" = "unknown"): FileAccessRetestAssistanceContext {
  const value = linkageFixture(state).value;
  return {
    schema_version: "bluefire.assistance-context.v1", selected, context_digest: `sha256:${"f".repeat(64)}`, analysis_only: true, capabilities: [], limitations: [...fileAccessRetestAssistanceLimitations],
    reference_summary: {
      schema_version: "bluefire.file-access-retest-assistance-summary.v1", proof_scope: "historical_saved_linkage_only",
      baseline: { source: "verified_saved_baseline_operation", control_revision: 2, mode: "0640", non_owner: "allowed", owner: "allowed", record_count: 8 },
      change: { source: "reviewed_saved_hardening_operation", control_revision: 3, mode: "0600" },
      retest: { source: "saved_composed_attempt", state: value.retest.state, non_owner_decision: value.retest.non_owner_decision, owner_decision: value.retest.owner_decision, record_count: value.retest.record_count, run_cleanup: value.retest.run_cleanup, request_cleanup: value.retest.request_cleanup, objective_established: value.retest.objective_established },
      comparison: value.comparison,
    } as FileAccessRetestAssistanceContext["reference_summary"],
  };
}
function body(): FileAccessRetestAssistanceRequest {
  return { submission_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", context_digest: context().context_digest, selection: selected, message: "Explain this exact historical comparison and its unknown retest.", autonomy: "assist", provider_id: provider.provider_id };
}
function envelope(original = body()): AssistanceEnvelope {
  return { job: { schema_version: "bluefire.job.v1", job_id: assistanceJobId(original.submission_id), kind: "assistance.turn", state: "completed", progress: {}, request: { submitted_request: original } },
    turn: { schema_version: "bluefire.assistance-turn.v1", status: "completed", can_start_new_turn: true, message: "The selected retest remains unknown.", context_digest: original.context_digest, selected: original.selection, plan: [], active_child: null, results: [], continuation: null, recovery: null, next_action: null, limitations: [...fileAccessRetestAssistanceLimitations] } } as AssistanceEnvelope;
}
function Probe() {
  const selection = useAssistanceSelection(), panel = useAssistancePanel(), location = useLocation();
  return <><output aria-label="Selection">{JSON.stringify(selection)}</output><output aria-label="Open">{String(panel?.open)}</output><output aria-label="Location">{location.pathname}{location.search}</output></>;
}
function mount(showSource = true, sourceFixture = fixture, availableProvider = provider) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false }, mutations: { retry: false } } });
  const tree = (source: boolean) => <QueryClientProvider client={client}><MemoryRouter initialEntries={[source ? fileAccessRetestComparisonPath(selected) : "/runs"]}><ProductProvider><AssistanceProvider>{source ? <FileAccessRetestComparison objective={sourceFixture.objective} attempt={sourceFixture.attempt} /> : null}<Probe /><ExperimentAssistant providers={[availableProvider]} /></AssistanceProvider></ProductProvider></MemoryRouter></QueryClientProvider>;
  const view = render(tree(showSource));
  return { ...view, leave: () => view.rerender(tree(false)), client };
}

it("binds the exact selected linkage and constructs only its canonical return path", () => {
  expect(validFileAccessRetestAssistanceSelection(selected)).toBe(true);
  for (const changed of [{ ...selected, extra: true }, { ...selected, linkage_digest: "sha256:bad" }, { ...selected, attempt_id: "attempt-other" }, { ...selected, control_owner_id: "job-latest" }]) expect(validFileAccessRetestAssistanceSelection(changed)).toBe(false);
  expect(() => fileAccessRetestSelection({ ...fixture.value, objective_owner_id: `job-${"e".repeat(32)}` } as never, fixture.objective, fixture.attempt)).toThrow();
  const url = new URL(fileAccessRetestComparisonPath(selected), "https://bluefire.invalid");
  expect([...url.searchParams]).toEqual([["control", selected.control_owner_id], ["objective", selected.objective_owner_id], ["pack", "bluefire.linux-file-access-pack.v1"], ["attempt", selected.attempt_id]]);
});

it("keeps unknown, established and verified false historical facts distinct", () => {
  for (const state of ["unknown", "established", "incomplete", "owner-unknown"] as const) {
    const value = context(state);
    expect(checkedFileAccessRetestAssistanceContext(value, selected)).toBe(value);
  }
  expect(context().reference_summary.retest.objective_established).toBeNull();
  expect(context("incomplete").reference_summary.retest.objective_established).toBe(false);
  for (const mutate of [
    (v: FileAccessRetestAssistanceContext) => { v.reference_summary.retest.objective_established = false; },
    (v: FileAccessRetestAssistanceContext) => { v.reference_summary.baseline.record_count = 101; },
    (v: FileAccessRetestAssistanceContext) => { v.reference_summary.change.control_revision = 2; },
    (v: FileAccessRetestAssistanceContext) => { v.selected = { ...selected, linkage_digest: `sha256:${"e".repeat(64)}` }; },
    (v: FileAccessRetestAssistanceContext) => { v.limitations = []; },
  ]) { const value = context(); mutate(value); expect(() => checkedFileAccessRetestAssistanceContext(value, selected)).toThrow(); }
  for (const extra of [{ raw_contents: "secret" }, { latest_control: {} }, { readiness: "ready" }, { file_hash: "raw" }]) {
    expect(() => checkedFileAccessRetestAssistanceContext({ ...context(), reference_summary: { ...context().reference_summary, ...extra } }, selected)).toThrow();
  }
  expect(() => checkedFileAccessRetestAssistanceContext({ ...context(), capabilities: [{ id: "run.saved_graph_and_inspect" }] }, selected)).toThrow();
  const falseEvidence = context("incomplete"); falseEvidence.reference_summary.comparison.content_preserved = null;
  expect(() => checkedFileAccessRetestAssistanceContext(falseEvidence, selected)).toThrow();
});

it("fetches only the selected objective/attempt preview and refuses changed bindings", async () => {
  vi.mocked(request).mockResolvedValue(context());
  await expect(fileAccessRetestAssistanceContext(selected)).resolves.toMatchObject({ selected, analysis_only: true });
  expect(request).toHaveBeenCalledWith(`/composition/objectives/${selected.objective_owner_id}/file-access-linkage/${selected.attempt_id}/assistant-context`);
  vi.mocked(request).mockResolvedValue({ ...context(), selected: { ...selected, control_owner_id: `job-${"e".repeat(32)}` } });
  await expect(fileAccessRetestAssistanceContext(selected)).rejects.toThrow();
});

it.each(["non_owner_decision", "owner_decision", "run_cleanup"])("rejects an array-coerced summary %s even with compatible false-result fields", field => {
  const value = context("incomplete");
  const retest = value.reference_summary.retest as unknown as Record<string, unknown>;
  retest[field] = [retest[field]];
  if (field === "owner_decision") value.reference_summary.comparison.owner_preserved = null;
  expect(() => checkedFileAccessRetestAssistanceContext(value, selected)).toThrow();
});

it.each(["array", "object"])("rejects %s values in every summary enum position", shape => {
  const fields = { baseline: ["source", "mode", "non_owner", "owner"], change: ["source", "mode"], retest: ["source", "state", "non_owner_decision", "owner_decision", "run_cleanup", "request_cleanup"], comparison: ["state", "non_owner_change"] };
  for (const [section, names] of Object.entries(fields)) for (const name of names) {
    const value = context("established");
    const row = (value.reference_summary as unknown as Record<string, Record<string, unknown>>)[section]!;
    row[name] = shape === "array" ? [row[name]] : { value: row[name] };
    expect(() => checkedFileAccessRetestAssistanceContext(value, selected), `${section}.${name}`).toThrow();
  }
});

it("retains exact receipts while rejecting plans, children, results and native continuation payloads", () => {
  const original = body(), saved = envelope(original);
  expect(storeAssistanceReceipt(original)).toBe(true);
  expect(readAssistanceReceipt()).toEqual(original);
  expect(matchesAssistanceReceipt(saved, original)).toBe(true);
  expect(matchesAssistanceReceipt({ ...saved, turn: { ...saved.turn, next_action: { kind: "new_turn", native_path: null } } }, original)).toBe(true);
  for (const patch of [{ plan: [{}] }, { active_child: {} }, { results: [{}] }, { continuation: {} }, { recovery: {} }, { receiver_test: {} }, { next_action: { kind: "new_turn", native_path: "/runs" } }, { next_action: { kind: "continue", native_path: null } }]) {
    expect(matchesAssistanceReceipt({ ...saved, turn: { ...saved.turn, ...patch } } as never, original)).toBe(false);
  }
  expect(matchesAssistanceReceipt(saved, { ...original, selection: { ...selected, linkage_digest: `sha256:${"0".repeat(64)}` } })).toBe(false);
});

it("publishes after validation, opens the normal Assistant, and preserves exact context after navigation and reload", async () => {
  let resolve!: (value: never) => void;
  const pending = new Promise<never>(done => { resolve = done; });
  vi.spyOn(fileAccessLinkageApi, "read").mockReturnValue(pending);
  vi.mocked(request).mockResolvedValue(context());
  const submit = vi.spyOn(api, "submitAssistance").mockImplementation(async original => envelope(original as FileAccessRetestAssistanceRequest));
  const view = mount();
  expect(screen.queryByRole("button", { name: "Explain this comparison" })).not.toBeInTheDocument();
  await act(async () => { resolve(fixture.value as never); await pending; });
  fireEvent.click(await screen.findByRole("button", { name: "Explain this comparison" }));
  expect(await screen.findByRole("group", { name: "Saved file-access comparison summary" })).toHaveTextContent("No verified retest conclusion");
  expect(screen.getByText("Explanation scope and evidence limits")).toBeInTheDocument();
  expect(screen.queryByLabelText("Development activity")).not.toBeInTheDocument();
  expect(submit).not.toHaveBeenCalled();
  view.leave();
  expect(await screen.findByRole("link", { name: "Reopen source" })).toHaveAttribute("href", fileAccessRetestComparisonPath(selected));
  expect(screen.getByRole("button", { name: "Start work" })).toBeDisabled();
  view.unmount();
  mount(false);
  expect(await screen.findByRole("link", { name: "Reopen source" })).toHaveAttribute("href", fileAccessRetestComparisonPath(selected));
  expect(screen.getByRole("button", { name: "Start work" })).toBeDisabled();
  expect(submit).not.toHaveBeenCalled();
});

it("retries a retained pending request after reload without substituting today's selection or provider", async () => {
  const original = body();
  expect(storeAssistanceReceipt(original)).toBe(true);
  sessionStorage.setItem("bluefire.assistance.selection.v1", JSON.stringify({ kind: "file_access_retest", selected: { ...selected, objective_owner_id: `job-${"9".repeat(32)}` }, title: "Another comparison", manualEdits: false }));
  vi.spyOn(api, "assistanceTurn").mockRejectedValue(new Error("Disconnected before publication"));
  const submit = vi.spyOn(api, "submitAssistance").mockImplementation(async requestBody => envelope(requestBody as FileAccessRetestAssistanceRequest));
  const view = mount(false, fixture, { ...provider, provider_id: "different-provider" });
  await userEvent.setup().click(screen.getByRole("button", { name: /^Assistant(?::|$)/ }));
  expect(await screen.findByRole("link", { name: "Saved baseline and retest comparison" })).toHaveAttribute("href", fileAccessRetestComparisonPath(original.selection));
  await userEvent.setup().click(await screen.findByRole("button", { name: "Retry original request" }));
  await waitFor(() => expect(submit).toHaveBeenCalledWith(original));
  expect(readAssistanceReceipt()).toEqual(original);
  view.unmount();
  mount(false);
  expect(await screen.findByRole("link", { name: "Saved baseline and retest comparison" })).toHaveAttribute("href", fileAccessRetestComparisonPath(original.selection));
  expect(readAssistanceReceipt()).toEqual(original);
});

it("submits only the previewed historical selection through the shared explanation request", async () => {
  const incomplete = linkageFixture("incomplete");
  vi.spyOn(fileAccessLinkageApi, "read").mockResolvedValue(incomplete.value);
  vi.mocked(request).mockResolvedValue(context("incomplete"));
  const submit = vi.spyOn(api, "submitAssistance").mockImplementation(async original => envelope(original as FileAccessRetestAssistanceRequest));
  vi.spyOn(api, "assistanceTurn").mockImplementation(async () => envelope(readAssistanceReceipt() as FileAccessRetestAssistanceRequest));
  mount(true, incomplete);
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Explain this comparison" }));
  expect(await screen.findByRole("group", { name: "Saved file-access comparison summary" })).toHaveTextContent("Recorded objective not established");
  await user.click(screen.getByRole("button", { name: "Assistant settings" }));
  await user.selectOptions(screen.getByLabelText("AI mode"), "assist");
  await user.selectOptions(screen.getByLabelText("Provider"), provider.provider_id);
  expect(screen.getByText("Explanation only. No experiment or control is rerun or changed.")).toBeVisible();
  await user.type(screen.getByLabelText("What would you like to do?"), body().message);
  await user.click(screen.getByRole("button", { name: "Start work" }));
  await waitFor(() => expect(submit).toHaveBeenCalledTimes(1));
  const sent = submit.mock.calls[0]![0];
  expect(sent).toMatchObject({ selection: selected, context_digest: context().context_digest, provider_id: provider.provider_id, autonomy: "assist", message: body().message });
  expect(Object.keys(sent).sort()).toEqual(["submission_id", "selection", "context_digest", "provider_id", "autonomy", "message"].sort());
  expect(await screen.findByRole("link", { name: "Saved baseline and retest comparison" })).toHaveAttribute("href", fileAccessRetestComparisonPath(selected));
});

it("does not reuse a previously checked preview after historical context refresh fails", async () => {
  vi.spyOn(fileAccessLinkageApi, "read").mockResolvedValue(fixture.value);
  vi.mocked(request).mockResolvedValueOnce(context()).mockRejectedValue(new Error("Historical evidence changed"));
  const submit = vi.spyOn(api, "submitAssistance");
  const view = mount();
  fireEvent.click(await screen.findByRole("button", { name: "Explain this comparison" }));
  await screen.findByRole("group", { name: "Saved file-access comparison summary" });
  await act(async () => { await view.client.invalidateQueries({ queryKey: ["assistance-context"] }); });
  expect(await screen.findByText("Context is unavailable")).toBeVisible();
  expect(screen.queryByRole("group", { name: "Saved file-access comparison summary" })).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Start work" })).toBeDisabled();
  expect(submit).not.toHaveBeenCalled();
});
