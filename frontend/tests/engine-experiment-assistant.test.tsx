import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, expect, it, vi } from "vitest";
import { ExperimentAssistant } from "../src/components/ExperimentAssistant";
import { api, request } from "../src/lib/api";
import { assistanceJobId, readAssistanceReceipt, type AssistanceEnvelope, type AssistanceRequest } from "../src/lib/assistance";
import { checkedEngineExperimentAssistanceContext, type EngineExperimentAssistanceSelection } from "../src/lib/engine-assistance";
import { AssistanceProvider, usePublishEngineExperimentSelection } from "../src/state/AssistanceContext";
import { ProductProvider } from "../src/state/ProductContext";

vi.mock("../src/lib/api", async importOriginal => ({ ...await importOriginal<typeof import("../src/lib/api")>(), DEMO_MODE: false, request: vi.fn() }));

const experimentId = `experiment-${"a".repeat(32)}`;
const attemptId = `engine-attempt-${"b".repeat(32)}`;
const runId = `run-20300101T000000Z-${"d".repeat(16)}`;
const digest = `sha256:${"c".repeat(64)}`;
const selection: EngineExperimentAssistanceSelection = { kind: "engine_experiment", experiment_id: experimentId, workspace_digest: digest, attempt_id: attemptId, check_id: null };
const context = {
  schema_version: "bluefire.assistance-context.v1", selected: selection, analysis_only: true, capabilities: [], context_digest: digest,
  reference_summary: {
    schema_version: "bluefire.engine-experiment-assistance-summary.v1", proof_scope: "saved_engine_experiment_only", experiment_id: experimentId, revision: 7, workspace_digest: digest, workflow_state: "complete",
    objective: { title: "Bounded tenant-record defense", summary: "Determine whether the saved defense changed the bounded mechanism." },
    environment: { display_name: "Generated Linux lab", platform: "linux", disposable: true, current_target: "established" },
    provider: { engine_id: "strix", engine_version: "0.1.0", model_provider: "provider.test", model_id: "fixture-model", data_destination: "https://model.test/v1", test_provider: true, live_model_inference_proven: false },
    attempts: [{ role: "baseline", attempt_id: attemptId, run_id: runId, state: "completed", completeness: "complete", engine_reported_evidence_count: 1, cleanup_state: "verified_absent" }],
    checks: [], independent_observations: [{ evidence_id: `evidence-${"e".repeat(20)}`, run_id: runId, attempt_id: attemptId, check_id: null, assessment: "unauthorized_disclosure", record_hash: `sha256:${"f".repeat(64)}` }],
    conclusion: {
      headline: "inconclusive_retest", original_mechanism: { status: "established", run_id: runId, support_refs: [`evidence-${"e".repeat(20)}`] },
      retained_reproducer: { status: "not_attempted", run_id: null, support_refs: [] }, adaptive_search: { status: "not_attempted", run_id: null, support_refs: [], limit_qualified: false },
      legitimate_use: { status: "not_attempted", run_id: null, support_refs: [] }, telemetry_health: { status: "complete", expected_sources: ["baseline"], verified_sources: ["baseline"], missing_sources: [] },
      cleanup: { status: "verified_absent", items: [] }, defense: { state: "not_reviewed", change_id: null, mechanism_ref: null, before_target_snapshot_ref: null, after_target_snapshot_ref: null, current_target_snapshot_ref: null, application_receipt_ref: null, reconciliation_receipt_ref: null, rollback_operation_ref: null, rollback_receipt_ref: null }, unknowns: ["A fresh retest is not recorded."],
    },
    selected_record: { kind: "engine_attempt", id: attemptId, role: "baseline", job_id: `job-${"1".repeat(32)}`, run_id: runId, state: "completed", completeness: "complete", observations: [{ evidence_id: `engine-evidence-${"2".repeat(24)}`, category: "engine_assertion", provenance: "engine_reported", summary: "Bounded engine assertion.", producer: "strix", timestamp: "2030-01-01T00:00:00Z", limitations: ["Engine reported only."] }], cleanup: { state: "verified_absent", receipt_ref: digest, limitations: [] } },
  },
  limitations: ["Explanation only. No execution authority."],
} as const;
const provider = { provider_id: "assistant-provider", kind: "openai_chat_completions", model: "assistant-model", health: { state: "ready", credential_available: true } } as const;

function Selection() { usePublishEngineExperimentSelection(selection, "Bounded tenant-record defense"); return null; }

function envelope(body: AssistanceRequest): AssistanceEnvelope {
  return { job: { schema_version: "bluefire.job.v1", kind: "assistance.turn", job_id: assistanceJobId(body.submission_id), state: "completed", request: { submitted_request: body }, progress: {} },
    turn: { schema_version: "bluefire.assistance-turn.v1", status: "completed", can_start_new_turn: true, message: "The saved engine assertion and independent observation have distinct provenance. A fresh retest remains unknown.", context_digest: body.context_digest,
      selected: "selection" in body ? body.selection : { run_id: body.run_id, candidate_id: body.candidate_id, candidate_resource_digest: body.candidate_resource_digest },
      plan: [], active_child: null, next_action: { kind: "new_turn", label: "Ask another question", native_path: null }, results: [], continuation: null, recovery: null, limitations: ["Explanation only. No effects were executed."] } };
}

beforeEach(() => {
  localStorage.clear(); sessionStorage.clear(); sessionStorage.setItem("bluefire.assistance.open.v1", "true");
  vi.mocked(request).mockReset(); vi.restoreAllMocks(); vi.mocked(request).mockResolvedValue(context);
});

it("uses the strict engine context for an explanation-only durable request and survives navigation", async () => {
  expect(() => checkedEngineExperimentAssistanceContext(context, selection)).not.toThrow();
  const genericContext = vi.spyOn(api, "assistanceContext");
  const submit = vi.spyOn(api, "submitAssistance").mockImplementation(async body => envelope(body));
  vi.spyOn(api, "assistanceTurn").mockImplementation(async () => envelope(readAssistanceReceipt()!));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false }, mutations: { retry: false } } });
  const tree = (show: boolean) => <QueryClientProvider client={client}><MemoryRouter><ProductProvider><AssistanceProvider>{show ? <Selection /> : null}<ExperimentAssistant providers={[provider]} /></AssistanceProvider></ProductProvider></MemoryRouter></QueryClientProvider>;
  const view = render(tree(true));

  expect(await screen.findByText("Bounded tenant-record defense")).toBeVisible();
  expect(await screen.findByText(/Labeled test provider · application mechanics only/)).toBeVisible();
  expect(screen.getByRole("group", { name: "Saved defense experiment summary" })).toHaveTextContent("Selected attempt: Baseline exploration · Completed");
  const user = userEvent.setup();
  await user.click(screen.getByText("Saved experiment evidence and source model"));
  expect(screen.getByText(/source model: provider.test \/ fixture-model/i)).toBeVisible();
  expect(screen.getByText(/Source data destination: https:\/\/model.test\/v1/)).toBeVisible();
  expect(screen.getByText(/No artifacts, raw output, local paths, credentials, target access, or execution authority/)).toBeVisible();
  expect(request).toHaveBeenCalledWith(`/engine-experiments/${experimentId}/assistant-context`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(selection) });
  expect(genericContext).not.toHaveBeenCalled();
  expect(screen.getByRole("button", { name: /Explain the outcome/ })).toBeVisible();
  expect(screen.getByRole("textbox", { name: "What would you like to do?" })).toBeVisible();
  expect(screen.queryByLabelText("Development activity")).not.toBeInTheDocument();

  await user.click(screen.getByRole("button", { name: /Separate claims and evidence/ }));
  await user.click(screen.getByRole("button", { name: "Assistant settings" }));
  expect(screen.getByRole("option", { name: "Assist · explanation only" })).toBeInTheDocument();
  expect(screen.getByRole("option", { name: "Auto · explanation only" })).toBeInTheDocument();
  expect(screen.getByText("No model work is delegated.")).toBeVisible();
  await user.selectOptions(screen.getByLabelText("AI mode"), "assist");
  expect(screen.getByText(/No engine execution, plan or defense mutation, artifact access, target authority, or lifecycle control/)).toBeVisible();
  await user.selectOptions(screen.getByLabelText("Provider"), provider.provider_id);
  await user.click(screen.getByRole("button", { name: "Assistant settings" }));

  view.rerender(tree(false));
  expect(await screen.findByRole("link", { name: "Reopen source" })).toHaveAttribute("href", `/composition?engine_experiment=${experimentId}&attempt=${attemptId}`);
  expect(screen.getByRole("textbox", { name: "What would you like to do?" })).toHaveValue("Separate engine-reported assertions from independent observations and explain the important evidence limits.");
  expect(submit).not.toHaveBeenCalled();
  view.rerender(tree(true));

  await user.click(screen.getByRole("button", { name: "Start work" }));
  await screen.findByRole("heading", { name: "Work completed" });
  expect(submit).toHaveBeenCalledTimes(1);
  const body = submit.mock.calls[0]![0];
  expect(body).toEqual({ submission_id: expect.any(String), context_digest: digest, selection, message: "Separate engine-reported assertions from independent observations and explain the important evidence limits.", autonomy: "assist", provider_id: provider.provider_id });
  expect(JSON.stringify(body)).not.toMatch(/raw_output|artifact|credential|authorization|private|\\\\/i);
  expect(screen.getByText(/distinct provenance/)).toBeVisible();
  expect(screen.getByRole("region", { name: "Captured request context" })).toHaveTextContent("Saved defense experiment");
  expect(genericContext).not.toHaveBeenCalled();
  await waitFor(() => expect(readAssistanceReceipt()).toEqual(body));
});

it("withholds the composer when the strict context is stale or tampered", async () => {
  vi.mocked(request).mockResolvedValue({ ...context, selected: { ...selection, workspace_digest: `sha256:${"0".repeat(64)}` } });
  const submit = vi.spyOn(api, "submitAssistance");
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter><ProductProvider><AssistanceProvider><Selection /><ExperimentAssistant providers={[provider]} /></AssistanceProvider></ProductProvider></MemoryRouter></QueryClientProvider>);
  expect(await screen.findByText(/context changed or is unavailable/i)).toBeVisible();
  expect(screen.getByRole("button", { name: "Start work" })).toBeDisabled();
  expect(submit).not.toHaveBeenCalled();
});
