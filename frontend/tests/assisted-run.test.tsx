import { useEffect, useRef } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { api } from "../src/lib/api";
import { demoCatalog, demoScenario } from "../src/lib/demo";
import type { GraphEnvelope } from "../src/lib/graph-assistance";
import { checkedAssistanceRun, readRunDecision, type AssistanceRunEnvelope, type SavedGraphSelection } from "../src/lib/run-assistance";
import { AssistedRunReview, SavedGraphRunSetup } from "../src/pages/AssistedRun";
import { AssistanceProvider, useAssistanceSelection } from "../src/state/AssistanceContext";
import { ProductProvider, useProduct } from "../src/state/ProductContext";

const graphJob = `job-${"a".repeat(32)}`, preparationJob = `job-${"b".repeat(32)}`;
const digest = `sha256:${"c".repeat(64)}`;
const document = { ...demoScenario, id: "scenario.reviewed.v1", title: "Reviewed experiment" };
const application = { proposal_job_id: graphJob, proposal_digest: digest, reviewed_digest: digest, operator_modified: true, scenario_id: document.id, version: 2, digest };
const selection: SavedGraphSelection = { kind: "saved_graph", proposal_job_id: graphJob, application,
  run_intent: { mode: "simulate", autonomy: "off", ai_provider_id: null, runner_profile_id: "sandbox-simulate.v1", target_scope: { scope_refs: ["sandbox.workspace"] } } };
function graph(): GraphEnvelope {
  return { job: { schema_version: "bluefire.job.v1", job_id: graphJob, kind: "graph.ai.propose", state: "completed", progress: {} }, application, review_ready: false,
    proposal: { schema_version: "bluefire.graph-ai-proposal.v1", proposal_job_id: graphJob, proposal_digest: digest, context_digest: digest, catalog_digest: digest, base_scenario: null,
      scenario: document, validation: { valid: true }, rationale: "Bounded local test", assumptions: [], limitations: [], provider: { effective_provider_id: "test-model", model: "test-model", used_fallback: false, attempts: 1 } } };
}
function ready(): AssistanceRunEnvelope {
  const preparation = { schema_version: "bluefire.assistance-run-preparation.v1" as const, preparation_digest: digest, context_digest: digest, selection,
    scenario: document, run_request: { scenario: document, ...selection.run_intent }, preflight: { ready: true, status: "ready", plan: { steps: [], edges: [], mode: "simulate" } }, approval_created: false as const, effects_started: false as const };
  return { job: { schema_version: "bluefire.job.v1", job_id: preparationJob, kind: "run.assistance.prepare", state: "completed", request: {}, progress: { preparation } }, preparation,
    decision: null, run_job: null, inspection_job: null, inspection: null, result: null, review_ready: true };
}
function Witness() {
  const selected = useAssistanceSelection();
  const { scenario, runConfig, assistantPreferences, setAssistantPreferences, setNewRunDefaults } = useProduct();
  return <><button onClick={() => setAssistantPreferences({ autonomy: "auto", provider: "different-provider", model: "different-model" })}>Change Assistant mode in test</button><button onClick={() => setNewRunDefaults({ mode: "execute", autonomy: "assist" })}>Change new run defaults</button><output aria-label="Assistant preferences">{JSON.stringify(assistantPreferences)}</output><output aria-label="Published selection">{JSON.stringify(selected)}</output><output aria-label="Active draft">{JSON.stringify(scenario)}</output><output aria-label="Global run settings">{JSON.stringify(runConfig)}</output></>;
}
function OverrideSeed() {
  const { runConfig, setRunConfig } = useProduct();
  const seeded = useRef(false);
  useEffect(() => { if (!seeded.current) { seeded.current = true; setRunConfig({ ...runConfig, mode: "execute", profileId: "sandbox-execute.v1", actionImplementations: { [demoScenario.steps[0]!.id]: "unrelated-method.v1" } }); } }, [runConfig, setRunConfig]);
  return null;
}
function mount(review = false, seedOverrides = false) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  const view = render(<QueryClientProvider client={client}><ProductProvider><AssistanceProvider><MemoryRouter>{seedOverrides ? <OverrideSeed /> : null}<Witness />{review ? <AssistedRunReview jobId={preparationJob} /> : <SavedGraphRunSetup jobId={graphJob} />}</MemoryRouter></AssistanceProvider></ProductProvider></QueryClientProvider>);
  return { ...view, user: userEvent.setup() };
}
function stubGraph() {
  vi.spyOn(api, "runnerStatus").mockResolvedValue({ schema_version: "bluefire.runner-lifecycle-status.v1", state: "stopped", runner_id: "runner", profile_id: "sandbox-execute.v1", loopback_only: true, enrollment: "active", process: "absent", runner: null, health: null });
  vi.spyOn(api, "catalog").mockResolvedValue(demoCatalog);
  vi.spyOn(api, "graphProposal").mockResolvedValue(graph());
  vi.spyOn(api, "immutableScenarioVersion").mockResolvedValue({ schema_version: "bluefire.scenario-version.v1", scenario: { scenario_id: document.id, title: document.title, version: 2, digest, document, created_at: "2030-01-01" } });
}

it.each(["completed", "awaiting_approval"] as const)("keeps original approval findings historical after accepting a preparation (%s)", async (state) => {
  const value = ready();
  value.preparation!.preflight.findings = ["Explicit operator approval is required."];
  value.decision = { decision: "accept", preparation_digest: digest };
  value.review_ready = false;
  value.run_job = { schema_version: "bluefire.job.v1", job_id: `job-${"e".repeat(32)}`, kind: "scenario.run", state, progress: {}, request: {
    _run_submission_request: value.preparation!.run_request, assistance_run: { operation_job_id: preparationJob, preparation_digest: digest } } };
  vi.spyOn(api, "assistanceRun").mockResolvedValue(value);
  const view = mount(true);
  const summary = await screen.findByText("Reviewed preparation");
  const finding = screen.getByText("Explicit operator approval is required.");
  expect(finding.closest("details")).toBe(summary.closest("details"));
  expect(finding).not.toBeVisible();
  if (state === "awaiting_approval") expect(screen.getByRole("link", { name: "Review Execute approval" })).toBeVisible();
  else expect(screen.queryByRole("link", { name: "Review Execute approval" })).not.toBeInTheDocument();
  await view.user.click(summary);
  expect(finding).toBeVisible();
  expect(screen.getByRole("heading", { name: "Findings when this plan was prepared" })).toBeVisible();
});

it("starts the saved experiment runner without changing its selection or active draft", async () => {
  stubGraph();
  localStorage.setItem("bluefire.local.scenario.v1", JSON.stringify(demoScenario));
  const start = vi.spyOn(api, "startRunner").mockImplementation(async () => {
    const status = { schema_version: "bluefire.runner-lifecycle-status.v1", state: "ready", runner_id: "runner", profile_id: "sandbox-execute.v1", loopback_only: true as const, enrollment: "active", process: "authenticated", runner: null, health: { accepting_execute: true } };
    vi.mocked(api.runnerStatus).mockResolvedValue(status); return status;
  });
  const view = mount(false, true);
  await screen.findByRole("button", { name: "Start runner" });
  const before = screen.getByLabelText("Published selection").textContent;
  const draft = screen.getByLabelText("Active draft").textContent;
  const preferences = screen.getByLabelText("Global run settings").textContent;
  await view.user.click(screen.getByRole("button", { name: "Start runner" }));
  expect(await screen.findByText("Ready for preflight")).toBeVisible();
  expect(start).toHaveBeenCalledExactlyOnceWith("sandbox-execute.v1");
  expect(screen.getByLabelText("Published selection").textContent).toBe(before);
  expect(screen.getByLabelText("Active draft").textContent).toBe(draft);
  expect(screen.getByLabelText("Global run settings").textContent).toBe(preferences);
});

it("retains separate settings across remount without replacing the active graph or runtime preferences", async () => {
  stubGraph();
  localStorage.setItem("bluefire.local.scenario.v1", JSON.stringify(demoScenario));
  const first = mount();
  const scope = await screen.findByLabelText(/^Target scope/);
  const globalBefore = screen.getByLabelText("Global run settings").textContent;
  await first.user.clear(scope); await first.user.type(scope, "owned.reviewed.scope");
  expect(JSON.parse(screen.getByLabelText("Published selection").textContent!).selected.run_intent.target_scope.scope_refs).toEqual(["owned.reviewed.scope"]);
  expect(JSON.parse(screen.getByLabelText("Active draft").textContent!)).toEqual(demoScenario);
  expect(screen.getByLabelText("Global run settings").textContent).toBe(globalBefore);
  first.unmount(); mount();
  expect(await screen.findByLabelText(/^Target scope/)).toHaveValue("owned.reviewed.scope");
  expect(screen.getByText("AI during the run")).toBeVisible();
});

it("does not inherit action overrides from the active experiment", async () => {
  stubGraph();
  localStorage.setItem("bluefire.local.scenario.v1", JSON.stringify(demoScenario));
  localStorage.setItem("bluefire.local.run-config.v1", JSON.stringify({ schema_version: "bluefire.ui-preferences.v1", theme: "dark", effect_mode: "execute", autonomy: "off" }));
  mount(false, true); await screen.findByLabelText(/^Target scope/);
  const selected = JSON.parse(screen.getByLabelText("Published selection").textContent!).selected;
  expect(selected.run_intent.mode).toBe("execute");
  expect(JSON.parse(screen.getByLabelText("Global run settings").textContent!).actionImplementations).toHaveProperty(demoScenario.steps[0]!.id);
  expect(selected.run_intent.action_implementations).toBeUndefined();
});

it("refuses a saved version whose digest no longer matches its accepted application", async () => {
  stubGraph();
  vi.mocked(api.immutableScenarioVersion).mockResolvedValue({ schema_version: "bluefire.scenario-version.v1", scenario: { scenario_id: document.id, title: document.title, version: 2, digest: `sha256:${"d".repeat(64)}`, document, created_at: "2030-01-01" } });
  mount();
  expect(await screen.findByText("The experiment does not match its saved review. Check the original proposal before continuing.")).toBeVisible();
  expect(screen.queryByRole("button", { name: "Run with Assistant" })).not.toBeInTheDocument();
  expect(screen.getByLabelText("Published selection")).toHaveTextContent("");
});

it("retains an uncertain acceptance across remount and retries exactly that decision", async () => {
  vi.spyOn(api, "assistanceRun").mockResolvedValue(ready());
  const accepted = { ...ready(), decision: { decision: "accept" as const, preparation_digest: digest }, review_ready: false };
  const post = vi.spyOn(api, "reviewAssistanceRun").mockRejectedValueOnce(new Error("Response lost")).mockResolvedValueOnce(accepted);
  const first = mount(true);
  await first.user.click(await screen.findByRole("button", { name: "Accept and prepare run" }));
  await screen.findByText("Response lost");
  expect(readRunDecision(preparationJob)).toEqual({ decision: "accept", preparation_digest: digest });
  first.unmount(); const second = mount(true);
  await second.user.click(await screen.findByRole("button", { name: "Retry acceptance" }));
  await screen.findByText("Your review is saved.");
  expect(post).toHaveBeenCalledTimes(2);
  expect(post.mock.calls[0]).toEqual(post.mock.calls[1]);
  expect(screen.queryByRole("button", { name: "Decline this run" })).not.toBeInTheDocument();
});

it("sends no review when browser persistence fails", async () => {
  vi.spyOn(api, "assistanceRun").mockResolvedValue(ready());
  const post = vi.spyOn(api, "reviewAssistanceRun");
  const view = mount(true);
  await screen.findByRole("button", { name: "Accept and prepare run" });
  const original = Storage.prototype.setItem;
  vi.spyOn(Storage.prototype, "setItem").mockImplementation(function (this: Storage, key, value) { if (key.startsWith("bluefire.assistance-run-review.")) throw new Error("Full"); original.call(this, key, value); });
  await view.user.click(screen.getByRole("button", { name: "Accept and prepare run" }));
  expect(await screen.findByText(/Enable browser session storage before reviewing/)).toBeVisible();
  expect(post).not.toHaveBeenCalled();
});

it("shows interrupted preparation and recovery rather than an endless checking message", async () => {
  vi.spyOn(api, "assistanceRun").mockResolvedValue({ ...ready(), preparation: null, review_ready: false, job: { ...ready().job, state: "interrupted" } });
  mount(true);
  expect(await screen.findByText(/Preparation did not finish/)).toBeVisible();
  expect(screen.getByRole("button", { name: "Open Assistant work" })).toBeEnabled();
  expect(screen.queryByRole("button", { name: "Accept and prepare run" })).not.toBeInTheDocument();
});

it("checks the submitted payload and parent binding while allowing server approval metadata", async () => {
  const value = ready();
  value.run_job = { schema_version: "bluefire.job.v1", job_id: `job-${"e".repeat(32)}`, kind: "scenario.run", state: "awaiting_approval", progress: {}, request: {
    _run_submission_request: value.preparation!.run_request, assistance_run: { operation_job_id: preparationJob, preparation_digest: digest }, approval_request_id: "server-only" } };
  expect(checkedAssistanceRun(value, preparationJob)).toBe(value);
  value.run_job.request!.assistance_run = { operation_job_id: graphJob, preparation_digest: digest };
  expect(() => checkedAssistanceRun(value, preparationJob)).toThrow("The run does not match");
});

it("retains the untouched runtime snapshot when Assistant mode changes before remount", async () => {
  stubGraph();
  const first = mount();
  await screen.findByLabelText(/^Target scope/);
  await first.user.click(screen.getByRole("button", { name: "Change Assistant mode in test" }));
  expect(JSON.parse(screen.getByLabelText("Global run settings").textContent!).autonomy).toBe("off");
  expect(JSON.parse(screen.getByLabelText("Assistant preferences").textContent!).autonomy).toBe("auto");
  first.unmount(); mount();
  await screen.findByLabelText(/^Target scope/);
  expect(JSON.parse(screen.getByLabelText("Published selection").textContent!).selected.run_intent.autonomy).toBe("off");
  expect(JSON.parse(screen.getByLabelText("Global run settings").textContent!).autonomy).toBe("off");
  expect(JSON.parse(screen.getByLabelText("Assistant preferences").textContent!).autonomy).toBe("auto");
});

it.each([false, true])("follows an interrupted preparation through inspection and preserves runtime changes (%s)", async (runtimeModified) => {
  const initial = { ...ready(), job: { ...ready().job, state: "interrupted" as const } };
  const accepted = { ...initial, decision: { decision: "accept" as const, preparation_digest: digest }, review_ready: false,
    run_job: { schema_version: "bluefire.job.v1" as const, job_id: `job-${"e".repeat(32)}`, kind: "scenario.run", state: "queued" as const, progress: {}, request: {
      _run_submission_request: initial.preparation!.run_request, assistance_run: { operation_job_id: preparationJob, preparation_digest: digest } } } };
  const completed: AssistanceRunEnvelope = { ...accepted,
    run_job: { ...accepted.run_job, state: "completed", result_ref: "run-reviewed" },
    inspection_job: { schema_version: "bluefire.job.v1", job_id: `job-${"f".repeat(32)}`, kind: "run.evidence.inspect", state: "completed", progress: {}, request: { run_id: "run-reviewed", run_digest: digest, assistance_run: { operation_job_id: preparationJob, preparation_digest: digest } } },
    inspection: { schema_version: "bluefire.run-evidence-inspection.v1", run_id: "run-reviewed", run_digest: digest, summary: "Simulation completed without independent observations.", findings: [], limitations: ["Synthetic only"], observed_records: 0, total_records: 7, status: "insufficient", provider: null, model_interpretation: false },
    result: { kind: "run_inspected", run_id: "run-reviewed", run_job_id: accepted.run_job.job_id, inspection_job_id: `job-${"f".repeat(32)}`, scenario_id: document.id, version: 2, digest, mode: "simulate", objective_reached: null, cleanup_state: "complete", observed_records: 0, total_records: 7, inspection_status: "insufficient", native_path: "/runs/run-reviewed", runtime_modified: runtimeModified, runtime_proposal_record_ids: runtimeModified ? ["proposal-reviewed"] : [], actual_scenario_digest: runtimeModified ? `sha256:${"d".repeat(64)}` : digest } };
  expect(() => checkedAssistanceRun({ ...completed, inspection: { ...completed.inspection!, run_id: "unrelated-run" } }, preparationJob)).toThrow("does not match its saved inspection");
  const get = vi.spyOn(api, "assistanceRun").mockResolvedValueOnce(initial).mockResolvedValue(completed);
  vi.spyOn(api, "reviewAssistanceRun").mockResolvedValue(accepted);
  const view = mount(true);
  await view.user.click(await screen.findByRole("button", { name: "Accept and prepare run" }));
  expect(await screen.findByText("Simulation completed without independent observations.", {}, { timeout: 4000 })).toBeVisible();
  expect(get.mock.calls.length).toBeGreaterThanOrEqual(2);
  expect(screen.getByRole("heading", { name: "Not enough evidence" })).toBeVisible();
  if (runtimeModified) {
    expect(screen.getByText("Reviewed runtime changes applied")).toBeVisible();
    expect(screen.getByText("Original preparation before reviewed runtime changes").closest("details")).not.toHaveAttribute("open");
    expect(screen.getByRole("link", { name: "Review run evidence and export" })).toHaveAttribute("href", "/runs/run-reviewed");
  } else {
    expect(screen.queryByText("Reviewed runtime changes applied")).not.toBeInTheDocument();
    expect(screen.getByText("Reviewed preparation").closest("details")).not.toHaveAttribute("open");
  }
});

it("keeps Off independent of an unavailable default provider and requires an explicit runtime choice", async () => {
  stubGraph();
  vi.mocked(api.catalog).mockResolvedValue({ ...demoCatalog, ai: { ...demoCatalog.ai, providers: [{ provider_id: "configured-test.v1", kind: "chat_completions", model: "configured-test", health: { state: "ready" } }] } });
  const view = mount();
  await screen.findByLabelText(/^Target scope/);
  expect(JSON.parse(screen.getByLabelText("Published selection").textContent!).selected.run_intent.ai_provider_id).toBeNull();
  await view.user.click(screen.getByText("AI provider & environment details"));
  const provider = screen.getByLabelText(/^Runtime provider/);
  expect(provider).toHaveValue("");
  expect(screen.getByText("No configured provider selected")).toBeVisible();
  await view.user.click(screen.getByRole("radio", { name: /Assist\s*Review proposal/ }));
  await view.user.selectOptions(provider, "configured-test.v1");
  expect(JSON.parse(screen.getByLabelText("Published selection").textContent!).selected.run_intent.ai_provider_id).toBe("configured-test.v1");
});

it.each([false, true])("explains a preparation failure and retains preflight findings when available (%s)", async (hasReport) => {
  const value = ready();
  vi.spyOn(api, "assistanceRun").mockResolvedValue({ ...value, preparation: null, review_ready: false,
    job: { ...value.job, state: "failed", request: { submitted_request: { selection } },
      progress: hasReport ? { preflight_refusal: { code: "run_preflight_refused", message: "Review the selected runner and run settings.", preflight: { ready: false, status: "refused", findings: ["Runner inventory is unavailable."] } } } : {},
      error: { code: "assistance_run_refused", message: "The selected runner is unavailable. Check the lab and review its run settings." } } });
  const post = vi.spyOn(api, "reviewAssistanceRun");
  mount(true);
  expect(await screen.findByRole("heading", { name: "Experiment could not be prepared" })).toBeVisible();
  if (hasReport) {
    expect(screen.getByText("Review the selected runner and run settings.")).toBeVisible();
    expect(screen.getByText("Runner inventory is unavailable.")).toBeVisible();
  } else {
    expect(screen.getByText("The selected runner is unavailable. Check the lab and review its run settings.")).toBeVisible();
  }
  expect(screen.getByRole("link", { name: "Review run settings" })).toHaveAttribute("href", `/runs?graph_job=${graphJob}`);
  expect(screen.queryByRole("button", { name: "Accept and prepare run" })).not.toBeInTheDocument();
  expect(post).not.toHaveBeenCalled();
});

it("labels runtime proposal review separately from Execute authorization", async () => {
  const value = ready();
  value.decision = { decision: "accept", preparation_digest: digest };
  value.review_ready = false;
  value.run_job = { schema_version: "bluefire.job.v1", job_id: `job-${"e".repeat(32)}`, kind: "scenario.run", state: "awaiting_approval", progress: { approval_kind: "ai_proposal" }, request: {
    _run_submission_request: value.preparation!.run_request, assistance_run: { operation_job_id: preparationJob, preparation_digest: digest } } };
  vi.spyOn(api, "assistanceRun").mockResolvedValue(value);
  mount(true);
  expect(await screen.findByRole("link", { name: "Review runtime proposal" })).toHaveAttribute("href", `/runs?job=${value.run_job.job_id}`);
  expect(screen.queryByRole("link", { name: "Review Execute approval" })).not.toBeInTheDocument();
});

it("keeps a prepared request and its review digest frozen after Assistant and future-default changes", async () => {
  const prepared = ready();
  const snapshot = structuredClone(prepared);
  vi.spyOn(api, "assistanceRun").mockResolvedValue(prepared);
  const accepted = { ...prepared, decision: { decision: "accept" as const, preparation_digest: digest }, review_ready: false };
  const review = vi.spyOn(api, "reviewAssistanceRun").mockResolvedValue(accepted);
  const { user } = mount(true);
  await screen.findByRole("button", { name: "Accept and prepare run" });
  await user.click(screen.getByRole("button", { name: "Change Assistant mode in test" }));
  await user.click(screen.getByRole("button", { name: "Change new run defaults" }));
  expect(JSON.parse(screen.getByLabelText("Global run settings").textContent!)).toMatchObject({ mode: "simulate", autonomy: "off", approved: false });
  expect(prepared).toEqual(snapshot);
  await user.click(screen.getByRole("button", { name: "Accept and prepare run" }));
  expect(review).toHaveBeenCalledExactlyOnceWith(preparationJob, { decision: "accept", preparation_digest: digest });
  expect(prepared.preparation?.run_request).toEqual(snapshot.preparation?.run_request);
  expect(readRunDecision(preparationJob)).toEqual({ decision: "accept", preparation_digest: digest });
});
