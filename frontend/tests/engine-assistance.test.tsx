import { beforeEach, expect, it, vi } from "vitest";
import { checkedEngineExperimentAssistanceContext, engineAssistanceLabel, engineExperimentAssistanceContext, engineExperimentSelection, engineExperimentSelectionMatches, validEngineExperimentSelection } from "../src/lib/engine-assistance";
import type { EngineExperiment } from "../src/lib/engine-experiment";
import { request } from "../src/lib/api";

vi.mock("../src/lib/api", async importOriginal => ({ ...await importOriginal<typeof import("../src/lib/api")>(), request: vi.fn() }));

const attemptId = `engine-attempt-${"4".repeat(32)}`;
const checkId = `controller-check-${"5".repeat(32)}`;
const experiment = {
  experiment_id: `experiment-${"1".repeat(32)}`,
  workspace_digest: `sha256:${"2".repeat(64)}`,
  objective: { title: "Controlled tenant-record defense fixture", summary: "Fixture only." },
  projection: { attempts: [{ attempt_id: attemptId, role: "baseline" }], checks: [{ check_id: checkId, role: "retained_reproducer" }] },
} as unknown as EngineExperiment;
const runId = `run-20300101T000000Z-${"6".repeat(16)}`;
const evidenceId = `evidence-${"7".repeat(20)}`;
const contextDigest = `sha256:${"8".repeat(64)}`;
const selection = { kind: "engine_experiment", experiment_id: experiment.experiment_id, workspace_digest: experiment.workspace_digest, attempt_id: attemptId, check_id: null } as const;
const context = {
  schema_version: "bluefire.assistance-context.v1", selected: selection, analysis_only: true, capabilities: [],
  reference_summary: {
    schema_version: "bluefire.engine-experiment-assistance-summary.v1", proof_scope: "saved_engine_experiment_only",
    experiment_id: experiment.experiment_id, revision: 9, workspace_digest: experiment.workspace_digest, workflow_state: "complete",
    objective: { title: "Controlled tenant-record defense fixture", summary: "Fixture only." },
    environment: { display_name: "Generated Linux lab", platform: "linux", disposable: true, current_target: "established" },
    provider: { engine_id: "strix", engine_version: "0.1.0", model_provider: "provider.test", model_id: "test-model", data_destination: "https://model.test/v1", test_provider: true, live_model_inference_proven: false },
    attempts: [{ role: "baseline", attempt_id: attemptId, run_id: runId, state: "completed", completeness: "complete", engine_reported_evidence_count: 2, cleanup_state: "verified_absent" }],
    checks: [{ role: "retained_reproducer", check_id: checkId, run_id: runId, state: "completed", performer: "bluefire.controller", cleanup_state: "verified_absent" }],
    independent_observations: [{ evidence_id: evidenceId, run_id: runId, attempt_id: attemptId, check_id: null, assessment: "unauthorized_disclosure", record_hash: `sha256:${"9".repeat(64)}` }],
    conclusion: {
      headline: "original_mechanism_still_succeeds",
      original_mechanism: { status: "established", run_id: runId, support_refs: [evidenceId] },
      retained_reproducer: { status: "still_succeeds", run_id: runId, support_refs: [evidenceId] },
      adaptive_search: { status: "not_attempted", run_id: null, support_refs: [], limit_qualified: false },
      legitimate_use: { status: "not_attempted", run_id: null, support_refs: [] },
      telemetry_health: { status: "complete", expected_sources: ["baseline"], verified_sources: ["baseline"], missing_sources: [] },
      cleanup: { status: "verified_absent", items: [{ kind: "engine_attempt", id: attemptId, state: "verified_absent", receipt_ref: contextDigest }] },
      defense: { state: "not_reviewed", change_id: null, mechanism_ref: null, before_target_snapshot_ref: null, after_target_snapshot_ref: null, current_target_snapshot_ref: null, application_receipt_ref: null, reconciliation_receipt_ref: null, rollback_operation_ref: null, rollback_receipt_ref: null },
      unknowns: ["No fresh adaptive search was recorded."],
    },
    selected_record: { kind: "engine_attempt", id: attemptId, role: "baseline", job_id: `job-${"a".repeat(32)}`, run_id: runId, state: "completed", completeness: "complete",
      observations: [{ evidence_id: `engine-evidence-${"b".repeat(24)}`, category: "engine_assertion", provenance: "engine_reported", summary: "The engine reported a bounded result.", producer: "strix", timestamp: "2030-01-01T00:00:00Z", limitations: ["Engine reported only."] }],
      cleanup: { state: "verified_absent", receipt_ref: contextDigest, limitations: [] } },
  },
  limitations: ["Explanation only. No execution authority."], context_digest: contextDigest,
} as const;

const clone = <T,>(value: T): T => JSON.parse(JSON.stringify(value)) as T;

beforeEach(() => vi.mocked(request).mockReset());

it("captures an exact immutable experiment and selected attempt context", () => {
  const selection = engineExperimentSelection(experiment, attemptId);
  expect(selection).toEqual({ kind: "engine_experiment", experiment_id: experiment.experiment_id, workspace_digest: experiment.workspace_digest, attempt_id: attemptId, check_id: null });
  expect(validEngineExperimentSelection(selection)).toBe(true);
  expect(engineExperimentSelectionMatches(selection, experiment)).toBe(true);
});

it("refuses unknown or extra selection fields", () => {
  expect(validEngineExperimentSelection({ kind: "engine_experiment", experiment_id: experiment.experiment_id, workspace_digest: experiment.workspace_digest, attempt_id: null, check_id: null, current: true })).toBe(false);
  expect(validEngineExperimentSelection({ kind: "engine_experiment", experiment_id: "engine-experiment-wrong", workspace_digest: experiment.workspace_digest, attempt_id: null, check_id: null })).toBe(false);
  expect(validEngineExperimentSelection({ kind: "engine_experiment", experiment_id: experiment.experiment_id, result_digest: experiment.workspace_digest, attempt_id: null, check_id: null })).toBe(false);
  expect(validEngineExperimentSelection({ kind: "engine_experiment", experiment_id: experiment.experiment_id, workspace_digest: experiment.workspace_digest, attempt_id: attemptId, check_id: checkId })).toBe(false);
});

it("refuses a missing attempt instead of silently changing captured context", () => {
  expect(() => engineExperimentSelection(experiment, `engine-attempt-${"f".repeat(32)}`)).toThrow(/unavailable/i);
});

it("does not match a newer mutable experiment digest", () => {
  const selection = engineExperimentSelection(experiment, attemptId);
  const changed = { ...experiment, workspace_digest: `sha256:${"3".repeat(64)}` } as EngineExperiment;
  expect(engineExperimentSelectionMatches(selection, changed)).toBe(false);
});

it("uses the same purpose-first attempt language as the workspace", () => {
  expect(engineAssistanceLabel(engineExperimentSelection(experiment, attemptId), experiment)).toBe("Controlled tenant-record defense fixture: Baseline exploration");
});

it("captures an exact trusted-controller check separately from an engine attempt", () => {
  const selection = engineExperimentSelection(experiment, null, checkId);
  expect(selection).toEqual({ kind: "engine_experiment", experiment_id: experiment.experiment_id, workspace_digest: experiment.workspace_digest, attempt_id: null, check_id: checkId });
  expect(engineAssistanceLabel(selection, experiment)).toBe("Controlled tenant-record defense fixture: Original mechanism retest");
});

it("accepts only the exact bounded analysis-only context", () => {
  expect(checkedEngineExperimentAssistanceContext(context, selection)).toEqual(context);
});

it("posts the exact captured selection to the strict engine endpoint", async () => {
  vi.mocked(request).mockResolvedValue(context);
  await expect(engineExperimentAssistanceContext(selection)).resolves.toEqual(context);
  expect(request).toHaveBeenCalledWith(`/engine-experiments/${experiment.experiment_id}/assistant-context`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(selection),
  });
});

it.each([
  ["stale workspace", (value: any) => { value.reference_summary.workspace_digest = `sha256:${"f".repeat(64)}`; }],
  ["other attempt", (value: any) => { value.reference_summary.selected_record.id = `engine-attempt-${"e".repeat(32)}`; }],
  ["dispatch capability", (value: any) => { value.capabilities = [{ id: "graph.propose_and_validate" }]; }],
  ["unknown top-level field", (value: any) => { value.raw_output = "never"; }],
  ["unknown nested field", (value: any) => { value.reference_summary.provider.api_key = "never"; }],
  ["unproven live model", (value: any) => { value.reference_summary.provider.live_model_inference_proven = true; }],
  ["local path", (value: any) => { value.reference_summary.objective.summary = "Inspect /private/operator/output.json"; }],
  ["secret", (value: any) => { value.reference_summary.selected_record.observations[0].summary = "token=secret-value"; }],
])("rejects %s rather than sending it to the Assistant", (_name, mutate) => {
  const changed: any = clone(context); mutate(changed);
  expect(() => checkedEngineExperimentAssistanceContext(changed, selection)).toThrow(/changed or is unavailable/i);
});
