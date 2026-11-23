import { request } from "./api";
import type { AssistanceContext } from "./assistance";
import { sameJson } from "./replay-review";

export interface ComparisonAssistanceSelection {
  kind: "comparison_snapshot";
  snapshot_id: string;
  snapshot_digest: string;
}

type StopStatus = "success" | "failed" | "blocked" | "control_blocked" | "refused" | "skipped" | "not_run" | "unknown" | "unreported";
type ObservationCounts = { evidence_records: null | { synthetic: number; executed: number; observed: number; control_blocked: number; counterfactual: number; unknown: number; other: number }; observed_artifacts: number | null; evidence_gaps: number | null };
type S3ReadState = "read" | "service_denied" | "unreported" | "not_selected" | "not_recorded";
type S3ReadCell = { state: S3ReadState; provenance: "synthetic" | "runner_reported" | null; cleanup: "verified" | "unknown" | null };
type S3SavedResults = {
  state: "saved_s3_read_results";
  comparison_state: "paired" | "baseline_only" | "retest_only" | "partial";
  change_state: "changed" | "unchanged" | "unknown";
  rows: Array<{ reader: "probe" | "legitimate"; purpose: "primary" | "health"; baseline: S3ReadCell; retest: S3ReadCell; changed: boolean | null }>;
  gaps: Array<"baseline_missing" | "retest_missing" | "baseline_selection_incomplete" | "retest_selection_incomplete" | "baseline_observations_incomplete" | "retest_observations_incomplete" | "cleanup_unresolved">;
  proof_scope: "saved_read_results_only";
  effective_access_claim: false;
  defensive_effectiveness_claim: false;
};

export interface ComparisonAssistanceSummary {
  schema_version: "bluefire.comparison-assistance-summary.v1";
  saved_comparison: {
    run_count: number;
    baseline_position: 1;
    runs: Array<{
      position: number;
      mode: "simulate" | "execute" | null;
      objective_reached: boolean | null;
      recorded_attempts: number | null;
      repeated_step_ids: boolean | null;
      first_stop: { recorded: false } | { recorded: true; status: StopStatus | null; policy_status: StopStatus | null };
      observations: ObservationCounts;
      detection: { total_matches: number | null; observed_matches: number | null; fixture_matches: number | null; benign_matches: number | null };
      cleanup: { source: "run_result" | "step_heuristic" | "not_recorded"; authoritative: boolean; state: "success" | "failed" | "unknown" | "not_attempted" | "verified_success" | "failed_or_incomplete" | "contradictory"; success: boolean | null };
    }>;
    changes: Array<{
      compared_position: number;
      objective_relation: "same_recorded_result" | "different_recorded_results" | "different_objectives" | "unverified_objective_proof" | "mixed_or_unreported_modes" | "unreported";
      material_changed: boolean | null;
      material_changes: Array<"configuration" | "path" | "outcomes" | "first_prevention" | "objective" | "controls" | "telemetry" | "ai_proposals" | "counterfactual" | "planner" | "implementation" | "evidence" | "detection" | "cleanup" | "budgets"> | null;
      first_divergence_position: number | null;
      divergence_kind: "method" | "path" | "unreported" | "none";
      observations: { added: number | null; removed: number | null; changed: number | null };
    }>;
    legitimate_use: { state: "not_recorded" } | { state: "unavailable"; reason: "mixed_selection" | "unsupported_operation" | "ambiguous_phase" | "incompatible_context" | "saved_context_unavailable" | "saved_binding_invalid" } | S3SavedResults;
  };
  source_integrity: { status: "verified" | "unavailable"; runs: Array<{ position: number; status: "verified" | "missing" | "changed" | "invalid" }> };
}

export interface ComparisonAssistanceContext extends AssistanceContext {
  selected: ComparisonAssistanceSelection;
  analysis_only: true;
  capabilities: [];
  reference_summary: ComparisonAssistanceSummary;
}

export const comparisonAssistanceLimitations = [
  "This explains one immutable saved comparison; it does not rerun, recompute, approve or change any experiment or control.",
  "Recorded objectives belong to their own run and mode; equal results do not establish the same objective, causation, prevention or defensive effectiveness.",
  "Evidence record counts, observed artifact counts and detector matches are distinct populations; missing values remain unreported. Observed, fixture and benign match populations may overlap and are not a coverage denominator.",
  "Repeated step identities do not contain individual attempt outcomes in this snapshot; final per-step outcomes cannot be assigned to each attempt.",
  "Legitimate use is unreported unless explicit saved read-result rows record it. S3 runner reports and synthetic evidence keep their provenance and do not prove effective access or defensive effectiveness.",
  "Current source integrity is reported separately from immutable historical comparison facts; unavailable source bundles are not substituted or recomputed.",
] as const;

const object = (value: unknown): value is Record<string, unknown> => Boolean(value) && typeof value === "object" && !Array.isArray(value);
const exact = (value: unknown, keys: string[]): value is Record<string, unknown> => object(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const digest = (value: unknown): value is string => typeof value === "string" && /^sha256:[0-9a-f]{64}$/.test(value);
const count = (value: unknown): value is number => Number.isSafeInteger(value) && Number(value) >= 0 && Number(value) <= 2_147_483_647;
const nullable = <T>(value: unknown, isValue: (input: unknown) => input is T): value is T | null => value === null || isValue(value);
const oneOf = <T extends string>(value: unknown, choices: readonly T[]): value is T => typeof value === "string" && choices.includes(value as T);
const stopStatuses: StopStatus[] = ["success", "failed", "blocked", "control_blocked", "refused", "skipped", "not_run", "unknown", "unreported"];
const materialChanges = ["configuration", "path", "outcomes", "first_prevention", "objective", "controls", "telemetry", "ai_proposals", "counterfactual", "planner", "implementation", "evidence", "detection", "cleanup", "budgets"] as const;
const s3Gaps = ["baseline_missing", "retest_missing", "baseline_selection_incomplete", "retest_selection_incomplete", "baseline_observations_incomplete", "retest_observations_incomplete", "cleanup_unresolved"] as const;

export function validComparisonAssistanceSelection(value: unknown): value is ComparisonAssistanceSelection {
  if (!exact(value, ["kind", "snapshot_id", "snapshot_digest"]) || value.kind !== "comparison_snapshot"
    || typeof value.snapshot_id !== "string" || !/^run-comparison-[0-9a-f]{64}$/.test(value.snapshot_id) || !digest(value.snapshot_digest)) return false;
  return value.snapshot_digest === `sha256:${value.snapshot_id.slice("run-comparison-".length)}`;
}

function validObservationCounts(value: unknown): value is ObservationCounts {
  if (!exact(value, ["evidence_records", "observed_artifacts", "evidence_gaps"]) || !nullable(value.observed_artifacts, count) || !nullable(value.evidence_gaps, count)) return false;
  return value.evidence_records === null || exact(value.evidence_records, ["synthetic", "executed", "observed", "control_blocked", "counterfactual", "unknown", "other"])
    && Object.values(value.evidence_records).every(count);
}

function validCell(value: unknown): value is S3ReadCell {
  if (!exact(value, ["state", "provenance", "cleanup"])
    || !oneOf(value.state, ["read", "service_denied", "unreported", "not_selected", "not_recorded"])
    || !nullable(value.provenance, (item): item is "synthetic" | "runner_reported" => oneOf(item, ["synthetic", "runner_reported"]))
    || !nullable(value.cleanup, (item): item is "verified" | "unknown" => oneOf(item, ["verified", "unknown"]))) return false;
  const noResult = value.state === "not_selected" || value.state === "not_recorded";
  return noResult ? value.provenance === null && value.cleanup === null : value.provenance !== null && value.cleanup !== null;
}

function validS3SavedResults(value: unknown): value is S3SavedResults {
  if (!exact(value, ["state", "comparison_state", "change_state", "rows", "gaps", "proof_scope", "effective_access_claim", "defensive_effectiveness_claim"])) return false;
  if (value.state !== "saved_s3_read_results" || !oneOf(value.comparison_state, ["paired", "baseline_only", "retest_only", "partial"])
    || !oneOf(value.change_state, ["changed", "unchanged", "unknown"]) || value.proof_scope !== "saved_read_results_only"
    || value.effective_access_claim !== false || value.defensive_effectiveness_claim !== false || !Array.isArray(value.rows) || value.rows.length !== 3
    || !Array.isArray(value.gaps)) return false;
  const gaps: unknown[] = value.gaps;
  if (!gaps.every(item => oneOf(item, s3Gaps)) || new Set(gaps).size !== gaps.length
    || gaps.some((item, index) => index > 0 && s3Gaps.indexOf(item as typeof s3Gaps[number]) < s3Gaps.indexOf(gaps[index - 1] as typeof s3Gaps[number]))) return false;
  const identities = [["probe", "primary"], ["legitimate", "primary"], ["legitimate", "health"]] as const;
  if (!value.rows.every((row, index) => {
    const identity = identities[index];
    if (!identity) return false;
    return exact(row, ["reader", "purpose", "baseline", "retest", "changed"])
      && row.reader === identity[0] && row.purpose === identity[1] && validCell(row.baseline) && validCell(row.retest)
      && nullable(row.changed, (item): item is boolean => typeof item === "boolean");
  })) return false;
  const rows = value.rows as S3SavedResults["rows"];
  const actualProvenance = new Set(rows.flatMap(row => [row.baseline, row.retest]
    .flatMap(cell => cell.provenance === null ? [] : [cell.provenance])));
  if (actualProvenance.size > 1) return false;

  const expectedGaps: S3SavedResults["gaps"] = [];
  const selectionIncomplete: Array<"baseline" | "retest"> = [];
  const observationsIncomplete: Array<"baseline" | "retest"> = [];
  const phaseMissing: Record<"baseline" | "retest", boolean> = { baseline: false, retest: false };
  let cleanupUnresolved = false;
  for (const phase of ["baseline", "retest"] as const) {
    const cells = rows.map(row => row[phase]);
    const primary = cells[0]!;
    const legitimate = cells[1]!;
    const health = cells[2]!;
    const missing = cells.every(cell => cell.state === "not_recorded");
    phaseMissing[phase] = missing;
    if (missing) {
      expectedGaps.push(`${phase}_missing`);
      continue;
    }
    if (legitimate.state === "not_recorded" || legitimate.state === "not_selected") {
      if (health.state !== legitimate.state) return false;
    } else if (health.provenance !== legitimate.provenance || health.cleanup !== legitimate.cleanup
      || ((health.state === "unreported") !== (legitimate.state === "unreported"))) return false;

    const selected = [primary, legitimate].filter(cell => cell.state !== "not_recorded" && cell.state !== "not_selected");
    if (!selected.length) return false;
    const selectionComplete = selected.length === 2;
    const observationsComplete = selectionComplete && cells.every(cell => cell.state === "read" || cell.state === "service_denied");
    if (!selectionComplete) selectionIncomplete.push(phase);
    if (!observationsComplete) observationsIncomplete.push(phase);
    if (selected.some(cell => cell.cleanup !== "verified")) cleanupUnresolved = true;
  }
  for (const phase of selectionIncomplete) expectedGaps.push(`${phase}_selection_incomplete`);
  for (const phase of observationsIncomplete) expectedGaps.push(`${phase}_observations_incomplete`);
  if (cleanupUnresolved) expectedGaps.push("cleanup_unresolved");
  const validatedGaps = value.gaps as S3SavedResults["gaps"];
  if (!sameJson(validatedGaps, expectedGaps)) return false;

  if (phaseMissing.baseline && phaseMissing.retest) return false;
  const expectedState = phaseMissing.baseline ? "retest_only"
    : phaseMissing.retest ? "baseline_only"
      : expectedGaps.length === 0 ? "paired" : "partial";
  if (value.comparison_state !== expectedState) return false;
  const paired = expectedState === "paired";
  const changedValues = rows.map(row => row.changed);
  if (paired) {
    if (!changedValues.every((item, index) => item === (rows[index]!.baseline.state !== rows[index]!.retest.state))) return false;
  } else if (changedValues.some(item => item !== null)) return false;
  const expectedChange = !paired ? "unknown" : changedValues.some(item => item === true) ? "changed" : "unchanged";
  return value.change_state === expectedChange;
}

function validRun(value: unknown, position: number): boolean {
  if (!exact(value, ["position", "mode", "objective_reached", "recorded_attempts", "repeated_step_ids", "first_stop", "observations", "detection", "cleanup"]) || value.position !== position
    || !nullable(value.mode, (item): item is "simulate" | "execute" => oneOf(item, ["simulate", "execute"]))
    || !nullable(value.objective_reached, (item): item is boolean => typeof item === "boolean")
    || !nullable(value.recorded_attempts, count)
    || !nullable(value.repeated_step_ids, (item): item is boolean => typeof item === "boolean")) return false;
  const stopValid = exact(value.first_stop, ["recorded"]) && value.first_stop.recorded === false
    || exact(value.first_stop, ["recorded", "status", "policy_status"]) && value.first_stop.recorded === true
      && nullable(value.first_stop.status, (item): item is StopStatus => oneOf(item, stopStatuses))
      && nullable(value.first_stop.policy_status, (item): item is StopStatus => oneOf(item, stopStatuses));
  if (!stopValid || !validObservationCounts(value.observations)
    || !exact(value.detection, ["total_matches", "observed_matches", "fixture_matches", "benign_matches"])
    || ![value.detection.total_matches, value.detection.observed_matches, value.detection.fixture_matches, value.detection.benign_matches].every(item => nullable(item, count))) return false;
  return exact(value.cleanup, ["source", "authoritative", "state", "success"])
    && oneOf(value.cleanup.source, ["run_result", "step_heuristic", "not_recorded"]) && typeof value.cleanup.authoritative === "boolean"
    && oneOf(value.cleanup.state, ["success", "failed", "unknown", "not_attempted", "verified_success", "failed_or_incomplete", "contradictory"])
    && nullable(value.cleanup.success, (item): item is boolean => typeof item === "boolean");
}

function validChange(value: unknown, position: number): boolean {
  if (!exact(value, ["compared_position", "objective_relation", "material_changed", "material_changes", "first_divergence_position", "divergence_kind", "observations"])
    || value.compared_position !== position
    || !oneOf(value.objective_relation, ["same_recorded_result", "different_recorded_results", "different_objectives", "unverified_objective_proof", "mixed_or_unreported_modes", "unreported"])
    || !(value.material_changes === null || Array.isArray(value.material_changes) && value.material_changes.every(item => oneOf(item, materialChanges)) && new Set(value.material_changes).size === value.material_changes.length)
    || !nullable(value.material_changed, (item): item is boolean => typeof item === "boolean")
    || !nullable(value.first_divergence_position, (item): item is number => typeof item === "number" && Number.isSafeInteger(item) && item > 0 && item <= 2_147_483_647)
    || !oneOf(value.divergence_kind, ["method", "path", "unreported", "none"])
    || !exact(value.observations, ["added", "removed", "changed"])
    || ![value.observations.added, value.observations.removed, value.observations.changed].every(item => nullable(item, count))) return false;
  return value.material_changed === null || value.material_changes === null || value.material_changed === (value.material_changes.length > 0);
}

function validLegitimateUse(value: unknown): boolean {
  if (exact(value, ["state"]) && value.state === "not_recorded") return true;
  if (exact(value, ["state", "reason"])) return value.state === "unavailable" && oneOf(value.reason, ["mixed_selection", "unsupported_operation", "ambiguous_phase", "incompatible_context", "saved_context_unavailable", "saved_binding_invalid"]);
  return validS3SavedResults(value);
}

function validSummary(value: unknown): value is ComparisonAssistanceSummary {
  if (!exact(value, ["schema_version", "saved_comparison", "source_integrity"]) || value.schema_version !== "bluefire.comparison-assistance-summary.v1") return false;
  const saved = value.saved_comparison;
  if (!exact(saved, ["run_count", "baseline_position", "runs", "changes", "legitimate_use"]) || !Number.isSafeInteger(saved.run_count) || Number(saved.run_count) < 2 || Number(saved.run_count) > 32
    || saved.baseline_position !== 1 || !Array.isArray(saved.runs) || saved.runs.length !== saved.run_count
    || !saved.runs.every((run, index) => validRun(run, index + 1)) || !Array.isArray(saved.changes) || saved.changes.length !== saved.run_count - 1
    || !saved.changes.every((change, index) => validChange(change, index + 2)) || !validLegitimateUse(saved.legitimate_use)) return false;
  const integrity = value.source_integrity;
  if (!exact(integrity, ["status", "runs"]) || !oneOf(integrity.status, ["verified", "unavailable"]) || !Array.isArray(integrity.runs) || integrity.runs.length !== saved.run_count) return false;
  const validIntegrity = integrity.runs.every((run, index) => exact(run, ["position", "status"]) && run.position === index + 1 && oneOf(run.status, ["verified", "missing", "changed", "invalid"]));
  return validIntegrity && (integrity.status === "verified" ? integrity.runs.every(run => run.status === "verified") : integrity.runs.some(run => run.status !== "verified"));
}

export function checkedComparisonAssistanceContext(value: unknown, selected: ComparisonAssistanceSelection): ComparisonAssistanceContext {
  if (!validComparisonAssistanceSelection(selected) || !exact(value, ["schema_version", "selected", "context_digest", "analysis_only", "capabilities", "reference_summary", "limitations"])
    || value.schema_version !== "bluefire.assistance-context.v1" || !sameJson(value.selected, selected) || !digest(value.context_digest)
    || value.analysis_only !== true || !Array.isArray(value.capabilities) || value.capabilities.length !== 0
    || !Array.isArray(value.limitations) || !sameJson(value.limitations, comparisonAssistanceLimitations)
    || !validSummary(value.reference_summary) || new TextEncoder().encode(JSON.stringify(value.reference_summary)).length > 32768) {
    throw new Error("The saved comparison explanation context changed or is unavailable.");
  }
  return value as unknown as ComparisonAssistanceContext;
}

export async function comparisonAssistanceContext(selected: ComparisonAssistanceSelection): Promise<ComparisonAssistanceContext> {
  if (!validComparisonAssistanceSelection(selected)) throw new Error("Select one exact saved comparison.");
  const response: unknown = await request(`/comparison-snapshots/${encodeURIComponent(selected.snapshot_id)}/assistant-context`);
  return checkedComparisonAssistanceContext(response, selected);
}
