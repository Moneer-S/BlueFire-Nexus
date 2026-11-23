import { validS3Job, validS3Run } from "./s3-access";
import type {
  ComparisonResponse,
  S3AccessComparison,
  S3AccessComparisonAvailable,
  S3AccessComparisonCell,
  S3AccessComparisonGap,
  S3AccessComparisonPhase,
  S3AccessComparisonRow,
} from "../types";

const unavailableReasons = ["mixed_selection", "unsupported_operation", "ambiguous_phase", "incompatible_context", "saved_context_unavailable", "saved_binding_invalid"] as const;
const gapOrder: S3AccessComparisonGap[] = ["baseline_missing", "retest_missing", "baseline_selection_incomplete", "retest_selection_incomplete", "baseline_observations_incomplete", "retest_observations_incomplete", "cleanup_unresolved"];
const rowIdentity = [["probe", "primary"], ["legitimate", "primary"], ["legitimate", "health"]] as const;
const phases = ["baseline", "retest"] as const;

function record(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function exactKeys(value: Record<string, unknown>, expected: string[]): boolean {
  return Object.keys(value).length === expected.length && expected.every((key) => Object.hasOwn(value, key));
}

function phase(value: unknown): value is S3AccessComparisonPhase {
  return record(value) && exactKeys(value, ["operation_job_id", "run_ids", "selection_complete", "observation_complete", "cleanup"])
    && validS3Job(value.operation_job_id)
    && Array.isArray(value.run_ids) && value.run_ids.length >= 1 && value.run_ids.length <= 2 && value.run_ids.every(validS3Run)
    && new Set(value.run_ids).size === value.run_ids.length
    && typeof value.selection_complete === "boolean"
    && typeof value.observation_complete === "boolean"
    && (value.cleanup === "verified" || value.cleanup === "unknown");
}

function cell(value: unknown): value is S3AccessComparisonCell {
  if (!record(value) || !exactKeys(value, ["run_id", "state", "provenance", "cleanup"])
    || !(value.run_id === null || validS3Run(value.run_id))
    || !["read", "service_denied", "unreported", "not_selected", "not_recorded"].includes(String(value.state))
    || !(value.provenance === null || value.provenance === "synthetic" || value.provenance === "runner_reported")
    || !(value.cleanup === null || value.cleanup === "verified" || value.cleanup === "unknown")) return false;
  if (value.state === "not_selected" || value.state === "not_recorded") {
    return value.run_id === null && value.provenance === null && value.cleanup === null;
  }
  return value.run_id !== null && value.provenance !== null && value.cleanup !== null;
}

function row(value: unknown, index: number): value is S3AccessComparisonRow {
  return record(value) && exactKeys(value, ["reader", "purpose", "baseline", "retest", "changed"])
    && value.reader === rowIdentity[index]?.[0]
    && value.purpose === rowIdentity[index]?.[1]
    && cell(value.baseline) && cell(value.retest)
    && (value.changed === null || typeof value.changed === "boolean");
}

function expectedGaps(value: Record<string, unknown>): S3AccessComparisonGap[] {
  const missing: S3AccessComparisonGap[] = [];
  for (const name of phases) if (value[name] === null) missing.push(`${name}_missing` as S3AccessComparisonGap);
  for (const name of phases) {
    const selected = value[name] as S3AccessComparisonPhase | null;
    if (selected && !selected.selection_complete) missing.push(`${name}_selection_incomplete` as S3AccessComparisonGap);
  }
  for (const name of phases) {
    const selected = value[name] as S3AccessComparisonPhase | null;
    if (selected && !selected.observation_complete) missing.push(`${name}_observations_incomplete` as S3AccessComparisonGap);
  }
  if (value.rows && (value.rows as S3AccessComparisonRow[]).some((item) => [item.baseline, item.retest].some((result) => result.run_id !== null && result.cleanup !== "verified"))) {
    missing.push("cleanup_unresolved");
  }
  return missing;
}

function unavailable(value: unknown): value is Extract<S3AccessComparison, { state: "unavailable" }> {
  return record(value) && exactKeys(value, ["schema_version", "state", "reason", "proof_scope"])
    && value.schema_version === "bluefire.s3-access-comparison.v1"
    && value.state === "unavailable"
    && unavailableReasons.includes(value.reason as typeof unavailableReasons[number])
    && value.proof_scope === "saved_read_results_only";
}

function available(value: unknown, selectedRunIds?: readonly string[]): value is S3AccessComparisonAvailable {
  if (!record(value)) return false;
  const required = ["schema_version", "state", "workflow_job_id", "scope_digest", "source_digest", "baseline", "retest", "rows", "change_state", "gaps", "proof_scope", "effective_access_claim", "defensive_effectiveness_claim"];
  if (!exactKeys(value, required)
    || value.schema_version !== "bluefire.s3-access-comparison.v1"
    || !["paired", "baseline_only", "retest_only", "partial"].includes(String(value.state))
    || !validS3Job(value.workflow_job_id)
    || typeof value.scope_digest !== "string" || !/^sha256:[0-9a-f]{64}$/.test(value.scope_digest)
    || typeof value.source_digest !== "string" || !/^sha256:[0-9a-f]{64}$/.test(value.source_digest)
    || !(value.baseline === null || phase(value.baseline))
    || !(value.retest === null || phase(value.retest))
    || (value.baseline === null && value.retest === null)
    || !Array.isArray(value.rows) || value.rows.length !== 3 || !value.rows.every(row)
    || !["changed", "unchanged", "unknown"].includes(String(value.change_state))
    || !Array.isArray(value.gaps) || !value.gaps.every((gap) => typeof gap === "string" && gapOrder.includes(gap as S3AccessComparisonGap))
    || new Set(value.gaps).size !== value.gaps.length
    || value.proof_scope !== "saved_read_results_only"
    || value.effective_access_claim !== false
    || value.defensive_effectiveness_claim !== false) return false;

  const typedRows = value.rows as S3AccessComparisonAvailable["rows"];
  const phaseValues = { baseline: value.baseline as S3AccessComparisonPhase | null, retest: value.retest as S3AccessComparisonPhase | null };
  const allRunIds = phases.flatMap((name) => phaseValues[name]?.run_ids ?? []);
  if (new Set(allRunIds).size !== allRunIds.length) return false;
  if (selectedRunIds && (new Set(selectedRunIds).size !== selectedRunIds.length
    || selectedRunIds.length !== allRunIds.length
    || selectedRunIds.some((id) => !allRunIds.includes(id)))) return false;

  for (const name of phases) {
    const current = phaseValues[name];
    const primary = typedRows[0][name];
    const legitimate = typedRows[1][name];
    const health = typedRows[2][name];
    if (!current) {
      if ([primary, legitimate, health].some((item) => item.state !== "not_recorded")) return false;
      continue;
    }
    const selectedIds = [primary, legitimate].filter((item) => item.run_id !== null).map((item) => item.run_id as string);
    if (JSON.stringify(current.run_ids) !== JSON.stringify(selectedIds)) return false;
    if (legitimate.state === "not_recorded" || legitimate.state === "not_selected") {
      if (legitimate.state !== health.state || health.run_id !== null) return false;
    } else if (legitimate.run_id !== health.run_id || legitimate.provenance !== health.provenance || legitimate.cleanup !== health.cleanup
      || (legitimate.state === "unreported") !== (health.state === "unreported")) return false;
    const complete = selectedIds.length === 2;
    const observed = complete && [primary, legitimate, health].every((item) => item.state === "read" || item.state === "service_denied");
    const cleanupVerified = complete && [primary.cleanup, legitimate.cleanup].every((item) => item === "verified");
    if (current.selection_complete !== complete || current.observation_complete !== observed
      || current.cleanup !== (cleanupVerified ? "verified" : "unknown")) return false;
  }

  const provenanceValues = typedRows.flatMap((item) => [item.baseline, item.retest])
    .filter((item) => item.run_id !== null).map((item) => item.provenance);
  if (new Set(provenanceValues).size > 1) return false;
  for (const item of typedRows) {
    if (item.changed !== null) {
      if (item.baseline.state !== "read" && item.baseline.state !== "service_denied") return false;
      if (item.retest.state !== "read" && item.retest.state !== "service_denied") return false;
      if (item.baseline.provenance !== item.retest.provenance || item.baseline.cleanup !== "verified" || item.retest.cleanup !== "verified"
        || item.changed !== (item.baseline.state !== item.retest.state)) return false;
    }
  }
  const expectedState = phaseValues.baseline === null ? "retest_only" : phaseValues.retest === null ? "baseline_only" :
    expectedGaps(value).length === 0 ? "paired" : "partial";
  const derivedGaps = expectedGaps(value);
  const allObserved = phaseValues.baseline?.observation_complete && phaseValues.retest?.observation_complete;
  const allClean = phaseValues.baseline?.cleanup === "verified" && phaseValues.retest?.cleanup === "verified";
  const comparable = Boolean(phaseValues.baseline !== null && phaseValues.retest !== null
    && phaseValues.baseline.selection_complete && phaseValues.retest.selection_complete && allObserved && allClean);
  const derivedChange = !comparable ? "unknown" : typedRows.some((item) => item.baseline.state !== item.retest.state) ? "changed" : "unchanged";
  return value.state === expectedState
    && JSON.stringify(value.gaps) === JSON.stringify(derivedGaps)
    && typedRows.every((item) => item.changed === (comparable ? item.baseline.state !== item.retest.state : null))
    && value.change_state === derivedChange;
}

export function checkedS3AccessComparison(value: unknown, selectedRunIds?: readonly string[]): S3AccessComparison {
  if (!record(value) || value.schema_version !== "bluefire.s3-access-comparison.v1") throw new Error("The S3 access comparison is invalid.");
  if (unavailable(value)) return value;
  if (!available(value, selectedRunIds)) throw new Error("The S3 access comparison is invalid.");
  return value;
}

export function checkedComparisonResponse(result: ComparisonResponse): ComparisonResponse {
  if (result.s3_access !== undefined) checkedS3AccessComparison(result.s3_access, result.run_ids);
  return result;
}
