import type { RunRecord } from "../types";

function object(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

export function retainedObservations(value: unknown, runId: string): RunRecord | null {
  if (!object(value) || value.schema_version !== "bluefire.retained-run-observations.v1" ||
      value.run_id !== runId || value.record_state !== "unsealed" || value.display_only !== true ||
      value.canonical !== false || value.replay_available !== false) return null;
  return retainedRunRecord(value.observations, runId);
}

/** Display-only records may be unfinished; they confer no replay or approval authority. */
export function retainedRunRecord(value: unknown, runId: string): RunRecord | null {
  // create_run stores mode in the plan; finalization adds it to result.json.
  // Resolve this display field only for the two supported unfinished states.
  if (object(value) && value.mode === undefined && value.finalized_at == null &&
      (value.status === "created" || value.status === "interrupted") && object(value.plan)) {
    value = { ...value, mode: value.plan.mode };
  }
  if (!object(value) || value.run_id !== runId ||
      (value.mode !== "execute" && value.mode !== "simulate") || typeof value.status !== "string" ||
      !Array.isArray(value.steps) || !value.steps.every(step => object(step) &&
        typeof step.step_id === "string" && typeof step.status === "string")) return null;
  if (value.evidence != null && (!object(value.evidence) || !Array.isArray(value.evidence.records) ||
      !value.evidence.records.every(record => object(record) && typeof record.provenance === "string" &&
        (record.limitations == null || (Array.isArray(record.limitations) && record.limitations.every(item => typeof item === "string")))))) return null;
  if (value.detections != null && (!object(value.detections) || !Array.isArray(value.detections.candidates) ||
      !value.detections.candidates.every(candidate => object(candidate) && typeof candidate.state === "string"))) return null;
  return value as unknown as RunRecord;
}
