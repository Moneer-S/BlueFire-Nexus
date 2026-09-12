import type { RunRecord } from "../types";

function object(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

/** Display-only records may be unfinished; they confer no replay or approval authority. */
export function isRetainedRunRecord(value: unknown, runId: string): value is RunRecord {
  if (!object(value) || value.run_id !== runId ||
      (value.mode !== "execute" && value.mode !== "simulate") || typeof value.status !== "string" ||
      !Array.isArray(value.steps) || !value.steps.every(step => object(step) &&
        typeof step.step_id === "string" && typeof step.status === "string")) return false;
  if (value.evidence != null && (!object(value.evidence) || !Array.isArray(value.evidence.records) ||
      !value.evidence.records.every(record => object(record) && typeof record.provenance === "string" &&
        (record.limitations == null || (Array.isArray(record.limitations) && record.limitations.every(item => typeof item === "string")))))) return false;
  if (value.detections != null && (!object(value.detections) || !Array.isArray(value.detections.candidates) ||
      !value.detections.candidates.every(candidate => object(candidate) && typeof candidate.state === "string"))) return false;
  return true;
}
