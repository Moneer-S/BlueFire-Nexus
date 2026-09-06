import type { RunRecord } from "../types";

export function sourceRunParam(params: URLSearchParams, key: string): string {
  const value = params.get(key) ?? "";
  return value.length <= 200 && !Array.from(value).some((character) => character.charCodeAt(0) < 32) ? value : "";
}

export function comparisonLink(sourceId: string, replayId?: string): string {
  const params = new URLSearchParams({ source: sourceId });
  if (replayId) params.set("replay", replayId);
  return `/compare?${params}`;
}

export function detectionLink(runId: string, candidateId?: string): string {
  const params = new URLSearchParams({ run: runId });
  if (candidateId) params.set("candidate", candidateId);
  return `/detection-lab?${params}`;
}

export function runCandidateKey(runId: string, candidateId: string): string {
  return `run:${runId}:${candidateId}`;
}

// This is a display/selection guard. The observed exercise service still verifies
// the immutable bundle, record integrity, provenance, and selected IDs itself.
export function sourceObservedRecords(run?: RunRecord) {
  if (!run?.manifest || run.is_demo) return [];
  return (run.evidence?.records ?? []).filter((record) => record.provenance === "observed" && record.run_id === run.run_id && Boolean(record.evidence_id));
}
