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

export function registeredDetectionLink(runId: string, candidateId: string): string {
  const params = new URLSearchParams({ run: runId, candidate: candidateId, candidate_scope: "registry" });
  return `/detection-lab?${params}`;
}

export function detectionEvaluationHandoff(params: URLSearchParams): { runId: string; candidateId: string } | undefined {
  if (["run", "candidate", "candidate_scope", "view"].some(key => params.getAll(key).length !== 1)
    || params.get("candidate_scope") !== "registry" || params.get("view") !== "evaluations") return undefined;
  const runId = sourceRunParam(params, "run"), candidateId = sourceRunParam(params, "candidate");
  return runId.trim() && candidateId.trim() ? { runId, candidateId } : undefined;
}

export function registeredDetectionEvaluationLink(runId: string, candidateId: string): string | undefined {
  const params = new URLSearchParams({ run: runId, candidate: candidateId, candidate_scope: "registry", view: "evaluations" });
  return detectionEvaluationHandoff(params) ? `/detection-lab?${params}` : undefined;
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
