import type { DetectionCandidate, RunRecord } from "../types";

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

export function hypothesisFromRun(candidate: DetectionCandidate, run: RunRecord): Record<string, unknown> {
  if (!candidate.behavior_id || !candidate.selection || !candidate.logsource) {
    throw new Error("This run record has no complete detection definition to save. Create a new hypothesis from the registered behavior instead.");
  }
  // Copy definition fields only. The persisted service must start a fresh
  // hypothesis; a run's parser, fixture, match, or observed status is not inherited.
  return {
    behavior_id: candidate.behavior_id,
    title: candidate.title ?? "Run-linked detection hypothesis",
    target_language: candidate.target_language ?? candidate.language ?? "internal",
    selection: candidate.selection,
    logsource: candidate.logsource,
    provenance: {
      ...candidate.provenance,
      source_run_id: run.run_id,
      source_candidate_id: candidate.candidate_id ?? candidate.id ?? "unidentified",
    },
    known_misses: candidate.known_misses ?? [],
    predicted_fields: candidate.predicted_fields ?? [],
  };
}
