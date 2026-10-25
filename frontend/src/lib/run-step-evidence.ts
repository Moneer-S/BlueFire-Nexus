import type { EvidenceRecord, RunRecord, RunStep } from "../types";

export interface RunStepEvidenceResolution {
  records: EvidenceRecord[];
  unresolvedIds: string[];
  distinctReferenceCount: number;
}

/** Resolve only the evidence identities recorded on this step, in reference order. */
export function resolveRunStepEvidence(
  run: Pick<RunRecord, "run_id" | "evidence"> | undefined,
  step: Pick<RunStep, "step_id" | "evidence_ids">,
): RunStepEvidenceResolution {
  const references = [...new Set(
    Array.isArray(step.evidence_ids)
      ? step.evidence_ids.filter((id): id is string => typeof id === "string" && id.length > 0)
      : [],
  )];
  const unresolvedIds: string[] = [];
  const records: EvidenceRecord[] = [];
  const available = run && Array.isArray(run.evidence?.records) ? run.evidence.records : undefined;

  for (const reference of references) {
    if (!run || !available) {
      unresolvedIds.push(reference);
      continue;
    }
    const matches = available.filter(record => {
      if (!record || typeof record !== "object") return false;
      const identity = record.evidence_id === undefined ? record.id : record.evidence_id;
      return identity === reference;
    });
    if (matches.length !== 1) {
      unresolvedIds.push(reference);
      continue;
    }
    const record = matches[0]!;
    if ((record.run_id !== undefined && record.run_id !== run.run_id)
      || (record.step_id !== undefined && record.step_id !== step.step_id)) {
      unresolvedIds.push(reference);
      continue;
    }
    records.push(record);
  }

  return { records, unresolvedIds, distinctReferenceCount: references.length };
}
