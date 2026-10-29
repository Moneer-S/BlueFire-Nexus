import { DEMO_MODE, request } from "./api";
import { compositionJobValid, type CompositionObjective } from "./composition";

export interface CompositionFinding {
  finding_id: string;
  evidence_id: string;
  step_id: string;
  behavior_id: string;
  action_id: string | null;
  provenance: "synthetic" | "executed" | "observed" | "control_blocked" | "counterfactual" | "unknown";
  semantic_kind: "observed_filesystem" | "observed_collection" | "observed_process_snapshot" | "observed_receiver_binding" | "runner_result" | "evidence_gap" | "record_metadata";
  observed_at: string;
  content_hash: string;
  record_hash: string;
  summary: Record<string, string | number | boolean>;
  applicability: { status: "historical_only"; reason: "current_state_not_verified" };
  record_ref: { owner_id: string; attempt_id: string; job_id: string; run_id: string; evidence_id: string; record_hash: string; source_binding_digest: string };
}

export interface CompositionKnowledgeAttempt {
  attempt_id: string;
  job_id: string;
  run_id: string;
  state: string;
  job_state: string;
  run_status: string | null;
  source_status: "verified" | "unavailable";
  source_binding: Record<string, unknown> | null;
  problem: string | null;
  findings_total: number;
  findings_truncated: boolean;
  findings: CompositionFinding[];
}

export interface CompositionKnowledge {
  schema_version: "bluefire.composition-knowledge.v1";
  owner_id: string;
  attempts: CompositionKnowledgeAttempt[];
  knowledge_digest: string;
}

const invalid = () => new Error("These findings could not be matched to the selected saved attempts.");
const object = (value: unknown): Record<string, unknown> => {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw invalid();
  return value as Record<string, unknown>;
};
const exact = (value: Record<string, unknown>, keys: string[]) => Object.keys(value).sort().join(",") === [...keys].sort().join(",");
const safeCharacters = (value: string) => [...value].every(character => character.charCodeAt(0) >= 32);
const text = (value: unknown, maximum = 200): value is string => typeof value === "string" && value.length > 0 && value.length <= maximum && safeCharacters(value);
const digest = (value: unknown) => typeof value === "string" && /^sha256:[0-9a-f]{64}$/.test(value);
const count = (value: unknown): value is number => Number.isSafeInteger(value) && Number(value) >= 0;
const attemptId = (value: unknown): value is string => typeof value === "string" && /^attempt-[0-9a-f]{32}$/.test(value);
const kinds = new Set(["observed_filesystem", "observed_collection", "observed_process_snapshot", "observed_receiver_binding", "runner_result", "evidence_gap", "record_metadata"]);
const provenances = new Set(["synthetic", "executed", "observed", "control_blocked", "counterfactual", "unknown"]);

export function checkedCompositionKnowledge(value: unknown, objective: { owner: { job_id: string }; attempts: Array<{ job_id: string; request: { composition_attempt: { attempt_id: string; run_id: string } } }> }, selected: string[]): CompositionKnowledge {
  if (!compositionJobValid(objective.owner.job_id) || selected.length < 1 || selected.length > 8 || new Set(selected).size !== selected.length || !selected.every(attemptId)) throw invalid();
  const root = object(value);
  if (!exact(root, ["schema_version", "owner_id", "attempts", "knowledge_digest"]) || root.schema_version !== "bluefire.composition-knowledge.v1" || root.owner_id !== objective.owner.job_id || !digest(root.knowledge_digest) || !Array.isArray(root.attempts) || root.attempts.length !== selected.length || JSON.stringify(value).length > 1_048_576) throw invalid();
  const expected = new Map(objective.attempts.map(attempt => [attempt.request.composition_attempt.attempt_id, attempt]));
  const returned = new Set<string>();
  const findingIds = new Set<string>();
  for (const item of root.attempts) {
    const row = object(item);
    if (!exact(row, ["attempt_id", "job_id", "run_id", "state", "job_state", "run_status", "source_status", "source_binding", "problem", "findings_total", "findings_truncated", "findings"]) || !attemptId(row.attempt_id) || !selected.includes(row.attempt_id) || returned.has(row.attempt_id)) throw invalid();
    returned.add(row.attempt_id);
    const saved = expected.get(row.attempt_id);
    if (!saved || row.job_id !== saved.job_id || row.run_id !== saved.request.composition_attempt.run_id || !["reserved", "claimed", "settled"].includes(String(row.state)) || !text(row.job_state, 80) || (row.run_status !== null && !text(row.run_status, 80)) || !Array.isArray(row.findings) || row.findings.length > 32 || !count(row.findings_total) || typeof row.findings_truncated !== "boolean") throw invalid();
    if (row.source_status === "unavailable") {
      if (row.source_binding !== null || !text(row.problem, 300) || row.findings.length || row.findings_total !== 0 || row.findings_truncated) throw invalid();
      continue;
    }
    if (row.source_status !== "verified" || row.problem !== null || row.run_status === null || row.findings_total < row.findings.length || row.findings_truncated !== (row.findings_total > row.findings.length)) throw invalid();
    const source = object(row.source_binding);
    if (source.run_id !== row.run_id || !digest(source.manifest_digest) || !digest(source.evidence_digest) || !digest(source.observed_records_digest) || source.mode !== "execute" || !text(source.finalized_at, 40) || !Number.isFinite(Date.parse(source.finalized_at)) || !count(source.evidence_count) || !count(source.observed_count)) throw invalid();
    for (const raw of row.findings) {
      const finding = object(raw);
      if (!exact(finding, ["finding_id", "evidence_id", "step_id", "behavior_id", "action_id", "provenance", "semantic_kind", "observed_at", "content_hash", "record_hash", "summary", "applicability", "record_ref"]) || typeof finding.finding_id !== "string" || !/^finding-[0-9a-f]{64}$/.test(finding.finding_id) || findingIds.has(finding.finding_id) || !text(finding.evidence_id) || !text(finding.step_id) || !text(finding.behavior_id) || (finding.action_id !== null && !text(finding.action_id)) || !provenances.has(String(finding.provenance)) || !kinds.has(String(finding.semantic_kind)) || !text(finding.observed_at, 40) || !Number.isFinite(Date.parse(finding.observed_at)) || !digest(finding.content_hash) || !digest(finding.record_hash)) throw invalid();
      findingIds.add(finding.finding_id);
      const applicability = object(finding.applicability);
      if (!exact(applicability, ["status", "reason"]) || applicability.status !== "historical_only" || applicability.reason !== "current_state_not_verified") throw invalid();
      const ref = object(finding.record_ref);
      if (!exact(ref, ["owner_id", "attempt_id", "job_id", "run_id", "evidence_id", "record_hash", "source_binding_digest"]) || ref.owner_id !== root.owner_id || ref.attempt_id !== row.attempt_id || ref.job_id !== row.job_id || ref.run_id !== row.run_id || ref.evidence_id !== finding.evidence_id || ref.record_hash !== finding.record_hash || !digest(ref.source_binding_digest)) throw invalid();
      const summary = object(finding.summary);
      if (Object.keys(summary).length > 20 || !Object.entries(summary).every(([key, field]) => text(key, 80) && (typeof field === "boolean" || typeof field === "number" && Number.isFinite(field) || typeof field === "string" && field.length <= 500 && safeCharacters(field)))) throw invalid();
    }
  }
  return value as CompositionKnowledge;
}

export const compositionKnowledgeApi = {
  read: async (objective: CompositionObjective, attemptIds: string[]): Promise<CompositionKnowledge> => {
    if (DEMO_MODE) throw new Error("Saved findings require the installed service and a recorded objective.");
    if (!compositionJobValid(objective.owner.job_id) || !attemptIds.length || attemptIds.length > 8 || new Set(attemptIds).size !== attemptIds.length || !attemptIds.every(attemptId)) throw invalid();
    const response: unknown = await request(`/composition/objectives/${encodeURIComponent(objective.owner.job_id)}/knowledge`, {
      method: "POST", body: JSON.stringify({ schema_version: "bluefire.composition-knowledge-query.v1", attempt_ids: attemptIds }),
    });
    return checkedCompositionKnowledge(response, objective, attemptIds);
  },
};
