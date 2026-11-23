import type { CompositionObjective } from "../src/lib/composition";
import type { CompositionKnowledge } from "../src/lib/composition-knowledge";
import { linkageFixture } from "./file-access-linkage-fixture";

const hash = `sha256:${"a".repeat(64)}`;
export function knowledgeFixture(count = 2, ownerDigit = "a") {
  const { objective } = linkageFixture();
  objective.owner.job_id = `job-${ownerDigit.repeat(32)}`;
  objective.attempts = Array.from({ length: count }, (_, index) => {
    const attempt = structuredClone(linkageFixture().attempt);
    const id = (index + 1).toString(16).padStart(32, "0");
    attempt.job_id = `job-${id}`;
    attempt.state = index === 0 ? "failed" : "completed";
    attempt.request.composition_attempt = { ...attempt.request.composition_attempt, parent_job_id: objective.owner.job_id, attempt_id: `attempt-${id}`, run_id: `run-knowledge-${index + 1}` };
    return attempt;
  });
  return { objective, value: knowledgeResponse(objective) };
}

export function knowledgeResponse(objective: CompositionObjective, selected = objective.attempts.map(attempt => attempt.request.composition_attempt.attempt_id)): CompositionKnowledge {
  return {
    schema_version: "bluefire.composition-knowledge.v1", owner_id: objective.owner.job_id, knowledge_digest: hash,
    attempts: objective.attempts.filter(attempt => selected.includes(attempt.request.composition_attempt.attempt_id)).map((attempt, index) => {
      const { attempt_id, run_id } = attempt.request.composition_attempt;
      const evidence = `evidence-${(index + 1).toString(16).padStart(20, "0")}`;
      const summary: Record<string, string | number | boolean> = index === 0
        ? { effective_access: "not_evaluated", group_write_bit: false, non_owner_write_bit: false, other_write_bit: false, permission_mode_octal: "0640", permission_status: "available", size_bytes: 128 }
        : { runner_status: "success", reported_outcome: "allowed", reported_reader: "owner", reported_mode: "0640", reported_record_count: 4 };
      return {
        attempt_id, job_id: attempt.job_id, run_id, state: "settled", job_state: attempt.state, run_status: attempt.state,
        source_status: "verified", source_binding: { run_id, manifest_digest: hash, evidence_digest: hash, observed_records_digest: hash, mode: "execute", finalized_at: "2026-10-28T10:00:00Z", evidence_count: 1, observed_count: index === 0 ? 1 : 0, excluded_provenance_counts: {} },
        problem: null, findings_total: 1, findings_truncated: false,
        findings: [{
          finding_id: `finding-${(index + 1).toString(16).padStart(64, "0")}`, evidence_id: evidence, step_id: index === 0 ? "inspect-copy" : "collect-copy", behavior_id: "sandbox.inspect.v1", action_id: "sandbox.inspect.v1",
          provenance: index === 0 ? "observed" : "executed", semantic_kind: index === 0 ? "observed_filesystem" : "runner_result", observed_at: "2026-10-28T09:59:00Z", content_hash: hash, record_hash: hash,
          summary, applicability: { status: "historical_only", reason: "current_state_not_verified" },
          record_ref: { owner_id: objective.owner.job_id, attempt_id, job_id: attempt.job_id, run_id, evidence_id: evidence, record_hash: hash, source_binding_digest: hash },
        }],
      };
    }),
  };
}
