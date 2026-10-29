import { fileAccessObjectiveFixture } from "./file-access-fixture";
import { controlId, testDigest } from "./composition-fixture";

// Authored presentation fixture; this is not native proof or independently collected evidence.
export function linkageFixture(state: "established" | "unknown" | "incomplete" | "owner-unknown" = "established") {
  const objective = fileAccessObjectiveFixture("permission_denied");
  const attempt = objective.attempts[0]!;
  attempt.request.composition_attempt.run_id = "run-proof";
  const unknown = state === "unknown";
  const incomplete = state === "incomplete";
  const ownerUnknown = state === "owner-unknown";
  return { objective, attempt, value: {
    schema_version: "bluefire.file-access-composed-retest-linkage.v1",
    objective_owner_id: objective.owner.job_id,
    attempt_id: attempt.request.composition_attempt.attempt_id,
    control_owner_id: controlId,
    linkage_digest: testDigest,
    baseline: { operation_job_id: `job-${"1".repeat(32)}`, control_revision: 2, control_digest: testDigest, baseline_digest: testDigest, mode: "0640", resource_generation: "generation-test", non_owner: "allowed", owner: "allowed", record_count: 8, sha256: testDigest },
    change: { operation_job_id: `job-${"2".repeat(32)}`, control_revision: 3, control_digest: testDigest, previous_control_digest: testDigest, mode: "0600", resource_generation: "generation-test" },
    retest: { attempt_job_id: attempt.job_id, run_id: "run-proof", state: unknown ? "unknown" : "verified",
      non_owner_decision: unknown ? null : incomplete ? "allowed" : "permission_denied", owner_decision: unknown ? null : ownerUnknown ? "unknown" : "allowed", record_count: unknown ? null : 8,
      sha256: unknown ? null : testDigest, run_cleanup: unknown ? null : incomplete ? "incomplete" : "complete",
      request_cleanup: unknown ? null : "verified_closed", objective_established: unknown ? null : !incomplete && !ownerUnknown,
      result_digest: unknown ? null : testDigest },
    comparison: { state: unknown ? "unknown" : incomplete || ownerUnknown ? "not_established" : "established",
      non_owner_change: unknown ? "unknown" : incomplete ? "still_allowed" : "allowed_to_denied",
      owner_preserved: unknown || ownerUnknown ? null : true, content_preserved: unknown || ownerUnknown ? null : true,
      cleanup_verified: unknown ? null : !incomplete },
  } };
}
