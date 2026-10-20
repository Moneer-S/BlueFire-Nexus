import { beforeEach, expect, it } from "vitest";
import { checkedCompositionContext, checkedCompositionObjective, checkedCompositionProposal, checkedCompositionReview, clearCompositionPending, compositionConfirmed, readCompositionPending, storeCompositionPending, type CompositionPending } from "../src/lib/composition";
import { attemptFixture, contextFixture, controlId, grantRequestFixture, objectiveFixture, ownerId, proposalFixture, proposalId, question, refusalFixture, reviewFixture, testDigest } from "./composition-fixture";
import { clearCompositionControl, compositionControlConfirmed, readCompositionControls, storeCompositionControl } from "../src/lib/composition";
import { clearCompositionCancellation, compositionCanRevise, compositionCancellationConfirmed, readCompositionCancellations, storeCompositionCancellation } from "../src/lib/composition";
import { compositionControlValid, compositionEstablished, compositionPack, compositionRecord, compositionRequestPack, FILE_ACCESS_PACK, MACOS_FILE_ACCESS_PACK, type CompositionObjective, type CompositionReview, type CompositionReviewRequest } from "../src/lib/composition";
import { fileAccessCompositionPack } from "../src/lib/file-access";
import { fileAccessCompositionReviewFixture, fileAccessControlFixture, fileAccessObjectiveFixture } from "./file-access-fixture";
import { macOSControlFixture, macOSOwner } from "./macos-file-access-fixture";

beforeEach(() => localStorage.clear());
const pending = (): CompositionPending => ({ kind: "proposal", owner: ownerId, control: controlId, id: proposalId, body: { submission_id: "cccccccc-cccc-cccc-cccc-cccccccccccc", provider_id: "configured", context_digest: testDigest, prior_attempt_id: null } });
it("retains an exact submission across reload and refuses replacement", () => {
  const value = pending(); storeCompositionPending(value);
  expect(readCompositionPending()).toEqual(value);
  expect(() => storeCompositionPending({ ...value, body: { ...value.body, provider_id: "other" } })).toThrow();
  expect(() => clearCompositionPending({ ...value, id: ownerId })).toThrow();
  clearCompositionPending(value); expect(readCompositionPending()).toBeUndefined();
});
it("fails closed on malformed saved recovery state", () => {
  localStorage.setItem("bluefire.composition.pending.v1", '{"kind":"attempt"}');
  expect(readCompositionPending).toThrow();
});
it("requires exact submitted provider/context/prior identity even for failed proposals", () => {
  const value = proposalFixture();
  expect(compositionConfirmed(value, pending())).toBe(true);
  value.proposal = null; value.provider_outcome = "unknown";
  expect(compositionConfirmed(value, pending())).toBe(true);
  value.job.request.submitted_request = { ...pending().body, provider_id: "substituted" };
  expect(compositionConfirmed(value, pending())).toBe(false);
});
it("does not resolve queued attempts from job identity alone", () => {
  const value = objectiveFixture(); const operation = { ...pending(), kind: "attempt" as const, body: { submission_id: "cccccccc-cccc-cccc-cccc-cccccccccccc", proposal: contextFixture().initial_proposal, prior_attempt_id: null } };
  value.attempts = [{ job_id: proposalId, kind: "composition.attempt", state: "queued", request: { composition_attempt: { parent_job_id: ownerId, grant_id: value.grant.document.grant_id, grant_digest: testDigest, attempt_id: `attempt-${"c".repeat(32)}`, compiled_digest: testDigest, run_id: "run-proof" } }, progress: {} }];
  expect(compositionConfirmed(value, operation)).toBe(false);
  value.attempts[0]!.progress.submitted_request = operation.body;
  expect(compositionConfirmed(value, operation)).toBe(true);
  value.attempts[0]!.progress.submitted_request = { ...operation.body, prior_attempt_id: "different" };
  expect(compositionConfirmed(value, operation)).toBe(false);
});
it("rejects cross-objective/control responses and changed review questions", () => {
  expect(() => checkedCompositionObjective(objectiveFixture(), proposalId, controlId)).toThrow();
  expect(() => checkedCompositionObjective(objectiveFixture(), ownerId, proposalId)).toThrow();
  expect(() => checkedCompositionReview(reviewFixture(), { control_owner_id: controlId, question: "changed", limits: null })).toThrow();
  expect(checkedCompositionReview(reviewFixture(), { control_owner_id: controlId, question, limits: null }).review_digest).toBe(testDigest);
});
it("rejects stale context identity and malformed typed projections", () => {
  expect(() => checkedCompositionContext(contextFixture(), "grant-other")).toThrow();
  const value = contextFixture(); value.initial_scenario = {} as typeof value.initial_scenario;
  expect(() => checkedCompositionContext(value, value.grant_id)).toThrow();
});
it("checks saved provider graph ownership and rejects fallback provenance", () => {
  expect(checkedCompositionProposal(proposalFixture(), proposalId, ownerId).candidate_ready).toBe(true);
  expect(() => checkedCompositionProposal(proposalFixture(), proposalId, controlId)).toThrow();
  const value = proposalFixture(); Object.assign(value.proposal!.provider, { used_fallback: true });
  expect(() => checkedCompositionProposal(value, proposalId, ownerId)).toThrow();
});
it("retains unknown stop/revoke/continue intent independently of a pending effect", () => {
  storeCompositionPending(pending()); storeCompositionControl(ownerId, "stop");
  expect(readCompositionControls()[ownerId]).toBe("stop");
  expect(compositionControlConfirmed(objectiveFixture(), "stop")).toBe(false);
  const value = objectiveFixture(); value.grant.status = "paused";
  expect(compositionControlConfirmed(value, "stop")).toBe(true);
  expect(() => clearCompositionControl(ownerId, "revoke")).toThrow();
  clearCompositionControl(ownerId, "stop");
  expect(readCompositionControls()).toEqual({}); expect(readCompositionPending()).toEqual(pending());
});
it("never weakens an unresolved revocation or resumes across an unknown stop", () => {
  storeCompositionControl(ownerId, "stop");
  expect(() => storeCompositionControl(ownerId, "continue")).toThrow();
  storeCompositionControl(ownerId, "revoke");
  expect(() => storeCompositionControl(ownerId, "stop")).toThrow();
  expect(() => storeCompositionControl(ownerId, "continue")).toThrow();
  expect(readCompositionControls()[ownerId]).toBe("revoke");
});
it("retains exact cancellation and only reconciles the independently stopped proposal", () => {
  storeCompositionCancellation(ownerId, proposalId);
  expect(readCompositionCancellations()).toEqual({ [ownerId]: proposalId });
  expect(() => storeCompositionCancellation(ownerId, controlId)).toThrow();
  const value = proposalFixture();
  expect(compositionCancellationConfirmed(value, ownerId, proposalId)).toBe(false);
  value.job.progress.stopped = true;
  expect(compositionCancellationConfirmed(value, ownerId, proposalId)).toBe(false);
  value.candidate_ready = false;
  expect(compositionCancellationConfirmed(value, ownerId, proposalId)).toBe(true);
  expect(compositionCancellationConfirmed(value, controlId, proposalId)).toBe(false);
  expect(() => clearCompositionCancellation(ownerId, controlId)).toThrow();
  clearCompositionCancellation(ownerId, proposalId); expect(readCompositionCancellations()).toEqual({});
});
it("does not claim an established outcome from another run or incomplete checks", () => {
  const value = objectiveFixture();
  value.attempts = [{ job_id: proposalId, kind: "composition.attempt", state: "completed", request: { composition_attempt: { parent_job_id: ownerId, grant_id: value.grant.document.grant_id, grant_digest: testDigest, attempt_id: `attempt-${"c".repeat(32)}`, compiled_digest: testDigest, run_id: "run-proof" } }, progress: { verified_result_digest: testDigest, verified_result: { run_id: "different-run", objective: { established: true, checks: {} } } } }];
  expect(() => checkedCompositionObjective(value, ownerId, controlId)).toThrow();
  const result = value.attempts[0]!.progress.verified_result as { run_id: string; objective: { established: boolean; checks: Record<string, boolean> } };
  result.run_id = "run-proof";
  result.objective.checks = Object.fromEntries(["receiver_verified", "policy_unchanged", "data_class_preserved", "record_count_preserved", "all_records_redacted", "accepted", "run_cleaned", "receiver_closed"].map(key => [key, true]));
  expect(checkedCompositionObjective(value, ownerId, controlId)).toBe(value);
  result.objective.checks.run_cleaned = false;
  expect(() => checkedCompositionObjective(value, ownerId, controlId)).toThrow();
});
it("revises only exact policy-refused evidence with settled cleanup and preserved records", () => {
  const value = objectiveFixture(); const attempt = attemptFixture();
  expect(compositionCanRevise(attempt, value)).toBe(true);
  expect(compositionCanRevise(attemptFixture(true), value)).toBe(false);
  const result = attempt.progress.verified_result as { receiver_result: Record<string, unknown>; cleanup: Record<string, unknown> };
  result.receiver_result.record_count = 0; expect(compositionCanRevise(attempt, value)).toBe(false);
  result.receiver_result.record_count = 8; result.cleanup.run = "incomplete"; expect(compositionCanRevise(attempt, value)).toBe(false);
});
it("clears a refused grant only from the exact durable immutable submission", () => {
  const operation: CompositionPending = { kind: "grant", owner: ownerId, control: controlId, id: ownerId, body: grantRequestFixture() };
  const value = refusalFixture();
  expect(checkedCompositionObjective(value, ownerId, controlId)).toBe(value);
  expect(compositionConfirmed(value, operation)).toBe(true);
  value.owner.progress.submitted_request = { ...operation.body, reviewed_by: "different" };
  expect(compositionConfirmed(value, operation)).toBe(false);
  const missing = refusalFixture(); missing.owner.progress.submitted_request = undefined;
  expect(() => checkedCompositionObjective(missing, ownerId, controlId)).toThrow();
});
it.each(["composition_review_changed", "composition_admission_unavailable", "composition_admission_interrupted"])("accepts terminal refusal %s but never treats in-progress admission as refused", code => {
  const value = refusalFixture(); value.owner.progress.admission = { accepted: false, problem: { code, message: "Review this delegation again." } };
  expect(checkedCompositionObjective(value, ownerId, controlId)).toBe(value);
  value.owner.state = "queued";
  expect(() => checkedCompositionObjective(value, ownerId, controlId)).toThrow();
  value.owner.state = "completed"; value.owner.progress.admission = { accepted: false, problem: { code: "composition_admission_pending", message: "Not yet admitted." } };
  expect(() => checkedCompositionObjective(value, ownerId, controlId)).toThrow();
});

// Authored UI contracts only; these documents do not establish original native custody.
function macCompositionReviewFixture(): CompositionReview {
  const original = reviewFixture();
  const template = original.snapshot.methods[0]!;
  const methods = ["macos.file_access.probe.v1", "macos.file_access.verify_owner.v1", "macos.file_access.close_attempt.v1"];
  const probe = { name: "probe", type: "artifact.macos_file_access.probe.v1", multiple: false, required: true };
  const workspace = { name: "workspace", type: "artifact.macos_file_access.attempt.v1", multiple: false, required: true };
  return {
    ...original, schema_version: "bluefire.composition-review.v2", pack: MACOS_FILE_ACCESS_PACK,
    objective: { question: "Verify the retained Mac control", predicate: { kind: "non_owner_denied_owner_preserves_records", record_count: 8, data_class: "generated_public_jsonl", sha256: testDigest } },
    environment: { environment_id: "environment-test", environment_generation: "generation-test", control_owner_id: macOSOwner, runner_id: "bluefire-macos-workspace.v1", enrollment_digest: testDigest, profile_digest: testDigest, target_scope_digest: testDigest, collector_digest: testDigest, control_digest: testDigest, resource_id: "resource-test", resource_generation: "generation-test", resource_digest: testDigest, probe_enrollment_digest: testDigest, baseline_digest: testDigest, control_revision: 3, mode: "0600", workspace_custody_digest: testDigest, binding_digest: testDigest },
    snapshot: {
      schema_version: "bluefire.macos-file-access-capability-snapshot.v1", platform: "macos", pack: MACOS_FILE_ACCESS_PACK, snapshot_digest: testDigest,
      artifact_context: { environment_digest: testDigest, materialization: "original_workspace_metadata_only", data_class: "generated_public_jsonl" },
      methods: methods.map((id, index) => ({
        ...template, behavior_id: id, action_id: id, parameter_domains: {},
        behavior: { ...template.behavior, id, execution_state: "action", action_ids: [id], platforms: ["macos"], safety_tier: "controlled", capabilities: [index === 2 ? "cleanup" : "filesystem.read"], parameters: [], inputs: index === 0 ? [] : index === 1 ? [probe] : [workspace], outputs: index === 0 ? [probe, workspace] : [{ name: index === 1 ? "verification" : "closure", type: index === 1 ? "artifact.macos_file_access.verification.v1" : "artifact.macos_file_access.attempt_closure.v1", multiple: false }] },
        action: { ...template.action, id, platforms: ["macos"], safety_tier: "controlled", capabilities: [index === 2 ? "cleanup" : "filesystem.read"], parameters: [], mutates: false, cleanup_action_id: index === 2 ? null : methods[2], inputs: index === 0 ? [] : index === 1 ? [probe] : [workspace], outputs: index === 0 ? [probe, workspace] : [{ name: index === 1 ? "verification" : "closure", type: index === 1 ? "artifact.macos_file_access.verification.v1" : "artifact.macos_file_access.attempt_closure.v1", multiple: false }] },
        cost: { schema_version: "bluefire.macos-file-access-method-cost.v1", pack: MACOS_FILE_ACCESS_PACK, method_id: id, cost_digest: testDigest, native_primitive_requests: index === 2 ? 0 : 1, reads: index === 2 ? [] : ["retained_resource"], business_steps: index === 2 ? 0 : 1, maximum_material_file_bytes: 0, retained_metadata_bytes: 128 * 1024, generated_bytes: 0, network_bytes: 0, writes: [], material_directories: [], removes: null },
      })),
    },
  };
}
function macCompositionRequestFixture(): CompositionReviewRequest {
  return { schema_version: "bluefire.composition-review-request.v2", pack: MACOS_FILE_ACCESS_PACK, control_owner_id: macOSOwner, question: "Verify the retained Mac control", limits: null };
}
function macCompositionObjectiveFixture(): CompositionObjective {
  const original = objectiveFixture();
  const review = macCompositionReviewFixture();
  const attempt = attemptFixture(true);
  const checks = Object.fromEntries(["probe_authenticated", "non_owner_denied", "owner_read_verified", "same_resource", "same_control_revision", "same_original_binding", "content_preserved", "requests_closed", "no_attempt_artifacts", "enrollment_retained"].map(key => [key, true]));
  attempt.progress.verified_result = {
    run_id: "run-proof",
    source_binding: { run_id: "run-proof", mode: "execute", finalized_at: "2026-10-16T00:00:00Z", manifest_digest: testDigest, evidence_digest: testDigest, observed_records_digest: testDigest, evidence_count: 3, observed_count: 0, excluded_provenance_counts: { executed: 3 } },
    macos_file_access_result: { probe_verified: true, non_owner_decision: "denied", owner_verified: true, owner_decision: "allowed", resource_digest: testDigest, resource_generation: "generation-test", control_revision: 3, binding_digest: testDigest, sha256: testDigest, record_count: 8, request_closure: "verified_closed", attempt_artifacts: "not_created", workers_retained: true, whole_enrollment_cleanup: false },
    cleanup: { request: "verified_closed", attempt_artifacts: "not_created", workers: "retained", whole_enrollment: false },
    objective: { established: true, checks },
  };
  return {
    ...original, attempts: [attempt], grant: { ...original.grant, document: {
      schema_version: "bluefire.capability-grant.v2", pack: MACOS_FILE_ACCESS_PACK, objective: review.objective, environment: review.environment, limits: review.limits, snapshot: review.snapshot,
      grant_id: original.grant.document.grant_id, grant_digest: testDigest, approved_by: "operator", created_at_ms: 1000, expires_at_ms: 901000,
    } },
  };
}
it("accepts only the closed original Mac review, grant and metadata result shape", () => {
  const review = macCompositionReviewFixture();
  expect(checkedCompositionReview(review, macCompositionRequestFixture())).toBe(review);
  expect(compositionPack(review)).toBe(MACOS_FILE_ACCESS_PACK);
  expect(compositionRequestPack(macCompositionRequestFixture())).toBe(MACOS_FILE_ACCESS_PACK);
  const objective = macCompositionObjectiveFixture();
  expect(checkedCompositionObjective(objective, ownerId, macOSOwner, MACOS_FILE_ACCESS_PACK)).toBe(objective);
  expect(compositionEstablished(objective)).toBe(true);
  expect(compositionCanRevise(objective.attempts[0]!, objective)).toBe(false);
});
it("keeps an authenticated allowed Mac probe unestablished rather than inventing denial", () => {
  const value = macCompositionObjectiveFixture();
  const result = compositionRecord(value.attempts[0]!.progress.verified_result);
  compositionRecord(result.macos_file_access_result).non_owner_decision = "allowed";
  const objective = compositionRecord(result.objective);
  objective.established = false; compositionRecord(objective.checks).non_owner_denied = false;
  expect(checkedCompositionObjective(value, ownerId, macOSOwner, MACOS_FILE_ACCESS_PACK)).toBe(value);
  expect(compositionEstablished(value)).toBe(false);
  expect(compositionCanRevise(value.attempts[0]!, value)).toBe(false);
});
it.each(["pack", "schema", "platform", "method", "parameter", "port", "cost", "control"])("rejects a Mac snapshot/request discriminator mismatch: %s", change => {
  const review = macCompositionReviewFixture();
  if (change === "pack") review.snapshot.pack = FILE_ACCESS_PACK;
  if (change === "schema") review.snapshot.schema_version = "bluefire.file-access-capability-snapshot.v1";
  if (change === "platform") review.snapshot.platform = "linux";
  if (change === "method") review.snapshot.methods[0]!.action_id = "sandbox.cleanup.v1";
  if (change === "parameter") review.snapshot.methods[0]!.parameter_domains = { path: ["arbitrary"] };
  if (change === "port") review.snapshot.methods[1]!.behavior.inputs = [];
  if (change === "cost") review.snapshot.methods[2]!.cost.native_primitive_requests = 1;
  if (change === "control") review.environment.control_owner_id = controlId;
  expect(() => checkedCompositionReview(review, macCompositionRequestFixture())).toThrow();
});
it.each(["decision", "binding", "binding_unestablished", "generation", "run", "source", "cleanup", "workers", "enrollment", "check", "linux_result"])("rejects a malformed Mac result join: %s", change => {
  const value = macCompositionObjectiveFixture();
  const result = compositionRecord(value.attempts[0]!.progress.verified_result);
  const evidence = compositionRecord(result.macos_file_access_result);
  if (change === "decision") evidence.non_owner_decision = "permission_denied";
  if (change === "binding") evidence.binding_digest = `sha256:${"e".repeat(64)}`;
  if (change === "binding_unestablished") {
    evidence.binding_digest = `sha256:${"e".repeat(64)}`;
    compositionRecord(result.objective).established = false;
    compositionRecord(compositionRecord(result.objective).checks).same_original_binding = false;
  }
  if (change === "generation") evidence.resource_generation = "different";
  if (change === "run") result.run_id = "different";
  if (change === "source") compositionRecord(result.source_binding).run_id = "different";
  if (change === "cleanup") compositionRecord(result.cleanup).request = "unknown";
  if (change === "workers") compositionRecord(result.cleanup).workers = "closed";
  if (change === "enrollment") evidence.whole_enrollment_cleanup = true;
  if (change === "check") compositionRecord(compositionRecord(result.objective).checks).requests_closed = false;
  if (change === "linux_result") { result.file_access_result = evidence; delete result.macos_file_access_result; }
  expect(() => checkedCompositionObjective(value, ownerId, macOSOwner, MACOS_FILE_ACCESS_PACK)).toThrow();
});
it("validates Mac refusal control identity and never accepts a Linux response for its pending review", () => {
  const value = refusalFixture();
  value.owner.progress.submitted_request = { ...grantRequestFixture(), review: macCompositionRequestFixture() };
  expect(checkedCompositionObjective(value, ownerId, macOSOwner, MACOS_FILE_ACCESS_PACK)).toBe(value);
  expect(() => checkedCompositionObjective(value, ownerId, macOSOwner, FILE_ACCESS_PACK)).toThrow();
  const submitted = compositionRecord(value.owner.progress.submitted_request);
  compositionRecord(submitted.review).control_owner_id = controlId;
  expect(() => checkedCompositionObjective(value, ownerId, undefined, MACOS_FILE_ACCESS_PACK)).toThrow();
  expect(() => checkedCompositionReview(fileAccessCompositionReviewFixture(), macCompositionRequestFixture())).toThrow();
});
it("retains a Mac pending control separately from job identity and rejects cross-pack control recovery", () => {
  const operation: CompositionPending = { kind: "grant", owner: ownerId, control: macOSOwner, id: ownerId, body: { ...grantRequestFixture(), review: macCompositionRequestFixture() } };
  storeCompositionPending(operation);
  expect(readCompositionPending()).toEqual(operation);
  expect(compositionControlValid(macOSOwner, MACOS_FILE_ACCESS_PACK)).toBe(true);
  expect(compositionControlValid(macOSOwner, FILE_ACCESS_PACK)).toBe(false);
  expect(compositionControlValid(controlId, MACOS_FILE_ACCESS_PACK)).toBe(false);
  clearCompositionPending(operation);
  storeCompositionPending({ ...operation, body: grantRequestFixture() });
  expect(readCompositionPending).toThrow();
});
it("keeps Linux composition semantics and selects only settled hardened file controls", () => {
  const linux = fileAccessObjectiveFixture();
  expect(checkedCompositionObjective(linux, ownerId, controlId, FILE_ACCESS_PACK)).toBe(linux);
  expect(fileAccessCompositionPack(fileAccessControlFixture())).toBe(FILE_ACCESS_PACK);
  expect(fileAccessCompositionPack(macOSControlFixture("hardened"))).toBe(MACOS_FILE_ACCESS_PACK);
  const pendingControl = macOSControlFixture("hardened"); pendingControl.usage_state = "pending";
  expect(fileAccessCompositionPack(pendingControl)).toBeUndefined();
  expect(fileAccessCompositionPack(macOSControlFixture("baseline_verified"))).toBeUndefined();
});
it("keeps noncurrent Mac hardened control history read-only without changing Linux eligibility", () => {
  const mac = macOSControlFixture("hardened");
  mac.allowed_operations = [];
  expect(fileAccessCompositionPack(mac)).toBeUndefined();
  const linux = fileAccessControlFixture();
  linux.allowed_operations = [];
  expect(fileAccessCompositionPack(linux)).toBe(FILE_ACCESS_PACK);
});
it.each(["identity", "extra", "version"])("rejects a noncanonical Mac review request: %s", change => {
  const request = macCompositionRequestFixture();
  if (change === "identity") request.control_owner_id = controlId;
  if (change === "extra") Object.assign(request, { arbitrary_path: "/not-authorized" });
  if (change === "version") Object.assign(request, { schema_version: "bluefire.composition-review-request.v1" });
  expect(() => compositionRequestPack(request)).toThrow();
});
it("keeps Mac proposal-context facts bound to the original pack and control", () => {
  const value = contextFixture();
  const review = macCompositionReviewFixture();
  value.snapshot = review.snapshot;
  value.objective = review.objective;
  value.initial_proposal = null; value.initial_scenario = null;
  value.facts = {
    schema_version: "bluefire.macos-file-access-composition-facts.v1", pack: MACOS_FILE_ACCESS_PACK, grant_id: value.grant_id,
    environment_digest: testDigest, control_digest: testDigest, facts_digest: testDigest, prior_attempt_id: null, prior_graph_digest: null,
    facts: [{ fact_id: "control", kind: "retained_macos_file_control", provenance: "observed", attempt_id: null,
      source: { kind: "control_record", id: macOSOwner, digest: testDigest }, environment_digest: testDigest, control_digest: testDigest,
      value: { control_owner_id: macOSOwner, control_digest: testDigest, resource_id: "resource-test", resource_generation: "generation-test", resource_digest: testDigest, probe_enrollment_digest: testDigest, baseline_digest: testDigest, control_revision: 3, workspace_custody_digest: testDigest, binding_digest: testDigest } }],
  };
  expect(checkedCompositionContext(value, value.grant_id, MACOS_FILE_ACCESS_PACK)).toBe(value);
  value.facts.facts[0]!.kind = "retained_file_control";
  expect(() => checkedCompositionContext(value, value.grant_id, MACOS_FILE_ACCESS_PACK)).toThrow();
});
