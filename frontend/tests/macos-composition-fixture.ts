import type { CompositionContext, CompositionObjective, CompositionReview, CompositionReviewRequest } from "../src/lib/composition";
import type { ScenarioStep } from "../src/types";
import { macOSControlFixture, macOSOwner } from "./macos-file-access-fixture";
import { attemptFixture, contextFixture, objectiveFixture, reviewFixture, testDigest } from "./composition-fixture";

const MACOS_FILE_ACCESS_PACK = "bluefire.macos-file-access-pack.v1";

// Authored presentation contracts only; no native workspace or access proof.
export function macReviewFixture(): CompositionReview {
  const original = reviewFixture();
  const template = original.snapshot.methods[0]!;
  const control = macOSControlFixture("hardened");
  const methods = ["macos.file_access.probe.v1", "macos.file_access.verify_owner.v1", "macos.file_access.close_attempt.v1"];
  const probe = { name: "probe", type: "artifact.macos_file_access.probe.v1", multiple: false, required: true };
  const workspace = { name: "workspace", type: "artifact.macos_file_access.attempt.v1", multiple: false, required: true };
  return {
    ...original, schema_version: "bluefire.composition-review.v2", pack: MACOS_FILE_ACCESS_PACK,
    objective: { question: "Verify the retained Mac control", predicate: { kind: "non_owner_denied_owner_preserves_records", record_count: 8, data_class: "generated_public_jsonl", sha256: control.resource.sha256 } },
    environment: { environment_id: "environment-test", environment_generation: control.resource.resource_generation, control_owner_id: macOSOwner, runner_id: "bluefire-macos-workspace.v1", enrollment_digest: testDigest, profile_digest: testDigest, target_scope_digest: testDigest, collector_digest: testDigest, control_digest: control.control_digest, resource_id: control.resource.resource_id, resource_generation: control.resource.resource_generation, resource_digest: testDigest, probe_enrollment_digest: testDigest, baseline_digest: control.baseline!.baseline_digest, control_revision: control.revision, mode: "0600", workspace_custody_digest: testDigest, binding_digest: testDigest },
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

export function macRequestFixture(): CompositionReviewRequest {
  return { schema_version: "bluefire.composition-review-request.v2", pack: MACOS_FILE_ACCESS_PACK, control_owner_id: macOSOwner, question: "Verify the retained Mac control", limits: null };
}

export function macObjectiveFixture(outcome: "none" | "settled" | "unknown" = "none"): CompositionObjective {
  const original = objectiveFixture();
  const review = macReviewFixture();
  const value: CompositionObjective = { ...original, grant: { ...original.grant, document: {
    schema_version: "bluefire.capability-grant.v2", pack: MACOS_FILE_ACCESS_PACK, objective: review.objective, environment: review.environment, limits: review.limits, snapshot: review.snapshot,
    grant_id: original.grant.document.grant_id, grant_digest: testDigest, approved_by: "operator", created_at_ms: Date.now(), expires_at_ms: Date.now() + 900000,
  } } };
  if (outcome === "none") return value;
  const attempt = attemptFixture(true);
  if (outcome === "unknown") {
    attempt.state = "failed";
    attempt.progress = { phase: "attempt_completed", settlement: "pending_cleanup", finalized_run_id: "run-proof", macos_file_access_request_state: "unknown", verified_result_problem: "The original owner request is unknown." };
  } else {
    const checks = Object.fromEntries(["probe_authenticated", "non_owner_denied", "owner_read_verified", "same_resource", "same_control_revision", "same_original_binding", "content_preserved", "requests_closed", "no_attempt_artifacts", "enrollment_retained"].map(key => [key, true]));
    attempt.progress.verified_result = {
      run_id: "run-proof",
      source_binding: { run_id: "run-proof", mode: "execute", finalized_at: "2026-10-16T00:00:00Z", manifest_digest: testDigest, evidence_digest: testDigest, observed_records_digest: testDigest, evidence_count: 3, observed_count: 0 },
      macos_file_access_result: { probe_verified: true, non_owner_decision: "denied", owner_verified: true, owner_decision: "allowed", resource_digest: testDigest, resource_generation: review.environment.resource_generation, control_revision: 3, binding_digest: testDigest, sha256: review.objective.predicate.sha256, record_count: 8, request_closure: "verified_closed", attempt_artifacts: "not_created", workers_retained: true, whole_enrollment_cleanup: false },
      cleanup: { request: "verified_closed", attempt_artifacts: "not_created", workers: "retained", whole_enrollment: false }, objective: { established: true, checks },
    };
  }
  value.attempts = [attempt];
  return value;
}

export function macContextFixture(): CompositionContext {
  const value = contextFixture();
  const review = macReviewFixture();
  const ids = ["probe", "owner", "close"];
  const steps = review.snapshot.methods.map((method, index): ScenarioStep => ({ id: ids[index]!, behavior_id: method.behavior_id, parameters: {}, inputs: index === 1 ? { probe: { from_step: "probe", artifact: "probe" } } : index === 2 ? { workspace: { from_step: "probe", artifact: "workspace" } } : {}, alternates: [] }));
  const edges = (["success", "partial", "failed", "blocked"] as const).flatMap(outcome => [{ from_step: "probe", outcome, to_step: "owner" }, { from_step: "owner", outcome, to_step: "close" }]);
  return { ...value, objective: review.objective, snapshot: review.snapshot,
    facts: { schema_version: "bluefire.macos-file-access-composition-facts.v1", pack: MACOS_FILE_ACCESS_PACK, grant_id: value.grant_id, prior_attempt_id: null, prior_graph_digest: null, facts_digest: testDigest, environment_digest: testDigest, control_digest: review.environment.control_digest,
      facts: [{ fact_id: "control", kind: "retained_macos_file_control", provenance: "observed", attempt_id: null, control_digest: review.environment.control_digest, environment_digest: testDigest, source: { kind: "control_record", id: macOSOwner, digest: review.environment.control_digest }, value: { ...review.environment } }] },
    initial_proposal: { schema_version: "bluefire.composition-proposal.v1", title: "Original Mac access graph", start: "probe", steps: steps.map(({ id, behavior_id, parameters }) => ({ id, behavior_id, parameters })), edges, rationale: "Read through the original workers and close only this attempt's requests.", evidence_refs: ["control"] },
    initial_scenario: { ...value.initial_scenario!, id: "mac-access-test", title: "Original Mac access graph", start: "probe", steps, edges },
  };
}
