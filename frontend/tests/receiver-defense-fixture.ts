import type { ReceiverContext, ReceiverDefenseEnvelope, ReceiverPhase, ReceiverPhaseView, ReceiverPreparation, ReceiverPhaseResult } from "../src/lib/receiver-defense-types";
import type { RunJob, RunRecord, Scenario } from "../src/types";
import { receiverJobId, receiverPhases } from "../src/lib/receiver-defense";

export const receiverFixtureDigest = `sha256:${"a".repeat(64)}`;
export const receiverFixtureSubmission = "10000000-0000-4000-8000-000000000000";
export const receiverFixtureId = receiverJobId(receiverFixtureSubmission);
const sha = "b".repeat(64);
const artifact = { sha256: sha, size_bytes: 120 };
const digest = receiverFixtureDigest;
const submission = (id: string) => ({ schema_version: "bluefire.job-submission.v1", submission_id: id, intent_digest: digest });
const job = (id: string, kind: string, request: Record<string, unknown>): RunJob => ({ schema_version: "bluefire.job.v1", job_id: receiverJobId(id), kind, state: "completed", request: { ...request, _submission: submission(id) }, progress: {}, result_ref: null });

/** Public wire shapes from receiver_defense_view/native and receiver_session_contract.
 * Synthetic data only; this does not stand in for an installed receiver proof.
 */
export function receiverFixture(phase: ReceiverPhase = "baseline", stage: "idle" | "prepared" | "approval" | "completed" | "insufficient" = "prepared"): ReceiverDefenseEnvelope & { context: ReceiverContext } {
  const scenario: Scenario = { schema_version: "bluefire.scenario.v1", id: "receiver-collection", title: "Public record handoff", purpose: "Compare receiver content policies", start: "stage", steps: [
    { id: "stage", behavior_id: "collection.stage.v1", inputs: {}, parameters: { container: "jsonl" }, alternates: [] },
    { id: "handoff", behavior_id: "peer.handoff.v1", inputs: { bundle: { from_step: "stage", artifact: "bundle" } }, parameters: { host: "127.0.0.1", port: 18796 }, alternates: [] },
  ], edges: [{ from_step: "stage", outcome: "success", to_step: "handoff" }], provenance: { source: "authored" }, limitations: ["Synthetic public records in an owned loopback receiver."] };
  const run_intent = { mode: "execute" as const, autonomy: "off" as const, ai_provider_id: null, runner_profile_id: "owned-lab", target_scope: { scope_refs: ["owned-lab"] }, collectors: [] };
  const selection = { kind: "saved_scenario" as const, scenario_id: scenario.id, version: 1, digest };
  const context: ReceiverContext = {
    schema_version: "bluefire.receiver-defense-context.v1", selection, run_intent, context_digest: digest, scenario, scenario_title: scenario.title,
    eligible: true, reasons: [], handoff: { stage_step_id: "stage", handoff_step_id: "handoff", port: 18796, artifact_type: "artifact.sandbox.bundle.v1", container: "jsonl" },
    policies: [
      { policy_id: "receiver.reviewed-records.v1", title: "Accept reviewed synthetic records", description: "Accept public records", digest },
      { policy_id: "receiver.redacted-only.v1", title: "Require redacted records", description: "Refuse retained records", digest: `sha256:${"c".repeat(64)}` },
    ], availability: { supported: true, ready: true, reason: null, native_path: null }, limitations: scenario.limitations,
  };
  const parent = job(receiverFixtureSubmission, "receiver.defense", { submitted_request: { selection, run_intent, submission_id: receiverFixtureSubmission, context_digest: digest }, context, context_digest: digest });
  const reservations: Record<string, unknown> = {};
  const admission = { accepted: true, problem: null };
  parent.progress = { phases: reservations, attempt_history: [], admission };
  const selectedIndex = receiverPhases.indexOf(phase);
  const phases: ReceiverPhaseView[] = receiverPhases.map((name, index) => {
    const policy = context.policies[index === 1 ? 1 : 0]!;
    const current: ReceiverPhaseView = { phase: name, policy_id: policy.policy_id, status: "not_started", prepare_allowed: index === selectedIndex, review_ready: false, receiver_job: null, preparation: null, decision: null, execution_job: null, result: null, cleanup: { receiver: "not_started", run: "not_started" }, problem: null, attempts: [] };
    if (index > selectedIndex || (index === selectedIndex && stage === "idle")) return current;
    const prepareId = `20000000-0000-4000-8000-00000000000${index}`;
    const executionId = `30000000-0000-5000-8000-00000000000${index}`;
    const request = { submission_id: prepareId, phase: name, reviewed_by: "operator" };
    const marker = { parent_job_id: parent.job_id, receiver_job_id: receiverJobId(prepareId), phase: name };
    const child = job(prepareId, "receiver.defense.prepare", { submitted_request: request, receiver_defense: marker });
    reservations[name] = { receiver_job_id: child.job_id, prepare_request: request };
    const session: ReceiverPreparation["session"] = { schema_version: "bluefire.owned-receiver-session.v1", launch_id: `launch-${index}`, worker_generation: `generation-${index}`,
      policy: { schema_version: "bluefire.receiver-content-policy.v1", policy_id: policy.policy_id, authentication: "managed_task_hmac_sha256", schema: "strict_public_synthetic_jsonl", maximum_bytes: 1048576, maximum_records: 100, accepted_records: index === 1 ? "every_record_explicitly_redacted" : "reviewed_public_values" }, policy_digest: policy.digest, host: "127.0.0.1", port: 18796, receiver_session_id: `session-${index}`, receiver_process_id: 900 + index,
      creation_identity: `owned-generation-${index}`, deadline_ns: 999999999999999, expires_at_ms: Date.now() + 240000, maximum_bytes: 1048576, maximum_decisions: 1, storage: "memory_only", review_digest: digest };
    const preflight = { ready: false, status: "approval_required", runner_profile: run_intent.runner_profile_id, scope: run_intent.target_scope, plan: { autonomy: "off" }, problems: ["Explicit operator approval is required."] };
    const replayRequest = { exact: false, autonomy: "off", runner_profile_id: run_intent.runner_profile_id, target_scope: run_intent.target_scope, defense_change: `Owned receiver content policy: ${policy.policy_id}` };
    const preparation: ReceiverPreparation = { schema_version: "bluefire.receiver-defense-preparation.v1", ...marker, context_digest: digest, preparation_digest: digest, session,
      execution_kind: index === 0 ? "scenario.run" : "scenario.replay", run_request: index === 0 ? { scenario, ...run_intent } : null,
      replay_preparation: index === 0 ? null : { schema_version: "bluefire.replay-preparation.v1", preparation_id: `replay-${index}`, preparation_context: { source: digest }, binding: { source: { run_id: "run-baseline" }, replay_request: replayRequest }, replay_request: replayRequest, replay_extent: "full", scenario, lineage: {}, preflight, approval_created: false, effects_started: false },
      preflight, baseline_artifact: index === 0 ? null : artifact, approval_created: false, target_effects_started: false, receiver_started: true };
    child.progress = { session, preparation };
    Object.assign(current, { receiver_job: child, preparation, status: "review_ready", review_ready: true, prepare_allowed: false, cleanup: { receiver: "active", run: "not_started" } });
    if (index === selectedIndex && stage === "prepared") return current;
    const decision = { submission_id: `40000000-0000-4000-8000-00000000000${index}`, phase: name, preparation_digest: digest, decision: "accept" as const, reviewed_by: "operator" };
    const execution = job(executionId, preparation.execution_kind, { receiver_defense: marker, ...(index === 0 ? { _run_submission_request: preparation.run_request } : { replay_request: replayRequest, replay_preparation: preparation.replay_preparation }) });
    child.progress = { ...child.progress, decision, execution_submission_id: executionId, execution_job_id: execution.job_id };
    Object.assign(current, { decision, execution_job: execution, status: "awaiting_approval", review_ready: false });
    execution.state = "awaiting_approval";
    if (index === selectedIndex && stage === "approval") return current;
    const task = { task_id: `task-${index}`, ...artifact };
    const refused = index === 1;
    const runId = index === 0 ? "run-baseline" : `run-${name}`;
    const run = { run_id: runId, scenario, mode: "execute", finalized_at: "2026-09-07T12:00:00Z", manifest: { run_id: runId }, plan: { autonomy: "off" }, evidence: { records: [] }, cleanup: { success: true, outstanding_receipt_count: 0 } } as unknown as RunRecord;
    const observed = { schema_version: "bluefire.owned-receiver-observation.v1", state: "verified", review_binding: session,
      task_binding: { kind: "bind", review_digest: digest, ...task }, process_exit: { returncode: 0, process_id: session.receiver_process_id, creation_identity: session.creation_identity },
      terminal: { kind: "terminal", review_digest: digest, task_digest: digest, summary: { schema_version: "bluefire.loopback-receiver-summary.v1", reason: "content_policy_decision", connections_handled: 2, challenges_issued: 1, requests_accepted: refused ? 0 : 1, requests_refused: refused ? 1 : 0 },
        decision: { schema_version: "bluefire.receiver-content-decision.v1", task_id: task.task_id, receiver_session_id: session.receiver_session_id, receiver_process_id: session.receiver_process_id,
          authenticated: true, policy_id: policy.policy_id, policy_digest: policy.digest, sha256: sha, bytes_received: artifact.size_bytes, decision: refused ? "policy_refused" : "accepted", reason: refused ? "records_not_all_redacted" : "reviewed_content",
          semantics: { container: "jsonl", record_count: 2, retained_record_count: 1, redacted_record_count: 1, empty_record_count: 0 } } } };
    const result: ReceiverPhaseResult = { phase: name, policy_id: policy.policy_id, preparation_job_id: child.job_id, execution_job_id: execution.job_id, execution_kind: preparation.execution_kind,
      run_id: runId, run, source_binding: { run_id: runId, mode: "execute", finalized_at: run.finalized_at, manifest_digest: digest, evidence_digest: digest, observed_records_digest: digest, evidence_count: 0, observed_count: 0, excluded_provenance_counts: {} },
      receiver_observation: observed, decision: refused ? "policy_refused" : "accepted", artifact, cleanup: { receiver: "verified_closed", run: "complete" } };
    if (index === selectedIndex && stage === "insufficient") {
      result.decision = "insufficient_evidence";
      result.receiver_observation = { schema_version: "bluefire.owned-receiver-observation.v1", state: "insufficient_evidence", reason: "Exact terminal unavailable" };
      result.artifact = null;
      result.cleanup = { receiver: "uncertain", run: "incomplete" };
    }
    child.progress = { ...child.progress, task_binding: task, receiver_closed: result.cleanup.receiver === "verified_closed", result };
    execution.state = "completed";
    execution.result_ref = runId;
    Object.assign(current, { result, status: result.decision === "insufficient_evidence" ? "failed" : "completed", cleanup: result.cleanup });
    return current;
  });
  const chosen = phases[selectedIndex]!;
  return { schema_version: "bluefire.receiver-defense.v1", job: parent, context, admission, phases, status: stage === "insufficient" ? "blocked" : phase === "restored" && stage === "completed" ? "completed" : "active",
    next_action: { kind: stage === "approval" ? "approve_execute" : stage === "prepared" ? "review_replay" : stage === "idle" ? "prepare_receiver" : stage === "insufficient" ? "cleanup_required" : "completed", phase, native_path: stage === "approval" ? `/runs?job=${chosen.execution_job!.job_id}` : null }, can_start_new_test: stage === "completed" || stage === "insufficient", limitations: context.limitations };
}
