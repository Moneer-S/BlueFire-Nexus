import type { ReceiverAttempt, ReceiverContext, ReceiverContextRequest, ReceiverDecision, ReceiverDefenseEnvelope, ReceiverPhase, ReceiverPhaseView } from "./receiver-defense-types";
import type { RunJob } from "../types";
import { sameJson } from "./replay-review";

export const receiverPhases: ReceiverPhase[] = ["baseline", "protected", "restored"];
export const phaseTitle = { baseline: "Baseline", protected: "Redaction required", restored: "Prior policy restored" };
export const policyTitle = { "receiver.reviewed-records.v1": "Accept reviewed synthetic records", "receiver.redacted-only.v1": "Require redacted records" };
export const receiverJobId = (submission: string) => `job-${submission.replaceAll("-", "")}`;
export const receiverJobValid = (value: string) => /^job-[0-9a-f]{32}$/.test(value);
const digest = (value: unknown) => typeof value === "string" && /^sha256:[0-9a-f]{64}$/.test(value);
const uuid = (value: unknown): value is string => typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value);
const record = (value: unknown): Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
const fail = () => { throw new Error("The control test response does not match its saved review. Refresh its status before continuing."); };

function checkedSubmission(job: RunJob, submissionId: unknown) {
  const submission = record(job.request?._submission);
  if (!uuid(submissionId) || job.job_id !== receiverJobId(submissionId) || submission.schema_version !== "bluefire.job-submission.v1" ||
    submission.submission_id !== submissionId || !digest(submission.intent_digest)) fail();
}

function checkedObservation(attempt: ReceiverAttempt) {
  const result = attempt.result!;
  const session = attempt.preparation!.session;
  const observed = result.receiver_observation;
  if (observed.schema_version !== "bluefire.owned-receiver-observation.v1") fail();
  // Incomplete observations are useful historical evidence, never prevention.
  if (result.decision === "insufficient_evidence") return;
  const task = record(attempt.receiver_job!.progress.task_binding);
  const terminal = record(observed.terminal);
  const decision = record(terminal.decision);
  const summary = record(terminal.summary);
  const exit = record(observed.process_exit);
  const semantics = record(decision.semantics);
  const counts = [semantics.retained_record_count, semantics.redacted_record_count, semantics.empty_record_count];
  if (observed.state !== "verified" || !sameJson(observed.review_binding, session) ||
    !sameJson(observed.task_binding, { kind: "bind", review_digest: session.review_digest, ...task }) ||
    typeof task.task_id !== "string" || typeof task.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(task.sha256) ||
    !Number.isInteger(task.size_bytes) || Number(task.size_bytes) < 1 || Number(task.size_bytes) > session.maximum_bytes ||
    terminal.kind !== "terminal" || terminal.review_digest !== session.review_digest || !digest(terminal.task_digest) ||
    exit.returncode !== 0 || exit.process_id !== session.receiver_process_id || exit.creation_identity !== session.creation_identity ||
    decision.schema_version !== "bluefire.receiver-content-decision.v1" || decision.authenticated !== true ||
    decision.task_id !== task.task_id || decision.sha256 !== task.sha256 || decision.bytes_received !== task.size_bytes ||
    decision.receiver_session_id !== session.receiver_session_id || decision.receiver_process_id !== session.receiver_process_id ||
    decision.policy_id !== attempt.policy_id || decision.policy_digest !== session.policy_digest || decision.decision !== result.decision ||
    summary.schema_version !== "bluefire.loopback-receiver-summary.v1" || summary.reason !== "content_policy_decision" ||
    [summary.connections_handled, summary.challenges_issued, summary.requests_accepted, summary.requests_refused].some((count) => !Number.isInteger(count) || Number(count) < 0 || Number(count) > 8) ||
    Number(summary.connections_handled) < 2 || Number(summary.challenges_issued) < 1 ||
    summary.requests_accepted !== (result.decision === "accepted" ? 1 : 0) || (result.decision === "policy_refused" && Number(summary.requests_refused) < 1) ||
    semantics.container !== "jsonl" || !Number.isInteger(semantics.record_count) || Number(semantics.record_count) < 1 || Number(semantics.record_count) > 100 ||
    counts.some((count) => !Number.isInteger(count) || Number(count) < 0 || Number(count) > 100) ||
    counts.reduce<number>((sum, count) => sum + Number(count), 0) !== semantics.record_count ||
    !sameJson(result.artifact, { sha256: task.sha256, size_bytes: task.size_bytes })) fail();
  const accepted = attempt.policy_id === "receiver.reviewed-records.v1" || semantics.redacted_record_count === semantics.record_count;
  if (result.decision !== (accepted ? "accepted" : "policy_refused") || decision.reason !== (accepted ? "reviewed_content" : "records_not_all_redacted")) fail();
}

function checkedAttempt(value: ReceiverDefenseEnvelope & { context: ReceiverContext }, attempt: ReceiverAttempt, reservation: unknown) {
  const child = attempt.receiver_job;
  if (!child) {
    if (attempt.preparation || attempt.decision || attempt.execution_job || attempt.result) fail();
    return; // A reserved but unpublished preparation can legitimately be interrupted.
  }
  const retained = record(reservation);
  const request = record(retained.prepare_request);
  const marker = { parent_job_id: value.job.job_id, receiver_job_id: child.job_id, phase: attempt.phase };
  checkedSubmission(child, request.submission_id);
  if (child.kind !== "receiver.defense.prepare" || retained.receiver_job_id !== child.job_id || request.phase !== attempt.phase ||
    !sameJson(child.request?.submitted_request, request) || !sameJson(child.request?.receiver_defense, marker) ||
    !sameJson(child.progress.preparation ?? null, attempt.preparation) || !sameJson(child.progress.decision ?? null, attempt.decision) ||
    !sameJson(child.progress.result ?? null, attempt.result)) fail();
  const prep = attempt.preparation;
  if (prep) {
    const policy = value.context.policies.find((item) => item.policy_id === attempt.policy_id);
    if (!policy || prep.session.policy.policy_id !== attempt.policy_id || prep.session.policy_digest !== policy.digest ||
      !sameJson(prep.session, child.progress.session) || prep.session.port !== value.context.handoff?.port || !digest(prep.session.review_digest)) fail();
    if (attempt.phase === "baseline") {
      if (!sameJson(prep.run_request, { scenario: value.context.scenario, ...value.context.run_intent }) || prep.replay_preparation !== null || prep.baseline_artifact !== null) fail();
    } else if (prep.run_request !== null || !prep.replay_preparation || !sameJson(prep.baseline_artifact, value.phases[0]?.result?.artifact) ||
      prep.replay_preparation.binding?.source?.run_id !== value.phases[0]?.result?.run_id) fail();
  }
  if (attempt.decision && (!uuid(attempt.decision.submission_id) || !["accept", "reject"].includes(attempt.decision.decision) || !attempt.decision.reviewed_by?.trim())) fail();
  const execution = attempt.execution_job;
  if (execution) {
    checkedSubmission(execution, child.progress.execution_submission_id);
    if (!prep || attempt.decision?.decision !== "accept" || execution.job_id !== child.progress.execution_job_id || execution.kind !== prep.execution_kind ||
      !sameJson(execution.request?.receiver_defense, marker)) fail();
    if (prep!.execution_kind === "scenario.run" && !sameJson(execution.request?._run_submission_request, prep!.run_request)) fail();
    if (prep!.execution_kind === "scenario.replay" && (!sameJson(execution.request?.replay_request, prep!.replay_preparation?.replay_request) ||
      !sameJson(execution.request?.replay_preparation, prep!.replay_preparation))) fail();
  }
  const result = attempt.result;
  if (result) {
    const run = record(result.run);
    const source = result.source_binding;
    const evidence = record(run.evidence).records;
    if (!sameJson(attempt.cleanup, result.cleanup) || (execution?.result_ref != null && execution.result_ref !== result.run_id) ||
      (result.decision !== "insufficient_evidence" && prep!.baseline_artifact !== null && !sameJson(result.artifact, prep!.baseline_artifact)) ||
      source.run_id !== result.run_id || source.mode !== run.mode || source.finalized_at !== run.finalized_at ||
      typeof run.finalized_at !== "string" || !Array.isArray(evidence) || source.evidence_count !== evidence.length ||
      source.observed_count !== evidence.filter((item) => record(item).provenance === "observed").length ||
      !digest(source.manifest_digest) || !digest(source.evidence_digest) || !digest(source.observed_records_digest) ||
      record(run.manifest).run_id !== result.run_id || run.mode !== "execute" || record(run.plan).autonomy !== "off" ||
      !sameJson(run.scenario, prep!.run_request?.scenario ?? prep!.replay_preparation?.scenario)) fail();
    checkedObservation(attempt);
  }
}

export function checkedReceiverContext(value: ReceiverContext, request?: ReceiverContextRequest): ReceiverContext {
  if (value?.schema_version !== "bluefire.receiver-defense-context.v1" || !digest(value.context_digest) ||
    value.selection?.kind !== "saved_scenario" || !digest(value.selection.digest) || !Number.isInteger(value.selection.version) || value.selection.version < 1 ||
    value.scenario?.id !== value.selection.scenario_id || !Array.isArray(value.reasons) || !Array.isArray(value.policies) || !Array.isArray(value.limitations) ||
    typeof value.eligible !== "boolean" || typeof value.availability?.ready !== "boolean" || typeof value.availability?.supported !== "boolean" ||
    (request && (!sameJson(value.selection, request.selection) || !sameJson(value.run_intent, request.run_intent)))) fail();
  if (value.eligible && (value.run_intent.mode !== "execute" || !value.handoff || value.handoff.container !== "jsonl" || value.handoff.artifact_type !== "artifact.sandbox.bundle.v1")) fail();
  return value;
}

export function checkedReceiverTest(value: ReceiverDefenseEnvelope, id: string): ReceiverDefenseEnvelope {
  if (value?.schema_version !== "bluefire.receiver-defense.v1" || value.job?.job_id !== id || value.job.kind !== "receiver.defense" ||
    !Array.isArray(value.phases) || value.phases.length !== 3 || !Array.isArray(value.limitations) ||
    !["active", "completed", "blocked", "stopping", "stopped"].includes(value.status) ||
    !["prepare_receiver", "review_replay", "approve_execute", "wait", "cleanup_required", "completed", "stopped"].includes(value.next_action?.kind)) fail();
  const submitted = record(value.job.request?.submitted_request);
  checkedSubmission(value.job, submitted.submission_id);
  const selection = record(submitted.selection);
  if (selection.kind !== "saved_scenario" || typeof selection.scenario_id !== "string" || !selection.scenario_id ||
    !Number.isInteger(selection.version) || Number(selection.version) < 1 || !digest(selection.digest)) fail();
  const admission = value.admission;
  if (typeof admission?.accepted !== "boolean" || !sameJson(admission, value.job.progress.admission) ||
    !sameJson(Object.keys(admission).sort(), ["accepted", "problem"]) ||
    (admission.problem !== null && (admission.accepted || typeof admission.problem?.code !== "string" || !admission.problem.code || typeof admission.problem.message !== "string" || !admission.problem.message))) fail();
  if (admission.accepted && value.job.state !== "completed") fail();
  if (!digest(submitted.context_digest) || value.job.request?.context_digest !== submitted.context_digest ||
    !sameJson(Object.keys(submitted).sort(), ["context_digest", "run_intent", "selection", "submission_id"]) ||
    !sameJson(value.job.request?.context, value.context)) fail();
  const refused = !admission.accepted && admission.problem !== null;
  if (refused && (value.job.state !== "failed" || !["blocked", "stopped"].includes(value.status))) fail();
  if (value.context === null) {
    if (!refused) fail();
  } else {
    checkedReceiverContext(value.context, { selection: submitted.selection, run_intent: submitted.run_intent } as ReceiverContextRequest);
    if (!refused && value.context.context_digest !== submitted.context_digest) fail();
  }
  if (!admission.accepted) {
    if (Object.keys(record(value.job.progress.phases)).length || (Array.isArray(value.job.progress.attempt_history) && value.job.progress.attempt_history.length) ||
      !["wait", "stopped"].includes(value.next_action.kind) || value.next_action.native_path !== null || value.status === "completed" ||
      (value.next_action.phase !== null && !receiverPhases.includes(value.next_action.phase)) ||
      value.phases.some((phase, index) => phase.phase !== receiverPhases[index] || phase.policy_id !== (index === 1 ? "receiver.redacted-only.v1" : "receiver.reviewed-records.v1") ||
        phase.prepare_allowed !== false || phase.review_ready !== false || phase.receiver_job !== null || phase.preparation !== null || phase.decision !== null ||
        phase.execution_job !== null || phase.result !== null || !Array.isArray(phase.attempts) || phase.attempts.length ||
        !sameJson(phase.cleanup, { receiver: "not_started", run: "not_started" }))) fail();
    return value;
  }
  if (!value.context) fail();
  const admitted = value as ReceiverDefenseEnvelope & { context: ReceiverContext };
  value.phases.forEach((phase, index) => {
    if (phase.phase !== receiverPhases[index] || phase.policy_id !== (index === 1 ? "receiver.redacted-only.v1" : "receiver.reviewed-records.v1") ||
      typeof phase.prepare_allowed !== "boolean" || typeof phase.review_ready !== "boolean" || !Array.isArray(phase.attempts)) fail();
    for (const attempt of [...phase.attempts, phase]) {
      if (attempt.phase !== phase.phase || attempt.policy_id !== phase.policy_id || !attempt.cleanup) fail();
      const prep = attempt.preparation;
      if (prep && (prep.schema_version !== "bluefire.receiver-defense-preparation.v1" || prep.parent_job_id !== id || prep.phase !== phase.phase ||
        prep.context_digest !== admitted.context.context_digest || !digest(prep.preparation_digest) || prep.receiver_job_id !== attempt.receiver_job?.job_id ||
        prep.approval_created !== false || prep.target_effects_started !== false || prep.receiver_started !== true ||
        prep.session?.schema_version !== "bluefire.owned-receiver-session.v1" || prep.session.host !== "127.0.0.1" || prep.session.maximum_decisions !== 1 ||
        prep.session.storage !== "memory_only" || !Number.isFinite(prep.session.expires_at_ms) || !digest(prep.session.policy_digest) ||
        prep.execution_kind !== (index === 0 ? "scenario.run" : "scenario.replay"))) fail();
      if (attempt.decision && (!prep || attempt.decision.phase !== phase.phase || attempt.decision.preparation_digest !== prep.preparation_digest)) fail();
      const result = attempt.result;
      if (result && (!prep || !attempt.execution_job || result.phase !== phase.phase || result.policy_id !== phase.policy_id || result.preparation_job_id !== prep.receiver_job_id ||
        result.execution_job_id !== attempt.execution_job.job_id || result.execution_kind !== prep.execution_kind || result.run_id !== result.run?.run_id ||
        !["accepted", "policy_refused", "insufficient_evidence"].includes(result.decision))) fail();
      const history = value.job.progress.attempt_history;
      const reservation = attempt === phase ? record(value.job.progress.phases)[phase.phase] :
        (Array.isArray(history) ? history : []).find((item) => record(item).phase === phase.phase && record(item).receiver_job_id === attempt.receiver_job?.job_id);
      checkedAttempt(admitted, attempt, reservation);
    }
  });
  if (value.next_action.phase !== null && !receiverPhases.includes(value.next_action.phase)) fail();
  if (value.next_action.kind === "approve_execute") {
    const phase = value.phases.find((item) => item.phase === value.next_action.phase);
    if (!phase?.execution_job || phase.execution_job.state !== "awaiting_approval" || value.next_action.native_path !== `/runs?job=${phase.execution_job.job_id}`) fail();
  }
  return value;
}

export type ReceiverPending =
  | { kind: "create"; id: string; body: ReceiverContextRequest & { submission_id: string; context_digest: string } }
  | { kind: "prepare"; id: string; body: { submission_id: string; phase: ReceiverPhase; reviewed_by: string } }
  | { kind: "review"; id: string; body: ReceiverDecision };
const pendingKey = "bluefire.receiver-defense.pending.v1";
export function readReceiverPending(): ReceiverPending | undefined {
  const raw = sessionStorage.getItem(pendingKey);
  if (!raw) return undefined;
  try {
    if (raw.length > 64000) throw new Error();
    const value = JSON.parse(raw) as ReceiverPending;
    if (!["create", "prepare", "review"].includes(value.kind) || !receiverJobValid(value.id) ||
      typeof value.body?.submission_id !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value.body.submission_id)) throw new Error();
    if (value.kind === "create" ? receiverJobId(value.body.submission_id) !== value.id || !digest(value.body.context_digest) || !value.body.selection || !value.body.run_intent :
      !receiverPhases.includes(value.body.phase) || typeof value.body.reviewed_by !== "string" || !value.body.reviewed_by.trim()) throw new Error();
    if (value.kind === "review" && (!digest(value.body.preparation_digest) || !["accept", "reject"].includes(value.body.decision))) throw new Error();
    return value;
  } catch { throw new Error("The saved control-test request could not be read. Use the retained test in Runs to check its status before starting another."); }
}
export function storeReceiverPending(value: ReceiverPending) {
  const raw = JSON.stringify(value);
  sessionStorage.setItem(pendingKey, raw);
  if (sessionStorage.getItem(pendingKey) !== raw) throw new Error("The request could not be retained. Restore browser storage before submitting it.");
}
export function receiverRequestConfirmed(value: ReceiverDefenseEnvelope, pending: ReceiverPending): boolean {
  if (value.job.job_id !== pending.id) return false;
  if (pending.kind === "create") {
    // A rejected first submission is still a durable receipt. Validate its
    // no-effects shape before allowing the exact saved request to be cleared.
    try { checkedReceiverTest(value, pending.id); } catch { return false; }
    return sameJson(value.job.request?.submitted_request, pending.body) &&
      ((!value.admission.accepted && value.admission.problem !== null) || (value.context?.context_digest === pending.body.context_digest && sameJson(value.context.selection, pending.body.selection) && sameJson(value.context.run_intent, pending.body.run_intent)));
  }
  const phase = value.phases.find((item) => item.phase === pending.body.phase);
  return Boolean(phase && [...phase.attempts, phase].some((attempt) => pending.kind === "prepare"
    ? attempt.receiver_job?.job_id === receiverJobId(pending.body.submission_id) && sameJson(attempt.receiver_job.request?.submitted_request, pending.body) &&
      sameJson(attempt.receiver_job.request?.receiver_defense, { parent_job_id: pending.id, receiver_job_id: receiverJobId(pending.body.submission_id), phase: pending.body.phase })
    : sameJson(attempt.decision, pending.body)));
}
export function clearReceiverPending(pending: ReceiverPending) {
  if (!sameJson(readReceiverPending(), pending)) throw new Error("The retained request changed in another view. Refresh before continuing.");
  sessionStorage.removeItem(pendingKey);
  if (sessionStorage.getItem(pendingKey) !== null) throw new Error("The confirmed request could not be cleared. Refresh its saved status.");
}
export function receiverOutcome(phase: ReceiverPhaseView) {
  return phase.result?.decision === "accepted" ? "Accepted by the receiver" : phase.result?.decision === "policy_refused" ? "Prevented by the receiver" :
    phase.result?.decision === "insufficient_evidence" ? "Not enough evidence" : phase.status === "not_started" ? "Not run" : phase.status.replaceAll("_", " ");
}
