import { receiverFixture, receiverFixtureDigest } from "./receiver-defense-fixture";
import type { ReceiverControlPolicy, ReceiverRetainedControl } from "../src/lib/receiver-defense-types";

const record = (value: unknown) => value as Record<string, unknown>;

export function retainedReceiverFixture(phase: "baseline" | "protected" | "legitimate" = "legitimate", stage: "idle" | "prepared" | "approval" | "completed" | "insufficient" = "completed", linked = false) {
  const value = structuredClone(receiverFixture(phase === "legitimate" ? "restored" : phase, stage));
  const context = value.context;
  const descriptor: ReceiverControlPolicy = {
    schema_version: "bluefire.receiver-control.v1", policy_id: "receiver.redacted-only.v1", policy_digest: context.policies[1]!.digest,
    control_digest: `sha256:${"d".repeat(64)}`, redaction_step_id: "transform",
    scope: { selection: context.selection, run_intent: context.run_intent, profile_digest: receiverFixtureDigest, catalog_binding: {}, collector_binding: {} },
  };
  context.schema_version = "bluefire.receiver-defense-context.v2";
  context.workflow = "retained_redaction";
  context.control = descriptor;
  context.scenario.steps.splice(1, 0, { id: "transform", behavior_id: "collection.transform.v1", inputs: { bundle: { from_step: "stage", artifact: "bundle" } }, parameters: { redact_values: false }, alternates: [] });
  value.schema_version = "bluefire.receiver-defense.v2";
  record(value.job.request!.submitted_request).workflow = "retained_redaction";
  if (value.next_action.phase === "restored") value.next_action.phase = "legitimate";
  const baseline = value.phases[0]!.result;
  for (const current of value.phases) {
    if (current.phase === "restored") {
      current.phase = "legitimate";
      current.policy_id = descriptor.policy_id;
      const reservations = record(value.job.progress.phases);
      if (reservations.restored) {
        reservations.legitimate = reservations.restored;
        record(record(reservations.legitimate).prepare_request).phase = "legitimate";
        delete reservations.restored;
      }
      if (current.receiver_job) {
        record(current.receiver_job.request!.receiver_defense).phase = "legitimate";
        record(current.receiver_job.request!.submitted_request).phase = "legitimate";
      }
      if (current.decision) current.decision.phase = "legitimate";
      if (current.execution_job) record(current.execution_job.request!.receiver_defense).phase = "legitimate";
    }
    const prep = current.preparation;
    if (!prep) continue;
    prep.phase = current.phase;
    prep.schema_version = "bluefire.receiver-defense-preparation.v2";
    prep.control_binding = descriptor;
    prep.baseline_reference = current.phase === "baseline" ? null : { run_id: baseline!.run_id, artifact: baseline!.artifact!, source_binding: baseline!.source_binding };
    if (current.phase !== "legitimate") continue;
    prep.baseline_artifact = null;
    prep.session.policy.policy_id = descriptor.policy_id;
    prep.session.policy.accepted_records = "every_record_explicitly_redacted";
    prep.session.policy_digest = descriptor.policy_digest;
    const replay = prep.replay_preparation!;
    replay.scenario = structuredClone(context.scenario);
    replay.scenario.steps.find((step) => step.id === "transform")!.parameters.redact_values = true;
    replay.replay_request.parameter_overrides = { transform: { redact_values: true } };
    const result = current.result;
    if (!result) continue;
    result.phase = "legitimate";
    result.policy_id = descriptor.policy_id;
    result.legitimate_use = { baseline_run_id: baseline!.run_id, established: result.decision === "accepted" };
    result.run.scenario = replay.scenario;
    if (result.decision === "insufficient_evidence") continue;
    const artifact = { sha256: "e".repeat(64), size_bytes: 100 };
    result.artifact = artifact;
    Object.assign(record(current.receiver_job!.progress.task_binding), artifact);
    Object.assign(record(result.receiver_observation.task_binding), artifact);
    const decision = record(record(result.receiver_observation.terminal).decision);
    Object.assign(decision, { policy_id: descriptor.policy_id, policy_digest: descriptor.policy_digest, sha256: artifact.sha256, bytes_received: artifact.size_bytes });
    Object.assign(record(decision.semantics), { retained_record_count: 0, redacted_record_count: 2 });
  }
  const protectedPhase = value.phases[1]!;
  const status = value.status === "completed" ? "retained" : protectedPhase.status === "completed" ? "verified" : protectedPhase.decision?.decision === "accept" ? "accepted" : "proposed";
  const control: ReceiverRetainedControl = { ...descriptor, owner_job_id: value.job.job_id, status, desired_policy_id: status === "proposed" ? "receiver.reviewed-records.v1" : descriptor.policy_id, receiver_state: stage === "completed" || stage === "idle" ? "stopped" : stage === "insufficient" ? "unknown" : "active", can_retest: status === "retained", can_rollback: status === "retained", rollback: null };
  if (linked) {
    context.source_control = { job_id: "job-70000000000040008000000000000000", control_digest: descriptor.control_digest };
    context.source_baseline = { run_id: baseline!.run_id, artifact: baseline!.artifact!, source_binding: baseline!.source_binding };
    record(value.job.request!.submitted_request).source_control = context.source_control;
    value.phases = value.phases.slice(1);
    delete record(value.job.progress.phases).baseline;
    control.owner_job_id = context.source_control.job_id;
    control.status = "retained";
    control.desired_policy_id = descriptor.policy_id;
    control.can_retest = value.status === "completed";
    control.can_rollback = value.status === "completed";
  }
  value.control = control;
  return value;
}
