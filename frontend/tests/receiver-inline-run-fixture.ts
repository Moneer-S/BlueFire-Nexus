import type { ReceiverPhase } from "../src/lib/receiver-defense-types";
import type { PreflightReport } from "../src/types";
import { receiverFixture } from "./receiver-defense-fixture";

export function nativeReceiverFixture(phase: ReceiverPhase = "baseline") {
  const envelope = receiverFixture(phase, "approval");
  const current = envelope.phases.find((item) => item.phase === phase)!;
  const job = current.execution_job!;
  const binding = { state_digest: `receiver-state-${phase}`, plan_digest: `reviewed-plan-${phase}`, target_scope_digest: "reviewed-scope", profile_id: envelope.context.run_intent.runner_profile_id!, maximum_tier: "controlled" };
  const preflight: PreflightReport = { ready: false, status: "approval_required", approval_binding: binding,
    plan: { mode: "execute", autonomy: "off", steps: [{ step_id: "handoff" }], edges: [] },
    approval_envelope: { schema_version: "bluefire.approval-envelope.v1", scenario_id: envelope.context.scenario.id, envelope_digest: `reviewed-envelope-${phase}`, steps: [{ step_id: "handoff", options: [] }] },
  };
  current.preparation!.preflight = preflight;
  if (current.preparation!.replay_preparation) current.preparation!.replay_preparation.preflight = preflight;
  Object.assign(job.request!, { approval_request_id: `approval-${phase}` });
  if (phase === "baseline") Object.assign(job.request!, { mode: "execute", _run_submission_preflight: preflight });
  else job.request!.source_run_id = "run-baseline";
  job.approval_request = { ...binding, approval_id: `approval-${phase}`, status: "pending", expires_at: "2099-01-01T00:00:00Z" };
  job.updated_at = "2026-09-07T12:00:00Z";
  return envelope;
}
