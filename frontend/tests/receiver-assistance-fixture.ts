import type { AssistanceEnvelope, ReceiverAssistanceRequest } from "../src/lib/assistance";
import type { ReceiverAssistanceContext, ReceiverInspectionPhase, ReceiverInspectionReceipt } from "../src/lib/receiver-assistance";
import { receiverFixture, receiverFixtureDigest as digest } from "./receiver-defense-fixture";

export const receiverAssistantProvider = { provider_id: "analysis-provider", kind: "openai_chat_completions", model: "configured-model" };
export function receiverAssistantFixture(existing = false, completed = false) {
  const native = receiverFixture(completed ? "restored" : "baseline", "completed");
  const source: ReceiverInspectionPhase[] = native.phases.filter((phase) => phase.result).map((phase) => ({
    phase: phase.phase, evidence_ref: `receiver:${phase.phase}:${phase.receiver_job!.job_id}`, result_digest: digest,
    decision: phase.result!.decision, transport_state: phase.phase === "protected" ? "failed" : "completed",
    receiver_cleanup: "verified_closed", run_cleanup: "complete", artifact_matches_baseline: true,
    record_count: 2, retained_record_count: 1, redacted_record_count: 1,
  }));
  const selection = existing ? { kind: "receiver_test" as const, receiver_job_id: native.job.job_id, receiver_context_digest: digest }
    : { kind: "receiver_scenario" as const, selection: native.context.selection, run_intent: native.context.run_intent };
  const context: ReceiverAssistanceContext = { schema_version: "bluefire.assistance-context.v1", selected: selection, context_digest: digest,
    receiver_context: native.context, source_prefix: existing ? source : [], reference_summary: { title: native.context.scenario_title, phases: existing ? source : [] },
    capabilities: [{ id: existing ? "receiver.inspect_and_plan_next" : "receiver.test_and_compare", title: existing ? "Inspect receiver evidence" : "Coordinate receiver phases", available: true, supported_autonomy: ["assist", "auto"], reason: "Prepare and Execute remain explicit.", native_path: "/compare" }], limitations: ["Development evidence only."] };
  const request: ReceiverAssistanceRequest = { submission_id: "44444444-4444-4444-8444-444444444444", selection, context_digest: digest,
    message: "Explain the evidence and guide the next phase.", autonomy: "assist", provider_id: receiverAssistantProvider.provider_id };
  function envelope(body: ReceiverAssistanceRequest = request): AssistanceEnvelope {
    const parentId = `job-${body.submission_id.replaceAll("-", "")}`;
    const inspectionSubmission = "55555555-5555-5555-8555-555555555555";
    const inspectionId = `job-${inspectionSubmission.replaceAll("-", "")}`;
    const inspectionRequest = { owner_job_id: native.job.job_id, phases: source, offered_next_phase: completed ? null : "protected", prefix_digest: digest, submission_id: inspectionSubmission };
    const interpretation: NonNullable<ReceiverInspectionReceipt["interpretation"]> = { schema_version: "bluefire.receiver-defense-inspection.v1", context_digest: digest, model_interpretation: true,
      summary: "The baseline retained the reviewed records. The policy decision is independent of transport status.", findings: [{ claim: "One record remained retained.", evidence_refs: [source[0]!.evidence_ref] }],
      limitations: ["No held-out deployment was tested."], next_phase: completed ? null : "protected", reason: "Compare the exact same artifact under the redaction requirement.", provider: { ...receiverAssistantProvider, usage: {} } };
    const inspection: ReceiverInspectionReceipt = { job: { schema_version: "bluefire.job.v1", job_id: inspectionId, kind: "receiver.defense.inspect", state: "completed",
      request: { submitted_request: inspectionRequest, assistance_receiver: { parent_job_id: parentId, owner_job_id: native.job.job_id }, _submission: { schema_version: "bluefire.job-submission.v1", submission_id: inspectionSubmission, intent_digest: digest } }, progress: { interpretation } },
      owner_job_id: native.job.job_id, prefix_digest: digest, phases: source, interpretation };
    const result: AssistanceEnvelope = { job: { schema_version: "bluefire.job.v1", job_id: parentId, kind: "assistance.turn", state: "completed",
      request: { submitted_request: body, context }, progress: { provider: receiverAssistantProvider, children: { receiver: { kind: "receiver.defense", job_id: native.job.job_id, submission_id: native.job.request!.submitted_request && (native.job.request!.submitted_request as { submission_id: string }).submission_id, request: native.job.request!.submitted_request } }, receiver_inspections: [{ job_id: inspectionId, submission_id: inspectionSubmission, request: inspectionRequest }] } },
      turn: { schema_version: "bluefire.assistance-turn.v1", selected: body.selection, context_digest: body.context_digest, message: "Coordinate the retained receiver test.", status: existing || completed ? "completed" : "awaiting_review", can_start_new_turn: existing || completed,
        plan: [{ step_id: "receiver", capability_id: existing ? "receiver.inspect_and_plan_next" : "receiver.test_and_compare", title: existing ? "Explain receiver evidence" : "Compare receiver policies", detector_ref: "none", reason: "Use the exact selected graph and phase evidence." }],
        active_child: null, next_action: { kind: existing || completed ? "open_results" : "review_receiver", native_path: `/compare?receiver_job=${native.job.job_id}` }, continuation: null, limitations: ["Every Execute needs fresh approval."],
        receiver_test: { owner_job_id: native.job.job_id, owner_context_digest: digest, owns_lifecycle: !existing, native_path: `/compare?receiver_job=${native.job.job_id}`, status: native.status, phase: native.next_action.phase, next_action: native.next_action, phases: native.phases, inspections: [inspection] },
        results: [...source.map((row) => ({ kind: "receiver_phase" as const, step_id: "receiver", owner_job_id: native.job.job_id, phase: row.phase, run_id: native.phases.find((phase) => phase.phase === row.phase)!.result!.run_id, result_digest: row.result_digest, decision: row.decision, native_path: `/compare?receiver_job=${native.job.job_id}` })),
          { kind: "receiver_inspection", step_id: "receiver", owner_job_id: native.job.job_id, inspection_job_id: inspectionId, prefix_digest: digest, native_path: `/compare?receiver_job=${native.job.job_id}` }] } };
    return JSON.parse(JSON.stringify(result)) as AssistanceEnvelope;
  }
  return { native, context, request, envelope };
}
