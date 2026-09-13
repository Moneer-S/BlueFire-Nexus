import type { AssistanceContext, AssistanceEnvelope } from "./assistance";
import type { RunJob } from "../types";
import type { ReceiverContext, ReceiverContextRequest, ReceiverDefenseEnvelope, ReceiverPhase } from "./receiver-defense-types";
import { sameJson } from "./replay-review";

export type ReceiverAssistanceSelection = ({ kind: "receiver_scenario" } & ReceiverContextRequest)
  | { kind: "receiver_test"; receiver_job_id: string; receiver_context_digest: string };
export interface ReceiverInspectionPhase {
  phase: ReceiverPhase; evidence_ref: string; result_digest: string;
  decision: "accepted" | "policy_refused" | "insufficient_evidence";
  transport_state: "completed" | "failed" | "cancelled" | "interrupted" | "unknown";
  receiver_cleanup: "verified_closed" | "uncertain"; run_cleanup: "complete" | "incomplete" | "unknown";
  artifact_matches_baseline: boolean | null; record_count: number | null;
  retained_record_count: number | null; redacted_record_count: number | null;
}
export interface ReceiverInspectionReceipt {
  job: RunJob; owner_job_id: string; prefix_digest: string; phases: ReceiverInspectionPhase[];
  interpretation: null | {
    schema_version: "bluefire.receiver-defense-inspection.v1"; context_digest: string; model_interpretation: true;
    summary: string; findings: Array<{ claim: string; evidence_refs: string[] }>; limitations: string[];
    next_phase: "protected" | "restored" | null; reason: string;
    provider: { provider_id: string; kind: string; model: string; usage: unknown };
  };
}
export interface ReceiverAssistanceProgress {
  owner_job_id: string; owner_context_digest: string; owns_lifecycle: boolean;
  status: ReceiverDefenseEnvelope["status"]; native_path: string; phase: ReceiverPhase | null;
  next_action: ReceiverDefenseEnvelope["next_action"]; phases: ReceiverDefenseEnvelope["phases"];
  inspections: ReceiverInspectionReceipt[];
}
export type ReceiverAssistanceResult =
  | { kind: "receiver_phase"; step_id: string; owner_job_id: string; phase: ReceiverPhase; run_id: string; result_digest: string; decision: ReceiverInspectionPhase["decision"]; native_path: string }
  | { kind: "receiver_inspection"; step_id: string; owner_job_id: string; inspection_job_id: string; prefix_digest: string; native_path: string };
export interface ReceiverAssistanceContext extends AssistanceContext {
  selected: ReceiverAssistanceSelection;
  receiver_context: Omit<ReceiverContext, "availability">;
  source_prefix: ReceiverInspectionPhase[];
  reference_summary: { title: string; phases: ReceiverInspectionPhase[] };
}
const object = (value: unknown): Record<string, unknown> => value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
const text = (value: unknown, max = 200): value is string => typeof value === "string" && value.trim().length > 0 && value.length <= max;
const digest = (value: unknown): value is string => typeof value === "string" && /^sha256:[0-9a-f]{64}$/.test(value);
const jobId = (value: unknown): value is string => typeof value === "string" && /^job-[0-9a-f]{32}$/.test(value);
const list = (value: unknown, max: number): value is string[] => Array.isArray(value) && value.length <= max && value.every((item) => text(item));
const phases: ReceiverPhase[] = ["baseline", "protected", "restored"];
const terminal = (state: string) => ["completed", "failed", "cancelled", "interrupted"].includes(state);
function fail(): never { throw new Error("The saved receiver assistance does not match its selected test and evidence. Its request is retained; no work was repeated."); }
export function validReceiverAssistanceSelection(value: unknown): value is ReceiverAssistanceSelection {
  const selected = object(value);
  if (selected.kind === "receiver_test") return Object.keys(selected).length === 3 && jobId(selected.receiver_job_id) && digest(selected.receiver_context_digest);
  const source = object(selected.selection), intent = object(selected.run_intent), scope = object(intent.target_scope);
  return selected.kind === "receiver_scenario" && Object.keys(selected).length === 3 && source.kind === "saved_scenario"
    && Object.keys(source).length === 4 && text(source.scenario_id) && Number.isSafeInteger(source.version) && Number(source.version) > 0 && digest(source.digest)
    && Object.keys(intent).every((key) => ["mode", "autonomy", "ai_provider_id", "runner_profile_id", "target_scope", "collectors", "action_implementations"].includes(key))
    && intent.mode === "execute" && intent.autonomy === "off" && intent.ai_provider_id === null && text(intent.runner_profile_id)
    && Object.keys(scope).length === 1 && list(scope.scope_refs, 32)
    && (intent.collectors === undefined || list(intent.collectors, 32))
    && (intent.action_implementations === undefined || typeof intent.action_implementations === "object" && intent.action_implementations !== null && !Array.isArray(intent.action_implementations)
      && Object.entries(intent.action_implementations).length <= 256 && Object.entries(intent.action_implementations).every(([key, item]) => text(key) && text(item)));
}
export function isReceiverSelection(value: unknown): value is ReceiverAssistanceSelection {
  return ["receiver_scenario", "receiver_test"].includes(String(object(value).kind));
}
function checkPhases(rows: ReceiverInspectionPhase[]) {
  if (!Array.isArray(rows) || rows.length > 3) fail();
  rows.forEach((row, index) => {
    if (row.phase !== phases[index] || !digest(row.result_digest) || !/^receiver:(baseline|protected|restored):job-[0-9a-f]{32}$/.test(row.evidence_ref)
      || !row.evidence_ref.startsWith(`receiver:${row.phase}:`) || !["accepted", "policy_refused", "insufficient_evidence"].includes(row.decision)
      || !["completed", "failed", "cancelled", "interrupted", "unknown"].includes(row.transport_state)
      || !["verified_closed", "uncertain"].includes(row.receiver_cleanup) || !["complete", "incomplete", "unknown"].includes(row.run_cleanup)
      || (row.artifact_matches_baseline !== null && typeof row.artifact_matches_baseline !== "boolean")
      || [row.record_count, row.retained_record_count, row.redacted_record_count].some((count) => count !== null && (!Number.isSafeInteger(count) || count < 0))) fail();
  });
}
export function checkedReceiverAssistanceContext(value: ReceiverAssistanceContext, selected: ReceiverAssistanceSelection): ReceiverAssistanceContext {
  if (!validReceiverAssistanceSelection(selected) || value.schema_version !== "bluefire.assistance-context.v1" || !sameJson(value.selected, selected) || !digest(value.context_digest)) fail();
  const native = value.receiver_context;
  if (!native || !digest(native.context_digest) || !text(native.scenario_title) || native.scenario?.id !== native.selection?.scenario_id) fail();
  if (selected.kind === "receiver_scenario" ? !sameJson(native.selection, selected.selection) || !sameJson(native.run_intent, selected.run_intent) : native.context_digest !== selected.receiver_context_digest) fail();
  checkPhases(value.source_prefix);
  if (selected.kind === "receiver_scenario" && value.source_prefix.length || !sameJson(value.reference_summary.phases, value.source_prefix)
    || value.capabilities.length !== 1 || value.capabilities[0]?.id !== (selected.kind === "receiver_scenario" ? "receiver.test_and_compare" : "receiver.inspect_and_plan_next")) fail();
  return value;
}
/** Checks serialized identities and retained copies; the service verifies bundle and content hashes. */
export function checkedReceiverAssistance(value: AssistanceEnvelope): AssistanceEnvelope {
  const selected = value.turn.selected;
  if (!isReceiverSelection(selected)) return value;
  if (!validReceiverAssistanceSelection(selected)) fail();
  const context = value.job.request?.context as ReceiverAssistanceContext | undefined;
  if (context) checkedReceiverAssistanceContext(context, selected);
  const progress = value.turn.receiver_test;
  if (!progress) {
    if (value.turn.results.some((row) => row.kind === "receiver_phase" || row.kind === "receiver_inspection")) fail();
    return value; // Off, planning, refused admission, or a reserved but unpublished child.
  }
  if (!context || !jobId(progress.owner_job_id) || !digest(progress.owner_context_digest)
    || progress.owns_lifecycle !== (selected.kind === "receiver_scenario") || progress.owner_context_digest !== context.receiver_context.context_digest
    || progress.native_path !== `/compare?receiver_job=${progress.owner_job_id}` || !["active", "completed", "blocked", "stopping", "stopped"].includes(progress.status)) fail();
  const children = object(value.job.progress.children), step = value.turn.plan[0];
  if (!step || value.turn.plan.length !== 1 || step.capability_id !== (progress.owns_lifecycle ? "receiver.test_and_compare" : "receiver.inspect_and_plan_next")) fail();
  if (selected.kind === "receiver_test") { if (selected.receiver_job_id !== progress.owner_job_id) fail(); }
  else {
    const child = object(children[step.step_id]);
    if (child.kind !== "receiver.defense" || child.job_id !== progress.owner_job_id || !sameJson(child.request, { submission_id: child.submission_id, selection: selected.selection, run_intent: selected.run_intent, context_digest: progress.owner_context_digest })) fail();
  }
  if (!Array.isArray(progress.phases) || progress.phases.length !== 3 || !Array.isArray(progress.inspections) || progress.inspections.length > 9) fail();
  progress.phases.forEach((phase, index) => {
    if (phase.phase !== phases[index]) fail();
    if (phase.receiver_job && !sameJson(phase.receiver_job.request?.receiver_defense, { parent_job_id: progress.owner_job_id, receiver_job_id: phase.receiver_job.job_id, phase: phase.phase })) fail();
    if (phase.result && (!phase.receiver_job || !phase.execution_job || phase.result.preparation_job_id !== phase.receiver_job.job_id || phase.result.execution_job_id !== phase.execution_job.job_id
      || phase.result.phase !== phase.phase || phase.result.run_id !== phase.result.run.run_id || !sameJson(phase.result, phase.receiver_job.progress.result))) fail();
  });
  const nativePaths = [progress.native_path, ...progress.phases.flatMap((phase) => phase.execution_job ? [`/runs?job=${phase.execution_job.job_id}`] : [])];
  if (progress.next_action.native_path !== null && !nativePaths.includes(progress.next_action.native_path)) fail();
  if (value.turn.next_action?.native_path && !nativePaths.includes(value.turn.next_action.native_path)) fail();
  if (value.turn.next_action?.kind === "approve_execute" && (progress.next_action.kind !== "approve_execute" || value.turn.next_action.native_path !== progress.next_action.native_path)) fail();
  const reservations = value.job.progress.receiver_inspections;
  for (const receipt of progress.inspections) {
    checkPhases(receipt.phases);
    const request = object(receipt.job.request?.submitted_request), marker = object(receipt.job.request?.assistance_receiver);
    const reserved = Array.isArray(reservations) ? reservations.find((row) => object(row).job_id === receipt.job.job_id) : undefined;
    if (!receipt.phases.length || receipt.job.kind !== "receiver.defense.inspect" || !jobId(receipt.job.job_id) || receipt.owner_job_id !== progress.owner_job_id
      || marker.parent_job_id !== value.job.job_id || marker.owner_job_id !== progress.owner_job_id || !reserved || !sameJson(object(reserved).request, request)
      || request.owner_job_id !== progress.owner_job_id || request.prefix_digest !== receipt.prefix_digest || !digest(receipt.prefix_digest) || !sameJson(request.phases, receipt.phases)
      || !sameJson(receipt.job.progress.interpretation ?? null, receipt.interpretation)) fail();
    receipt.phases.forEach((row, index) => {
      const phase = progress.phases[index];
      if (!value.turn.results.some((result) => result.kind === "receiver_phase" && result.phase === row.phase && result.result_digest === row.result_digest)) fail();
      const semantics = object(object(object(phase?.result?.receiver_observation).terminal).decision).semantics;
      const counts = object(semantics);
      if (["record_count", "retained_record_count", "redacted_record_count"].some((key) => object(row)[key] !== (counts[key] ?? null))) fail();
      if (!phase?.result || row.evidence_ref !== `receiver:${row.phase}:${phase.receiver_job?.job_id}` || row.decision !== phase.result.decision) fail();
    });
    const interpretation = receipt.interpretation;
    if (interpretation) {
      const provider = object(value.job.progress.provider);
      const refs = receipt.phases.map((row) => row.evidence_ref);
      if (interpretation.schema_version !== "bluefire.receiver-defense-inspection.v1" || interpretation.model_interpretation !== true || !digest(interpretation.context_digest)
        || !text(interpretation.summary, 2000) || !text(interpretation.reason, 1000) || !Array.isArray(interpretation.findings) || interpretation.findings.length > 8
        || !Array.isArray(interpretation.limitations) || interpretation.limitations.length > 8 || !interpretation.limitations.every((item) => text(item, 1000))
        || interpretation.next_phase !== null && interpretation.next_phase !== request.offered_next_phase
        || ["provider_id", "kind", "model"].some((key) => object(interpretation.provider)[key] !== provider[key])
        || interpretation.findings.some((finding) => !text(finding.claim, 1000) || !Array.isArray(finding.evidence_refs) || !finding.evidence_refs.length || finding.evidence_refs.length > 8 || finding.evidence_refs.some((ref) => !refs.includes(ref)))) fail();
    }
  }
  for (const result of value.turn.results) {
    if (result.kind !== "receiver_phase" && result.kind !== "receiver_inspection") fail();
    if (result.owner_job_id !== progress.owner_job_id || result.native_path !== progress.native_path || result.step_id !== step.step_id) fail();
    if (result.kind === "receiver_phase") {
      const phase = progress.phases.find((row) => row.phase === result.phase);
      if (!phase?.result || result.run_id !== phase.result.run_id || !digest(result.result_digest) || result.decision !== phase.result.decision) fail();
    } else if (!progress.inspections.some((row) => row.job.job_id === result.inspection_job_id && row.prefix_digest === result.prefix_digest && row.interpretation)) fail();
  }
  if (value.turn.status === "completed" && (progress.owns_lifecycle && progress.status !== "completed" || !terminal(value.job.state)
    || progress.inspections.some((row) => !terminal(row.job.state)) || !progress.inspections.some((row) => row.interpretation) || value.turn.continuation && !terminal(value.turn.continuation.state))) fail();
  return value;
}
