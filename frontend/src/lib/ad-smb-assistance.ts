import { request } from "./api";
import type { AssistanceContext } from "./assistance";
import { adPhases, adSteps, type AdPhase, type AdWorkflow } from "./ad-smb";
import { sameJson } from "./replay-review";

export interface AdSmbAssistanceSelection { kind: "ad_smb_workflow"; workflow_job_id: string; result_digest: string }
type Cleanup = "verified" | "unknown";
type ReadObservation = { reader: "probe" | "legitimate"; purpose: "primary" | "health"; state: string; bytes_read: number; local_cleanup: Cleanup; server_session_closed: null; authenticated_remote_reader: false; fresh_server_logon: false; independent_observation: false; effective_access_claim: false };
type SnapshotObservation = { state: "inspection_recorded" | "not_attempted" | "readback_matched" | "unknown"; receiver_completed_at: string | null; descriptor_digest: string | null };
type AuditObservation = { events: number; truncated: boolean; authenticated_source: false; independent_observation: false; effective_access_claim: false; normalization: null | { capture_state: string; window_start: string; window_end: string; reported_completeness: string; input_events: number; duplicate_events: number; limitations: string[]; classification_counts: Array<{ event_id: 4624 | 5145; audit_outcome: "success" | "failure" | "unknown"; binding: "matched" | "incomplete" | "outside_scope"; count: number }> } };
export interface AdSmbAssistanceTask {
  step: string; request_digest: string; task_id: string | null; original_digest: string | null; execution_digest: string | null; requested_at: string;
  provenance: "runner_reported" | "synthetic_fixture" | "controller_local" | null; dispatch: "unknown" | "attempted" | "not_started"; cleanup: Cleanup;
  observation: ReadObservation | SnapshotObservation | AuditObservation | null;
}
export interface AdSmbAssistanceSummary {
  schema_version: "bluefire.ad-smb-assistance-summary.v1"; proof_scope: "saved_ad_workflow_only"; provenance: "runner_reported" | "synthetic_fixture";
  revision: number; policy_state: "baseline" | "hardened" | "unknown"; stopped: boolean; pending_operation: string | null; missing_phases: AdPhase[]; effective_access_claim: false;
  operations: Array<{ operation_job_id: string; phase: AdPhase; state: "completed" | "failed" | "cancelled" | "interrupted"; run_id: string;
    outcome: { state: "complete" | "partial" | "not_started" | "unknown"; read_expectation: "matched" | "not_met" | "incomplete" | null; distinct_local_contexts: boolean | null; audit_complete: boolean | null; evidence_digest: string; cleanup: Cleanup; authenticated_remote_reader: false; independent_observation: false; effective_access_claim: false }; tasks: AdSmbAssistanceTask[] }>;
}
export interface AdSmbAssistanceContext extends AssistanceContext { selected: AdSmbAssistanceSelection; analysis_only: true; capabilities: []; reference_summary: AdSmbAssistanceSummary }
export const adSmbAssistanceLimitations = [
  "This explains one exact retained AD workflow snapshot only. It cannot dispatch, read a file, change an ACL, collect audit, recover a task, or grant authority.",
  "Saved runner-reported projections retain their original provenance; digest and task-linkage checks do not authenticate a remote reader or independently verify a receiver result. Synthetic fixtures remain authored evidence.",
  "A reviewed ACL change or matching descriptor readback does not establish effective access. Probe and legitimate-reader outcomes remain separate; no combined prevention claim is made.",
  "Distinct local contexts do not prove a fresh server logon. Remote session closure and authenticated remote-reader identity remain unknown.",
  "Snapshot times are receiver completion times, not native observation times. Reads have no recorded native observation timestamp; request times are not observation times.",
  "Audit completeness is a saved collector assertion. Missing events cannot prove denial; a share access-check event does not prove an NTFS read or returned bytes.",
  "Missing stages, unavailable original results, unknown cleanup, and incomplete audit remain unknown. Later workflow changes refuse this selection; the store does not supply historical snapshots for reopening an older digest.",
] as const;
const object = (v: unknown): v is Record<string, unknown> => Boolean(v) && typeof v === "object" && !Array.isArray(v);
const exact = (v: unknown, keys: string[]): v is Record<string, unknown> => object(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
const text = (v: unknown): v is string => typeof v === "string" && v.length > 0 && v.length <= 512 && [...v].every(c => c.charCodeAt(0) >= 32 && c.charCodeAt(0) !== 127);
const digest = (v: unknown): v is string => typeof v === "string" && /^sha256:[a-f0-9]{64}$/.test(v);
const job = (v: unknown): v is string => typeof v === "string" && /^job-[a-f0-9]{32}$/.test(v);
const count = (v: unknown): v is number => Number.isSafeInteger(v) && Number(v) >= 0 && Number(v) <= 2_147_483_647;
const stamp = (v: unknown): v is string => text(v) && v.length <= 40 && Number.isFinite(Date.parse(v));
const nullable = (v: unknown, check: (v: unknown) => boolean) => v === null || check(v);
const bool = (v: unknown) => typeof v === "boolean";
const oneOf = (v: unknown, values: readonly string[]): v is string => typeof v === "string" && values.includes(v);
const noClaims = (v: Record<string, unknown>) => v.authenticated_remote_reader === false && v.independent_observation === false && v.effective_access_claim === false;
const clean = (v: unknown) => oneOf(v, ["verified", "unknown"]);
const unavailable = () => new Error("The selected saved AD workflow is unavailable or changed. Reopen its saved results before explaining.");

export function validAdSmbAssistanceSelection(v: unknown): v is AdSmbAssistanceSelection {
  return exact(v, ["kind", "workflow_job_id", "result_digest"]) && v.kind === "ad_smb_workflow" && job(v.workflow_job_id) && digest(v.result_digest);
}
export function adSmbAssistancePath(selected: AdSmbAssistanceSelection): string {
  if (!validAdSmbAssistanceSelection(selected)) throw unavailable();
  return `/ad-smb?${new URLSearchParams({ workflow: selected.workflow_job_id })}`;
}
function validObservation(v: unknown, step: string): boolean {
  if (v === null) return true;
  if (step.startsWith("read_")) return exact(v, ["reader", "purpose", "state", "bytes_read", "local_cleanup", "server_session_closed", "authenticated_remote_reader", "fresh_server_logon", "independent_observation", "effective_access_claim"])
    && oneOf(v.reader, ["probe", "legitimate"]) && oneOf(v.purpose, ["primary", "health"]) && step === `read_${v.reader}_${v.purpose}`
    && oneOf(v.state, ["bytes_matched", "open_access_denied", "unknown", "deadline", "cancelled", "not_started"]) && count(v.bytes_read) && clean(v.local_cleanup)
    && v.server_session_closed === null && v.fresh_server_logon === false && noClaims(v);
  if (step !== "collect_audit") return exact(v, ["state", "receiver_completed_at", "descriptor_digest"]) && oneOf(v.state, ["inspection_recorded", "not_attempted", "readback_matched", "unknown"])
    && nullable(v.receiver_completed_at, stamp) && nullable(v.descriptor_digest, digest);
  if (!exact(v, ["events", "truncated", "authenticated_source", "independent_observation", "effective_access_claim", "normalization"]) || !count(v.events) || v.events > 1000 || !bool(v.truncated)
    || v.authenticated_source !== false || v.independent_observation !== false || v.effective_access_claim !== false) return false;
  const n = v.normalization;
  return n === null || exact(n, ["capture_state", "window_start", "window_end", "reported_completeness", "input_events", "duplicate_events", "limitations", "classification_counts"])
    && oneOf(n.capture_state, ["query_exhausted", "event_limit", "byte_limit", "event_rejected", "deadline", "cancelled", "read_failed", "cleanup_unknown"])
    && stamp(n.window_start) && stamp(n.window_end) && Date.parse(n.window_start) < Date.parse(n.window_end)
    && n.reported_completeness === ({ query_exhausted: "complete", event_limit: "truncated", byte_limit: "truncated", event_rejected: "incomplete", deadline: "incomplete", cancelled: "incomplete", read_failed: "incomplete", cleanup_unknown: "unknown" } as Record<string, string>)[n.capture_state]
    && count(n.input_events) && n.input_events <= 1000 && count(n.duplicate_events) && Array.isArray(n.limitations) && n.limitations.length <= 16 && n.limitations.every(text)
    && validClassifications(n.classification_counts, Number(n.input_events) - Number(n.duplicate_events));
}
function validClassifications(value: unknown, expected: number): boolean {
  if (!Array.isArray(value) || value.length > 18 || expected < 0) return false;
  let total = 0, previous = "";
  for (const row of value) {
    if (!exact(row, ["event_id", "audit_outcome", "binding", "count"]) || typeof row.event_id !== "number" || ![4624, 5145].includes(row.event_id)
      || !oneOf(row.audit_outcome, ["success", "failure", "unknown"]) || !oneOf(row.binding, ["matched", "incomplete", "outside_scope"]) || !count(row.count) || row.count < 1 || row.count > 1000) return false;
    const key = `${row.event_id}:${row.audit_outcome}:${row.binding}`;
    if (key <= previous) return false;
    previous = key; total += row.count;
  }
  return total === expected;
}
function validTask(v: unknown, step: string): boolean {
  return exact(v, ["step", "request_digest", "task_id", "original_digest", "execution_digest", "requested_at", "provenance", "dispatch", "cleanup", "observation"])
    && v.step === step && digest(v.request_digest) && nullable(v.task_id, text) && nullable(v.original_digest, digest) && nullable(v.execution_digest, digest) && stamp(v.requested_at)
    && nullable(v.provenance, p => oneOf(p, ["runner_reported", "synthetic_fixture", "controller_local"])) && oneOf(v.dispatch, ["unknown", "attempted", "not_started"]) && clean(v.cleanup) && validObservation(v.observation, step);
}
function validSummary(v: unknown): v is AdSmbAssistanceSummary {
  if (!exact(v, ["schema_version", "proof_scope", "provenance", "revision", "policy_state", "stopped", "pending_operation", "operations", "missing_phases", "effective_access_claim"])
    || v.schema_version !== "bluefire.ad-smb-assistance-summary.v1" || v.proof_scope !== "saved_ad_workflow_only" || !oneOf(v.provenance, ["runner_reported", "synthetic_fixture"])
    || !count(v.revision) || !oneOf(v.policy_state, ["baseline", "hardened", "unknown"]) || !bool(v.stopped) || !nullable(v.pending_operation, job) || v.effective_access_claim !== false
    || !Array.isArray(v.operations) || v.operations.length === 0 || v.operations.length > 7 || !Array.isArray(v.missing_phases)) return false;
  if (!v.operations.every(op => {
    if (!exact(op, ["operation_job_id", "phase", "state", "run_id", "outcome", "tasks"]) || !job(op.operation_job_id) || !oneOf(op.phase, adPhases) || !oneOf(op.state, ["completed", "failed", "cancelled", "interrupted"]) || !text(op.run_id)
      || !Array.isArray(op.tasks) || op.tasks.length !== adSteps[op.phase as AdPhase].length || !op.tasks.every((task, i) => validTask(task, adSteps[op.phase as AdPhase][i]!))) return false;
    const o = op.outcome;
    return exact(o, ["state", "read_expectation", "distinct_local_contexts", "audit_complete", "evidence_digest", "cleanup", "authenticated_remote_reader", "independent_observation", "effective_access_claim"])
      && oneOf(o.state, ["complete", "partial", "not_started", "unknown"]) && nullable(o.read_expectation, value => oneOf(value, ["matched", "not_met", "incomplete"]))
      && nullable(o.distinct_local_contexts, bool) && nullable(o.audit_complete, bool) && digest(o.evidence_digest) && clean(o.cleanup) && noClaims(o);
  })) return false;
  const operations = v.operations as AdSmbAssistanceSummary["operations"];
  return new Set(operations.map(op => op.operation_job_id)).size === operations.length && sameJson(v.missing_phases, adPhases.filter(phase => !operations.some(op => op.phase === phase)));
}
export function checkedAdSmbAssistanceContext(v: unknown, owner: string, selected?: AdSmbAssistanceSelection, workflow?: AdWorkflow): AdSmbAssistanceContext {
  if (!job(owner) || !exact(v, ["schema_version", "selected", "context_digest", "analysis_only", "capabilities", "reference_summary", "limitations"])
    || v.schema_version !== "bluefire.assistance-context.v1" || !validAdSmbAssistanceSelection(v.selected) || v.selected.workflow_job_id !== owner || selected && !sameJson(v.selected, selected)
    || !digest(v.context_digest) || v.analysis_only !== true || !Array.isArray(v.capabilities) || v.capabilities.length !== 0 || !sameJson(v.limitations, adSmbAssistanceLimitations)
    || !validSummary(v.reference_summary) || new TextEncoder().encode(JSON.stringify(v.reference_summary)).length > 65536) throw unavailable();
  const context = v as unknown as AdSmbAssistanceContext;
  if (workflow && !adSmbAssistanceMatchesWorkflow(context, workflow)) throw unavailable();
  return context;
}
export function adSmbAssistanceMatchesWorkflow(context: AdSmbAssistanceContext, workflow: AdWorkflow): boolean {
  const summary = context.reference_summary;
  return context.selected.workflow_job_id === workflow.id && workflow.revision === summary.revision && workflow.policy === summary.policy_state && workflow.stopped === summary.stopped && workflow.pending === summary.pending_operation
    && workflow.environment.provenance === summary.provenance && sameJson(summary.operations.map(op => op.operation_job_id), [...workflow.operations.map(op => op.id), ...(workflow.pending ? [workflow.pending] : [])])
    && workflow.operations.every((op, i) => { const captured = summary.operations[i]; return Boolean(captured && captured.phase === op.phase && captured.run_id === op.runId && captured.outcome.evidence_digest === op.digest && captured.outcome.state === op.state); });
}
export async function adSmbAssistanceContext(owner: string, selected?: AdSmbAssistanceSelection, workflow?: AdWorkflow): Promise<AdSmbAssistanceContext> {
  if (!job(owner) || selected && !validAdSmbAssistanceSelection(selected)) throw unavailable();
  return checkedAdSmbAssistanceContext(await request(`/ad-smb/workflows/${encodeURIComponent(owner)}/assistance-context`), owner, selected, workflow);
}
