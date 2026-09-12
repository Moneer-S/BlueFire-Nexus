import type { CatalogResponse, RunRecord, RunStep } from "../types";

export type RuntimeRecord = NonNullable<RunRecord["ai_proposals"]>[number];
const object = (value: unknown): Record<string, unknown> => value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
export const adaptiveRecords = (run: RunRecord) => (run.ai_proposals ?? []).filter(record => record.schema_version === "bluefire.ai-proposal-record.v4");
export const recordedMethodName = (catalog: CatalogResponse, behavior?: string | null, action?: string | null) =>
  catalog.actions.find(item => item.id === action)?.title ?? catalog.behaviors.find(item => item.id === behavior)?.title ?? "Method unavailable in this catalog";

export function decisionOrigin(run: RunRecord, record: RuntimeRecord): number {
  if (record.run_id !== run.run_id || typeof record.deterministic_decision_id !== "string") return -1;
  return run.steps.findIndex(step => step.step_id === record.current_step_id && step.planner_decision_id === record.deterministic_decision_id);
}

/** Selection is not dispatch. Only a later exact step result can establish an attempt. */
export function selectedAttempt(run: RunRecord, record: RuntimeRecord): RunStep | undefined {
  const origin = decisionOrigin(run, record), selected = record.proposal;
  if (origin < 0 || record.application_status !== "applied_reviewed_method" || !selected) return undefined;
  const applied = object(record.applied_step);
  if (applied.step_id !== selected.selected_step_id || applied.behavior_id !== selected.selected_behavior_id || applied.action_id !== selected.selected_action_id) return undefined;
  return run.steps.slice(origin + 1).find(step => step.execution_disposition !== "counterfactual"
    && step.step_id === selected.selected_step_id && step.behavior_id === selected.selected_behavior_id && step.action_id === selected.selected_action_id);
}

export function dispatchDescription(step: RunStep, run: RunRecord): string {
  if (run.mode !== "execute" || step.execution_disposition === "counterfactual") return "Synthetic result; no execution established";
  if (step.interruption?.schema_version === "bluefire.execution-interruption.v1") {
    if (step.interruption.dispatch_requested === true) return "Dispatch interrupted; effects unknown";
    if (step.interruption.dispatch_requested === false) return "Cancelled before dispatch; no runner result";
    return "Interruption recorded; dispatch and effects unknown";
  }
  if (step.runner_status && step.request_hash) return `Runner returned ${step.runner_status.replaceAll("_", " ")}`;
  if (step.policy?.allowed === false) return "Refused before dispatch";
  return "Dispatch or runner result not established";
}

export function decisionProvenance(record: RuntimeRecord): { label: string; provider: string; model: string } {
  const receipt = object(record.provider), attempt = object(record.provider_attempt);
  const provider = String(receipt.effective_provider_id ?? attempt.provider_id ?? "Not recorded");
  const model = String(receipt.model ?? attempt.model ?? "Not recorded");
  if (receipt.used_fallback === true || String(record.decision_source).includes("fallback")) return { label: "Configured fallback · not live model evidence", provider, model };
  if (record.provider_called === false) return { label: "No provider call", provider, model };
  if (record.decision_source === "deterministic_provider" || attempt.kind === "deterministic") return { label: "Deterministic provider · software evidence", provider, model };
  if (record.decision_source === "provider" && record.provider_called === true && record.provider && record.proposal) return { label: "Live provider response", provider, model };
  return { label: record.provider_called === true ? "Provider called; no permitted choice established" : "Provider provenance not established", provider, model };
}

export function decisionObservations(record: RuntimeRecord) {
  const projection = object(object(record.planner_state).observations);
  const attempts = Array.isArray(projection.attempts) ? projection.attempts.map(object) : [];
  const latest = attempts.filter(attempt => attempt.step_id === record.current_step_id).at(-1);
  return { classification: object(latest?.failure).classification, budgets: object(projection.remaining_budgets),
    evidence: Array.isArray(latest?.evidence) ? latest.evidence.map(object).filter(item => typeof item.evidence_id === "string") : [],
    unknowns: Array.isArray(projection.unknowns) ? projection.unknowns.filter((item): item is string => typeof item === "string") : [] };
}

export function recordedPathNodes(run: RunRecord) {
  const groups = new Map<string, { stepId: string; attempts: Array<{ step: RunStep; index: number }>; decisions: RuntimeRecord[] }>();
  run.steps.forEach((step, index) => {
    if (!groups.has(step.step_id)) groups.set(step.step_id, { stepId: step.step_id, attempts: [], decisions: [] });
    groups.get(step.step_id)!.attempts.push({ step, index });
  });
  for (const record of adaptiveRecords(run)) {
    if (decisionOrigin(run, record) >= 0) groups.get(String(record.current_step_id))?.decisions.push(record);
  }
  return [...groups.values()];
}
