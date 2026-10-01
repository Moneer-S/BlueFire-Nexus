import type { CatalogResponse, RunRecord, RunStep } from "../types";
import { displayTitle } from "./display-title";
import { observationCount, observationFacts, type ObservationFact } from "./adaptive-observation-facts";

export type RuntimeRecord = NonNullable<RunRecord["ai_proposals"]>[number];
const object = (value: unknown): Record<string, unknown> => value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
export const adaptiveRecords = (run: RunRecord) => (run.ai_proposals ?? []).filter(record => record.schema_version === "bluefire.ai-proposal-record.v4");
export const recordedMethodName = (catalog: CatalogResponse, behavior?: string | null, action?: string | null) =>
  displayTitle(catalog.actions.find(item => item.id === action)?.title ?? catalog.behaviors.find(item => item.id === behavior)?.title ?? "Method unavailable in this catalog");

export function decisionOrigin(run: RunRecord, record: RuntimeRecord): number {
  if (record.run_id !== run.run_id || typeof record.deterministic_decision_id !== "string" || !record.deterministic_decision_id) return -1;
  const matches = run.steps.flatMap((step, index) => step.step_id === record.current_step_id && step.planner_decision_id === record.deterministic_decision_id ? [index] : []);
  return matches.length === 1 ? matches[0]! : -1;
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
  // provider_called records the planner invocation; it does not establish wire dispatch.
  return { label: record.provider_called === true ? "Provider request did not produce a permitted choice" : "Provider provenance not established", provider, model };
}

const provenanceLabels: Record<string, string> = {
  observed: "Independent observation", executed: "Reported execution", synthetic: "Simulated evidence",
  control_blocked: "BlueFire control record", counterfactual: "Counterfactual evidence", unknown: "Observation unavailable",
};
const classifications = ["platform_mismatch", "bluefire_authorization_refusal", "bluefire_control_refusal", "resource_limit", "prerequisite_failure", "execution_timeout", "execution_failure", "runner_transport_failure", "missing_telemetry", "none", "unknown"];
const limitations = [
  "Target prevention is not established by a product refusal.",
  "Reported execution alone does not independently verify the objective.",
  "Method availability does not establish success or external prerequisites.",
  "permission mode bits only; ACLs, parent-directory traversal and effective access are not evaluated",
];
export type DecisionObservations = {
  available: boolean; classification?: string; budgets: Record<string, number>;
  evidence: Array<{ evidence_id: string; record_hash: string; label: string; facts: ObservationFact[] | null }>;
  unknowns: string[]; missing?: number; omitted?: number; omittedAttempts?: number; telemetryGap?: boolean;
};

/** The saved projection is not proof of provider wire contents or objective completion. */
export function decisionObservations(run: RunRecord, record: RuntimeRecord): DecisionObservations {
  const unavailable: DecisionObservations = { available: false, budgets: {}, evidence: [], unknowns: [] };
  const origin = decisionOrigin(run, record), step = run.steps[origin];
  const projection = object(object(record.planner_state).observations);
  if (!step || record.schema_version !== "bluefire.ai-proposal-record.v4" || projection.schema_version !== "bluefire.runtime-observations.v1"
    || !Array.isArray(projection.attempts) || projection.attempts.length > 16) return unavailable;
  const attempts = projection.attempts.map(object), indices = attempts.map(attempt => attempt.attempt_index);
  if (indices.some(index => !observationCount(index) || index > origin) || new Set(indices).size !== indices.length) return unavailable;
  const matched = attempts.filter(attempt => attempt.attempt_index === origin);
  if (matched.length !== 1) return unavailable;
  const attempt = matched[0]!;
  if (attempt.step_id !== step.step_id || attempt.behavior_id !== step.behavior_id || attempt.action_id !== step.action_id
    || attempt.outcome !== step.status || attempt.outcome !== record.outcome
    || !observationCount(attempt.missing_evidence_count) || !observationCount(attempt.omitted_evidence_count)
    || !observationCount(projection.omitted_attempt_count) || !Array.isArray(attempt.evidence) || attempt.evidence.length > 32) return unavailable;
  if (!Array.isArray(step.evidence_ids) || attempt.evidence.length + attempt.missing_evidence_count + attempt.omitted_evidence_count !== new Set(step.evidence_ids).size) return unavailable;
  const evidence: DecisionObservations["evidence"] = [];
  for (const value of attempt.evidence) {
    const row = object(value);
    if (typeof row.evidence_id !== "string" || !/^evidence-[0-9a-f]{20}$/.test(row.evidence_id)
      || typeof row.record_hash !== "string" || !/^sha256:[0-9a-f]{64}$/.test(row.record_hash)
      || typeof row.provenance !== "string" || !Object.hasOwn(provenanceLabels, row.provenance)
      || !step.evidence_ids?.includes(row.evidence_id) || evidence.some(item => item.evidence_id === row.evidence_id)) return unavailable;
    evidence.push({ evidence_id: row.evidence_id, record_hash: row.record_hash, label: provenanceLabels[row.provenance]!, facts: observationFacts(row.facts, row.provenance) });
  }
  const budgets: Record<string, number> = {};
  for (const [key, value] of Object.entries(object(projection.remaining_budgets))) {
    if (["steps", "retries"].includes(key) && observationCount(value)) budgets[key] = value;
    if (key === "seconds" && typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= Number.MAX_SAFE_INTEGER) budgets[key] = value;
  }
  const failure = object(attempt.failure), classification = failure.classification, unknowns = projection.unknowns;
  return { available: true, classification: typeof classification === "string" && classifications.includes(classification) ? classification : undefined,
    budgets, evidence, missing: attempt.missing_evidence_count, omitted: attempt.omitted_evidence_count, omittedAttempts: projection.omitted_attempt_count,
    telemetryGap: typeof failure.telemetry_gap === "boolean" ? failure.telemetry_gap : undefined,
    unknowns: Array.isArray(unknowns) ? limitations.filter(value => unknowns.includes(value)) : [] };
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
