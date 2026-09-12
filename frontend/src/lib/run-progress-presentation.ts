import type { CatalogResponse, EvidenceRecord, RunRecord, RunStep } from "../types";
import { recordedMethodName } from "./adaptive-run";
import { stepOutcomeLabel } from "./run-presentation";

const object = (value: unknown): Record<string, unknown> => value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
const text = (value: unknown): string | undefined => typeof value === "string" && value.trim() ? value : undefined;
const readable = (value: string) => value.replace(/[._-]+/g, " ").replace(/^./, letter => letter.toUpperCase());

/** A repeated node may use a different method on each recorded attempt. */
export function recordedStepLabels(step: RunStep, catalog?: CatalogResponse, run?: RunRecord | null) {
  const behaviorId = step.behavior_id
    ?? catalog?.behaviors.find(item => item.simulation_id === step.simulation_id && Boolean(step.simulation_id))?.id
    ?? run?.scenario?.steps.find(item => item.id === step.step_id)?.behavior_id;
  const behavior = catalog?.behaviors.find(item => item.id === behaviorId);
  const name = behavior?.title ?? (step.step_id ? readable(step.step_id) : "Recorded step");
  const method = catalog ? recordedMethodName(catalog, behaviorId, step.action_id) : "Method details unavailable";
  return { name, method: step.simulation_id && !step.action_id ? `Simulation · ${behavior?.title ?? "recorded method"}` : method };
}

/** An evidence link can identify an attempt; a repeated step ID alone cannot. */
export function recordedEvidenceLabels(record: EvidenceRecord, catalog?: CatalogResponse, run?: RunRecord | null) {
  const evidenceId = record.evidence_id ?? record.id;
  const linked = (!record.run_id || record.run_id === run?.run_id ? run?.steps : [])?.filter(step => evidenceId && step.evidence_ids?.includes(evidenceId)
    && (!record.step_id || step.step_id === record.step_id)
    && (!record.behavior_id || step.behavior_id === record.behavior_id)
    && (record.action_id === undefined || step.action_id === record.action_id)) ?? [];
  const attempt = linked.length === 1 ? linked[0] : undefined;
  const step: RunStep = { step_id: record.step_id ?? attempt?.step_id ?? "", status: "not_reported",
    behavior_id: record.behavior_id ?? attempt?.behavior_id,
    action_id: record.action_id === undefined ? attempt?.action_id : record.action_id,
    simulation_id: attempt?.simulation_id };
  const labels = recordedStepLabels(step, catalog);
  const knownMethod = catalog?.actions.some(item => item.id === step.action_id)
    || catalog?.behaviors.some(item => item.id === step.behavior_id || Boolean(step.simulation_id) && item.simulation_id === step.simulation_id);
  return { name: step.step_id ? labels.name : "Unattributed evidence", method: knownMethod ? labels.method : undefined };
}

export function runEventPresentation(value: unknown, catalog?: CatalogResponse, run?: RunRecord | null, requestedMode?: unknown) {
  const event = object(value);
  // Canonical hashed events use data. Flat fields remain supported for older
  // display records, but cannot override an existing canonical data object.
  const data = event.data && typeof event.data === "object" && !Array.isArray(event.data) ? object(event.data) : event;
  const type = text(event.event_type) ?? text(event.type) ?? text(event.status) ?? "event";
  const mode = run?.mode ?? text(requestedMode) ?? text(data.mode) ?? "unknown";
  const stepId = text(data.step_id) ?? text(data.selected_step_id);
  const status = text(data.status) ?? "not_reported";
  const step = {
    ...data,
    step_id: stepId ?? "",
    behavior_id: text(data.behavior_id) ?? text(data.selected_behavior_id),
    action_id: text(data.action_id) ?? text(data.selected_action_id),
    simulation_id: text(data.simulation_id),
    status,
  } as RunStep;
  const labels = recordedStepLabels(step, catalog, run);
  const reason = text(data.reason) ?? text(data.message) ?? text(object(data.error).message);
  const titles: Record<string, string> = {
    "run.created": "Run created", "run.finalized": "Run finalized",
    "step.completed": "Step result recorded", "planner.decision": "Plan decision",
  };
  let detail = reason ?? (text(data.execution_disposition) ?? text(data.disposition) ? readable(String(data.execution_disposition ?? data.disposition)) : "No additional detail recorded");
  if (type === "step.completed" || stepId && text(data.status)) {
    detail = `${labels.name} · ${stepOutcomeLabel(step, mode)}${reason ? ` · ${reason}` : ""}`;
  } else if (type === "planner.decision") {
    const origin = data.proposed_by === "deterministic-planner.v1" ? "Deterministic routing" : "Recorded planner decision";
    detail = `${origin}${stepId ? ` · Next step: ${labels.name}` : ""}${reason ? ` · ${reason}` : ""}`;
  } else if (type === "run.created" || type === "run.finalized") {
    detail = [text(data.scenario_title) ?? run?.scenario?.title ?? run?.scenario_title, mode === "simulate" ? "Simulate" : mode === "execute" ? "Execute" : undefined, text(data.status) ? readable(String(data.status)) : undefined, reason].filter(Boolean).join(" · ") || "Saved run record";
  }
  return {
    title: titles[type] ?? readable(type), detail, status: status === "not_reported" ? text(event.status) ?? "observed" : status,
    type, stepId, methodId: step.action_id ?? step.simulation_id, behaviorId: step.behavior_id,
    timestamp: text(event.timestamp), sequence: typeof event.sequence === "number" ? event.sequence : undefined,
  };
}
