import type { RunRecord, RunStep } from "../types";

// Presentation only: names come from the saved experiment, never today's catalog.
export function runLabel(run: Pick<RunRecord, "scenario" | "scenario_title" | "objective" | "scenario_id">): string {
  return run.scenario?.title?.trim() || run.scenario_title?.trim() || run.objective?.trim() || run.scenario_id || "Experiment";
}

export function objectiveLabel(reached?: boolean, mode?: string): string {
  return reached === true ? (mode === "simulate" ? "Achieved (synthetic)" : "Achieved") : reached === false ? "Not achieved" : "Not established";
}

export function stepOutcomeLabel(step: RunStep, mode: string): string {
  if (step.execution_disposition === "counterfactual") return "Simulated continuation";
  if (step.status === "blocked" || step.status === "control_blocked" || step.status === "refused") {
    if (mode === "simulate") return "Simulated stop";
    if (step.policy?.allowed === false || step.telemetry?.includes("policy.control_blocked")) return "Stopped by BlueFire policy";
    return step.status === "refused" ? "Refused · inspect cause" : "Blocked · inspect cause";
  }
  if (step.status === "failed" || step.status === "error") return mode === "simulate" ? "Simulated failure" : "Execution error";
  if (step.status === "success" || step.status === "succeeded") return mode === "simulate" ? "Simulated success" : "Reported success";
  return step.status.replaceAll("_", " ").replace(/^./, (letter) => letter.toUpperCase()) || "Not reported";
}

export function cleanupSummary(cleanup: RunRecord["cleanup"]) {
  if (cleanup === true) return "Complete";
  if (cleanup === false) return "Needs attention";
  if (!cleanup) return "Not recorded";
  const count = cleanup.outstanding_receipt_count ?? cleanup.outstanding_effects;
  const outstanding = typeof count === "number" ? count : undefined;
  if (outstanding !== undefined && outstanding > 0) return `Needs attention · ${outstanding} outstanding effect${outstanding === 1 ? "" : "s"}`;
  if (cleanup.success === false) return "Failed · cleanup needs attention";
  if (cleanup.success === true && outstanding === 0) return "Complete · no outstanding effects";
  if (cleanup.attempted === false) return "Not attempted";
  return typeof cleanup.status === "string" ? cleanup.status.replaceAll("_", " ").replace(/^./, (letter) => letter.toUpperCase()) : "Result not reported";
}

export function recordedTargetScope(run: RunRecord & { authorized_target_scope?: unknown }): string {
  for (const scope of [run.authorized_target_scope, run.policy?.authorized_target_scope, run.target_scope]) {
    if (!scope || typeof scope !== "object" || !("scope_refs" in scope) || !Array.isArray(scope.scope_refs)) continue;
    return scope.scope_refs.filter((ref): ref is string => typeof ref === "string" && Boolean(ref.trim())).join(", ") || "None recorded";
  }
  return "Not recorded";
}
