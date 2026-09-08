import type { RunRecord, RunStep } from "../types";

export { runLabel, runMatchesSearch } from "./runPresentation";

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

export function runLimitationGroups(run: Pick<RunRecord, "scenario" | "limitations">) {
  const notes = run.limitations ?? [];
  const source = run.scenario?.limitations;
  if (!Array.isArray(source) || (!source.length && !notes.length)) return [{ title: "Recorded limitations", description: "", items: notes }];
  // Only exact immutable scenario provenance classifies a note. Never guess from
  // its wording or treat source constraints as satisfied by a completed run.
  // Source notes stand independently even when a partial result omits its copies.
  const sourceNotes = [...source];
  const runNotes = notes.filter((note) => !source.includes(note));
  return [
    ...(runNotes.length ? [{ title: "Run limitations", description: "", items: runNotes }] : []),
    ...(sourceNotes.length ? [{ title: "Scenario assumptions and source notes", description: "Recorded when the saved experiment was authored. These assumptions and constraints remain relevant; this run's preparation, approval, and outcomes are recorded separately.", items: sourceNotes }] : []),
  ];
}
