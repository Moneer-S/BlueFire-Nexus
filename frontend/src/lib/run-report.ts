import type { RunRecord } from "../types";
import { cleanupSummary, recordedTargetScope, objectiveLabel, runLabel, runLimitationGroups, stepOutcomeLabel } from "./run-presentation";

// Escape record text, including HTML, so saved metadata cannot become report markup.
const text = (value: unknown) => String(value ?? "Not recorded").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/[\\`*_{}[\]()#+.!|~-]/g, "\\$&").replace(/\r?\n/g, " ");

export function runReport(run: RunRecord): string {
  const records = run.evidence?.records;
  const count = (provenance: string) => records ? String(records.filter((record) => record.provenance === provenance).length) : "Not reported";
  const lines = [
    `# ${text(runLabel(run))}`, "", "BlueFire run report", "",
    `- Run: ${text(run.run_id)}`, `- Mode: ${text(run.mode)}${run.is_demo ? " (sanitized demo)" : ""}`,
    `- Status: ${text(run.status)}`, `- Started: ${text(run.created_at)}`, `- Finalized: ${text(run.finalized_at)}`,
    `- Scenario: ${text(run.scenario_id ?? run.scenario?.id)}`,
    `- Profile: ${text(run.runner_profile_id)}`, `- Authorized targets: ${text(recordedTargetScope(run))}`,
    `- AI mode: ${text(run.autonomy ?? run.autonomy_level ?? (run.ai_enabled ? "assist" : "off"))}`,
    "", "## Recorded outcome", "", `Objective: ${text(run.objective)}`,
    "", `**${objectiveLabel(run.objective_reached, run.mode)}**`, "",
    run.mode === "simulate" ? "Simulation does not establish real effects or a working defense." : "An achieved objective requires independent observations to establish real effects; a failed objective alone does not prove a target defense stopped it.",
    "", `Cleanup: ${text(cleanupSummary(run.cleanup))}`,
    run.mode === "simulate" ? "Simulate does not perform target cleanup." : "Missing cleanup records do not establish that effects were removed.",
    "", "## Recorded path", "",
    ...(run.steps?.length ? run.steps.flatMap((step, index) => [
      `${index + 1}. **${text(step.step_id)}** — ${text(stepOutcomeLabel(step, run.mode))}`,
      `   Behavior: ${text(step.behavior_id)}; method: ${text(step.action_id ?? step.simulation_id)}; disposition: ${text(step.execution_disposition)}.`,
      `   Evidence references: ${text(step.evidence_ids?.join(", ") || "None recorded")}.`,
      ...(step.error ? [`   Error: ${text(step.error.code)} — ${text(step.error.message)}`] : []),
    ]) : ["No completed steps are recorded; this does not establish completion."]),
    "", "## Evidence and detection", "",
    `- Independently observed: ${count("observed")}`, `- Runner output (executed): ${count("executed")}`,
    `- Synthetic: ${count("synthetic")}`, `- Counterfactual: ${count("counterfactual")}`, `- BlueFire control blocked: ${count("control_blocked")}`,
    "", "Runner output and synthetic or counterfactual evidence are not independent observations. BlueFire policy stops do not prove a target defense worked.",
    "", `Detection candidates: ${run.detections ? run.detections.candidates.length : "Not reported"}. Candidates alone do not establish a detection fired or passed evaluation.`,
    "", "Detector revisions and Detection Lab evaluations are separate records outside this run bundle.",
    ...runLimitationGroups(run).flatMap((group) => ["", `## ${group.title}`, "", ...(group.description ? [group.description, ""] : []),
      ...(group.items.length ? group.items.map((item) => `- ${text(item)}`) : ["No limitations were attached. This is incomplete metadata, not proof that there are none."])]),
    "", "## Reproducibility", "",
    `Manifest bundle hash: ${text(run.manifest?.bundle_hash)}`,
    "", "This readable report summarizes the displayed saved run. It is not the full evidence archive. Download the run bundle for exact original files, all event bytes, and independently hashed recovery records. No event-page truncation is applied to that archive.", "",
  ];
  return lines.join("\n");
}
