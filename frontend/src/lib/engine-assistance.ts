import { engineAttemptLabel, engineControllerCheckLabel, type EngineExperiment } from "./engine-experiment";

export interface EngineExperimentAssistanceSelection {
  kind: "engine_experiment";
  experiment_id: string;
  workspace_digest: string;
  attempt_id: string | null;
  check_id: string | null;
}

const EXPERIMENT_ID = /^experiment-[0-9a-f]{32}$/;
const ATTEMPT_ID = /^engine-attempt-[0-9a-f]{32}$/;
const CHECK_ID = /^controller-check-[0-9a-f]{32}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;

export function validEngineExperimentSelection(value: unknown): value is EngineExperimentAssistanceSelection {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const row = value as Record<string, unknown>;
  const fields = ["attempt_id", "check_id", "experiment_id", "kind", "workspace_digest"];
  const actual = Object.keys(row).sort();
  return actual.length === fields.length && actual.every((field, index) => field === fields[index])
    && row.kind === "engine_experiment"
    && typeof row.experiment_id === "string" && EXPERIMENT_ID.test(row.experiment_id)
    && typeof row.workspace_digest === "string" && DIGEST.test(row.workspace_digest)
    && (row.attempt_id === null || typeof row.attempt_id === "string" && ATTEMPT_ID.test(row.attempt_id))
    && (row.check_id === null || typeof row.check_id === "string" && CHECK_ID.test(row.check_id))
    && !(row.attempt_id !== null && row.check_id !== null);
}

export function engineExperimentSelection(experiment: EngineExperiment, attemptId?: string | null, checkId?: string | null): EngineExperimentAssistanceSelection {
  const selectedAttempt = attemptId ?? null, selectedCheck = checkId ?? null;
  if (selectedAttempt !== null && selectedCheck !== null) throw new Error("Select either an engine attempt or a trusted check.");
  if (selectedAttempt !== null && !experiment.projection.attempts.some(attempt => attempt.attempt_id === selectedAttempt)) throw new Error("Selected engine attempt is unavailable.");
  if (selectedCheck !== null && !experiment.projection.checks.some(check => check.check_id === selectedCheck)) throw new Error("Selected controller check is unavailable.");
  return { kind: "engine_experiment", experiment_id: experiment.experiment_id, workspace_digest: experiment.workspace_digest, attempt_id: selectedAttempt, check_id: selectedCheck };
}

export function engineExperimentSelectionMatches(selection: EngineExperimentAssistanceSelection, experiment: EngineExperiment): boolean {
  return validEngineExperimentSelection(selection)
    && selection.experiment_id === experiment.experiment_id
    && selection.workspace_digest === experiment.workspace_digest
    && (selection.attempt_id === null || experiment.projection.attempts.some(attempt => attempt.attempt_id === selection.attempt_id))
    && (selection.check_id === null || experiment.projection.checks.some(check => check.check_id === selection.check_id));
}

export const engineAssistanceLabel = (selection: EngineExperimentAssistanceSelection, experiment: EngineExperiment): string => {
  if (!engineExperimentSelectionMatches(selection, experiment)) throw new Error("Engine Assistant context changed.");
  const attempt = selection.attempt_id === null ? undefined : experiment.projection.attempts.find(item => item.attempt_id === selection.attempt_id);
  const check = selection.check_id === null ? undefined : experiment.projection.checks.find(item => item.check_id === selection.check_id);
  return attempt ? `${experiment.objective.title}: ${engineAttemptLabel(attempt.role)}` : check ? `${experiment.objective.title}: ${engineControllerCheckLabel(check.role)}` : experiment.objective.title;
};
