import { engineAttemptLabel, type EngineExperiment } from "./engine-experiment";

export interface EngineExperimentAssistanceSelection {
  kind: "engine_experiment";
  experiment_id: string;
  workspace_digest: string;
  attempt_id: string | null;
}

const EXPERIMENT_ID = /^experiment-[0-9a-f]{32}$/;
const ATTEMPT_ID = /^engine-attempt-[0-9a-f]{32}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;

export function validEngineExperimentSelection(value: unknown): value is EngineExperimentAssistanceSelection {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const row = value as Record<string, unknown>;
  return Object.keys(row).sort().join() === "attempt_id,experiment_id,kind,workspace_digest"
    && row.kind === "engine_experiment"
    && typeof row.experiment_id === "string" && EXPERIMENT_ID.test(row.experiment_id)
    && typeof row.workspace_digest === "string" && DIGEST.test(row.workspace_digest)
    && (row.attempt_id === null || typeof row.attempt_id === "string" && ATTEMPT_ID.test(row.attempt_id));
}

export function engineExperimentSelection(experiment: EngineExperiment, attemptId?: string | null): EngineExperimentAssistanceSelection {
  const selected = attemptId ?? null;
  if (selected !== null && !experiment.projection.attempts.some(attempt => attempt.attempt_id === selected)) throw new Error("Selected engine attempt is unavailable.");
  return { kind: "engine_experiment", experiment_id: experiment.experiment_id, workspace_digest: experiment.workspace_digest, attempt_id: selected };
}

export function engineExperimentSelectionMatches(selection: EngineExperimentAssistanceSelection, experiment: EngineExperiment): boolean {
  return validEngineExperimentSelection(selection)
    && selection.experiment_id === experiment.experiment_id
    && selection.workspace_digest === experiment.workspace_digest
    && (selection.attempt_id === null || experiment.projection.attempts.some(attempt => attempt.attempt_id === selection.attempt_id));
}

export const engineAssistanceLabel = (selection: EngineExperimentAssistanceSelection, experiment: EngineExperiment): string => {
  if (!engineExperimentSelectionMatches(selection, experiment)) throw new Error("Engine Assistant context changed.");
  const attempt = selection.attempt_id === null ? undefined : experiment.projection.attempts.find(item => item.attempt_id === selection.attempt_id);
  return attempt ? `${experiment.objective.title}: ${engineAttemptLabel(attempt.role)}` : experiment.objective.title;
};
