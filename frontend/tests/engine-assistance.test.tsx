import { expect, it } from "vitest";
import { engineAssistanceLabel, engineExperimentSelection, engineExperimentSelectionMatches, validEngineExperimentSelection } from "../src/lib/engine-assistance";
import type { EngineExperiment } from "../src/lib/engine-experiment";

const attemptId = `engine-attempt-${"4".repeat(32)}`;
const experiment = {
  experiment_id: `experiment-${"1".repeat(32)}`,
  workspace_digest: `sha256:${"2".repeat(64)}`,
  objective: { title: "Controlled tenant-record defense fixture", summary: "Fixture only." },
  projection: { attempts: [{ attempt_id: attemptId, role: "baseline" }] },
} as unknown as EngineExperiment;

it("captures an exact immutable experiment and selected attempt context", () => {
  const selection = engineExperimentSelection(experiment, attemptId);
  expect(selection).toEqual({ kind: "engine_experiment", experiment_id: experiment.experiment_id, workspace_digest: experiment.workspace_digest, attempt_id: attemptId });
  expect(validEngineExperimentSelection(selection)).toBe(true);
  expect(engineExperimentSelectionMatches(selection, experiment)).toBe(true);
});

it("refuses unknown or extra selection fields", () => {
  expect(validEngineExperimentSelection({ kind: "engine_experiment", experiment_id: experiment.experiment_id, workspace_digest: experiment.workspace_digest, attempt_id: null, current: true })).toBe(false);
  expect(validEngineExperimentSelection({ kind: "engine_experiment", experiment_id: "engine-experiment-wrong", workspace_digest: experiment.workspace_digest, attempt_id: null })).toBe(false);
  expect(validEngineExperimentSelection({ kind: "engine_experiment", experiment_id: experiment.experiment_id, result_digest: experiment.workspace_digest, attempt_id: null })).toBe(false);
});

it("refuses a missing attempt instead of silently changing captured context", () => {
  expect(() => engineExperimentSelection(experiment, `engine-attempt-${"f".repeat(32)}`)).toThrow(/unavailable/i);
});

it("does not match a newer mutable experiment digest", () => {
  const selection = engineExperimentSelection(experiment, attemptId);
  const changed = { ...experiment, workspace_digest: `sha256:${"3".repeat(64)}` } as EngineExperiment;
  expect(engineExperimentSelectionMatches(selection, changed)).toBe(false);
});

it("uses the same purpose-first attempt language as the workspace", () => {
  expect(engineAssistanceLabel(engineExperimentSelection(experiment, attemptId), experiment)).toBe("Controlled tenant-record defense fixture: Baseline exploration");
});
