import { beforeEach, expect, it, vi } from "vitest";
import { request } from "../src/lib/api";
import { checkedEngineExperimentList, engineExperimentApi, engineExperimentPath } from "../src/lib/engine-experiment-api";

vi.mock("../src/lib/api", () => ({ request: vi.fn() }));

const checkedWorkspace = vi.hoisted(() => vi.fn((value: unknown, _experimentId?: string, selection?: { kind: string; id: string }) => {
  if (selection?.kind === "controller_check") throw new Error("Selected workspace context changed.");
  return value;
}));
vi.mock("../src/lib/engine-experiment", () => ({ checkedEngineExperiment: checkedWorkspace }));

beforeEach(() => { vi.mocked(request).mockReset(); checkedWorkspace.mockClear(); });

it("loads and binds the exact selected workspace through a canonical API query", async () => {
  const experimentId = `experiment-${"a".repeat(32)}`;
  const attemptId = `engine-attempt-${"b".repeat(32)}`;
  const raw = { experiment_id: experimentId, selected_context: { kind: "engine_attempt" } };
  vi.mocked(request).mockResolvedValue(raw);

  const workspace = await engineExperimentApi.workspace(experimentId, { kind: "engine_attempt", id: attemptId });

  expect(workspace.selected_context?.kind).toBe("engine_attempt");
  expect(request).toHaveBeenCalledExactlyOnceWith(`/engine-experiments/${experimentId}/workspace?attempt=${attemptId}`);
  expect(checkedWorkspace).toHaveBeenCalledWith(raw, experimentId, { kind: "engine_attempt", id: attemptId });
});

it("rejects malformed route identities before making a request", async () => {
  expect(engineExperimentPath(`experiment-${"a".repeat(32)}`, { kind: "controller_check", id: `controller-check-${"c".repeat(32)}` }))
    .toBe(`/composition?engine_experiment=experiment-${"a".repeat(32)}&check=controller-check-${"c".repeat(32)}`);
  expect(() => engineExperimentPath("experiment-invalid")).toThrow(/experiment identity/i);
  expect(() => engineExperimentPath(`experiment-${"a".repeat(32)}`, { kind: "engine_attempt", id: "engine-attempt-invalid" })).toThrow(/attempt identity/i);
  expect(() => engineExperimentPath(`experiment-${"a".repeat(32)}`, { kind: "controller_check", id: "controller-check-invalid" })).toThrow(/check identity/i);
  expect(() => engineExperimentPath(`experiment-${"a".repeat(32)}`, { kind: "engine_attempt", id: `engine-attempt-${"b".repeat(32)}`, extra: true } as never)).toThrow(/selection/i);
  expect(request).not.toHaveBeenCalled();
});

it("strictly validates bounded saved experiment heads", () => {
  const value = {
    schema_version: "bluefire.engine-experiment-list.v1",
    experiments: [{
      schema_version: "bluefire.engine-experiment-head.v1",
      experiment_id: `experiment-${"a".repeat(32)}`,
      active_revision: 3,
      active_digest: `sha256:${"b".repeat(64)}`,
      created_at: "2026-11-04T12:00:00Z",
      updated_at: "2026-11-04T12:01:00Z",
    }],
  };
  expect(checkedEngineExperimentList(value)).toEqual(value);
  expect(() => checkedEngineExperimentList({ ...value, experiments: [value.experiments[0], value.experiments[0]] })).toThrow(/invalid/i);
  expect(() => checkedEngineExperimentList({ ...value, next_cursor: null })).toThrow(/invalid/i);
  expect(() => checkedEngineExperimentList({ ...value, experiments: [{ ...value.experiments[0], updated_at: "2026-02-31T12:01:00Z" }] })).toThrow(/invalid/i);
});

it("refuses a response whose selected context does not match the requested item", async () => {
  const experimentId = `experiment-${"a".repeat(32)}`;
  const checkId = `controller-check-${"c".repeat(32)}`;
  const raw = { experiment_id: experimentId };
  vi.mocked(request).mockResolvedValue(raw);

  await expect(engineExperimentApi.workspace(experimentId, { kind: "controller_check", id: checkId })).rejects.toThrow(/selected workspace context changed/i);
});
