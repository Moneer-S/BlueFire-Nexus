import { beforeEach, expect, it, vi } from "vitest";
import type { EngineExperiment } from "../src/lib/engine-experiment";
import { engineExperimentApi } from "../src/lib/engine-experiment-api";

const workspace = vi.hoisted(() => vi.fn());
vi.mock("../src/lib/engine-experiment-api", async importOriginal => {
  const actual = await importOriginal<typeof import("../src/lib/engine-experiment-api")>();
  return { ...actual, engineExperimentApi: { ...actual.engineExperimentApi, workspace } };
});

import { activeWorkHref, loadActiveWork } from "../src/lib/active-defensive-work";

const experimentId = `experiment-${"a".repeat(32)}`;
const baselineRun = "run-20261104T120001Z-1111111111111111";
const checkRun = "run-20261104T120002Z-2222222222222222";
const value = {
  experiment_id: experimentId,
  objective: { title: "Bounded tenant-record defense", summary: "Test one generated tenant-record objective." },
  environment: { display_name: "Disposable tenant lab", platform: "linux" },
  current_target: { snapshot_ref: `sha256:${"1".repeat(64)}` },
  defensive_change: { kind: "identity", summary: "Require a target-bound signed session." },
  projection: {
    workflow_state: "run_adaptive_search",
    attempts: [{ role: "baseline", attempt_id: `engine-attempt-${"b".repeat(32)}`, run_id: baselineRun }],
    checks: [{ role: "retained_reproducer", check_id: `controller-check-${"c".repeat(32)}`, run_id: checkRun }],
    conclusion: {
      original_mechanism: { status: "established" },
      retained_reproducer: { status: "blocked" },
      adaptive_search: { status: "not_started" },
      legitimate_use: { status: "not_started" },
    },
  },
} as unknown as EngineExperiment;

beforeEach(() => vi.mocked(engineExperimentApi.workspace).mockReset().mockResolvedValue(value));

it("uses the existing Home active-work model without inventing readiness or a latest cross-type selection", async () => {
  const reference = { family: "engine" as const, id: experimentId };
  const summary = await loadActiveWork(reference);

  expect(engineExperimentApi.workspace).toHaveBeenCalledExactlyOnceWith(experimentId);
  expect(summary.title).toBe("Bounded tenant-record defense");
  expect(summary.environment).toBe("Disposable tenant lab · Linux");
  expect(summary.phase).toBe("Run adaptive search");
  expect(summary.href).toBe(`/composition?engine_experiment=${experimentId}`);
  expect(summary.change).toBe("Identity: Require a target-bound signed session.");
  expect(summary.results).toEqual([
    { label: "Original mechanism", value: "Established", tone: "caution" },
    { label: "Original mechanism retest", value: "Blocked", tone: "positive" },
    { label: "Fresh adaptive search", value: "Not started", tone: "neutral" },
    { label: "Legitimate use", value: "Not started", tone: "neutral" },
  ]);
  expect(summary.links).toEqual([
    { label: "Baseline exploration run evidence", href: `/runs/${baselineRun}` },
    { label: "Original mechanism retest run evidence", href: `/runs/${checkRun}` },
  ]);
  expect(activeWorkHref(reference)).toBe(summary.href);
  expect(summary.results.map(item => item.label)).not.toContain("Coverage");
  expect(summary.results.map(item => item.label)).not.toContain("Readiness");
});
