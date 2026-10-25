import { describe, expect, it } from "vitest";
import type { EvidenceRecord } from "../src/types";
import { simulationProjectionSummary } from "../src/lib/evidence-projection-summary";

function evidence(overrides: Partial<EvidenceRecord> = {}): EvidenceRecord {
  return {
    schema_version: "bluefire.evidence.v1",
    producer: "simulation-registry.v1",
    provenance: "synthetic",
    content: {
      simulation_id: "simulation.sandbox.fixture.create.v1",
      side_effects_started: false,
      artifacts: {
        workspace: {
          type: "artifact.sandbox.workspace.v1",
          format: "jsonl",
          record_count: 8,
        },
      },
    },
    ...overrides,
  };
}

describe("simulationProjectionSummary", () => {
  it("summarizes only the simulator-owned fixture workspace projection", () => {
    expect(simulationProjectionSummary(evidence())).toBe("Simulation projected 8 sample records in JSONL format.");
    expect(simulationProjectionSummary(evidence({
      content: {
        simulation_id: "simulation.sandbox.fixture.create.v1",
        side_effects_started: false,
        artifacts: { workspace: { type: "artifact.sandbox.workspace.v1", format: "jsonl", record_count: 1 } },
      },
    }))).toBe("Simulation projected 1 sample record in JSONL format.");
  });

  it.each([
    ["schema", { schema_version: "bluefire.evidence.v2" }],
    ["producer", { producer: "adapter.fixture.v1" }],
    ["provenance", { provenance: "observed" }],
    ["missing content", { content: undefined }],
    ["missing simulation id", { content: { side_effects_started: false, artifacts: { workspace: { type: "artifact.sandbox.workspace.v1", format: "jsonl", record_count: 8 } } } }],
    ["other simulation", { content: { simulation_id: "simulation.sandbox.fixture.transform.v1", side_effects_started: false, artifacts: { workspace: { type: "artifact.sandbox.workspace.v1", format: "jsonl", record_count: 8 } } } }],
    ["effects started", { content: { simulation_id: "simulation.sandbox.fixture.create.v1", side_effects_started: true, artifacts: { workspace: { type: "artifact.sandbox.workspace.v1", format: "jsonl", record_count: 8 } } } }],
    ["effects unknown", { content: { simulation_id: "simulation.sandbox.fixture.create.v1", artifacts: { workspace: { type: "artifact.sandbox.workspace.v1", format: "jsonl", record_count: 8 } } } }],
    ["missing artifacts", { content: { simulation_id: "simulation.sandbox.fixture.create.v1", side_effects_started: false } }],
    ["wrong artifact", { content: { simulation_id: "simulation.sandbox.fixture.create.v1", side_effects_started: false, artifacts: { workspace: { type: "artifact.sandbox.file.v1", format: "jsonl", record_count: 8 } } } }],
    ["wrong format", { content: { simulation_id: "simulation.sandbox.fixture.create.v1", side_effects_started: false, artifacts: { workspace: { type: "artifact.sandbox.workspace.v1", format: "csv", record_count: 8 } } } }],
    ["fractional count", { content: { simulation_id: "simulation.sandbox.fixture.create.v1", side_effects_started: false, artifacts: { workspace: { type: "artifact.sandbox.workspace.v1", format: "jsonl", record_count: 1.5 } } } }],
    ["unsafe count", { content: { simulation_id: "simulation.sandbox.fixture.create.v1", side_effects_started: false, artifacts: { workspace: { type: "artifact.sandbox.workspace.v1", format: "jsonl", record_count: Number.MAX_SAFE_INTEGER + 1 } } } }],
    ["count below range", { content: { simulation_id: "simulation.sandbox.fixture.create.v1", side_effects_started: false, artifacts: { workspace: { type: "artifact.sandbox.workspace.v1", format: "jsonl", record_count: 0 } } } }],
    ["count above range", { content: { simulation_id: "simulation.sandbox.fixture.create.v1", side_effects_started: false, artifacts: { workspace: { type: "artifact.sandbox.workspace.v1", format: "jsonl", record_count: 101 } } } }],
  ] as const)("returns undefined for %s", (_label, overrides) => {
    expect(simulationProjectionSummary(evidence(overrides))).toBeUndefined();
  });

  it("does not mutate the saved evidence record", () => {
    const record = evidence();
    const before = structuredClone(record);
    expect(simulationProjectionSummary(record)).toBe("Simulation projected 8 sample records in JSONL format.");
    expect(record).toEqual(before);
  });
});
