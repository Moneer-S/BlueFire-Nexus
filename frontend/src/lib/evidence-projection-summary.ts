import type { EvidenceRecord } from "../types";

const SIMULATOR_SCHEMA = "bluefire.evidence.v1";
const SIMULATOR_PRODUCER = "simulation-registry.v1";
const FIXTURE_SIMULATION = "simulation.sandbox.fixture.create.v1";
const WORKSPACE_ARTIFACT = "artifact.sandbox.workspace.v1";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Describe a saved simulator projection only when its recorded contract is exact. */
export function simulationProjectionSummary(record: EvidenceRecord): string | undefined {
  if (
    record.schema_version !== SIMULATOR_SCHEMA ||
    record.producer !== SIMULATOR_PRODUCER ||
    record.provenance !== "synthetic"
  ) return undefined;

  const content = record.content;
  if (!isRecord(content) || content.side_effects_started !== false || content.simulation_id !== FIXTURE_SIMULATION) {
    return undefined;
  }

  const artifacts = content.artifacts;
  if (!isRecord(artifacts)) return undefined;
  const workspace = artifacts.workspace;
  if (!isRecord(workspace) || workspace.type !== WORKSPACE_ARTIFACT || workspace.format !== "jsonl") {
    return undefined;
  }

  const count = workspace.record_count;
  if (!Number.isSafeInteger(count) || (count as number) < 1 || (count as number) > 100) return undefined;

  return `Simulation projected ${count} sample ${count === 1 ? "record" : "records"} in JSONL format.`;
}
