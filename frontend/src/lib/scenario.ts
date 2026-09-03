import type { Outcome, Scenario } from "../types";

const scenarioOutcomes = new Set(["success", "partial", "blocked", "failed"]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function requireString(document: Record<string, unknown>, field: string, path: string) {
  if (typeof document[field] !== "string" || !document[field]) throw new Error(`Scenario ${path}.${field} must be a non-empty string.`);
}

function requireStringArray(value: unknown, path: string): asserts value is string[] {
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) throw new Error(`Scenario ${path} must be an array of strings.`);
}

function isParameterValue(value: unknown) {
  return typeof value === "string"
    || typeof value === "boolean"
    || (typeof value === "number" && Number.isFinite(value))
    || (Array.isArray(value) && value.every((item) => typeof item === "string"));
}

export function parseScenarioDocument(value: unknown): Scenario {
  if (!isRecord(value)) throw new Error("The document is not a BlueFire scenario object.");
  for (const field of ["schema_version", "id", "title", "purpose", "start"]) requireString(value, field, "document");
  if (!Array.isArray(value.steps)) throw new Error("Scenario document.steps must be an array.");
  const steps = value.steps.map((candidate, index) => {
    const path = `document.steps[${index}]`;
    if (!isRecord(candidate)) throw new Error(`Scenario ${path} must be an object.`);
    requireString(candidate, "id", path);
    requireString(candidate, "behavior_id", path);
    const parameters = candidate.parameters === undefined ? {} : candidate.parameters;
    if (!isRecord(parameters)) throw new Error(`Scenario ${path}.parameters must be an object.`);
    for (const [name, parameter] of Object.entries(parameters)) {
      if (!isParameterValue(parameter)) throw new Error(`Scenario ${path}.parameters.${name} must be a string, finite number, boolean, or string array.`);
    }
    const inputs = candidate.inputs === undefined ? {} : candidate.inputs;
    if (!isRecord(inputs)) throw new Error(`Scenario ${path}.inputs must be an object.`);
    for (const [name, binding] of Object.entries(inputs)) {
      if (!isRecord(binding)) throw new Error(`Scenario ${path}.inputs.${name} must be an artifact binding object.`);
      requireString(binding, "from_step", `${path}.inputs.${name}`);
      requireString(binding, "artifact", `${path}.inputs.${name}`);
    }
    const alternates = candidate.alternates == null ? [] : candidate.alternates;
    requireStringArray(alternates, `${path}.alternates`);
    return { ...candidate, parameters, inputs, alternates };
  });
  if (!Array.isArray(value.edges)) throw new Error("Scenario document.edges must be an array.");
  value.edges.forEach((candidate, index) => {
    const path = `document.edges[${index}]`;
    if (!isRecord(candidate)) throw new Error(`Scenario ${path} must be an object.`);
    requireString(candidate, "from_step", path);
    requireString(candidate, "to_step", path);
    if (typeof candidate.outcome !== "string" || !scenarioOutcomes.has(candidate.outcome)) throw new Error(`Scenario ${path}.outcome must be success, partial, blocked, or failed.`);
  });
  if (!isRecord(value.provenance)) throw new Error("Scenario document.provenance must be an object.");
  for (const field of ["source", "reference", "license"]) requireString(value.provenance, field, "document.provenance");
  if (typeof value.provenance.derived !== "boolean") throw new Error("Scenario document.provenance.derived must be a boolean.");
  const provenance = { ...value.provenance };
  if (provenance.notes == null) delete provenance.notes;
  else if (typeof provenance.notes !== "string" || !provenance.notes.trim()) throw new Error("Scenario document.provenance.notes must be a non-empty string when provided.");
  const limitations = value.limitations == null ? [] : value.limitations;
  requireStringArray(limitations, "document.limitations");
  if (value.layout !== undefined) {
    if (!isRecord(value.layout)) throw new Error("Scenario document.layout must be an object.");
    for (const [stepId, position] of Object.entries(value.layout)) {
      if (!isRecord(position) || typeof position.x !== "number" || !Number.isFinite(position.x) || typeof position.y !== "number" || !Number.isFinite(position.y)) throw new Error(`Scenario document.layout.${stepId} must contain finite x and y coordinates.`);
    }
  }
  return { ...value, steps, provenance, limitations } as unknown as Scenario;
}

export interface ScenarioGraphDeletionEdge {
  kind?: "route" | "artifact";
  outcome?: Outcome;
  source: string;
  target: string;
  sourceHandle?: string | null;
  targetHandle?: string | null;
}

export function deleteScenarioGraphElements(
  scenario: Scenario,
  deletedNodeIds: readonly string[],
  deletedEdges: readonly ScenarioGraphDeletionEdge[],
): Scenario {
  const deletedNodes = new Set(deletedNodeIds);
  const deletedRoutes = deletedEdges.filter((edge) => edge.kind === "route");
  const deletedArtifacts = deletedEdges.filter((edge) => edge.kind === "artifact");
  const steps = scenario.steps
    .filter((step) => !deletedNodes.has(step.id))
    .map((step) => ({
      ...step,
      inputs: Object.fromEntries(Object.entries(step.inputs).filter(([inputName, binding]) => (
        !deletedNodes.has(binding.from_step)
        && !deletedArtifacts.some((edge) => (
          edge.source === binding.from_step
          && edge.target === step.id
          && edge.sourceHandle === `out:${binding.artifact}`
          && edge.targetHandle === `in:${inputName}`
        ))
      ))),
    }));
  const edges = scenario.edges.filter((edge) => (
    !deletedNodes.has(edge.from_step)
    && !deletedNodes.has(edge.to_step)
    && !deletedRoutes.some((deleted) => (
      deleted.source === edge.from_step
      && deleted.target === edge.to_step
      && deleted.outcome === edge.outcome
    ))
  ));
  const layout = scenario.layout === undefined
    ? undefined
    : Object.fromEntries(Object.entries(scenario.layout).filter(([stepId]) => !deletedNodes.has(stepId)));
  return {
    ...scenario,
    start: deletedNodes.has(scenario.start) ? steps[0]?.id ?? "missing_start" : scenario.start,
    steps,
    edges,
    layout,
  };
}
