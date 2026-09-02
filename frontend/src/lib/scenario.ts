import type { Scenario } from "../types";

const scenarioOutcomes = new Set(["success", "partial", "blocked", "failed"]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function requireString(document: Record<string, unknown>, field: string, path: string) {
  if (typeof document[field] !== "string" || !document[field]) throw new Error(`Scenario ${path}.${field} must be a non-empty string.`);
}

function requireStringArray(value: unknown, path: string) {
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
  value.steps.forEach((candidate, index) => {
    const path = `document.steps[${index}]`;
    if (!isRecord(candidate)) throw new Error(`Scenario ${path} must be an object.`);
    requireString(candidate, "id", path);
    requireString(candidate, "behavior_id", path);
    if (!isRecord(candidate.parameters)) throw new Error(`Scenario ${path}.parameters must be an object.`);
    for (const [name, parameter] of Object.entries(candidate.parameters)) {
      if (!isParameterValue(parameter)) throw new Error(`Scenario ${path}.parameters.${name} must be a string, finite number, boolean, or string array.`);
    }
    if (!isRecord(candidate.inputs)) throw new Error(`Scenario ${path}.inputs must be an object.`);
    for (const [name, binding] of Object.entries(candidate.inputs)) {
      if (!isRecord(binding)) throw new Error(`Scenario ${path}.inputs.${name} must be an artifact binding object.`);
      requireString(binding, "from_step", `${path}.inputs.${name}`);
      requireString(binding, "artifact", `${path}.inputs.${name}`);
    }
    requireStringArray(candidate.alternates, `${path}.alternates`);
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
  for (const field of ["source", "reference", "license", "notes"]) {
    if (value.provenance[field] !== undefined && typeof value.provenance[field] !== "string") throw new Error(`Scenario document.provenance.${field} must be a string.`);
  }
  if (value.provenance.derived !== undefined && typeof value.provenance.derived !== "boolean") throw new Error("Scenario document.provenance.derived must be a boolean.");
  requireStringArray(value.limitations, "document.limitations");
  if (value.layout !== undefined) {
    if (!isRecord(value.layout)) throw new Error("Scenario document.layout must be an object.");
    for (const [stepId, position] of Object.entries(value.layout)) {
      if (!isRecord(position) || typeof position.x !== "number" || !Number.isFinite(position.x) || typeof position.y !== "number" || !Number.isFinite(position.y)) throw new Error(`Scenario document.layout.${stepId} must contain finite x and y coordinates.`);
    }
  }
  return value as unknown as Scenario;
}
