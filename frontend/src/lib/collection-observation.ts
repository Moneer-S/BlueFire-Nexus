import type { RunConfiguration, Scenario } from "../types";

export const collectionSemanticsCollector = "collector.collection-semantics.sandbox.v1";
const methods = new Set(["sandbox.collection.records.v1", "sandbox.collection.archive.v1"]);

export function collectionObservationSteps(scenario: Scenario) {
  return scenario.steps.filter((step) => methods.has(step.behavior_id)).map((step) => ({
    stepId: step.id,
    path: `staged/${step.parameters?.stage_variant === "heldout" ? "variation" : "collection"}/bundle.${step.behavior_id === "sandbox.collection.archive.v1" ? "tar" : "jsonl"}`,
  }));
}

export function collectionObserverSelection(config: RunConfiguration, enabled: boolean): string[] {
  const selected = config.collectors.filter((id) => id !== collectionSemanticsCollector);
  return enabled ? [...selected, collectionSemanticsCollector] : selected;
}
