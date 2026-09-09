import type { RunConfiguration, Scenario } from "../types";

export const collectionSemanticsCollector = "collector.collection-semantics.sandbox.v1";
const extensions: Record<string, string> = {
  "sandbox.collection.records.v1": "jsonl",
  "sandbox.collection.archive.v1": "tar",
  "sandbox.collection.atomic-gzip.v1": "jsonl.gz",
};

export function collectionObservationSteps(scenario: Scenario) {
  return scenario.steps.filter((step) => Object.hasOwn(extensions, step.behavior_id)).map((step) => ({
    stepId: step.id,
    path: `staged/${step.parameters?.stage_variant === "heldout" ? "variation" : "collection"}/bundle.${extensions[step.behavior_id]}`,
  }));
}

export function collectionObserverSelection(config: RunConfiguration, enabled: boolean): string[] {
  const selected = config.collectors.filter((id) => id !== collectionSemanticsCollector);
  return enabled ? [...selected, collectionSemanticsCollector] : selected;
}
