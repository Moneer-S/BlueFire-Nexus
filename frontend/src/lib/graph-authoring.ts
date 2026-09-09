import type { Behavior, Scenario, ScenarioStep } from "../types";
import { inputLabel } from "./graph-view";

/** Producers must run before this step on every incoming path, including hidden branches. */
export function guaranteedInputSources(scenario: Pick<Scenario, "steps" | "edges" | "start">, target: string): Set<string> {
  const known = new Set(scenario.steps.map((step) => step.id));
  const reachable = (omitted?: string) => {
    const visited = new Set<string>();
    const queue = [scenario.start];
    for (let index = 0; index < queue.length; index++) {
      const id = queue[index]!;
      if (id === omitted || visited.has(id) || !known.has(id)) continue;
      visited.add(id);
      for (const edge of scenario.edges) if (edge.from_step === id) queue.push(edge.to_step);
    }
    return visited;
  };
  const connected = reachable();
  if (!connected.has(target)) return new Set();
  return new Set([...connected].filter((id) => id !== target && !reachable(id).has(target)));
}

/** A short authoring summary; execution results are never inferred from a design. */
export function stepParameterSummary(step: ScenarioStep, behavior?: Behavior): string {
  return (behavior?.parameters ?? []).flatMap((spec) => {
    const value = step.parameters[spec.name];
    if (value === undefined || value === null || value === "" || typeof value === "object") return [];
    const display = typeof value === "boolean" ? value ? "Yes" : "No" : String(value);
    return [`${inputLabel(spec.name)}: ${display.length > 48 ? `${display.slice(0, 45)}…` : display}`];
  }).slice(0, 2).join(" · ");
}
