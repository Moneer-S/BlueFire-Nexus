import type { Outcome, Scenario } from "../types";

export const branchLabels: Record<Outcome, string> = {
  success: "On success", partial: "When partly complete", blocked: "When blocked", failed: "On failure",
};

export function inputLabel(name: string): string {
  return name.replaceAll("_", " ").replace(/^./, (letter) => letter.toUpperCase());
}

export function inputTypeLabel(type: string): string {
  const words = type.replace(/^artifact\./, "").replace(/\.v\d+$/, "").replaceAll(".", " ").replaceAll("_", " ");
  return words || "compatible results";
}

/** A presentation-only projection. The complete scenario remains the execution plan. */
export function graphView(scenario: Scenario, allBranches: boolean, expanded: ReadonlySet<string> = new Set()) {
  const known = new Set(scenario.steps.map((step) => step.id));
  const visible = new Set<string>();
  const queue = allBranches ? scenario.steps.map((step) => step.id) : [scenario.start];
  for (let i = 0; i < queue.length; i += 1) {
    const id = queue[i]!;
    if (visible.has(id) || !known.has(id)) continue;
    visible.add(id);
    for (const edge of scenario.edges) {
      if (edge.from_step === id && (allBranches || edge.outcome === "success" || expanded.has(id))) queue.push(edge.to_step);
    }
  }
  const ordered = [...visible].map((id) => scenario.steps.find((step) => step.id === id)!);
  const hiddenBranches = scenario.edges.filter((edge) => !visible.has(edge.from_step) || !visible.has(edge.to_step) || (!allBranches && edge.outcome !== "success" && !expanded.has(edge.from_step))).length;
  return { visible, ordered, hiddenSteps: scenario.steps.length - visible.size, hiddenBranches };
}

/** Stable initial positions and an explicit arrange action; never moves saved positions. */
export function initialGraphLayout(scenario: Scenario): NonNullable<Scenario["layout"]> {
  const ordered = graphView(scenario, false).ordered;
  const placed = new Set(ordered.map((step) => step.id));
  ordered.push(...scenario.steps.filter((step) => !placed.has(step.id)));
  return Object.fromEntries(ordered.map((step, index) => [step.id, {
    x: 48 + (index % 4) * 294,
    y: 48 + Math.floor(index / 4) * 190,
  }]));
}
