import type { Scenario } from "../types";
import { graphSections, graphView } from "./graph-view";

const prefix = "bluefire.working-graph-view.v1:";
const maximumBytes = 32768;
type StepReference = { id: string; behavior: string };
export type WorkingGraphView = {
  selected: StepReference | null;
  mode: "graph" | "steps";
  allBranches: boolean;
  expanded: StepReference[];
  section: number | null;
  inspector: boolean;
  routes: boolean;
  inputs: boolean;
};

export function defaultGraphView(scenario: Scenario): WorkingGraphView {
  const step = scenario.steps[0];
  return { selected: step ? { id: step.id, behavior: step.behavior_id } : null,
    mode: window.matchMedia?.("(max-width: 760px)")?.matches ? "steps" : "graph",
    allBranches: false, expanded: [], section: 0, inspector: false, routes: false, inputs: false };
}

function reference(value: unknown, scenario: Scenario): value is StepReference {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const item = value as Record<string, unknown>;
  return Object.keys(item).length === 2 && typeof item.id === "string" && typeof item.behavior === "string"
    && scenario.steps.some(step => step.id === item.id && step.behavior_id === item.behavior);
}

/** Presentation only: never restores a graph, run configuration, or authority. */
export function readWorkingGraphView(scenario: Scenario): WorkingGraphView {
  const fallback = defaultGraphView(scenario);
  try {
    const raw = sessionStorage.getItem(prefix + scenario.id);
    if (!raw || raw.length > maximumBytes) return fallback;
    const record: unknown = JSON.parse(raw);
    if (!record || typeof record !== "object" || Array.isArray(record)) return fallback;
    const envelope = record as Record<string, unknown>;
    if (Object.keys(envelope).length !== 2 || envelope.scenarioId !== scenario.id || !envelope.view || typeof envelope.view !== "object" || Array.isArray(envelope.view)) return fallback;
    const value = envelope.view as Record<string, unknown>;
    if (Object.keys(value).length !== 8 || !(value.selected === null || reference(value.selected, scenario))
      || !(value.mode === "graph" || value.mode === "steps")
      || !["allBranches", "inspector", "routes", "inputs"].every(key => typeof value[key] === "boolean")
      || !Array.isArray(value.expanded) || value.expanded.length > 256 || !value.expanded.every(item => reference(item, scenario))
      || new Set(value.expanded.map(item => item.id)).size !== value.expanded.length
      || !(value.section === null || (Number.isSafeInteger(value.section) && Number(value.section) >= 0))) return fallback;
    const view = value as WorkingGraphView;
    let projection = graphView(scenario, view.allBranches, new Set(view.expanded.map(item => item.id)));
    // A legitimate retained step may have moved to a different branch or section.
    if (view.selected && !projection.visible.has(view.selected.id)) {
      view.allBranches = true;
      projection = graphView(scenario, true);
    }
    const sections = graphSections(projection.ordered);
    const selectedSection = sections.findIndex(section => section.steps.some(step => step.id === view.selected?.id));
    if (view.section !== null) view.section = selectedSection >= 0 ? selectedSection : Math.min(view.section, sections.length - 1);
    return view;
  } catch { return fallback; }
}

export function writeWorkingGraphView(scenario: Scenario, view: WorkingGraphView): void {
  try {
    const raw = JSON.stringify({ scenarioId: scenario.id, view });
    if (raw.length <= maximumBytes) sessionStorage.setItem(prefix + scenario.id, raw);
  } catch { /* View retention is optional; the working graph remains in ProductContext. */ }
}
