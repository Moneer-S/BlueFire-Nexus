import dagre from "@dagrejs/dagre";
import type { Outcome, Scenario, ScenarioStep } from "../types";

export type ScenarioGraph = Pick<Scenario, "steps" | "edges" | "start" | "layout">;

export const GRAPH_NODE_WIDTH = 220;
export const GRAPH_NODE_HEIGHT = 104;

export type GraphViewport = { x: number; y: number; zoom: number };
export type GraphFrame = { width: number; height: number };
export type GraphNodeBounds = { x: number; y: number; width: number; height: number };

/** Opening a long path must not make every card an unreadable miniature. */
export function readableGraphViewport(node: GraphNodeBounds, frame: GraphFrame, atStart = false): GraphViewport {
  const margin = 24;
  const zoom = Math.max(0.1, Math.min(1, (frame.width - margin * 2) / node.width, (frame.height - margin * 2) / node.height));
  return {
    x: frame.width / 2 - (node.x + node.width / 2) * zoom,
    y: atStart ? margin - node.y * zoom : frame.height / 2 - (node.y + node.height / 2) * zoom,
    zoom,
  };
}

/** Fit a visible topology or step group without allowing a zoom floor to clip it. */
export function graphBoundsViewport(nodes: readonly GraphNodeBounds[], frame: GraphFrame, padding = 24, maxZoom = 1): GraphViewport | undefined {
  if (!nodes.length || frame.width <= 0 || frame.height <= 0) return undefined;
  const left = Math.min(...nodes.map(node => node.x));
  const top = Math.min(...nodes.map(node => node.y));
  const right = Math.max(...nodes.map(node => node.x + node.width));
  const bottom = Math.max(...nodes.map(node => node.y + node.height));
  const width = right - left;
  const height = bottom - top;
  const zoom = Math.min(maxZoom, (frame.width - padding * 2) / width, (frame.height - padding * 2) / height);
  if (!Number.isFinite(zoom) || zoom <= 0) return undefined;
  return {
    x: frame.width / 2 - (left + width / 2) * zoom,
    y: frame.height / 2 - (top + height / 2) * zoom,
    zoom,
  };
}

/** Reveal only the obscured distance. Panel changes never reset user zoom. */
export function revealGraphNode(viewport: GraphViewport, node: GraphNodeBounds, frame: GraphFrame, margin = 48): GraphViewport {
  const shift = (start: number, size: number, extent: number) => {
    if (size > extent - margin * 2) return (extent - size) / 2 - start;
    return start < margin ? margin - start : start + size > extent - margin ? extent - margin - start - size : 0;
  };
  const x = shift(viewport.x + node.x * viewport.zoom, node.width * viewport.zoom, frame.width);
  const y = shift(viewport.y + node.y * viewport.zoom, node.height * viewport.zoom, frame.height);
  return x || y ? { ...viewport, x: viewport.x + x, y: viewport.y + y } : viewport;
}

/** Keep nearby causes and destinations visible when they fit at the operator's zoom. */
export function revealGraphContext(viewport: GraphViewport, selected: GraphNodeBounds, neighbors: readonly GraphNodeBounds[], frame: GraphFrame): GraphViewport {
  if (!neighbors.length) return revealGraphNode(viewport, selected, frame);
  const cards = [selected, ...neighbors];
  const x = Math.min(...cards.map(card => card.x));
  const y = Math.min(...cards.map(card => card.y));
  const width = Math.max(...cards.map(card => card.x + card.width)) - x;
  const height = Math.max(...cards.map(card => card.y + card.height)) - y;
  if (width * viewport.zoom > frame.width - 48 || height * viewport.zoom > frame.height - 48) return revealGraphNode(viewport, selected, frame);
  return revealGraphNode(viewport, { x, y, width, height }, frame, 24);
}

/** Maximal connected paths, split at decisions and joins. These are view groups, never execution phases. */
export function graphSections(steps: readonly ScenarioStep[], edges: ScenarioGraph["edges"] = [], start?: string) {
  const byId = new Map(steps.map(step => [step.id, step]));
  const ordinals = new Map(steps.map((step, index) => [step.id, index + 1]));
  const incoming = new Map(steps.map(step => [step.id, new Set<string>()]));
  const outgoing = new Map(steps.map(step => [step.id, new Set<string>()]));
  for (const edge of edges) if (byId.has(edge.from_step) && byId.has(edge.to_step)) {
    outgoing.get(edge.from_step)!.add(edge.to_step);
    incoming.get(edge.to_step)!.add(edge.from_step);
  }
  if (!steps.length || !edges.length) return [{ title: "All steps", steps: [...steps] }];
  const entry = byId.get(start ?? "") ?? steps.find(step => incoming.get(step.id)!.size === 0);
  const pathStarts = steps.filter(step => {
    const predecessors = incoming.get(step.id)!;
    if (predecessors.size !== 1) return true;
    return outgoing.get(predecessors.values().next().value!)!.size !== 1;
  });
  const assigned = new Set<string>();
  const groups: { title: string; steps: ScenarioStep[] }[] = [];
  // Seed from topology before array order. Anchor the real entry point so a
  // returning route cannot hide it inside a join group; leftovers cover cycles.
  for (const first of [...(entry ? [entry] : []), ...pathStarts, ...steps]) {
    if (assigned.has(first.id)) continue;
    const group = [first];
    assigned.add(first.id);
    let current = first;
    while (outgoing.get(current.id)?.size === 1) {
      const nextId = [...outgoing.get(current.id)!][0]!;
      if (assigned.has(nextId) || incoming.get(nextId)?.size !== 1) break;
      const next = byId.get(nextId)!;
      group.push(next); assigned.add(nextId); current = next;
    }
    const ordinal = ordinals.get(first.id)!;
    const title = groups.length === 0 ? "Main path" : incoming.get(first.id)!.size > 1 ? `Join at step ${ordinal}` : incoming.get(first.id)!.size ? `Branch at step ${ordinal}` : `Disconnected path at step ${ordinal}`;
    groups.push({ title, steps: group });
  }
  return groups.length === 1 ? [{ ...groups[0]!, title: "All steps" }] : groups;
}

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
export function graphView(scenario: ScenarioGraph, allBranches: boolean, expanded: ReadonlySet<string> = new Set()) {
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

/** A topology projection only. Callers retain saved positions until explicit auto-layout. */
export function initialGraphLayout(scenario: ScenarioGraph, preserveSaved = false): NonNullable<Scenario["layout"]> {
  const ordered = graphView(scenario, false).ordered;
  const placed = new Set(ordered.map((step) => step.id));
  ordered.push(...scenario.steps.filter((step) => !placed.has(step.id)));
  const topology = new dagre.graphlib.Graph();
  topology.setGraph({ rankdir: "LR", nodesep: 48, ranksep: 56, edgesep: 18, marginx: 32, marginy: 32, acyclicer: "greedy" });
  topology.setDefaultEdgeLabel(() => ({}));
  for (const step of ordered) topology.setNode(step.id, { width: GRAPH_NODE_WIDTH, height: GRAPH_NODE_HEIGHT });
  // Placement needs one relation per node pair, not one constraint per outcome.
  // The renderer retains every distinct execution edge and artifact binding.
  const connect = (from: string, to: string, weight: number) => {
    if (!topology.hasNode(from) || !topology.hasNode(to)) return;
    topology.setEdge(from, to, { weight: Math.max(weight, topology.edge(from, to)?.weight ?? 0), minlen: 1 });
  };
  scenario.edges.forEach(edge => connect(edge.from_step, edge.to_step, edge.outcome === "success" ? 8 : 1));
  for (const step of ordered) for (const binding of Object.values(step.inputs)) {
    if (topology.hasNode(binding.from_step) && binding.from_step !== step.id) {
      connect(binding.from_step, step.id, 2);
    }
  }
  dagre.layout(topology);
  const positions = Object.fromEntries(ordered.map((step) => {
    const position = topology.node(step.id);
    return [step.id, { x: position.x! - GRAPH_NODE_WIDTH / 2, y: position.y! - GRAPH_NODE_HEIGHT / 2 }];
  }));
  // A small single success chain can use a compact, at-most-three-row overview.
  // Longer chains retain the continuous left-to-right flow and focus navigation.
  // Connections still determine order; failure and data routes remain intact.
  // Saved coordinates are restored below, so opening a graph never moves them.
  const successEdges = scenario.edges.filter(edge => edge.outcome === "success");
  const successPath = graphView(scenario, false).ordered;
  const sequential = successPath.length === ordered.length && successEdges.length === ordered.length - 1
    && successPath.every((step, index) => index === successPath.length - 1
      ? !successEdges.some(edge => edge.from_step === step.id)
      : successEdges.filter(edge => edge.from_step === step.id).length === 1 && successEdges.some(edge => edge.from_step === step.id && edge.to_step === successPath[index + 1]!.id));
  if (sequential && ordered.length > 3 && ordered.length <= 9) {
    const rows = Math.ceil(Math.sqrt(ordered.length));
    successPath.forEach((step, index) => {
      positions[step.id] = { x: 32 + Math.floor(index / rows) * (GRAPH_NODE_WIDTH + 88), y: 32 + (index % rows) * (GRAPH_NODE_HEIGHT + 44) };
    });
  }
  if (!preserveSaved) return positions;
  const occupied = ordered.flatMap(step => scenario.layout?.[step.id] ? [scenario.layout[step.id]!] : []);
  for (const step of ordered) {
    const saved = scenario.layout?.[step.id];
    if (saved) { positions[step.id] = { ...saved }; continue; }
    const position = positions[step.id]!;
    // Dagre does not pin nodes. Fill missing positions around the operator's
    // fixed cards without using a partial layout as permission to move them.
    let collision;
    while ((collision = occupied.find(rect => position.x < rect.x + GRAPH_NODE_WIDTH + 24 && position.x + GRAPH_NODE_WIDTH + 24 > rect.x && position.y < rect.y + GRAPH_NODE_HEIGHT + 24 && position.y + GRAPH_NODE_HEIGHT + 24 > rect.y))) {
      position.y = collision.y + GRAPH_NODE_HEIGHT + 48;
    }
    occupied.push(position);
  }
  return positions;
}

/** Compact only an isolated view group; saved operator coordinates remain authoritative unless explicitly replaced. */
export function focusedGraphLayout(scenario: ScenarioGraph, stepIds: readonly string[], replaceSaved = false): NonNullable<Scenario["layout"]> {
  const selected = new Set(stepIds);
  const steps = scenario.steps.filter(step => selected.has(step.id));
  if (!steps.length) return {};
  const ids = new Set(steps.map(step => step.id));
  const edges = scenario.edges.filter(edge => ids.has(edge.from_step) && ids.has(edge.to_step));
  const graph: ScenarioGraph = {
    steps,
    edges,
    start: ids.has(scenario.start) ? scenario.start : steps[0]!.id,
  };
  const positions = initialGraphLayout(graph);
  const pinned = replaceSaved ? [] : steps.filter(step => scenario.layout?.[step.id]);
  for (const step of pinned) positions[step.id] = { ...scenario.layout![step.id]! };
  const overlaps = (a: { x: number; y: number }, b: { x: number; y: number }) =>
    a.x < b.x + GRAPH_NODE_WIDTH + 24 && a.x + GRAPH_NODE_WIDTH + 24 > b.x
    && a.y < b.y + GRAPH_NODE_HEIGHT + 24 && a.y + GRAPH_NODE_HEIGHT + 24 > b.y;
  const generated = steps.filter(step => !pinned.some(pin => pin.id === step.id));
  const generatedCards = generated.map(step => positions[step.id]!);
  const hasOverlap = generatedCards.some((card, index) => generatedCards.slice(index + 1).some(other => overlaps(card, other)));
  if (!pinned.length && hasOverlap) {
    // Fully disconnected nodes can share a Dagre rank position. Preserve order
    // and guarantee usable cards instead of letting them cover one another.
    steps.forEach((step, index) => { positions[step.id] = { x: 32 + index * (GRAPH_NODE_WIDTH + 56), y: 32 }; });
  } else {
    const occupied = pinned.map(step => positions[step.id]!);
    for (const step of generated) {
      const position = positions[step.id]!;
      let collision;
      while ((collision = occupied.find(rect => overlaps(position, rect)))) position.y = collision.y + GRAPH_NODE_HEIGHT + 48;
      occupied.push(position);
    }
  }
  return positions;
}
