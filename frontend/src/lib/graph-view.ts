import dagre from "@dagrejs/dagre";
import type { Outcome, Scenario, ScenarioStep } from "../types";

export type ScenarioGraph = Pick<Scenario, "steps" | "edges" | "start" | "layout">;

export const GRAPH_NODE_WIDTH = 220;
export const GRAPH_NODE_HEIGHT = 104;

export type GraphViewport = { x: number; y: number; zoom: number };
export type GraphFrame = { width: number; height: number; x?: number; y?: number };
export type GraphNodeBounds = { x: number; y: number; width: number; height: number };

/** Opening a long path must not make every card an unreadable miniature. */
export function readableGraphViewport(node: GraphNodeBounds, frame: GraphFrame, atStart = false): GraphViewport {
  const margin = 24;
  const zoom = Math.max(0.1, Math.min(1, (frame.width - margin * 2) / node.width, (frame.height - margin * 2) / node.height));
  return {
    x: (frame.x ?? 0) + frame.width / 2 - (node.x + node.width / 2) * zoom,
    y: (frame.y ?? 0) + (atStart ? margin - node.y * zoom : frame.height / 2 - (node.y + node.height / 2) * zoom),
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
    x: (frame.x ?? 0) + frame.width / 2 - (left + width / 2) * zoom,
    y: (frame.y ?? 0) + frame.height / 2 - (top + height / 2) * zoom,
    zoom,
  };
}

/** Keep compact context readable; at path ends, use the canvas for connected work. */
export function focusedGraphViewport(selected: GraphNodeBounds, context: readonly GraphNodeBounds[], frame: GraphFrame, fitHeight = false): GraphViewport {
  const cards = [selected, ...context];
  const padding = 24;
  const readable = readableGraphViewport(selected, frame);
  // When opening, columns only slightly taller than the canvas fit their height
  // at a readable scale, so the bottom row is not clipped while panning sideways.
  const height = Math.max(...cards.map(card => card.y + card.height)) - Math.min(...cards.map(card => card.y));
  const heightZoom = (frame.height - padding * 2) / height;
  const zoom = fitHeight && heightZoom < readable.zoom && heightZoom >= 0.8 ? heightZoom : readable.zoom;
  const focused = { zoom, x: (frame.x ?? 0) + frame.width / 2 - (selected.x + selected.width / 2) * zoom, y: (frame.y ?? 0) + frame.height / 2 - (selected.y + selected.height / 2) * zoom };
  const whole = graphBoundsViewport(cards, frame, padding, focused.zoom);
  // A small adjustment can fit a compact plan in a shorter desktop window.
  // Longer plans retain readable cards instead of shrinking to an overview.
  if (whole && whole.zoom >= focused.zoom * 0.9) return whole;
  const constrain = (position: number, start: number, end: number, size: number, origin: number) => {
    if ((end - start) * focused.zoom <= size - padding * 2) return origin + size / 2 - (start + end) / 2 * focused.zoom;
    return Math.min(origin + padding - start * focused.zoom,
      Math.max(origin + size - padding - end * focused.zoom, position));
  };
  return {
    ...focused,
    x: constrain(focused.x, Math.min(...cards.map(card => card.x)), Math.max(...cards.map(card => card.x + card.width)), frame.width, frame.x ?? 0),
    y: constrain(focused.y, Math.min(...cards.map(card => card.y)), Math.max(...cards.map(card => card.y + card.height)), frame.height, frame.y ?? 0),
  };
}

/** Reveal only the obscured distance. Panel changes never reset user zoom. */
export function revealGraphNode(viewport: GraphViewport, node: GraphNodeBounds, frame: GraphFrame, margin = 48): GraphViewport {
  const shift = (start: number, size: number, extent: number) => {
    if (size > extent - margin * 2) return (extent - size) / 2 - start;
    return start < margin ? margin - start : start + size > extent - margin ? extent - margin - start - size : 0;
  };
  const x = shift(viewport.x + node.x * viewport.zoom - (frame.x ?? 0), node.width * viewport.zoom, frame.width);
  const y = shift(viewport.y + node.y * viewport.zoom - (frame.y ?? 0), node.height * viewport.zoom, frame.height);
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

const platformNames: Record<string, string> = { windows: "Windows", linux: "Linux", macos: "macOS" };
export function platformLabel(name: string): string {
  return platformNames[name.toLowerCase()] ?? inputLabel(name);
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

const FLOW_ROW_GAP = 64;
const FLOW_LANE_GAP = 80;
const FLOW_COLUMN_GAP = 112;
const FLOW_SINGLE_ROW_RANKS = 4;

/** Rows per flow column: three fit a 1366x768 Build canvas at a readable scale. */
export const FLOW_COLUMN_ROWS = 3;

/**
 * Column sizes for consecutive ranks, at most `rows` each. Balanced heights are
 * preferred, but a break crossed by a decision's outcomes or a branch entry
 * costs more than a shorter column, so decisions stay with their branches.
 */
function flowColumnSizes(scenario: ScenarioGraph, rankOf: ReadonlyMap<string, number>, rankCount: number, spine: ReadonlySet<string>, rows: number) {
  const destinations = new Map<string, Set<string>>();
  for (const edge of scenario.edges) destinations.set(edge.from_step, (destinations.get(edge.from_step) ?? new Set()).add(edge.to_step));
  const breakCost = new Array<number>(Math.max(0, rankCount - 1)).fill(0);
  for (const edge of scenario.edges) {
    const from = rankOf.get(edge.from_step), to = rankOf.get(edge.to_step);
    if (from === undefined || to === undefined || to <= from) continue;
    const splitsDecision = !spine.has(edge.to_step) || (destinations.get(edge.from_step)?.size ?? 0) > 1;
    for (let index = from; index < to; index += 1) breakCost[index]! += splitsDecision ? 6 : to - from > 1 ? 1 : 0;
  }
  const cost = [0], previous = [0];
  for (let end = 1; end <= rankCount; end += 1) {
    cost[end] = Infinity;
    for (let size = 1; size <= Math.min(rows, end); size += 1) {
      const start = end - size;
      const candidate = cost[start]! + (size - rows) ** 2 * 1.5 + (start > 0 ? breakCost[start - 1]! : 0);
      if (candidate < cost[end]!) { cost[end] = candidate; previous[end] = start; }
    }
  }
  const sizes: number[] = [];
  for (let end = rankCount; end > 0; end = previous[end]!) sizes.unshift(end - previous[end]!);
  return sizes;
}

/**
 * Columns of consecutive ranks. The success path keeps the first lane so its
 * edges stay straight; fallbacks and alternatives take side lanes in their own
 * rank, and unconnected steps follow the plan. Returns undefined when one row
 * already reads well.
 */
function columnFlowPositions(scenario: ScenarioGraph, ordered: readonly ScenarioStep[], rowLayout: NonNullable<Scenario["layout"]>) {
  const linked = new Set(scenario.edges.flatMap(edge => [edge.from_step, edge.to_step]));
  for (const step of ordered) for (const binding of Object.values(step.inputs)) if (binding.from_step !== step.id) { linked.add(step.id); linked.add(binding.from_step); }
  const connected = ordered.filter(step => linked.has(step.id));
  const detached = ordered.filter(step => !linked.has(step.id));
  const rankX = [...new Set(connected.map(step => Math.round(rowLayout[step.id]!.x)))].sort((a, b) => a - b);
  if (rankX.length <= FLOW_SINGLE_ROW_RANKS) return undefined;
  const rankOf = new Map(connected.map(step => [step.id, rankX.indexOf(Math.round(rowLayout[step.id]!.x))]));
  const ranks = rankX.map((_, rank) => connected.filter(step => rankOf.get(step.id) === rank).sort((a, b) => rowLayout[a.id]!.y - rowLayout[b.id]!.y));
  const spine = new Set(graphView(scenario, false).ordered.map(step => step.id));
  const lanes = new Map<string, number>();
  for (const rank of ranks) {
    const taken = new Set<number>();
    // A success loop can put two success-path steps in one rank; only the
    // first keeps the straight lane, the other is placed beside it.
    const straight = rank.find(step => spine.has(step.id));
    if (straight) { lanes.set(straight.id, 0); taken.add(0); }
    for (const step of rank) {
      if (step === straight) continue;
      // A side chain stays in its predecessor's lane where that lane is free.
      const predecessor = scenario.edges.find(edge => edge.to_step === step.id && lanes.has(edge.from_step) && !spine.has(edge.from_step));
      let lane = predecessor ? lanes.get(predecessor.from_step)! : 1;
      while (taken.has(lane)) lane += 1;
      lanes.set(step.id, lane); taken.add(lane);
    }
  }
  const sizes = flowColumnSizes(scenario, rankOf, ranks.length, spine, FLOW_COLUMN_ROWS);
  const positions: NonNullable<Scenario["layout"]> = {};
  let first = 0, x = 32;
  for (const size of sizes) {
    const columnRanks = ranks.slice(first, first + size);
    first += size;
    const steps = columnRanks.flat();
    // Without the success path, a column starts at its first occupied lane.
    const offset = steps.some(step => lanes.get(step.id) === 0) ? 0 : Math.min(...steps.map(step => lanes.get(step.id)!));
    const widest = Math.max(...steps.map(step => lanes.get(step.id)! - offset));
    columnRanks.forEach((rank, row) => rank.forEach(step => {
      positions[step.id] = { x: x + (lanes.get(step.id)! - offset) * (GRAPH_NODE_WIDTH + FLOW_LANE_GAP), y: 32 + row * (GRAPH_NODE_HEIGHT + FLOW_ROW_GAP) };
    }));
    x += (widest + 1) * GRAPH_NODE_WIDTH + widest * FLOW_LANE_GAP + FLOW_COLUMN_GAP;
  }
  detached.forEach((step, index) => {
    positions[step.id] = { x: x + Math.floor(index / FLOW_COLUMN_ROWS) * (GRAPH_NODE_WIDTH + FLOW_COLUMN_GAP), y: 32 + index % FLOW_COLUMN_ROWS * (GRAPH_NODE_HEIGHT + FLOW_ROW_GAP) };
  });
  return positions;
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
  // Plans longer than a few ranks read top to bottom in short balanced columns,
  // left to right, so an ordinary plan fits a desktop canvas at readable scale
  // instead of one long row or a thumbnail. Dagre still decides ranks and order;
  // connections, failure and data routes are unchanged.
  // Saved coordinates are restored below, so opening a graph never moves them.
  const flow = columnFlowPositions(scenario, ordered, positions);
  if (flow) Object.assign(positions, flow);
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
