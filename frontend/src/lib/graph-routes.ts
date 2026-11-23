import type { Edge } from "@xyflow/react";
import type { Outcome } from "../types";

export interface RoutePoint { x: number; y: number; }
export interface RouteObstacle extends RoutePoint { id: string; width: number; height: number; }
type PortSide = "top" | "bottom" | "left" | "right";
export interface RouteGeometry {
  source: RoutePoint;
  target: RoutePoint;
  sourceId?: string;
  targetId?: string;
  sourceSide?: PortSide;
  targetSide?: PortSide;
  obstacles?: readonly RouteObstacle[];
  lane?: number;
  labelWidth?: number;
}

export type BuilderFlowEdge = Edge<{
  kind: "route" | "artifact";
  outcome?: Outcome;
  artifactType?: string;
  artifactLabel?: string;
  number?: number;
  /** A conditional outcome that reaches the same step as its success route. */
  parallel?: boolean;
  /** On a success route: the conditional outcomes that reach the same step. */
  alsoOn?: readonly Outcome[];
  lane?: number;
  sourceTitle?: string;
  targetTitle?: string;
  obstacles?: readonly RouteObstacle[];
}>;

const clearance = 14;
const lead = 28;
const distance = (a: RoutePoint, b: RoutePoint) => Math.abs(a.x - b.x) + Math.abs(a.y - b.y);
const same = (a: RoutePoint, b: RoutePoint) => a.x === b.x && a.y === b.y;
function portLead(point: RoutePoint, side: PortSide, obstacles: readonly RouteObstacle[], ownId: string | undefined, length = lead): RoutePoint {
  const horizontal = side === "left" || side === "right";
  const forward = side === "right" || side === "bottom";
  for (const rect of obstacles) {
    if (rect.id === ownId) continue;
    const across = horizontal ? point.y : point.x;
    const low = (horizontal ? rect.y : rect.x) - clearance;
    const high = (horizontal ? rect.y + rect.height : rect.x + rect.width) + clearance;
    if (across <= low || across >= high) continue;
    const boundary = horizontal
      ? forward ? rect.x - clearance : rect.x + rect.width + clearance
      : forward ? rect.y - clearance : rect.y + rect.height + clearance;
    const gap = (boundary - (horizontal ? point.x : point.y)) * (forward ? 1 : -1);
    // A top handle extends above its card. In a compact row gap, a fixed lead
    // can enter the preceding card's clearance and trap every channel search.
    if (gap >= 0) length = Math.min(length, gap);
  }
  return { x: point.x + (side === "right" ? length : side === "left" ? -length : 0), y: point.y + (side === "bottom" ? length : side === "top" ? -length : 0) };
}
function simplify(points: RoutePoint[]): RoutePoint[] {
  const result: RoutePoint[] = [];
  for (const point of points) {
    if (result.length && same(result.at(-1)!, point)) continue;
    const [a, b] = result.slice(-2);
    if (a && b && ((a.x === b.x && b.x === point.x) || (a.y === b.y && b.y === point.y))) result.pop();
    result.push(point);
  }
  return result;
}

/** Touching a clearance boundary is allowed; entering an unrelated card is not. */
export function segmentCrossesObstacle(a: RoutePoint, b: RoutePoint, rect: RouteObstacle, padding = 0): boolean {
  const left = rect.x - padding, right = rect.x + rect.width + padding;
  const top = rect.y - padding, bottom = rect.y + rect.height + padding;
  if (a.x === b.x) return a.x > left && a.x < right && Math.max(a.y, b.y) > top && Math.min(a.y, b.y) < bottom;
  if (a.y === b.y) return a.y > top && a.y < bottom && Math.max(a.x, b.x) > left && Math.min(a.x, b.x) < right;
  return true;
}

function openPath(points: RoutePoint[], obstacles: readonly RouteObstacle[]): boolean {
  return points.slice(1).every((point, index) => !obstacles.some(rect => segmentCrossesObstacle(points[index]!, point, rect, clearance)));
}

/** Sparse orthogonal search is only needed when manually positioned cards block simple channels. */
function findChannel(start: RoutePoint, end: RoutePoint, obstacles: readonly RouteObstacle[]): RoutePoint[] | undefined {
  const xs = [...new Set([start.x, end.x, ...obstacles.flatMap(rect => [rect.x - clearance, rect.x + rect.width + clearance])])].sort((a, b) => a - b);
  const ys = [...new Set([start.y, end.y, ...obstacles.flatMap(rect => [rect.y - clearance, rect.y + rect.height + clearance])])].sort((a, b) => a - b);
  const width = xs.length;
  const point = (id: number): RoutePoint => ({ x: xs[id % width]!, y: ys[Math.floor(id / width)]! });
  const first = ys.indexOf(start.y) * width + xs.indexOf(start.x), last = ys.indexOf(end.y) * width + xs.indexOf(end.x);
  const cost = new Map<number, number>([[first, 0]]), previous = new Map<number, number>();
  const heap: { id: number; cost: number; priority: number }[] = [];
  function push(item: typeof heap[number]) {
    heap.push(item); let index = heap.length - 1;
    while (index > 0) { const parent = Math.floor((index - 1) / 2); if (heap[parent]!.priority <= item.priority) break; heap[index] = heap[parent]!; index = parent; }
    heap[index] = item;
  }
  function pop() {
    const result = heap[0]!, tail = heap.pop()!;
    if (heap.length) {
      let index = 0;
      while (index * 2 + 1 < heap.length) {
        let child = index * 2 + 1;
        if (child + 1 < heap.length && heap[child + 1]!.priority < heap[child]!.priority) child += 1;
        if (heap[child]!.priority >= tail.priority) break;
        heap[index] = heap[child]!; index = child;
      }
      heap[index] = tail;
    }
    return result;
  }
  push({ id: first, cost: 0, priority: distance(start, end) });
  while (heap.length) {
    const current = pop();
    if (current.cost !== cost.get(current.id)) continue;
    if (current.id === last) {
      const path = [end]; let id = last;
      while (id !== first) { id = previous.get(id)!; path.unshift(point(id)); }
      return simplify(path);
    }
    const at = point(current.id), column = current.id % width, row = Math.floor(current.id / width);
    const neighbors = [column > 0 ? current.id - 1 : -1, column + 1 < width ? current.id + 1 : -1, row > 0 ? current.id - width : -1, row + 1 < ys.length ? current.id + width : -1];
    for (const id of neighbors) {
      if (id < 0) continue;
      const next = point(id), nextCost = current.cost + distance(at, next);
      if (nextCost >= (cost.get(id) ?? Infinity) || obstacles.some(rect => segmentCrossesObstacle(at, next, rect, clearance))) continue;
      cost.set(id, nextCost); previous.set(id, current.id);
      push({ id, cost: nextCost, priority: nextCost + distance(next, end) });
    }
  }
  return undefined;
}

/** Routes use measured, visible card bounds and never move nodes or modify execution edges. */
export function routePath({ source, target, sourceId, targetId, sourceSide = "bottom", targetSide = "top", obstacles = [], lane = 0, labelWidth = 90 }: RouteGeometry) {
  const offset = 12 * lane;
  const vertical = sourceSide === "bottom" || sourceSide === "top";
  const targetVertical = targetSide === "bottom" || targetSide === "top";
  // Perpendicular arrivals need separate outward lanes before they turn back
  // toward a top/bottom join; their middle channel can lie inside the source.
  // A bottom port facing a top port across a narrow row gap shares the gap
  // between both leads, and its channel stays inside it: no U-shaped turn back.
  const facingGap = sourceSide === "bottom" && targetSide === "top" && target.y > source.y ? target.y - source.y : undefined;
  const start = portLead(source, sourceSide, obstacles, sourceId, Math.min(lead + (vertical !== targetVertical ? offset : 0), facingGap === undefined ? Infinity : facingGap / 2));
  const end = portLead(target, targetSide, obstacles, targetId, Math.min(lead, facingGap === undefined ? Infinity : facingGap / 2));
  // Opposing exits must not share a lane: a dashed fallback would otherwise
  // obscure the primary route beneath their common source card.
  const direction = Math.sign(vertical ? end.x - start.x : end.y - start.y);
  const exitOffset = direction ? direction * (8 + offset) : offset;
  const centred = vertical ? (start.y + end.y) / 2 + exitOffset : (start.x + end.x) / 2 + exitOffset;
  const middle = facingGap === undefined ? centred : Math.min(Math.max(centred, start.y), end.y);
  const candidates: RoutePoint[][] = vertical
    ? [[start, { x: start.x, y: middle }, { x: end.x, y: middle }, end]]
    : [[start, { x: middle, y: start.y }, { x: middle, y: end.y }, end]];
  const channels = vertical
    ? [start.x, end.x, ...obstacles.flatMap(rect => [rect.x - clearance - offset, rect.x + rect.width + clearance + offset])]
    : [start.y, end.y, ...obstacles.flatMap(rect => [rect.y - clearance - offset, rect.y + rect.height + clearance + offset])];
  for (const channel of new Set(channels)) candidates.push(vertical
    ? [start, { x: channel, y: start.y }, { x: channel, y: end.y }, end]
    : [start, { x: start.x, y: channel }, { x: end.x, y: channel }, end]);
  const length = (points: RoutePoint[]) => points.slice(1).reduce((total, point, index) => total + distance(points[index]!, point), 0);
  const channel = candidates.filter(candidate => openPath(candidate, obstacles)).sort((a, b) => length(a) - length(b))[0]
    ?? findChannel(start, end, obstacles);
  // Overlapping operator positions can trap a port. Retain its route, and report
  // the obstruction instead of silently dropping the edge or moving saved work.
  const points = simplify([source, ...(channel ?? candidates[0]!), target]);
  const unrelated = obstacles.filter(rect => rect.id !== sourceId && rect.id !== targetId);
  const obstructed = points.slice(1).some((point, index) => unrelated.some(rect => segmentCrossesObstacle(points[index]!, point, rect)));
  const label = { x: (source.x + start.x) / 2, y: (source.y + start.y) / 2 };
  const segments = points.slice(1).map((point, index) => ({ from: points[index]!, to: point })).sort((a, b) => Number(b.from.y === b.to.y) - Number(a.from.y === a.to.y) || distance(b.from, b.to) - distance(a.from, a.to));
  const payloadLabel = segments.flatMap(segment => [.5, .25, .75].map(ratio => ({ x: segment.from.x + (segment.to.x - segment.from.x) * ratio, y: segment.from.y + (segment.to.y - segment.from.y) * ratio })))
    .find(point => !obstacles.some(rect => point.x + labelWidth / 2 > rect.x - 4 && point.x - labelWidth / 2 < rect.x + rect.width + 4 && point.y + 10 > rect.y - 4 && point.y - 10 < rect.y + rect.height + 4));
  return { points, path: points.map((point, index) => `${index ? "L" : "M"} ${point.x},${point.y}`).join(" "), label, payloadLabel, obstructed };
}
