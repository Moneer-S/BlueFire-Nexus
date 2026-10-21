import { describe, expect, it } from "vitest";
import { initialGraphLayout, GRAPH_NODE_HEIGHT, GRAPH_NODE_WIDTH, type ScenarioGraph } from "../src/lib/graph-view";
import { routePath, segmentCrossesObstacle, type RouteGeometry, type RouteObstacle } from "../src/lib/graph-routes";
import type { ScenarioStep } from "../src/types";

const step = (id: string): ScenarioStep => ({ id, behavior_id: "test.generated.v1", parameters: {}, inputs: {}, alternates: [] });
const chain = (count: number): ScenarioGraph => ({ start: "step-0", steps: Array.from({ length: count }, (_, index) => step(`step-${index}`)), edges: Array.from({ length: count - 1 }, (_, index) => ({ from_step: `step-${index}`, to_step: `step-${index + 1}`, outcome: "success" })) });
const bounds = (graph: ScenarioGraph): RouteObstacle[] => Object.entries(initialGraphLayout(graph)).map(([id, position]) => ({ id, ...position, width: GRAPH_NODE_WIDTH, height: GRAPH_NODE_HEIGHT }));
function expectClear(options: RouteGeometry) {
  const before = JSON.stringify(options);
  const route = routePath(options);
  expect(route.obstructed).toBe(false);
  expect(route.points[0]).toEqual(options.source);
  expect(route.points.at(-1)).toEqual(options.target);
  for (const [index, point] of route.points.slice(1).entries()) {
    const previous = route.points[index]!;
    expect(previous.x === point.x || previous.y === point.y).toBe(true);
    for (const rect of options.obstacles ?? []) if (rect.id !== options.sourceId && rect.id !== options.targetId) expect(segmentCrossesObstacle(previous, point, rect)).toBe(false);
  }
  expect(JSON.stringify(options)).toBe(before);
  return route;
}

describe("topology layout", () => {
  it("keeps a long chain in one top-to-bottom flow instead of wrapping every fourth card", () => {
    const graph = chain(15), serialized = JSON.stringify(graph), positions = initialGraphLayout(graph);
    expect(new Set(Object.values(positions).map(point => point.x)).size).toBe(1);
    for (let index = 1; index < 15; index += 1) expect(positions[`step-${index}`]!.y).toBeGreaterThan(positions[`step-${index - 1}`]!.y + GRAPH_NODE_HEIGHT);
    expect(JSON.stringify(graph)).toBe(serialized);
  });

  it("places alternatives beside the continuation and joins below every predecessor", () => {
    const graph: ScenarioGraph = { start: "prepare", steps: ["prepare", "primary", "fallback", "join"].map(step), edges: [
      { from_step: "prepare", to_step: "primary", outcome: "success" }, { from_step: "prepare", to_step: "fallback", outcome: "blocked" },
      { from_step: "primary", to_step: "join", outcome: "success" }, { from_step: "fallback", to_step: "join", outcome: "success" },
    ] };
    const positions = initialGraphLayout(graph);
    expect(positions.primary!.y).toBe(positions.fallback!.y);
    expect(Math.abs(positions.primary!.x - positions.fallback!.x)).toBeGreaterThan(GRAPH_NODE_WIDTH);
    expect(positions.join!.y).toBeGreaterThan(positions.primary!.y + GRAPH_NODE_HEIGHT);
    for (const edge of graph.edges) {
      const source = positions[edge.from_step]!, target = positions[edge.to_step]!;
      expectClear({ source: { x: source.x + 45, y: source.y + GRAPH_NODE_HEIGHT }, target: { x: target.x + 126, y: target.y }, sourceId: edge.from_step, targetId: edge.to_step, obstacles: bounds(graph) });
    }
  });

  it("includes producer/consumer ordering, disconnected steps and retry cycles without modifying saved positions", () => {
    const graph = chain(5);
    graph.steps.push({ ...step("consumer"), inputs: { result: { from_step: "step-3", artifact: "records" } } }, step("detached"));
    graph.edges.push({ from_step: "step-4", to_step: "step-0", outcome: "failed" });
    graph.layout = { "step-0": { x: -300, y: 1200 } };
    const serialized = JSON.stringify(graph), positions = initialGraphLayout(graph);
    expect(Object.keys(positions)).toHaveLength(7);
    expect(positions.consumer!.y).toBeGreaterThan(positions["step-3"]!.y);
    expect(initialGraphLayout(graph)).toEqual(positions);
    expect(JSON.stringify(graph)).toBe(serialized);
  });

  it("fills partial layouts around pinned operator cards and keeps explicit auto-layout independent", () => {
    const graph = chain(3);
    graph.layout = { "step-0": { x: 48, y: 324 }, "step-2": { x: 48, y: 600 } };
    const serialized = JSON.stringify(graph);
    const filled = initialGraphLayout(graph, true);
    expect(filled["step-0"]).toEqual(graph.layout["step-0"]);
    expect(filled["step-2"]).toEqual(graph.layout["step-2"]);
    expect(filled["step-1"]!.y).toBeGreaterThan(600 + GRAPH_NODE_HEIGHT);
    expect(initialGraphLayout(graph)["step-0"]).toEqual({ x: 48, y: 48 });
    expect(JSON.stringify(graph)).toBe(serialized);
  });

  it("lays out repeated outcome edges to the same cleanup step without collapsing execution routes", () => {
    const graph = chain(6);
    for (let index = 1; index < 5; index += 1) for (const outcome of ["partial", "blocked", "failed"] as const) {
      graph.edges.push({ from_step: `step-${index}`, to_step: "step-5", outcome });
    }
    const serialized = JSON.stringify(graph), positions = initialGraphLayout(graph);
    expect(graph.edges).toHaveLength(17);
    expect(Object.keys(positions)).toHaveLength(6);
    expect(Object.values(positions).every(point => Number.isFinite(point.x) && Number.isFinite(point.y))).toBe(true);
    expect(JSON.stringify(graph)).toBe(serialized);
  });

  it("lays out the 128-node/256-route fixture without card collisions", () => {
    const graph = chain(128);
    for (let index = 0; index < 128; index += 1) graph.edges.push({ from_step: `step-${index}`, to_step: `step-${(index + 7) % 128}`, outcome: "blocked" });
    graph.edges.push({ from_step: "step-127", to_step: "step-0", outcome: "failed" });
    expect(graph.edges).toHaveLength(256);
    const cards = bounds(graph);
    for (let index = 0; index < cards.length; index += 1) for (const other of cards.slice(index + 1)) {
      const card = cards[index]!;
      expect(card.x + card.width <= other.x || other.x + other.width <= card.x || card.y + card.height <= other.y || other.y + other.height <= card.y).toBe(true);
    }
  });
});

describe("card-aware routing", () => {
  const cards: RouteObstacle[] = [
    { id: "start", x: 100, y: 40, width: 252, height: 180 },
    { id: "middle", x: 100, y: 320, width: 252, height: 180 },
    { id: "end", x: 100, y: 600, width: 252, height: 180 },
  ];
  it.each([[0, 0], [0, 1], [1, 0]])("separates opposing branch exit lanes with incoming indices %s and %s", (rightLane, leftLane) => {
    const graph: ScenarioGraph = { start: "prepare", steps: ["prepare", "primary", "fallback", "join"].map(step), edges: [
      { from_step: "prepare", to_step: "primary", outcome: "success" }, { from_step: "prepare", to_step: "fallback", outcome: "blocked" },
      { from_step: "primary", to_step: "join", outcome: "success" }, { from_step: "fallback", to_step: "join", outcome: "success" },
    ] };
    const obstacles = bounds(graph);
    const source = obstacles.find(card => card.id === "prepare")!;
    const destinations = obstacles.filter(card => card.id === "primary" || card.id === "fallback").sort((a, b) => a.x - b.x);
    const left = destinations[0]!, right = destinations[1]!;
    const rightRoute = expectClear({ source: { x: source.x + GRAPH_NODE_WIDTH * 0.18, y: source.y + source.height }, target: { x: right.x + right.width / 2, y: right.y }, sourceId: source.id, targetId: right.id, obstacles, lane: rightLane });
    const leftRoute = expectClear({ source: { x: source.x + GRAPH_NODE_WIDTH * 0.62, y: source.y + source.height }, target: { x: left.x + left.width / 2, y: left.y }, sourceId: source.id, targetId: left.id, obstacles, lane: leftLane });
    const horizontal = (points: typeof rightRoute.points) => points.slice(1).flatMap((to, index) => {
      const from = points[index]!;
      return from.y === to.y && from.x !== to.x ? [{ y: from.y, left: Math.min(from.x, to.x), right: Math.max(from.x, to.x) }] : [];
    });
    const rightSegments = horizontal(rightRoute.points), leftSegments = horizontal(leftRoute.points);
    expect(rightSegments.length).toBeGreaterThan(0);
    expect(leftSegments.length).toBeGreaterThan(0);
    expect(rightSegments.some(a => leftSegments.some(b => Math.min(a.right, b.right) > Math.max(a.left, b.left)))).toBe(true);
    for (const a of rightSegments) for (const b of leftSegments) {
      if (Math.min(a.right, b.right) > Math.max(a.left, b.left)) expect(Math.abs(a.y - b.y)).toBeGreaterThanOrEqual(16);
    }
  });
  it("takes a clear side channel past an unrelated card", () => {
    const route = expectClear({ source: { x: 145, y: 220 }, target: { x: 226, y: 600 }, sourceId: "start", targetId: "end", obstacles: cards });
    expect(route.points.some(point => point.x < 100 || point.x > 352)).toBe(true);
  });
  it("returns a retry to an earlier step outside the intervening cards", () => {
    const route = expectClear({ source: { x: 300, y: 780 }, target: { x: 226, y: 40 }, sourceId: "end", targetId: "start", obstacles: cards, lane: 3 });
    expect(route.points.some(point => point.x < 100 || point.x > 352)).toBe(true);
  });
  it("routes right-to-left data ports without entering the producer or consumer", () => {
    const route = expectClear({ source: { x: 352, y: 110 }, target: { x: 100, y: 670 }, sourceId: "start", targetId: "end", sourceSide: "right", targetSide: "left", obstacles: cards });
    for (const [index, point] of route.points.slice(1).entries()) for (const card of cards) expect(segmentCrossesObstacle(route.points[index]!, point, card)).toBe(false);
    expect(route.payloadLabel).toBeDefined();
    for (const card of cards) {
      const label = route.payloadLabel!;
      expect(label.x + 45 <= card.x || label.x - 45 >= card.x + card.width || label.y + 10 <= card.y || label.y - 10 >= card.y + card.height).toBe(true);
    }
  });
  it("handles irregular saved positions which need more than one side channel", () => {
    const obstacles = [...cards, { id: "left", x: -60, y: 220, width: 200, height: 120 }, { id: "right", x: 300, y: 490, width: 200, height: 100 }];
    expectClear({ source: { x: 226, y: 220 }, target: { x: 226, y: 600 }, sourceId: "start", targetId: "end", obstacles });
  });
  it("retains and marks a connection trapped by overlapping saved cards", () => {
    const route = routePath({ source: { x: 226, y: 220 }, target: { x: 226, y: 600 }, sourceId: "start", targetId: "end", obstacles: [...cards, { id: "overlap", x: 200, y: 180, width: 252, height: 180 }] });
    expect(route.path).toContain("M 226,220");
    expect(route.obstructed).toBe(true);
  });
});
