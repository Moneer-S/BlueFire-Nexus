import { describe, expect, it } from "vitest";
import { focusedGraphLayout, graphBoundsViewport, initialGraphLayout, GRAPH_NODE_HEIGHT, GRAPH_NODE_WIDTH, type ScenarioGraph } from "../src/lib/graph-view";
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
  const overlapFree = (cards: RouteObstacle[]) => cards.every((card, index) => cards.slice(index + 1).every(other =>
    card.x + card.width <= other.x || other.x + other.width <= card.x || card.y + card.height <= other.y || other.y + other.height <= card.y));
  // Builder ports (Builder.tsx displayNodes): a success route leaves the bottom
  // (20px from the left) when the next step is below and not to the right, and
  // enters the top when a success predecessor is directly above.
  const ports = (graph: ScenarioGraph, positions: Record<string, { x: number; y: number }>, edge: ScenarioGraph["edges"][number]) => {
    const source = positions[edge.from_step]!, target = positions[edge.to_step]!;
    const successTo = graph.edges.find(item => item.from_step === edge.from_step && item.outcome === "success");
    const after = successTo && positions[successTo.to_step];
    const bottom = edge.outcome === "success" && after && after.x < source.x + 1 && after.y > source.y + GRAPH_NODE_HEIGHT;
    const top = graph.edges.some(item => item.to_step === edge.to_step && item.outcome === "success" && positions[item.from_step]!.x === target.x && positions[item.from_step]!.y < target.y);
    return {
      source: bottom ? { x: source.x + 20, y: source.y + GRAPH_NODE_HEIGHT } : { x: source.x + GRAPH_NODE_WIDTH, y: source.y + GRAPH_NODE_HEIGHT / 2 },
      target: top ? { x: target.x + 20, y: target.y } : { x: target.x, y: target.y + GRAPH_NODE_HEIGHT / 2 },
      sourceSide: bottom ? "bottom" as const : "right" as const, targetSide: top ? "top" as const : "left" as const,
    };
  };
  // A route from a bottom port down to a top port never turns back upward (no U-shaped kink).
  const flowsDown = (geometry: ReturnType<typeof ports>, points: { x: number; y: number }[]) =>
    geometry.sourceSide !== "bottom" || geometry.targetSide !== "top" || geometry.target.y <= geometry.source.y
    || points.slice(1).every((point, index) => point.y >= points[index]!.y);
  const routeFlows = (graph: ScenarioGraph, positions: Record<string, { x: number; y: number }>, edge: ScenarioGraph["edges"][number], cards: RouteObstacle[]) => {
    const geometry = ports(graph, positions, edge);
    // Several routes entering one step use offset lanes; each must still flow down.
    return [0, 1, 2].every(lane => flowsDown(geometry, expectClear({ ...geometry, lane, sourceId: edge.from_step, targetId: edge.to_step, obstacles: cards }).points));
  };

  it("reads a long chain top to bottom in balanced columns, left to right, at a readable desktop scale", () => {
    const graph = chain(15), serialized = JSON.stringify(graph), positions = initialGraphLayout(graph);
    const columns = [...new Set(Object.values(positions).map(point => point.x))].sort((a, b) => a - b);
    expect(columns).toHaveLength(5);
    for (let index = 1; index < 15; index += 1) {
      const previous = positions[`step-${index - 1}`]!, next = positions[`step-${index}`]!;
      // Each step is either directly below its predecessor or starts the next column.
      if (next.x === previous.x) expect(next.y).toBeGreaterThan(previous.y + GRAPH_NODE_HEIGHT);
      else { expect(next.x).toBeGreaterThan(previous.x + GRAPH_NODE_WIDTH); expect(next.y).toBe(32); }
    }
    const counts = columns.map(x => Object.values(positions).filter(point => point.x === x).length);
    expect(Math.max(...counts) - Math.min(...counts)).toBeLessThanOrEqual(1);
    const cards = bounds(graph);
    expect(overlapFree(cards)).toBe(true);
    // Every column fits the measured 1366x768 Build canvas height at a readable scale.
    for (const x of columns) expect(graphBoundsViewport(cards.filter(card => card.x === x), { width: 1116, height: 435 }, 24)!.zoom).toBeGreaterThanOrEqual(0.8);
    expect(JSON.stringify(graph)).toBe(serialized);
  });

  it("keeps a short plan in one row and places a fallback beside the straight success path", () => {
    expect(new Set(Object.values(initialGraphLayout(chain(4))).map(point => point.y)).size).toBe(1);
    const graph = chain(9);
    graph.edges = graph.edges.filter(edge => !(edge.from_step === "step-7" && edge.to_step === "step-8"));
    graph.edges.push({ from_step: "step-6", to_step: "step-7", outcome: "blocked" }, { from_step: "step-6", to_step: "step-7", outcome: "failed" });
    graph.edges = graph.edges.filter(edge => !(edge.from_step === "step-6" && edge.to_step === "step-7" && edge.outcome === "success"));
    graph.edges.push({ from_step: "step-6", to_step: "step-8", outcome: "success" }, { from_step: "step-7", to_step: "step-8", outcome: "success" });
    const serialized = JSON.stringify(graph), positions = initialGraphLayout(graph);
    const main = positions["step-6"]!, fallback = positions["step-7"]!, join = positions["step-8"]!;
    // The fallback takes a side lane so the success route 6 -> 8 stays straight.
    expect(join.x).toBe(main.x);
    expect(join.y).toBeGreaterThan(main.y + GRAPH_NODE_HEIGHT);
    expect(fallback.x).toBeGreaterThanOrEqual(main.x + GRAPH_NODE_WIDTH);
    expect(fallback.y).toBeGreaterThan(main.y);
    expect(fallback.y).toBeLessThan(join.y);
    const cards = bounds(graph);
    expect(overlapFree(cards)).toBe(true);
    expect(graphBoundsViewport(cards, { width: 1116, height: 435 }, 24)!.zoom).toBeGreaterThanOrEqual(0.8);
    for (const edge of graph.edges) expect(routeFlows(graph, positions, edge, cards), `${edge.from_step} -> ${edge.to_step}`).toBe(true);
    expect(JSON.stringify(graph)).toBe(serialized);
  });

  it("keeps a decision, its fallback and the rejoin in one column instead of splitting them at a balanced break", () => {
    const graph = chain(5);
    graph.steps.push(step("fallback"), step("cleanup"));
    graph.edges.push({ from_step: "step-4", to_step: "fallback", outcome: "blocked" }, { from_step: "step-4", to_step: "fallback", outcome: "failed" },
      { from_step: "step-4", to_step: "cleanup", outcome: "success" }, { from_step: "fallback", to_step: "cleanup", outcome: "success" });
    const positions = initialGraphLayout(graph);
    const decision = positions["step-4"]!, fallback = positions.fallback!, rejoin = positions.cleanup!;
    expect(rejoin.x).toBe(decision.x);
    expect(fallback.x).toBeGreaterThan(decision.x);
    expect(fallback.x).toBeLessThan(decision.x + 2 * GRAPH_NODE_WIDTH + 112);
    expect(decision.y).toBeLessThan(fallback.y);
    expect(fallback.y).toBeLessThan(rejoin.y);
    const cards = bounds(graph);
    expect(overlapFree(cards)).toBe(true);
    for (const edge of graph.edges) expect(routeFlows(graph, positions, edge, cards), `${edge.from_step} -> ${edge.to_step}`).toBe(true);
  });

  it("keeps success-loop drafts and unconnected steps from overlapping or widening the plan", () => {
    const loop = chain(7);
    loop.edges.push({ from_step: "step-6", to_step: "step-1", outcome: "success" });
    const looped = bounds(loop);
    expect(overlapFree(looped)).toBe(true);
    const drafted = chain(6);
    drafted.steps.push(step("new-a"), step("new-b"), step("new-c"));
    const positions = initialGraphLayout(drafted);
    const planRight = Math.max(...drafted.steps.slice(0, 6).map(item => positions[item.id]!.x));
    // Newly added, unconnected steps follow the plan instead of crowding its first column.
    for (const id of ["new-a", "new-b", "new-c"]) expect(positions[id]!.x).toBeGreaterThan(planRight + GRAPH_NODE_WIDTH);
    expect(positions["step-1"]!.x).toBe(positions["step-0"]!.x);
    expect(overlapFree(bounds(drafted))).toBe(true);
  });

  it("places alternatives below the continuation and joins after every predecessor", () => {
    const graph: ScenarioGraph = { start: "prepare", steps: ["prepare", "primary", "fallback", "join"].map(step), edges: [
      { from_step: "prepare", to_step: "primary", outcome: "success" }, { from_step: "prepare", to_step: "fallback", outcome: "blocked" },
      { from_step: "primary", to_step: "join", outcome: "success" }, { from_step: "fallback", to_step: "join", outcome: "success" },
    ] };
    const positions = initialGraphLayout(graph);
    expect(positions.primary!.x).toBe(positions.fallback!.x);
    expect(Math.abs(positions.primary!.y - positions.fallback!.y)).toBeGreaterThan(GRAPH_NODE_HEIGHT);
    expect(positions.join!.x).toBeGreaterThan(positions.primary!.x + GRAPH_NODE_WIDTH);
    for (const edge of graph.edges) {
      const source = positions[edge.from_step]!, target = positions[edge.to_step]!;
      expectClear({ source: { x: source.x + GRAPH_NODE_WIDTH, y: source.y + GRAPH_NODE_HEIGHT / 2 }, target: { x: target.x, y: target.y + GRAPH_NODE_HEIGHT / 2 }, sourceId: edge.from_step, targetId: edge.to_step, sourceSide: "right", targetSide: "left", obstacles: bounds(graph) });
    }
  });

  it("keeps focused branch and join relationships routable after projection", () => {
    const graph: ScenarioGraph = { start: "prepare", steps: ["prepare", "primary", "fallback", "join"].map(step), edges: [
      { from_step: "prepare", to_step: "primary", outcome: "success" }, { from_step: "prepare", to_step: "fallback", outcome: "blocked" },
      { from_step: "primary", to_step: "join", outcome: "success" }, { from_step: "fallback", to_step: "join", outcome: "success" },
    ] };
    const ids = ["primary", "fallback", "join"];
    const positions = focusedGraphLayout(graph, ids)!;
    expect(positions.primary!.x).toBe(positions.fallback!.x);
    expect(Math.abs(positions.primary!.y - positions.fallback!.y)).toBeGreaterThan(GRAPH_NODE_HEIGHT);
    expect(positions.join!.x).toBeGreaterThan(positions.primary!.x + GRAPH_NODE_WIDTH);
    const obstacles = ids.map(id => ({ id, ...positions[id]!, width: GRAPH_NODE_WIDTH, height: GRAPH_NODE_HEIGHT }));
    for (const edge of graph.edges.filter(edge => ids.includes(edge.from_step) && ids.includes(edge.to_step))) {
      const source = obstacles.find(card => card.id === edge.from_step)!;
      const target = obstacles.find(card => card.id === edge.to_step)!;
      expectClear({ source: { x: source.x + source.width, y: source.y + source.height / 2 }, target: { x: target.x, y: target.y + target.height / 2 }, sourceSide: "right", targetSide: "left", sourceId: source.id, targetId: target.id, obstacles });
    }
  });

  it("includes producer/consumer ordering, disconnected steps and retry cycles without modifying saved positions", () => {
    const graph = chain(5);
    graph.steps.push({ ...step("consumer"), inputs: { result: { from_step: "step-3", artifact: "records" } } }, step("detached"));
    graph.edges.push({ from_step: "step-4", to_step: "step-0", outcome: "failed" });
    graph.layout = { "step-0": { x: -300, y: 1200 } };
    const serialized = JSON.stringify(graph), positions = initialGraphLayout(graph);
    expect(Object.keys(positions)).toHaveLength(7);
    expect(positions.consumer!.x).toBeGreaterThan(positions["step-3"]!.x);
    expect(initialGraphLayout(graph)).toEqual(positions);
    expect(JSON.stringify(graph)).toBe(serialized);
  });

  it("fills partial layouts around pinned operator cards and keeps explicit auto-layout independent", () => {
    const graph = chain(3);
    const generated = initialGraphLayout(graph);
    graph.layout = { "step-0": { ...generated["step-1"]! }, "step-2": { x: 48, y: 600 } };
    const serialized = JSON.stringify(graph);
    const filled = initialGraphLayout(graph, true);
    expect(filled["step-0"]).toEqual(graph.layout["step-0"]);
    expect(filled["step-2"]).toEqual(graph.layout["step-2"]);
    expect(filled["step-1"]!.x).toBe(generated["step-1"]!.x);
    expect(filled["step-1"]!.y).toBeGreaterThanOrEqual(graph.layout["step-0"]!.y + GRAPH_NODE_HEIGHT);
    expect(filled["step-1"]!.x + GRAPH_NODE_WIDTH).toBeLessThanOrEqual(generated["step-2"]!.x);
    expect(initialGraphLayout(graph)["step-0"]).toEqual({ x: 32, y: 32 });
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

  it("keeps every three-step group readable in the 128-node/256-route topology", () => {
    const graph = chain(128);
    for (let index = 0; index < 43; index += 1) {
      for (const [offset, outcome] of (["partial", "blocked", "failed"] as const).entries()) {
        graph.edges.push({ from_step: `step-${index}`, to_step: `step-${index + offset + 2}`, outcome });
      }
    }
    expect(graph.edges).toHaveLength(256);
    const serialized = JSON.stringify(graph);
    for (let start = 0; start < graph.steps.length; start += 3) {
      const ids = graph.steps.slice(start, start + 3).map(step => step.id);
      const positions = focusedGraphLayout(graph, ids)!;
      const cards = ids.map(id => ({ ...positions[id]!, width: GRAPH_NODE_WIDTH, height: GRAPH_NODE_HEIGHT }));
      expect(graphBoundsViewport(cards, { width: 1080, height: 330 })?.zoom, `group starting at step ${start}`).toBeGreaterThanOrEqual(0.8);
      expect(cards.every((card, index) => cards.slice(index + 1).every(other =>
        card.x + card.width <= other.x || other.x + other.width <= card.x || card.y + card.height <= other.y || other.y + other.height <= card.y))).toBe(true);
    }
    expect(JSON.stringify(graph)).toBe(serialized);
  });

  it("keeps generated group positions separate from saved coordinates until explicit group layout", () => {
    const graph = chain(6);
    graph.layout = { "step-4": { x: 840, y: 520 } };
    const serialized = JSON.stringify(graph);
    const projected = focusedGraphLayout(graph, ["step-3", "step-4", "step-5"]);
    expect(projected["step-4"]).toEqual(graph.layout["step-4"]);
    const projectedCards = ["step-3", "step-4", "step-5"].map(id => ({ ...projected[id]!, width: GRAPH_NODE_WIDTH, height: GRAPH_NODE_HEIGHT }));
    for (let index = 0; index < projectedCards.length; index += 1) for (const other of projectedCards.slice(index + 1)) {
      const card = projectedCards[index]!;
      expect(card.x + card.width <= other.x || other.x + other.width <= card.x || card.y + card.height <= other.y || other.y + other.height <= card.y).toBe(true);
    }
    const arranged = focusedGraphLayout(graph, ["step-3", "step-4", "step-5"], true)!;
    expect(arranged["step-4"]).not.toEqual(graph.layout["step-4"]);
    expect(graph.layout["step-4"]).toEqual({ x: 840, y: 520 });
    expect(JSON.stringify(graph)).toBe(serialized);
  });
});

describe("card-aware routing", () => {
  const cards: RouteObstacle[] = [
    { id: "start", x: 100, y: 40, width: GRAPH_NODE_WIDTH, height: GRAPH_NODE_HEIGHT },
    { id: "middle", x: 100, y: 320, width: GRAPH_NODE_WIDTH, height: GRAPH_NODE_HEIGHT },
    { id: "end", x: 100, y: 600, width: GRAPH_NODE_WIDTH, height: GRAPH_NODE_HEIGHT },
  ];
  it.each([[0, 0], [0, 1], [1, 0]])("separates opposing branch exit lanes with incoming indices %s and %s", (rightLane, leftLane) => {
    const graph: ScenarioGraph = { start: "prepare", steps: ["prepare", "primary", "fallback", "join"].map(step), edges: [
      { from_step: "prepare", to_step: "primary", outcome: "success" }, { from_step: "prepare", to_step: "fallback", outcome: "blocked" },
      { from_step: "primary", to_step: "join", outcome: "success" }, { from_step: "fallback", to_step: "join", outcome: "success" },
    ] };
    // The router also supports vertical geometry with bottom and top ports.
    const positions = { prepare: { x: 200, y: 32 }, primary: { x: 32, y: 300 }, fallback: { x: 368, y: 300 }, join: { x: 200, y: 568 } };
    const obstacles = graph.steps.map(step => ({ id: step.id, ...positions[step.id as keyof typeof positions], width: GRAPH_NODE_WIDTH, height: GRAPH_NODE_HEIGHT }));
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
  it("routes compact left-to-right alternatives from their actual side ports", () => {
    const graph: ScenarioGraph = { start: "prepare", steps: ["prepare", "primary", "fallback", "join"].map(step), edges: [
      { from_step: "prepare", to_step: "primary", outcome: "success" }, { from_step: "prepare", to_step: "fallback", outcome: "blocked" },
      { from_step: "primary", to_step: "join", outcome: "success" }, { from_step: "fallback", to_step: "join", outcome: "success" },
    ] };
    const obstacles = bounds(graph);
    for (const edge of graph.edges) {
      const source = obstacles.find(card => card.id === edge.from_step)!;
      const target = obstacles.find(card => card.id === edge.to_step)!;
      const port = edge.outcome === "blocked" ? .6 : .2;
      const route = expectClear({ source: { x: source.x + source.width, y: source.y + source.height * port }, target: { x: target.x, y: target.y + target.height / 2 }, sourceSide: "right", targetSide: "left", sourceId: source.id, targetId: target.id, obstacles });
      for (const [index, point] of route.points.slice(1).entries()) for (const card of obstacles) expect(segmentCrossesObstacle(route.points[index]!, point, card)).toBe(false);
    }
  });
  it("keeps conditional lanes outside their source in a compact row gap with protruding handles", () => {
    const source = { id: "collection", x: 373, y: 435.1875, width: 220, height: 104 };
    const target = { id: "cleanup", x: source.x, y: source.y + source.height + 44, width: 220, height: 104 };
    const obstacles = [source, target];
    const routes = [.6, .8].map((port, index) => expectClear({
      source: { x: source.x + source.width + 4.5, y: source.y + source.height * port },
      target: { x: target.x + 20, y: target.y - 4.5 },
      sourceId: source.id, targetId: target.id, sourceSide: "right", targetSide: "top", obstacles, lane: index + 1,
    }));
    const lanes = routes.map(route => {
      for (const [index, point] of route.points.slice(1).entries()) for (const card of obstacles) {
        expect(segmentCrossesObstacle(route.points[index]!, point, card)).toBe(false);
      }
      const exit = route.points.slice(1).find((point, index) => point.x === route.points[index]!.x && point.y !== route.points[index]!.y)!;
      expect(exit).toBeDefined();
      expect(exit.x).toBeGreaterThan(source.x + source.width + 14);
      expect(route.payloadLabel).toBeDefined();
      return exit.x;
    });
    expect(Math.abs(lanes[1]! - lanes[0]!)).toBeGreaterThanOrEqual(12);
  });
  it("routes the compact conditional join around an unrelated manually positioned card", () => {
    const source = { id: "collection", x: 373, y: 435.1875, width: 220, height: 104 };
    const target = { id: "cleanup", x: source.x, y: source.y + source.height + 44, width: 220, height: 104 };
    const obstacles = [source, target, { id: "saved-neighbor", x: 620, y: 535, width: 100, height: 100 }];
    for (const [index, port] of [.6, .8].entries()) {
      const route = expectClear({
        source: { x: source.x + source.width + 4.5, y: source.y + source.height * port },
        target: { x: target.x + 20, y: target.y - 4.5 },
        sourceId: source.id, targetId: target.id, sourceSide: "right", targetSide: "top", obstacles, lane: index + 1,
      });
      for (const [index, point] of route.points.slice(1).entries()) for (const card of obstacles) {
        expect(segmentCrossesObstacle(route.points[index]!, point, card)).toBe(false);
      }
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
