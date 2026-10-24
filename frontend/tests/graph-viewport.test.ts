import { describe, expect, it } from "vitest";
import { graphBoundsViewport, readableGraphViewport, revealGraphContext, revealGraphNode } from "../src/lib/graph-view";
import { defaultGraphView } from "../src/lib/graph-view-retention";
import { demoScenario } from "../src/lib/demo";

const node = { x: 908, y: 2052, width: 252, height: 180 };

describe("readable graph framing", () => {
  it("starts at the graph entry point even when the saved step array has another order", () => {
    const scenario = { ...demoScenario, steps: [...demoScenario.steps].reverse() };
    expect(defaultGraphView(scenario).selected?.id).toBe(scenario.start);
    expect(defaultGraphView(scenario).section).toBeNull();
    expect(defaultGraphView(scenario).allBranches).toBe(true);
  });

  it.each([{ width: 710, height: 380 }, { width: 1040, height: 480 }, { width: 1640, height: 780 }])("opens a long path at readable scale in a $width by $height canvas", (frame) => {
    const viewport = readableGraphViewport(node, frame, true);
    expect(viewport.zoom).toBe(1);
    expect(viewport.x + node.x).toBe((frame.width - node.width) / 2);
    expect(viewport.y + node.y).toBe(24);
  });

  it("fits selection to its actual canvas, without including unrelated steps", () => {
    const frame = { width: 360, height: 220 };
    const viewport = readableGraphViewport(node, frame);
    expect(viewport.zoom).toBeGreaterThan(0.9);
    expect(viewport.zoom).toBeLessThanOrEqual(1);
    expect(viewport.x + (node.x + node.width / 2) * viewport.zoom).toBe(frame.width / 2);
    expect(viewport.y + (node.y + node.height / 2) * viewport.zoom).toBe(frame.height / 2);
  });

  it("fits a compact visible group at readable scale without a zoom floor hiding cards", () => {
    const frame = { width: 740, height: 300 };
    const group = [0, 1, 2].map(index => ({ x: index * 276, y: 0, width: 220, height: 150 }));
    const viewport = graphBoundsViewport(group, frame);
    expect(viewport?.zoom).toBeGreaterThan(0.8);
    expect(viewport?.zoom).toBeLessThanOrEqual(1);
    for (const item of group) {
      expect(viewport!.x + item.x * viewport!.zoom).toBeGreaterThanOrEqual(24);
      expect(viewport!.x + (item.x + item.width) * viewport!.zoom).toBeLessThanOrEqual(frame.width - 24);
      expect(viewport!.y + item.y * viewport!.zoom).toBeGreaterThanOrEqual(24);
      expect(viewport!.y + (item.y + item.height) * viewport!.zoom).toBeLessThanOrEqual(frame.height - 24);
    }
  });

  it("uses the exact overview scale required by the whole graph instead of clipping at a floor", () => {
    const frame = { width: 740, height: 300 };
    const allSteps = Array.from({ length: 9 }, (_, index) => ({ x: index * 276, y: 0, width: 220, height: 150 }));
    const viewport = graphBoundsViewport(allSteps, frame);
    expect(viewport?.zoom).toBeCloseTo((frame.width - 48) / (allSteps.at(-1)!.x + 220));
    expect(viewport!.zoom).toBeGreaterThan(0.1);
    expect(viewport!.x + (allSteps.at(-1)!.x + 220) * viewport!.zoom).toBeLessThanOrEqual(frame.width - 24);
  });

  it("keeps the exact viewport object when the selected node is still visible", () => {
    const viewport = { x: -800, y: -1900, zoom: 1 };
    expect(revealGraphNode(viewport, node, { width: 710, height: 380 })).toBe(viewport);
  });

  it("pans only enough to reveal the selection after the canvas shrinks", () => {
    const viewport = { x: -510, y: -1900, zoom: 1 };
    const next = revealGraphNode(viewport, node, { width: 600, height: 300 });
    expect(next).toEqual({ x: -608, y: -1980, zoom: 1 });
    expect(next.x + node.x + node.width).toBe(552);
    expect(next.y + node.y + node.height).toBe(252);
  });

  it("never changes operator zoom when a selected card is larger than the canvas", () => {
    const viewport = { x: 37, y: 92, zoom: 1.6 };
    const next = revealGraphNode(viewport, node, { width: 300, height: 240 });
    expect(next.zoom).toBe(1.6);
    expect(next.x + (node.x + node.width / 2) * next.zoom).toBeCloseTo(150);
    expect(next.y + (node.y + node.height / 2) * next.zoom).toBeCloseTo(120);
  });

  it("reveals the selected step, predecessor and destination together at desktop height", () => {
    const selected = { x: 500, y: 180, width: 292, height: 104 };
    const neighbors = [32, 328].map(y => ({ x: 500, y, width: 220, height: 104 }));
    const frame = { width: 455, height: 488 };
    const viewport = revealGraphContext({ x: -300, y: 110, zoom: 1 }, selected, neighbors, frame);
    expect(viewport.zoom).toBe(1);
    for (const card of [selected, ...neighbors]) {
      expect(viewport.x + card.x).toBeGreaterThanOrEqual(24);
      expect(viewport.x + card.x + card.width).toBeLessThanOrEqual(frame.width - 24);
      expect(viewport.y + card.y).toBeGreaterThanOrEqual(24);
      expect(viewport.y + card.y + card.height).toBeLessThanOrEqual(frame.height - 24);
    }
  });

  it("prioritizes a readable selection when distant neighbors cannot fit without changing user zoom", () => {
    const viewport = { x: 37, y: 92, zoom: 1.2 };
    const frame = { width: 455, height: 488 };
    const next = revealGraphContext(viewport, node, [{ ...node, y: 6000 }], frame);
    expect(next.zoom).toBe(viewport.zoom);
    expect(next.x + node.x * next.zoom).toBeGreaterThanOrEqual(48);
    expect(next.y + node.y * next.zoom).toBeGreaterThanOrEqual(48);
    expect(next.y + (node.y + node.height) * next.zoom).toBeLessThanOrEqual(frame.height - 48);
  });

  it("reserves conditional label space in graph units at enlarged operator zoom", () => {
    const selected = { x: 500, y: 180, width: 292, height: 104 };
    const frame = { width: 600, height: 760 };
    const viewport = revealGraphContext({ x: 0, y: 110, zoom: 1.6 }, selected,
      [32, 328].map(y => ({ x: 500, y, width: 220, height: 104 })), frame);
    expect(viewport.zoom).toBe(1.6);
    // The longest normal condition label extends 68 graph units after its card.
    expect(viewport.x + (selected.x + 220 + 68) * viewport.zoom).toBeLessThanOrEqual(frame.width - 24);
  });
});
