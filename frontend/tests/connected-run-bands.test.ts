import { describe, expect, it } from "vitest";
import { connectedRunBands, type BandCard, type BandEdge } from "../src/lib/connected-run-bands";

const card = (ordinal: number, x = 40, y = (ordinal - 1) * 160): BandCard => ({ id: `step_${ordinal}`, ordinal, x, y, width: 220, height: 104 });
const edge = (from: number, to: number, outcome: BandEdge["outcome"] = "success"): BandEdge => ({ from_step: `step_${from}`, to_step: `step_${to}`, outcome });
const ids = (bands: ReturnType<typeof connectedRunBands>) => bands.map(band => band.stepIds);

describe("presentation-only connected run bands", () => {
  it("bands actual directly connected vertical cards and labels their real ordinals", () => {
    const bands = connectedRunBands([card(1), card(2), card(3)], [edge(1, 2), edge(2, 3)]);
    expect(bands).toEqual([{ id: 'connected-run:["step_1","step_2","step_3"]', stepIds: ["step_1", "step_2", "step_3"], ordinals: [1, 2, 3], label: "Steps 1–3", x: 28, y: -12, width: 244, height: 448 }]);
  });

  it("does not infer a band from proximity, non-success edges, or singleton cards", () => {
    expect(connectedRunBands([card(1), card(2)], [])).toEqual([]);
    expect(connectedRunBands([card(1), card(2)], [edge(1, 2, "failed")])).toEqual([]);
    expect(connectedRunBands([card(1)], [])).toEqual([]);
  });

  it("permits multiple outcomes to the same real successor without inventing a branch", () => {
    expect(ids(connectedRunBands([card(1), card(2), card(3)], [edge(1, 2), edge(1, 2, "partial"), edge(2, 3), edge(2, 3, "blocked"), edge(2, 3, "failed")]))).toEqual([["step_1", "step_2", "step_3"]]);
  });

  it("ends at a genuine branch, including a branch to a hidden/off-view endpoint", () => {
    const cards = [card(1), card(2), card(3), card(4), { ...card(5, 600), hidden: true }];
    expect(ids(connectedRunBands(cards, [edge(1, 2), edge(2, 3), edge(2, 5, "blocked"), edge(3, 4)]))).toEqual([["step_1", "step_2"], ["step_3", "step_4"]]);
  });

  it("starts a new run at a join and retains every original edge", () => {
    const edges = [edge(1, 2), edge(2, 3), edge(5, 3), edge(3, 4)];
    const snapshot = JSON.stringify(edges);
    expect(ids(connectedRunBands([card(1), card(2), card(3), card(4), card(5, 600)], edges))).toEqual([["step_1", "step_2"], ["step_3", "step_4"]]);
    expect(JSON.stringify(edges)).toBe(snapshot);
  });

  it("splits column changes and long gaps without moving saved positions", () => {
    const cards = [card(1), card(2), card(3, 400), card(4, 400), card(5, 400, 1200), card(6, 400, 1360)];
    const snapshot = JSON.stringify(cards);
    expect(ids(connectedRunBands(cards, [edge(1, 2), edge(2, 3), edge(3, 4), edge(4, 5), edge(5, 6)]))).toEqual([["step_1", "step_2"], ["step_3", "step_4"], ["step_5", "step_6"]]);
    expect(JSON.stringify(cards)).toBe(snapshot);
  });

  it("splits across an intervening unrelated card instead of enclosing it", () => {
    const cards = [card(1, 40, 0), card(2, 40, 160), card(3, 40, 400), card(4, 40, 560), { ...card(5, 40, 310), height: 24 }];
    expect(ids(connectedRunBands(cards, [edge(1, 2), edge(2, 3), edge(3, 4)], { maxGap: 160 }))).toEqual([["step_1", "step_2"], ["step_3", "step_4"]]);
  });

  it("does not enclose a spatially intermediate card skipped by an edge", () => {
    expect(ids(connectedRunBands([card(1), card(2), card(3), card(4)], [edge(1, 3), edge(3, 4)], { maxGap: 300 }))).toEqual([["step_3", "step_4"]]);
  });

  it("omits intersecting/overlapping cards, including outsiders touching the padded hull", () => {
    expect(connectedRunBands([card(1), card(2, 40, 90)], [edge(1, 2)])).toEqual([]);
    const outsider = { ...card(3, 265, 80), width: 40, height: 40 };
    expect(connectedRunBands([card(1), card(2), outsider], [edge(1, 2)])).toEqual([]);
  });

  it("omits simple execution loops even if one edge points downward", () => {
    expect(connectedRunBands([card(1), card(2)], [edge(1, 2), edge(2, 1)])).toEqual([]);
    expect(connectedRunBands([card(1), card(2), card(3)], [edge(1, 2), edge(2, 3), edge(3, 1)])).toEqual([]);
  });

  it("labels nonconsecutive real ordinals without implying missing steps are members", () => {
    expect(connectedRunBands([card(1), card(4, 40, 160), card(5, 40, 320)], [edge(1, 4), edge(4, 5)])[0]?.label).toBe("Steps 1, 4–5");
  });

  it("preserves frozen inputs and emits only presentation fields", () => {
    const cards = Object.freeze([Object.freeze(card(1)), Object.freeze(card(2))]);
    const edges = Object.freeze([Object.freeze(edge(1, 2))]);
    const snapshot = JSON.stringify({ cards, edges });
    const band = connectedRunBands(cards, edges)[0];
    expect(JSON.stringify({ cards, edges })).toBe(snapshot);
    expect(Object.keys(band!).sort()).toEqual(["height", "id", "label", "ordinals", "stepIds", "width", "x", "y"]);
  });

  it("fails closed on ambiguous or invalid visible bounds and invalid options", () => {
    expect(connectedRunBands([card(1), { ...card(2), id: "step_1" }], [edge(1, 2)])).toEqual([]);
    expect(connectedRunBands([card(1), { ...card(2), ordinal: 1 }], [edge(1, 2)])).toEqual([]);
    expect(connectedRunBands([card(1), { ...card(2), x: Number.NaN }], [edge(1, 2)])).toEqual([]);
    expect(connectedRunBands([card(1), card(2)], [edge(1, 2)], { padding: -1 })).toEqual([]);
  });

  it("keeps dense/large decoration work bounded by declining it", () => {
    const cards = Array.from({ length: 513 }, (_, index) => card(index + 1));
    expect(connectedRunBands(cards, [])).toEqual([]);
    expect(connectedRunBands([card(1), card(2)], Array.from({ length: 8193 }, () => edge(1, 2)))).toEqual([]);
    // 256 disjoint pairs force a full no-collision scan per pair. Decoration is
    // omitted when the collision budget is exhausted rather than doing unbounded work.
    const dense = Array.from({ length: 512 }, (_, index) => card(index + 1, Math.floor(index / 2) * 400, (index % 2) * 160));
    const links = Array.from({ length: 256 }, (_, index) => edge(index * 2 + 1, index * 2 + 2));
    expect(connectedRunBands(dense, links)).toEqual([]);
  });
});
