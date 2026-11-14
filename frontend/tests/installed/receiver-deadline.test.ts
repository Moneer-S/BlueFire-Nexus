import { describe, expect, it } from "vitest";
import { boundedLocalTimeout, createDeadlineBudget } from "./receiver-deadline.mjs";

describe("installed receiver deadline budget", () => {
  it("adds only two finite attempt allowances and retains the original cleanup reserve", () => {
    const budget = createDeadlineBudget(0, 295_000 + 2 * 90_000, 60_000);
    expect(budget.remaining(475_000)).toBe(0);
    expect(budget.beginCleanup(475_000)).toBe(535_000);
    expect(budget.remaining(475_000)).toBe(60_000);
    expect(budget.beginCleanup(534_000)).toBe(535_000);
    expect(budget.remaining(535_000)).toBe(0);
  });

  it("caps journey waits at the shared deadline", () => {
    const budget = createDeadlineBudget(1_000, 300_000, 60_000);
    expect(budget.remaining(11_000)).toBe(290_000);
    expect(budget.bounded(120_000, 250_000)).toBe(51_000);
    expect(budget.remaining(301_000)).toBe(0);
    expect(budget.bounded(10_000, 301_000)).toBe(0);
  });

  it("reserves bounded cleanup time without extending the total cap", () => {
    const budget = createDeadlineBudget(1_000, 300_000, 60_000);
    expect(budget.beginCleanup(301_000)).toBe(361_000);
    expect(budget.remaining(301_000)).toBe(60_000);
    expect(budget.bounded(45_000, 301_000)).toBe(45_000);
    expect(budget.beginCleanup(359_000)).toBe(361_000);
    expect(budget.remaining(361_000)).toBe(0);
  });

  it("caps each slow owner poll by both the local wait and shared journey deadlines", () => {
    expect(boundedLocalTimeout(10_000, 0, 40_000)).toBe(10_000);
    expect(boundedLocalTimeout(10_000, 9_500, 40_000)).toBe(500);
    expect(boundedLocalTimeout(10_000, 1_000, 700)).toBe(700);
    expect(boundedLocalTimeout(10_000, 10_000, 40_000)).toBe(0);
  });
});
