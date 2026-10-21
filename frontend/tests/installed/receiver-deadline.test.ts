import { describe, expect, it } from "vitest";
import { createDeadlineBudget } from "./receiver-deadline.mjs";

describe("installed receiver deadline budget", () => {
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
});
