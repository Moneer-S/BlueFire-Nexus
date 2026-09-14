import { expect, test, type Page } from "@playwright/test";
import { demoScenario } from "../../src/lib/demo";
import type { Outcome, Scenario } from "../../src/types";

const steps = demoScenario.steps.filter((step) => step.id !== "fallback");
const scenario: Scenario = { ...demoScenario, title: "Inspect every outcome route", steps,
  layout: Object.fromEntries(steps.map((step, index) => [step.id, { x: 48 + index % 4 * 294, y: 48 + Math.floor(index / 4) * 190 }])),
  edges: [...steps.slice(0, -1).map((step, index) => ({ from_step: step.id, outcome: "success" as Outcome, to_step: steps[index + 1]!.id })),
    ...steps.slice(1, -1).flatMap((step) => (["partial", "blocked", "failed"] as Outcome[]).map((outcome) => ({ from_step: step.id, outcome, to_step: "cleanup" })))],
};
async function frame(page: Page) {
  await page.evaluate(() => new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
}
async function settle(page: Page) {
  await expect.poll(async () => { const before = await viewport(page); await frame(page); return await viewport(page) === before; }).toBe(true);
}
async function viewport(page: Page) {
  return page.locator(".react-flow__viewport").evaluate((element) => getComputedStyle(element).transform);
}

for (const width of [1100, 640]) {
  test(`bounds the route dock and fits every step without changing arranged positions at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 791 });
    await page.addInitScript((draft) => localStorage.setItem("bluefire.local.scenario.v1", JSON.stringify(draft)), scenario);
    await page.goto("./#/builder");
    await page.getByRole("button", { name: "Canvas", exact: true }).click();
    const canvas = page.getByLabel("Scenario graph canvas");
    await expect(page.locator(".react-flow__node:visible")).toHaveCount(6);
    await frame(page);
    await page.getByRole("button", { name: /^Zoom in$/i }).click();
    await settle(page);
    const chosen = await viewport(page);
    await page.getByRole("button", { name: "Show all branches", exact: true }).click();
    const routes = page.getByRole("complementary", { name: "Route inspection" });
    await expect(routes.getByRole("list", { name: "Visible routes" }).getByRole("button")).toHaveCount(17);
    await frame(page);
    expect(await viewport(page)).toBe(chosen);
    // The route list must scroll in a bounded dock, never expand the canvas to its full contents.
    const dock = await routes.boundingBox();
    const before = await canvas.boundingBox();
    expect(dock!.height).toBeLessThanOrEqual(560);
    expect(before!.height).toBeLessThanOrEqual(560);
    if (width > 760) expect(before!.x + before!.width).toBeLessThanOrEqual(dock!.x + 1);
    else expect(before!.y + before!.height).toBeLessThanOrEqual(dock!.y + 1);
    await page.getByRole("button", { name: "Fit graph", exact: true }).click();
    await expect.poll(() => canvas.evaluate((element) => {
      const boundary = element.getBoundingClientRect();
      return [...element.querySelectorAll<HTMLElement>(".react-flow__node")].filter((node) => {
        const box = node.getBoundingClientRect();
        return box.width <= 0 || box.left < boundary.left - 1 || box.right > boundary.right + 1 || box.top < boundary.top - 1 || box.bottom > boundary.bottom + 1;
      }).map((node) => node.dataset.id);
    }), { message: "Explicit Fit contains every measured step inside the reserved visible canvas" }).toEqual([]);
    await page.getByRole("list", { name: "Visible routes" }).getByRole("button").last().focus();
    await expect(page.getByRole("list", { name: "Visible routes" }).getByRole("button").last()).toBeInViewport();
    await settle(page);
    const fitted = await viewport(page);
    await page.getByRole("button", { name: "Close route list" }).click();
    await frame(page);
    expect(await viewport(page)).toBe(fitted);
    expect(await page.evaluate(() => JSON.parse(localStorage.getItem("bluefire.local.scenario.v1")!))).toEqual(scenario);
  });
}
