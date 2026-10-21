import { expect, test, type Page } from "@playwright/test";

async function viewport(page: Page) {
  return page.locator(".react-flow__viewport").evaluate((element) => {
    const matrix = new DOMMatrixReadOnly(getComputedStyle(element).transform);
    return { x: matrix.m41, y: matrix.m42, zoom: matrix.m11 };
  });
}

async function finishLayout(page: Page) {
  await page.evaluate(() => new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
}
async function selectedInsideCanvas(page: Page) {
  return page.locator(".flow-node.selected").evaluate((node) => {
    const box = node.getBoundingClientRect();
    const boundary = node.closest(".graph-canvas")!.getBoundingClientRect();
    return box.left >= boundary.left && box.right <= boundary.right && box.top >= boundary.top && box.bottom <= boundary.bottom;
  });
}
async function visibleNodesInsideCanvas(page: Page) {
  return page.getByLabel("Scenario graph canvas").evaluate((canvas) => {
    const boundary = canvas.getBoundingClientRect();
    return Array.from(canvas.querySelectorAll<HTMLElement>(".react-flow__node"))
      .filter((node) => getComputedStyle(node).display !== "none" && getComputedStyle(node).visibility !== "hidden")
      .every((node) => {
        const box = node.getBoundingClientRect();
        return box.left >= boundary.left - 1 && box.top >= boundary.top - 1 && box.right <= boundary.right + 1 && box.bottom <= boundary.bottom + 1;
      });
  });
}

test("opens at readable focus, keeps an explicit whole-path overview, and preserves the operator viewport", async ({ page }) => {
  await page.setViewportSize({ width: 1366, height: 768 });
  await page.goto("./#/builder");
  const canvas = page.getByLabel("Scenario graph canvas");
  await expect(page.getByRole("heading", { name: "Endpoint control validation", level: 1 })).toBeVisible();
  await expect(page.locator(".react-flow__node:visible")).toHaveCount(3);
  await expect(page.locator(".graph-group-count")).toHaveText("3 of 7 steps");
  await expect(page.locator(".graph-disclosure")).not.toContainText("steps shown");
  await expect(page.locator(".graph-disclosure")).toContainText(/branches hidden.*Review run includes the whole experiment/);
  await expect(page.locator(".graph-group-connections")).not.toHaveAttribute("open");
  await page.locator(".graph-group-connections > summary").click();
  await expect(page.getByText(/To: .*On success/)).toBeVisible();
  await page.locator(".graph-group-connections > summary").click();
  await expect(page.locator(".graph-group-connections")).not.toHaveAttribute("open");
  const initial = await viewport(page);
  expect(initial.zoom).toBeGreaterThanOrEqual(0.8);
  const initiallySelected = canvas.locator(".flow-node.selected");
  await expect(initiallySelected).toBeVisible();
  await expect.poll(() => selectedInsideCanvas(page), { message: "Initial selected step remains readable and inside the canvas" }).toBe(true);
  await expect.poll(() => visibleNodesInsideCanvas(page), { message: "Every node in the initial group stays inside the canvas" }).toBe(true);

  await page.getByRole("combobox", { name: "Step group" }).selectOption("all");
  await expect(page.locator(".react-flow__node:visible")).toHaveCount(6);
  await page.getByRole("button", { name: "Fit visible graph" }).click();
  await expect.poll(() => canvas.evaluate((element) => {
    const boundary = element.getBoundingClientRect();
    return Array.from(element.querySelectorAll<HTMLElement>(".react-flow__node"))
      .filter((node) => getComputedStyle(node).display !== "none" && getComputedStyle(node).visibility !== "hidden")
      .filter((node) => {
        const box = node.getBoundingClientRect();
        return box.width <= 0 || box.height <= 0 || box.left < boundary.left - 1 || box.top < boundary.top - 1 || box.right > boundary.right + 1 || box.bottom > boundary.bottom + 1;
      }).map((node) => node.dataset.id);
  }), { message: "Explicit overview contains every step on the visible path" }).toEqual([]);
  const overview = await viewport(page);
  expect(overview.zoom).toBeLessThan(initial.zoom);
  await page.getByRole("button", { name: "Focus selected step" }).click();
  await expect.poll(async () => (await viewport(page)).zoom).toBeGreaterThan(overview.zoom);
  await expect.poll(() => selectedInsideCanvas(page)).toBe(true);

  const focused = await viewport(page);
  await page.getByRole("button", { name: /^Zoom in$/i }).click();
  await expect.poll(async () => (await viewport(page)).zoom).toBeGreaterThan(focused.zoom);
  await finishLayout(page);
  const zoomed = await viewport(page);
  const boundary = await canvas.boundingBox();
  expect(boundary).not.toBeNull();
  await page.mouse.move(boundary!.x + 16, boundary!.y + 16);
  await page.mouse.down();
  await page.mouse.move(boundary!.x + 76, boundary!.y + 56, { steps: 6 });
  await page.mouse.up();
  await expect.poll(async () => Math.abs((await viewport(page)).x - zoomed.x)).toBeGreaterThan(30);
  await finishLayout(page);
  const chosen = await viewport(page);
  expect(chosen.zoom).toBeCloseTo(zoomed.zoom, 5);

  const name = page.getByRole("textbox", { name: "Experiment name" });
  await name.fill("My manually framed experiment");
  await expect(name).toHaveValue("My manually framed experiment");
  await finishLayout(page);
  expect(await viewport(page)).toEqual(chosen);

  await page.getByRole("button", { name: "Show node inspector" }).click();
  await expect(page.locator(".inspector-panel")).toBeVisible();
  await finishLayout(page);
  expect((await viewport(page)).zoom).toBeCloseTo(chosen.zoom, 5);
  await expect.poll(() => selectedInsideCanvas(page)).toBe(true);

  await page.setViewportSize({ width: 1180, height: 820 });
  await expect.poll(async () => (await canvas.boundingBox())!.width).toBeLessThan(boundary!.width);
  await finishLayout(page);
  expect((await viewport(page)).zoom).toBeCloseTo(chosen.zoom, 5);
  await expect.poll(() => selectedInsideCanvas(page)).toBe(true);
  await expect(name).toHaveValue("My manually framed experiment");
});

test("selecting a rightmost step keeps it visible beside its details without changing zoom", async ({ page }) => {
  await page.setViewportSize({ width: 1366, height: 768 });
  await page.goto("./#/builder");
  const canvas = page.getByLabel("Scenario graph canvas");
  await expect(page.locator(".react-flow__node:visible")).toHaveCount(3);
  await finishLayout(page);
  const before = await viewport(page);
  const rightmost = await canvas.locator(".react-flow__node:visible").evaluateAll(elements => elements
    .map(element => ({ id: (element as HTMLElement).dataset.id!, right: element.getBoundingClientRect().right }))
    .sort((left, right) => right.right - left.right)[0]!.id);
  // Use the observed data identity, rather than a fixture-specific step order.
  const selected = canvas.locator(`.react-flow__node[data-id="${rightmost}"]`);
  await selected.click();
  await expect(page.locator(".inspector-panel")).toBeVisible();
  await expect.poll(() => selected.evaluate(element => {
    const box = element.getBoundingClientRect();
    const boundary = element.closest(".graph-canvas")!.getBoundingClientRect();
    return box.left >= boundary.left && box.right <= boundary.right && box.top >= boundary.top && box.bottom <= boundary.bottom;
  })).toBe(true);
  expect((await viewport(page)).zoom).toBeCloseTo(before.zoom, 5);
});
