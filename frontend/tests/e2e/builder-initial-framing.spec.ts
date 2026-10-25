import { expect, test, type Page } from "@playwright/test";
import { demoScenario } from "../../src/lib/demo";

async function viewOptions(page: Page, open: boolean) {
  if (await page.locator("details.graph-options").evaluate(element => (element as HTMLDetailsElement).open) !== open) {
    await page.getByLabel("View options", { exact: true }).click();
  }
}

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

async function expectPaintedOutcomeRoutes(page: Page) {
  const expected = demoScenario.edges.map((edge, index) => ({
    id: `route-${edge.from_step}-${edge.outcome}-${edge.to_step}-${index}`,
    pathCount: 1, finitePath: true, nonzeroLength: true, painted: true, visibleAncestors: true,
    finiteBounds: true, dashed: edge.outcome !== "success",
  })).sort((left, right) => left.id.localeCompare(right.id));
  const routes = page.locator(".react-flow__edge");
  await expect(routes).toHaveCount(expected.length);
  // Straight SVG paths may have a zero-width or zero-height box despite a
  // visible stroke. Check their saved identities and painted geometry directly.
  await expect.poll(() => routes.evaluateAll(edges => edges.map(edge => {
    const paths = edge.querySelectorAll<SVGPathElement>(".react-flow__edge-path");
    const path = paths[0];
    const style = path ? getComputedStyle(path) : undefined;
    const box = path?.getBoundingClientRect();
    const d = path?.getAttribute("d");
    let length = Number.NaN;
    try { length = path?.getTotalLength() ?? Number.NaN; } catch { /* Invalid geometry fails the assertion. */ }
    let visibleAncestors = Boolean(path);
    for (let ancestor: Element | null = path ?? null; ancestor; ancestor = ancestor.parentElement) {
      const ancestorStyle = getComputedStyle(ancestor);
      if (ancestorStyle.display === "none" || ["hidden", "collapse"].includes(ancestorStyle.visibility)
        || Number(ancestorStyle.opacity) === 0) visibleAncestors = false;
    }
    const strokeWidth = Number.parseFloat(style?.strokeWidth ?? "");
    return {
      id: edge.getAttribute("data-id") ?? "", pathCount: paths.length,
      finitePath: Boolean(d && !/NaN|Infinity/.test(d)), nonzeroLength: Number.isFinite(length) && length > 0,
      painted: Boolean(style && style.stroke !== "none" && style.stroke !== "transparent"
        && !/rgba\([^)]*,\s*0(?:\.0*)?\)$/.test(style.stroke)
        && Number.isFinite(strokeWidth) && strokeWidth > 0 && Number(style.strokeOpacity) > 0),
      visibleAncestors,
      finiteBounds: Boolean(box && [box.x, box.y, box.width, box.height].every(Number.isFinite)
        && box.width >= 0 && box.height >= 0 && (box.width > 0 || box.height > 0)),
      dashed: Boolean(style && style.strokeDasharray !== "none"),
    };
  }).sort((left, right) => left.id.localeCompare(right.id)))).toEqual(expected);
}

test("opens at readable focus, keeps an explicit whole-path overview, and preserves the operator viewport", async ({ page }) => {
  await page.setViewportSize({ width: 1366, height: 768 });
  await page.goto("./#/builder");
  const canvas = page.getByLabel("Scenario graph canvas");
  await expect(page.getByRole("heading", { name: "Endpoint control validation", level: 1 })).toBeVisible();
  await expect(page.locator(".react-flow__node:visible")).toHaveCount(demoScenario.steps.length);
  await expectPaintedOutcomeRoutes(page);
  await expect(page.getByRole("navigation", { name: "Focused connected path" })).toHaveCount(0);
  await expect(page.locator(".graph-disclosure")).toHaveCount(0);
  const initial = await viewport(page);
  expect(initial.zoom).toBeGreaterThanOrEqual(0.8);
  const initiallySelected = canvas.locator(".flow-node.selected");
  await expect(initiallySelected).toBeVisible();
  await expect.poll(() => selectedInsideCanvas(page), { message: "Initial selected step remains readable and inside the canvas" }).toBe(true);
  const savedBeforeViewChanges = await page.evaluate(() => localStorage.getItem("bluefire.local.scenario.v1"));
  await page.getByRole("button", { name: "Fit view", exact: true }).click();
  await expect.poll(() => visibleNodesInsideCanvas(page), { message: "Explicit overview contains every step and branch" }).toBe(true);
  const overview = await viewport(page);
  expect(overview.zoom).toBeLessThan(initial.zoom);
  await viewOptions(page, true);
  await page.getByRole("button", { name: "Focus selected step" }).click();
  await viewOptions(page, false);
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
  expect(await page.evaluate(() => localStorage.getItem("bluefire.local.scenario.v1"))).toBe(savedBeforeViewChanges);

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

test("step details use the full available inspector height", async ({ page }) => {
  await page.setViewportSize({ width: 1920, height: 1080 });
  await page.goto("./#/builder");
  await page.getByRole("button", { name: "Show node inspector" }).click();
  const body = page.locator(".inspector-body");
  await expect(body).toBeVisible();
  await expect(body).toHaveCSS("max-height", "none");
  await expect.poll(() => body.evaluate(element => {
    const panel = element.closest(".inspector-panel")!.getBoundingClientRect();
    return Math.abs(panel.bottom - element.getBoundingClientRect().bottom);
  })).toBeLessThanOrEqual(3);
  await page.setViewportSize({ width: 1366, height: 768 });
  const section = body.locator('[role="tabpanel"]:visible > section').nth(1);
  await expect(section).toHaveCSS("padding-top", "13px");
  await expect(section).toHaveCSS("padding-bottom", "13px");
  await expect(section).toHaveCSS("border-right-width", "0px");
  await expect(section).toHaveCSS("border-bottom-width", "1px");
});

test("selecting a rightmost visible step keeps it beside its details without changing zoom", async ({ page }) => {
  await page.setViewportSize({ width: 1366, height: 768 });
  await page.goto("./#/builder");
  const canvas = page.getByLabel("Scenario graph canvas");
  await expect(page.locator(".react-flow__node:visible")).toHaveCount(demoScenario.steps.length);
  await viewOptions(page, true);
  await page.getByRole("button", { name: "Focus selected step" }).click();
  await viewOptions(page, false);
  await expect.poll(async () => (await viewport(page)).zoom).toBeCloseTo(1, 5);
  // Exercise the readable band below 100% through the actual operator control.
  await page.getByRole("button", { name: /^Zoom out$/i }).click();
  await expect.poll(async () => (await viewport(page)).zoom).toBeCloseTo(1 / 1.2, 5);
  await finishLayout(page);
  const before = await viewport(page);
  expect(before.zoom).toBeGreaterThanOrEqual(0.8);
  expect(before.zoom).toBeLessThan(1);
  const savedBefore = await page.evaluate(() => localStorage.getItem("bluefire.local.scenario.v1"));
  const rightmost = await canvas.locator(".react-flow__node:visible").evaluateAll(elements => {
    const boundary = elements[0]!.closest(".graph-canvas")!.getBoundingClientRect();
    return elements.map(element => ({ id: (element as HTMLElement).dataset.id!, box: element.getBoundingClientRect() }))
      .filter(({ box }) => box.left >= boundary.left && box.right <= boundary.right && box.top >= boundary.top && box.bottom <= boundary.bottom)
      .sort((left, right) => right.box.right - left.box.right)[0]!.id;
  });
  // Use the observed data identity, rather than a fixture-specific step order.
  const selected = canvas.locator(`.react-flow__node[data-id="${rightmost}"]`);
  await expect(selected.locator(".flow-node")).not.toHaveClass(/\bselected\b/);
  await selected.click();
  await expect(page.locator(".inspector-panel")).toBeVisible();
  await expect.poll(() => selected.evaluate(element => {
    const box = element.getBoundingClientRect();
    const boundary = element.closest(".graph-canvas")!.getBoundingClientRect();
    return box.left >= boundary.left && box.right <= boundary.right && box.top >= boundary.top && box.bottom <= boundary.bottom;
  })).toBe(true);
  expect((await viewport(page)).zoom).toBeCloseTo(before.zoom, 5);
  expect(await page.evaluate(() => localStorage.getItem("bluefire.local.scenario.v1"))).toBe(savedBefore);
});
