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

test("initially frames the complete visible demo path and preserves the operator viewport through metadata and layout changes", async ({ page }) => {
  await page.setViewportSize({ width: 1366, height: 768 });
  await page.goto("./#/builder");
  const canvas = page.getByLabel("Scenario graph canvas");
  await expect(page.getByRole("heading", { name: "Build your experiment" })).toBeVisible();
  await expect(page.locator(".react-flow__node:visible")).toHaveCount(6);
  await expect(page.getByText(/6 of 7 steps shown/)).toBeVisible();
  // No Fit graph click: every measured node on the normal initial path must fit.
  await expect.poll(() => canvas.evaluate((element) => {
    const boundary = element.getBoundingClientRect();
    return Array.from(element.querySelectorAll<HTMLElement>(".react-flow__node"))
      .filter((node) => getComputedStyle(node).display !== "none" && getComputedStyle(node).visibility !== "hidden")
      .filter((node) => {
        const box = node.getBoundingClientRect();
        return box.width <= 0 || box.height <= 0 || box.left < boundary.left - 1 || box.top < boundary.top - 1 || box.right > boundary.right + 1 || box.bottom > boundary.bottom + 1;
      }).map((node) => node.dataset.id);
  }), { message: "All six initially visible steps fit inside the canvas after measurement" }).toEqual([]);

  const initial = await viewport(page);
  await page.getByRole("button", { name: /^Zoom in$/i }).click();
  await expect.poll(async () => (await viewport(page)).zoom).toBeGreaterThan(initial.zoom);
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
  expect(await viewport(page)).toEqual(chosen);

  await page.setViewportSize({ width: 1180, height: 820 });
  await expect.poll(async () => (await canvas.boundingBox())!.width).toBeLessThan(boundary!.width);
  await finishLayout(page);
  expect(await viewport(page)).toEqual(chosen);
  await expect(name).toHaveValue("My manually framed experiment");
});
