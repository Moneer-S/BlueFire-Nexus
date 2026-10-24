import { expect, test } from "@playwright/test";

test("Assistant stays beside or below the work when a desktop window is constrained", async ({ page }) => {
  await page.setViewportSize({ width: 1366, height: 768 });
  await page.goto("./#/detection-lab");
  const trigger = page.getByRole("button", { name: /^Assistant$/ });
  await trigger.click();
  const assistant = page.getByRole("complementary", { name: "BlueFire Assistant" });
  const close = assistant.getByRole("button", { name: "Close assistant" });
  for (const viewport of [{ width: 1366, height: 768 }, { width: 1024, height: 768 }, { width: 910, height: 512 }]) {
    await page.setViewportSize(viewport);
    await expect(close).toBeInViewport();
    const regions = await page.evaluate(() => {
      const main = document.getElementById("main-content")!.getBoundingClientRect();
      const dock = document.getElementById("assistant-dock")!.getBoundingClientRect();
      return { main: { left: main.left, top: main.top, right: main.right, bottom: main.bottom, width: main.width, height: main.height }, dock: { left: dock.left, top: dock.top, bottom: dock.bottom } };
    });
    expect(regions.main.width).toBeGreaterThan(0);
    expect(regions.main.height).toBeGreaterThan(0);
    expect(regions.main.left).toBeLessThan(viewport.width);
    expect(regions.main.top).toBeLessThan(viewport.height);
    expect(regions.main.right).toBeGreaterThan(0);
    expect(regions.main.bottom).toBeGreaterThan(0);
    expect(regions.main.right <= regions.dock.left + 1 || regions.main.bottom <= regions.dock.top + 1).toBe(true);
    expect(regions.dock.bottom).toBeLessThanOrEqual(viewport.height + 1);
  }
  await close.focus();
  await page.keyboard.press("Escape");
  await expect(assistant).toHaveCount(0);
  await expect(trigger).toBeFocused();
});

test("Assistant stays reachable on laptop and narrow screens and returns keyboard focus", async ({ page }) => {
  await page.goto("./#/detection-lab");
  for (const width of [1280, 390, 320]) {
    await page.setViewportSize({ width, height: 844 });
    await expect(page.locator(".workspace-topbar")).toBeVisible();
    const trigger = page.getByRole("button", { name: /^Assistant$/ });
    await expect(trigger).toBeVisible();
    const bounds = await trigger.boundingBox();
    expect(bounds).not.toBeNull();
    if (!bounds) throw new Error("Assistant trigger is not rendered.");
    expect(bounds.x).toBeGreaterThanOrEqual(0);
    expect(bounds.x + bounds.width).toBeLessThanOrEqual(width);
    await trigger.click();
    const dialog = page.getByRole("complementary", { name: "BlueFire Assistant" });
    await expect(dialog).toBeVisible();
    await expect(dialog.getByText(/This preview cannot run assistant operations/)).toBeVisible();
    await expect(dialog.getByRole("button", { name: "Start work" })).toBeDisabled();
    expect(await dialog.evaluate((element) => element.scrollWidth)).toBeLessThanOrEqual(width);
    await expect(page.getByRole("main")).not.toHaveAttribute("inert");
    await dialog.getByRole("button", { name: "Close assistant" }).focus();
    await page.keyboard.press("Escape");
    await expect(dialog).toHaveCount(0);
    await expect(trigger).toBeFocused();
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
  }
});
