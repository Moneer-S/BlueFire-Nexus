import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

test("primary navigation is keyboard-accessible and the overview has no serious axe violations", async ({ page }) => {
  const consoleErrors: string[] = [];
  page.on("console", (message) => { if (message.type() === "error") consoleErrors.push(message.text()); });
  await page.goto("./");
  await expect(page.getByRole("heading", { name: "Design the path. Observe the defense." })).toBeVisible();

  await page.keyboard.press("Tab");
  await expect(page.getByRole("link", { name: "Skip to content" })).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.locator("#main-content")).toBeFocused();

  const accessibility = await new AxeBuilder({ page }).analyze();
  expect(accessibility.violations.filter((item) => ["serious", "critical"].includes(item.impact ?? ""))).toEqual([]);
  expect(consoleErrors).toEqual([]);
});

test("all major workspaces are reachable", async ({ page }) => {
  const routes = [
    ["Scenarios", "Reusable security experiments"],
    ["Scenario Builder", "Compose a typed adaptive graph"],
    ["Runs", "Preflight every path. Observe every decision."],
    ["Compare", "Measure what changed"],
    ["Behaviors", "Neutral, typed behavior contracts"],
    ["Detection Lab", "Detection Lab"],
    ["Runner Profiles", "Runner profiles"],
    ["Runners", "Runners"],
    ["Actions & Plugins", "Actions & plugins"],
    ["Research Sources", "Research sources"],
    ["AI Planner", "AI Planner"],
    ["Settings", "Settings"],
    ["Help & Docs", "Help center"],
  ] as const;
  await page.goto("./");
  for (const [link, heading] of routes) {
    await page.getByRole("link", { name: link, exact: true }).click();
    await expect(page.getByRole("heading", { name: heading, exact: true })).toBeVisible();
  }
});
