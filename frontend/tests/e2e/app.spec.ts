import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
import { demoScenario } from "../../src/lib/demo";

test("primary navigation is keyboard-accessible and the overview has no serious axe violations", async ({ page }) => {
  const consoleErrors: string[] = [];
  page.on("console", (message) => { if (message.type() === "error") consoleErrors.push(message.text()); });
  await page.goto("./");
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();

  await page.keyboard.press("Tab");
  await expect(page.getByRole("link", { name: "Skip to content" })).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.locator("#main-content")).toBeFocused();

  const accessibility = await new AxeBuilder({ page }).analyze();
  expect(accessibility.violations.filter((item) => ["serious", "critical"].includes(item.impact ?? ""))).toEqual([]);
  expect(consoleErrors).toEqual([]);
});

test("skip navigation preserves the active HashRouter workspace", async ({ page }) => {
  await page.goto("./#/builder");
  await expect(page.getByRole("heading", { name: demoScenario.title })).toBeVisible();
  await page.keyboard.press("Tab");
  await expect(page.getByRole("link", { name: "Skip to content" })).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.locator("#main-content")).toBeFocused();
  expect(new URL(page.url()).hash).toBe("#/builder");
});

test("system theme follows live operating-system color-scheme changes", async ({ page }) => {
  await page.emulateMedia({ colorScheme: "dark" });
  await page.goto("./#/settings");
  await expect(page.getByRole("heading", { name: "Settings" })).toBeVisible();
  await page.getByRole("button", { name: /^System/ }).click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");

  await page.getByRole("link", { name: "Build" }).click();
  await expect(page.getByRole("heading", { name: demoScenario.title })).toBeVisible();
  await page.emulateMedia({ colorScheme: "light" });
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
});

test("all major workspaces are reachable", async ({ page }) => {
  const routes = [
    ["Experiments", "Experiments"],
    ["Build", demoScenario.title],
    ["Runs", "Runs"],
    ["Compare", "Compare runs"],
    ["Behaviors", "Methods"],
    ["Detection Lab", "Detection Lab"],
    ["Runner Profiles", "Runner profiles"],
    ["Runners", "Runners"],
    ["Actions & Plugins", "Actions & plugins"],
    ["Action Packages", "Action packages"],
    ["Research Sources", "Research sources"],
    ["Proposal audit", "Runtime proposal audit"],
    ["Settings", "Settings"],
    ["Help & Docs", "Help center"],
  ] as const;
  await page.goto("./");
  for (const [link, heading] of routes) {
    const target = page.getByRole("link", { name: link, exact: true });
    if (!await target.isVisible()) {
      const group = ["Runner Profiles", "Runners", "Actions & Plugins", "Action Packages"].includes(link) ? "Show settings tools" : "Show more tools";
      await page.getByRole("button", { name: group }).click();
    }
    await target.click();
    await expect(page.getByRole("heading", { name: heading, exact: true })).toBeVisible();
  }
});

test("Overview opens the exact experiment in the list without replacing the working draft", async ({ page }) => {
  await page.goto("./");
  await expect(page.getByRole("heading", { name: "Overview", exact: true })).toBeVisible();
  const before = await page.evaluate(() => localStorage.getItem("bluefire.local.scenario.v1"));
  const experiment = page.getByRole("region", { name: "Experiments", exact: true }).getByRole("listitem").filter({ hasText: demoScenario.title });
  await experiment.getByRole("link", { name: "Open in library" }).click();
  expect(new URL(page.url()).hash).toBe(`#/scenarios?selected=${encodeURIComponent(demoScenario.id)}`);
  const selected = page.getByRole("article").filter({ has: page.getByRole("heading", { name: demoScenario.title, exact: true }) });
  await expect(selected).toHaveAttribute("aria-current", "true");
  await expect(selected).toBeFocused();
  expect(await page.evaluate(() => localStorage.getItem("bluefire.local.scenario.v1"))).toBe(before);
});
