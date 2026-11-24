import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

// The demo build holds one pair of runs that is BUILT, not a result: two
// recordings of the lab's CI runs, the after one changed by hand, compared by
// bluefire-lab compare. Its recordings are not in the demo.

test("a pair of runs opens from Runs, says it is built, reads as a claim, and Back returns", async ({ page }) => {
  const problems: string[] = [];
  page.on("pageerror", (error) => problems.push(String(error)));
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("./#/runs");

  const pairs = page.getByRole("region", { name: "Before against after" });
  const pair = pairs.getByRole("listitem").filter({ hasText: "The settings of sensor auditd" });
  await expect(pair.getByText("Built for the demo")).toBeVisible();
  await expect(pair.getByText("1 better, 0 worse, 0 changed without a cause, of 91 paired steps")).toBeVisible();
  const list = await new AxeBuilder({ page }).include(".recorded-pairs").analyze();
  expect(list.violations.filter((item) => ["serious", "critical"].includes(item.impact ?? ""))).toEqual([]);

  await pair.getByRole("link", { name: "The settings of sensor auditd" }).click();
  await expect(page).toHaveURL(/#\/runs\/compared\/[0-9a-f]{16}$/);
  await expect(page.getByRole("heading", { level: 1, name: "One change: the settings of sensor auditd" })).toBeVisible();
  await expect(page.getByText(/^Built for the demo, not a result\./)).toBeVisible();
  const moved = page.getByRole("region", { name: /^What the change moved/ });
  await expect(moved.getByRole("button", { name: /Clear Bash history \(echo\)/ })).toBeVisible();
  await expect(moved).toContainText("on 1 of the 4 published procedures of T1070.003 in the list");
  await expect(page.getByRole("region", { name: /^The control/ })).toContainText("the same on 91 of 91 paired steps");
  // One main landmark: the page sits inside the app's own.
  await expect(page.getByRole("main")).toHaveCount(1);
  const pagePart = await new AxeBuilder({ page }).include(".compared").analyze();
  expect(pagePart.violations.filter((item) => ["serious", "critical"].includes(item.impact ?? ""))).toEqual([]);

  // The step's detail is a place of its own. Its recordings are not in the demo, and it says so.
  await moved.getByRole("button", { name: /Clear Bash history \(echo\)/ }).click();
  await expect(page).toHaveURL(/\?step=/);
  await expect(page.getByRole("heading", { name: "Clear Bash history (echo), before and after" })).toBeFocused();
  await expect(page.getByText(/^The before recording could not be loaded/)).toBeVisible();
  await page.goBack();
  await expect(page.getByRole("heading", { name: "Clear Bash history (echo), before and after" })).toHaveCount(0);
  await page.goBack();
  await expect(page).toHaveURL(/#\/runs$/);
  await expect(pairs).toBeVisible();
  expect(problems).toEqual([]);
});
