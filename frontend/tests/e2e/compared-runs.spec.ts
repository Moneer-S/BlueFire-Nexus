import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

// The demo build holds the pair of runs that ships with the app, the same files
// the service ships: two runs side by side in one CI run, before and after an
// audit watch on the test account's shell history files, and the lab's delta of
// them. Its recordings are loaded when they are asked for.

test("the shipped pair opens from Runs, reads as a claim with its price, opens a step from both runs, and Back returns", async ({ page }) => {
  const problems: string[] = [];
  page.on("pageerror", (error) => problems.push(String(error)));
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("./#/runs");

  const pairs = page.getByRole("region", { name: "Before against after" });
  const pair = pairs.getByRole("listitem").filter({ hasText: "The settings of sensor auditd" });
  await expect(pair.getByText("Shipped with BlueFire")).toBeVisible();
  await expect(pair.getByText("1 better, 0 worse, 0 changed without a cause, of 91 paired steps")).toBeVisible();
  const list = await new AxeBuilder({ page }).include(".recorded-pairs").analyze();
  expect(list.violations.filter((item) => ["serious", "critical"].includes(item.impact ?? ""))).toEqual([]);

  await pair.getByRole("link", { name: "The settings of sensor auditd" }).click();
  await expect(page).toHaveURL(/#\/runs\/compared\/[0-9a-f]{16}$/);
  await expect(page.getByRole("heading", { level: 1, name: "One change: the settings of sensor auditd" })).toBeVisible();
  await expect(page.getByText("The same steps, made with the same setup apart from this change, side by side in one CI run, each on a fresh runner of its own.")).toBeVisible();
  const moved = page.getByRole("region", { name: /^What the change moved/ });
  await expect(moved.getByRole("button", { name: /Clear Bash history \(echo\)/ })).toBeVisible();
  await expect(moved).toContainText("on 1 of the 4 published procedures of T1070.003 in the list");
  await expect(moved.getByText(/^price: /)).toBeVisible();
  await expect(page.getByRole("region", { name: /^The control/ })).toContainText("the same on 91 of 91 paired steps");
  // One main landmark: the page sits inside the app's own.
  await expect(page.getByRole("main")).toHaveCount(1);
  const pagePart = await new AxeBuilder({ page }).include(".compared").analyze();
  expect(pagePart.violations.filter((item) => ["serious", "critical"].includes(item.impact ?? ""))).toEqual([]);

  // The step's detail is a place of its own, drawn from both shipped recordings.
  await moved.getByRole("button", { name: /Clear Bash history \(echo\)/ }).click();
  await expect(page).toHaveURL(/\?step=/);
  const detail = page.getByRole("region", { name: "Clear Bash history (echo), before and after" });
  await expect(detail.getByRole("heading", { name: "Clear Bash history (echo), before and after" })).toBeFocused();
  await expect(detail.getByRole("article")).toHaveCount(2);
  await expect(detail.getByRole("article").first()).toContainText("It took effect, and no sensor recorded it.");
  await page.goBack();
  await expect(detail).toHaveCount(0);
  await page.goBack();
  await expect(page).toHaveURL(/#\/runs$/);
  await expect(pairs).toBeVisible();
  expect(problems).toEqual([]);
});
