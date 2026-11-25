import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

// The demo build holds the two comparisons that ship with the app, the same
// files the service ships: two runs side by side in one CI run, before and after
// an audit watch on the test account's shell history files, and one run
// evaluated with and without the rule drafted from what that watch saw. Their
// recordings are loaded when they are asked for.

const SENSOR = "Clear Bash history (echo) went from unseen to seen.";
const RULE = "4 steps went from seen to alerted.";

test("the first turn opens from Runs and answers on its first screen: what moved, its price, what else moved, and the fair line", async ({ page }) => {
  const problems: string[] = [];
  page.on("pageerror", (error) => problems.push(String(error)));
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("./#/runs");

  const pairs = page.getByRole("region", { name: "Before against after" });
  // In the order the loop went: the watch, then the rule.
  await expect(pairs.getByRole("listitem").getByRole("heading", { level: 4 })).toHaveText([SENSOR, RULE]);
  const turn = pairs.getByRole("listitem").filter({ hasText: SENSOR });
  await expect(turn.getByText("Shipped with BlueFire")).toBeVisible();
  await expect(turn.getByText("90 of 91 steps the same")).toBeVisible();
  await expect(turn.getByText("2 published rules alert on ordinary activity, before and after", { exact: true })).toBeVisible();
  const list = await new AxeBuilder({ page }).include(".recorded-pairs").analyze();
  expect(list.violations.filter((item) => ["serious", "critical"].includes(item.impact ?? ""))).toEqual([]);

  await turn.getByRole("link", { name: SENSOR }).click();
  await expect(page).toHaveURL(/#\/runs\/compared\/[0-9a-f]{16}$/);
  await expect(page.getByRole("heading", { level: 1, name: SENSOR })).toBeInViewport();
  const stages = page.getByRole("group", { name: "Clear Bash history (echo), before and after" });
  await expect(stages.getByRole("article", { name: /^After auditd's new settings/ })).toContainText("auditd recorded 1 event.");
  // The first screen holds the answer, its price, what else moved, what comes next and the fair line.
  for (const name of ["What it cost", "What else moved", "What comes next"]) await expect(page.getByRole("region", { name })).toBeInViewport();
  await expect(page.getByText("One pair of runs, made side by side in one CI run, 24 Nov 2026.", { exact: true })).toBeInViewport();
  await expect(page.getByText("Only the settings of sensor auditd differed.", { exact: true })).toBeInViewport();
  await expect(page.getByRole("region", { name: "What else moved" })).toContainText("1 of 91 steps moved. 90 are the same.");
  // One main landmark: the page sits inside the app's own.
  await expect(page.getByRole("main")).toHaveCount(1);

  // How we know opens in place, with the control in it.
  await page.getByText("How we know").click();
  await expect(page.getByText("What happened, which this change cannot move: the same on 91 of 91 paired steps.")).toBeVisible();
  const pagePart = await new AxeBuilder({ page }).include(".compared").analyze();
  expect(pagePart.violations.filter((item) => ["serious", "critical"].includes(item.impact ?? ""))).toEqual([]);

  // The step's whole detail is a place of its own, drawn from both shipped recordings.
  await stages.getByRole("button", { name: "Every detail of this step, from both runs" }).click();
  await expect(page).toHaveURL(/\?step=.*detail=1/);
  const detail = page.getByRole("region", { name: "Clear Bash history (echo), every detail before and after" });
  await expect(detail.getByRole("heading", { name: "Clear Bash history (echo), every detail before and after" })).toBeFocused();
  await expect(detail.getByRole("article")).toHaveCount(2);
  await expect(detail.getByRole("article").first()).toContainText("It took effect, and nothing of the test was recorded besides its launcher's start.");
  await page.goBack();
  await expect(detail).toHaveCount(0);
  await page.goBack();
  await expect(page).toHaveURL(/#\/runs$/);
  await expect(pairs).toBeVisible();
  expect(problems).toEqual([]);
});

test("the second turn reads as one run evaluated twice: a row puts its step on the stages, and the rule's text is there", async ({ page }) => {
  const problems: string[] = [];
  page.on("pageerror", (error) => problems.push(String(error)));
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("./#/runs");

  const pairs = page.getByRole("region", { name: "Before against after" });
  const turn = pairs.getByRole("listitem").filter({ hasText: RULE });
  await expect(turn.getByText("One run evaluated with two rule sets, 24 Nov 2026")).toBeVisible();
  await expect(turn.getByText(/^Not counted: /)).toBeVisible();
  await turn.getByRole("link", { name: RULE }).click();

  await expect(page.getByRole("heading", { level: 1, name: RULE })).toBeVisible();
  await expect(page.getByText("One run, its telemetry read with two rule sets, 24 Nov 2026.", { exact: true })).toBeInViewport();
  for (const name of ["What it cost", "What else moved", "What comes next"]) await expect(page.getByRole("region", { name })).toBeInViewport();
  await expect(page.getByText("Only the lab's rules differed.", { exact: true })).toBeInViewport();
  const move = page.getByRole("region", { name: "What the change did" });
  // Four rows, one of them on the stages.
  await expect(move.getByRole("button", { name: /^Clear Bash history/ })).toHaveCount(4);
  await expect(move.getByRole("button", { pressed: true })).toHaveCount(1);
  await move.getByRole("button", { name: /^Clear Bash history \(cat dev\/null\)\s*with other arguments/ }).click();
  await expect(page).toHaveURL(/\?step=variant/);
  await expect(page.getByRole("group", { name: "Clear Bash history (cat dev/null), before and after" }).getByRole("article", { name: /^After/ })).toContainText("The new rule alerted, which the score does not count");
  await expect(page.getByLabel("The text of the rule Shell History File Truncated In Place")).toContainText("title: Shell History File Truncated In Place");
  await expect(page.getByRole("region", { name: "What made the difference" }).getByText("/home/bluefire-lab/.sh_history")).toBeVisible();
  const pagePart = await new AxeBuilder({ page }).include(".compared").analyze();
  expect(pagePart.violations.filter((item) => ["serious", "critical"].includes(item.impact ?? ""))).toEqual([]);
  expect(problems).toEqual([]);
});
