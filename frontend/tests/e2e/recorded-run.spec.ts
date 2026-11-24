import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

// The demo build ships the one real recording made in this repository's CI:
// 60 published tests on one Linux host, one of which nothing recorded.

/** Where the timeline stands, without its clock: "Test 11, seen: List OS Information, 13 of 91". */
async function moment(page: Page): Promise<string> {
  const text = await page.getByRole("slider", { name: /^Timeline/ }).getAttribute("aria-valuetext");
  return (text ?? "").split(", ").slice(0, -1).join(", ");
}

/** Where the timeline stands, clock included. */
async function position(page: Page): Promise<string> {
  return (await page.getByRole("slider", { name: /^Timeline/ }).getAttribute("aria-valuetext")) ?? "";
}

test("a recorded run opens from Runs, plays in the live view and keeps its moment in the address", async ({ page }) => {
  const problems: string[] = [];
  page.on("pageerror", (error) => problems.push(String(error)));
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("./#/runs");

  const recorded = page.getByRole("region", { name: "Recorded runs" });
  await expect(recorded.getByText("Shipped with BlueFire", { exact: true })).toBeVisible();
  await expect(recorded.getByText("3 of 60 tests alerted, 56 seen, 1 unseen")).toBeVisible();
  await recorded.getByRole("link", { name: "60 published tests on one Linux host" }).click();
  await expect(page).toHaveURL(/#\/runs\/recorded\/[A-Za-z0-9_-]+/);
  const opened = await page.evaluate(() => window.history.length);

  // The first step, told in plain words.
  await expect(page.getByText("Deletes the shell history file with rm.", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Pause", exact: true }).click();
  await expect(page.getByRole("button", { name: "Play", exact: true })).toBeVisible();
  await expect(page).toHaveURL(/paused=1/);
  const paused = page.url();

  // Ten steps on along the scrubber; the address follows.
  const before = await moment(page);
  const scrubber = page.getByRole("slider", { name: /^Timeline/ });
  await scrubber.focus();
  await page.keyboard.press("PageUp");
  const after = await moment(page);
  expect(after).not.toBe(before);
  await expect.poll(() => page.url()).not.toBe(paused);
  // The scrubber's keys go to a step's start: the address says so, at=0.
  await expect(page).toHaveURL(/step=[^&]+&at=0&paused=1$/);
  const watching = page.url();
  const exact = await position(page);

  // A reload at that address is at the same moment, clock included, paused, and leaves the address as it was.
  await page.reload();
  await expect(page.getByRole("button", { name: "Play", exact: true })).toBeVisible();
  expect(await position(page)).toBe(exact);
  await page.waitForTimeout(600);
  expect(page.url()).toBe(watching);

  // Analyse, the one test nothing recorded, and where to start fixing it.
  await page.getByRole("button", { name: "Analyse", exact: true }).click();
  await expect(page.getByRole("button", { name: "Analyse", exact: true })).toHaveAttribute("aria-pressed", "true");
  await page.getByRole("button", { name: "Clear Bash history (echo)", exact: true }).click();
  const detail = page.getByRole("heading", { name: "Clear Bash history (echo)", exact: true });
  await expect(detail).toBeVisible();
  // The hint says where the gap is: nothing recorded it, so a sensor comes first.
  await expect(page.getByText(/^Start with a sensor/).first()).toBeVisible();
  await page.getByRole("button", { name: "Fix this", exact: true }).click();
  await expect(page.getByRole("status").filter({ hasText: "the hint in the step's detail says where the gap is" })).toBeVisible();
  await expect(page).toHaveURL(/mode=analyse&select=/);
  const analysing = page.url();

  // Moving through the run replaced the address; it added nothing to the history.
  expect(await page.evaluate(() => window.history.length)).toBe(opened);

  await page.reload();
  await expect(page.getByRole("button", { name: "Analyse", exact: true })).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByRole("heading", { name: "Clear Bash history (echo)", exact: true })).toBeVisible();
  expect(page.url()).toBe(analysing);
  expect(problems).toEqual([]);
});

test("Fix this while watching opens the step's detail in analyse mode, and leads nowhere else", async ({ page }) => {
  await page.goto("./#/runs");
  const link = page.getByRole("region", { name: "Recorded runs" }).getByRole("link", { name: "60 published tests on one Linux host" });
  const path = await link.getAttribute("href");
  // Test 40 of the shipped recording is the one nothing recorded; its step id is "43".
  await page.goto(`./${path}?step=43&at=0.95&paused=1`);
  await expect(page.getByText("Overwrites the shell history file with an empty line, using echo.", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Fix this", exact: true }).click();
  await expect(page.getByRole("button", { name: "Analyse", exact: true })).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByRole("heading", { name: "Clear Bash history (echo)", exact: true })).toBeVisible();
  await expect(page.getByRole("status").filter({ hasText: "BlueFire cannot make the change for you yet." })).toBeVisible();
  await expect(page).toHaveURL(/mode=analyse&select=43$/);

  // A link to another moment opens there, and the note about the step being fixed goes.
  await page.goto(`./${path}?step=42&at=0.6&paused=1`);
  await expect(page.getByRole("button", { name: "Analyse", exact: true })).toHaveAttribute("aria-pressed", "false");
  await expect(page.getByText("BlueFire cannot make the change for you yet.")).toHaveCount(0);
});

test("the recorded runs open from the keyboard, and the Runs screen and the recorded run page have no serious axe violations", async ({ page }) => {
  await page.goto("./#/runs");
  const recorded = page.getByRole("region", { name: "Recorded runs" });
  await expect(recorded.getByRole("link", { name: "60 published tests on one Linux host" })).toBeVisible();
  const runs = await new AxeBuilder({ page }).include(".recorded-runs").analyze();
  expect(runs.violations.filter((item) => ["serious", "critical"].includes(item.impact ?? ""))).toEqual([]);

  await recorded.getByRole("link", { name: "60 published tests on one Linux host" }).focus();
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/#\/runs\/recorded\//);
  await expect(page.getByRole("link", { name: "Runs", exact: true }).last()).toBeVisible();
  const bar = await new AxeBuilder({ page }).include(".recorded-run-bar").analyze();
  expect(bar.violations.filter((item) => ["serious", "critical"].includes(item.impact ?? ""))).toEqual([]);
  // One main landmark: the live view sits inside the app's own.
  await expect(page.getByRole("main")).toHaveCount(1);
  const landmarks = await new AxeBuilder({ page }).withRules(["landmark-no-duplicate-main", "landmark-main-is-top-level"]).analyze();
  expect(landmarks.violations).toEqual([]);
});

test("at phone width the recorded run's page stacks the live view's bands and scrolls down, as the single replay page does", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("./#/runs");
  const path = await page.getByRole("region", { name: "Recorded runs" }).getByRole("link", { name: "60 published tests on one Linux host" }).getAttribute("href");
  await page.goto(`./${path}?step=43&at=0.95&paused=1`);
  await expect(page.getByRole("button", { name: "Play", exact: true })).toBeVisible();

  // Nothing to scroll sideways for: the modes, the score and the step's words sit inside the window's width.
  const inWidth = async (box: { x: number; width: number } | null) => box !== null && box.x >= 0 && box.x + box.width <= 390;
  expect(await inWidth(await page.getByRole("button", { name: "Analyse", exact: true }).boundingBox())).toBe(true);
  expect(await inWidth(await page.getByLabel("The score so far", { exact: true }).boundingBox())).toBe(true);
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
  // The step's caption and its Fix this are further down the page, in the window's width.
  const fix = page.getByRole("region", { name: "The step", exact: true }).getByRole("button", { name: "Fix this" });
  await fix.scrollIntoViewIfNeeded();
  expect(await inWidth(await fix.boundingBox())).toBe(true);
  await fix.click();
  await expect(page.getByRole("button", { name: "Analyse", exact: true })).toHaveAttribute("aria-pressed", "true");
});

test("a recording that is not there is said plainly, with the way back", async ({ page }) => {
  await page.goto("./#/runs/recorded/no-such-recording");
  await expect(page.getByText("This recording could not be loaded")).toBeVisible();
  await expect(page.getByText("Recording was not found.")).toBeVisible();
  await page.getByRole("link", { name: "Runs", exact: true }).first().click();
  await expect(page.getByRole("region", { name: "Recorded runs" })).toBeVisible();
});
