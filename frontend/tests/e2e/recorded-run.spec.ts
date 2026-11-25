import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";
import { span } from "../../src/live/format";

/** The path through range one that the demo build ships, as its file holds it. */
const rangePath = JSON.parse(readFileSync(join(resolve(process.cwd(), ".."), "bluefire/data/recordings/lab-range-one-path.json"), "utf-8")) as {
  title: string;
  network: { hosts: { name: string }[] };
  score: { steps: number; alerted: number; seen: number; unseen: number; first_alert_seconds: number; goal_seconds: number };
};

// The demo build ships the real recordings made in this repository's CI: 60
// published tests on one Linux host, one of which nothing recorded, and the
// path of eleven steps of ten published tests through range one.

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
  // The example is the one run listed on its own; the pair's two runs are listed with their pair.
  const example = recorded.getByRole("listitem").filter({ hasText: "60 published tests on one Linux host" });
  await expect(example.getByText("Shipped with BlueFire", { exact: true })).toBeVisible();
  await expect(example.getByText("3 of 60 tests alerted, 56 seen, 1 unseen")).toBeVisible();
  await example.getByRole("link", { name: "60 published tests on one Linux host" }).click();
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
  // The address names the test that was clicked. Before the click it named the step on screen, so wait for this one.
  await expect(page).toHaveURL(/mode=analyse&select=43(&|$)/);
  const analysing = page.url();

  // Moving through the run replaced the address; it added nothing to the history.
  expect(await page.evaluate(() => window.history.length)).toBe(opened);

  await page.reload();
  await expect(page.getByRole("button", { name: "Analyse", exact: true })).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByRole("heading", { name: "Clear Bash history (echo)", exact: true })).toBeVisible();
  expect(page.url()).toBe(analysing);

  // Fix this opens the step's own page, and its Back returns to the step's detail.
  await page.getByRole("button", { name: "Fix this", exact: true }).click();
  await expect(page).toHaveURL(/#\/runs\/recorded\/[A-Za-z0-9_-]+\/fix\/43\?/);
  await expect(page.getByRole("heading", { level: 1, name: "Clear Bash history (echo)" })).toBeFocused();
  await page.getByRole("link", { name: "Back to the run" }).click();
  await expect(page).toHaveURL(analysing);
  await expect(page.getByRole("heading", { name: "Clear Bash history (echo)", exact: true })).toBeVisible();
  expect(problems).toEqual([]);
});

test("Fix this while watching opens the step's page, which says what the recording holds, and Back returns to the same moment", async ({ page }) => {
  const problems: string[] = [];
  page.on("pageerror", (error) => problems.push(String(error)));
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("./#/runs");
  const link = page.getByRole("region", { name: "Recorded runs" }).getByRole("link", { name: "60 published tests on one Linux host" });
  const path = await link.getAttribute("href");
  // Test 40 of the shipped recording is the one nothing recorded; its step id is "43".
  await page.goto(`./${path}?step=43&at=0.95&paused=1`);
  const watching = page.url();
  await expect(page.getByText("Overwrites the shell history file with an empty line, using echo.", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Fix this", exact: true }).click();
  await expect(page).toHaveURL(/\/fix\/43\?step=43&at=0\.95&paused=1$/);
  const fixing = page.url();

  // Where to start first, in plain words, on the first screen.
  const start = page.getByRole("region", { name: "Where to start" });
  await expect(start).toContainText("Nothing of this test was recorded besides its launcher's start. Start with a sensor's settings: a rule can only match what a sensor records.");
  await expect(start).toBeInViewport();
  await expect(page.getByRole("textbox")).toHaveCount(0);
  // The shipped example is older than stable step ids: the two shipped comparisons are tied to its test by the published test's id, as other runs of the same list.
  const tried = page.getByRole("region", { name: /^What was already tried/ });
  const watchLine = tried.getByRole("listitem").filter({ hasText: "New auditd settings" });
  const ruleLine = tried.getByRole("listitem").filter({ hasText: "A new rule: Shell History File Truncated In Place" });
  for (const line of [watchLine, ruleLine]) {
    await expect(line).toContainText("Another run of the same list, not this one, with the same published test as the list runs it. Tied by the published test's id cbf506a5");
    await expect(line.getByRole("link", { name: "Open the comparison at this step" })).toHaveAttribute("href", /\/runs\/compared\/[0-9a-f]+\?step=test%3Acbf506a5$/);
  }
  await expect(watchLine).toBeInViewport({ ratio: 1 });
  // What the recording says of the step, in its own words, one quiet line away.
  const basis = page.getByText("nothing of the test was recorded besides its launcher's start", { exact: true });
  await expect(basis).toBeHidden();
  await page.getByText("How we know", { exact: true }).click();
  await expect(basis).toBeVisible();
  // The demo's configuration has no model: the fixed text says so.
  await expect(page.getByRole("complementary", { name: "The model's place" })).toContainText("No model is connected. Nothing was sent.");
  const fixPage = await new AxeBuilder({ page }).include(".fx").analyze();
  expect(fixPage.violations.filter((item) => ["serious", "critical"].includes(item.impact ?? ""))).toEqual([]);

  // The page's address can be shared, and Back returns to the moment it was opened from.
  await page.reload();
  await expect(page.getByRole("heading", { level: 1, name: "Clear Bash history (echo)" })).toBeVisible();
  expect(page.url()).toBe(fixing);
  await page.getByRole("link", { name: "Back to the run" }).click();
  await expect(page).toHaveURL(watching);
  await expect(page.getByText("Overwrites the shell history file with an empty line, using echo.", { exact: true })).toBeVisible();
  expect(problems).toEqual([]);
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
  // The play button stays in the window at the top of the page and as it scrolls down to the caption.
  const play = page.getByRole("button", { name: "Play", exact: true });
  await expect(play).toBeInViewport();
  await fix.scrollIntoViewIfNeeded();
  expect(await inWidth(await fix.boundingBox())).toBe(true);
  await expect(play).toBeInViewport();
  await fix.click();
  // It opens the step's own page, which fits the window's width too.
  await expect(page).toHaveURL(/\/fix\/43\?/);
  await expect(page.getByRole("region", { name: "Where to start" })).toContainText("Nothing of this test was recorded besides its launcher's start.");
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
});

test("the demo lists the path through range one first, as an attack path with its score and its race, and opens it on the range's map", async ({ page }) => {
  const problems: string[] = [];
  page.on("pageerror", (error) => problems.push(String(error)));
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("./#/runs");
  // The title, the score and the race are the shipped file's own.
  const { title, score, network } = rangePath;
  expect(score.first_alert_seconds).toBeLessThan(score.goal_seconds);
  const recorded = page.getByRole("region", { name: "Recorded runs" });
  await expect(recorded.getByRole("listitem").first().getByRole("link")).toHaveText(title);
  const path = recorded.getByRole("listitem").filter({ hasText: title });
  await expect(path.getByText("Attack path", { exact: true })).toBeVisible();
  await expect(path.getByText("Shipped with BlueFire", { exact: true })).toBeVisible();
  await expect(path.getByText(`${score.alerted} of ${score.steps} steps alerted, ${score.seen} seen, ${score.unseen} unseen`, { exact: true })).toBeVisible();
  const race = `The first alert came after ${span(score.first_alert_seconds * 1000)}, ${span((score.goal_seconds - score.first_alert_seconds) * 1000)} before the attacker reached the goal`;
  await expect(path.getByText(race, { exact: true })).toBeVisible();
  await path.getByRole("link", { name: title }).click();
  await expect(page).toHaveURL(/#\/runs\/recorded\/[A-Za-z0-9_-]+/);
  const map = page.getByRole("region", { name: "Network map" });
  for (const host of network.hosts) await expect(map.getByText(host.name, { exact: true }).first()).toBeVisible();
  expect(problems).toEqual([]);
});

test("a recording that is not there is said plainly, with the way back", async ({ page }) => {
  await page.goto("./#/runs/recorded/no-such-recording");
  await expect(page.getByText("This recording could not be loaded")).toBeVisible();
  await expect(page.getByText("Recording was not found.")).toBeVisible();
  await page.getByRole("link", { name: "Runs", exact: true }).first().click();
  await expect(page.getByRole("region", { name: "Recorded runs" })).toBeVisible();
});
