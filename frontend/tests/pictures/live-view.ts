import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";

// Takes the pictures of the live view that the README shows, and keeps the
// single replay page they were taken of, from the recording shipped with the
// app and the real service. CI runs it and keeps the folder as an artifact:
//
//   BLUEFIRE_PICTURES=<new folder> pnpm pictures
//
// The moments are found by the steps' outcomes in the recording, so another
// recording of the same kind gives the same pictures of its own run. The script
// fails if a page prints an error, if the replay page asks for anything beyond
// its own file or the app for anything beyond the service, or if a moment does
// not show what the picture is meant to show.

interface Step {
  id: string;
  order: number;
  role: string;
  title: string;
  outcome: string;
}

interface Shipped {
  id: string;
  title: string;
  source: { run_url?: string };
  steps: Step[];
  alerts: { step: string; detector: string; rule: { title: string }; launcher_only?: boolean }[];
}

const repository = resolve(process.cwd(), "..");
const RECORDING = "bluefire/data/recordings/lab-linux-host.json";
const shipped: Shipped = JSON.parse(readFileSync(join(repository, RECORDING), "utf-8"));
const PAIR = "bluefire/data/recordings/deltas/lab-pair-history-watch.json";
const pairRun: string = (JSON.parse(readFileSync(join(repository, PAIR), "utf-8")) as { after: { run_url?: string } }).after.run_url ?? "not named in the comparison";
const RULE_PAIR = "bluefire/data/recordings/deltas/lab-rule-history-truncated.json";
const rulePairRun: string = (JSON.parse(readFileSync(join(repository, RULE_PAIR), "utf-8")) as { after: { run_url?: string } }).after.run_url ?? "not named in the comparison";
const FILES = [
  "SOURCE.txt",
  "analyse-unseen.png",
  "analyse.png",
  "app-overview.png",
  "app-pair.png",
  "app-recorded-run.png",
  "app-rule-pair.png",
  "app-runs-pair.png",
  "app-runs.png",
  "replay.html",
  "watch-first-alert.png",
  "watch-seen.png",
  "watch-stopped.png",
  "watch-unseen.png",
  "wide-first-alert.png",
];
// Late in a step: its outcome is told and every rule match has reached its engine.
const LATE = 0.95;

/** The steps that pass the test, in the run's order. */
function every(what: string, passes: (step: Step) => boolean): Step[] {
  const found = [...shipped.steps].sort((one, other) => one.order - other.order).filter(passes);
  if (found.length === 0) throw new Error(`The recording has no ${what}.`);
  return found;
}

/** The first step in the run's order that passes the test. */
function first(what: string, passes: (step: Step) => boolean): Step {
  const [found] = every(what, passes);
  if (!found) throw new Error(`The recording has no ${what}.`);
  return found;
}

function matchedBy(step: Step, detector: string): boolean {
  return shipped.alerts.some((alert) => alert.step === step.id && alert.detector === detector && !alert.launcher_only);
}

// A match on the launcher line gets a long line of its own that a picture cuts off, so the pictures choose steps without one.
function launcherLine(step: Step): boolean {
  return shipped.alerts.some((alert) => alert.step === step.id && alert.launcher_only);
}

const firstAlert = first("test that alerted", (step) => step.role === "test" && step.outcome === "alerted");
const unseen = first("unseen test", (step) => step.role === "test" && step.outcome === "unseen");
// Seen with no alert, while a rule written in this repository would have alerted: the gap and its fix in one picture.
// The first of these whose rule titles fit the picture whole.
const seen = every("test seen with no alert", (step) => step.role === "test" && step.outcome === "seen" && matchedBy(step, "pinned") && matchedBy(step, "lab") && !launcherLine(step));
const stopped = first("hardened rerun that was stopped", (step) => step.role === "hardened" && step.outcome === "stopped" && !launcherLine(step));

/** Every error the page prints, and every request it makes beyond what it may reach. */
function watch(page: Page, allowed: (url: string) => boolean) {
  const problems: string[] = [];
  page.on("pageerror", (error) => problems.push(String(error)));
  page.on("console", (message) => {
    if (message.type() === "error") problems.push(message.text());
  });
  page.on("request", (request) => {
    const url = request.url();
    if (!url.startsWith("data:") && !allowed(url)) problems.push(`request: ${url}`);
  });
  return problems;
}

/** Waits for the fonts and for every animation and transition to end, then for two frames. */
async function settle(page: Page): Promise<void> {
  await page.evaluate(() => document.fonts.ready.then(() => true));
  await expect.poll(() => page.evaluate(() => document.getAnimations().filter((item) => item.playState === "running").length), { timeout: 15_000 }).toBe(0);
  await page.evaluate(() => new Promise((done) => requestAnimationFrame(() => requestAnimationFrame(done))));
}

async function picture(page: Page, folder: string, name: string): Promise<void> {
  await settle(page);
  await page.screenshot({ path: join(folder, name) });
}

/**
 * A picture of a view whose lists scroll: it ends just below the lowest table
 * row that is whole, at a line no text crosses, so no row or heading is cut in two.
 */
async function pictureOfLists(page: Page, folder: string, name: string): Promise<void> {
  await settle(page);
  const height = await page.evaluate(() => {
    const MARGIN = 6;
    // The boxes of the lines of text themselves, not of the cells or blocks that hold them.
    const lineBoxes: DOMRect[] = [];
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
      if ((node.textContent ?? "").trim() === "") continue;
      const range = document.createRange();
      range.selectNodeContents(node);
      lineBoxes.push(...range.getClientRects());
    }
    const crossed = (top: number, bottom: number) => lineBoxes.some((box) => box.height > 0 && box.top < bottom && box.bottom > top);
    /** Where a row can be seen: inside the window and every box around it that scrolls. */
    const seenTo = (item: Element) => {
      let limit = window.innerHeight;
      for (let around = item.parentElement; around; around = around.parentElement) {
        if (/(auto|scroll|hidden)/.test(getComputedStyle(around).overflowY)) limit = Math.min(limit, around.getBoundingClientRect().bottom);
      }
      return limit;
    };
    const lines = [...document.querySelectorAll("tr")]
      .map((row) => ({ bottom: row.getBoundingClientRect().bottom, limit: seenTo(row) }))
      .filter((row) => row.bottom <= row.limit && row.bottom + MARGIN <= window.innerHeight)
      .map((row) => row.bottom)
      .sort((one, other) => other - one);
    const line = lines.find((bottom) => !crossed(bottom, bottom + MARGIN));
    return line === undefined ? 0 : Math.ceil(line + MARGIN);
  });
  const viewport = page.viewportSize();
  if (!viewport) throw new Error("The page has no viewport size.");
  if (height < viewport.height * 0.8) throw new Error(`${name}: no line near the bottom ends the lists whole (found ${height} px of ${viewport.height}).`);
  await page.screenshot({ path: join(folder, name), clip: { x: 0, y: 0, width: viewport.width, height } });
}

/**
 * Paused late in the step, its outcome told: the caption names the step, the
 * timeline no longer says it is running and every engine that matched shows a
 * match. Gives the titles of the match lines on screen that are cut short.
 */
async function expectMoment(page: Page, step: Step): Promise<string[]> {
  await expect(page.getByRole("button", { name: "Play", exact: true })).toBeVisible();
  await expect(page.getByRole("region", { name: "The step", exact: true })).toContainText(step.title);
  const where = page.getByRole("slider", { name: /^Timeline/ });
  await expect.poll(async () => (await where.getAttribute("aria-valuetext")) ?? "").toContain(step.title);
  await expect(where).not.toHaveAttribute("aria-valuetext", /, running: /);
  // Every rule engine that matched the step shows a match of its own (each lists a few and counts the rest).
  // A match line in an engine carries its rule's title as its tooltip, which the step's caption does not.
  const matches = shipped.alerts.filter((alert) => alert.step === step.id && !alert.launcher_only);
  await settle(page);
  const cut: string[] = [];
  for (const detector of new Set(matches.map((alert) => alert.detector))) {
    const lines = matches.filter((alert) => alert.detector === detector).map((alert) => page.getByTitle(alert.rule.title, { exact: true }));
    const any = lines.reduce((one, other) => one.or(other));
    await expect(any.first()).toBeVisible();
    for (const line of await any.all()) {
      if (!(await line.isVisible())) continue;
      const short = await line.evaluate((item) => [item, ...item.querySelectorAll("*")].some((part) => part.scrollWidth > part.clientWidth + 1));
      if (short) cut.push((await line.getAttribute("title")) ?? "");
    }
  }
  return cut;
}

/** Each match line on screen holds its rule's whole title. */
async function expectWholeMoment(page: Page, step: Step): Promise<void> {
  expect(await expectMoment(page, step), "match lines cut short").toEqual([]);
}

test("pictures of the live view, in the replay page and in the app", async ({ page }) => {
  const folder = process.env.BLUEFIRE_PICTURES ?? "";
  if (!folder) throw new Error("Set BLUEFIRE_PICTURES to the folder the pictures go to.");
  mkdirSync(folder, { recursive: true });
  expect(readdirSync(folder), `${folder} must be empty: it is kept as it is`).toEqual([]);

  // The page, as the command line makes it.
  const workspace = mkdtempSync(join(tmpdir(), "bluefire-pictures-"));
  const replay = join(folder, "replay.html");
  try {
    const made = spawnSync(process.env.BLUEFIRE_PYTHON ?? "python3", ["-m", "bluefire.cli", "--runs-dir", workspace, "recordings", "page", shipped.id, "--out", replay], { cwd: repository, encoding: "utf-8" });
    if (made.status !== 0) throw new Error(`bluefire recordings page exited with ${made.status}:\n${made.stdout}\n${made.stderr}`);
  } finally {
    rmSync(workspace, { recursive: true, force: true });
  }

  // The page may reach its own file only; the app, later, the service that serves it.
  const own = pathToFileURL(replay).href;
  const address = process.env.BLUEFIRE_SERVICE_URL ?? "";
  const service = `${new URL(address).origin}/`;
  let reachable = own;
  const problems = watch(page, (url) => url.startsWith(reachable));
  const open = async (query: string) => {
    await page.goto(`${own}?${query}`);
    await expect(page.getByRole("heading", { level: 1, name: shipped.title })).toBeVisible();
  };

  await page.setViewportSize({ width: 1440, height: 900 });
  const watched: [string, Step[]][] = [
    ["watch-first-alert.png", [firstAlert]],
    ["watch-unseen.png", [unseen]],
    ["watch-seen.png", seen],
    ["watch-stopped.png", [stopped]],
  ];
  for (const [name, steps] of watched) {
    const tried: string[] = [];
    for (const step of steps) {
      await open(`step=${step.id}&at=${LATE}&paused=1`);
      const cut = await expectMoment(page, step);
      if (cut.length === 0) {
        await picture(page, folder, name);
        break;
      }
      tried.push(`${step.title}: ${cut.join(", ")}`);
    }
    if (tried.length === steps.length) throw new Error(`${name}: every step cuts a rule title short.\n${tried.join("\n")}`);
  }

  await open("mode=analyse");
  await expect(page.getByRole("button", { name: "Analyse", exact: true })).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByRole("table")).toBeVisible();
  await pictureOfLists(page, folder, "analyse.png");

  await open(`mode=analyse&select=${unseen.id}`);
  await expect(page.getByRole("article").getByRole("heading", { name: unseen.title, exact: true })).toBeVisible();
  await pictureOfLists(page, folder, "analyse-unseen.png");

  await page.setViewportSize({ width: 1920, height: 1080 });
  await open(`step=${firstAlert.id}&at=${LATE}&paused=1`);
  await expectWholeMoment(page, firstAlert);
  await picture(page, folder, "wide-first-alert.png");

  // Inside the app: the Overview, which leads with the real run and the turns of the loop.
  await page.setViewportSize({ width: 1440, height: 900 });
  reachable = service;
  await page.goto(address);
  await expect(page.getByText("Connected", { exact: true })).toBeVisible();
  await expect(page.getByRole("region", { name: "Watch a real run" }).getByRole("list", { name: "The changes to the defense, in order" }).getByRole("link")).toHaveCount(2);
  await picture(page, folder, "app-overview.png");

  // The Runs screen with the recorded run, and the run's page on its first alert.
  await page.getByRole("link", { name: "Runs", exact: true }).first().click();
  const recorded = page.getByRole("region", { name: "Recorded runs" });
  const link = recorded.getByRole("link", { name: shipped.title, exact: true });
  await expect(link).toBeVisible();
  await picture(page, folder, "app-runs.png");

  // The pair of runs shipped with the app: its part of the Runs screen alone, and its own page.
  const pairs = page.getByRole("region", { name: "Before against after" });
  const pair = pairs.getByRole("link", { name: "One test that nobody saw is now seen.", exact: true });
  await pairs.scrollIntoViewIfNeeded();
  await expect(pair).toBeVisible();
  await settle(page);
  await pairs.screenshot({ path: join(folder, "app-runs-pair.png") });
  await pair.click();
  await expect(page).toHaveURL(/#\/runs\/compared\/[0-9a-f]{16}$/);
  await expect(page.getByRole("heading", { level: 1, name: "One test that nobody saw is now seen." })).toBeVisible();
  // The stages are drawn from both recordings before the picture is taken.
  await expect(page.getByRole("group", { name: "Clear Bash history (echo), before and after" }).getByRole("article")).toHaveCount(2);
  await picture(page, folder, "app-pair.png");
  await page.getByRole("link", { name: "Runs", exact: true }).first().click();
  await expect(link).toBeVisible();

  // The run evaluated with two rule sets, the rule drafted from what the watch saw: its own page, with its stages drawn.
  await pairs.getByRole("link", { name: "Four steps that were seen with no alert now raise an alert.", exact: true }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Four steps that were seen with no alert now raise an alert." })).toBeVisible();
  await expect(page.getByRole("group", { name: "Clear Bash history (echo), before and after" }).getByRole("article")).toHaveCount(2);
  await expect(page.getByLabel("The text of the rule Shell History File Truncated In Place")).toBeAttached();
  await picture(page, folder, "app-rule-pair.png");
  await page.getByRole("link", { name: "Runs", exact: true }).first().click();
  await expect(link).toBeVisible();

  const path = await link.getAttribute("href");
  if (!path?.startsWith("#/")) throw new Error(`The recorded run's link is ${path}.`);
  // Inside the app the live view shares the width with the app's own rail: the wide size keeps every rule title whole.
  await page.setViewportSize({ width: 1920, height: 1080 });
  await page.evaluate((hash) => {
    window.location.hash = hash;
  }, `${path.slice(1)}?step=${firstAlert.id}&at=${LATE}&paused=1`);
  await expectWholeMoment(page, firstAlert);
  await picture(page, folder, "app-recorded-run.png");

  writeFileSync(
    join(folder, "SOURCE.txt"),
    [
      "Pictures of the live view and its single replay page, made from the recording shipped with BlueFire,",
      "and of the Overview, the Runs screen and the pages of the pair of runs and the run evaluated twice shipped with it.",
      `Recording: ${shipped.id} (${RECORDING})`,
      `Recorded in the CI run: ${shipped.source.run_url ?? "not named in the recording"}`,
      `Pair: ${PAIR} (made in the CI run ${pairRun})`,
      `Run evaluated twice: ${RULE_PAIR} (made in the CI run ${rulePairRun})`,
      `Made from the commit: ${process.env.GITHUB_SHA ?? "not known: made outside CI"}`,
      "",
    ].join("\n"),
  );

  expect(problems).toEqual([]);
  expect(readdirSync(folder).sort()).toEqual(FILES);
});
