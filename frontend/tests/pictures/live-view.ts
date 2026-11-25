import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";
import { loopFrames, takeFrames, writeLoop } from "./loop";
import type { LoopPlan } from "./loop";

// Takes the pictures of the live view that the README shows, and the loop of it
// playing (see loop.ts), and keeps the
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
  command?: string;
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
  "live-view-loop.gif",
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
const afterFirstAlert = first("step after the first alert on a test", (step) => step.order > firstAlert.order);
// The README's caption under the loop says that the test after the first alert is one no sensor recorded.
if (afterFirstAlert.role !== "test" || afterFirstAlert.outcome !== "unseen") {
  throw new Error(
    `The step after the first alert, "${afterFirstAlert.title}", is a ${afterFirstAlert.role} with the outcome ${afterFirstAlert.outcome}, not an unseen test. ` +
      'The caption under the loop in README.md ("a published rule raises its first alert, then the next test does its work and neither sensor records it") ' +
      "would be untrue of this recording: change the caption, or the loop's plan, with the recording.",
  );
}
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

/**
 * Waits for the fonts and for every animation and transition to end, then for
 * the page to stand still: no animation runs, and nothing on it moves over two
 * frames. An entrance animation that starts after a first look found none, as a
 * page that has just loaded can start one, is waited for too, so the same page
 * gives the same picture on every run.
 */
async function settle(page: Page): Promise<void> {
  await page.evaluate(() => document.fonts.ready.then(() => true));
  await expect
    .poll(
      () =>
        page.evaluate(async () => {
          const frame = () => new Promise((done) => requestAnimationFrame(() => done(null)));
          const places = () => JSON.stringify([...document.querySelectorAll("body *")].slice(0, 4000).map((item) => {
            const box = item.getBoundingClientRect();
            return [box.x, box.y, box.width, box.height];
          }));
          const running = () => document.getAnimations().some((item) => item.playState === "running");
          const before = places();
          await frame();
          await frame();
          return !running() && places() === before;
        }),
      { timeout: 15_000 },
    )
    .toBe(true);
  await page.evaluate(() => new Promise((done) => requestAnimationFrame(() => requestAnimationFrame(done))));
}

async function picture(page: Page, folder: string, name: string): Promise<void> {
  await settle(page);
  await page.screenshot({ path: join(folder, name) });
}

/**
 * In analyse mode, every step's title in the table takes two lines at the most (three in a window narrower than 1440
 * px), and the first row in view stands whole under the table's head: no row shows cut under it. With a row chosen,
 * that row is whole in the table's box, above the fade at its foot.
 */
async function expectWholeRows(page: Page, name: string, chosen?: string): Promise<{ scrolled: number }> {
  await settle(page);
  const found = await page.evaluate((selected) => {
    const titles = [...document.querySelectorAll<HTMLElement>(".lv-table .lv-row-button")].filter((title) => title.getBoundingClientRect().height > 0);
    // Two lines at the most in a window 1440 px wide or wider, three in a narrower one.
    const most = window.innerWidth >= 1440 ? 2 : 3;
    const tall = titles.filter((title) => title.getBoundingClientRect().height / parseFloat(getComputedStyle(title).lineHeight) > most + 0.5).map((title) => title.textContent ?? "");
    // The head's cells stick to the top of the box as the rows scroll; the head itself scrolls away with them.
    const head = document.querySelector(".lv-table thead th")?.getBoundingClientRect().bottom ?? 0;
    const rows = [...document.querySelectorAll<HTMLElement>(".lv-table tbody tr")];
    const cut = rows
      .filter((row) => {
        const box = row.getBoundingClientRect();
        return box.top < head - 0.5 && box.bottom > head + 0.5;
      })
      .map((row) => row.querySelector(".lv-row-button")?.textContent ?? "");
    const wrap = document.querySelector<HTMLElement>(".lv-table-wrap");
    const row = rows.find((item) => item.dataset.step === selected);
    let whole = true;
    if (selected !== null) {
      if (!wrap || !row) return { tall, cut, titles: titles.length, whole: false, scrolled: 0 };
      const box = row.getBoundingClientRect();
      const foot = wrap.getBoundingClientRect().top + wrap.clientTop + wrap.clientHeight - parseFloat(getComputedStyle(wrap).paddingBottom);
      whole = box.top >= head - 0.5 && box.bottom <= foot + 0.5;
    }
    return { tall, cut, titles: titles.length, whole, scrolled: wrap?.scrollTop ?? 0 };
  }, chosen ?? null);
  expect(found.titles, `${name}: the table shows no title`).toBeGreaterThan(0);
  expect(found.tall, `${name}: titles over two lines, or three in a narrower window`).toEqual([]);
  expect(found.cut, `${name}: rows cut under the table's head`).toEqual([]);
  expect(found.whole, `${name}: the chosen row is not whole in the table's box`).toBe(true);
  return { scrolled: found.scrolled };
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

/** Each match line on screen holds its rule's whole title, and a title that wraps does not reach the next engine's label. */
async function expectWholeMoment(page: Page, step: Step): Promise<void> {
  expect(await expectMoment(page, step), "match lines cut short").toEqual([]);
  const overlaps = await page.evaluate(() => {
    const labels = [...document.querySelectorAll(".lv-engine-label")].map((label) => ({ top: label.getBoundingClientRect().top, bottom: label.querySelector(".lv-matches")?.getBoundingClientRect().bottom ?? label.getBoundingClientRect().bottom })).sort((one, other) => one.top - other.top);
    return labels.slice(1).map((label, index) => (labels[index]?.bottom ?? 0) - label.top).filter((overlap) => overlap > 0);
  });
  expect(overlaps, "an engine's matches reach the next engine's label by these many pixels").toEqual([]);
}

/**
 * The host's label under the node, with the step's command on two lines, ends
 * above the bottom of the map: the band below it does not cut its last line.
 */
async function expectWholeHostLabel(page: Page, step: Step): Promise<void> {
  await expect(page.getByRole("region", { name: "The step", exact: true })).toContainText(step.title);
  await settle(page);
  const found = await page.evaluate(() => {
    const command = document.querySelector(".lv-host-command");
    const role = document.querySelector(".lv-host-role");
    const stage = document.querySelector(".lv-stage");
    if (!command || !role || !stage) return { lines: 0, below: Number.NaN };
    const lines = Math.round(command.getBoundingClientRect().height / parseFloat(getComputedStyle(command).lineHeight));
    return { lines, below: role.getBoundingClientRect().bottom - stage.getBoundingClientRect().bottom };
  });
  expect(found.lines, `the command of ${step.title} takes two lines`).toBe(2);
  expect(found.below, "the host's label ends this far below the map").toBeLessThanOrEqual(0);
}

/** The race line above the map holds its whole sentence: nothing of it is cut short. */
async function expectWholeRaceLine(page: Page, name: string): Promise<void> {
  const cut = await page.evaluate(() => {
    const line = document.querySelector(".lv-winning");
    return line ? line.scrollWidth - line.clientWidth : 0;
  });
  expect(cut, `${name}: the race line is cut short by these many pixels`).toBeLessThanOrEqual(1);
}

/** The lanes' time axis has labels across the run: its last one lies past the middle of the axis. */
async function expectLabelledAxis(page: Page): Promise<void> {
  const where = await page.evaluate(() => {
    const svg = document.querySelector(".lv-ln-svg");
    const labels = [...document.querySelectorAll(".lv-ln-tick text")];
    const last = labels[labels.length - 1];
    if (!svg || !last) return Number.NaN;
    const box = svg.getBoundingClientRect();
    return (last.getBoundingClientRect().left - box.left) / box.width;
  });
  expect(where, "the last label of the lanes' time axis lies this far along it").toBeGreaterThan(0.5);
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
        await expectWholeRaceLine(page, name);
        await picture(page, folder, name);
        break;
      }
      tried.push(`${step.title}: ${cut.join(", ")}`);
    }
    if (tried.length === steps.length) throw new Error(`${name}: every step cuts a rule title short.\n${tried.join("\n")}`);
  }

  // Rows far down the table, and its last, chosen: the table scrolls to the row and stands at a row's edge under its
  // head, the chosen row whole, and again each time the window changes size and the rows wrap anew. The pictures
  // below choose rows near the table's top, where it does not scroll.
  await open("mode=analyse");
  await expect(page.getByRole("table")).toBeVisible();
  const order = await page.locator(".lv-table tbody tr[data-step]").evaluateAll((rows) => rows.map((row) => (row instanceof HTMLElement ? (row.dataset.step ?? "") : "")));
  for (const place of [Math.floor(order.length / 4), Math.floor(order.length / 2), Math.floor(order.length * 0.8), order.length - 1]) {
    const far = order[place];
    if (!far) throw new Error(`The table has ${order.length} rows.`);
    await open(`mode=analyse&select=${far}`);
    await expect(page.locator(`.lv-table tr[data-step="${far}"]`)).toHaveClass(/is-selected/);
    const name = `analyse, row ${place + 1} of ${order.length} chosen`;
    const { scrolled } = await expectWholeRows(page, `${name}, 1440 by 900`, far);
    expect(scrolled, `${name}: the table did not scroll`).toBeGreaterThan(0);
    for (const [width, height] of [[1280, 720], [1920, 1080], [1440, 900]] as const) {
      await page.setViewportSize({ width, height });
      await expectWholeRows(page, `${name}, the window made ${width} by ${height}`, far);
    }
  }

  await open("mode=analyse");
  await expect(page.getByRole("button", { name: "Analyse", exact: true })).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByRole("table")).toBeVisible();
  await expectLabelledAxis(page);
  await expectWholeRows(page, "analyse.png");
  await picture(page, folder, "analyse.png");

  await open(`mode=analyse&select=${unseen.id}`);
  await expect(page.getByRole("article").getByRole("heading", { name: unseen.title, exact: true })).toBeVisible();
  await expectWholeRows(page, "analyse-unseen.png");
  await picture(page, folder, "analyse-unseen.png");

  await page.setViewportSize({ width: 1920, height: 1080 });
  await open(`step=${firstAlert.id}&at=${LATE}&paused=1`);
  await expectWholeMoment(page, firstAlert);
  await picture(page, folder, "wide-first-alert.png");

  // Inside the app: the Overview, which leads with the real run and the turns of the loop.
  await page.setViewportSize({ width: 1440, height: 900 });
  reachable = service;
  await page.goto(address);
  await expect(page.getByText("Connected", { exact: true })).toBeVisible();
  await expect(page.getByRole("region", { name: "A run recorded in CI" }).getByRole("list", { name: "The changes to the defense, in order" }).getByRole("link")).toHaveCount(2);
  await picture(page, folder, "app-overview.png");

  // The Runs screen with the recorded run, and the run's page on its first alert.
  await page.getByRole("link", { name: "Runs", exact: true }).first().click();
  const recorded = page.getByRole("region", { name: "Recorded runs" });
  const link = recorded.getByRole("link", { name: shipped.title, exact: true });
  await expect(link).toBeVisible();
  await picture(page, folder, "app-runs.png");

  // The pair of runs shipped with the app: its part of the Runs screen alone, and its own page.
  const pairs = page.getByRole("region", { name: "Before against after" });
  const pair = pairs.getByRole("link", { name: "Clear Bash history (echo) went from unseen to seen.", exact: true });
  await pairs.scrollIntoViewIfNeeded();
  await expect(pair).toBeVisible();
  await settle(page);
  await pairs.screenshot({ path: join(folder, "app-runs-pair.png") });
  await pair.click();
  await expect(page).toHaveURL(/#\/runs\/compared\/[0-9a-f]{16}$/);
  await expect(page.getByRole("heading", { level: 1, name: "Clear Bash history (echo) went from unseen to seen." })).toBeVisible();
  // The stages are drawn from both recordings before the picture is taken.
  await expect(page.getByRole("group", { name: "Clear Bash history (echo), before and after" }).getByRole("article")).toHaveCount(2);
  await picture(page, folder, "app-pair.png");
  await page.getByRole("link", { name: "Runs", exact: true }).first().click();
  await expect(link).toBeVisible();

  // The run evaluated with two rule sets, the rule drafted from what the watch saw: its own page, with its stages drawn.
  await pairs.getByRole("link", { name: "4 steps went from seen to alerted.", exact: true }).click();
  await expect(page.getByRole("heading", { level: 1, name: "4 steps went from seen to alerted." })).toBeVisible();
  await expect(page.getByRole("group", { name: "Clear Bash history (echo), before and after" }).getByRole("article")).toHaveCount(2);
  await expect(page.getByLabel("The text of the rule Shell History File Truncated In Place")).toBeAttached();
  await picture(page, folder, "app-rule-pair.png");
  await page.getByRole("link", { name: "Runs", exact: true }).first().click();
  await expect(link).toBeVisible();

  const path = await link.getAttribute("href");
  if (!path?.startsWith("#/")) throw new Error(`The recorded run's link is ${path}.`);
  const moment = (step: Step) =>
    page.evaluate((hash) => {
      window.location.hash = hash;
    }, `${path.slice(1)}?step=${step.id}&at=${LATE}&paused=1`);
  // At 1440 by 900 too, where the live view shares the width with the app's own rail: every rule title
  // of the first alert is whole, wrapped where it is long, and the host's label is not cut by the band
  // below the map when the step's command takes two lines, as the longest command of a test does.
  await moment(firstAlert);
  await expectWholeMoment(page, firstAlert);
  const [longest] = every("test with a command", (step) => step.role === "test" && (step.command ?? "") !== "").sort((one, other) => (other.command ?? "").length - (one.command ?? "").length);
  if (!longest) throw new Error("The recording has no test with a command.");
  await moment(longest);
  await expectWholeHostLabel(page, longest);

  await page.setViewportSize({ width: 1920, height: 1080 });
  await moment(firstAlert);
  await expectWholeMoment(page, firstAlert);
  await picture(page, folder, "app-recorded-run.png");

  // The loop for the top of the README, back in the replay page. It comes last because its frames
  // take minutes, and the app above has to be opened while the address the service printed is
  // still good. Its first frame, which a still or a link preview shows, is the moment of
  // watch-first-alert.png, held a second. It goes on to the step after it, held there, then plays
  // the alerted test from the moment it begins up to that first frame again, so it closes with no
  // seam. Six tenths of the view's speed, so the lights can be followed.
  // Leave the app first, so that nothing of it is still asking the service when only the page's own file may be reached.
  await page.goto("about:blank");
  await page.setViewportSize({ width: 1440, height: 900 });
  reachable = own;
  const alertMoment = { step: firstAlert.id, at: LATE };
  const loop: LoopPlan = {
    stretches: [
      { from: alertMoment, to: { step: afterFirstAlert.id, at: 1 }, holdFirst: 1000, holdLast: 2000 },
      { from: { step: firstAlert.id, at: 0 }, to: alertMoment },
    ],
    fps: 10,
    pace: 0.6,
  };
  const frames = loopFrames(shipped, loop);
  const pictures = await takeFrames(page, open, frames);
  // The last frame is the alerted test just before the loop's first frame.
  await expect(page.getByRole("region", { name: "The step", exact: true })).toContainText(firstAlert.title);
  await writeLoop(pictures, frames, 1000, join(folder, "live-view-loop.gif"));

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
