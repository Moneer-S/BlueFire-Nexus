import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { expect, test } from "@playwright/test";
import type { Locator, Page } from "@playwright/test";
import { loopFrames, placeAfterFirstAlert, takeFrames, writeLoop } from "./loop";
import type { LoopPlan, Place } from "./loop";

// Takes the pictures that the README and the documents show, from the two
// recordings shipped with the app and the real service, and keeps the single
// replay page of each recording they were taken of. CI runs it and keeps the
// folder as an artifact:
//
//   BLUEFIRE_PICTURES=<new folder> pnpm pictures
//
// The run on one Linux machine gives the pictures of the live view on one host
// and its page, replay.html; the attack path through a network gives the loop
// at the top of the README (see loop.ts), the pictures of the path and its
// page, attack-path.html; the app gives its own screens.
//
// The moments are found by what the steps are in the recording (their outcomes,
// their hosts, the first alert, the goal), so another recording of the same
// kind gives the same pictures of its own run. The script fails if a page
// prints an error, if a replay page asks for anything beyond its own file or
// the app for anything beyond the service, if a moment does not show what the
// picture is meant to show, or if a recording or a shipped comparison no longer
// bears out what the README says of it. Each picture is taken once the page is
// at rest: two pictures taken one after the other are the same, and the app's
// top bar says the service is connected.

interface Step {
  id: string;
  order: number;
  role: string;
  title: string;
  outcome: string;
  command?: string;
  host?: string;
  from?: string | null;
  technique?: { id: string };
}

interface ShippedAlert {
  step: string;
  detector: string;
  rule: { title: string; level?: string; origin?: string };
  launcher_only?: boolean;
}

interface Shipped {
  id: string;
  title: string;
  source: { run_url?: string; tools?: { name: string; role?: string }[] };
  steps: Step[];
  alerts: ShippedAlert[];
}

interface ShippedPath extends Shipped {
  kind: string;
  network: { hosts: { id: string; role: string; kind: string }[] };
  attacker: { goal?: string };
  score: { first_alert_seconds: number | null; goal_seconds: number | null };
}

const repository = resolve(process.cwd(), "..");
const RECORDING = "bluefire/data/recordings/lab-linux-host.json";
const shipped: Shipped = JSON.parse(readFileSync(join(repository, RECORDING), "utf-8"));
const PATH_RECORDING = "bluefire/data/recordings/lab-range-one-path.json";
const path: ShippedPath = JSON.parse(readFileSync(join(repository, PATH_RECORDING), "utf-8"));
/** A step's marks on one side of a comparison: by the published rules, and with the lab's own rules too. */
interface Marks {
  outcome: string;
  outcome_with_lab_rules: string;
}

/** A comparison of two runs, or of one run evaluated with two rule sets, as far as this script reads it. */
interface Comparison {
  after: { run_url?: string };
  lab_rules: { title: string; change: string }[];
  steps: { id: string; title: string; result: string; before: Marks; after: Marks }[];
}

const PAIR = "bluefire/data/recordings/deltas/lab-pair-history-watch.json";
const pairShipped: Comparison = JSON.parse(readFileSync(join(repository, PAIR), "utf-8"));
const pairRun: string = pairShipped.after.run_url ?? "not named in the comparison";
const RULE_PAIR = "bluefire/data/recordings/deltas/lab-rule-history-truncated.json";
const rulePairShipped: Comparison = JSON.parse(readFileSync(join(repository, RULE_PAIR), "utf-8"));
const rulePairRun: string = rulePairShipped.after.run_url ?? "not named in the comparison";
const FILES = [
  "SOURCE.txt",
  "analyse-unseen.png",
  "analyse.png",
  "app-analyse.png",
  "app-overview.png",
  "app-pair.png",
  "app-recorded-run.png",
  "app-rule-pair.png",
  "app-runs-pair.png",
  "app-runs.png",
  "app-watch-stopped.png",
  "attack-path.html",
  "live-view-loop.gif",
  "path-goal-wide.png",
  "path-no-alert.png",
  "replay.html",
  "watch-first-alert.png",
  "watch-seen.png",
  "watch-stopped.png",
  "watch-unseen.png",
  "wide-first-alert.png",
];
// Late in a step: its outcome is told and every rule match has reached its engine.
const LATE = 0.95;

function inOrder(recording: Shipped): Step[] {
  return [...recording.steps].sort((one, other) => one.order - other.order);
}

/** The steps that pass the test, in the run's order. */
function every(what: string, passes: (step: Step) => boolean, recording: Shipped = shipped): Step[] {
  const found = inOrder(recording).filter(passes);
  if (found.length === 0) throw new Error(`${recording.title}: the recording has no ${what}.`);
  return found;
}

/** The first step in the run's order that passes the test. */
function first(what: string, passes: (step: Step) => boolean, recording: Shipped = shipped): Step {
  const [found] = every(what, passes, recording);
  if (!found) throw new Error(`${recording.title}: the recording has no ${what}.`);
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

// The attack path, and what the README says of it. Each sentence is checked here, so a later recording that no
// longer bears it out fails with the sentence to change.
const CAPTION =
  'The caption under the loop in README.md ("Wazuh, an open-source security monitor, alerted on the password guessing on the web server a minute in. ' +
  "About eleven minutes later the build server's signing secret was copied to inet, the stand-in internet, with no alert.\")";
const NO_ALERT_SECTION =
  'The section "Read what no rule alerted on" of README.md ("Every step after the password guessing was recorded, and no rule alerted on any of them. ' +
  'Pictured: step 9 of the same run, where every stock rule that matched was below alert level and the screen names the one to start from.")';
const NO_ALERT_PICTURE = 'The words of the picture under "Read what no rule alerted on" in README.md ("the step told seen with two rules matched for review and none at alert level")';
const CHANGE_SECTION =
  'The section "Change a defense, see before and after" of README.md ("new auditd settings took "Clear Bash history (echo)" from unseen to seen, ' +
  'then a rule written by hand from its event alerted on 4 steps that were seen. The score counts published rules only, so it still marks those 4 steps seen.")';
const UNSEEN_SECTION = 'The section "Find what nobody saw" of README.md ("On the Runs screen, open the run on one Linux machine and press Analyse: the table lists first the one unseen test, "Clear Bash history (echo)".")';
const HARDENING_SECTION =
  'The section "See what hardening stopped" of README.md ("In Analyse, the Hardened tab lists these reruns, each marked stopped or not; ' +
  'Watch from here on one shows it with the hardening change named, next to what the same test did without it.")';
function untrue(sentence: string, reason: string, recording: string = PATH_RECORDING): never {
  throw new Error(`${sentence} is untrue of ${recording}: ${reason}. Change it with the recording, and the loop's plan or the picture if they no longer show it.`);
}
const pathSteps = inOrder(path);
const pathFirst = first("step", () => true, path);
const pathLast = every("step", () => true, path).reverse()[0] ?? pathFirst;
function pathHost(id: string | null | undefined): { id: string; role: string; kind: string } | undefined {
  return path.network.hosts.find((host) => host.id === id);
}
/** A match of one of the published rules the recording names (not one written in this repository). */
function stock(alert: ShippedAlert): boolean {
  return alert.rule.origin === "pinned" && !alert.launcher_only;
}
const BELOW_ALERT = new Set(["low", "medium"]);
const webServer = pathHost(pathFirst.host);
const buildServer = path.network.hosts.find((host) => /build server/i.test(host.role));
const internet = path.network.hosts.find((host) => host.kind === "internet");
if (path.kind !== "attack path") untrue(CAPTION, `it is a recording of kind "${path.kind}", not an attack path`);
if (pathFirst.outcome !== "alerted") untrue(CAPTION, `its first step, "${pathFirst.title}", is ${pathFirst.outcome}, not alerted`);
if (!(pathFirst.technique?.id ?? "").startsWith("T1110")) untrue(CAPTION, `its first step, "${pathFirst.title}", is ${pathFirst.technique?.id ?? "no technique"}, not password guessing (T1110)`);
if (!webServer || !/^web\b/i.test(webServer.role)) untrue(CAPTION, `its first step ran on ${pathFirst.host ?? "no host"}, whose role is not the web server's`);
if (!path.alerts.some((alert) => alert.step === pathFirst.id && stock(alert) && (alert.rule.level === "high" || alert.rule.level === "critical"))) untrue(CAPTION, "no published rule alerted on its first step");
if (!(path.source.tools ?? []).some((tool) => tool.role === "rules" && tool.name.startsWith("Wazuh"))) untrue(CAPTION, "its published rules are not Wazuh's");
const firstAlertSeconds = path.score.first_alert_seconds;
const goalSeconds = path.score.goal_seconds;
if (firstAlertSeconds === null || Math.round(firstAlertSeconds / 60) !== 1) untrue(CAPTION, `its first alert came ${firstAlertSeconds ?? "never"} s in, not a minute in`);
if (goalSeconds === null) untrue(CAPTION, "the attacker did not reach its goal");
if (Math.round((goalSeconds - firstAlertSeconds) / 60) !== 11) untrue(CAPTION, `the goal was reached ${Math.round(goalSeconds - firstAlertSeconds)} s after the first alert, not about eleven minutes`);
if (!buildServer || !/signing secret/i.test(path.attacker.goal ?? "") || !(path.attacker.goal ?? "").startsWith(`${buildServer.id}'s`)) untrue(CAPTION, `its goal is "${path.attacker.goal ?? ""}", not the build server's signing secret`);
if (!internet || pathLast.host !== internet.id || !(path.attacker.goal ?? "").endsWith(internet.id)) untrue(CAPTION, `its last step ran on ${pathLast.host ?? "no host"}, not the stand-in internet the goal names`);
if (internet.id !== "inet") untrue(CAPTION, `its stand-in internet is called "${internet.id}", not inet`);
const afterGuessing = pathSteps.slice(1).filter((step) => step.outcome !== "seen");
if (afterGuessing.length > 0) untrue(NO_ALERT_SECTION, `these steps after the first are not seen with no alert: ${afterGuessing.map((step) => `"${step.title}" (${step.outcome})`).join(", ")}`);
// The step that logs in to the build server from the web server and copies files back: of the steps from the web server
// to the build server, the last that a published rule matched below alert level, which "Fix this" starts from.
const copies = pathSteps.filter((step) => step.from === webServer.id && step.host === buildServer.id && path.alerts.some((alert) => alert.step === step.id && stock(alert) && BELOW_ALERT.has(alert.rule.level ?? "")));
const copy = copies[copies.length - 1];
if (!copy) untrue(NO_ALERT_SECTION, `no step from ${webServer.id} to ${buildServer.id} was matched by a published rule below alert level`);
if (pathSteps.indexOf(copy) !== 8) untrue(NO_ALERT_SECTION, `the login to ${buildServer.id} that copies files back is step ${pathSteps.indexOf(copy) + 1}, not step 9`);
// Every published rule that matched step 9, at any level, was below alert level (high or critical).
const copyAtAlert = path.alerts.filter((alert) => alert.step === copy.id && stock(alert) && (alert.rule.level === "high" || alert.rule.level === "critical"));
if (copyAtAlert.length > 0) untrue(NO_ALERT_SECTION, `published rules matched step 9 at alert level: ${copyAtAlert.map((alert) => `"${alert.rule.title}" (${alert.rule.level ?? "no level"})`).join(", ")}`);

// The run on one Linux machine: its one unseen test, which "Find what nobody saw" names.
const unseenTests = every("unseen test", (step) => step.role === "test" && step.outcome === "unseen");
if (unseenTests.length !== 1) untrue(UNSEEN_SECTION, `it has ${unseenTests.length} unseen tests, not one`, RECORDING);
if (unseen.title !== "Clear Bash history (echo)") untrue(UNSEEN_SECTION, `its unseen test is "${unseen.title}"`, RECORDING);

// The two changes to the defense: what each comparison says moved.
const pairMoved = pairShipped.steps.filter((step) => step.result !== "same");
const pairEcho = pairMoved.find((step) => step.title === "Clear Bash history (echo)");
if (!pairEcho || pairEcho.before.outcome !== "unseen" || pairEcho.after.outcome !== "seen") untrue(CHANGE_SECTION, `"Clear Bash history (echo)" did not go from unseen to seen; the steps that moved: ${pairMoved.map((step) => `"${step.title}" ${step.before.outcome} to ${step.after.outcome}`).join(", ") || "none"}`, PAIR);
const ruleMoved = rulePairShipped.steps.filter((step) => step.result !== "same");
if (rulePairShipped.lab_rules.length !== 1 || rulePairShipped.lab_rules[0]?.change !== "new") untrue(CHANGE_SECTION, `the change to the lab's rules is not one new rule: ${rulePairShipped.lab_rules.map((rule) => `"${rule.title}" (${rule.change})`).join(", ") || "none"}`, RULE_PAIR);
const notAsSaid = ruleMoved.filter((step) => !(step.before.outcome_with_lab_rules === "seen" && step.after.outcome_with_lab_rules === "alerted" && step.before.outcome === "seen" && step.after.outcome === "seen"));
if (ruleMoved.length !== 4 || notAsSaid.length > 0)
  untrue(
    CHANGE_SECTION,
    `${ruleMoved.length} steps moved, and these did not go from seen to alerted with the lab's rules while staying seen in the score: ${notAsSaid.map((step) => `"${step.title}" (${step.id}) ${step.before.outcome}/${step.before.outcome_with_lab_rules} to ${step.after.outcome}/${step.after.outcome_with_lab_rules}`).join(", ") || "none"}`,
    RULE_PAIR,
  );

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
 * page that has just loaded can start one, is waited for too.
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

/** Inside the app: the top bar says the service is connected, which it says only while its last check is fresh. */
async function expectConnected(page: Page): Promise<void> {
  // The shell checks the service every 15 seconds and calls a check older than 30 "unchecked".
  await expect(page.getByRole("img", { name: "Local service connected", exact: true }), "the app's top bar does not say Connected").toBeVisible({ timeout: 30_000 });
  await expect(page.getByRole("button", { name: /^Check(ing)? connection$/ })).toHaveCount(0);
}

/**
 * Takes a picture once the page is at rest, and writes it: settled (see above), and two pictures taken one after the
 * other the same, so nothing on screen was still changing, whatever changed it (an entrance, a colour fading, an
 * answer from the service). Inside the app the top bar also says Connected, before the pictures and after them.
 */
async function picture(page: Page, folder: string, name: string, part?: Locator): Promise<void> {
  const app = page.url().startsWith("http");
  const take = () => (part ? part.screenshot() : page.screenshot());
  const tried: number[] = [];
  for (let attempt = 0; attempt < 20; attempt += 1) {
    if (app) await expectConnected(page);
    await settle(page);
    if (app) {
      await page.evaluate((whole) => {
        // A screen opened from a scrolled one can keep a few pixels of the old scroll; a visitor's page starts at its top.
        // Instant: the app's own style scrolls smoothly, and a smooth scroll can still be a pixel short when checked.
        if (whole) window.scrollTo({ top: 0, left: 0, behavior: "instant" });
        // The app's entrance, ended, holds its last frame with the page on a layer of its own, which can be drawn a
        // shade apart from the same page without it: let it go, and the page stands as its own style draws it.
        for (const item of document.getAnimations()) if (item instanceof CSSAnimation && item.animationName === "page-in" && item.playState === "finished") item.cancel();
      }, !part);
      await settle(page);
      if (!part) expect(await page.evaluate(() => window.scrollY), `${name}: the page is not at its top`).toBe(0);
    }
    const one = await take();
    const other = await take();
    if (app) await expectConnected(page);
    if (one.equals(other)) {
      writeFileSync(join(folder, name), one);
      return;
    }
    tried.push(attempt);
  }
  throw new Error(`${name}: the page did not come to rest: ${tried.length} pairs of pictures taken one after the other differed.`);
}

/**
 * In analyse mode, every step's title in the table takes two lines at the most (three where the live view is narrower
 * than 1440 px, as inside the app beside its rail), no cell of the table is cut short, and the first row in view stands
 * whole under the table's head: no row shows cut under it. With a row chosen, that row is whole in the table's box,
 * above the fade at its foot.
 */
async function expectWholeRows(page: Page, name: string, chosen?: string): Promise<{ scrolled: number }> {
  await settle(page);
  const found = await page.evaluate((selected) => {
    const titles = [...document.querySelectorAll<HTMLElement>(".lv-table .lv-row-button")].filter((title) => title.getBoundingClientRect().height > 0);
    // Two lines at the most where the live view is 1440 px wide or wider, three where it is narrower: the room the
    // table has is the view's, not the window's.
    const view = document.querySelector(".lv")?.getBoundingClientRect().width ?? 0;
    const most = view >= 1440 ? 2 : 3;
    const tall = titles.filter((title) => title.getBoundingClientRect().height / parseFloat(getComputedStyle(title).lineHeight) > most + 0.5).map((title) => title.textContent ?? "");
    // A cell, or a part of one, whose words are wider than its box (text for screen readers only aside).
    const short = [...document.querySelectorAll<HTMLElement>(".lv-table tbody td")]
      .filter((cell) => [cell, ...cell.querySelectorAll<HTMLElement>("*")].some((part) => !part.closest(".lv-sr") && getComputedStyle(part).overflow !== "visible" && part.scrollWidth > part.clientWidth + 1))
      .map((cell) => `${cell.closest("tr")?.dataset.step ?? ""}: ${cell.textContent ?? ""}`);
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
      if (!wrap || !row) return { tall, short, cut, titles: titles.length, whole: false, scrolled: 0 };
      const box = row.getBoundingClientRect();
      const foot = wrap.getBoundingClientRect().top + wrap.clientTop + wrap.clientHeight - parseFloat(getComputedStyle(wrap).paddingBottom);
      whole = box.top >= head - 0.5 && box.bottom <= foot + 0.5;
    }
    return { tall, short, cut, titles: titles.length, whole, scrolled: wrap?.scrollTop ?? 0 };
  }, chosen ?? null);
  expect(found.titles, `${name}: the table shows no title`).toBeGreaterThan(0);
  expect(found.tall, `${name}: titles over two lines, or three in a narrower live view`).toEqual([]);
  expect(found.short, `${name}: cells of the table cut short`).toEqual([]);
  expect(found.cut, `${name}: rows cut under the table's head`).toEqual([]);
  expect(found.whole, `${name}: the chosen row is not whole in the table's box`).toBe(true);
  return { scrolled: found.scrolled };
}

/**
 * Paused late in the step, its outcome told: the caption names the step, the
 * timeline no longer says it is running and every engine that matched shows a
 * match. Gives the titles of the match lines on screen that are cut short.
 */
async function expectMoment(page: Page, step: Step, recording: Shipped = shipped): Promise<string[]> {
  await expect(page.getByRole("button", { name: "Play", exact: true })).toBeVisible();
  await expect(page.getByRole("region", { name: "The step", exact: true })).toContainText(step.title);
  const where = page.getByRole("slider", { name: /^Timeline/ });
  await expect.poll(async () => (await where.getAttribute("aria-valuetext")) ?? "").toContain(step.title);
  await expect(where).not.toHaveAttribute("aria-valuetext", /, running: /);
  // Every rule engine that matched the step shows a match of its own (each lists a few and counts the rest).
  // A match line in an engine carries its rule's title as its tooltip, which the step's caption does not.
  const matches = recording.alerts.filter((alert) => alert.step === step.id && !alert.launcher_only);
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
async function expectWholeMoment(page: Page, step: Step, recording: Shipped = shipped): Promise<void> {
  expect(await expectMoment(page, step, recording), "match lines cut short").toEqual([]);
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

/** The path at its goal: the last step told, the goal marked reached, the race line whole. */
async function expectGoal(page: Page, name: string): Promise<void> {
  await expectMoment(page, pathLast, path);
  await expect(page.getByText(/goal reached/i).filter({ visible: true }).first(),`${name}: the goal is not marked reached`).toBeVisible();
  await expect(page.getByText(/The attacker reached its goal/), `${name}: the race line does not say the attacker reached its goal`).toBeVisible();
  await expectWholeRaceLine(page, name);
}

/** The single replay page of a recording, as the command line writes it. */
function writePage(recording: Shipped, out: string): void {
  const workspace = mkdtempSync(join(tmpdir(), "bluefire-pictures-"));
  try {
    const made = spawnSync(process.env.BLUEFIRE_PYTHON ?? "python3", ["-m", "bluefire.cli", "--runs-dir", workspace, "recordings", "page", recording.id, "--out", out], { cwd: repository, encoding: "utf-8" });
    if (made.status !== 0) throw new Error(`bluefire recordings page ${recording.id} exited with ${made.status}:\n${made.stdout}\n${made.stderr}`);
  } finally {
    rmSync(workspace, { recursive: true, force: true });
  }
}

test("pictures of the live view, in the replay pages and in the app", async ({ page }) => {
  const folder = process.env.BLUEFIRE_PICTURES ?? "";
  if (!folder) throw new Error("Set BLUEFIRE_PICTURES to the folder the pictures go to.");
  mkdirSync(folder, { recursive: true });
  expect(readdirSync(folder), `${folder} must be empty: it is kept as it is`).toEqual([]);

  // The pages, as the command line makes them.
  const replay = join(folder, "replay.html");
  writePage(shipped, replay);
  const attackPath = join(folder, "attack-path.html");
  writePage(path, attackPath);

  // A page may reach its own file only; the app, later, the service that serves it.
  const own = pathToFileURL(replay).href;
  const pathOwn = pathToFileURL(attackPath).href;
  const address = process.env.BLUEFIRE_SERVICE_URL ?? "";
  const service = `${new URL(address).origin}/`;
  let reachable = own;
  const problems = watch(page, (url) => url.startsWith(reachable));
  const open = async (query: string) => {
    await page.goto(`${own}?${query}`);
    await expect(page.getByRole("heading", { level: 1, name: shipped.title })).toBeVisible();
  };
  const openPath = async (query: string) => {
    await page.goto(`${pathOwn}?${query}`);
    await expect(page.getByRole("heading", { level: 1, name: path.title })).toBeVisible();
  };
  const at = (place: Place) => `step=${encodeURIComponent(place.step)}&at=${place.at}&paused=1`;

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

  // The attack path in its own page. "Read what no rule alerted on" in the README: late in the step that logs in to
  // the build server and copies files back, seen, the published rules that matched it below alert level whole,
  // "Fix this" beside it and the hint that says which rule to start from.
  reachable = pathOwn;
  await page.setViewportSize({ width: 1440, height: 900 });
  await openPath(at({ step: copy.id, at: LATE }));
  await expectWholeMoment(page, copy, path);
  const told = page.getByRole("region", { name: "The step", exact: true });
  await expect(told.getByRole("button", { name: "Fix this", exact: true }), `${NO_ALERT_SECTION}: the step it shows has no Fix this`).toBeVisible();
  await expect(told, `${NO_ALERT_PICTURE}: the step it shows is not told as seen with two rules matched for review`).toContainText(/2 rules matched for review, none at alert level/);
  await expect(told, `${NO_ALERT_SECTION}: the step's hint does not start from a rule that matched it`).toContainText(/start from the rule/);
  await expectWholeRaceLine(page, "path-no-alert.png");
  await picture(page, folder, "path-no-alert.png");
  // The path at its goal, at 1920 by 1080, for the documents.
  await page.setViewportSize({ width: 1920, height: 1080 });
  await openPath(at({ step: pathLast.id, at: 1 }));
  await expectGoal(page, "path-goal-wide.png");
  await picture(page, folder, "path-goal-wide.png");

  // Inside the app: the Overview, which leads with the attack path and the turns of the loop.
  await page.setViewportSize({ width: 1440, height: 900 });
  reachable = service;
  await page.goto(address);
  await expectConnected(page);
  const leading = page.getByRole("region", { name: "A run recorded in CI" });
  await expect(leading).toContainText(path.title);
  await expect(leading.getByRole("list", { name: "The changes to the defense, in order" }).getByRole("link")).toHaveCount(2);
  await picture(page, folder, "app-overview.png");

  // The Runs screen with the recorded runs, and the run's page on its first alert.
  await page.getByRole("link", { name: "Runs", exact: true }).first().click();
  const recorded = page.getByRole("region", { name: "Recorded runs" });
  const link = recorded.getByRole("link", { name: shipped.title, exact: true });
  await expect(link).toBeVisible();
  await expect(recorded.getByRole("link", { name: path.title, exact: true })).toBeVisible();
  await picture(page, folder, "app-runs.png");

  // The pair of runs shipped with the app: its part of the Runs screen alone, and its own page.
  const pairs = page.getByRole("region", { name: "Before against after" });
  const pair = pairs.getByRole("link", { name: "Clear Bash history (echo) went from unseen to seen.", exact: true });
  await pairs.scrollIntoViewIfNeeded();
  await expect(pair).toBeVisible();
  await picture(page, folder, "app-runs-pair.png", pairs);
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

  const runPath = await link.getAttribute("href");
  if (!runPath?.startsWith("#/")) throw new Error(`The recorded run's link is ${runPath}.`);

  // "Find what nobody saw" in the README: open the run on one Linux machine, press Analyse, and click the first row of
  // the table, which is the unseen test: its detail opens beside the table, with "Fix this". At 1440 by 900, the size
  // of the README's other pictures, where the live view beside the app's rail is 1440 px less the rail.
  await link.click();
  await page.getByRole("button", { name: "Analyse", exact: true }).click();
  await expect(page.getByRole("button", { name: "Analyse", exact: true })).toHaveAttribute("aria-pressed", "true");
  const rows = page.locator(".lv-table tbody tr[data-step]");
  await expect(rows.first(), `${UNSEEN_SECTION}: pressing Analyse does not list "${unseen.title}" first`).toHaveAttribute("data-step", unseen.id);
  await rows.first().locator(".lv-row-button").click();
  const detail = page.getByRole("article");
  await expect(detail.getByRole("heading", { name: unseen.title, exact: true })).toBeVisible();
  await expect(detail.getByRole("button", { name: "Fix this", exact: true }), `${UNSEEN_SECTION}: the panel beside the table has no Fix this`).toBeVisible();
  await expectWholeRows(page, "app-analyse.png");
  await picture(page, folder, "app-analyse.png");

  // "See what hardening stopped" in the README: in Analyse, the Hardened tab, then Watch from here on a rerun that was
  // stopped. Every cell of that tab is whole. The view then plays the rerun from its start; the picture is taken
  // paused late in it, as its address names that moment, the rerun told stopped with its hardening change named and
  // what the same test did without it.
  await page.getByRole("group", { name: "Role" }).getByRole("button", { name: /^Hardened/ }).click();
  const reruns = await rows.evaluateAll((items) => items.map((row) => (row instanceof HTMLElement ? (row.dataset.step ?? "") : "")));
  const hardened = new Set(every("hardened rerun", (step) => step.role === "hardened").map((step) => step.id));
  expect(reruns.filter((id) => !hardened.has(id)), `${HARDENING_SECTION}: the Hardened tab lists steps that are not hardened reruns`).toEqual([]);
  expect(reruns, `${HARDENING_SECTION}: the Hardened tab does not list the rerun "${stopped.title}"`).toContain(stopped.id);
  await expectWholeRows(page, "the Hardened tab");
  await page.locator(`.lv-table tbody tr[data-step="${stopped.id}"] .lv-row-button`).click();
  await expect(detail.getByRole("heading", { name: stopped.title, exact: true })).toBeVisible();
  await detail.getByRole("button", { name: "Watch from here", exact: true }).click();
  await expect(page.getByRole("button", { name: "Watch", exact: true })).toHaveAttribute("aria-pressed", "true");
  const watching = page.getByRole("region", { name: "The step", exact: true });
  await expect(watching).toContainText(stopped.title);
  await page.evaluate((hash) => {
    window.location.hash = hash;
  }, `${runPath.slice(1)}?step=${stopped.id}&at=${LATE}&paused=1`);
  await expectMoment(page, stopped);
  await expect(watching.locator(".lv-word"), `${HARDENING_SECTION}: the rerun is not told stopped`).toHaveText("stopped");
  await expect(watching, `${HARDENING_SECTION}: the hardening change is not named`).toContainText("Hardening change:");
  await expect(watching, `${HARDENING_SECTION}: what the same test did without it is not shown`).toContainText(/Without it/i);
  await expectWholeRaceLine(page, "app-watch-stopped.png");
  await picture(page, folder, "app-watch-stopped.png");
  await page.getByRole("link", { name: "Runs", exact: true }).first().click();
  await expect(link).toBeVisible();
  const moment = (step: Step) =>
    page.evaluate((hash) => {
      window.location.hash = hash;
    }, `${runPath.slice(1)}?step=${step.id}&at=${LATE}&paused=1`);
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

  // The loop for the top of the README, in the attack path's page. It comes last because its frames
  // take minutes, and the app above has to be opened while the address the service printed is
  // still good. Its first frame, which a still or a link preview shows, is the path at its goal:
  // every hop drawn, the first alert's mark on the web server, the goal reached, both marks on the
  // clock, held 2.5 s. Then the first step from its start until its alert has been told, played
  // four times as fast as the view since it is a long step, held 1.5 s; then the step that copies
  // files back from the build server, twice as fast, to late in it, seen with no alert, held 1.5 s;
  // then the last step from its start to its end, which is the first frame again, so the loop closes
  // with no seam. About 13 seconds in all.
  // Leave the app first, so that nothing of it is still asking the service when only the page's own file may be reached.
  await page.goto("about:blank");
  await page.setViewportSize({ width: 1440, height: 900 });
  reachable = pathOwn;
  const goal = { step: pathLast.id, at: 1 };
  const alertTold = placeAfterFirstAlert(path, 1);
  const copyLate = { step: copy.id, at: LATE };
  // Each held place shows what the README says of it before any frame is taken.
  await openPath(at(goal));
  await expectGoal(page, "the loop's first frame");
  await openPath(at(alertTold));
  await expect(page.getByRole("region", { name: "The step", exact: true }).locator(".lv-word"), `${CAPTION}: the loop's frame of the first alert does not tell the first step alerted`).toHaveText("alerted");
  await expect(page.getByText(/^The defense raised its first alert/), "the loop's frame of the first alert has no first alert on the race line").toBeVisible();
  await openPath(at(copyLate));
  await expect(page.getByRole("region", { name: "The step", exact: true }).getByRole("button", { name: "Fix this", exact: true })).toBeVisible();
  const loop: LoopPlan = {
    stretches: [
      { from: goal, holdFirst: 2500 },
      { from: { step: pathFirst.id, at: 0 }, to: alertTold, holdLast: 1500, pace: 4 },
      { from: { step: copy.id, at: 0 }, to: copyLate, holdLast: 1500, pace: 2 },
      { from: { step: pathLast.id, at: 0 }, to: goal },
    ],
    fps: 10,
    pace: 1,
  };
  const frames = loopFrames(path, loop);
  const pictures = await takeFrames(page, openPath, frames);
  // The last frame is the last step just before the loop's first frame.
  await expect(page.getByRole("region", { name: "The step", exact: true })).toContainText(pathLast.title);
  await writeLoop(pictures, frames, 1000, join(folder, "live-view-loop.gif"));

  writeFileSync(
    join(folder, "SOURCE.txt"),
    [
      "Pictures of the live view and the single replay pages, made from the two recordings shipped with BlueFire,",
      "and of the Overview, the Runs screen, the run on one Linux machine and the pages of the pair of runs and the run",
      "evaluated twice shipped with it.",
      `Run on one Linux machine: ${shipped.id} (${RECORDING}), recorded in the CI run ${shipped.source.run_url ?? "not named in the recording"}`,
      `Attack path: ${path.id} (${PATH_RECORDING}), recorded in the CI run ${path.source.run_url ?? "not named in the recording"}`,
      `Pair: ${PAIR} (made in the CI run ${pairRun})`,
      `Run evaluated twice: ${RULE_PAIR} (made in the CI run ${rulePairRun})`,
      `Made from the commit: ${process.env.GITHUB_SHA ?? "not known: made outside CI"}`,
      "",
      "Of the run on one Linux machine: replay.html, watch-*.png, analyse.png, analyse-unseen.png, wide-first-alert.png.",
      "Of the attack path: attack-path.html, live-view-loop.gif, path-no-alert.png, path-goal-wide.png.",
      "Of the app: app-*.png.",
      "",
    ].join("\n"),
  );

  expect(problems).toEqual([]);
  expect(readdirSync(folder).sort()).toEqual(FILES);
});
