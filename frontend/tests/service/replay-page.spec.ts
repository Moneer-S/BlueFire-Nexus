import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { expect, test } from "@playwright/test";
import type { Locator, Page } from "@playwright/test";

// The single replay page, made by the app's command line from the committed
// template and the recording shipped with the app, opened from a file address
// as someone would open a page they were sent.

interface Score {
  alerted: number;
  seen: number;
  unseen: number;
  stopped: number;
  false_alerts?: number;
}

interface ShippedRecording {
  id: string;
  title: string;
  score: Score;
  steps: { id: string; role: string; title: string; plain?: string }[];
  events: { text: string }[];
  notes: string[];
  source: Record<string, unknown>;
}

const repository = resolve(process.cwd(), "..");
const shipped: ShippedRecording = JSON.parse(readFileSync(join(repository, "bluefire/data/recordings/lab-linux-host.json"), "utf-8"));
const UNSEEN = "Clear Bash history (echo)";
const HOSTILE_IMAGE = "<img src=http://198.51.100.7/beacon.png onerror=alert(1)>";
const HOSTILE_LINK = "javascript:alert(document.domain)";

let workspace = "";
let shippedPage = "";
let hostilePage = "";
let unsaidPage = "";
let labPage = "";
const ORIGIN_ELEMENT = '<script id="bluefire-origin" type="application/json">';

/** Runs the app's command line on the test's own workspace. */
function bluefire(...args: string[]): void {
  const run = spawnSync(process.env.BLUEFIRE_PYTHON ?? "python3", ["-m", "bluefire.cli", "--runs-dir", join(workspace, "runs"), ...args], { cwd: repository, encoding: "utf-8" });
  if (run.status !== 0) throw new Error(`bluefire ${args.join(" ")} exited with ${run.status}:\n${run.stdout}\n${run.stderr}`);
}

/** Runs the lab's command line from this checkout, as the lab workflow does after a run. */
function bluefireLab(...args: string[]): void {
  const run = spawnSync(process.env.BLUEFIRE_PYTHON ?? "python3", ["-m", "bluefire_lab", ...args], { cwd: join(repository, "lab"), encoding: "utf-8" });
  if (run.status !== 0) throw new Error(`bluefire-lab ${args.join(" ")} exited with ${run.status}:\n${run.stdout}\n${run.stderr}`);
}

test.beforeAll(() => {
  workspace = mkdtempSync(join(tmpdir(), "bluefire-replay-"));
  shippedPage = join(workspace, "shipped.html");
  bluefire("recordings", "page", shipped.id, "--out", shippedPage);

  // A recording whose texts hold markup and addresses: the page must show them as text.
  const hostile: ShippedRecording = structuredClone(shipped);
  hostile.id = "rec-hostile";
  hostile.title = HOSTILE_IMAGE;
  hostile.source.run_url = HOSTILE_LINK;
  const first = hostile.steps[0];
  if (!first) throw new Error("The shipped recording has no step.");
  first.title = `${HOSTILE_IMAGE} </script><!--`;
  first.plain = `Opens ${HOSTILE_LINK} <a href="${HOSTILE_LINK}">here</a>`;
  hostile.notes = [...hostile.notes, HOSTILE_IMAGE];
  const recordingFile = join(workspace, "hostile.json");
  writeFileSync(recordingFile, JSON.stringify(hostile));
  bluefire("recordings", "import", recordingFile);
  hostilePage = join(workspace, "hostile.html");
  bluefire("recordings", "page", hostile.id, "--out", hostilePage);

  // The shipped recording's page with its origin taken out, as a template filled by other means would be.
  const made = readFileSync(shippedPage, "utf-8");
  const start = made.indexOf(ORIGIN_ELEMENT) + ORIGIN_ELEMENT.length;
  if (start < ORIGIN_ELEMENT.length) throw new Error("The page has no origin element.");
  unsaidPage = join(workspace, "unsaid.html");
  writeFileSync(unsaidPage, `${made.slice(0, start)}null${made.slice(made.indexOf("</script>", start))}`);

  // The page a run of the lab leaves beside its recording, from the same template, written by the run that recorded it.
  const labRecording = join(workspace, "recording.json");
  writeFileSync(labRecording, JSON.stringify(shipped));
  labPage = join(workspace, "lab.html");
  bluefireLab("replay", labRecording, "--template", join(repository, "bluefire/ui/replay.html"), "--out", labPage, "--run-url", String(shipped.source.run_url));
});

test.afterAll(() => {
  if (workspace) rmSync(workspace, { recursive: true, force: true });
});

/** Opens a page and records every request it makes beyond its own file, and every error it prints. */
async function open(page: Page, file: string, query = "") {
  const address = `${pathToFileURL(file).href}${query}`;
  const requests: string[] = [];
  const problems: string[] = [];
  page.on("request", (request) => {
    const url = request.url();
    if (url !== address && !url.startsWith("data:")) requests.push(url);
  });
  page.on("pageerror", (error) => problems.push(String(error)));
  page.on("console", (message) => {
    if (message.type() === "error") problems.push(message.text());
  });
  await page.goto(address);
  return { requests, problems };
}

function scrubber(page: Page): Locator {
  return page.getByRole("slider", { name: /^Timeline/ });
}

/** The step the scrubber stands on: its place among all steps, from 1. */
async function scrubberPlace(page: Page): Promise<number> {
  const text = (await scrubber(page).getAttribute("aria-valuetext")) ?? "";
  const place = /, (\d+) of \d+, /.exec(text)?.[1];
  if (place === undefined) throw new Error(`The scrubber says no step: ${text}`);
  return Number(place);
}

function caption(page: Page): Locator {
  return page.getByRole("region", { name: "The step", exact: true });
}

/** The score's numbers as the screen shows them, in the order they stand. */
async function scoreOnScreen(page: Page, label: string): Promise<string> {
  const text = (await page.getByLabel(label, { exact: true }).textContent()) ?? "";
  return text.replace(/\s+/g, " ").trim();
}

function expectedScore(recording: ShippedRecording): string {
  const score = recording.score;
  const hardened = recording.steps.filter((step) => step.role === "hardened").length;
  const falseAlerts = score.false_alerts === undefined ? "" : `${score.false_alerts}${score.false_alerts === 1 ? "false alert" : "false alerts"}`;
  return `${score.alerted}/ ${score.alerted + score.seen + score.unseen}tests alerted${score.seen}seen, no alert${score.unseen}unseen${falseAlerts}${score.stopped} / ${hardened}reruns stopped`;
}

test("watch mode tells the run step by step, and plays, pauses and moves by pointer and keyboard", async ({ page }) => {
  const { requests, problems } = await open(page, shippedPage);
  const firstStep = shipped.steps[0];
  if (!firstStep?.plain) throw new Error("The shipped recording's first step has no plain words.");

  await expect(page.getByRole("heading", { level: 1, name: shipped.title })).toBeVisible();
  await expect(caption(page)).toContainText(firstStep.plain);
  // Under the title: the recording shipped with BlueFire, and the CI run that made it.
  const origin = page.getByText(/^Shipped with BlueFire\. This repository's lab workflow recorded it in the CI run at /);
  await expect(origin).toBeVisible();
  await expect(origin).toContainText(String(shipped.source.run_url));

  // Playing: the clock moves. The button pauses it, and plays it again.
  const play = page.getByRole("button", { name: "Pause", exact: true });
  await expect(play).toBeVisible();
  const before = await scrubber(page).getAttribute("aria-valuetext");
  await expect.poll(() => scrubber(page).getAttribute("aria-valuetext")).not.toBe(before);
  await play.click();
  await expect(page.getByRole("button", { name: "Play", exact: true })).toBeFocused();
  const paused = await scrubber(page).getAttribute("aria-valuetext");
  await page.waitForTimeout(600);
  expect(await scrubber(page).getAttribute("aria-valuetext")).toBe(paused);

  // Space plays and pauses from anywhere on the page.
  await page.evaluate(() => {
    if (document.activeElement instanceof HTMLElement) document.activeElement.blur();
  });
  await page.keyboard.press("Space");
  await expect(page.getByRole("button", { name: "Pause", exact: true })).toBeVisible();
  await expect.poll(() => scrubber(page).getAttribute("aria-valuetext")).not.toBe(paused);
  await page.keyboard.press("Space");
  await expect(page.getByRole("button", { name: "Play", exact: true })).toBeVisible();

  // The pointer: a press in the middle of the strip goes to the middle step, and a drag follows.
  const box = await scrubber(page).boundingBox();
  if (!box) throw new Error("The scrubber is not on screen.");
  const count = shipped.steps.length;
  const y = box.y + box.height / 2;
  await page.mouse.click(box.x + box.width * 0.5, y);
  expect(Math.abs((await scrubberPlace(page)) - count * 0.5)).toBeLessThanOrEqual(2);
  await page.mouse.move(box.x + box.width * 0.2, y);
  await page.mouse.down();
  await page.mouse.move(box.x + box.width * 0.8, y, { steps: 6 });
  await page.mouse.up();
  expect(Math.abs((await scrubberPlace(page)) - count * 0.8)).toBeLessThanOrEqual(2);
  await expect(page.getByRole("button", { name: "Play", exact: true })).toBeVisible();

  // The keyboard: Home, an arrow, Page Up and End.
  await scrubber(page).focus();
  await page.keyboard.press("Home");
  expect(await scrubberPlace(page)).toBe(1);
  await expect(caption(page)).toContainText(firstStep.plain);
  // Ordinary activity has no times, so its false alerts are not in the score so far.
  await expect(page.getByLabel("The score so far", { exact: true })).not.toContainText("false alert");
  await page.keyboard.press("ArrowRight");
  expect(await scrubberPlace(page)).toBe(2);
  await page.keyboard.press("PageUp");
  expect(await scrubberPlace(page)).toBe(12);
  await page.keyboard.press("ArrowLeft");
  expect(await scrubberPlace(page)).toBe(11);
  await page.keyboard.press("End");
  expect(await scrubberPlace(page)).toBe(count);

  // At the end of the run the score on screen is the recording's.
  expect(await scoreOnScreen(page, "The score so far")).toBe(expectedScore(shipped));

  expect(problems).toEqual([]);
  expect(requests).toEqual([]);
});

test("the unseen test says it took effect and that no sensor recorded it, and Fix this opens its detail", async ({ page }) => {
  const step = shipped.steps.find((item) => item.title === UNSEEN);
  if (!step) throw new Error(`The shipped recording has no step ${UNSEEN}.`);
  const { requests, problems } = await open(page, shippedPage, `?step=${step.id}&paused=1`);

  await expect(page.getByRole("button", { name: "Play", exact: true })).toBeVisible();
  await expect(caption(page)).toContainText(UNSEEN);
  await expect(caption(page).getByText("unseen", { exact: true })).toBeVisible();
  await expect(caption(page).getByText("No sensor recorded it.", { exact: true })).toBeVisible();
  await expect(page.getByText(/It took effect, and\s*nothing travelled\./)).toBeVisible();
  expect(await scrubber(page).getAttribute("aria-valuetext")).toContain(UNSEEN);
  // Paused, it stays on the step.
  await page.waitForTimeout(600);
  await expect(caption(page)).toContainText(UNSEEN);

  await caption(page).getByRole("button", { name: "Fix this" }).click();
  const detail = page.getByRole("article");
  await expect(page.getByRole("button", { name: "Analyse", exact: true })).toHaveAttribute("aria-pressed", "true");
  await expect(detail.getByRole("heading", { name: UNSEEN })).toBeVisible();
  await expect(detail).toBeFocused();
  await expect(detail).toContainText("It took effect, and no sensor recorded it.");
  await expect(detail.getByRole("status")).toContainText("Start with a sensor: other runs of T1070.003 were recorded");
  // The page has no app to fix in, so the detail offers no second "Fix this".
  await expect(detail.getByRole("button", { name: "Fix this" })).toHaveCount(0);

  expect(problems).toEqual([]);
  expect(requests).toEqual([]);
});

test("analyse mode lists the tests, filters them, opens a step and watches from it", async ({ page }) => {
  const { requests, problems } = await open(page, shippedPage, "?mode=analyse");
  const score = shipped.score;
  const tests = shipped.steps.filter((step) => step.role === "test").length;
  const all = shipped.steps.length;

  await expect(page.getByRole("button", { name: new RegExp(`^Tests\\s*${tests}$`) })).toHaveAttribute("aria-pressed", "true");
  const outcomes = page.getByRole("group", { name: `Outcomes of ${tests} tests` });
  await expect(outcomes.getByRole("button", { name: new RegExp(`^alerted\\s*${score.alerted}$`) })).toBeVisible();
  await expect(outcomes.getByRole("button", { name: new RegExp(`^seen, no alert\\s*${score.seen}$`) })).toBeVisible();
  await expect(outcomes.getByRole("button", { name: new RegExp(`^unseen\\s*${score.unseen}$`) })).toBeVisible();
  const table = page.getByRole("table");
  await expect(table.getByRole("row")).toHaveCount(tests + 1);
  await expect(page.getByText(`${tests} of ${all}`, { exact: true })).toBeVisible();
  expect(await scoreOnScreen(page, "The score")).toBe(expectedScore(shipped));

  // A filter narrows the table to the one test nobody saw.
  await outcomes.getByRole("button", { name: /^unseen/ }).click();
  await expect(table.getByRole("row")).toHaveCount(score.unseen + 1);
  await expect(page.getByText(`${score.unseen} of ${all}`, { exact: true })).toBeVisible();

  // Choosing its row shows its detail.
  await table.getByRole("button", { name: UNSEEN, exact: true }).click();
  const detail = page.getByRole("article");
  await expect(detail.getByRole("heading", { name: UNSEEN })).toBeVisible();
  await expect(detail).toContainText("It took effect, and no sensor recorded it.");

  // Watch from here goes back to watch mode on that step.
  await detail.getByRole("button", { name: "Watch from here" }).click();
  await expect(page.getByRole("button", { name: "Watch", exact: true })).toHaveAttribute("aria-pressed", "true");
  await expect(caption(page)).toContainText(UNSEEN);
  expect(await scrubber(page).getAttribute("aria-valuetext")).toContain(UNSEEN);

  expect(problems).toEqual([]);
  expect(requests).toEqual([]);
});

test("the address opens a step's detail, or a moment of a step in watch mode", async ({ page }) => {
  const step = shipped.steps.find((item) => item.title === UNSEEN);
  if (!step) throw new Error(`The shipped recording has no step ${UNSEEN}.`);
  const { requests, problems } = await open(page, shippedPage, `?mode=analyse&select=${step.id}`);
  await expect(page.getByRole("button", { name: "Analyse", exact: true })).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByRole("article").getByRole("heading", { name: UNSEEN })).toBeVisible();

  // At the start of the step its outcome is not told yet; a little later it is.
  await page.goto(`${pathToFileURL(shippedPage).href}?mode=watch&step=${step.id}&at=0&paused=1`);
  await expect(page.getByRole("button", { name: "Watch", exact: true })).toHaveAttribute("aria-pressed", "true");
  await expect(caption(page)).toContainText(UNSEEN);
  expect(await scrubber(page).getAttribute("aria-valuetext")).toContain(`, running: ${UNSEEN}`);
  await page.goto(`${pathToFileURL(shippedPage).href}?mode=watch&step=${step.id}&at=0.9&paused=1`);
  await expect(caption(page)).toContainText(UNSEEN);
  expect(await scrubber(page).getAttribute("aria-valuetext")).not.toContain(", running: ");

  // Past 1 the address reaches into the silence after the step: still that step, its clock later than the step's end.
  await page.goto(`${pathToFileURL(shippedPage).href}?mode=watch&step=${step.id}&at=1&paused=1`);
  await expect(caption(page)).toContainText(UNSEEN);
  const atEnd = await scrubber(page).getAttribute("aria-valuetext");
  await page.goto(`${pathToFileURL(shippedPage).href}?mode=watch&step=${step.id}&at=1.9&paused=1`);
  await expect(caption(page)).toContainText(UNSEEN);
  const inSilence = await scrubber(page).getAttribute("aria-valuetext");
  expect(inSilence).toContain(`, unseen: ${UNSEEN}`);
  expect(inSilence).not.toBe(atEnd);

  expect(problems).toEqual([]);
  expect(requests.filter((url) => !url.startsWith(pathToFileURL(shippedPage).href))).toEqual([]);
});

test("a page that does not say where its recording comes from says so", async ({ page }) => {
  const { requests, problems } = await open(page, unsaidPage, "?paused=1");

  await expect(page.getByRole("heading", { level: 1, name: shipped.title })).toBeVisible();
  await expect(page.getByText("This page does not say where its recording comes from.", { exact: true })).toBeVisible();
  await expect(page.getByText(/^Shipped with BlueFire/)).toHaveCount(0);
  expect(problems).toEqual([]);
  expect(requests).toEqual([]);
});

test("the page a lab run leaves says that the lab's CI run made it", async ({ page }) => {
  const { requests, problems } = await open(page, labPage, "?paused=1");

  await expect(page.getByRole("heading", { level: 1, name: shipped.title })).toBeVisible();
  const origin = page.getByText(/^Made by this repository's lab workflow in the CI run at /);
  await expect(origin).toBeVisible();
  await expect(origin).toContainText(String(shipped.source.run_url));
  await expect(page.getByText(/^Shipped with BlueFire/)).toHaveCount(0);
  expect(problems).toEqual([]);
  expect(requests).toEqual([]);
});

test("a recording cannot make the page load anything: its markup and addresses are shown as text", async ({ page }) => {
  const { requests, problems } = await open(page, hostilePage, "?step=1&paused=1");

  await expect(page.getByRole("heading", { level: 1 })).toHaveText(HOSTILE_IMAGE);
  // An imported recording says what BlueFire checked and what it cannot confirm.
  await expect(page.getByText(/^Imported\. BlueFire checked that this file follows the recording format/)).toContainText("It cannot confirm that the steps ran");
  await expect(page.getByText(/^Shipped with BlueFire/)).toHaveCount(0);
  await expect(caption(page)).toContainText(`${HOSTILE_IMAGE} </script><!--`);
  await expect(caption(page)).toContainText(`Opens ${HOSTILE_LINK} <a href="${HOSTILE_LINK}">here</a>`);
  await expect(page.locator("img")).toHaveCount(0);
  await expect(page.locator("a")).toHaveCount(0);
  await page.getByRole("button", { name: /tool versions/ }).click();
  await expect(page.getByText(HOSTILE_IMAGE, { exact: true }).last()).toBeVisible();
  await expect(page.locator("img")).toHaveCount(0);
  await expect(page.locator("a")).toHaveCount(0);
  expect(problems).toEqual([]);
  expect(requests).toEqual([]);

  // Even script on the page itself cannot reach out: the page's own policy refuses
  // an image and a connection to another address, whatever the network would do.
  const failed: string[] = [];
  page.on("requestfailed", (request) => {
    failed.push(`${request.url()} ${request.failure()?.errorText ?? ""}`);
  });
  const tried = await page.evaluate(async () => {
    const violations: string[] = [];
    document.addEventListener("securitypolicyviolation", (event) => violations.push(event.effectiveDirective));
    const image = await new Promise<string>((done) => {
      const element = new Image();
      element.onload = () => done("loaded");
      element.onerror = () => done("refused");
      element.src = "http://198.51.100.7/beacon.png";
    });
    const fetched = await fetch("http://198.51.100.7/beacon").then(
      () => "loaded",
      () => "refused",
    );
    await new Promise((done) => setTimeout(done, 100));
    return { image, fetched, violations };
  });
  expect(tried).toEqual({ image: "refused", fetched: "refused", violations: ["img-src", "connect-src"] });
  // Chromium names the refused image as a request that failed by the policy, before it left the page; the connection is not even named.
  expect(failed).toEqual(["http://198.51.100.7/beacon.png csp"]);
  expect(requests).toEqual(["http://198.51.100.7/beacon.png"]);
});
