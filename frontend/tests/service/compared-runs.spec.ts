import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createHash } from "node:crypto";
import { expect, test, type Page } from "@playwright/test";
import { launchService } from "./start-service";

// Two compared runs in the real service: recording files imported on the Runs
// screen, and the delta that the lab's own command makes of them sent to the
// service's route. The pair with a declared change is BUILT here from the
// recording shipped with the app (another digest for the audit rules, and its
// one unseen test made seen by one added record), because no real pair with a
// declared change exists yet. The refused pair is real: the shipped recording
// compared with itself, which the lab refuses for want of source.setup.

interface Step { id: string; order: number; title: string; outcome: string; outcome_with_lab_rules?: string; started?: string; host: string; visibility: { answer: string; basis: string; events?: number }; first_event?: string }
interface Recording {
  id: string;
  title: string;
  source: { setup?: unknown; [key: string]: unknown };
  network: { detectors: { id: string; digest?: string }[] };
  steps: Step[];
  events: { id: string; time: string; host: string; sensor: string; kind: string; text: string; step: string; tied_by: string }[];
  score: { seen: number; unseen: number };
}
interface DeltaStep { id: string; title: string; result: string; verdict: string }
interface Delta { steps: DeltaStep[]; control: { same: number; of: number }; refused_because: string[] }

const repository = resolve(process.cwd(), "..");
const shippedFile = join(repository, "bluefire/data/recordings/lab-linux-host.json");
const UNSEEN = "Clear Bash history (echo)";
let workspace = "";
let service: Awaited<ReturnType<typeof launchService>> | undefined;
let changed: Delta;
let refused: Delta;

function bluefireLab(...args: string[]): void {
  const run = spawnSync(process.env.BLUEFIRE_PYTHON ?? "python3", ["-m", "bluefire_lab", ...args], { cwd: join(repository, "lab"), encoding: "utf-8" });
  if (run.status !== 0) throw new Error(`bluefire-lab ${args.join(" ")} exited with ${run.status}:\n${run.stdout}\n${run.stderr}`);
}

const digest = (text: string) => createHash("sha256").update(text).digest("hex");

/** BUILT: the shipped recording under another id, with the setup a comparison needs. */
function built(id: string, auditRules: string): Recording {
  const recording: Recording = JSON.parse(readFileSync(shippedFile, "utf-8"));
  recording.id = id;
  // A title of its own, so that the other tests on this service find the shipped recording by its title alone.
  recording.title = `Built for a browser test from the shipped run (${id})`;
  recording.source.setup = { sensors: { sysmon: digest("built sysmon configuration"), auditd: digest(auditRules) } };
  for (const detector of recording.network.detectors) detector.digest = digest(`built rules of ${detector.id}`);
  return recording;
}

/** BUILT: the unseen test made seen by one added auditd record. */
function seenBy(recording: Recording): Recording {
  const step = recording.steps.find((item) => item.title === UNSEEN && item.outcome === "unseen");
  if (!step?.started) throw new Error(`The shipped recording has no unseen ${UNSEEN}.`);
  const time = step.started;
  const place = recording.events.findIndex((item) => item.time > time);
  const added = { id: `${step.order}-built`, time, host: step.host, sensor: "auditd", kind: "openat", text: "/home/bluefire-lab/.bash_history", step: step.id, tied_by: "session" };
  recording.events.splice(place < 0 ? recording.events.length : place, 0, added);
  step.visibility = { answer: "telemetry only", basis: "BUILT: one auditd record added for this test", events: 1 };
  step.outcome = "seen";
  if (step.outcome_with_lab_rules !== undefined) step.outcome_with_lab_rules = "seen";
  step.first_event = time;
  recording.score.unseen -= 1;
  recording.score.seen += 1;
  return recording;
}

function write(name: string, value: unknown): string {
  const path = join(workspace, name);
  writeFileSync(path, `${JSON.stringify(value, null, 1)}\n`);
  return path;
}

test.beforeAll(async () => {
  test.setTimeout(120_000);
  // A service of its own: the shared one's connection code opens one browser only, the screens test's.
  service = await launchService(8766);
  workspace = mkdtempSync(join(tmpdir(), "bluefire-pairs-"));
  write("before.json", built("built-before", "built audit rules before"));
  write("after.json", seenBy(built("built-after", "built audit rules after")));
  bluefireLab("compare", join(workspace, "before.json"), join(workspace, "after.json"), "--out", join(workspace, "changed"), "--change", "sensors:auditd");
  bluefireLab("compare", shippedFile, shippedFile, "--out", join(workspace, "refused"));
  changed = JSON.parse(readFileSync(join(workspace, "changed", "delta.json"), "utf-8"));
  refused = JSON.parse(readFileSync(join(workspace, "refused", "delta.json"), "utf-8"));
});

test.afterAll(async () => {
  if (workspace) rmSync(workspace, { recursive: true, force: true });
  await service?.stop();
});

/** Sends a delta to the service's route from the page, with the page's own session. */
async function importDelta(page: Page, folder: string): Promise<number> {
  const delta: unknown = JSON.parse(readFileSync(join(workspace, folder, "delta.json"), "utf-8"));
  return page.evaluate(async (body) => {
    const session = sessionStorage.getItem("bluefire.browser-session.v1") ?? "";
    const response = await fetch("/api/v1/recordings/deltas", { method: "POST", headers: { "Content-Type": "application/json", Accept: "application/json", "X-BlueFire-Session": session }, body: JSON.stringify({ delta: body }) });
    return response.status;
  }, delta);
}

test("a pair of runs is imported, listed on Runs and read on its own page as a claim with its price", async ({ page }) => {
  test.setTimeout(120_000);
  const problems: string[] = [];
  page.on("pageerror", (error) => problems.push(String(error)));
  page.on("response", (response) => {
    if (response.status() >= 500) problems.push(`${response.status()} ${response.url()}`);
  });
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(service?.url ?? "");
  await expect(page.getByText("Connected", { exact: true })).toBeVisible();
  await page.getByRole("link", { name: "Runs", exact: true }).click();

  // The recording files go in on the Runs screen, as the lab wrote them; the deltas by the route.
  for (const name of ["before.json", "after.json"]) {
    await page.getByLabel("Recording file to import").setInputFiles(join(workspace, name));
    await expect(page).toHaveURL(/#\/runs\/recorded\/built-(before|after)/);
    await page.getByRole("link", { name: "Runs", exact: true }).first().click();
  }
  expect(await importDelta(page, "changed")).toBe(201);
  expect(await importDelta(page, "refused")).toBe(201);
  await page.reload();

  const pairs = page.getByRole("region", { name: "Before against after" });
  const pair = pairs.getByRole("listitem").filter({ hasText: "The settings of sensor auditd" });
  await expect(pair.getByText("1 better, 0 worse, 0 changed without a cause, of 91 paired steps")).toBeVisible();
  const noVerdict = pairs.getByRole("listitem").filter({ hasText: "Nothing declared as changed" });
  await expect(noVerdict.getByText(`No verdict: ${(refused.refused_because[0] ?? "").replaceAll("`", "")}`, { exact: false })).toBeVisible();

  await pair.getByRole("link", { name: "The settings of sensor auditd" }).click();
  await expect(page).toHaveURL(/#\/runs\/compared\/[0-9a-f]{16}$/);
  const address = page.url();
  await expect(page.getByRole("heading", { level: 1, name: "One change: the settings of sensor auditd" })).toBeVisible();
  await expect(page.getByText(/^Imported\. BlueFire checked that this comparison follows the delta format/)).toBeVisible();
  const better = changed.steps.find((step) => step.result === "better");
  if (!better) throw new Error("The lab's delta should hold one better step.");
  const moved = page.getByRole("region", { name: /^What the change moved/ });
  await expect(moved).toContainText(better.verdict);
  await expect(moved.getByText(/^price: /)).toBeVisible();
  await expect(page.getByRole("region", { name: /^The control/ })).toContainText(`the same on ${changed.control.same} of ${changed.control.of} paired steps`);

  // The step's detail opens for both runs, the address keeps it, and Back closes it.
  await moved.getByRole("button", { name: new RegExp(UNSEEN.replace(/[()]/g, "\\$&")) }).click();
  const detail = page.getByRole("region", { name: `${UNSEEN}, before and after` });
  await expect(detail.getByRole("heading", { name: `${UNSEEN}, before and after` })).toBeFocused();
  await expect(page).toHaveURL(/\?step=/);
  await expect(detail.getByRole("article")).toHaveCount(2);
  const [before, after] = await detail.getByRole("article").all();
  if (!before || !after) throw new Error("The detail should show both runs.");
  await expect(before).toContainText("It took effect, and no sensor recorded it.");
  await expect(after).toContainText("1 event recorded");
  await page.goBack();
  await expect(detail).toHaveCount(0);
  expect(page.url()).toBe(address);

  // The refused pair, real: No verdict, with its reason, as prominent as a verdict.
  await page.getByRole("link", { name: "Runs", exact: true }).first().click();
  await pairs.getByRole("link", { name: "Nothing declared as changed" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "No verdict" })).toBeVisible();
  // The lab's code spans read as code, without their backticks.
  for (const reason of refused.refused_because) await expect(page.getByText(reason.replaceAll("`", ""), { exact: true })).toBeVisible();
  expect(problems).toEqual([]);
});
