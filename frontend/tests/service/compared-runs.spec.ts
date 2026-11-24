import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { expect, test, type Page } from "@playwright/test";
import { launchService } from "./start-service";

// Compared runs in the real service. The pair shipped with the app is real: two
// runs side by side in one CI run, before and after an audit watch on the test
// account's shell history files, and the lab's delta of them, all as the lab
// wrote them. It is opened as it ships, with nothing imported. The refused pair
// is real too: the shipped example compared with itself, which the lab refuses
// for want of source.setup, sent to the service's route.

interface DeltaStep { id: string; title: string; result: string; verdict: string; price?: string }
interface Delta { steps: DeltaStep[]; control: { same: number; of: number }; refused_because: string[]; after: { run_url: string } }

const repository = resolve(process.cwd(), "..");
const shippedFile = join(repository, "bluefire/data/recordings/lab-linux-host.json");
const pairFile = join(repository, "bluefire/data/recordings/deltas/lab-pair-history-watch.json");
const pair: Delta = JSON.parse(readFileSync(pairFile, "utf-8"));
const MOVED = "Clear Bash history (echo)";
let workspace = "";
let service: Awaited<ReturnType<typeof launchService>> | undefined;
// A connection code opens one browser once: the run evaluated twice is read through a service of its own.
let ruleService: Awaited<ReturnType<typeof launchService>> | undefined;
let refused: Delta;

function bluefireLab(...args: string[]): void {
  const run = spawnSync(process.env.BLUEFIRE_PYTHON ?? "python3", ["-m", "bluefire_lab", ...args], { cwd: join(repository, "lab"), encoding: "utf-8" });
  if (run.status !== 0) throw new Error(`bluefire-lab ${args.join(" ")} exited with ${run.status}:\n${run.stdout}\n${run.stderr}`);
}

test.beforeAll(async () => {
  test.setTimeout(120_000);
  // A service of its own: the shared one's connection code opens one browser only, the screens test's.
  service = await launchService(8766);
  ruleService = await launchService(8767);
  workspace = mkdtempSync(join(tmpdir(), "bluefire-pairs-"));
  bluefireLab("compare", shippedFile, shippedFile, "--out", join(workspace, "refused"));
  refused = JSON.parse(readFileSync(join(workspace, "refused", "delta.json"), "utf-8"));
});

test.afterAll(async () => {
  if (workspace) rmSync(workspace, { recursive: true, force: true });
  await service?.stop();
  await ruleService?.stop();
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

test("the pair shipped with the app is listed on Runs and read on its own page as a claim with its price, and a refused pair as No verdict", async ({ page }) => {
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

  const recorded = page.getByRole("region", { name: "Recorded runs" });
  const pairs = page.getByRole("region", { name: "Before against after" });
  const item = pairs.getByRole("listitem").filter({ hasText: "The settings of sensor auditd" });
  await expect(item.getByText("Shipped with BlueFire")).toBeVisible();
  await expect(item.getByText("Two runs side by side, 24 Nov 2026")).toBeVisible();
  await expect(item.getByText("1 better, 0 worse, 0 changed without a cause, of 91 paired steps")).toBeVisible();
  // The pair's two runs open from the pair, and are not listed again as runs of their own.
  await expect(item.getByRole("link", { name: /^Play the before run/ })).toBeVisible();
  await expect(item.getByRole("link", { name: /^Play the after run/ })).toBeVisible();
  await expect(recorded.getByRole("link", { name: "60 published tests on one Linux host", exact: true })).toHaveCount(1);
  // The pair's two runs and the run evaluated twice, which is one run.
  await expect(recorded.getByText("3 more recorded runs are listed with their pairs under Before against after.")).toBeVisible();
  // The pairs in the order the loop went: the watch, then the rule drafted from what it saw.
  await expect(pairs.getByRole("listitem")).toHaveText([/^The settings of sensor auditd/, /^A new rule: Shell History File Truncated In Place/]);

  await item.getByRole("link", { name: "The settings of sensor auditd" }).click();
  await expect(page).toHaveURL(/#\/runs\/compared\/[0-9a-f]{16}$/);
  const address = page.url();
  await expect(page.getByRole("heading", { level: 1, name: "One change: the settings of sensor auditd" })).toBeVisible();
  await expect(page.getByText("The same steps, made with the same setup apart from this change, side by side in one CI run, each on a fresh runner of its own.")).toBeVisible();
  await expect(page.getByRole("region", { name: /^A limited verdict/ })).toHaveCount(0);
  // Where it comes from: the one CI run that made both runs and the comparison, confirmed as the shipped example's is.
  const bar = page.getByRole("navigation", { name: "Compared runs" });
  await expect(bar.getByText("Shipped with BlueFire")).toBeVisible();
  await expect(bar.getByRole("link", { name: "run 45365902367" })).toHaveAttribute("href", pair.after.run_url);

  const better = pair.steps.find((step) => step.result === "better");
  if (!better?.price) throw new Error("The shipped pair should hold one better step with its price.");
  expect(better.title).toBe(MOVED);
  const moved = page.getByRole("region", { name: /^What the change moved/ });
  await expect(moved).toContainText(better.verdict);
  await expect(moved.getByText(better.price, { exact: true })).toBeVisible();
  await expect(moved).toContainText("What sensor auditd recorded of it in one run only");
  await expect(page.getByRole("region", { name: /^The control/ })).toContainText(`the same on ${pair.control.same} of ${pair.control.of} paired steps`);

  // The step's detail opens from both recordings, the address keeps it, and Back closes it.
  await moved.getByRole("button", { name: new RegExp(MOVED.replace(/[()]/g, "\\$&")) }).click();
  const detail = page.getByRole("region", { name: `${MOVED}, before and after` });
  await expect(detail.getByRole("heading", { name: `${MOVED}, before and after` })).toBeFocused();
  await expect(page).toHaveURL(/\?step=/);
  await expect(detail.getByRole("article")).toHaveCount(2);
  const [before, after] = await detail.getByRole("article").all();
  if (!before || !after) throw new Error("The detail should show both runs.");
  await expect(before).toContainText("It took effect, and nothing of the test was recorded besides its launcher's start.");
  await expect(after).toContainText("1 event recorded");
  const opened = page.url();
  await page.goBack();
  await expect(detail).toHaveCount(0);
  expect(page.url()).toBe(address);
  // The address of the open step is one that can be shared.
  await page.goto(opened);
  await expect(page.getByRole("region", { name: `${MOVED}, before and after` }).getByRole("article")).toHaveCount(2);

  // A refused pair, real too, sent to the route: No verdict with its reasons, as prominently as a verdict.
  await page.getByRole("link", { name: "Runs", exact: true }).first().click();
  expect(await importDelta(page, "refused")).toBe(201);
  await page.reload();
  const noVerdict = pairs.getByRole("listitem").filter({ hasText: "Nothing declared as changed" });
  await expect(noVerdict.getByText(`No verdict: ${(refused.refused_because[0] ?? "").replaceAll("`", "")}`, { exact: false })).toBeVisible();
  await pairs.getByRole("link", { name: "Nothing declared as changed" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "No verdict" })).toBeVisible();
  // The lab's code spans read as code, without their backticks.
  for (const reason of refused.refused_because) await expect(page.getByText(reason.replaceAll("`", ""), { exact: true })).toBeVisible();
  expect(problems).toEqual([]);
});

const ruleFile = join(repository, "bluefire/data/recordings/deltas/lab-rule-history-truncated.json");
const RULE = "Shell History File Truncated In Place";

test("the run evaluated with two rule sets shipped with the app reads as one run, with its rule, the steps it moved and the event each alert rests on", async ({ page }) => {
  test.setTimeout(120_000);
  const rulePair: Delta & { after: { id: string; sha256: string; run_url: string } } = JSON.parse(readFileSync(ruleFile, "utf-8"));
  const problems: string[] = [];
  page.on("pageerror", (error) => problems.push(String(error)));
  page.on("response", (response) => {
    if (response.status() >= 400) problems.push(`${response.status()} ${response.url()}`);
  });
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(ruleService?.url ?? "");
  await expect(page.getByText("Connected", { exact: true })).toBeVisible();
  await page.getByRole("link", { name: "Runs", exact: true }).click();

  const item = page.getByRole("region", { name: "Before against after" }).getByRole("listitem").filter({ hasText: RULE });
  await expect(item.getByText("One run evaluated with two rule sets, 24 Nov 2026")).toBeVisible();
  await expect(item.getByText("Clear Bash history (echo) and Clear Bash history (cat dev/null), each also with changed input arguments: seen to alerted with the lab's rules")).toBeVisible();
  await item.getByRole("link", { name: `A new rule: ${RULE}` }).click();

  await expect(page.getByRole("heading", { level: 1, name: `A new rule: ${RULE}` })).toBeVisible();
  await expect(page.getByText(/^One run, evaluated twice: the list ran once, on one runner/)).toBeVisible();
  await expect(page.getByRole("region", { name: "The two runs" })).toHaveCount(0);
  const bar = page.getByRole("navigation", { name: "Compared runs" });
  await expect(bar.getByRole("link", { name: "run 45395673682" })).toHaveAttribute("href", rulePair.after.run_url);

  // The rule: where its file is, how each evaluation judged it, and its text from the after recording.
  const rule = page.getByRole("article", { name: RULE });
  await expect(rule.getByText("lab/rules/linux/auditd/lnx_auditd_history_file_truncated_in_place.yml")).toBeVisible();
  await expect(rule.getByLabel("How each evaluation judged it")).toContainText("Beforenot there");
  await expect(rule.getByLabel("How each evaluation judged it")).toContainText("it alerted on every run with changed input arguments and on no ordinary activity");
  await expect(rule.getByLabel(`The text of the rule ${RULE}`)).toContainText("key: shell-history");

  // The steps it moved, each with the event its alert rests on, and the price said once.
  const moved = page.getByRole("region", { name: /^What the change moved/ });
  await expect(moved.locator(".cmp-step")).toHaveCount(4);
  await expect(moved.getByText("auditd openat: /home/bluefire-lab/.bash_history")).toHaveCount(2);
  await expect(moved.getByText("auditd openat: /home/bluefire-lab/.zsh_history")).toBeVisible();
  await expect(moved.getByRole("heading", { name: /^The price/ })).toBeVisible();
  await expect(page.getByText(`All of this rests on one run evaluated with two rule sets.`)).toBeVisible();

  // A step's detail from both evaluations, each by its own file.
  await moved.locator(".cmp-step").first().getByRole("button", { name: /Clear Bash history \(echo\)/ }).click();
  const detail = page.getByRole("region", { name: "Clear Bash history (echo), before and after" });
  await expect(detail.getByRole("article")).toHaveCount(2);
  await expect(detail.getByRole("article").last()).toContainText(RULE);

  // The run opens with the head's rules by its own file.
  await page.getByRole("region", { name: "The run" }).getByRole("link", { name: /Open with the rules after/ }).click();
  await expect(page).toHaveURL(new RegExp(`#/runs/recorded/${rulePair.after.id}/${rulePair.after.sha256}`));
  // The pair's page, whose step detail and price name the same rules, is gone before the run's page is read.
  await expect(page.getByRole("region", { name: "The run" })).toHaveCount(0);
  await expect(page.getByText("Rules written in this repository")).toBeVisible();
  expect(problems).toEqual([]);
});
