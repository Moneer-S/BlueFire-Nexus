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
  const item = pairs.getByRole("listitem").filter({ hasText: "New auditd settings" });
  await expect(item.getByText("Shipped with BlueFire")).toBeVisible();
  await expect(item.getByText("Two runs side by side, 24 Nov 2026")).toBeVisible();
  await expect(item.getByText("90 of 91 steps the same")).toBeVisible();
  // The price the service lists with the step, in plain words.
  await expect(item.getByText("2 published rules alert on ordinary activity, before and after", { exact: true })).toBeVisible();
  // The pair's two runs open from the pair, and are not listed again as runs of their own.
  await expect(item.getByRole("link", { name: /^Play the before run/ })).toBeVisible();
  await expect(item.getByRole("link", { name: /^Play the after run/ })).toBeVisible();
  await expect(recorded.getByRole("link", { name: "60 published tests on one Linux host", exact: true })).toHaveCount(1);
  // The pair's two runs and the run evaluated twice, which is one run.
  await expect(recorded.getByText("3 more recorded runs are listed with their pairs under Before against after.")).toBeVisible();
  // The pairs in the order the loop went: the watch, then the rule drafted from what it saw.
  await expect(pairs.getByRole("listitem").getByRole("heading", { level: 4 })).toHaveText(["Clear Bash history (echo) went from unseen to seen.", "4 steps went from seen to alerted."]);

  await item.getByRole("link", { name: "Clear Bash history (echo) went from unseen to seen." }).click();
  await expect(page).toHaveURL(/#\/runs\/compared\/[0-9a-f]{16}$/);
  const address = page.url();
  await expect(page.getByRole("heading", { level: 1, name: "Clear Bash history (echo) went from unseen to seen." })).toBeVisible();
  await expect(page.getByRole("region", { name: /^A limited verdict/ })).toHaveCount(0);
  await expect(page.getByRole("navigation", { name: "Compared runs" }).getByText("Turn 1: New auditd settings")).toBeVisible();

  // How we know: the one CI run that made both runs and the comparison, confirmed as the shipped example's is.
  await page.getByText("How we know").click();
  const proof = page.locator("#cmp-fair");
  await expect(proof.getByText("The same steps, made with the same setup apart from this change, side by side in one CI run, each on a fresh runner of its own.", { exact: false })).toBeVisible();
  await expect(proof.getByRole("link", { name: "run 45365902367" }).first()).toHaveAttribute("href", pair.after.run_url);
  const better = pair.steps.find((step) => step.result === "better");
  if (!better?.price) throw new Error("The shipped pair should hold one better step with its price.");
  expect(better.title).toBe(MOVED);
  const words = page.getByRole("region", { name: "Each step that differs, in the comparison's words" });
  await expect(words).toContainText(better.verdict);
  await expect(words.getByText(better.price, { exact: true })).toBeVisible();
  await expect(proof).toContainText(`the same on ${pair.control.same} of ${pair.control.of} paired steps`);
  await expect(page.getByRole("region", { name: "What made the difference" })).toContainText("What sensor auditd recorded of it in one run only");

  // The step's whole detail opens from both recordings, the address keeps it, and Back closes it.
  await page.getByRole("button", { name: "Every detail of this step, from both runs" }).click();
  const detail = page.getByRole("region", { name: `${MOVED}, every detail before and after` });
  await expect(detail.getByRole("heading", { name: `${MOVED}, every detail before and after` })).toBeFocused();
  await expect(page).toHaveURL(/\?step=.*detail=1/);
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
  await expect(page.getByRole("region", { name: `${MOVED}, every detail before and after` }).getByRole("article")).toHaveCount(2);

  // A refused pair, real too, sent to the route: No verdict with its reasons, as prominently as a verdict.
  await page.getByRole("link", { name: "Runs", exact: true }).first().click();
  expect(await importDelta(page, "refused")).toBe(201);
  await page.reload();
  const noVerdict = pairs.getByRole("listitem").filter({ hasText: "Nothing declared" });
  await expect(noVerdict.getByText(`No verdict: ${(refused.refused_because[0] ?? "").replaceAll("`", "")}`, { exact: false })).toBeVisible();
  await noVerdict.getByRole("link", { name: "No verdict." }).click();
  await expect(page.getByRole("heading", { level: 1, name: "No verdict." })).toBeVisible();
  // The lab's code spans read as code, without their backticks.
  for (const reason of refused.refused_because) await expect(page.getByText(reason.replaceAll("`", ""), { exact: true })).toBeVisible();
  expect(problems).toEqual([]);
});

const ruleFile = join(repository, "bluefire/data/recordings/deltas/lab-rule-history-truncated.json");
const RULE = "Shell History File Truncated In Place";
const HEADLINE = "4 steps went from seen to alerted.";

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
  await expect(item.getByText("Clear Bash history (echo) and (cat dev/null), each also with other arguments")).toBeVisible();
  await item.getByRole("link", { name: HEADLINE }).click();

  await expect(page.getByRole("heading", { level: 1, name: HEADLINE })).toBeVisible();
  await expect(page.getByText("One run, its telemetry read with two rule sets, 24 Nov 2026.", { exact: true })).toBeVisible();
  await page.getByText("How we know").click();
  const proof = page.locator("#cmp-fair");
  await expect(proof.getByText(/One run, evaluated twice: the list ran once, on one runner/)).toBeVisible();
  await expect(proof.getByRole("link", { name: "run 45395673682" }).first()).toHaveAttribute("href", rulePair.after.run_url);
  await expect(proof.getByRole("region", { name: "Each step that differs, in the comparison's words" }).getByText("better", { exact: true })).toHaveCount(4);

  // The rule: where its file is, how each evaluation judged it, and its text from the after recording.
  const rule = page.getByRole("article", { name: RULE });
  await expect(rule.getByText("lab/rules/linux/auditd/lnx_auditd_history_file_truncated_in_place.yml")).toBeVisible();
  await expect(rule.getByLabel("How each evaluation judged it")).toContainText("Beforenot there");
  await expect(rule.getByLabel("How each evaluation judged it")).toContainText("it alerted on every run with changed input arguments and on no ordinary activity");
  await expect(rule.getByLabel(`The text of the rule ${RULE}`)).toContainText("key: shell-history");

  // The steps it moved, each a row, each with the event its alert rests on, and the price not counted.
  const move = page.getByRole("region", { name: "What the change did" });
  await expect(move.getByRole("button", { name: /^Clear Bash history/ })).toHaveCount(4);
  await expect(move.getByRole("button", { pressed: true })).toHaveCount(1);
  const difference = page.getByRole("region", { name: "What made the difference" });
  await expect(difference.getByText("/home/bluefire-lab/.bash_history", { exact: true })).toHaveCount(2);
  await expect(difference.getByText("/home/bluefire-lab/.zsh_history", { exact: true })).toBeVisible();
  await expect(page.getByRole("region", { name: "What it cost" })).toContainText("Not counted");

  // A step's whole detail from both evaluations, each by its own file.
  await page.getByRole("button", { name: "Every detail of this step, from both runs" }).click();
  const detail = page.getByRole("region", { name: "Clear Bash history (echo), every detail before and after" });
  await expect(detail.getByRole("article")).toHaveCount(2);
  await expect(detail.getByRole("article").last()).toContainText(RULE);

  // The run opens with the head's rules by its own file.
  await page.getByRole("link", { name: "Play with the rules after" }).click();
  await expect(page).toHaveURL(new RegExp(`#/runs/recorded/${rulePair.after.id}/${rulePair.after.sha256}`));
  // The pair's page, whose step detail and price name the same rules, is gone before the run's page is read.
  await expect(page.getByRole("region", { name: "What the change did" })).toHaveCount(0);
  await expect(page.getByText("Rules written in this repository")).toBeVisible();
  expect(problems).toEqual([]);
});
