import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { expect, test } from "@playwright/test";
import { launchService } from "./start-service";

// The defender's loop in the real service, the whole way a user goes with what
// ships with the app and nothing imported: the watch's before run, the test
// nobody saw, "Fix this", what its recording says, what was already tried; the
// watch's own page; the same test in its after run, seen by one audit event,
// with an empty draft; the rule's comparison, made on a later run and tied to
// the test by its stable id; and in that comparison's after recording the test
// alerted, with the rule that alerted.

interface Step { id: string; title: string; visibility: { basis: string } }
interface Recording { steps: Step[] }

const repository = resolve(process.cwd(), "..");
const before: Recording = JSON.parse(readFileSync(join(repository, "bluefire/data/recordings/lab-pair-history-watch-before.json"), "utf-8"));
const TEST = "Clear Bash history (echo)";
const RULE = "Shell History File Truncated In Place";
let service: Awaited<ReturnType<typeof launchService>> | undefined;
let exampleService: Awaited<ReturnType<typeof launchService>> | undefined;

test.beforeAll(async () => {
  test.setTimeout(180_000);
  // A service for each test: a connection code opens one browser only.
  service = await launchService(8768);
  exampleService = await launchService(8769);
});

test.afterAll(async () => {
  await service?.stop();
  await exampleService?.stop();
});

test("Fix this walks the loop shipped with the app: the unseen test, the watch, the test seen in its after run, and the rule that made it alert", async ({ page }) => {
  test.setTimeout(180_000);
  const unseen = before.steps.find((step) => step.title === TEST);
  if (!unseen) throw new Error(`The watch's before run should hold ${TEST}.`);
  const problems: string[] = [];
  page.on("pageerror", (error) => problems.push(String(error)));
  page.on("response", (response) => {
    if (response.status() >= 400) problems.push(`${response.status()} ${response.url()}`);
  });
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(service?.url ?? "");
  await expect(page.getByText("Connected", { exact: true })).toBeVisible();

  // Runs, the watch's before run, the test nobody saw.
  await page.getByRole("link", { name: "Runs", exact: true }).click();
  const watch = page.getByRole("region", { name: "Before against after" }).getByRole("listitem").filter({ hasText: "The settings of sensor auditd" });
  await watch.getByRole("link", { name: /^Play the before run/ }).click();
  await page.getByRole("button", { name: "Analyse", exact: true }).click();
  await page.getByRole("button", { name: TEST, exact: true }).click();
  await page.getByRole("button", { name: "Fix this", exact: true }).click();
  await expect(page).toHaveURL(/#\/runs\/recorded\/[A-Za-z0-9_-]+\/[0-9a-f]{64}\/fix\//);
  await expect(page.getByRole("heading", { level: 1, name: TEST })).toBeFocused();

  // Where to start, a sensor before any rule; what the recording says, one quiet line away.
  await expect(page.getByRole("region", { name: "Where to start" })).toContainText("Nothing of this test was recorded. Start with a sensor's settings");
  const recorded = page.getByRole("region", { name: /^What was recorded/ });
  await expect(recorded.getByRole("article", { name: /^Sensor auditd/ })).toContainText("0 events of this step");
  await recorded.getByText("How we know", { exact: true }).click();
  await expect(recorded.getByText(unseen.visibility.basis, { exact: true })).toBeVisible();
  await expect(page.getByRole("textbox")).toHaveCount(0);
  await expect(page.getByRole("complementary", { name: "The model's place" })).toContainText("No model is connected. Nothing was sent.");

  // What was already tried, on the first screen: the watch, of which this run is the before, and the rule, on a later run tied by the test's id.
  const tried = page.getByRole("region", { name: /^What was already tried/ });
  const watchLine = tried.getByRole("listitem").filter({ hasText: "The settings of sensor auditd" });
  const ruleLine = tried.getByRole("listitem").filter({ hasText: `A new rule: ${RULE}` });
  await expect(watchLine).toContainText("This run is the one before the change.");
  await watchLine.getByText("The comparison's own words", { exact: true }).click();
  await expect(watchLine).toContainText("no telemetry to recorded by the sensors");
  await expect(ruleLine).toContainText(`Another run of the same list, not this one, with the same published test. Step ${unseen.id}`);
  const fixing = page.url();

  // The watch's own page, at the step.
  await watchLine.getByRole("link", { name: "Open the comparison at this step" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "One change: the settings of sensor auditd" })).toBeVisible();
  await expect(page.getByRole("region", { name: `${TEST}, before and after` }).getByRole("article")).toHaveCount(2);
  await page.goBack();
  await expect(page).toHaveURL(fixing);

  // The same test in the after run, and "Fix this" there: the event the watch recorded, and an empty draft.
  await page.getByRole("region", { name: /^What was already tried/ }).getByRole("listitem").filter({ hasText: "The settings of sensor auditd" }).getByRole("link", { name: "Open the same step in the after run" }).click();
  await expect(page.getByRole("heading", { name: TEST, exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Fix this", exact: true }).click();
  await expect(page.getByRole("heading", { level: 1, name: TEST })).toBeVisible();
  const auditd = page.getByRole("region", { name: /^What was recorded/ }).getByRole("article", { name: /^Sensor auditd/ });
  await expect(auditd).toContainText("1 event of this step");
  await expect(auditd.getByRole("table")).toContainText("/home/bluefire-lab/.bash_history");
  await expect(auditd.getByRole("table")).toContainText("audit key shell-history");
  await expect(page.getByRole("region", { name: "Rules that matched it" })).toContainText("Use Of Hidden Paths Or Files");
  await expect(page.getByRole("textbox", { name: "Your rule" })).toHaveValue("");
  await expect(page.getByText("Kept in this browser only. The file in the repository is what runs.")).toBeVisible();
  const afterTried = page.getByRole("region", { name: /^What was already tried/ });
  await expect(afterTried.getByRole("listitem").filter({ hasText: "The settings of sensor auditd" })).toContainText("This run is the one after the change.");

  // The rule's comparison, where the ids tie the runs, and on its after recording the test alerted with the rule that alerted.
  await afterTried.getByRole("listitem").filter({ hasText: `A new rule: ${RULE}` }).getByRole("link", { name: "Open the comparison at this step" }).click();
  await expect(page.getByRole("heading", { level: 1, name: `A new rule: ${RULE}` })).toBeVisible();
  await page.getByRole("region", { name: "The run" }).getByRole("link", { name: /Open with the rules after/ }).click();
  await page.getByRole("button", { name: "Analyse", exact: true }).click();
  // The test comes before its run with changed input arguments, which has the same title.
  await page.getByRole("button", { name: TEST, exact: true }).first().click();
  await page.getByRole("button", { name: "Fix this", exact: true }).click();
  await expect(page.getByRole("region", { name: "Where to start" })).toContainText("One of the lab's own rules raised an alert on it: it is caught.");
  const rule = page.getByRole("region", { name: "Rules that matched it" }).getByRole("article", { name: RULE });
  await expect(rule).toContainText("accepted");
  await expect(rule).toContainText("lab/rules/linux/auditd/lnx_auditd_history_file_truncated_in_place.yml");
  await expect(rule.getByLabel(`The text of the rule ${RULE}`)).toContainText("key: shell-history");
  await expect(page.getByRole("textbox")).toHaveCount(0);
  await expect(page.getByRole("region", { name: /^What was already tried/ }).getByRole("listitem").filter({ hasText: `A new rule: ${RULE}` })).toContainText("This run, with the rules from after the change.");
  expect(problems).toEqual([]);
});

test("Fix this on the example shipped with the app reaches both shipped comparisons by the published test's id, as other runs", async ({ page }) => {
  test.setTimeout(120_000);
  const problems: string[] = [];
  page.on("pageerror", (error) => problems.push(String(error)));
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(exampleService?.url ?? "");
  await expect(page.getByText("Connected", { exact: true })).toBeVisible();
  await page.getByRole("link", { name: "Runs", exact: true }).click();
  await page.getByRole("region", { name: "Recorded runs" }).getByRole("link", { name: "60 published tests on one Linux host" }).click();
  // Test 40 of the example is the one nothing recorded; the example is older than stable ids, so its step id is "43".
  await page.goto(page.url().replace(/(#\/runs\/recorded\/[A-Za-z0-9_-]+).*$/, "$1/fix/43"));
  await expect(page.getByRole("heading", { level: 1, name: TEST })).toBeVisible();
  const tried = page.getByRole("region", { name: /^What was already tried/ });
  const watchLine = tried.getByRole("listitem").filter({ hasText: "The settings of sensor auditd" });
  const ruleLine = tried.getByRole("listitem").filter({ hasText: `A new rule: ${RULE}` });
  for (const line of [watchLine, ruleLine]) {
    await expect(line).toContainText("Another run of the same list, not this one, with the same published test as the list runs it. Published test cbf506a5");
  }
  await expect(watchLine).toBeInViewport({ ratio: 1 });
  // The watch's page opens at the same test, now recorded.
  await watchLine.getByRole("link", { name: "Open the comparison at this step" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "One change: the settings of sensor auditd" })).toBeVisible();
  await expect(page.getByRole("region", { name: `${TEST}, before and after` })).toBeVisible();
  await page.goBack();
  // The rule's page opens at the same test, alerted with the lab's rules.
  await page.getByRole("region", { name: /^What was already tried/ }).getByRole("listitem").filter({ hasText: `A new rule: ${RULE}` }).getByRole("link", { name: "Open the comparison at this step" }).click();
  await expect(page.getByRole("heading", { level: 1, name: `A new rule: ${RULE}` })).toBeVisible();
  await expect(page).toHaveURL(/\?step=test%3Acbf506a5$/);
  expect(problems).toEqual([]);
});
