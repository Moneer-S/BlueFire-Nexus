import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { expect, test } from "@playwright/test";
import { day, span } from "../../src/live/format";
import { launchService } from "./start-service";

// The path through range one that ships with the app, in the real service: it
// is listed on Runs as an attack path with its score and its race, plays on a
// map of the range's network from the first step to the goal, and "Fix this"
// on a step seen with no alert says where a range's defense is set.

interface Host { id: string; name: string }
interface Step { id: string; title: string; plain?: string; outcome: string }
interface Recording {
  title: string;
  source: { started: string };
  network: { hosts: Host[]; sensors: { id: string; host: string }[]; detectors: { id: string; name: string }[] };
  attacker: { goal: string | null };
  steps: Step[];
  events: { sensor: string; step?: string }[];
  score: { steps: number; alerted: number; seen: number; unseen: number; first_alert_seconds?: number; goal_seconds?: number };
  defenses: { id: string; name: string }[];
}

/** The agent that recorded a step, by its host's name as the page labels it, and how many of the step's events it recorded. */
function recordedBy(recording: Recording, stepId: string): { host: string; events: string } {
  const events = recording.events.filter((event) => event.step === stepId);
  const sensor = recording.network.sensors.find((item) => events.some((event) => event.sensor === item.id));
  const host = recording.network.hosts.find((item) => item.id === sensor?.host);
  if (!sensor || !host) throw new Error(`No agent recorded step ${stepId}.`);
  const own = events.filter((event) => event.sensor === sensor.id).length;
  return { host: host.name, events: `${own} ${own === 1 ? "event" : "events"} of this step` };
}

const repository = resolve(process.cwd(), "..");
const path: Recording = JSON.parse(readFileSync(join(repository, "bluefire/data/recordings/lab-range-one-path.json"), "utf-8"));
let service: Awaited<ReturnType<typeof launchService>> | undefined;

test.beforeAll(async () => {
  test.setTimeout(180_000);
  service = await launchService(8770);
});

test.afterAll(async () => {
  await service?.stop();
});

test("the path through range one is listed on Runs, plays across the range's hosts to the goal, and Fix this says where the range's defense is set", async ({ page }) => {
  test.setTimeout(180_000);
  // The words below are the recording's own: its title, score and race, read from the shipped file.
  const { first_alert_seconds: alert, goal_seconds: goal } = path.score;
  if (alert === undefined || goal === undefined || !path.attacker.goal || alert > goal) throw new Error("The path should name its goal, and alert before reaching it.");
  const race = span((goal - alert) * 1000);
  const first = path.steps[0];
  const last = path.steps[path.steps.length - 1];
  // The port scan of build from web: seen with no alert, recorded by build's agent.
  const seen = path.steps.find((step) => step.id === "s05a");
  if (!first || !last || !seen || seen.outcome !== "seen") throw new Error("The path should run from s01 to s10, with s05a seen and no alert.");
  const seenBy = recordedBy(path, seen.id);
  // The goal ran against inet, which has no agent: the agent of the host it ran from recorded it.
  const lastBy = recordedBy(path, last.id);

  const problems: string[] = [];
  page.on("pageerror", (error) => problems.push(String(error)));
  page.on("response", (response) => {
    if (response.status() >= 400) problems.push(`${response.status()} ${response.url()}`);
  });
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(service?.url ?? "");
  await expect(page.getByText("Connected", { exact: true })).toBeVisible();

  // Runs: the path is the first recorded run, and says what it is, where it was recorded, its score and its race.
  await page.getByRole("link", { name: "Runs", exact: true }).click();
  const recorded = page.getByRole("region", { name: "Recorded runs" });
  await expect(recorded.getByRole("listitem").first()).toContainText(path.title);
  const item = recorded.getByRole("listitem").filter({ hasText: path.title });
  await expect(item.getByText("Attack path", { exact: true })).toBeVisible();
  await expect(item.getByText(`Recorded on a GitHub-hosted runner, ${day(path.source.started)}`, { exact: true })).toBeVisible();
  await expect(item.getByText("Shipped with BlueFire", { exact: true })).toBeVisible();
  await expect(item.getByText(`${path.score.alerted} of ${path.score.steps} steps alerted, ${path.score.seen} seen, ${path.score.unseen} unseen`, { exact: true })).toBeVisible();
  await expect(item.getByText(`The first alert came after ${span(alert * 1000)}, ${race} before the attacker reached the goal`, { exact: true })).toBeVisible();

  // It opens in the live view, at its first step, on a map of every host of the range.
  await item.getByRole("link", { name: path.title, exact: true }).click();
  await expect(page).toHaveURL(/#\/runs\/recorded\/[A-Za-z0-9_-]+/);
  const defenses = page.getByRole("group", { name: "The defenses that judge this run" });
  await expect(defenses.getByRole("button")).toHaveCount(5);
  await expect(defenses.getByRole("button", { name: /Wazuh with its stock rules/ })).toHaveAttribute("aria-pressed", "true");
  await page.getByRole("button", { name: "Pause", exact: true }).click();
  if (first.plain) await expect(page.getByText(first.plain, { exact: true })).toBeVisible();
  const map = page.getByRole("region", { name: "Network map" });
  for (const host of path.network.hosts) await expect(map.getByText(host.name, { exact: true }).first()).toBeVisible();

  // On along the timeline, step by step, to the last step and the end of the run: the goal, after the alert.
  const timeline = page.getByRole("slider", { name: /^Timeline/ });
  await timeline.focus();
  for (let moved = 1; moved < path.steps.length; moved += 1) await page.keyboard.press("ArrowRight");
  if (last.plain) await expect(page.getByText(last.plain, { exact: true })).toBeVisible();
  await page.keyboard.press("End");
  await expect(page.getByText(`The attacker reached its goal, “${path.attacker.goal}”, ${race} after the first alert, with no step stopped.`, { exact: true })).toBeVisible();

  // A step seen with no alert: Fix this says to start with a rule, and where a range's rules and sensors are set.
  await page.goto(page.url().replace(/(#\/runs\/recorded\/[A-Za-z0-9_-]+).*$/, `$1?step=${seen.id}&at=1&paused=1`));
  if (seen.plain) await expect(page.getByText(seen.plain, { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Fix this", exact: true }).click();
  await expect(page.getByRole("heading", { level: 1, name: seen.title })).toBeFocused();
  const start = page.getByRole("region", { name: "Where to start" });
  await expect(start).toContainText("A sensor recorded this step, but no rule raised an alert. Start with a rule");
  // The step is named as the live view names it.
  await expect(page.getByText("step 5", { exact: true })).toBeVisible();
  await expect(page.getByRole("region", { name: /^What was already tried/ })).toContainText("No comparison has moved this step yet.");
  const rules = path.network.detectors.find((detector) => detector.id === "pinned")?.name;
  if (!rules) throw new Error("The path should name the rules that ran.");
  await expect(start).toContainText(`The rules that ran in this range were ${rules}. The range has no rules of the lab's own yet. A new rule goes into the manager's image,`);
  await expect(start).not.toContainText("lab/rules/linux/");
  await expect(page.getByRole("region", { name: /^What was recorded/ }).getByRole("article", { name: `Sensor Wazuh agent on ${seenBy.host}` })).toContainText(seenBy.events);
  await expect(page.getByRole("textbox", { name: "Your rule" })).toHaveValue("");
  await expect(page.getByRole("region", { name: "Running it again" })).toContainText("Its CI builds the range, runs the path through it again");

  // The goal's fix page shows the events the agent of the host it ran from recorded of it.
  await page.goto(page.url().replace(/\/fix\/[^?]+/, `/fix/${last.id}`));
  await expect(page.getByRole("heading", { level: 1, name: last.title })).toBeVisible();
  await expect(page.getByRole("region", { name: /^What was recorded/ }).getByRole("article", { name: `Sensor Wazuh agent on ${lastBy.host}` })).toContainText(lastBy.events);
  expect(problems).toEqual([]);
});
