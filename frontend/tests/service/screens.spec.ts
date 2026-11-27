import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { expect, test } from "@playwright/test";

/** A small recording that follows the format: two steps of an attack path, one alerted and one seen. */
function smallRecording() {
  return {
    schema: "bluefire.recording/1",
    id: "small-attack-path",
    title: "Two steps toward a secrets file",
    kind: "attack path",
    source: { engine: "test-engine", environment: "containers on a developer machine", started: "2026-11-20T10:00:00Z", finished: "2026-11-20T10:05:00Z", tools: [] },
    network: {
      hosts: [{ id: "web", name: "web", role: "web application", kind: "host" }],
      sensors: [{ id: "sysmon", name: "Sysmon for Linux 1.6.0", host: "web", records: "program starts" }],
      detectors: [{ id: "pinned", name: "Published Sigma rules", rules: 10, when: "after the run" }],
    },
    attacker: { kind: "scripted", description: "A short script.", goal: "Read the web server's secrets file." },
    steps: [
      {
        id: "1", order: 1, role: "test", title: "Discover the host", plain: "Prints what system the host runs.", technique: { id: "T1082" }, host: "web",
        started: "2026-11-20T10:01:00.000Z", ended: "2026-11-20T10:01:02.000Z",
        happened: { answer: "took effect", basis: "the command exited with status 0" },
        visibility: { answer: "alert", basis: "a published rule matched at level high", events: 1 },
        outcome: "alerted", first_event: "2026-11-20T10:01:00.500Z", first_alert: "2026-11-20T10:01:00.500Z",
      },
      {
        id: "2", order: 2, role: "test", title: "Read the secrets file", plain: "Reads the web server's secrets file.", technique: { id: "T1005" }, host: "web",
        started: "2026-11-20T10:02:00.000Z", ended: "2026-11-20T10:02:03.000Z",
        happened: { answer: "took effect", basis: "the file was read" },
        visibility: { answer: "telemetry only", basis: "a sensor recorded it, no rule at alert level matched", events: 1 },
        outcome: "seen", first_event: "2026-11-20T10:02:01.000Z",
      },
    ],
    events: [
      { id: "e1", time: "2026-11-20T10:01:00.500Z", host: "web", sensor: "sysmon", kind: "process start", text: "uname -a", step: "1", tied_by: "session" },
      { id: "e2", time: "2026-11-20T10:02:01.000Z", host: "web", sensor: "sysmon", kind: "process start", text: "cat /srv/secrets", step: "2", tied_by: "session" },
    ],
    alerts: [{
      id: "a1", time: "2026-11-20T10:01:00.500Z", host: "web", detector: "pinned",
      rule: { id: "r1", title: "System Information Discovery", level: "high", origin: "pinned" }, counts: true, step: "1", events: ["e1"],
    }],
    score: { steps: 2, took_effect: 2, alerted: 1, seen: 1, unseen: 0, stopped: 0, first_alert_seconds: 0.5, goal_seconds: 63 },
    notes: [],
  };
}

/** The path through range one that ships with BlueFire: its title and score, read from the shipped file. */
const shippedPath = JSON.parse(readFileSync(join(resolve(process.cwd(), ".."), "bluefire/data/recordings/lab-range-one-path.json"), "utf-8")) as {
  title: string;
  score: { steps: number; alerted: number; seen: number; unseen: number };
};
const shippedPathScore = `${shippedPath.score.alerted} of ${shippedPath.score.steps} steps alerted, ${shippedPath.score.seen} seen, ${shippedPath.score.unseen} unseen`;


/** The same real path judged by two defenses that disagree on which step alerted. */
function multiDefenseRecording() {
  const base = smallRecording();
  const [first, second] = base.steps;
  if (!first || !second) throw new Error("The small recording must have two steps.");
  const verdict = (step: (typeof base.steps)[number]) => ({
    visibility: step.visibility,
    outcome: step.outcome,
    first_event: step.first_event,
    ...("first_alert" in step ? { first_alert: step.first_alert } : {}),
  });
  const secondAlertAt = "2026-11-20T10:02:01.200Z";
  const capture = { id: "capture", name: "Packet capture", host: "web", records: "packets" };
  const sigma = { id: "sigma", name: "Sigma rules over packets", rules: 3, when: "after the run" };
  const captured = { id: "e3", time: secondAlertAt, host: "web", sensor: "capture", kind: "packet", text: "a packet to the secrets service", step: "2", tied_by: "session" };
  const captureAlert = {
    id: "a2",
    time: secondAlertAt,
    host: "web",
    detector: "sigma",
    rule: { id: "r2", title: "Connection to the secrets service", level: "high", origin: "pinned" },
    counts: true,
    step: "2",
    events: ["e3"],
  };
  return {
    ...base,
    id: "small-judged-twice",
    title: "One path, judged by two defenses",
    network: { ...base.network, sensors: [...base.network.sensors, capture], detectors: [...base.network.detectors, sigma] },
    events: [...base.events, captured],
    alerts: [...base.alerts, captureAlert],
    defenses: [
      {
        id: "sysmon-alone",
        name: "Sysmon with the published rules",
        sensors: ["sysmon"],
        detectors: ["pinned"],
        steps: { "1": verdict(first), "2": verdict(second) },
        score: { ...base.score },
      },
      {
        id: "with-capture",
        name: "Sysmon, packet capture and Sigma",
        sensors: ["sysmon", "capture"],
        detectors: ["sigma"],
        steps: {
          "1": { visibility: { answer: "telemetry only", basis: "Sysmon recorded it but Sigma did not alert", events: 1 }, outcome: "seen", first_event: first.first_event },
          "2": { visibility: { answer: "alert", basis: "Sigma matched the captured packet", events: 2 }, outcome: "alerted", first_event: second.first_event, first_alert: secondAlertAt },
        },
        score: { ...base.score, first_alert_seconds: 61.2 },
      },
    ],
  };
}
function file(name: string, value: unknown) {
  return { name, mimeType: "application/json", buffer: Buffer.from(JSON.stringify(value)) };
}

// The demo build's tests never reach the service. This one opens the address
// the real service prints and walks the main screens it serves.
test("the service serves the interface, and its main screens open on a fresh workspace", async ({ page }) => {
  // The walk waits on a running recording's polling, which takes some seconds of its own.
  test.setTimeout(120_000);
  const problems: string[] = [];
  page.on("pageerror", error => problems.push(String(error)));
  page.on("response", response => {
    if (response.status() >= 500) problems.push(`${response.status()} ${response.url()}`);
  });

  await page.goto(process.env.BLUEFIRE_SERVICE_URL ?? "");
  await expect(page.getByRole("heading", { name: "Overview", exact: true })).toBeVisible();
  await expect(page.getByText("Connected", { exact: true })).toBeVisible();
  // The Overview leads with the first run Runs lists on its own, shipped with BlueFire, to watch, and the
  // turns of the loop under it, above the workspace's own blocks. On a fresh workspace that run is the
  // shipped path through range one, recorded after the shipped pairs' runs.
  const real = page.getByRole("region", { name: "A run recorded in CI" });
  await expect(real.getByText(shippedPath.title, { exact: true })).toBeVisible();
  await expect(real.getByText(shippedPathScore, { exact: true })).toBeVisible();
  const play = real.getByRole("link", { name: /^Play the run/ });
  await expect(play).toContainText(shippedPath.title);
  await expect(play).toHaveAttribute("href", /^#\/runs\/recorded\/[A-Za-z0-9_-]+$/);
  const turns = real.getByRole("list", { name: "The changes to the defense, in order" });
  await expect(turns.getByRole("link")).toHaveText(["Clear Bash history (echo) went from unseen to seen.", "4 steps went from seen to alerted."]);
  const realBox = await real.boundingBox();
  const draftBox = await page.getByRole("heading", { name: /^(Working draft|Example plan)$/ }).first().boundingBox();
  expect(realBox && draftBox && realBox.y < draftBox.y).toBe(true);
  // Recent outcomes offers the newest of what Runs lists: the same path, not a pair.
  const newestRun = page.getByRole("link", { name: /^Watch the first recorded run on Runs/ });
  await expect(newestRun).toContainText(shippedPath.title);
  await expect(newestRun).toContainText(`Shipped with BlueFire · ${shippedPathScore}`);
  await expect(newestRun).toHaveAttribute("href", /^#\/runs\/recorded\/[A-Za-z0-9_-]+$/);
  await expect(page.getByRole("link", { name: /^See the newest change to the defense/ })).toHaveCount(0);
  await expect(page.getByText("No experiment runs yet.")).toBeVisible();

  // What a fresh workspace holds: the packaged experiments, the recording that
  // ships with BlueFire, and no runs of the app's own engine yet.
  await page.getByRole("link", { name: "Experiments", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Experiments", exact: true })).toBeVisible();
  await expect(page.getByText("Collect samples with a local fallback").first()).toBeVisible();

  await page.getByRole("link", { name: "Build", exact: true }).click();
  await expect(page.getByRole("button", { name: "Validate", exact: true })).toBeVisible();

  await page.getByRole("link", { name: "Runs", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Runs", exact: true })).toBeVisible();
  const recorded = page.getByRole("region", { name: "Recorded runs" });
  const shipped = recorded.getByRole("listitem").filter({ hasText: "60 published tests on one Linux host" });
  await expect(shipped.getByText("Shipped with BlueFire")).toBeVisible();
  await expect(shipped.getByText("3 of 60 tests alerted, 56 seen, 1 unseen")).toBeVisible();
  await expect(page.getByText("No experiment runs yet.")).toBeVisible();

  // The shipped recording plays in the live view.
  await shipped.getByRole("link").click();
  await expect(page).toHaveURL(/#\/runs\/recorded\/[A-Za-z0-9_-]+/);
  await expect(page.getByRole("slider", { name: /^Timeline/ })).toBeVisible();
  await expect(page.getByRole("button", { name: "Analyse", exact: true })).toBeVisible();

  // A recording that does not agree with itself is refused with the service's own words.
  await page.getByRole("link", { name: "Runs", exact: true }).first().click();
  const broken = smallRecording();
  broken.id = "small-broken";
  broken.score.alerted = 2;
  await page.getByLabel("Recording file to import").setInputFiles(file("broken.json", broken));
  const refusal = page.getByRole("alert").filter({ hasText: "The recording was not imported" });
  await expect(refusal.getByText("The recording is not valid: score.alerted is 2, but the steps give 1.")).toBeVisible();

  // The screen sends a file's own bytes: each of the small refused files is refused with the
  // reason the command line and the import route give it (tests_platform/test_recordings.py).
  const refusedFolder = join(resolve(process.cwd(), ".."), "tests_platform/fixtures/refused-recordings");
  const reasons = (JSON.parse(readFileSync(join(refusedFolder, "reasons.json"), "utf-8")) as { files: Record<string, string> }).files;
  for (const [name, reason] of Object.entries(reasons)) {
    await page.getByLabel("Recording file to import").setInputFiles({ name, mimeType: "application/json", buffer: readFileSync(join(refusedFolder, name)) });
    await expect(refusal, name).toContainText(`The recording is not valid: ${reason}`);
  }
  await expect(page).toHaveURL(/#\/runs$/);

  // A small valid one is imported, opens, and says what BlueFire could and could not check.
  // The CI run it names is shown as the file's claim, never as a link to the run that made it.
  const small = smallRecording();
  const claimed = "https://github.com/example/lab/actions/runs/123";
  Object.assign(small.source, { repository: "example/lab", run_url: claimed });
  await page.getByLabel("Recording file to import").setInputFiles(file("small.json", small));
  await expect(page).toHaveURL(/#\/runs\/recorded\/small-attack-path/);
  await expect(page.getByText("Imported, not verified by BlueFire", { exact: true })).toBeVisible();
  await expect(page.getByText(/^Imported\. BlueFire checked that this file follows the recording format.+It cannot confirm that the steps ran/)).toBeVisible();
  await expect(page.getByText(`The file names this CI run, which BlueFire cannot confirm: ${claimed}`, { exact: false })).toBeVisible();
  await page.getByRole("button", { name: /^An imported run, not verified by BlueFire, recorded .+· details$/ }).click();
  await expect(page.getByRole("heading", { name: "Where this recording comes from" })).toBeVisible();
  await expect(page.getByRole("link", { name: /CI run/ })).toHaveCount(0);
  await page.getByRole("button", { name: "Close", exact: true }).click();
  await expect(page.getByRole("slider", { name: /^Timeline/ })).toBeVisible();

  await page.getByRole("link", { name: "Runs", exact: true }).first().click();
  const imported = recorded.getByRole("listitem").filter({ hasText: "Two steps toward a secrets file" });
  await expect(imported.getByText("Imported, not verified by BlueFire", { exact: true })).toBeVisible();
  await expect(imported.getByText("1 of 2 steps alerted, 1 seen, 0 unseen")).toBeVisible();

  // The app keeps the same real moment while either defense judges every visible answer.
  const judged = multiDefenseRecording();
  await page.getByLabel("Recording file to import").setInputFiles(file("judged.json", judged));
  await expect(page).toHaveURL(/#\/runs\/recorded\/small-judged-twice/);
  const judgedAddress = new URL(page.url());
  judgedAddress.hash = "/runs/recorded/small-judged-twice?step=2&at=2&paused=1&defense=sysmon-alone";
  await page.goto(judgedAddress.toString());
  const choices = page.getByRole("group", { name: "The defenses that judge this run" });
  const choiceRows = choices.getByRole("button");
  await expect(choiceRows).toHaveCount(2);
  await expect(choiceRows.first()).toHaveAttribute("aria-pressed", "true");
  await expect(page.locator(".lv-sensor.is-off title", { hasText: "Packet capture" })).toHaveCount(1);
  const judgedSlider = page.getByRole("slider", { name: /^Timeline/ });
  const judgedAt = await judgedSlider.getAttribute("aria-valuenow");
  const judgedClock = await page.locator(".lv-clock b").textContent();
  await expect(page.locator(".lv-word")).toHaveText("seen");
  await page.keyboard.press("2");
  await expect(choiceRows.nth(1)).toHaveAttribute("aria-pressed", "true");
  await expect(page).toHaveURL(/defense=with-capture/);
  await expect(judgedSlider).toHaveAttribute("aria-valuenow", judgedAt ?? "");
  await expect(page.locator(".lv-clock b")).toHaveText(judgedClock ?? "");
  await expect(page.locator(".lv-word")).toHaveText("alerted");
  await expect(page.locator(".lv-sensor.is-off title", { hasText: "Packet capture" })).toHaveCount(0);
  await page.getByRole("button", { name: "Analyse", exact: true }).click();
  const comparison = page.getByRole("group", { name: "The defenses side by side" });
  await expect(comparison).toBeVisible();
  await expect(comparison.getByRole("button")).toHaveCount(2);
  await page.getByRole("link", { name: "Runs", exact: true }).first().click();

  // A recording still running says so, and its page asks the service again until it has finished.
  let asked = 0;
  page.on("request", request => {
    if (new URL(request.url()).pathname === "/api/v1/recordings/small-running") asked += 1;
  });
  const running = smallRecording();
  running.id = "small-running";
  const unfinished: Record<string, unknown> = { ...running.source };
  delete unfinished.finished;
  await page.getByLabel("Recording file to import").setInputFiles(file("running.json", { ...running, source: unfinished }));
  await expect(page).toHaveURL(/#\/runs\/recorded\/small-running/);
  await expect(page.getByText("Still running: new steps appear as they arrive")).toBeVisible();
  await expect.poll(() => asked, { timeout: 15_000 }).toBeGreaterThanOrEqual(2);

  // The finished version, sent again under the same id, replaces it at once, and the asking stops.
  await page.getByRole("link", { name: "Runs", exact: true }).first().click();
  await page.getByLabel("Recording file to import").setInputFiles(file("finished.json", running));
  await expect(page).toHaveURL(/#\/runs\/recorded\/small-running/);
  await expect(page.getByRole("slider", { name: /^Timeline/ })).toBeVisible();
  await expect(page.getByText("Still running: new steps appear as they arrive")).toHaveCount(0);
  const settled = asked;
  await page.waitForTimeout(9_000);
  expect(asked).toBe(settled);

  // An imported run recorded after the shipped runs is listed after what was shipped, and the
  // Overview still offers the shipped path: an imported file never takes a shipped run's place.
  await page.getByRole("link", { name: "Runs", exact: true }).first().click();
  const later = JSON.parse(JSON.stringify({ ...smallRecording(), id: "small-later", title: "Two later steps toward a secrets file" }).replaceAll("2026-11-20", "2026-11-30"));
  await page.getByLabel("Recording file to import").setInputFiles(file("later.json", later));
  await expect(page).toHaveURL(/#\/runs\/recorded\/small-later/);
  await page.getByRole("link", { name: "Runs", exact: true }).first().click();
  const titles = recorded.getByRole("listitem").getByRole("link");
  await expect(titles.first()).toHaveText(shippedPath.title);
  await page.getByRole("link", { name: "Overview", exact: true }).first().click();
  const stillNewest = page.getByRole("link", { name: /^Watch the first recorded run on Runs/ });
  await expect(stillNewest).toContainText(shippedPath.title);
  await expect(stillNewest).toContainText("Shipped with BlueFire");
  await expect(page.getByRole("link", { name: /^See the newest change to the defense/ })).toHaveCount(0);
  // The run that leads is still the real one shipped with BlueFire, never the later imported file.
  const stillReal = page.getByRole("region", { name: "A run recorded in CI" });
  await expect(stillReal.getByText(shippedPath.title, { exact: true })).toBeVisible();
  await expect(stillReal.getByText("Two later steps toward a secrets file", { exact: true })).toHaveCount(0);
  await expect(page.getByRole("region", { name: "An imported run" })).toHaveCount(0);

  await page.getByRole("link", { name: "Detection Lab", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Detection Lab", exact: true })).toBeVisible();

  await page.getByRole("link", { name: "Compare", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Compare runs", exact: true })).toBeVisible();

  expect(problems).toEqual([]);
});
