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
  // The Overview leads with the real run shipped with BlueFire, to watch, and the turns of the loop under it,
  // above the workspace's own blocks.
  const real = page.getByRole("region", { name: "Watch a real run" });
  await expect(real.getByText("60 published tests on one Linux host", { exact: true })).toBeVisible();
  await expect(real.getByText("3 of 60 tests alerted, 56 seen, 1 unseen")).toBeVisible();
  // The score counts only published rules; what the lab's own rules alert on is said apart, never as "no alert".
  await expect(real.getByText("With the lab's own rules, 17 of 60 would alert. The score counts only published rules.")).toBeVisible();
  await expect(real.getByRole("link", { name: /^Play it/ })).toHaveAttribute("href", /^#\/runs\/recorded\/[A-Za-z0-9_-]+$/);
  const turns = real.getByRole("list", { name: "The changes to the defense, in order" });
  await expect(turns.getByRole("link")).toHaveText(["One test that nobody saw is now seen.", "Four steps that were seen with no alert now raise an alert."]);
  const realBox = await real.boundingBox();
  const draftBox = await page.getByRole("heading", { name: /^(Working draft|Example plan)$/ }).first().boundingBox();
  expect(realBox && draftBox && realBox.y < draftBox.y).toBe(true);
  // The Overview offers the newest of what Runs lists: on a fresh workspace the newest shipped pair, the
  // run evaluated with the new rule, whose run is listed only with its pair, never on its own.
  const newestPair = page.getByRole("link", { name: /^See the newest change to the defense, before against after/ });
  await expect(newestPair).toContainText("A new rule: Shell History File Truncated In Place");
  await expect(newestPair).toContainText("Shipped with BlueFire · Clear Bash history (echo) and Clear Bash history (cat dev/null), each also with changed input arguments: seen to alerted with the lab's rules");
  await expect(newestPair).toHaveAttribute("href", /^#\/runs\/compared\/[0-9a-f]{16}$/);
  await expect(page.getByRole("link", { name: /^Watch the newest recorded run/ })).toHaveCount(0);
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

  // A small valid one is imported, opens, and says what BlueFire could and could not check.
  // The CI run it names is shown as the file's claim, never as a link to the run that made it.
  const small = smallRecording();
  const claimed = "https://github.com/example/lab/actions/runs/123";
  Object.assign(small.source, { repository: "example/lab", run_url: claimed });
  await page.getByLabel("Recording file to import").setInputFiles(file("small.json", small));
  await expect(page).toHaveURL(/#\/runs\/recorded\/small-attack-path/);
  await expect(page.getByText("Imported", { exact: true })).toBeVisible();
  await expect(page.getByText(/^Imported\. BlueFire checked that this file follows the recording format.+It cannot confirm that the steps ran/)).toBeVisible();
  await expect(page.getByText(`The file names this CI run, which BlueFire cannot confirm: ${claimed}`, { exact: false })).toBeVisible();
  await expect(page.getByRole("link", { name: "CI run (github.com)" })).toHaveCount(0);
  await expect(page.getByRole("slider", { name: /^Timeline/ })).toBeVisible();

  await page.getByRole("link", { name: "Runs", exact: true }).first().click();
  const imported = recorded.getByRole("listitem").filter({ hasText: "Two steps toward a secrets file" });
  await expect(imported.getByText("Imported", { exact: true })).toBeVisible();
  await expect(imported.getByText("1 of 2 tests alerted, 1 seen, 0 unseen")).toBeVisible();

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

  // A run recorded after the pair, listed on its own, is what the Overview offers then.
  await page.getByRole("link", { name: "Runs", exact: true }).first().click();
  const later = JSON.parse(JSON.stringify({ ...smallRecording(), id: "small-later", title: "Two later steps toward a secrets file" }).replaceAll("2026-11-20", "2026-11-30"));
  await page.getByLabel("Recording file to import").setInputFiles(file("later.json", later));
  await expect(page).toHaveURL(/#\/runs\/recorded\/small-later/);
  await page.getByRole("link", { name: "Overview", exact: true }).first().click();
  const newestRun = page.getByRole("link", { name: /^Watch the newest recorded run/ });
  await expect(newestRun).toContainText("Two later steps toward a secrets file");
  await expect(newestRun).toContainText("Imported · 1 of 2 tests alerted, 1 seen, 0 unseen");
  await expect(newestRun).toHaveAttribute("href", "#/runs/recorded/small-later");
  await expect(page.getByRole("link", { name: /^See the newest change to the defense/ })).toHaveCount(0);
  // It leads too, said to be an imported recording rather than a real run BlueFire shipped.
  const recordedFirst = page.getByRole("region", { name: "Watch a recorded run" });
  await expect(recordedFirst.getByText("Two later steps toward a secrets file", { exact: true })).toBeVisible();
  await expect(recordedFirst.getByText("Imported", { exact: true })).toBeVisible();

  await page.getByRole("link", { name: "Detection Lab", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Detection Lab", exact: true })).toBeVisible();

  await page.getByRole("link", { name: "Compare", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Compare runs", exact: true })).toBeVisible();

  expect(problems).toEqual([]);
});
