import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";

// One file, two readers, one answer. Each edge of the recording format below
// goes to the service's import, and to the replay page: the one the app's
// command line makes when the service keeps it, or the committed template
// filled by hand when the service refuses it. A recording the service keeps
// must play, and one it refuses must not.

type Value = Record<string, unknown>;
type Answer = "kept and plays" | "refused" | "kept while running";

const repository = resolve(process.cwd(), "..");
const template = readFileSync(join(repository, "bluefire/ui/replay.html"), "utf-8");
const RECORDING_ELEMENT = '<script id="bluefire-recording" type="application/json">';

/** Two tests of a test list on one host, in the shape the lab writes them: one alerted, one seen. */
function small(id: string): Value {
  const stepOf = (n: number, title: string, answer: string, events: number, outcome: string): Value => ({
    id: String(n),
    order: n,
    role: "test",
    title,
    technique: { id: "T1070.003" },
    host: "target",
    started: `2026-11-17T17:07:2${n}.000Z`,
    ended: `2026-11-17T17:07:2${n}.500Z`,
    happened: { answer: "took effect", basis: "the effect check exited with 0" },
    visibility: { answer, basis: "what the sensors and rules said", events },
    outcome,
    first_event: `2026-11-17T17:07:2${n}.100Z`,
    ...(answer === "alert" ? { first_alert: `2026-11-17T17:07:2${n}.100Z` } : {}),
  });
  const eventOf = (eventId: string, step: string, time: string, text: string): Value => ({ id: eventId, time, host: "target", sensor: "sysmon", kind: "process start", text, step, tied_by: "session" });
  return {
    schema: "bluefire.recording/1",
    id,
    title: `Edge ${id}`,
    kind: "test list",
    source: { engine: "bluefire-lab", environment: "GitHub-hosted runner", started: "2026-11-17T17:07:20Z", finished: "2026-11-17T17:08:14Z", tools: [] },
    network: {
      hosts: [{ id: "target", name: "runner", role: "Linux host under test", kind: "host" }],
      sensors: [{ id: "sysmon", name: "Sysmon for Linux 1.6.0", host: "target", records: "process starts" }],
      detectors: [{ id: "pinned", name: "Published Sigma rules", rules: 1, when: "after the run" }],
    },
    attacker: { kind: "scripted", description: "A list of published tests.", goal: null },
    steps: [stepOf(1, "Clear Bash history (rm)", "alert", 2, "alerted"), stepOf(2, "List running processes", "telemetry only", 1, "seen")],
    events: [eventOf("1-1", "1", "2026-11-17T17:07:21.100Z", "rm .bash_history"), eventOf("1-2", "1", "2026-11-17T17:07:21.102Z", "rm"), eventOf("2-1", "2", "2026-11-17T17:07:22.100Z", "ps aux")],
    alerts: [
      {
        id: "alert-1",
        time: "2026-11-17T17:07:21.100Z",
        host: "target",
        detector: "pinned",
        rule: { id: "rule-1", title: "History File Deletion", level: "high", origin: "pinned" },
        counts: true,
        step: "1",
        events: ["1-1"],
      },
    ],
    score: { steps: 2, took_effect: 2, alerted: 1, seen: 1, unseen: 0, stopped: 0 },
    notes: [],
  };
}

/** Adds a third step, seen, after the two of `small`. */
function third(value: Value): void {
  (value.steps as Value[]).push({ ...part(value, "steps", 1), id: "3", order: 3, title: "Show the user", started: "2026-11-17T17:07:23.000Z", ended: "2026-11-17T17:07:23.500Z", first_event: "2026-11-17T17:07:23.100Z" });
  (value.events as Value[]).push({ ...part(value, "events", 2), id: "3-1", step: "3", time: "2026-11-17T17:07:23.100Z", text: "id" });
}

function part(value: Value, ...path: (string | number)[]): Value {
  let at: unknown = value;
  for (const key of path) {
    if (typeof at !== "object" || at === null) throw new Error(`No ${path.join(".")} in the edge recording.`);
    at = (at as Record<string | number, unknown>)[key];
  }
  if (typeof at !== "object" || at === null) throw new Error(`No ${path.join(".")} in the edge recording.`);
  return at as Value;
}

/** Each edge is one way a recording can be at the limits of the format, with the answer both readers must give. */
const EDGES: { name: string; answer: Answer; make: (value: Value) => void; onMap?: string }[] = [
  { name: "the smallest test list, with every optional key left out", answer: "kept and plays", make: () => undefined },
  {
    name: "times with six digits after the second",
    answer: "kept and plays",
    make: (value) => {
      part(value, "steps", 0).started = "2026-11-17T17:07:21.000001Z";
      part(value, "steps", 1).ended = "2026-11-17T17:07:22.999999Z";
    },
  },
  {
    name: "empty texts where the format allows them",
    answer: "kept and plays",
    make: (value) => {
      Object.assign(part(value, "steps", 0), { command: "", output: "", plain: "" });
      Object.assign(part(value, "events", 2), { text: "", user: "", image: "", fields: { exit: null } });
    },
  },
  {
    name: "a finished run with hosts and sensors and no step",
    answer: "kept and plays",
    make: (value) => {
      Object.assign(value, { steps: [], events: [], alerts: [], score: { steps: 0, took_effect: 0, alerted: 0, seen: 0, unseen: 0, stopped: 0 } });
    },
  },
  {
    name: "a step that did not start, with no times and no events",
    answer: "kept and plays",
    make: (value) => {
      const second = part(value, "steps", 1);
      for (const key of ["started", "ended", "first_event"]) delete second[key];
      Object.assign(second, { happened: { answer: "not attempted", basis: "a program was missing" }, visibility: { answer: "not applicable", basis: "the test did not run" }, outcome: "no effect" });
      value.events = (value.events as Value[]).filter((event) => event.step !== "2");
      Object.assign(part(value, "score"), { took_effect: 1, seen: 0 });
    },
  },
  {
    name: "a run whose start and end are the same moment",
    answer: "kept and plays",
    make: (value) => {
      const moment = "2026-11-17T17:07:20Z";
      Object.assign(part(value, "source"), { finished: moment });
      Object.assign(value, {
        steps: [{ ...part(value, "steps", 1), id: "1", order: 1, started: moment, ended: moment, first_event: moment }],
        events: [{ ...part(value, "events", 2), id: "1-1", step: "1", time: moment }],
        alerts: [],
        score: { steps: 1, took_effect: 1, alerted: 0, seen: 1, unseen: 0, stopped: 0 },
      });
    },
  },
  {
    name: "an attack path with a live alert raised late and a goal",
    answer: "kept and plays",
    make: (value) => {
      value.kind = "attack path";
      Object.assign(part(value, "attacker"), { goal: "Read the history file of another account." });
      Object.assign(part(value, "network", "detectors", 0), { when: "live" });
      Object.assign(part(value, "alerts", 0), { raised: "2026-11-17T17:07:22.300Z" });
      // A live alert counts from when it was raised, so the step's first alert is that moment.
      Object.assign(part(value, "steps", 0), { first_alert: "2026-11-17T17:07:22.300Z" });
      Object.assign(part(value, "score"), { first_alert_seconds: 1.3, goal_seconds: 1.5 });
    },
  },
  {
    name: "every optional key there",
    answer: "kept and plays",
    make: (value) => {
      Object.assign(part(value, "source"), {
        repository: "example/lab",
        commit: "0123abc",
        run_url: "https://github.com/example/lab/actions/runs/1",
        tools: [{ name: "Atomic Red Team", version: "0123abc", role: "tests" }],
      });
      const network = part(value, "network");
      (network.hosts as Value[]).push({ id: "attacker", name: "Kali", role: "the attacker's host", kind: "attacker", os: "Kali 2026.1", addresses: ["10.0.0.5"] });
      Object.assign(part(value, "network", "hosts", 0), { os: "Ubuntu 24.04", addresses: ["10.0.0.9"] });
      network.links = [{ from: "attacker", to: "target", label: "ssh" }];
      (network.detectors as Value[]).push({ id: "lab", name: "Rules written in this repository", rules: 2, when: "after the run" });
      const [first, second] = [part(value, "steps", 0), part(value, "steps", 1)];
      Object.assign(first, {
        plain: "Deletes the shell history file.",
        technique: { id: "T1070.003", name: "Clear Command History", tactic: "defense-evasion" },
        test: { project: "Atomic Red Team", guid: "a1b2", executor: "sh", elevated: false },
        from: "attacker",
        command: "sh -c 'rm ~/.bash_history'",
        output: "...done",
        visibility: { answer: "alert", basis: "a rule matched", events: 5, kept: 2 },
        outcome_with_lab_rules: "alerted",
        first_alert_with_lab_rules: "2026-11-17T17:07:21.100Z",
      });
      Object.assign(second, { outcome_with_lab_rules: "alerted", first_alert_with_lab_rules: "2026-11-17T17:07:22.100Z" });
      (value.steps as Value[]).push({
        id: "3",
        order: 3,
        role: "hardened",
        title: "Clear Bash history (rm)",
        technique: { id: "T1070.003" },
        host: "target",
        started: "2026-11-17T17:07:23.000Z",
        ended: "2026-11-17T17:07:23.500Z",
        happened: { answer: "blocked", basis: "the file could not be removed" },
        visibility: { answer: "no telemetry", basis: "nothing was recorded", events: 0 },
        outcome: "stopped",
        outcome_with_lab_rules: "stopped",
        compared_with: "1",
        defense: { title: "Make the history file append-only", why: "A history that cannot be emptied keeps the trail." },
      });
      Object.assign(part(value, "events", 0), { user: "lab", image: "/usr/bin/rm", fields: { ProcessId: 41, exit: null, elevated: false } });
      (value.alerts as Value[]).push(
        { id: "alert-2", time: "2026-11-17T17:07:22.000Z", host: "target", detector: "pinned", rule: { id: "rule-2", title: "Shell Launcher", level: "high", origin: "pinned" }, counts: false, step: "2", events: [], launcher_only: true },
        { id: "alert-3", time: "2026-11-17T17:07:22.100Z", host: "target", detector: "lab", rule: { id: "rule-3", title: "Process List", level: "high", origin: "lab" }, counts: true, step: "2", events: ["2-1"] },
      );
      value.ordinary = { events: 40, matches: [{ rule: "Sudo Use", level: "high", count: 3 }] };
      Object.assign(part(value, "score"), { stopped: 1, alerted_with_lab_rules: 2, false_alerts: 1 });
      value.notes = ["The rules were evaluated after the run ended."];
    },
  },
  {
    name: "a network with every kind of host, a sensor on the defense host, a link of a host to itself and a detector of its own name",
    answer: "kept and plays",
    make: (value) => {
      const network = part(value, "network");
      (network.hosts as Value[]).push(
        { id: "web", name: "web", role: "web application", kind: "host" },
        { id: "attacker", name: "attacker", role: "the attacker's host", kind: "attacker" },
        { id: "internet", name: "internet", role: "the outside", kind: "internet" },
        { id: "siem", name: "Wazuh manager", role: "collects the agents' logs", kind: "defense" },
      );
      network.links = [
        { from: "internet", to: "attacker", label: "https" },
        { from: "attacker", to: "web", label: "http" },
        { from: "web", to: "target", label: "ssh" },
        { from: "target", to: "target", label: "loopback" },
      ];
      (network.sensors as Value[]).push({ id: "agent", name: "Wazuh agent", host: "web", records: "log lines" }, { id: "manager-log", name: "Manager log", host: "siem", records: "the manager's own log" });
      (network.detectors as Value[]).push({ id: "wazuh", name: "Wazuh rules", rules: 0, when: "live" });
      Object.assign(part(value, "steps", 1), { host: "web", from: "attacker", visibility: { answer: "telemetry only", basis: "what the sensors and rules said", events: 2 } });
      Object.assign(part(value, "events", 2), { host: "web", sensor: "agent", kind: "log line" });
      (value.events as Value[]).push({ id: "2-2", time: "2026-11-17T17:07:22.200Z", host: "siem", sensor: "manager-log", kind: "log line", text: "agent web: new session", step: "2", tied_by: "session" });
    },
    onMap: "Manager log",
  },
  {
    name: "a run with no sensor and no detector",
    answer: "kept and plays",
    make: (value) => {
      Object.assign(part(value, "network"), { sensors: [], detectors: [] });
      for (const step of value.steps as Value[]) {
        Object.assign(step, { visibility: { answer: "no telemetry", basis: "no sensor ran", events: 0 }, outcome: "unseen" });
        delete step.first_event;
        delete step.first_alert;
      }
      Object.assign(value, { events: [], alerts: [] });
      Object.assign(part(value, "score"), { alerted: 0, seen: 0, unseen: 2 });
    },
  },
  {
    name: "a run that has not finished",
    answer: "kept while running",
    make: (value) => {
      delete part(value, "source").finished;
    },
  },
  {
    name: "what real recordings hold: events stamped a moment outside their step, and a live alert that names an event after its moment",
    answer: "kept and plays",
    make: (value) => {
      value.kind = "attack path";
      Object.assign(part(value, "attacker"), { goal: "Read the history file of another account." });
      Object.assign(part(value, "network", "detectors", 0), { when: "live" });
      Object.assign(part(value, "events", 0), { time: "2026-11-17T17:07:20.995Z" });
      Object.assign(part(value, "events", 1), { time: "2026-11-17T17:07:21.700Z" });
      Object.assign(part(value, "steps", 0), { first_event: "2026-11-17T17:07:20.995Z", first_alert: "2026-11-17T17:07:21.200Z" });
      Object.assign(part(value, "alerts", 0), { time: "2026-11-17T17:07:20.995Z", raised: "2026-11-17T17:07:21.200Z", events: ["1-1", "1-2"] });
      value.ordinary = { events: 40, matches: [{ rule: "Sudo Use", level: "high", count: 3 }] };
      Object.assign(part(value, "score"), { false_alerts: 1, first_alert_seconds: 0.2, goal_seconds: 1.5 });
    },
  },
  {
    name: "a step that ends before it starts",
    answer: "refused",
    make: (value) => {
      part(value, "steps", 0).ended = "2026-11-17T17:07:20.900Z";
    },
  },
  {
    name: "steps whose starts go back in time",
    answer: "refused",
    make: (value) => {
      part(value, "steps", 1).started = "2026-11-17T17:07:20.500Z";
    },
  },
  {
    name: "a step that starts before the step before it has ended",
    answer: "refused",
    make: (value) => {
      part(value, "steps", 1).started = "2026-11-17T17:07:21.400Z";
    },
  },
  {
    name: "an event of a step stamped inside the next step",
    answer: "refused",
    make: (value) => {
      part(value, "events", 1).time = "2026-11-17T17:07:22.050Z";
    },
  },
  {
    name: "an alert whose moment is earlier than the first event it names",
    answer: "refused",
    make: (value) => {
      part(value, "alerts", 0).time = "2026-11-17T17:07:21.050Z";
      part(value, "steps", 0).first_alert = "2026-11-17T17:07:21.050Z";
    },
  },
  {
    name: "an alert on another host than the event it names",
    answer: "refused",
    make: (value) => {
      (part(value, "network").hosts as Value[]).push({ id: "other", name: "other", role: "another host", kind: "host" });
      part(value, "alerts", 0).host = "other";
    },
  },
  {
    name: "a number in an event's fields past 2^53, written as a float",
    answer: "refused",
    make: (value) => {
      part(value, "events", 0).fields = { size: 1e300 };
    },
  },
  {
    name: "a number in an event's fields at 2^53",
    answer: "kept and plays",
    make: (value) => {
      part(value, "events", 0).fields = { size: 2 ** 53, ratio: -0.5 };
    },
  },
  {
    name: "direction marks and overrides in a step's command, output and plain sentence, which are free text",
    answer: "kept and plays",
    make: (value) => {
      Object.assign(part(value, "steps", 0), { command: "cp x /tmp/\u202Etxt.exe\u202C", output: "\u2067done\u2069", plain: "Copies a file whose name reads backwards\u200F." });
    },
  },
  {
    name: "an attack path that begins with a canary",
    answer: "refused",
    make: (value) => {
      value.kind = "attack path";
      Object.assign(part(value, "attacker"), { goal: "Read the history file of another account." });
      part(value, "steps", 0).role = "canary";
      Object.assign(part(value, "score"), { steps: 1, took_effect: 1, alerted: 0 });
    },
  },
  {
    name: "an attack path whose first step has no start",
    answer: "refused",
    make: (value) => {
      value.kind = "attack path";
      Object.assign(part(value, "attacker"), { goal: "Read the history file of another account." });
      delete part(value, "steps", 0).started;
    },
  },
  {
    name: "a goal time and no goal",
    answer: "refused",
    make: (value) => {
      value.kind = "attack path";
      Object.assign(part(value, "score"), { goal_seconds: 1.5 });
    },
  },
  {
    name: "a goal on a test list",
    answer: "refused",
    make: (value) => {
      Object.assign(part(value, "attacker"), { goal: "Read the history file of another account." });
    },
  },
  {
    name: "false alerts without ordinary activity",
    answer: "refused",
    make: (value) => {
      part(value, "score").false_alerts = 7;
    },
  },
  {
    name: "one rule listed twice in ordinary activity",
    answer: "refused",
    make: (value) => {
      value.ordinary = { events: 100, matches: [{ rule: "Sudo Use", level: "high", count: 1 }, { rule: "Sudo Use", level: "high", count: 1 }] };
      part(value, "score").false_alerts = 1;
    },
  },
  {
    name: "a rule that matched more ordinary events than there were",
    answer: "refused",
    make: (value) => {
      value.ordinary = { events: 0, matches: [{ rule: "Sudo Use", level: "high", count: 1000000 }] };
      part(value, "score").false_alerts = 1;
    },
  },
  {
    name: "a rerun compared with itself",
    answer: "refused",
    make: (value) => {
      Object.assign(part(value, "steps", 1), { role: "hardened", compared_with: "2" });
      Object.assign(part(value, "score"), { steps: 1, took_effect: 1, seen: 0 });
    },
  },
  {
    name: "a repository without its owner",
    answer: "refused",
    make: (value) => {
      part(value, "source").repository = "example";
    },
  },
  {
    name: "a C1 control in a step's title",
    answer: "refused",
    make: (value) => {
      part(value, "steps", 0).title = "Clear\u0085history";
    },
  },
  {
    name: "a direction override in a host's name",
    answer: "refused",
    make: (value) => {
      part(value, "network", "hosts", 0).name = "runner\u202e";
    },
  },
  {
    name: "a direction isolate in a rule's title",
    answer: "refused",
    make: (value) => {
      part(value, "alerts", 0, "rule").title = "History\u2066 File";
    },
  },
  {
    name: "a line separator in an event's text",
    answer: "refused",
    make: (value) => {
      part(value, "events", 0).text = "rm\u2028history";
    },
  },
  {
    name: "a control character in a key",
    answer: "refused",
    make: (value) => {
      part(value, "events", 0).fields = { "a\u0085b": "x" };
    },
  },
  {
    name: "a NUL in a step's command, a text the other control rules leave free",
    answer: "refused",
    make: (value) => {
      part(value, "steps", 0).command = "rm\u0000x";
    },
  },
  {
    name: "compared_with on a step of role test",
    answer: "refused",
    make: (value) => {
      part(value, "steps", 1).compared_with = "1";
    },
  },
  {
    name: "a rerun compared with a later step",
    answer: "refused",
    make: (value) => {
      third(value);
      Object.assign(part(value, "steps", 1), { role: "variant", compared_with: "3" });
    },
  },
  {
    name: "a rerun compared with another rerun",
    answer: "refused",
    make: (value) => {
      third(value);
      Object.assign(part(value, "steps", 1), { role: "variant", compared_with: "1" });
      Object.assign(part(value, "steps", 2), { role: "variant", compared_with: "2" });
      Object.assign(part(value, "score"), { steps: 1, took_effect: 1, seen: 0 });
    },
  },
  {
    name: "an attack path with a goal time and no step",
    answer: "refused",
    make: (value) => {
      value.kind = "attack path";
      Object.assign(part(value, "attacker"), { goal: "Read the history file of another account." });
      Object.assign(value, { steps: [], events: [], alerts: [], score: { steps: 0, took_effect: 0, alerted: 0, seen: 0, unseen: 0, stopped: 0, goal_seconds: 5 } });
    },
  },
  {
    name: "a source with no list of tools",
    answer: "refused",
    make: (value) => {
      delete part(value, "source").tools;
    },
  },
  {
    name: "a step role the format does not name",
    answer: "refused",
    make: (value) => {
      part(value, "steps", 1).role = "baseline";
      Object.assign(part(value, "score"), { steps: 1, took_effect: 1, seen: 0 });
    },
  },
];

let workspace = "";

function bluefire(...args: string[]): { status: number | null; output: Value } {
  const run = spawnSync(process.env.BLUEFIRE_PYTHON ?? "python3", ["-m", "bluefire.cli", "--runs-dir", join(workspace, "runs"), ...args], { cwd: repository, encoding: "utf-8" });
  let output: Value = {};
  try {
    output = JSON.parse(run.stdout) as Value;
  } catch {
    throw new Error(`bluefire ${args.join(" ")} printed no JSON:\n${run.stdout}\n${run.stderr}`);
  }
  return { status: run.status, output };
}

/** The page of a recording the service did not make a page of: the committed template, filled by hand. */
function pageByHand(recording: Value, file: string): void {
  const start = template.indexOf(RECORDING_ELEMENT) + RECORDING_ELEMENT.length;
  const end = template.indexOf("</script>", start);
  writeFileSync(file, `${template.slice(0, start)}${JSON.stringify(recording).replace(/</g, "\\u003c")}${template.slice(end)}`);
}

/**
 * What the page makes of its recording: plays, in watch mode at its start and end and in analyse mode, or refuses.
 * `onMap` is a sensor's name that the watch view's map must show.
 */
async function pageAnswer(page: Page, file: string, recording: Value, onMap?: string): Promise<"plays" | string> {
  const problems: string[] = [];
  page.on("pageerror", (error) => problems.push(String(error)));
  const address = pathToFileURL(file).href;
  const steps = recording.steps as Value[];
  const last = steps[steps.length - 1];
  const addresses = ["", "?mode=analyse", ...(last ? [`?step=${String(last.id)}&at=2&paused=1`] : [])];
  for (const query of addresses) {
    await page.goto(`${address}${query}`);
    const refused = page.getByRole("heading", { level: 1, name: "This recording cannot be played" });
    const title = page.getByRole("heading", { level: 1, name: String(recording.title), exact: true });
    await expect(refused.or(title)).toBeVisible();
    if (await refused.isVisible()) return (await page.locator(".replay-empty p").textContent()) ?? "refused";
    // A moment of playing: the view must stay up while the clock moves.
    await page.waitForTimeout(400);
    await expect(title).toBeVisible();
    if (onMap && !query.startsWith("?mode=analyse")) await expect(page.getByText(onMap, { exact: true })).toBeVisible();
  }
  expect(problems).toEqual([]);
  return "plays";
}

test.beforeAll(() => {
  workspace = mkdtempSync(join(tmpdir(), "bluefire-parity-"));
});

test.afterAll(() => {
  if (workspace) rmSync(workspace, { recursive: true, force: true });
});

EDGES.forEach((edge, index) => {
  test(`the service and the page agree on ${edge.name}`, async ({ page }) => {
    const recording = small(`rec-edge-${index + 1}`);
    edge.make(recording);
    const file = join(workspace, `edge-${index + 1}.json`);
    writeFileSync(file, JSON.stringify(recording));
    const pageFile = join(workspace, `edge-${index + 1}.html`);

    const imported = bluefire("recordings", "import", file);
    let answer: Answer;
    if (imported.status !== 0) {
      answer = "refused";
      pageByHand(recording, pageFile);
      expect(await pageAnswer(page, pageFile, recording)).not.toBe("plays");
    } else {
      const made = bluefire("recordings", "page", String(recording.id), "--out", pageFile);
      if (made.status === 0) {
        answer = "kept and plays";
        expect(await pageAnswer(page, pageFile, recording, edge.onMap)).toBe("plays");
      } else {
        // A page is made of a finished run only; the page says the same of a running one.
        answer = "kept while running";
        expect(made.output).toMatchObject({ error: { code: "recording_running" } });
        pageByHand(recording, pageFile);
        expect(await pageAnswer(page, pageFile, recording)).toContain("still running");
      }
    }
    expect(answer, JSON.stringify(imported.output)).toBe(edge.answer);
  });
});
