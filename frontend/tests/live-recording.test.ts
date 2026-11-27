import { describe, expect, it } from "vitest";
import { alertsByStep, countsAsAlert, countsForScore, eventsByStep, readRecording, RecordingError, timeOf } from "../src/live/recording";
import type { Recording } from "../src/live/recording";
import { alert, at, event, recording, step } from "./live-fixture";

function valid() {
  return recording({
    steps: [step("1", 10, 11), step("2", 20, 21)],
    events: [event("1-1", "1", 10.1), event("2-1", "2", 20.2), event("2-2", "2", 20.4)],
    alerts: [alert("a1", "2", 20.4, ["2-2"])],
  });
}

function correlation(): Recording {
  const value = valid();
  Object.assign(value.events[0] ?? {}, { user: "lab" });
  Object.assign(value.events[2] ?? {}, { user: "lab" });
  Object.assign(value.alerts[0] ?? {}, { events: ["1-1", "2-2"] });
  return value;
}

function copy(): Record<string, unknown> {
  return JSON.parse(JSON.stringify(valid())) as Record<string, unknown>;
}

describe("reading a recording", () => {
  it("accepts a valid recording, also after a trip through JSON text", () => {
    const read = readRecording(copy());
    expect(read.steps.map((item) => item.id)).toEqual(["1", "2"]);
    expect(read.events).toHaveLength(3);
  });

  it("reads a recording that is still running, with no end time yet, for the app that follows it", () => {
    const value = copy();
    const source = { ...(value.source as Record<string, unknown>) };
    delete source.finished;
    const read = readRecording({ ...value, source }, { running: true });
    expect(read.source.finished).toBeUndefined();
    expect(read.steps).toHaveLength(2);
    expect(() => readRecording({ ...value, source: { ...source, finished: "yesterday" } }, { running: true })).toThrow("The source's end is not a UTC time");
  });

  it("refuses a value that holds no recording", () => {
    expect(() => readRecording(null)).toThrow("There is no recording here.");
    expect(() => readRecording([])).toThrow(RecordingError);
  });

  it("refuses another schema and names it", () => {
    const value = { ...copy(), schema: "bluefire.recording/2" };
    expect(() => readRecording(value)).toThrow(/schema is "bluefire.recording\/2", not "bluefire.recording\/1"/);
  });

  it("refuses a recording whose steps are not a list", () => {
    expect(() => readRecording({ ...copy(), steps: {} })).toThrow("The recording's steps is not a list.");
  });

  it("refuses an event that names a missing step", () => {
    const value = valid();
    value.events.push(event("9-1", "9", 30));
    expect(() => readRecording(value)).toThrow('Event "9-1" names the step "9", which is not in the recording.');
  });

  it("refuses a match that names a missing event", () => {
    const value = valid();
    value.alerts.push(alert("a2", "1", 10.1, ["1-7"]));
    expect(() => readRecording(value)).toThrow('Alert "a2" names the event "1-7", which is not in the recording.');
  });

  it("keeps an after-run correlation's earlier-step evidence and terminal event", () => {
    const read = readRecording(correlation());
    expect(read.alerts[0]?.events).toEqual(["1-1", "2-2"]);
    expect(read.alerts[0]?.step).toBe("2");
  });

  it.each([
    [
      "terminal step",
      (value: Recording) => Object.assign(value.alerts[0] ?? {}, { events: ["2-2", "1-1"] }),
      'Alert "a1" does not end with a terminal event of its step "2".',
    ],
    ["terminal time", (value: Recording) => Object.assign(value.alerts[0] ?? {}, { time: at(20.3) }), 'Alert "a1" has the time 2026-01-01T10:00:20.300Z, not the time of its terminal event.'],
    [
      "future evidence",
      (value: Recording) => Object.assign(value.alerts[0] ?? {}, { events: ["1-1", "2-2", "2-1"], time: at(20.2) }),
      'Alert "a1" names evidence after its terminal event.',
    ],
    [
      "another observed user",
      (value: Recording) => Object.assign(value.events[2] ?? {}, { user: "another-user" }),
      'Alert "a1" names events of different observed users.',
    ],
    [
      "a live cross-step match",
      (value: Recording) => {
        Object.assign(value.network.detectors[0] ?? {}, { when: "live" });
        Object.assign(value.alerts[0] ?? {}, { raised: at(20.4) });
      },
      'Alert "a1" names an event of another step.',
    ],
  ] as const)("refuses correlation evidence without one real %s", (_case, change, message) => {
    const value = correlation();
    change(value);
    expect(() => readRecording(value)).toThrow(message);
  });

  it("refuses two steps with the same id", () => {
    const value = valid();
    value.steps.push(step("2", 30, 31));
    expect(() => readRecording(value)).toThrow('Two steps have the id "2".');
  });

  it("says a recording without an end time is still running, which the service keeps but makes no page of", () => {
    const value = copy();
    const source = value.source;
    if (!isHolder(source)) throw new Error("fixture");
    delete source.finished;
    expect(() => readRecording(value)).toThrow("This recording is still running: it has no end time yet, and a replay is made of a finished run.");
  });

  it("refuses a time that is not a time", () => {
    const value = valid();
    value.steps.push(step("3", 30, 31, { started: "yesterday" }));
    expect(() => readRecording(value)).toThrow('The start of Step "3" is not a UTC time such as 2026-11-17T17:07:23.834Z: "yesterday".');
  });
});

/** A copy of the valid recording with one value replaced at a path of keys and list places. */
function isHolder(value: unknown): value is Record<string | number, unknown> {
  return typeof value === "object" && value !== null;
}

function changed(path: (string | number)[], value: unknown): unknown {
  const top = copy();
  let at: unknown = top;
  for (const key of path.slice(0, -1)) {
    if (!isHolder(at)) throw new Error("bad path");
    at = at[key];
  }
  const last = path[path.length - 1];
  if (last === undefined || !isHolder(at)) throw new Error("bad path");
  at[last] = value;
  return top;
}

function refusal(value: unknown): string {
  try {
    readRecording(value);
  } catch (error) {
    if (error instanceof RecordingError) return error.message;
    throw new Error(`not a RecordingError: ${String(error)}`);
  }
  throw new Error("the recording was accepted");
}

describe("refusing a wrong value in a field the view shows", () => {
  it("refuses an object where the basis of what happened should be text, with a plain message", () => {
    expect(refusal(changed(["steps", 0, "happened", "basis"], { text: "x" }))).toBe('The basis of what happened in Step "1" is not text.');
  });

  it("refuses a goal time of null", () => {
    expect(refusal(changed(["score", "goal_seconds"], null))).toBe("The score's goal_seconds is not a number.");
  });

  it.each([
    ["the source", ["source", "engine"], 3, "The source's engine is not text."],
    ["a tool", ["source", "tools"], [{ name: "Sysmon", version: "1", role: "camera" }], 'The role of tool 1 is "camera", which is not one of: tests, executor, sensor, rules, rule engine.'],
    ["a list of tools", ["source", "tools"], [null], "Tool 1 is not an object."],
    ["the run address", ["source", "run_url"], ["https://github.com/a/b/actions/runs/1"], "The address of the run that made the recording is not text."],
    ["a host", ["network", "hosts", 0, "role"], 7, "The role of host 1 is not text."],
    ["a host's addresses", ["network", "hosts", 0, "addresses"], ["10.0.0.1", 4], "Item 2 of the addresses of host 1 is not text."],
    ["a link", ["network", "links"], [{ from: "target", to: "target", label: { a: 1 } }], "The label of link 1 is not text."],
    ["a sensor", ["network", "sensors", 0, "records"], null, "What sensor 1 records is not text."],
    ["a detector", ["network", "detectors", 0, "rules"], "10", "The number of rules of detector 1 is not a number."],
    ["the attacker", ["attacker", "goal"], 5, "The attacker's goal is not text."],
    ["a technique", ["steps", 0, "technique", "name"], ["T"], 'The technique name of Step "1" is not text.'],
    ["a published test", ["steps", 0, "test"], { project: "Atomic Red Team", guid: "g", executor: "sh", elevated: "yes" }, 'Whether the test of Step "1" ran as root is not true or false.'],
    ["a visibility", ["steps", 0, "visibility", "events"], Number.NaN, 'The events counted for Step "1" is not a number.'],
    ["a hardening change", ["steps", 0, "defense"], { title: "Mount /tmp noexec" }, 'Why the hardening change of Step "1" is deployed is not text.'],
    ["an event", ["events", 0, "user"], 0, 'The user of Event "1-1" is not text.'],
    ["an event's fields", ["events", 0, "fields"], { exit: { code: 1 } }, 'The field "exit" of Event "1-1" is not text, a number no further than 2^53 from zero, true or false, null or a list of text.'],
    ["an event's fields, with a number past 2^53 written as a float", ["events", 0, "fields"], { size: 1e300 }, 'The field "size" of Event "1-1" is not text, a number no further than 2^53 from zero, true or false, null or a list of text.'],
    ["a rule", ["alerts", 0, "rule", "id"], 12, 'The rule id of Alert "a1" is not text.'],
    ["ordinary activity", ["ordinary"], { events: 5, matches: [{ rule: "R", level: "high", count: "3" }] }, "The count of match 1 on ordinary activity is not a number."],
    ["the score", ["score", "seen"], "1", "The score's seen is not a number."],
  ])("refuses a wrong type in %s and names the field", (_kind, path, value, message) => {
    expect(refusal(changed(path, value))).toBe(message);
  });
});

describe("times", () => {
  it("refuses a time without a Z or a time that is only a year, and accepts UTC times with and without milliseconds", () => {
    expect(refusal(changed(["steps", 0, "started"], "2026-01-01T10:00:10.000"))).toBe('The start of Step "1" is not a UTC time such as 2026-11-17T17:07:23.834Z: "2026-01-01T10:00:10.000".');
    expect(refusal(changed(["steps", 0, "started"], "2026"))).toBe('The start of Step "1" is not a UTC time such as 2026-11-17T17:07:23.834Z: "2026".');
    expect(refusal(changed(["steps", 0, "started"], "2026-13-01T10:00:10Z"))).toBe('The start of Step "1" is not a time: "2026-13-01T10:00:10Z".');
    expect(() => readRecording(changed(["steps", 0, "started"], "2026-01-01T10:00:10Z"))).not.toThrow();
    expect(() => readRecording(changed(["steps", 0, "started"], "2026-01-01T10:00:10.5Z"))).not.toThrow();
  });

  it("accepts up to six digits after the second, as the service does, and orders them as finely as it does", () => {
    const read = readRecording(changed(["steps", 0, "started"], "2026-01-01T10:00:09.999999Z"));
    expect(timeOf(read.steps[0]?.started ?? "")).toBeCloseTo(Date.parse("2026-01-01T10:00:09.999Z") + 0.999, 6);
    expect(timeOf("2026-01-01T10:00:00.000001Z")).toBeGreaterThan(Date.parse("2026-01-01T10:00:00Z"));
    // Two times a fraction of a millisecond apart keep their order, and the same moment written two ways is one time.
    expect(timeOf("2026-01-01T10:00:00.2001Z")).toBeLessThan(timeOf("2026-01-01T10:00:00.2009Z"));
    expect(timeOf("2026-01-01T10:00:00.2000Z")).toBe(timeOf("2026-01-01T10:00:00.2Z"));
    expect(refusal(changed(["steps", 0, "started"], "2026-01-01T10:00:10.0000001Z"))).toBe('The start of Step "1" is not a UTC time such as 2026-11-17T17:07:23.834Z: "2026-01-01T10:00:10.0000001Z".');
  });
});

/** The valid recording as an attack path toward a goal, whose first step is a test with a start. */
function path(): Recording {
  return { ...valid(), kind: "attack path", attacker: { kind: "scripted", description: "A script", goal: "Read the history file." } };
}

type Refusal = [string, (value: Recording) => void, string];

/** The same recording as the engine sends it while the run is still going: no end time yet. */
function running(value: Recording): unknown {
  const copied = JSON.parse(JSON.stringify(value)) as Recording;
  delete copied.source.finished;
  return copied;
}

function runningRefusal(value: unknown): string {
  try {
    readRecording(value, { running: true });
  } catch (error) {
    if (error instanceof RecordingError) return error.message;
    throw new Error(`not a RecordingError: ${String(error)}`);
  }
  throw new Error("the recording was accepted");
}

describe("refusing what the page could not show truthfully, as the service does on import", () => {
  const refusals: Refusal[] = [
    ["a step that ends before it starts", (value) => Object.assign(value.steps[0] ?? {}, { ended: at(9) }), 'Step "1" ends before it starts: its ended, 2026-01-01T10:00:09.000Z, is earlier than its started, 2026-01-01T10:00:10.000Z.'],
    ["a step that starts before the step before it", (value) => Object.assign(value.steps[1] ?? {}, { started: at(5), ended: at(6) }), 'Step "2" starts before Step "1", the step before it: its started is earlier, and steps run forward in their order.'],
    ["a step that starts before the step before it has ended", (value) => Object.assign(value.steps[1] ?? {}, { started: at(10.5) }), 'Step "2" starts before Step "1", the step before it, has ended: its started is earlier than that step\'s end, and steps do not overlap.'],
    ["an event of a step stamped inside the next step", (value) => value.events.splice(1, 0, event("1-2", "1", 20.3)), 'Step "2" begins before Step "1", the step before it, ends: a step\'s start, events and alerts come after the end, events and alerts of the step before it.'],
    ["an alert whose moment is earlier than the first event it names", (value) => Object.assign(value.alerts[0] ?? {}, { time: at(20.3) }), 'Alert "a1" is earlier than the earliest event it matched: its time, 2026-01-01T10:00:20.300Z, comes before that event.'],
    [
      "an alert on another host than the events it names",
      (value) => {
        value.network.hosts.push({ id: "other", name: "other", role: "another host", kind: "host" });
        Object.assign(value.alerts[0] ?? {}, { host: "other" });
      },
      'Alert "a1" is on the host "other", but an event it matched is on another host: an alert is on the host of its events.',
    ],
    ["false alerts without ordinary activity", (value) => Object.assign(value.score, { false_alerts: 7 }), "The score's false_alerts is set, but the recording has no ordinary activity to count it from."],
    ["a rule listed twice in ordinary activity", (value) => Object.assign(value, { ordinary: { events: 100, matches: [{ rule: "Sudo Use", level: "high", count: 1 }, { rule: "Sudo Use", level: "high", count: 1 }] } }), 'Match 2 on ordinary activity names the rule "Sudo Use" again; each rule is listed once.'],
    ["a rule that matched more ordinary events than there were", (value) => Object.assign(value, { ordinary: { events: 0, matches: [{ rule: "Sudo Use", level: "high", count: 1000000 }] } }), "The count of match 1 on ordinary activity, 1000000, is more than the 0 events of ordinary activity."],
    ["a goal on a test list", (value) => Object.assign(value.attacker, { goal: "Read the history file." }), "The attacker's goal is set, but a test list has no goal: it is null."],
    ["a rerun compared with itself", (value) => Object.assign(value.steps[1] ?? {}, { role: "hardened", compared_with: "2" }), 'Step "2" names itself in compared_with; a rerun is compared with the step it repeats.'],
    ["a rerun compared with a later step", (value) => Object.assign(value.steps[0] ?? {}, { role: "variant", compared_with: "2" }), 'Step "1" names a later step in compared_with; a rerun repeats a step run before it.'],
    ["a test compared with another step", (value) => Object.assign(value.steps[1] ?? {}, { compared_with: "1" }), 'Step "2" has compared_with, but it is of role test; only a hardened or variant step repeats another.'],
    ["a repository without its owner", (value) => Object.assign(value.source, { repository: "example" }), 'The source\'s repository, "example", is not a GitHub repository as owner/name.'],
    ["a C1 control in a step's title", (value) => Object.assign(value.steps[0] ?? {}, { title: "Clear\u0085history" }), "The text at steps[0].title holds a control character, a direction mark or a line separator; only a step's command, output and plain sentence, the attacker's description and goal, and the notes may."],
    ["a right-to-left override in a host's name", (value) => Object.assign(value.network.hosts[0] ?? {}, { name: "tegrat\u202e" }), "The text at network.hosts[0].name holds a control character, a direction mark or a line separator; only a step's command, output and plain sentence, the attacker's description and goal, and the notes may."],
    ["a line separator in an event's text", (value) => Object.assign(value.events[0] ?? {}, { text: "one\u2028two" }), "The text at events[0].text holds a control character, a direction mark or a line separator; only a step's command, output and plain sentence, the attacker's description and goal, and the notes may."],
    ["a NUL in a step's command", (value) => Object.assign(value.steps[0] ?? {}, { command: "rm\u0000x" }), "The text at steps[0].command holds a NUL character."],
  ];
  it.each(refusals)("refuses %s, with the field named", (_case, change, message) => {
    const value = valid();
    change(value);
    expect(refusal(JSON.parse(JSON.stringify(value)))).toBe(message);
  });

  const pathRefusals: Refusal[] = [
    ["that begins with a canary", (value) => Object.assign(value.steps[0] ?? {}, { role: "canary" }), 'The first step of an attack path, Step "1", has the role canary: an attack path begins with a step of role test, and its race counts from that step\'s started.'],
    ["whose first step has no start", (value) => Object.assign(value, { steps: [step("1", null, null, { visibility: { answer: "telemetry only", basis: "events", events: 1 } }), value.steps[1]] }), 'The first step of an attack path, Step "1", has no started: its race counts from that step\'s start.'],
    ["with a goal time and no goal", (value) => Object.assign(value, { attacker: { ...value.attacker, goal: null }, score: { ...value.score, goal_seconds: 11 } }), "The score's goal_seconds is set, but the attacker has no goal."],
    ["with a goal time and no step", (value) => Object.assign(value, { steps: [], events: [], alerts: [], score: { ...value.score, goal_seconds: 5 } }), "The score's goal_seconds is set, but the recording has no step to reach the goal at."],
  ];
  it.each(pathRefusals)("refuses an attack path %s", (_case, change, message) => {
    const value = path();
    change(value);
    expect(refusal(JSON.parse(JSON.stringify(value)))).toBe(message);
  });

  // The app follows a recording as it grows: each copy it is sent is checked as a finished one is.
  it.each(refusals)("refuses %s in a recording that is still running, with the same words", (_case, change, message) => {
    const value = valid();
    change(value);
    expect(runningRefusal(running(value))).toBe(message);
  });

  it.each(pathRefusals)("refuses an attack path %s while it is still running, with the same words", (_case, change, message) => {
    const value = path();
    change(value);
    expect(runningRefusal(running(value))).toBe(message);
  });

  it("follows a running attack path from its first copy to its last: no step yet, a step under way, then the run's end", () => {
    // Before any step: the race has not begun, and nothing is there to begin it.
    const empty = { ...path(), steps: [], events: [], alerts: [], score: { ...path().score, steps: 0 } };
    expect(() => readRecording(running(empty), { running: true })).not.toThrow();
    // The second step has started and not ended, and its sensor has stamped one event so far.
    const underway = path();
    const second = underway.steps[1];
    if (!second) throw new Error("fixture");
    delete second.ended;
    underway.events = underway.events.filter((item) => item.id !== "2-2");
    underway.alerts = [];
    underway.score = { ...underway.score, alerted: 0 };
    expect(() => readRecording(running(underway), { running: true })).not.toThrow();
    // The finished copy is read by the replay page too; a running one only by the app.
    expect(() => readRecording(running(underway))).toThrow("This recording is still running");
    expect(() => readRecording(JSON.parse(JSON.stringify(path())))).not.toThrow();
  });

  it("keeps a free text's line breaks and the shapes every real recording has", () => {
    const value = path();
    Object.assign(value.steps[0] ?? {}, { command: "sh -c 'a'\nb\u2028", output: "\u001b[1mok" });
    value.notes = ["Two lines,\nof a note."];
    // A sensor stamps its own records: an event a little before its step's start, or after its end.
    value.events.unshift(event("1-0", "1", 9.99));
    value.events.splice(2, 0, event("1-2", "1", 11.2));
    value.score = { ...value.score, goal_seconds: 11 };
    value.ordinary = { events: 40, matches: [{ rule: "Sudo Use", level: "high", count: 3 }] };
    value.score.false_alerts = 1;
    expect(() => readRecording(JSON.parse(JSON.stringify(value)))).not.toThrow();
  });
});

describe("recording helpers", () => {
  it("groups events and matches by step", () => {
    const value = valid();
    expect(eventsByStep(value).get("2")?.map((item) => item.id)).toEqual(["2-1", "2-2"]);
    expect(eventsByStep(value).get("1")?.map((item) => item.id)).toEqual(["1-1"]);
    expect(alertsByStep(value).get("1")).toEqual([]);
  });

  it("never counts a match on the launcher line, and counts only published rules for the score", () => {
    const launcher = alert("l", "1", 10, [], { launcher_only: true });
    const lab = alert("b", "1", 10, [], { rule: { id: "x", title: "Lab rule", level: "high", origin: "lab" } });
    const review = alert("r", "1", 10, [], { counts: false, rule: { id: "y", title: "Review", level: "medium", origin: "pinned" } });
    expect(countsAsAlert(launcher)).toBe(false);
    expect(countsForScore(launcher)).toBe(false);
    expect(countsAsAlert(lab)).toBe(true);
    expect(countsForScore(lab)).toBe(false);
    expect(countsAsAlert(review)).toBe(false);
    expect(countsForScore(alert("p", "1", 10, []))).toBe(true);
  });
});
