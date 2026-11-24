import { describe, expect, it } from "vitest";
import { alertsByStep, countsAsAlert, countsForScore, eventsByStep, readRecording, RecordingError, timeOf } from "../src/live/recording";
import { alert, event, recording, step } from "./live-fixture";

function valid() {
  return recording({
    steps: [step("1", 10, 11), step("2", 20, 21)],
    events: [event("1-1", "1", 10.1), event("2-1", "2", 20.2), event("2-2", "2", 20.4)],
    alerts: [alert("a1", "2", 20.4, ["2-2"])],
  });
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
    ["an event's fields", ["events", 0, "fields"], { exit: { code: 1 } }, 'The field "exit" of Event "1-1" is not text, a number, true or false, null or a list of text.'],
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

  it("accepts up to six digits after the second, as the service does, and plays them to the millisecond", () => {
    const read = readRecording(changed(["steps", 0, "started"], "2026-01-01T10:00:09.999999Z"));
    expect(timeOf(read.steps[0]?.started ?? "")).toBe(Date.parse("2026-01-01T10:00:09.999Z"));
    expect(timeOf("2026-01-01T10:00:00.000001Z")).toBe(Date.parse("2026-01-01T10:00:00Z"));
    expect(refusal(changed(["steps", 0, "started"], "2026-01-01T10:00:10.0000001Z"))).toBe('The start of Step "1" is not a UTC time such as 2026-11-17T17:07:23.834Z: "2026-01-01T10:00:10.0000001Z".');
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
