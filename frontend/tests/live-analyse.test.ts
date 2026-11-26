import { describe, expect, it } from "vitest";
import { FIRST_TABLE_STATE } from "../src/live/StepTable";
import { fixHint, groupMatches, otherRuns, roleRuns, seenBreakdown, stepRows, tableRows } from "../src/live/analyse";
import { elapsed, ordinal, ordinaryAlertEvents, span, stepLabel, stepShortName } from "../src/live/format";
import { buildTimeline } from "../src/live/playback";
import type { Recording } from "../src/live/recording";
import { alert, event, recording, step } from "./live-fixture";

const run = recording({
  steps: [
    step("1", 1, 2, { role: "canary", outcome: "alerted", technique: { id: "T1070.003" } }),
    step("2", 3, 4, { outcome: "seen", technique: { id: "T1070.003" } }),
    step("3", 5, 6, { outcome: "unseen", visibility: { answer: "no telemetry", basis: "none", events: 0 } }),
    step("4", 7, 8, { outcome: "alerted", technique: { id: "T1070.003" } }),
    step("5", 9, 10, { role: "hardened", outcome: "stopped", compared_with: "2", technique: { id: "T1070.003" } }),
    step("6", 11, 12, { role: "hardened", outcome: "seen", compared_with: "4" }),
  ],
  events: [event("e1", "2", 3.1), event("e2", "2", 3.2), event("e3", "4", 7.1)],
  alerts: [
    alert("pub", "4", 7.1, ["e3"]),
    alert("lab", "4", 7.1, ["e3"], { detector: "lab", rule: { id: "r-lab", title: "Ours", level: "high", origin: "lab" } }),
    alert("rev", "2", 3.1, ["e1"], { counts: false, rule: { id: "r-rev", title: "Review", level: "medium", origin: "pinned" } }),
    alert("launch", "2", 3, [], { counts: true, launcher_only: true }),
  ],
});
const rows = stepRows(run, buildTimeline(run));

describe("the table of every step", () => {
  it("puts the step nobody saw first, then the alerted ones, each group in run order", () => {
    const shown = tableRows(rows, { role: "all", outcome: null }, { key: FIRST_TABLE_STATE.sort, ascending: FIRST_TABLE_STATE.ascending });
    expect(shown.map((row) => row.step.id)).toEqual(["3", "1", "4", "2", "6", "5"]);
  });

  it("filters by role and by outcome together", () => {
    expect(tableRows(rows, { role: "hardened", outcome: null }, { key: "order", ascending: true }).map((row) => row.step.id)).toEqual(["5", "6"]);
    expect(tableRows(rows, { role: "test", outcome: "alerted" }, { key: "order", ascending: true }).map((row) => row.step.id)).toEqual(["4"]);
    expect(tableRows(rows, { role: "canary", outcome: "seen" }, { key: "order", ascending: true })).toEqual([]);
  });

  it("counts each sensor's events for a step", () => {
    const second = rows.find((row) => row.step.id === "2");
    expect(second?.bySensor.get("sysmon")).toBe(2);
    expect(rows.find((row) => row.step.id === "3")?.bySensor.size).toBe(0);
  });
});

describe("the rules that matched a step", () => {
  it("keeps published and lab rules apart, alert and review apart, and names the launcher line", () => {
    const fourth = groupMatches(run.alerts.filter((item) => item.step === "4"));
    expect(fourth.alert.map((item) => item.id)).toEqual(["pub"]);
    expect(fourth.labAlert.map((item) => item.id)).toEqual(["lab"]);
    const second = groupMatches(run.alerts.filter((item) => item.step === "2"));
    expect(second.review.map((item) => item.id)).toEqual(["rev"]);
    expect(second.launcher.map((item) => item.id)).toEqual(["launch"]);
    expect(second.alert).toEqual([]);
  });
});

describe("a step's neighbours and its gap", () => {
  it("lists the other runs of the same technique, tests first", () => {
    const own = run.steps.find((item) => item.id === "2");
    expect(own).toBeDefined();
    if (!own) return;
    expect(otherRuns(run, own).map((item) => item.id)).toEqual(["4", "1", "5"]);
  });

  it("says where the gap is for a step that got through, and nothing for one that alerted or a canary", () => {
    const by = (id: string) => run.steps.find((item) => item.id === id);
    const seen = by("2");
    const unseen = by("3");
    const alerted = by("4");
    const canary = by("1");
    if (!seen || !unseen || !alerted || !canary) throw new Error("fixture");
    // The hint says why a sensor is the place to start, in the recording's own words: its one record by the noun the recording gives it.
    const lab = { ...unseen, technique: { id: "T9999" }, visibility: { answer: "no telemetry" as const, basis: "nothing of the test was recorded besides its launcher's start", events: 0 } };
    expect(fixHint(run, lab)).toBe("Start with a sensor: its only record is its launcher's start, which never counts.");
    const other = { ...lab, visibility: { ...lab.visibility, basis: "No event of the agent named the step's session." } };
    expect(fixHint(run, other)).toBe("Start with a sensor: no event of the agent named the step's session.");
    // Another engine's basis that names a launcher, or starts with an acronym, is still told in its own words.
    const neither = { ...lab, visibility: { ...lab.visibility, basis: "Neither the test nor its launcher was recorded." } };
    expect(fixHint(run, neither)).toBe("Start with a sensor: neither the test nor its launcher was recorded.");
    const edr = { ...lab, visibility: { ...lab.visibility, basis: "EDR saw nothing of the test" } };
    expect(fixHint(run, edr)).toBe("Start with a sensor: EDR saw nothing of the test.");
    expect(fixHint(run, seen)).toBe("No rule matched this step: start by writing one.");
    expect(fixHint(run, alerted)).toBeNull();
    expect(fixHint(run, { ...canary, outcome: "seen" })).toBeNull();
  });

  it("points a step nobody saw at the other runs of its technique that a sensor recorded, each by its name", () => {
    const base = run.steps.find((item) => item.id === "3");
    if (!base) throw new Error("fixture");
    const unseen = { ...base, id: "9", order: 9, technique: { id: "T1070.003" }, visibility: { answer: "no telemetry" as const, basis: "nothing of the test was recorded besides its launcher's start", events: 0 } };
    // A test by its count among the tests, any other step by its role: never by its place in the list.
    expect(fixHint(run, unseen)).toBe("Start with a sensor: its only record is its launcher's start, which never counts. Other runs of T1070.003 were recorded: the canary alerted, test 3 alerted, test 1 seen.");
  });

  it("names a published rule to start from when rules already matched a seen step below alert level, with its noise on ordinary activity", () => {
    const seen = run.steps.find((item) => item.id === "2");
    if (!seen) throw new Error("fixture");
    const groups = groupMatches(run.alerts.filter((item) => item.step === "2"));
    expect(fixHint(run, seen, groups)).toBe('To alert here, start from the rule "Review": it matched this step at medium level.');
    const quiet: Recording = { ...run, ordinary: { events: 50, matches: [] } };
    expect(fixHint(quiet, seen, groups)).toBe('To alert here, start from the rule "Review": it matched this step at medium level, and nothing in ordinary activity.');
    const noisy: Recording = { ...run, ordinary: { events: 50, matches: [{ rule: "Review", level: "medium", count: 5 }] } };
    expect(fixHint(noisy, seen, groups)).toBe('To alert here, start from the rule "Review": it matched this step at medium level, and 5 events of ordinary activity too.');
  });

  it("splits the tests seen with no alert by what the published rules made of them", () => {
    expect(seenBreakdown(run)).toEqual({ total: 1, review: 1, info: 0, launcher: 0, none: 0 });
  });

  it("does not count a test whose only matches are informational as for review, as the table does not", () => {
    const informational: Recording = { ...run, alerts: run.alerts.map((item) => (item.id === "rev" ? { ...item, rule: { ...item.rule, level: "informational" as const } } : item)) };
    expect(seenBreakdown(informational)).toEqual({ total: 1, review: 0, info: 1, launcher: 0, none: 0 });
  });

  it("groups consecutive steps of one role for the brackets over the lanes", () => {
    expect(roleRuns(run.steps).map((item) => [item.role, item.count])).toEqual([
      ["canary", 1],
      ["test", 3],
      ["hardened", 2],
    ]);
  });
});

describe("numbers that could look wrong", () => {
  it("counts a step's place in words", () => {
    expect([1, 2, 3, 11, 22, 46].map(ordinal)).toEqual(["1st", "2nd", "3rd", "11th", "22nd", "46th"]);
  });

  it("counts the events of ordinary activity a rule alerted on, and nothing for a match below alert level", () => {
    const withOrdinary: Recording = {
      ...run,
      ordinary: {
        events: 100,
        matches: [
          { rule: "Rule pub", level: "high", count: 3 },
          { rule: "Review", level: "medium", count: 9 },
        ],
      },
    };
    expect(ordinaryAlertEvents(withOrdinary, "Rule pub")).toBe(3);
    expect(ordinaryAlertEvents(withOrdinary, "Review")).toBe(0);
    expect(ordinaryAlertEvents(run, "Rule pub")).toBe(0);
  });
});

describe("the name of a step", () => {
  it("names a test by its count among the tests, and any other step by its role and the step it reruns", () => {
    const reruns = recording({
      steps: [
        step("test:aa", 1, 2, { role: "canary" }),
        step("test:bb", 3, 4, { role: "control" }),
        step("test:cc", 5, 6),
        step("test:dd", 7, 8),
        step("hardened:cc", 9, 10, { role: "hardened", compared_with: "test:cc" }),
        step("variant:dd:1", 11, 12, { role: "variant", compared_with: "test:dd" }),
        step("variant:dd:2", 13, 14, { role: "variant", compared_with: "test:dd" }),
        step("canary:end", 15, 16, { role: "canary" }),
      ],
    });
    const names = reruns.steps.map((item) => stepLabel(reruns, item));
    expect(names).toEqual(["canary 1", "the control", "test 1", "test 2", "hardened rerun of test 1", "variant 1 of test 2", "variant 2 of test 2", "canary 2"]);
    expect(reruns.steps.map((item) => stepShortName(reruns, item))).toEqual(["canary 1", "control", "test 1", "test 2", "rerun of test 1", "variant 1 of test 2", "variant 2 of test 2", "canary 2"]);
    // Each name is one step's alone.
    expect(new Set(names).size).toBe(names.length);
  });
});

describe("lengths of time in words", () => {
  it("uses milliseconds, seconds or minutes as fits", () => {
    expect(span(144)).toBe("144 ms");
    expect(span(4200)).toBe("4.2 s");
    expect(span(65_000)).toBe("1 min 5 s");
    expect(span(119_700)).toBe("2 min");
  });

  it("rounds a clock reading before it splits minutes and seconds", () => {
    expect(elapsed(239.97)).toBe("04:00.0");
    expect(elapsed(239.851)).toBe("03:59.9");
    expect(elapsed(59.6, 0)).toBe("01:00");
  });
});
