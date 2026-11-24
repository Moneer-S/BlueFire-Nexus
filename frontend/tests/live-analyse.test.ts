import { describe, expect, it } from "vitest";
import { FIRST_TABLE_STATE } from "../src/live/StepTable";
import { fixHint, groupMatches, otherRuns, roleRuns, seenBreakdown, stepRows, tableRows } from "../src/live/analyse";
import { elapsed, falseAlertsOf, ordinal, span } from "../src/live/format";
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
    expect(fixHint(run, { ...unseen, technique: { id: "T9999" } })).toBe("No sensor recorded it: start with a sensor.");
    expect(fixHint(run, seen)).toBe("Recorded, no rule at alert level: start with a rule.");
    expect(fixHint(run, alerted)).toBeNull();
    expect(fixHint(run, { ...canary, outcome: "seen" })).toBeNull();
  });

  it("points a step nobody saw at the other runs of its technique that a sensor recorded", () => {
    const base = run.steps.find((item) => item.id === "3");
    if (!base) throw new Error("fixture");
    const unseen = { ...base, id: "9", order: 9, technique: { id: "T1070.003" } };
    // Tests are named by their place among the tests, other steps by their place in the run.
    expect(fixHint(run, unseen)).toBe("Start with a sensor: other runs of T1070.003 were recorded (step 1 alerted, test 3 alerted, test 1 seen).");
  });

  it("names a published rule to start from when rules already matched a seen step below alert level, with its noise on ordinary activity", () => {
    const seen = run.steps.find((item) => item.id === "2");
    if (!seen) throw new Error("fixture");
    const groups = groupMatches(run.alerts.filter((item) => item.step === "2"));
    expect(fixHint(run, seen, groups)).toBe("Start with a rule: Review (medium) matched it below alert level.");
    const quiet: Recording = { ...run, ordinary: { events: 50, matches: [] } };
    expect(fixHint(quiet, seen, groups)).toBe("Start with a rule: Review (medium) matched it below alert level, and nothing in ordinary activity.");
    const noisy: Recording = { ...run, ordinary: { events: 50, matches: [{ rule: "Review", level: "medium", count: 5 }] } };
    expect(fixHint(noisy, seen, groups)).toBe("Start with a rule: Review (medium) matched it below alert level, and 5 ordinary events.");
  });

  it("splits the tests seen with no alert by what the published rules made of them", () => {
    expect(seenBreakdown(run)).toEqual({ total: 1, review: 1, launcher: 0, none: 0 });
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

  it("finds the false alerts a rule raised on ordinary activity, and nothing for a match below alert level", () => {
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
    expect(falseAlertsOf(withOrdinary, "Rule pub")).toBe(3);
    expect(falseAlertsOf(withOrdinary, "Review")).toBe(0);
    expect(falseAlertsOf(run, "Rule pub")).toBe(0);
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
