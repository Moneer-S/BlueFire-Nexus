import { createElement } from "react";
import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { buildTimeline, frameAt } from "../src/live/playback";
import type { Timeline } from "../src/live/playback";
import { firstAlertClock, revealTime, runFacts } from "../src/live/moment";
import { RaceLine, whoIsWinning } from "../src/live/RaceLine";
import { runLink, stepLabel } from "../src/live/format";
import type { Alert, Recording } from "../src/live/recording";
import { timeOf } from "../src/live/recording";
import { alert, at, event, recording, step } from "./live-fixture";

/** The race sentence at screen time `screen`, with the score so far. */
function sentenceAt(value: Recording, timeline: Timeline, screen: number): string {
  const frame = frameAt(timeline, screen);
  return whoIsWinning(value, frame, frame.score, runFacts(value, timeline));
}

/** Three tests on an attack path, at 10, 20 and 30 s; the first step starts the clock. */
function path(alerts: Alert[], goal?: number, firstStarts = true): Recording {
  const value = recording({
    when: "live",
    steps: [firstStarts ? step("1", 10, 11) : step("1", null, null), step("2", 20, 21), step("3", 30, 31)],
    events: [event("1-1", "1", 10.8), event("3-1", "3", 30.5)],
    alerts,
  });
  return { ...value, kind: "attack path", score: { ...value.score, ...(goal === undefined ? {} : { goal_seconds: goal }) } };
}

const end = (value: Recording) => {
  const timeline = buildTimeline(value);
  return sentenceAt(value, timeline, timeline.duration);
};

describe("the race sentence on an attack path", () => {
  it("says only that no step alerted when the recording has no goal", () => {
    expect(end(path([]))).toBe("No alert on any step.");
  });

  it("says the attacker reached the goal with no alert", () => {
    expect(end(path([], 12))).toBe("The attacker reached the goal with no alert.");
  });

  it("says the defense alerted first, and by how much, when the alert came before the goal", () => {
    // The alert at 10.8 s, the goal 12 s after the first step's start at 10 s.
    expect(end(path([alert("a", "1", 10.8, ["1-1"])], 12))).toBe("The defense alerted 11 s before the attacker reached the goal.");
  });

  it("says the attacker reached the goal first, and by how much, when the alert came after it", () => {
    expect(end(path([alert("a", "3", 30.5, ["3-1"])], 12))).toBe("The attacker reached the goal 8.5 s before the first alert.");
  });

  it("names the first alert's time from the first test step before the goal is reached", () => {
    const value = path([alert("a", "1", 10.8, ["1-1"])], 12);
    const timeline = buildTimeline(value);
    expect(sentenceAt(value, timeline, timeline.fire.get("a") ?? Infinity)).toBe("The defense raised its first alert on test 1, 00:00.8 after the first test step.");
  });

  it("times a live alert from when it was raised, in the sentence, the flag's clock and the goal comparison", () => {
    // The test starts at 10 s, its event is at 10.8 s and its alert is raised at 25 s; the goal falls at 22 s.
    // The score's own number, counted from the event, disagrees: what the alerts say is shown.
    const value = path([alert("a", "1", 10.8, ["1-1"], { raised: at(25) })], 12);
    value.score = { ...value.score, first_alert_seconds: 0.8 };
    const timeline = buildTimeline(value);
    const first = timeline.firstAlert;
    expect(first ? firstAlertClock(value, runFacts(value, timeline), first) : null).toEqual({ seconds: 15, words: "after the first test step" });
    expect(sentenceAt(value, timeline, timeline.fire.get("a") ?? Infinity)).toBe("The attacker reached the goal 3.0 s before the first alert.");
  });

  describe("with an event stamped before its step's recorded start", () => {
    // Test 1 starts at 10 s and ends at 20 s, the goal; its event is stamped at 9.9 s and
    // its alert raised live at 19.95 s, 50 ms before the goal. A canary may run first.
    function early(canary = false, tail = false): Recording {
      const tests = [step("1", 10, 20, { outcome: "alerted", visibility: { answer: "alert", basis: "rules", events: tail ? 2 : 1 } }), step("2", 30, 31)];
      const value = recording({
        when: "live",
        steps: canary ? [step("0", 2, 3, { role: "canary" }), ...tests] : tests,
        events: [...(canary ? [event("0-1", "0", 2.5)] : []), event("1-1", "1", 9.9), ...(tail ? [event("1-2", "1", 20.5)] : []), event("2-1", "2", 30.5)],
        alerts: [alert("a", "1", 9.9, tail ? ["1-1", "1-2"] : ["1-1"], { raised: at(19.95) })],
      });
      return { ...value, kind: "attack path", score: { ...value.score, first_alert_seconds: 9.95, goal_seconds: canary ? 18 : 10 } };
    }

    /** The race line at screen time `screen`: its sentence and the left edges of its two flags. */
    function line(value: Recording, screen: number) {
      const timeline = buildTimeline(value);
      const frame = frameAt(timeline, screen);
      const revealed = frame.ended || (frame.segment !== null && screen >= revealTime(timeline, frame.segment));
      const { container, unmount } = render(createElement(RaceLine, { recording: value, timeline, frame, facts: runFacts(value, timeline), score: frame.score, revealed }));
      const left = (selector: string) => {
        const flag = container.querySelector<HTMLElement>(selector);
        return flag ? Number.parseFloat(flag.style.left) : null;
      };
      const parts = { sentence: container.querySelector(".lv-winning")?.textContent ?? "", first: left(".lv-flag:not(.is-goal)"), goal: left(".lv-flag.is-goal") };
      unmount();
      return parts;
    }

    it.each([false, true])("puts the goal at its recorded time, after the alert (canary first: %s)", (canary) => {
      const value = early(canary);
      const timeline = buildTimeline(value);
      expect(line(value, timeline.duration)).toMatchObject({ sentence: "The defense alerted 50 ms before the attacker reached the goal." });
      const { first, goal } = line(value, timeline.duration);
      expect(first).not.toBeNull();
      expect(goal ?? -1).toBeGreaterThan(first ?? Infinity);
      // The clock reaches the goal at the end of test 1's body, while the alert raised at 19.95 s
      // travels to its rule engine: the goal waits until that alert is told, and never comes first.
      const segment = timeline.segments.find((item) => item.step.id === "1");
      if (!segment) throw new Error("fixture");
      expect(frameAt(timeline, segment.bodyEnd).real).toBe(timeOf(at(20)));
      expect(line(value, segment.bodyEnd)).toEqual({ sentence: "No alert yet.", first: null, goal: null });
      const told = line(value, revealTime(timeline, segment));
      expect(told.sentence).toBe("The defense alerted 50 ms before the attacker reached the goal.");
      expect(told.goal ?? -1).toBeGreaterThan(told.first ?? Infinity);
    });

    it("holds the goal back for an alert raised before it that fires on screen only after it", () => {
      // The alert raised at 19.95 s also names an event stamped at 20.5 s, after test 1's recorded
      // end at 20 s, which is the goal: it fires once that event has arrived, with the clock past the goal.
      const value = early(false, true);
      const timeline = buildTimeline(value);
      expect(frameAt(timeline, timeline.fire.get("a") ?? 0).real).toBeGreaterThan(timeOf(at(20)));
      let shown = false;
      for (let screen = 0; screen <= timeline.duration; screen += 0.1) {
        const now = line(value, screen);
        expect(now.sentence).not.toBe("The attacker reached the goal with no alert.");
        // The goal is told only after the alert, and once told it is not taken back.
        if (now.goal !== null) expect(now.first).not.toBeNull();
        if (shown) expect(now.goal).not.toBeNull();
        shown = shown || now.goal !== null;
      }
      expect(shown).toBe(true);
      expect(line(value, timeline.duration).sentence).toBe("The defense alerted 50 ms before the attacker reached the goal.");
    });
  });

  it("counts the goal from the earliest recorded start when the first step has none", () => {
    // Test 1 has no start and its event is at 10.8 s; test 2 starts at 20 s, so the goal, 11 s on, is test 3's end at 31 s.
    expect(end(path([alert("a", "3", 30.5, ["3-1"])], 11, false))).toBe("The defense alerted 500 ms before the attacker reached the goal.");
  });

  it("gives no time when the first test has no recorded start", () => {
    const value = path([alert("a", "1", 10.8, ["1-1"])], undefined, false);
    const timeline = buildTimeline(value);
    expect(sentenceAt(value, timeline, timeline.duration)).toBe("The defense raised its first alert on test 1.");
  });
});

describe("the race sentence on a test list", () => {
  it("counts the tests that have run while none has taken effect", () => {
    const value = recording({
      steps: [
        step("1", 10, 11, { happened: { answer: "not attempted", basis: "a program was missing" }, outcome: "no effect" }),
        step("2", 20, 21, { happened: { answer: "attempted without effect", basis: "it changed nothing" }, outcome: "no effect" }),
        step("3", 30, 31),
      ],
    });
    const timeline = buildTimeline(value);
    const third = timeline.segments[2];
    if (!third) throw new Error("fixture");
    expect(sentenceAt(value, timeline, third.start + 0.1)).toBe("2 of 3 tests have run; none is yet alerted, seen or unseen.");
    const first = timeline.segments[0];
    if (!first) throw new Error("fixture");
    expect(sentenceAt(value, timeline, first.start + 0.1)).toBe("The first test is running.");
  });
});

describe("naming a step", () => {
  // Orders skip positions that were not steps: 1, 5 and 9.
  const value: Recording = {
    ...recording({
      steps: [step("1", 10, 11, { role: "canary", outcome: "alerted" }), step("5", 20, 21), step("9", 30, 31, { outcome: "alerted" })],
      events: [event("9-1", "9", 30.5)],
      alerts: [alert("a", "9", 30.5, ["9-1"])],
    }),
    kind: "attack path",
  };

  it("uses the step's place, not its order", () => {
    const [canary, first, second] = value.steps;
    if (!canary || !first || !second) throw new Error("fixture");
    expect(stepLabel(value, canary)).toBe("step 1");
    expect(stepLabel(value, first)).toBe("test 1");
    expect(stepLabel(value, second)).toBe("test 2");
    const timeline = buildTimeline(value);
    expect(sentenceAt(value, timeline, timeline.duration)).toBe("The defense raised its first alert on test 2, 00:10.5 after the first test step.");
  });
});

describe("the link to the run that made a recording", () => {
  const link = (address: unknown, repository: string | null = "example/lab") => runLink(repository === null ? { run_url: address } : { repository, run_url: address });

  it("links a GitHub Actions run of the recording's own repository", () => {
    expect(link("https://github.com/example/lab/actions/runs/123")).toBe("https://github.com/example/lab/actions/runs/123");
    expect(link("https://github.com/example/lab/actions/runs/123/attempts/2")).toBe("https://github.com/example/lab/actions/runs/123/attempts/2");
    expect(link("https://github.com/other/repo/actions/runs/9", null)).toBe("https://github.com/other/repo/actions/runs/9");
  });

  it("links nothing else", () => {
    expect(link("https://github.example.com/example/lab/actions/runs/123")).toBeNull();
    expect(link("http://github.com/example/lab/actions/runs/123")).toBeNull();
    expect(link("https://github.com/other/lab/actions/runs/123")).toBeNull();
    expect(link("https://github.com/example/lab/pulls")).toBeNull();
    expect(link("https://user@github.com/example/lab/actions/runs/123")).toBeNull();
    expect(link("javascript:alert(1)")).toBeNull();
    expect(link(["https://github.com/example/lab/actions/runs/123"])).toBeNull();
    expect(link(undefined)).toBeNull();
  });
});
