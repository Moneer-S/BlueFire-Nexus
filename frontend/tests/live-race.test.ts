import { createElement } from "react";
import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { buildTimeline, frameAt } from "../src/live/playback";
import type { Timeline } from "../src/live/playback";
import { firstAlertClock, revealTime, runFacts } from "../src/live/moment";
import { placeFlags, RaceLine, whoIsWinning } from "../src/live/RaceLine";
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
function path(alerts: Alert[], goal?: number): Recording {
  const value = recording({
    when: "live",
    steps: [step("1", 10, 11), step("2", 20, 21), step("3", 30, 31)],
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
    expect(end(path([], 12))).toBe("The attacker reached the goal with no alert and no step stopped.");
  });

  it("tells the goal at the end of the run when goal_seconds rounds the last step's end up by less than a millisecond", () => {
    // The last step ends 21 s after the first step's start; the score says 21.0004 s.
    expect(end(path([], 21.0004))).toBe("The attacker reached the goal with no alert and no step stopped.");
  });

  it("says the attacker still reached the goal, with no step stopped, and how long after the first alert, when the alert came before the goal", () => {
    // The alert at 10.8 s, the goal 12 s after the first step's start at 10 s.
    expect(end(path([alert("a", "1", 10.8, ["1-1"])], 12))).toBe("The attacker reached the goal 11 s after the first alert, with no step stopped.");
  });

  it("says the attacker reached the goal first, and by how much, when the alert came after it", () => {
    expect(end(path([alert("a", "3", 30.5, ["3-1"])], 12))).toBe("The attacker reached the goal 8.5 s before the first alert.");
  });

  it("names the first alert's time from the first step before the goal is reached", () => {
    const value = path([alert("a", "1", 10.8, ["1-1"])], 12);
    const timeline = buildTimeline(value);
    expect(sentenceAt(value, timeline, timeline.fire.get("a") ?? Infinity)).toBe("The defense raised its first alert on step 1, 00:00.8 into the run.");
  });

  it("times a live alert from when it was raised, in the sentence, the flag's clock and the goal comparison", () => {
    // The test starts at 10 s, its event is at 10.8 s and its alert is raised at 25 s; the goal falls at 22 s.
    // The score's own number, counted from the event, disagrees: what the alerts say is shown.
    const value = path([alert("a", "1", 10.8, ["1-1"], { raised: at(25) })], 12);
    value.score = { ...value.score, first_alert_seconds: 0.8 };
    const timeline = buildTimeline(value);
    const first = timeline.firstAlert;
    expect(first ? firstAlertClock(value, runFacts(value, timeline), first) : null).toEqual({ seconds: 15, words: "into the run" });
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
      // The flags as a user and a screen reader get them: not the hidden copies the race line measures.
      const left = (selector: string) => {
        const flag = [...container.querySelectorAll<HTMLElement>(selector)].find((node) => !node.closest("[aria-hidden='true']"));
        return flag ? Number.parseFloat(flag.style.left) : null;
      };
      const parts = { sentence: container.querySelector(".lv-winning")?.textContent ?? "", first: left(".lv-flag:not(.is-goal)"), goal: left(".lv-flag.is-goal") };
      unmount();
      return parts;
    }

    it.each([false, true])("puts the goal at its recorded time, after the alert (canary first: %s)", (canary) => {
      const value = early(canary);
      const timeline = buildTimeline(value);
      expect(line(value, timeline.duration)).toMatchObject({ sentence: "The attacker reached the goal 50 ms after the first alert, with no step stopped." });
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
      expect(told.sentence).toBe("The attacker reached the goal 50 ms after the first alert, with no step stopped.");
      expect(told.goal ?? -1).toBeGreaterThan(told.first ?? Infinity);
    });

    it("fires an alert at its moment although it names an event stamped after it, and tells the goal after it", () => {
      // The alert raised at 19.95 s also names an event stamped at 20.5 s, after test 1's recorded
      // end at 20 s, which is the goal: it fires at 19.95 s all the same, before the clock reaches the goal.
      const value = early(false, true);
      const timeline = buildTimeline(value);
      expect(frameAt(timeline, timeline.fire.get("a") ?? 0).real).toBeCloseTo(timeOf(at(19.95)), 3);
      let shown = false;
      for (let screen = 0; screen <= timeline.duration; screen += 0.1) {
        const now = line(value, screen);
        expect(now.sentence).not.toBe("The attacker reached the goal with no alert and no step stopped.");
        // The goal is told only after the alert, and once told it is not taken back.
        if (now.goal !== null) expect(now.first).not.toBeNull();
        if (shown) expect(now.goal).not.toBeNull();
        shown = shown || now.goal !== null;
      }
      expect(shown).toBe(true);
      expect(line(value, timeline.duration).sentence).toBe("The attacker reached the goal 50 ms after the first alert, with no step stopped.");
    });
  });

  it("names the attacker's goal where the race says it was reached", () => {
    const value = { ...path([alert("a", "1", 10.8, ["1-1"])], 12), attacker: { kind: "scripted" as const, description: "A script", goal: "Read the domain admin's password." } };
    expect(end(value)).toBe("The attacker reached its goal, “Read the domain admin's password”, 11 s after the first alert, with no step stopped.");
  });

  it("counts the first alert's number, its place on the track and the goal from one moment, the first step's recorded start", () => {
    // Test 1 starts at 10 s, and a sensor stamped its event at 9.9 s: the track and the clock still count from 10 s.
    const value = recording({
      when: "live",
      steps: [step("1", 10, 20, { outcome: "alerted", visibility: { answer: "alert", basis: "rules", events: 1 } }), step("2", 30, 50)],
      events: [event("1-1", "1", 9.9), event("2-1", "2", 30.5)],
      alerts: [alert("a", "1", 9.9, ["1-1"], { raised: at(13) })],
    });
    const attack: Recording = { ...value, kind: "attack path", attacker: { ...value.attacker, goal: "Read the file." }, score: { ...value.score, first_alert_seconds: 3, goal_seconds: 40 } };
    const timeline = buildTimeline(attack);
    const facts = runFacts(attack, timeline);
    const first = timeline.firstAlert;
    if (!first) throw new Error("fixture");
    expect(facts.start).toBe(timeOf(at(10)));
    expect(firstAlertClock(attack, facts, first)?.seconds).toBeCloseTo(3, 6);
    // Where the flag sits on the track, as seconds from its 00:00 start, is the number it gives.
    expect((first.real - facts.start) / 1000).toBeCloseTo(3, 6);
    expect(((facts.goal ?? 0) - facts.start) / 1000).toBeCloseTo(40, 6);
    expect(sentenceAt(attack, timeline, timeline.duration)).toBe("The attacker reached its goal, “Read the file”, 37 s after the first alert, with no step stopped.");
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

  it("names a step of a path's tests by its count among them and any other step by its role, never by its order or its place", () => {
    const [canary, first, second] = value.steps;
    if (!canary || !first || !second) throw new Error("fixture");
    expect(stepLabel(value, canary)).toBe("the canary");
    expect(stepLabel(value, first)).toBe("step 1");
    expect(stepLabel(value, second)).toBe("step 2");
    const timeline = buildTimeline(value);
    expect(sentenceAt(value, timeline, timeline.duration)).toBe("The defense raised its first alert on step 2, 00:10.5 into the run.");
  });
});

describe("the labels of the race line's flags", () => {
  // A track of 1000 px; the first alert's label is 260 px wide, the goal's 140, "no alert" 60 and "00:00" 40.
  const alert = (x: number) => ({ x, width: 260 });
  const goal = (x: number) => ({ x, width: 140 });

  it("opens a label to the right of its flag, as on the shipped recording", () => {
    expect(placeFlags(1000, alert(400), null, 130, 40)).toMatchObject({ alert: 400, raised: false, waitEnd: 1000, startClearOfAlert: true });
  });

  it("opens a label near the right end to the left of its flag, inside the track", () => {
    expect(placeFlags(1000, alert(940), null, 130, 40).alert).toBe(690);
    expect(placeFlags(1000, null, goal(1000), 130, 40).goal).toBe(860);
  });

  it("keeps a first alert at 00:00 at the start, and says it covers the start's 00:00", () => {
    expect(placeFlags(1000, alert(0), null, 130, 40)).toMatchObject({ alert: 0, startClearOfAlert: false });
  });

  it("leaves two labels far apart on one row, also when the goal comes first", () => {
    expect(placeFlags(1000, alert(940), goal(300), 130, 40)).toMatchObject({ alert: 690, goal: 300, raised: false });
  });

  it("puts two labels within a second of each other one to each side when there is room", () => {
    // The alert's label ends 10 px past its flag at 510; the goal's starts at its flag at 530.
    expect(placeFlags(1000, alert(500), goal(530), 130, 40)).toMatchObject({ alert: 250, goal: 530, raised: false });
  });

  it("raises the goal's label a row when the two flags stand together at the end", () => {
    expect(placeFlags(1000, alert(950), goal(1000), 130, 40)).toMatchObject({ alert: 700, goal: 860, raised: true });
    expect(placeFlags(1000, alert(500), goal(500), 130, 40)).toMatchObject({ raised: true });
  });

  it("moves the words that wait for the first alert to the left of the goal's label", () => {
    expect(placeFlags(1000, null, goal(1000), 60, 40).waitEnd).toBe(848);
    expect(placeFlags(1000, null, null, 60, 40).waitEnd).toBe(1000);
  });

  it("opens every label to the right of its flag until the track is measured", () => {
    expect(placeFlags(0, alert(0), goal(0), 0, 0)).toMatchObject({ alert: 0, goal: 0, raised: false });
  });

  it("never lets two labels on one row touch, or a label leave the track, at any width the view supports", () => {
    const wrong: string[] = [];
    for (let track = 300; track <= 2400; track += 150) {
      for (let a = 0; a <= 20; a += 1) {
        for (let g = 0; g <= 20; g += 1) {
          const places = placeFlags(track, alert((a / 20) * track), goal((g / 20) * track), 60, 40);
          const alertLeft = places.alert ?? Number.NaN;
          const goalLeft = places.goal ?? Number.NaN;
          const inside = alertLeft >= 0 && alertLeft + 260 <= track && goalLeft >= 0 && goalLeft + 140 <= track && places.waitEnd <= track;
          const apart = places.raised || alertLeft + 260 + 12 <= goalLeft || goalLeft + 140 + 12 <= alertLeft;
          if (!inside || !apart) wrong.push(`${track} px, alert at ${a / 20}, goal at ${g / 20}`);
        }
      }
    }
    expect(wrong).toEqual([]);
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
