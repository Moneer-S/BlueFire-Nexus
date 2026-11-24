import { describe, expect, it } from "vitest";
import { buildTimeline, frameAt } from "../src/live/playback";
import type { Timeline } from "../src/live/playback";
import { firstAlertClock, runFacts } from "../src/live/moment";
import { whoIsWinning } from "../src/live/RaceLine";
import { runLink, stepLabel } from "../src/live/format";
import type { Alert, Recording } from "../src/live/recording";
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
