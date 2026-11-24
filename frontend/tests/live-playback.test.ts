import { describe, expect, it } from "vitest";
import { bodySeconds, buildTimeline, evenPosition, evenTime, frameAt, PLAYBACK_RULE, realToScreen, screenToReal, seekStep, stepPosition } from "../src/live/playback";
import { timeOf } from "../src/live/recording";
import { alert, at, event, recording, step } from "./live-fixture";

// Step 1: a quick test that alerts. Step 2: a long test that is only seen,
// with an event a few ms before its start. Step 3: a canary that alerts.
// Step 4: a hardened rerun that was stopped. Step 5: a test that is unseen.
function run(when: "live" | "after the run" = "after the run", raised?: string) {
  return recording({
    when,
    steps: [
      step("1", 10, 10.15, { outcome: "alerted", visibility: { answer: "alert", basis: "rule", events: 2 } }),
      step("2", 40, 100),
      step("3", 103, 103.2, { role: "canary", outcome: "alerted" }),
      step("4", 110, 110.5, { role: "hardened", outcome: "stopped", happened: { answer: "blocked", basis: "refused" } }),
      step("5", 120, 121, { outcome: "unseen", visibility: { answer: "no telemetry", basis: "none", events: 0 } }),
    ],
    events: [
      event("1-1", "1", 10.01),
      event("1-2", "1", 10.1),
      event("2-0", "2", 39.997),
      event("2-1", "2", 41),
      event("2-2", "2", 70),
      event("3-1", "3", 103.1),
      event("4-1", "4", 110.2),
    ],
    alerts: [
      alert("launcher", "2", 40, [], { counts: false, launcher_only: true, rule: { id: "l", title: "Launcher", level: "medium", origin: "pinned" } }),
      alert("first", "1", 10.1, ["1-2"], raised === undefined ? {} : { raised }),
      alert("review", "2", 41, ["2-1"], { counts: false, rule: { id: "m", title: "Review", level: "medium", origin: "pinned" } }),
      alert("canary", "3", 103.1, ["3-1"]),
    ],
  });
}

describe("the playback rule", () => {
  it("stretches short steps and squeezes long ones into a bounded range", () => {
    expect(bodySeconds(0)).toBe(PLAYBACK_RULE.minBody);
    expect(bodySeconds(0.15)).toBeGreaterThan(PLAYBACK_RULE.minBody);
    expect(bodySeconds(5)).toBeGreaterThan(bodySeconds(1));
    expect(bodySeconds(60)).toBeGreaterThan(bodySeconds(10));
    expect(bodySeconds(3600)).toBeLessThan(PLAYBACK_RULE.maxBody);
    expect(bodySeconds(Number.NaN)).toBe(PLAYBACK_RULE.minBody);
    expect(bodySeconds(-5)).toBe(PLAYBACK_RULE.minBody);
  });

  it("shortens every silence between steps to one beat", () => {
    const timeline = buildTimeline(run());
    expect(timeline.gaps).toHaveLength(4);
    for (const gap of timeline.gaps) expect(gap.end - gap.start).toBeCloseTo(PLAYBACK_RULE.beat);
    expect(timeline.gaps[0]?.realEnd).toBe(timeOf(at(39.997)));
  });
});

describe("the timeline", () => {
  it("is monotonic, and maps screen time to real time and back", () => {
    const timeline = buildTimeline(run());
    let lastReal = -Infinity;
    for (let t = 0; t <= timeline.duration; t += 0.05) {
      const real = screenToReal(timeline, t);
      expect(real).toBeGreaterThanOrEqual(lastReal);
      lastReal = real;
    }
    for (const segment of timeline.segments) {
      const middle = (segment.bodyStart + segment.bodyEnd) / 2;
      expect(realToScreen(timeline, screenToReal(timeline, middle))).toBeCloseTo(middle, 6);
    }
    expect(screenToReal(timeline, timeline.duration)).toBe(timeOf(at(121)));
    expect(realToScreen(timeline, timeOf(at(70)))).toBeGreaterThan(timeline.segments[1]?.bodyStart ?? Infinity);
  });

  it("seeks to a step and a position inside it", () => {
    const timeline = buildTimeline(run());
    const start = seekStep(timeline, "4", 0);
    const later = seekStep(timeline, "4", 0.6);
    const end = seekStep(timeline, "4", 1);
    if (start === null || later === null || end === null) throw new Error("step 4 should be found");
    expect(frameAt(timeline, start).step?.id).toBe("4");
    expect(frameAt(timeline, later).step?.id).toBe("4");
    expect(frameAt(timeline, later).progress).toBeCloseTo(0.6);
    expect(frameAt(timeline, end).step?.id).toBe("4");
    expect(seekStep(timeline, "nope")).toBeNull();
  });

  it("seeks past a step's end into the silence after it, where that step is still on screen", () => {
    const timeline = buildTimeline(run());
    const silence = seekStep(timeline, "4", 1.5);
    if (silence === null) throw new Error("step 4 should be found");
    const frame = frameAt(timeline, silence);
    expect(frame.step?.id).toBe("4");
    expect(frame.gap).not.toBeNull();
    expect(frameAt(timeline, seekStep(timeline, "4", 9) ?? Number.NaN).step?.id).toBe("5");
    // The last step has no silence after it: past its end is its end.
    expect(seekStep(timeline, "5", 1.5)).toBe(seekStep(timeline, "5", 1));
  });

  it("gives the place of a frame in its step, also in the silence after it, so that seeking there reads the same moment", () => {
    const timeline = buildTimeline(run());
    // Inside the step the place is how far the step has got.
    const inside = frameAt(timeline, seekStep(timeline, "4", 0.6) ?? Number.NaN);
    expect(stepPosition(inside)).toBeCloseTo(0.6);
    // In the silence after it the step's own progress stays at 1, and the place goes on above it.
    const silence = seekStep(timeline, "4", 1.5);
    if (silence === null) throw new Error("step 4 should be found");
    const frame = frameAt(timeline, silence);
    expect(frame.progress).toBe(1);
    expect(stepPosition(frame)).toBeCloseTo(1.5);
    expect(seekStep(timeline, "4", stepPosition(frame))).toBeCloseTo(silence, 6);
    // The silence's last moment stays short of 2, which is the next step's start.
    if (!frame.gap) throw new Error("step 4 should have a silence after it");
    const last = frameAt(timeline, frame.gap.end - 0.0001);
    expect(last.step?.id).toBe("4");
    expect(stepPosition(last)).toBeLessThan(2);
    expect(frameAt(timeline, seekStep(timeline, "4", stepPosition(last)) ?? Number.NaN).step?.id).toBe("4");
  });

  it("gives every step the same width on the scrubber, and maps a position back to its time", () => {
    const timeline = buildTimeline(run());
    const count = timeline.segments.length;
    timeline.segments.forEach((segment, index) => {
      expect(evenPosition(timeline, segment.start)).toBeCloseTo(index / count);
      expect(frameAt(timeline, evenTime(timeline, (index + 0.5) / count)).step?.id).toBe(segment.step.id);
    });
    for (const t of [0, 1.3, 7.7, timeline.duration / 2, timeline.duration]) expect(evenTime(timeline, evenPosition(timeline, t))).toBeCloseTo(t);
    expect(evenPosition(timeline, timeline.duration)).toBe(1);
  });

  it("delivers events in time order, never before their step's segment begins", () => {
    const timeline = buildTimeline(run());
    const times = timeline.arrivals.map(({ event: item }) => timeOf(item.time));
    expect(times).toEqual([...times].sort((a, b) => a - b));
    for (const { event: item, at: arrival } of timeline.arrivals) {
      const segment = timeline.segments.find((each) => each.step.id === item.step);
      expect(arrival).toBeGreaterThanOrEqual(segment?.start ?? Infinity);
      expect(arrival).toBeLessThanOrEqual(segment?.end ?? -Infinity);
    }
    const two = timeline.segments[1];
    if (!two) throw new Error("step 2 should be there");
    expect(frameAt(timeline, two.start).events).toEqual([]);
    expect(frameAt(timeline, two.end).events.map((item) => item.id)).toEqual(["2-0", "2-1", "2-2"]);
  });

  it("fires an alert when its event has arrived, for rules run after the run", () => {
    const timeline = buildTimeline(run());
    const fire = timeline.fire.get("first");
    expect(fire).toBe(timeline.arrival.get("1-2"));
    if (fire === undefined) throw new Error("the alert should fire");
    expect(frameAt(timeline, fire - 0.01).alerts.map((item) => item.id)).toEqual([]);
    expect(frameAt(timeline, fire).alerts.map((item) => item.id)).toEqual(["first"]);
  });

  it("fires an alert at its raised time when it has one", () => {
    const timeline = buildTimeline(run("live", at(43)));
    const fire = timeline.fire.get("first");
    expect(fire).toBeCloseTo(realToScreen(timeline, timeOf(at(43))), 6);
    expect(fire).toBeGreaterThan(timeline.segments[1]?.bodyStart ?? Infinity);
  });
});

describe("the score and the race so far", () => {
  it("counts tests for alerted, seen and unseen, and any role for stopped", () => {
    const timeline = buildTimeline(run());
    const end = frameAt(timeline, timeline.duration);
    expect(end.ended).toBe(true);
    expect(end.score).toMatchObject({ testsDone: 3, alerted: 1, seen: 1, unseen: 1, stopped: 1 });
    const one = timeline.segments[0];
    if (!one) throw new Error("step 1 should be there");
    expect(frameAt(timeline, one.start).score.alerted).toBe(0);
    expect(frameAt(timeline, timeline.fire.get("first") ?? Infinity).score.alerted).toBe(1);
  });

  it("never counts a match on the launcher line", () => {
    // Even a launcher match marked as counting is not an alert.
    const launcher = alert("launcher", "1", 10, [], { launcher_only: true });
    const value = recording({
      steps: [step("1", 10, 11, { outcome: "alerted" })],
      events: [event("1-1", "1", 10.8)],
      alerts: [launcher, alert("real", "1", 10.8, ["1-1"])],
    });
    const timeline = buildTimeline(value);
    expect(timeline.firstAlert?.alert.id).toBe("real");
    const real = timeline.fire.get("real") ?? Infinity;
    expect(frameAt(timeline, real - 0.01).score.alerted).toBe(0);
    expect(frameAt(timeline, real).score.alerted).toBe(1);

    const launcherOnly = buildTimeline({ ...value, alerts: [launcher] });
    const end = frameAt(launcherOnly, Infinity);
    expect(end.race.firstAlert).toBeNull();
    expect(end.race.firstAlertWithLabRules).toBeNull();
  });

  it("shows the first alert on a test only once playback reaches it, and not a canary's", () => {
    const value = run();
    value.steps = value.steps.map((item) => (item.id === "1" ? { ...item, outcome: "seen" } : item));
    value.alerts = value.alerts.filter((item) => item.id !== "first");
    value.alerts.push(alert("late", "5", 120.5, []));
    const timeline = buildTimeline(value);
    expect(timeline.firstAlert?.step.id).toBe("5");
    expect(timeline.firstAlert?.testsBefore).toBe(2);
    expect(timeline.firstAlert?.secondsFromFirstTest).toBeCloseTo(110.5);
    const fire = timeline.fire.get("late") ?? Infinity;
    expect(frameAt(timeline, fire - 0.01).race.firstAlert).toBeNull();
    expect(frameAt(timeline, fire).race.firstAlert?.alert.id).toBe("late");
    expect(frameAt(timeline, fire).race).toMatchObject({ testsRun: 3, testsTotal: 3 });
  });
});

describe("the first alert on a test", () => {
  // Four tests at 10, 20, 30 and 40 s.
  const four = (alerts: ReturnType<typeof alert>[]) =>
    recording({
      when: "live",
      steps: [step("1", 10, 11, { outcome: "alerted" }), step("2", 20, 21), step("3", 30, 31), step("4", 40, 41)],
      events: [event("1-1", "1", 10.5)],
      alerts,
    });

  it("counts the tests that had begun when a live alert was raised, not those before its step", () => {
    const timeline = buildTimeline(four([alert("late", "1", 10.5, ["1-1"], { raised: at(35) })]));
    // Tests 2 and 3 had begun by 35 s; test 1 is the alert's own step and test 4 starts at 40 s.
    expect(timeline.firstAlert?.testsBefore).toBe(2);
  });

  it("names the alert that fires first, which is the one raised first", () => {
    const timeline = buildTimeline(
      four([alert("later", "1", 10.5, ["1-1"], { raised: at(25), rule: { id: "r1", title: "Raised later", level: "high", origin: "pinned" } }), alert("sooner", "1", 10.5, ["1-1"], { raised: at(12), rule: { id: "r2", title: "Raised sooner", level: "high", origin: "pinned" } })]),
    );
    expect(timeline.firstAlert?.alert.rule.title).toBe("Raised sooner");
  });

  it("is never timed from a later step when the first test has no start", () => {
    const value = recording({
      steps: [step("1", null, null, { outcome: "alerted", happened: { answer: "inconclusive", basis: "no exit code" } }), step("2", 20, 21)],
      events: [event("1-1", "1", 10.5)],
      alerts: [alert("a", "1", 10.5, ["1-1"])],
    });
    const first = buildTimeline(value).firstAlert;
    expect(first?.step.id).toBe("1");
    expect(first?.secondsFromFirstTest).toBeNull();
  });

  it("times the first alert of an attack path from its raised time, the moment it fires", () => {
    const value = { ...four([alert("a", "1", 10.5, ["1-1"], { raised: at(25) })]), kind: "attack path" as const };
    value.score = { ...value.score, first_alert_seconds: 15 };
    expect(buildTimeline(value).firstAlert?.secondsFromFirstTest).toBeCloseTo(15);
  });

  it("shows what the alerts say when the attack path's own first alert time disagrees with them", () => {
    const value = { ...four([alert("a", "1", 10.5, ["1-1"], { raised: at(25) })]), kind: "attack path" as const };
    value.score = { ...value.score, first_alert_seconds: 0.5 };
    expect(buildTimeline(value).firstAlert?.secondsFromFirstTest).toBeCloseTo(15);
  });
});

describe("large recordings", () => {
  it("places an alert on 200,000 events after the last of them", () => {
    const events = Array.from({ length: 200_000 }, (_, index) => event(`e${index}`, "1", 10 + index / 100_000));
    const value = recording({ steps: [step("1", 10, 12, { outcome: "alerted" })], events, alerts: [alert("all", "1", 10, events.map((item) => item.id))] });
    const timeline = buildTimeline(value);
    expect(timeline.fire.get("all")).toBeGreaterThanOrEqual(timeline.arrival.get("e199999") ?? Infinity);
  });

  it("works out a frame quickly for thousands of alerted steps and tens of thousands of matches", () => {
    const steps = Array.from({ length: 3000 }, (_, index) => step(String(index + 1), index * 10, index * 10 + 1, { outcome: "alerted" }));
    const events = steps.map((item, index) => event(`e${item.id}`, item.id, index * 10 + 0.5));
    const alerts = steps.flatMap((item, index) => Array.from({ length: 10 }, (_, n) => alert(`a${item.id}-${n}`, item.id, index * 10 + 0.5, [`e${item.id}`])));
    const timeline = buildTimeline(recording({ steps, events, alerts }));
    const started = performance.now();
    for (let index = 60; index > 0; index -= 1) frameAt(timeline, timeline.duration - index * 0.01);
    const frame = frameAt(timeline, timeline.duration);
    expect(performance.now() - started).toBeLessThan(1000);
    expect(frame.score).toMatchObject({ testsDone: 3000, alerted: 3000, seen: 0, unseen: 0 });
  });
});

describe("unusual steps", () => {
  it("gives steps of zero length and steps without times their place", () => {
    const value = recording({
      steps: [step("1", 10, 10), step("2", null, null, { happened: { answer: "not attempted", basis: "did not start" }, outcome: "no effect" }), step("3", null, null), step("4", 30, 29)],
      events: [event("3-1", "3", 20), event("3-2", "3", 21)],
    });
    const timeline = buildTimeline(value);
    expect(timeline.segments).toHaveLength(4);
    for (const segment of timeline.segments) {
      expect(segment.end - segment.start).toBeGreaterThanOrEqual(PLAYBACK_RULE.lead + PLAYBACK_RULE.minBody - 1e-9);
      expect(segment.realEnd).toBeGreaterThanOrEqual(segment.realStart);
    }
    expect(timeline.segments[1]?.timed).toBe(false);
    expect(timeline.segments[1]?.realStart).toBe(timeOf(at(10)));
    expect(timeline.segments[2]?.realStart).toBe(timeOf(at(20)));
    expect(Number.isFinite(timeline.duration)).toBe(true);
    for (let t = -1; t <= timeline.duration + 1; t += 0.1) {
      const frame = frameAt(timeline, t);
      expect(Number.isFinite(frame.real)).toBe(true);
      expect(frame.step).not.toBeNull();
    }
  });

  it("plays an empty recording without failing", () => {
    const timeline = buildTimeline(recording({ steps: [] }));
    expect(timeline.duration).toBe(0);
    const frame = frameAt(timeline, 3);
    expect(frame.step).toBeNull();
    expect(frame.score.testsDone).toBe(0);
  });
});
