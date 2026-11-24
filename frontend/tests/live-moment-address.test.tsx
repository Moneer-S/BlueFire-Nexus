import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { LiveView, type LiveMoment } from "../src/live/LiveView";
import { buildTimeline, frameAt, seekStep, stepPosition } from "../src/live/playback";
import { alert, at, event, recording, step } from "./live-fixture";

describe("the moment the live view reports for an address", () => {
  // Test 1 runs from 10 to 11 s. Its alert is raised live at 13 s, in the silence before test 2 at 60 s.
  const value = recording({
    when: "live",
    steps: [step("1", 10, 11, { outcome: "alerted", visibility: { answer: "alert", basis: "rules", events: 1 } }), step("2", 60, 61)],
    events: [event("1-1", "1", 10.5), event("2-1", "2", 60.5)],
    alerts: [alert("a", "1", 10.5, ["1-1"], { raised: at(13) })],
  });

  it("is the place in the silence after a step, so that opening it again shows the late alert that was on screen", () => {
    const timeline = buildTimeline(value);
    const fired = timeline.fire.get("a");
    if (fired === undefined) throw new Error("the alert should fire");
    // The viewer paused a little after the late alert fired, in the silence after test 1.
    const paused = frameAt(timeline, fired + 0.2);
    expect(paused.step?.id).toBe("1");
    expect(paused.gap).not.toBeNull();
    expect(paused.progress).toBe(1);
    expect(paused.late.map((fire) => fire.alert.id)).toEqual(["a"]);

    const moments: LiveMoment[] = [];
    const { unmount } = render(<LiveView recording={value} initial={{ step: "1", at: stepPosition(paused), paused: true }} onMoment={(moment) => moments.push(moment)} />);
    const reported = moments[moments.length - 1];
    unmount();
    expect(reported?.step).toBe("1");
    expect(reported?.paused).toBe(true);
    // Not the step's end: the place inside the silence.
    expect(reported?.at ?? 0).toBeGreaterThan(1);

    // An address with that place opens the same moment: the clock has not gone back, and the late alert is there.
    const again = seekStep(timeline, "1", reported?.at ?? 0);
    if (again === null) throw new Error("step 1 should be found");
    const reopened = frameAt(timeline, again);
    expect(Math.abs(again - paused.time)).toBeLessThan(0.05);
    expect(reopened.step?.id).toBe("1");
    expect(reopened.late.map((fire) => fire.alert.id)).toEqual(["a"]);
    // The step's end, which the address held before, is a moment at which the alert had not fired.
    const end = seekStep(timeline, "1", 1);
    if (end === null) throw new Error("step 1 should be found");
    expect(frameAt(timeline, end).late).toHaveLength(0);
  });

  it("opens the same moment from anywhere in a silence that holds at a late arrival, the late alerts on screen and the held clock with it", () => {
    // Test 1 runs from 10 to 11 s. Two alerts are raised live after it, at 13 s and 20 s, in the
    // silence before test 2 at 60 s: the silence holds at 20 s, the last of them, while it is read.
    const late = recording({
      when: "live",
      steps: [step("1", 10, 11, { outcome: "alerted", visibility: { answer: "alert", basis: "rules", events: 1 } }), step("2", 60, 61)],
      events: [event("1-1", "1", 10.5), event("2-1", "2", 60.5)],
      alerts: [alert("a", "1", 10.5, ["1-1"], { raised: at(13) }), alert("b", "1", 10.5, ["1-1"], { raised: at(20) })],
    });
    const timeline = buildTimeline(late);
    const first = timeline.fire.get("a");
    const last = timeline.fire.get("b");
    const gap = timeline.gaps[0];
    if (first === undefined || last === undefined || !gap) throw new Error("both alerts should fire in the silence after test 1");
    // The silence holds where the last arrival fires, its clock stopped at 20 s.
    expect(gap.holdEnd).toBeGreaterThan(gap.holdStart);
    expect(last).toBeCloseTo(gap.holdStart, 9);
    const twenty = Date.parse(at(20));

    const places = {
      "as the silence begins": gap.start + 0.001,
      "as the first late alert fires": first,
      "between the two": (first + last) / 2,
      "as the last fires and the hold begins": last,
      "a moment into the hold": last + 0.0003,
      "in the middle of the hold": (gap.holdStart + gap.holdEnd) / 2,
      "at the hold's end": gap.holdEnd,
      "after the hold": (gap.holdEnd + gap.end) / 2,
      "at the silence's last moment": gap.end - 0.0001,
    };
    for (const [where, time] of Object.entries(places)) {
      const paused = frameAt(timeline, time);
      expect(paused.step?.id, where).toBe("1");
      const moments: LiveMoment[] = [];
      const { unmount } = render(<LiveView recording={late} initial={{ step: "1", at: stepPosition(paused), paused: true }} onMoment={(moment) => moments.push(moment)} />);
      const reported = moments[moments.length - 1];
      unmount();
      expect(reported?.step, where).toBe("1");
      const again = seekStep(timeline, "1", reported?.at ?? 0);
      if (again === null) throw new Error("step 1 should be found");
      const reopened = frameAt(timeline, again);
      // The same screen moment, with the same step and the same late alerts on screen. It is never an
      // earlier one, but in the silence's last thousandth, which opens at 1.999: 2 is the next step's start.
      expect(again, where).toBeGreaterThanOrEqual(Math.min(paused.time, gap.start + (gap.end - gap.start) * 0.999));
      expect(Math.abs(again - paused.time), where).toBeLessThan(0.01);
      expect(reopened.step?.id, where).toBe("1");
      expect(reopened.late.map((fire) => fire.alert.id), where).toEqual(paused.late.map((fire) => fire.alert.id));
      // Inside the hold the clock stands at the last arrival's moment, and opens there again.
      if (paused.time >= gap.holdStart && paused.time < gap.holdEnd) {
        expect(paused.real, where).toBe(twenty);
        expect(reopened.real, where).toBe(twenty);
      }
    }
  });
});
