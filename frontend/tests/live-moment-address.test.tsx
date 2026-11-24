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
});
