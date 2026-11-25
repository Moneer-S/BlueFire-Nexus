import { render } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { LiveView } from "../src/live/LiveView";
import { buildTimeline, PLAYBACK_RULE } from "../src/live/playback";
import type { Timeline } from "../src/live/playback";
import type { Recording } from "../src/live/recording";
import { alert, at, event, recording, step } from "./live-fixture";

const PLAIN = "123,202,255";
const ALERT = "255,112,69";
/** The light to an engine that did not match an event another engine matched. */
const MATCHED_ELSEWHERE = "255,210,125";

/** The address position (`at`) of screen time `screen` on step `id`, 0 to 1 in its segment. */
function position(timeline: Timeline, id: string, screen: number): number {
  const segment = timeline.segments.find((item) => item.step.id === id);
  if (!segment) throw new Error(`no step ${id}`);
  return (screen - segment.start) / (segment.end - segment.start);
}

/** The colours of the lights travelling on the map at screen time `screen`, as the page draws them. */
function lightColours(value: Recording, screen: number): string[] {
  vi.spyOn(HTMLElement.prototype, "clientWidth", "get").mockReturnValue(1440);
  vi.spyOn(HTMLElement.prototype, "clientHeight", "get").mockReturnValue(420);
  const timeline = buildTimeline(value);
  const { container, unmount } = render(<LiveView recording={value} initial={{ step: "1", at: position(timeline, "1", screen), paused: true }} />);
  const colours = [...container.querySelectorAll<HTMLElement>(".lv-motion .lv-light:not(.lv-light--cross)")].map((node) => node.style.getPropertyValue("--rgb"));
  unmount();
  vi.restoreAllMocks();
  return colours.sort();
}

// Test 1 runs from 10 to 20 s; its one event at 10.2 s is matched by a published rule at alert level.
const run = (raised: number | null) =>
  recording({
    when: raised === null ? "after the run" : "live",
    steps: [step("1", 10, 20, { outcome: "alerted", visibility: { answer: "alert", basis: "rules", events: 1 } }), step("2", 40, 41)],
    events: [event("1-1", "1", 10.2)],
    alerts: [alert("a", "1", 10.2, ["1-1"], raised === null ? {} : { raised: at(raised) })],
  });

describe("the light of a recorded event", () => {
  it("travels plain until a live detector raises its match, and takes the match's colour from then", () => {
    // Raised 0.3 s after the event: it fires while the event's light is still on its way.
    const value = run(10.5);
    const timeline = buildTimeline(value);
    const arrives = timeline.arrival.get("1-1") ?? Number.NaN;
    const fires = timeline.fire.get("a") ?? Number.NaN;
    expect(fires).toBeGreaterThan(arrives + 0.1);
    expect(fires).toBeLessThan(arrives + PLAYBACK_RULE.travel - 0.1);

    // One light to each rule engine: both plain before the match fires.
    expect(lightColours(value, arrives + 0.05)).toEqual([PLAIN, PLAIN]);
    expect(lightColours(value, fires - 0.05)).toEqual([PLAIN, PLAIN]);
    // Once it has fired, the light to its engine is an alert's, and the other one shows the event was matched elsewhere.
    expect(lightColours(value, fires + 0.05)).toEqual([ALERT, MATCHED_ELSEWHERE]);
  });

  it("takes its match's colour from the start when the rules ran after the run, since the match fires at its event's time", () => {
    const value = run(null);
    const timeline = buildTimeline(value);
    const arrives = timeline.arrival.get("1-1") ?? Number.NaN;
    expect(timeline.fire.get("a")).toBe(arrives);
    expect(lightColours(value, arrives + 0.05)).toEqual([ALERT, MATCHED_ELSEWHERE]);
  });
});
