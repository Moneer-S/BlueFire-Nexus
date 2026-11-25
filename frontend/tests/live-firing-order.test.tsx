import { render } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { LiveView } from "../src/live/LiveView";
import { buildTimeline, PLAYBACK_RULE } from "../src/live/playback";
import type { Timeline } from "../src/live/playback";
import type { Recording } from "../src/live/recording";
import { timeOf } from "../src/live/recording";
import { stepRows } from "../src/live/analyse";
import { StepDetail } from "../src/live/StepDetail";
import { alert, at, event, recording, step } from "./live-fixture";

// Two counting alerts on test 1, raised live out of the order of their events:
// rule A matches an event at 11 s and is raised at 30 s, rule B matches an
// event at 12 s and is raised at 13 s. The recording lists them in the order
// of their events, A first. Rule A also alerts on ordinary activity.
function example(firstEnds: number, second: [number, number]): Recording {
  const value = recording({
    when: "live",
    steps: [step("1", 10, firstEnds, { outcome: "alerted", visibility: { answer: "alert", basis: "rules", events: 2 } }), step("2", second[0], second[1])],
    events: [event("1-1", "1", 11), event("1-2", "1", 12), event("2-1", "2", second[0] + 0.5)],
    alerts: [alert("a", "1", 11, ["1-1"], { raised: at(30) }), alert("b", "1", 12, ["1-2"], { raised: at(13) })],
  });
  return { ...value, ordinary: { events: 100, matches: [{ rule: "Rule a", level: "high", count: 3 }] } };
}

/** The address position (`at`) of screen time `screen` on step `id`: 0 to 1 in its segment, 1 to 2 in the silence after it. */
function position(timeline: Timeline, id: string, screen: number): number {
  const segment = timeline.segments.find((item) => item.step.id === id);
  if (!segment) throw new Error(`no step ${id}`);
  if (screen <= segment.end) return (screen - segment.start) / (segment.end - segment.start);
  const gap = timeline.gaps.find((item) => item.after === segment.index);
  if (!gap) throw new Error(`no silence after step ${id}`);
  return 1 + (screen - gap.start) / (gap.end - gap.start);
}

const texts = (root: ParentNode, selector: string) => [...root.querySelectorAll(selector)].map((node) => node.textContent?.trim() ?? "");

/** What each part of the watch view says, read from the page opened at screen time `screen` on step `id`. */
function watch(value: Recording, id: string, screen: number) {
  vi.spyOn(HTMLElement.prototype, "clientWidth", "get").mockReturnValue(1440);
  vi.spyOn(HTMLElement.prototype, "clientHeight", "get").mockReturnValue(420);
  const timeline = buildTimeline(value);
  const { container, unmount } = render(<LiveView recording={value} initial={{ step: id, at: position(timeline, id, screen), paused: true }} />);
  const caption = container.querySelector(".lv-caption");
  const parts = {
    sentence: caption?.querySelector(".lv-verdict:not(.is-hidden) .lv-why")?.textContent ?? null,
    falseNote: caption?.querySelector(".lv-after:not(.is-hidden) .lv-falsenote")?.textContent ?? null,
    spoken: caption?.querySelector(".lv-sr")?.textContent ?? "",
    late: caption?.querySelector(".lv-late")?.textContent ?? "",
    engine: texts(container, ".lv-engine-label .lv-match:not(.lv-match--late) .lv-match-title"),
    engineLate: texts(container, ".lv-engine-label .lv-match--late .lv-match-title"),
    log: texts(container, ".lv-log-line .lv-log-mark").filter(Boolean),
    // The first alert's flag as a user and a screen reader get it: not the hidden copies the race line measures.
    flag: [...container.querySelectorAll(".lv-flag:not(.is-goal)")].find((node) => !node.closest("[aria-hidden='true']"))?.getAttribute("title") ?? null,
    scrubber: container.querySelector("[role='slider']")?.getAttribute("aria-valuetext") ?? "",
    hint: caption?.querySelector(".lv-after:not(.is-hidden) .lv-fix-hint")?.textContent ?? null,
    fixButton: caption?.querySelector(".lv-verdict:not(.is-hidden) .lv-fix") !== null,
    none: texts(container, ".lv-engine-label .lv-match--none").length,
  };
  unmount();
  vi.restoreAllMocks();
  return parts;
}

describe("a step with two live alerts raised out of the order of their events", () => {
  it.each([
    ["while test 1 is still on screen", 35, [40, 41] as [number, number]],
    ["after test 1 ended, during test 2", 15, [20, 40] as [number, number]],
  ])("names the alert that fired first, rule B, everywhere, with rule A raised %s", (_, firstEnds, second) => {
    const value = example(firstEnds, second);
    const timeline = buildTimeline(value);
    const fireB = timeline.fire.get("b") ?? Number.NaN;
    const fireA = timeline.fire.get("a") ?? Number.NaN;
    const first = timeline.segments[0];
    if (!first) throw new Error("test 1 should be there");
    expect(fireB).toBeLessThan(fireA);

    // Before B fires: no rule is named anywhere.
    const before = watch(value, "1", fireB - 0.05);
    expect(before).toMatchObject({ sentence: null, falseNote: null, engine: [], engineLate: [], log: [], flag: null });
    expect(before.spoken).not.toMatch(/Rule/);
    expect(before.scrubber).toMatch(/^Test 1, running:/);

    // After B, before A: the step is told by rule B, and rule A is nowhere.
    const told = Math.min(first.end, fireA) - 0.05;
    const between = watch(value, "1", told);
    expect(between.sentence).toBe("Rule b (high) matched an event of this step.");
    expect(between.falseNote).toBeNull();
    expect(between.spoken).toBe("Alerted: Rule b (high) matched an event of this step.");
    expect(between.engine).toEqual(["Rule b"]);
    expect(between.log).toEqual(["alert"]);
    expect(between.flag).toContain("Rule: Rule b.");
    expect(between.scrubber).toMatch(/^Test 1, alerted:/);

    // After A has landed: A is shown as the later match it is, and the step is still told by B.
    const landed = fireA + PLAYBACK_RULE.travel + 0.05;
    const onScreen = fireA > first.end ? "2" : "1";
    const after = watch(value, onScreen, landed);
    expect(after.flag).toContain("Rule: Rule b.");
    if (onScreen === "1") {
      expect(after.sentence).toBe("Rule b (high) matched an event of this step.");
      expect(after.falseNote).toBeNull();
      expect(after.spoken).toBe("Alerted: Rule b (high) matched an event of this step.");
      expect(after.engine).toEqual(["Rule b", "Rule a"]);
      expect(after.log).toEqual(["alert", "alert"]);
    } else {
      expect(after.late).toBe("Alert on test 1, Test 1: Rule a, raised 15 s after that step ended.");
      expect(after.engineLate).toEqual(["Rule a"]);
      expect(after.spoken).not.toMatch(/Rule b/);
    }
  });

  it("names a lab rule's alert raised after its step ended only once it has fired", () => {
    const value = recording({
      when: "live",
      steps: [step("1", 10, 11, { outcome: "seen", outcome_with_lab_rules: "alerted", visibility: { answer: "telemetry only", basis: "events", events: 1 } }), step("2", 30, 31)],
      events: [event("1-1", "1", 10.5)],
      alerts: [alert("lab", "1", 10.5, ["1-1"], { raised: at(15), detector: "lab", rule: { id: "rule-lab", title: "Lab rule", level: "high", origin: "lab" } })],
    });
    const timeline = buildTimeline(value);
    const fire = timeline.fire.get("lab") ?? Number.NaN;
    const first = timeline.segments[0];
    if (!first) throw new Error("test 1 should be there");
    expect(fire).toBeGreaterThan(first.end);
    const note = (screen: number) => {
      const { container, unmount } = render(<LiveView recording={value} initial={{ step: "1", at: position(timeline, "1", screen), paused: true }} />);
      const text = container.querySelector(".lv-after:not(.is-hidden) .lv-labnote")?.textContent ?? null;
      unmount();
      return text;
    };
    expect(note(first.end - 0.05)).toBeNull();
    expect(note(fire + 0.05)).toBe("One of the lab's own rules alerted, which the score does not count: Lab rule.");
  });

  it("names rule B in analyse mode too, and times the first alert from it", () => {
    const value = example(15, [20, 40]);
    const row = stepRows(value, buildTimeline(value))[0];
    if (!row) throw new Error("no row");
    const ignore = () => undefined;
    const { container } = render(<StepDetail recording={value} row={row} colours={new Map()} testNumber={1} testsTotal={2} origin={timeOf(at(10))} onSelect={ignore} onWatch={ignore} onClose={ignore} takeFocus={false} />);
    const detail = container.querySelector(".lv-dt");
    expect(detail?.querySelector(".lv-dt-why")?.textContent).toBe("Rule b (high) matched an event of this step.");
    expect(detail?.textContent).toContain("first alert 3.0 s after the start");
    expect(texts(detail ?? container, ".lv-dt-group .lv-dt-rule")).toEqual(["Rule b", "Rule a"]);
  });
});

describe("a match that fires after its step ended", () => {
  it.each([
    ["a published rule", "pinned", "pinned"],
    ["a rule written in this repository", "lab", "lab"],
  ] as const)("speaks of a match for review by %s, raised after its step ended, only once it has fired", (_, detector, origin) => {
    // Test 1 is seen: its one event at 10.5 s is matched below alert level, and the match is raised live at 15 s, after the step ended at 11 s.
    const value = recording({
      when: "live",
      steps: [step("1", 10, 11, { outcome: "seen", visibility: { answer: "telemetry only", basis: "events", events: 1 } }), step("2", 30, 31)],
      events: [event("1-1", "1", 10.5)],
      alerts: [alert("r", "1", 10.5, ["1-1"], { raised: at(15), counts: false, detector, rule: { id: "rule-r", title: "Rule r", level: "medium", origin } })],
    });
    const timeline = buildTimeline(value);
    const fire = timeline.fire.get("r") ?? Number.NaN;
    const first = timeline.segments[0];
    const next = timeline.segments[1];
    if (!first || !next) throw new Error("both tests should be there");
    // It fires in the silence after test 1, while test 1 is still on screen.
    expect(fire).toBeGreaterThan(first.end + 0.1);
    expect(fire).toBeLessThan(next.start);
    const quiet = "1 event recorded, no rule matched.";
    const review = origin === "pinned" ? "1 event recorded, 1 rule matched for review, none at alert level." : quiet;
    // Both engines, the published rules and the lab's, say they matched nothing.
    const nothingYet = { sentence: quiet, spoken: `Seen, no alert: ${quiet}`, hint: "No rule matched this step: start by writing one.", fixButton: true, none: 2, engine: [], engineLate: [], late: "", log: [] };

    // Just before test 1 ends, and in the silence after it before the match fires: no part speaks of the match.
    expect(watch(value, "1", first.end - 0.05)).toMatchObject(nothingYet);
    expect(watch(value, "1", (first.end + fire) / 2)).toMatchObject(nothingYet);

    // Once it has fired: it is the late line, and the caption counts it, its hint names it, and its engine no longer says none.
    const after = watch(value, "1", fire + 0.05);
    expect(after).toMatchObject({ sentence: review, spoken: `Seen, no alert: ${review}`, fixButton: true, none: 1, engine: [], engineLate: ["Rule r"] });
    expect(after.late).toBe("Match for review on test 1, Test 1: Rule r, raised 4.0 s after that step ended.");
    expect(after.hint).toBe(origin === "pinned" ? 'To alert here, start from the rule "Rule r": it matched this step at medium level.' : "No rule matched this step: start by writing one.");
  });
});
