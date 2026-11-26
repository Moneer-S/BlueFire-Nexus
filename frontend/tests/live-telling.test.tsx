import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { render } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { refusalOf } from "../src/live/EventLog";
import { LiveView } from "../src/live/LiveView";
import type { LiveViewProps } from "../src/live/LiveView";
import { momentOf, revealTime, scoreOnScreen, stepMatches } from "../src/live/moment";
import { buildTimeline, endedAt, frameAt, seekStep, stepEnd, stepMatchesInFiringOrder } from "../src/live/playback";
import { readRecording } from "../src/live/recording";
import type { Recording } from "../src/live/recording";
import { alert, at, event, recording, step } from "./live-fixture";

afterEach(() => {
  vi.restoreAllMocks();
});

function open(value: Recording, initial: LiveViewProps["initial"]) {
  vi.spyOn(HTMLElement.prototype, "clientWidth", "get").mockReturnValue(1440);
  vi.spyOn(HTMLElement.prototype, "clientHeight", "get").mockReturnValue(420);
  return render(<LiveView recording={value} initial={initial} />);
}

const text = (root: ParentNode, selector: string) => root.querySelector(selector)?.textContent?.trim() ?? null;

/** What the screen says of the step on it: its clock in ms of the fixture's day, the map's word, the caption's word if told, and the score. */
function screen(container: HTMLElement) {
  const clock = text(container, ".lv-clock b")?.replace("UTC", "") ?? "";
  const [h, m, s] = clock.split(":").map(Number);
  const verdict = container.querySelector(".lv-verdict");
  return {
    clock: Date.parse("2026-01-01T00:00:00.000Z") + (((h ?? 0) * 60 + (m ?? 0)) * 60 + (s ?? 0)) * 1000,
    badge: text(container, ".lv-badge"),
    told: verdict !== null && !verdict.classList.contains("is-hidden") ? text(container, ".lv-word") : null,
    alerted: Number(text(container, ".lv-score-lead b") ?? "0"),
    seen: Number(text(container, ".lv-score-item.is-seen b") ?? "0"),
  };
}

// Test 1 runs from 10 to 20 s and is only seen: its one event comes at 12 s, a long while before it ends. Test 2 runs
// from 30 to 40 s and alerts: a live rule raised its alert at 32.5 s, while it still ran. Test 3 runs from 50 to 51 s
// and is only seen: its event comes at its very end, so it is told a moment after it ends, once the event is judged.
const value = recording({
  when: "live",
  steps: [
    step("1", 10, 20, { visibility: { answer: "telemetry only", basis: "recorded", events: 1 } }),
    step("2", 30, 40, { outcome: "alerted", visibility: { answer: "alert", basis: "rules", events: 1 } }),
    step("3", 50, 51, { visibility: { answer: "telemetry only", basis: "recorded", events: 1 } }),
  ],
  events: [event("1-1", "1", 12), event("2-1", "2", 32), event("3-1", "3", 50.99)],
  alerts: [alert("a", "2", 32, ["2-1"], { raised: at(32.5) })],
});
const places = [0.05, 0.15, 0.25, 0.3, 0.35, 0.4, 0.45, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 1, 1.5];

describe("a step's outcome, told by the step's own clock", () => {
  it.each([
    ["1", 20, 0],
    ["3", 51, 1],
  ] as const)("says nothing of how test %s, without an alert, ended before its clock reaches its recorded end, and never calls it running from then on", (id, ended, seenBefore) => {
    const end = Date.parse(at(ended));
    let toldAfter = false;
    let endedUntold = false;
    for (const place of id === "3" ? [...places, 0.48, 0.5, 0.52, 0.55] : places) {
      const { container, unmount } = open(value, { step: id, at: place, paused: true });
      const now = screen(container);
      const where = `test ${id} at ${place}, clock ${new Date(now.clock).toISOString()}`;
      if (now.clock < end) {
        expect(now.badge === null || now.badge === "running", where).toBe(true);
        expect(now.told, where).toBeNull();
        expect(now.seen, where).toBe(seenBefore);
      } else {
        expect(now.badge, where).toBe("took effect");
        if (now.told !== null) {
          expect(now.told, where).toBe("seen");
          expect(now.seen, where).toBe(seenBefore + 1);
          toldAfter = true;
        } else endedUntold = true;
      }
      unmount();
    }
    // It is told, with the score, once its clock has reached its end.
    expect(toldAfter).toBe(true);
    // Test 3 is seen ended, its event still on its way to the rule engines, before it is told.
    if (id === "3") expect(endedUntold).toBe(true);
  }, 60_000);

  it("tells an alert when it was raised, while the step still runs, and what the step did only from its end", () => {
    const end = Date.parse(at(40));
    let alertedWhileRunning = false;
    for (const place of places) {
      const { container, unmount } = open(value, { step: "2", at: place, paused: true });
      const now = screen(container);
      const where = `test 2 at ${place}, clock ${new Date(now.clock).toISOString()}`;
      // Test 1, seen, is counted before it: test 2 is never counted as seen.
      expect(now.seen, where).toBe(1);
      if (now.clock < end) {
        expect(now.badge === null || now.badge === "running", where).toBe(true);
        if (now.clock < Date.parse(at(32.5))) {
          expect(now.told, where).toBeNull();
          expect(now.alerted, where).toBe(0);
        }
        if (now.told !== null) {
          expect(now.told, where).toBe("alerted");
          expect(now.alerted, where).toBe(1);
          alertedWhileRunning = true;
        }
      } else {
        expect(now.badge, where).toBe("took effect");
        expect(now.told, where).toBe("alerted");
      }
      unmount();
    }
    expect(alertedWhileRunning).toBe(true);
  }, 60_000);

  it("marks the line where the host refused a stopped rerun as stopped only once the rerun's clock has reached its end", () => {
    // A hardened rerun from 60 to 70 s that its change stopped: the host refused it at 61 s, a long while before it ended.
    const refused = recording({
      steps: [step("1", 60, 70, { role: "hardened", outcome: "stopped", happened: { answer: "blocked", basis: "refused" }, visibility: { answer: "telemetry only", basis: "recorded", events: 1 } })],
      events: [{ ...event("1-1", "1", 61), fields: { success: "no" } }],
    });
    const end = Date.parse(at(70));
    let shownWhileRunning = false;
    let markedAfter = false;
    for (const place of places) {
      const { container, unmount } = open(refused, { step: "1", at: place, paused: true });
      const now = screen(container);
      const where = `the rerun at ${place}, clock ${new Date(now.clock).toISOString()}`;
      const lines = container.querySelectorAll(".lv-log-line").length;
      const marks = [...container.querySelectorAll(".lv-log-mark")].map((mark) => mark.textContent ?? "").filter(Boolean);
      if (now.clock < end) {
        expect(marks, where).toEqual([]);
        if (lines > 0) shownWhileRunning = true;
      } else {
        expect(now.badge, where).toBe("stopped");
        expect(marks, where).toEqual(["stopped"]);
        markedAfter = true;
      }
      unmount();
    }
    // The line itself is in the log while the rerun still runs, unmarked, and is marked once it has ended.
    expect(shownWhileRunning).toBe(true);
    expect(markedAfter).toBe(true);
  }, 60_000);
});

describe("the shipped recordings, step by step", () => {
  it.each(["lab-range-one-path", "lab-linux-host"])("%s: no outcome before a step's recorded end but an alert raised by then, and the step never running from its end on", (name) => {
    const shipped = readRecording(JSON.parse(readFileSync(resolve(process.cwd(), `../bluefire/data/recordings/${name}.json`), "utf-8")));
    const timeline = buildTimeline(shipped);
    const found: string[] = [];
    for (const segment of timeline.segments) {
      const end = stepEnd(segment);
      const before = scoreOnScreen(timeline, frameAt(timeline, segment.start), null);
      for (let place = 0; place <= 1.5; place += 0.05) {
        const t = seekStep(timeline, segment.step.id, place) ?? 0;
        const frame = frameAt(timeline, t);
        if (frame.segment !== segment) continue;
        const moment = momentOf(timeline, frame, stepMatches(stepMatchesInFiringOrder(timeline, segment.step.id)));
        if (!moment) continue;
        const score = scoreOnScreen(timeline, frame, moment);
        const where = `${segment.step.id} at ${place.toFixed(2)}`;
        // A millisecond of rounding either way of the end is let pass: the clock shows milliseconds.
        if (frame.real < end - 1) {
          if (moment.ended) found.push(`${where}: ended before its end`);
          if (moment.revealed && !(moment.outcome === "alerted" && moment.named !== null)) found.push(`${where}: told ${moment.outcome} before its end`);
          if (score.seen + score.unseen + score.stopped !== before.seen + before.unseen + before.stopped) found.push(`${where}: counted before its end`);
          if (score.alerted > before.alerted && moment.named === null) found.push(`${where}: counted as alerted before an alert`);
        } else if (frame.real > end + 1 && !moment.ended) found.push(`${where}: still running after its end`);
      }
    }
    expect(found).toEqual([]);
  });

  it("lab-linux-host: at each hardened rerun's recorded end and a moment after, the host's badge, the log's mark, the score and the race line say the same of whether it was stopped", () => {
    const shipped = readRecording(JSON.parse(readFileSync(resolve(process.cwd(), "../bluefire/data/recordings/lab-linux-host.json"), "utf-8")));
    const timeline = buildTimeline(shipped);
    const reruns = timeline.segments.filter((segment) => segment.step.role === "hardened");
    expect(reruns.length).toBeGreaterThan(0);
    const found: string[] = [];
    let stoppedSeen = 0;
    for (const segment of reruns) {
      const stopped = segment.step.outcome === "stopped";
      // Not every stopped rerun recorded the host's refusal: the log can mark only a line it has.
      const refusal = refusalOf(shipped.events.filter((event) => event.step === segment.step.id)) !== undefined;
      // Every rerun before this one has left the screen and is counted; this one counts from its recorded end on.
      const before = reruns.filter((other) => other.end <= segment.start && other.step.outcome === "stopped").length;
      const length = segment.end - segment.start;
      const ended = (endedAt(segment) - segment.start) / length;
      const told = (revealTime(timeline, segment) - segment.start) / length;
      const moments: [string, number, boolean][] = [
        ["just before its end", ended - 1e-4, false],
        ["at its end", ended + 1e-9, true],
        ["a moment after its end", (ended + told) / 2, true],
        ["when its outcome is told", told + 1e-9, true],
      ];
      for (const [words, place, over] of moments) {
        if (place < 0 || place > 1) continue;
        const { container, unmount } = open(shipped, { step: segment.step.id, at: place, paused: true });
        const where = `rerun ${segment.step.id} ${words}`;
        const badge = text(container, ".lv-badge");
        const marked = [...container.querySelectorAll(".lv-log-mark")].some((mark) => mark.textContent === "stopped");
        const header = Number.parseInt(text(container, ".lv-score-reruns b") ?? "", 10);
        const race = Number(text(container, ".lv-phase b") ?? "NaN");
        const expected = before + (stopped && over ? 1 : 0);
        if (over && stopped) {
          stoppedSeen += 1;
          if (badge !== "stopped") found.push(`${where}: the badge reads ${badge}`);
          if (refusal && !marked) found.push(`${where}: the log marks no line stopped`);
          if (!refusal && marked) found.push(`${where}: the log marks a line stopped that is not the refusal`);
        } else {
          if (badge === "stopped") found.push(`${where}: the badge reads stopped`);
          if (marked) found.push(`${where}: the log marks a line stopped`);
        }
        if (header !== expected) found.push(`${where}: the score reads ${header} stopped, not ${expected}`);
        if (race !== expected) found.push(`${where}: the race line reads ${race} stopped, not ${expected}`);
        unmount();
      }
    }
    expect(found).toEqual([]);
    // The recording has stopped reruns, so the walk read them.
    expect(stoppedSeen).toBeGreaterThan(0);
  }, 180_000);
});
