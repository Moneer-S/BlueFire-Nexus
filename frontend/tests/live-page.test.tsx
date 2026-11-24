import { fireEvent, render, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { LiveView } from "../src/live/LiveView";
import type { LiveViewProps } from "../src/live/LiveView";
import { buildTimeline } from "../src/live/playback";
import type { Timeline } from "../src/live/playback";
import type { Recording } from "../src/live/recording";
import { Scrubber } from "../src/live/Scrubber";
import { alert, at, event, recording, step } from "./live-fixture";

afterEach(() => {
  vi.restoreAllMocks();
});

function open(value: Recording, initial: LiveViewProps["initial"]) {
  vi.spyOn(HTMLElement.prototype, "clientWidth", "get").mockReturnValue(1440);
  vi.spyOn(HTMLElement.prototype, "clientHeight", "get").mockReturnValue(420);
  return render(<LiveView recording={value} initial={initial} />);
}

const texts = (root: ParentNode, selector: string) => [...root.querySelectorAll(selector)].map((node) => node.textContent?.trim() ?? "");

describe("several late arrivals fired at once", () => {
  // The alerts of tests 1, 2 and 3 are all raised live at 20 s, while test 4 runs.
  const value = recording({
    when: "live",
    steps: [1, 2, 3].map((n) => step(String(n), n, n + 0.5, { outcome: "alerted", visibility: { answer: "alert", basis: "rules", events: 1 } })).concat([step("4", 18, 25)]),
    events: [event("1-1", "1", 1.1), event("2-1", "2", 2.1), event("3-1", "3", 3.1), event("4-1", "4", 18.5)],
    alerts: [1, 2, 3].map((n) => alert(`a${n}`, String(n), n + 0.1, [`${n}-1`], { raised: at(20) })),
  });

  it("names every one of them under the step, in the log and on the engine, never fewer than the score counts", () => {
    const timeline = buildTimeline(value);
    const fire = timeline.fire.get("a1") ?? Number.NaN;
    const four = timeline.segments[3];
    if (!four) throw new Error("fixture");
    const { container, unmount } = open(value, { step: "4", at: (fire + 0.2 - four.start) / (four.end - four.start), paused: true });
    const late = container.querySelector(".lv-late")?.textContent ?? "";
    for (const rule of ["Rule a1", "Rule a2", "Rule a3"]) expect(late).toContain(rule);
    expect(late).toMatch(/^3 alerts raised late/);
    const log = container.querySelector(".lv-log")?.textContent ?? "";
    for (const rule of ["Rule a1", "Rule a2", "Rule a3"]) expect(log).toContain(rule);
    const engine = container.querySelector(".lv-match--late");
    expect(engine?.textContent).toContain("2 more late");
    for (const rule of ["Rule a1", "Rule a2", "Rule a3"]) expect(engine?.getAttribute("title")).toContain(rule);
    expect(container.querySelector(".lv-score-lead b")?.textContent).toBe("3");
    unmount();
  });

  it("draws twenty thousand of them on one engine without stalling, and names the newest in a tooltip of readable size", () => {
    // Every alert of test 1 is raised live at 20 s, while test 2 runs: the importer takes 20,000 alerts.
    const many = recording({
      when: "live",
      steps: [step("1", 1, 2, { outcome: "alerted", visibility: { answer: "alert", basis: "rules", events: 1 } }), step("2", 18, 25)],
      events: [event("1-1", "1", 1.5), event("2-1", "2", 18.5)],
      alerts: Array.from({ length: 20_000 }, (_, n) => alert(`a${n}`, "1", 1.5, ["1-1"], { raised: at(20) })),
    });
    const timeline = buildTimeline(many);
    const fire = timeline.fire.get("a0") ?? Number.NaN;
    const two = timeline.segments[1];
    if (!two) throw new Error("fixture");
    const started = performance.now();
    const { container, unmount } = open(many, { step: "2", at: (fire + 0.2 - two.start) / (two.end - two.start), paused: true });
    const took = performance.now() - started;
    const engine = container.querySelector(".lv-match--late");
    // Nothing is counted short: the engine says how many more arrived late.
    expect(engine?.textContent).toContain("19999 more late");
    // The tooltip names the newest and counts the rest: it does not grow with every arrival.
    const title = engine?.getAttribute("title") ?? "";
    expect(title).toContain("earlier ones, then");
    expect(title.length).toBeLessThan(5_000);
    // A copy of the names for every arrival took seven seconds here; one list takes well under one.
    expect(took).toBeLessThan(4_000);
    unmount();
  }, 60_000);
});

describe("the page's address", () => {
  const value = recording({ steps: [step("a", 10, 11), step("b", 20, 21), step("c", 30, 31)] });
  // The line, its tooltip, and whether a screen reader is told it.
  const notice = (container: HTMLElement) => {
    const found = container.querySelector(".lv-address");
    return found ? { line: found.textContent, full: found.getAttribute("title"), status: found.getAttribute("role") === "status" } : null;
  };

  it("says in one line when it names a step the recording does not hold, in watch mode", () => {
    const { container, unmount } = open(value, { step: "nope", paused: true });
    expect(notice(container)).toEqual({ line: 'Step "nope" is not in this recording.', full: 'The page\'s address names step "nope", which this recording does not hold, so the view opened at the start of the run.', status: true });
    unmount();
  });

  it("says so in analyse mode too, and opens on the whole run", () => {
    const { container, unmount } = open(value, { mode: "analyse", select: "nope" });
    expect(notice(container)).toEqual({ line: 'Step "nope" is not in this recording.', full: 'The page\'s address names step "nope", which this recording does not hold, so analyse mode opened on the whole run.', status: true });
    expect(within(container).getByRole("article", { name: "The whole run" })).toBeTruthy();
    unmount();
  });

  it("says nothing when every step it names is there", () => {
    const { container, unmount } = open(value, { step: "b", paused: true });
    expect(notice(container)).toBeNull();
    unmount();
  });
});

describe("analyse mode of a recording without tests", () => {
  it("opens the table on every step, with All pressed and each row shown", () => {
    const value = recording({
      steps: [step("1", 1, 2, { role: "canary", outcome: "alerted" }), step("2", 3, 4, { role: "control", outcome: "unseen", visibility: { answer: "no telemetry", basis: "none", events: 0 } })],
    });
    const { container, unmount } = open(value, { mode: "analyse" });
    const roles = within(container).getByRole("group", { name: "Role" });
    expect(within(roles).getByRole("button", { name: /All/ }).getAttribute("aria-pressed")).toBe("true");
    expect(container.querySelectorAll("tr[data-step]")).toHaveLength(2);
    expect(container.textContent).not.toContain("No step has this role and outcome.");
    expect(container.querySelector(".lv-filter-count")?.textContent).toBe("2 of 2");
    unmount();
  });

  it("reads as English for a run of one step", () => {
    const value = recording({ steps: [step("1", 1, 2, { role: "canary", outcome: "alerted" })] });
    const { container, unmount } = open(value, { mode: "analyse" });
    expect(within(container).getByRole("group", { name: "Outcomes of the one step" })).toBeTruthy();
    expect(texts(container, ".lv-chips-scope")).toEqual(["the one step:"]);
    unmount();
  });
});

describe("the attacker's goal", () => {
  it("is named in the run's summary where it is claimed, and said not to be recorded as reached without a time", () => {
    const base = recording({ steps: [step("1", 10, 20), step("2", 30, 40)] });
    const value: Recording = { ...base, kind: "attack path", attacker: { ...base.attacker, goal: "Read the domain admin's password." }, score: { ...base.score, goal_seconds: 30 } };
    const reached = open(value, { mode: "analyse" });
    const goal = within(reached.container).getByText("Goal").nextElementSibling?.textContent ?? "";
    expect(goal).toBe("Read the domain admin's password.Reached 00:30.0 after the first step.");
    reached.unmount();
    const unknown = open({ ...value, score: base.score }, { mode: "analyse" });
    expect(within(unknown.container).getByText("Goal").nextElementSibling?.textContent).toBe("Read the domain admin's password.The recording does not say it was reached.");
    unknown.unmount();
  });
});

describe("keys on the timeline", () => {
  const value = recording({ steps: [step("1", 10, 12), step("2", 40, 45), step("3", 60, 62)] });

  function press(timeline: Timeline, time: number, key: string): number[] {
    const seeks: number[] = [];
    const { container, unmount } = render(<Scrubber recording={value} timeline={timeline} time={time} real={0} revealed={false} onSeek={(to) => seeks.push(to)} />);
    const slider = container.querySelector("[role='slider']");
    if (!slider) throw new Error("no slider");
    fireEvent.keyDown(slider, { key });
    unmount();
    return seeks;
  }

  it.each(["ArrowRight", "ArrowUp", "PageUp"])("never moves back with %s, on the last step or at the end", (key) => {
    const timeline = buildTimeline(value);
    const last = timeline.segments[2];
    if (!last) throw new Error("fixture");
    for (const time of [(last.start + last.end) / 2, timeline.duration]) {
      const [to] = press(timeline, time, key);
      expect(to).toBeGreaterThanOrEqual(time);
    }
    // From the first step it still moves on to a later step's start.
    const [on] = press(timeline, 0.1, key);
    expect(on).toBeGreaterThan(0.1);
  });
});
