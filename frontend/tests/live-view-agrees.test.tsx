import { fireEvent, render, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { LiveView } from "../src/live/LiveView";
import type { LiveViewProps } from "../src/live/LiveView";
import type { Recording } from "../src/live/recording";
import { alert, event, recording, step } from "./live-fixture";

afterEach(() => {
  vi.restoreAllMocks();
});

function open(value: Recording, initial: LiveViewProps["initial"]) {
  vi.spyOn(HTMLElement.prototype, "clientWidth", "get").mockReturnValue(1440);
  vi.spyOn(HTMLElement.prototype, "clientHeight", "get").mockReturnValue(420);
  return render(<LiveView recording={value} initial={initial} />);
}

const text = (root: ParentNode, selector: string) => root.querySelector(selector)?.textContent?.trim() ?? null;
const texts = (root: ParentNode, selector: string) => [...root.querySelectorAll(selector)].map((node) => node.textContent?.trim() ?? "");

/** An attack path of `count` steps, 10 s apart, each with one event; the first alerted, and the goal at the end of the last. */
function path(count: number): Recording {
  const steps = Array.from({ length: count }, (_, n) => step(String(n + 1), 10 * (n + 1), 10 * (n + 1) + 1, { visibility: { answer: "telemetry only", basis: "recorded", events: 1 } }));
  const first = steps[0];
  if (first) Object.assign(first, { outcome: "alerted", visibility: { answer: "alert", basis: "rules", events: 1 } });
  const base = recording({
    when: "live",
    steps,
    events: steps.map((item, n) => event(`${item.id}-1`, item.id, 10 * (n + 1) + 0.5)),
    alerts: [alert("a", "1", 10.5, ["1-1"])],
  });
  return { ...base, kind: "attack path", attacker: { ...base.attacker, goal: "Reach the last host." }, score: { ...base.score, goal_seconds: 10 * count - 10 + 1 } };
}

describe("the caption, the log and the map count the same events at every moment of a step", () => {
  // Step 1 records its one event just before its end, step 2 at its very end: both are told by what was recorded.
  const value = recording({
    steps: [step("1", 10, 20, { visibility: { answer: "telemetry only", basis: "recorded", events: 1 } }), step("2", 30, 31, { visibility: { answer: "telemetry only", basis: "recorded", events: 1 } })],
    events: [event("1-1", "1", 19.9), event("2-1", "2", 31)],
  });
  const places = Array.from({ length: 31 }, (_, n) => Math.round(n * 5) / 100);

  it.each(["1", "2"])("never tells step %s with an event the log and the map have not shown yet", (id) => {
    let toldAtEnd = false;
    for (const at of places) {
      const { container, unmount } = open(value, { step: id, at, paused: true });
      const told = !(container.querySelector(".lv-verdict")?.classList.contains("is-hidden") ?? true);
      if (told) {
        const where = `step ${id} at ${at}`;
        expect(text(container, ".lv-why"), where).toBe("1 event recorded, no rule matched.");
        // "Nothing recorded." is said only of a told step that has no event at all.
        expect(text(container, ".lv-log-none"), where).toBeNull();
        expect(text(container, ".lv-log-count"), where).toBe("1 event");
        expect(texts(container, ".lv-sensor-count"), where).toEqual(["1 event"]);
      }
      if (at === 1) toldAtEnd = told;
      unmount();
    }
    // The step is told before it ends, with its event on screen.
    expect(toldAtEnd).toBe(true);
  }, 60_000);
});

describe("the end of the run, however it is reached", () => {
  it("stops, tells the goal and the final score when End is pressed while the run plays", async () => {
    const value = path(3);
    const { container, unmount } = open(value, { step: "1", at: 0.2, paused: true });
    const play = within(container).getByRole("button", { name: "Play" });
    fireEvent.click(play);
    expect(play.getAttribute("aria-label")).toBe("Pause");
    const slider = container.querySelector("[role='slider']");
    if (!slider) throw new Error("no slider");
    fireEvent.keyDown(slider, { key: "End" });
    // At once, before another frame plays: the view is at its end.
    const atEnd = () => {
      expect(text(container, ".lv-score-label")).toBe("steps alerted");
      expect(text(container, ".lv-winning")).toBe("The attacker reached its goal, “Reach the last host”, 21 s after the first alert, with no step stopped.");
      expect(container.querySelector(".lv-race .lv-track > .lv-flag.is-goal")).not.toBeNull();
    };
    atEnd();
    // And it stays there, stopped.
    await waitFor(() => expect(play.getAttribute("aria-label")).toBe("Play"));
    await new Promise((done) => setTimeout(done, 300));
    atEnd();
    expect(play.getAttribute("aria-label")).toBe("Play");
    unmount();
  });
});

describe("one clock, one name, on an attack path", () => {
  it("names the first alert's time as the clock beside the timeline names its own: into the run", () => {
    const value = path(3);
    const watch = open(value, { step: "1", at: 1.5, paused: true });
    expect(text(watch.container, ".lv-clock span")).toMatch(/^\d\d:\d\d\.\d into the run$/);
    expect(text(watch.container, ".lv-winning")).toBe("The defense raised its first alert on step 1, 00:00.5 into the run.");
    expect(watch.container.textContent).not.toContain("after the first step began");
    watch.unmount();
    const analyse = open(value, { mode: "analyse" });
    expect(analyse.container.querySelector(".lv-ln-bracket title")?.textContent).toBe("No other step had started when the first alert on a step fired, 00:00.5 into the run");
    analyse.unmount();
  });
});

describe("the lanes' axis on an attack path", () => {
  it("names a step as the table and the detail do, so its last label is not read as the last step's", () => {
    const value = path(11);
    const { container, unmount } = open(value, { mode: "analyse", select: "11" });
    const labels = texts(container, ".lv-ln-tick text");
    expect(labels[0]).toMatch(/^step 1 {2}00:00$/);
    expect(labels.some((label) => label.startsWith("step 10 "))).toBe(true);
    expect(labels.filter((label) => label.startsWith("#"))).toEqual([]);
    unmount();
  });
});
