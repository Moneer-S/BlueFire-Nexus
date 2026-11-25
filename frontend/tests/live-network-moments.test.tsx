import { render } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { LiveView } from "../src/live/LiveView";
import { buildTimeline } from "../src/live/playback";
import type { Recording, RecordingEvent } from "../src/live/recording";
import { alert, at, recording, step } from "./live-fixture";

// A small path through a network: from the attacker into web (test 1, alerted by an alert raised after the step ended),
// a step that stays on web (test 2), and one from web against build (test 3), which reaches the goal.

const sensed = (id: string, stepId: string, sensor: string, on: string, seconds: number): RecordingEvent => ({ id, time: at(seconds), host: on, sensor, kind: "log line", text: `line ${id}`, step: stepId, tied_by: "session" });

function path(): Recording {
  const base = recording({
    when: "live",
    steps: [
      step("1", 10, 11, { host: "web", from: "attacker", outcome: "alerted", visibility: { answer: "alert", basis: "rules", events: 2 } }),
      step("2", 20, 21, { host: "web", visibility: { answer: "telemetry only", basis: "events", events: 1 } }),
      step("3", 30, 31, { host: "build", from: "web", visibility: { answer: "telemetry only", basis: "events", events: 3 } }),
    ],
    events: [sensed("1-1", "1", "agent-web", "web", 10.4), sensed("1-2", "1", "agent-web", "web", 10.6), sensed("2-1", "2", "agent-web", "web", 20.5), sensed("3-1", "3", "agent-web", "web", 30.2), sensed("3-2", "3", "agent-build", "build", 30.4), sensed("3-3", "3", "agent-build", "build", 30.6)],
    // The one alert of the run, on web: it matched an event of test 1 and was raised a second after the step ended.
    alerts: [alert("a", "1", 10.6, ["1-2"], { host: "web", raised: at(12) })],
  });
  return {
    ...base,
    kind: "attack path",
    attacker: { kind: "scripted", description: "A path", goal: "Read the file." },
    score: { ...base.score, goal_seconds: 21 },
    network: {
      hosts: [
        { id: "attacker", name: "attacker", role: "the attacker's machine", kind: "attacker" },
        { id: "web", name: "web", role: "web application", kind: "host" },
        { id: "build", name: "build", role: "build server", kind: "host" },
        { id: "manager", name: "manager", role: "Wazuh manager", kind: "defense" },
      ],
      links: [
        { from: "attacker", to: "web", label: "edge" },
        { from: "web", to: "build", label: "inside" },
        { from: "web", to: "manager", label: "mgmt" },
        { from: "build", to: "manager", label: "mgmt" },
      ],
      sensors: [
        { id: "agent-web", name: "Wazuh agent 4.14", host: "web", records: "log lines" },
        { id: "agent-build", name: "Wazuh agent 4.14", host: "build", records: "log lines" },
      ],
      detectors: [{ id: "pinned", name: "Published rules", rules: 10, when: "live" }],
    },
  };
}

/** The page at screen time `screen` past the start of step `id`'s place on the timeline, paused, in a window of 1440 by 900. */
function open(value: Recording, id: string, screen: (start: number, end: number, fire: (alertId: string) => number) => number) {
  vi.spyOn(HTMLElement.prototype, "clientWidth", "get").mockReturnValue(1440);
  vi.spyOn(HTMLElement.prototype, "clientHeight", "get").mockReturnValue(420);
  const timeline = buildTimeline(value);
  const segment = timeline.segments.find((item) => item.step.id === id);
  if (!segment) throw new Error(`step ${id}`);
  const at = screen(segment.start, segment.end, (alertId) => timeline.fire.get(alertId) ?? Number.NaN);
  return render(<LiveView recording={value} initial={{ step: id, at: (at - segment.start) / (segment.end - segment.start), paused: true }} />);
}

const texts = (root: ParentNode, selector: string) => [...root.querySelectorAll(selector)].map((node) => node.textContent?.trim() ?? "");
const hostWords = (root: ParentNode, name: string) => [...root.querySelectorAll(".lv-host-label")].find((node) => node.querySelector(".lv-host-name")?.textContent === name);

afterEach(() => {
  vi.restoreAllMocks();
});

describe("a network at its first alert, raised after its step ended", () => {
  it("names the rule as an alert on the engine, with its delay in the words the log and the caption use, and the host it was raised on says so", () => {
    const { container, unmount } = open(path(), "1", (_, __, fire) => fire("a") + 0.1);
    // The engine names it as an alert, and where and when it was raised.
    const match = [...container.querySelectorAll(".lv-engine-label .lv-match")].find((node) => node.querySelector(".lv-chip--alert"));
    expect(match?.querySelector(".lv-chip--alert")?.textContent).toBe("alert · high");
    expect(match?.querySelector(".lv-match-title")?.textContent).toBe("Rule a");
    expect(texts(match ?? container, ".lv-match-where")).toEqual(["on web · step 1 · rule rule-a", "raised 1.0 s after the step ended"]);
    // The host it was raised on carries its chip and the race line's time for it, strong at this moment.
    const web = hostWords(container, "web");
    expect(web?.querySelector(".lv-host-alert.is-strong .lv-chip")?.textContent).toBe("alert · high");
    expect(web?.querySelector(".lv-host-alert-time.is-first")?.textContent).toBe(`first alert ${container.querySelector(".lv-flag:not(.is-goal) b")?.textContent ?? "?"}`);
    expect(hostWords(container, "build")?.querySelector(".lv-host-alert")).toBeNull();
    // The log calls its line an alert, and the caption says the same delay.
    const line = [...container.querySelectorAll(".lv-log-line")].find((node) => node.querySelector(".lv-log-kind")?.textContent === "alert");
    expect(line?.querySelector(".lv-log-text")?.textContent).toBe("web · Rule a · raised 1.0 s after the step ended");
    expect(container.querySelector(".lv-why")?.textContent).toBe("Rule a (high) matched an event of this step, raised 1.0 s after the step ended.");
    unmount();
  });

  it("keeps the alert on its host, quieter, at a later step", () => {
    const { container, unmount } = open(path(), "2", (start, end) => (start + end) / 2);
    const web = hostWords(container, "web");
    expect(web?.querySelector(".lv-host-alert:not(.is-strong) .lv-chip")?.textContent).toBe("alert · high");
    unmount();
  });
});

describe("a network at the goal", () => {
  it("marks the goal on the map with the time the race line gives it, and the race sentence says the attacker still reached it", () => {
    // At the end of the last step: the goal is reached as it ends.
    const { container, unmount } = open(path(), "3", (_, end) => end);
    const goal = container.querySelector(".lv-badge.is-goal");
    const told = container.querySelector(".lv-flag.is-goal b")?.textContent ?? "";
    expect(told).not.toBe("");
    expect(goal?.textContent).toBe(`goal reached${told}`);
    expect(goal?.querySelector(".lv-badge-time")?.textContent).toBe(told);
    expect(container.querySelector(".lv-winning")?.textContent).toBe("The attacker reached its goal, “Read the file”, 19 s after the first alert, with no step stopped.");
    // The host the goal was reached on wears the goal's ring, centred on it; no other host does.
    const rings = [...container.querySelectorAll(".lv-goal-mark circle")];
    const build = hostWords(container, "build");
    expect(rings).toHaveLength(1);
    expect(Number(rings[0]?.getAttribute("cx"))).toBe(Number.parseFloat(build instanceof HTMLElement ? build.style.left : "NaN"));
    unmount();
  });
});

describe("a step from one host against another", () => {
  it("shows the sensors of both hosts, each counted in words on the map and named by its host in the log", () => {
    const { container, unmount } = open(path(), "3", (start, end) => end - 0.01);
    expect(hostWords(container, "web")?.querySelector(".lv-host-count")?.textContent).toBe("agent · 1 event");
    expect(hostWords(container, "build")?.querySelector(".lv-host-count")?.textContent).toBe("agent · 2 events");
    expect(texts(container, ".lv-log-key > span")).toEqual(["Wazuh agent on web 1", "Wazuh agent on build 2"]);
    // Its hop in words beside its number in the caption.
    expect(texts(container, ".lv-kicker .lv-hop-chip")).toEqual(["from web to build"]);
    unmount();
  });
});

describe("a step that stays on its host", () => {
  it("lights a mark on that host while it runs, and a step that crosses a link does not", () => {
    const stays = open(path(), "2", (start, end) => start + (end - start) * 0.3);
    expect(stays.container.querySelectorAll(".lv-loop")).toHaveLength(1);
    stays.unmount();
    const crosses = open(path(), "3", (start, end) => start + (end - start) * 0.3);
    expect(crosses.container.querySelectorAll(".lv-loop")).toHaveLength(0);
    expect(crosses.container.querySelectorAll(".lv-link.is-used")).toHaveLength(1);
    crosses.unmount();
  });
});
