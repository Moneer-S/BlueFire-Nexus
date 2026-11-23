import { describe, expect, it } from "vitest";
import { layoutNetwork } from "../src/live/networkLayout";
import type { Network } from "../src/live/recording";
import { buildTimeline, frameAt } from "../src/live/playback";
import { firstAlertOnScreen, momentOf, revealTime, runFacts, scoreOnScreen, stepMatches } from "../src/live/moment";
import { whoIsWinning } from "../src/live/RaceLine";
import { middleCut } from "../src/live/format";
import { alert, event, recording, step } from "./live-fixture";

// A small range: the attacker reaches web, web reaches db, and the defense collects from both.
const range: Network = {
  hosts: [
    { id: "wazuh", name: "wazuh", role: "the defense's own server", kind: "defense" },
    { id: "db", name: "db", role: "database", kind: "host" },
    { id: "attacker", name: "attacker", role: "where the path starts", kind: "attacker" },
    { id: "web", name: "web", role: "web application", kind: "host" },
  ],
  links: [
    { from: "attacker", to: "web", label: "HTTP" },
    { from: "web", to: "db", label: "PostgreSQL" },
  ],
  sensors: [
    { id: "agent-web", name: "Wazuh agent", host: "web", records: "log lines" },
    { id: "agent-db", name: "Wazuh agent", host: "db", records: "log lines" },
  ],
  detectors: [{ id: "rules", name: "Wazuh rules", rules: 10, when: "live" }],
};

describe("the network map's layout", () => {
  it("lays hosts out from the attacker rightward along the links, with the defense and the rule engines last", () => {
    const layout = layoutNetwork(range, 1440, 420);
    const x = (id: string) => layout.hosts.find((node) => node.host.id === id)?.x ?? Number.NaN;
    expect(x("attacker")).toBeLessThan(x("web"));
    expect(x("web")).toBeLessThan(x("db"));
    expect(x("db")).toBeLessThan(x("wazuh"));
    expect(layout.detectors[0]?.x ?? 0).toBeGreaterThan(x("wazuh"));
    expect(layout.junction.hostId).toBe("wazuh");
  });

  it("keeps every host, sensor and rule engine inside the box", () => {
    for (const [width, height] of [[1440, 380], [1920, 520], [1000, 340]] as const) {
      const layout = layoutNetwork(range, width, height);
      for (const node of [...layout.hosts, ...layout.sensors, ...layout.detectors]) {
        expect(node.x - node.r).toBeGreaterThanOrEqual(0);
        expect(node.x + node.r).toBeLessThanOrEqual(width);
        expect(node.y - node.r).toBeGreaterThanOrEqual(0);
        expect(node.y + node.r).toBeLessThanOrEqual(height);
      }
    }
  });

  it("gives every sensor a path from its host to every rule engine", () => {
    const layout = layoutNetwork(range, 1440, 420);
    for (const sensor of range.sensors) {
      expect(layout.hostToSensor.has(sensor.id)).toBe(true);
      expect(layout.sensorToJunction.has(sensor.id)).toBe(true);
    }
    expect(layout.junctionToDetector.has("rules")).toBe(true);
  });

  it("draws one host with its sensors around it and a plain joining point when there is no defense server", () => {
    const layout = layoutNetwork(recording({ steps: [] }).network, 1440, 400);
    expect(layout.single).toBe(true);
    expect(layout.junction.hostId).toBeNull();
    const host = layout.hosts[0];
    expect(host).toBeDefined();
    for (const sensor of layout.sensors) expect(sensor.x).toBeGreaterThan(host?.x ?? 0);
  });
});

describe("the watch view's words and numbers", () => {
  const run = recording({
    steps: [
      step("1", 10, 10.2, { outcome: "alerted", visibility: { answer: "alert", basis: "rule", events: 1 } }),
      step("2", 20, 21, { outcome: "unseen", visibility: { answer: "no telemetry", basis: "none", events: 0 } }),
    ],
    events: [event("1-1", "1", 10.1)],
    alerts: [alert("a", "1", 10.1, ["1-1"])],
  });
  const timeline = buildTimeline(run);
  const at = (screen: number) => {
    const frame = frameAt(timeline, screen);
    const own = run.alerts.filter((item) => item.step === frame.step?.id);
    return { frame, moment: momentOf(timeline, frame, own, stepMatches(own)) };
  };

  it("counts a step in the score at the moment its outcome is told, not before", () => {
    const second = timeline.segments[1];
    expect(second).toBeDefined();
    if (!second) return;
    const told = revealTime(timeline, second);
    const before = at(told - 0.05);
    const after = at(told + 0.05);
    expect(scoreOnScreen(timeline, before.frame, before.moment).unseen).toBe(0);
    expect(scoreOnScreen(timeline, after.frame, after.moment).unseen).toBe(1);
    expect(whoIsWinning(run, after.frame, scoreOnScreen(timeline, after.frame, after.moment), runFacts(run, timeline))).toBe("1 of 2 tests so far got through without an alert, 1 not even recorded.");
  });

  it("counts an alerted step when its alert reaches the rule engine, as the caption says it", () => {
    const first = timeline.segments[0];
    expect(first).toBeDefined();
    if (!first) return;
    const told = revealTime(timeline, first);
    const before = at(told - 0.05);
    const after = at(told + 0.05);
    expect(scoreOnScreen(timeline, before.frame, before.moment).alerted).toBe(0);
    expect(scoreOnScreen(timeline, after.frame, after.moment).alerted).toBe(1);
  });

  it("names the first alert on the race only once the score counts it", () => {
    const first = timeline.segments[0];
    expect(first).toBeDefined();
    if (!first) return;
    const told = revealTime(timeline, first);
    const shown = (screen: number) => {
      const { frame, moment } = at(screen);
      return firstAlertOnScreen(frame.race.firstAlert, frame.time, frame.segment, moment?.revealed ?? false);
    };
    expect(at(told - 0.05).frame.race.firstAlert).not.toBeNull();
    expect(shown(told - 0.05)).toBeNull();
    expect(shown(told + 0.05)?.step.id).toBe("1");
    const later = timeline.segments[1];
    if (later) expect(shown(later.start)?.step.id).toBe("1");
  });
});

describe("cutting long recorded text", () => {
  it("keeps the start and the file name, and marks the cut", () => {
    const cut = middleCut("/usr/bin/truncate, /lib64/ld-linux-x86-64.so.2, /var/lib/example/history.log", 40);
    expect(cut.length).toBe(40);
    expect(cut.startsWith("/usr/bin/truncate")).toBe(true);
    expect(cut.endsWith("/history.log")).toBe(true);
    expect(cut).toContain("…");
  });
});
