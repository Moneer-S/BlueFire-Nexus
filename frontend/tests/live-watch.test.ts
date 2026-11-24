import { describe, expect, it } from "vitest";
import { layoutNetwork } from "../src/live/networkLayout";
import type { Network } from "../src/live/recording";
import { buildTimeline, frameAt, outcomeAt, PLAYBACK_RULE } from "../src/live/playback";
import { timeOf } from "../src/live/recording";
import { firstAlertOnScreen, lateWords, momentOf, revealTime, runFacts, scoreOnScreen, stepMatches } from "../src/live/moment";
import { whoIsWinning } from "../src/live/RaceLine";
import { middleCut } from "../src/live/format";
import { alert, at as atSecond, event, recording, step } from "./live-fixture";

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

  it.each(["alerted", "seen"] as const)("lets the light of a match on a %s step's last event land and tells the step before the next one begins", (outcome) => {
    const late = recording({
      steps: [step("1", 10, 11, { outcome }), step("2", 20, 21)],
      events: [event("1-1", "1", 10.2), event("1-2", "1", 11)],
      alerts: [alert("a", "1", 11, ["1-2"], outcome === "seen" ? { rule: { id: "r", title: "R", level: "low", origin: "pinned" }, counts: false } : {})],
    });
    const lateTimeline = buildTimeline(late);
    const next = lateTimeline.segments[1];
    expect(next).toBeDefined();
    if (!next) return;
    const frame = frameAt(lateTimeline, next.start - 0.01);
    const own = late.alerts;
    const moment = momentOf(lateTimeline, frame, own, stepMatches(own));
    expect(frame.step?.id).toBe("1");
    expect(moment?.revealed).toBe(true);
    expect(moment?.landed.map(({ alert: item }) => item.id)).toEqual(["a"]);
    expect(scoreOnScreen(lateTimeline, frame, moment).alerted).toBe(outcome === "alerted" ? 1 : 0);
    expect(scoreOnScreen(lateTimeline, frame, moment).seen).toBe(outcome === "seen" ? 1 : 0);
  });
});

describe("an alert raised live after its step ended", () => {
  // Test 1 runs from 10 to 11 s and its alert is raised at `raised`; test 2 runs from `next` to `next` + 20 s.
  const late = (raised: number, next = 20) => {
    const value = recording({
      when: "live",
      steps: [step("1", 10, 11, { outcome: "alerted", visibility: { answer: "alert", basis: "rule", events: 1 } }), step("2", next, next + 20)],
      events: [event("1-1", "1", 10.5), event("2-1", "2", next + 1)],
      alerts: [alert("a", "1", 10.5, ["1-1"], { raised: atSecond(raised) })],
    });
    const timeline = buildTimeline(value);
    const view = (screen: number) => {
      const frame = frameAt(timeline, screen);
      const own = value.alerts.filter((item) => item.step === frame.step?.id);
      const moment = momentOf(timeline, frame, own, stepMatches(own));
      return { frame, moment, score: scoreOnScreen(timeline, frame, moment), first: firstAlertOnScreen(frame.race.firstAlert, frame.time, frame.segment, moment?.revealed ?? false) };
    };
    const fire = timeline.fire.get("a") ?? Number.NaN;
    return { value, timeline, view, fire };
  };

  it("tells an alert raised during its own step as that step's own, with no late line", () => {
    const { timeline, view } = late(10.8);
    const first = timeline.segments[0];
    if (!first) throw new Error("test 1 should be there");
    const end = view(first.end - 0.01);
    expect(end.moment?.revealed).toBe(true);
    expect(end.moment?.outcome).toBe("alerted");
    expect(end.moment?.landed.map(({ alert: item }) => item.id)).toEqual(["a"]);
    expect(end.frame.late).toEqual([]);
    expect(end.score.alerted).toBe(1);
  });

  it("shows an alert raised during a later step on that step's screen, and counts it only from then", () => {
    const { value, timeline, view, fire } = late(25);
    const [first, second] = timeline.segments;
    if (!first || !second) throw new Error("both tests should be there");
    // Test 1 is told as it stood at its end: seen, with no alert yet.
    const told = view(first.end - 0.01);
    expect(told.moment?.revealed).toBe(true);
    expect(told.moment?.outcome).toBe("seen");
    expect(told.score).toMatchObject({ alerted: 0, seen: 1 });
    expect(fire).toBeGreaterThan(second.bodyStart);
    const before = view(fire - 0.01);
    expect(before.frame.step?.id).toBe("2");
    expect(before.frame.late).toEqual([]);
    expect(before.score).toMatchObject({ alerted: 0, seen: 1 });
    expect(before.first).toBeNull();
    expect(outcomeAt(timeline, first, fire - 0.01)).toBe("seen");
    const after = view(fire);
    expect(after.frame.step?.id).toBe("2");
    expect(after.frame.late.map(({ alert: item }) => item.id)).toEqual(["a"]);
    expect(after.moment?.late.map(({ alert: item }) => item.id)).toEqual(["a"]);
    const arrived = after.frame.late[0];
    if (!arrived) throw new Error("the late alert should be on screen");
    expect(lateWords(value, timeline, arrived)).toBe("Alert on test 1, Test 1: Rule a, raised 14 s after that step ended.");
    expect(after.frame.alerts).toEqual([]);
    expect(after.score).toMatchObject({ alerted: 1, seen: 0 });
    expect(after.first?.alert.id).toBe("a");
    expect(outcomeAt(timeline, first, fire)).toBe("alerted");
    // It stays long enough to be read before test 2 gives way.
    expect(second.end).toBeGreaterThanOrEqual(fire + PLAYBACK_RULE.read);
    expect(view(fire + PLAYBACK_RULE.read - 0.01).frame.late.map(({ alert: item }) => item.id)).toEqual(["a"]);
  });

  it("shows an alert raised in the silence after its step there, held long enough to read, at its own time", () => {
    const { timeline, view, fire } = late(15, 30);
    const [first, second] = timeline.segments;
    if (!first || !second) throw new Error("both tests should be there");
    expect(view(first.end - 0.01).moment?.outcome).toBe("seen");
    expect(fire).toBeGreaterThan(first.end);
    const after = view(fire);
    expect(after.frame.step?.id).toBe("1");
    expect(after.frame.gap).not.toBeNull();
    expect(after.frame.late.map(({ alert: item }) => item.id)).toEqual(["a"]);
    expect(after.frame.real).toBeCloseTo(timeOf(atSecond(15)), -1);
    expect(after.score.alerted).toBe(1);
    expect(view(fire - 0.01).score.alerted).toBe(0);
    expect(second.start).toBeGreaterThanOrEqual(fire + PLAYBACK_RULE.read);
  });

  it("has every part of the screen agree in the silence after a step, before and after its own late alert fires", () => {
    const { value, timeline, view, fire } = late(15, 30);
    const first = timeline.segments[0];
    if (!first) throw new Error("test 1 should be there");
    // What each part is given: the caption's verdict word and the host's badge
    // read the moment's outcome, the caption's sentence how the step stood at
    // its end, and the scrubber's cell and its text the step's outcome then.
    const parts = (screen: number) => {
      const { frame, moment, score, first: flag } = view(screen);
      const arrived = frame.late[frame.late.length - 1];
      return {
        step: frame.step?.id,
        silence: frame.gap !== null,
        told: moment?.revealed,
        verdict: moment?.outcome,
        stood: moment?.stood,
        late: arrived ? lateWords(value, timeline, arrived) : null,
        score: { alerted: score.alerted, seen: score.seen },
        flag: flag?.alert.id ?? null,
        scrubber: outcomeAt(timeline, first, frame.time),
      };
    };
    const shared = { step: "1", silence: true, told: true, stood: "seen" };
    expect(parts(fire - 0.01)).toEqual({ ...shared, verdict: "seen", late: null, score: { alerted: 0, seen: 1 }, flag: null, scrubber: "seen" });
    expect(parts(fire)).toEqual({ ...shared, verdict: "alerted", late: "Alert on test 1, Test 1: Rule a, raised 4.0 s after that step ended.", score: { alerted: 1, seen: 0 }, flag: "a", scrubber: "alerted" });
  });

  it("shows an alert raised after the last step at the end of the run, at its own time", () => {
    const { timeline, view, fire } = late(50);
    const second = timeline.segments[1];
    if (!second) throw new Error("test 2 should be there");
    expect(fire).toBeGreaterThan(second.end);
    expect(timeline.duration).toBeGreaterThanOrEqual(fire + PLAYBACK_RULE.read);
    expect(view(fire - 0.01).score.alerted).toBe(0);
    const after = view(fire);
    expect(after.frame.step?.id).toBe("2");
    expect(after.frame.late.map(({ alert: item }) => item.id)).toEqual(["a"]);
    expect(after.frame.real).toBeCloseTo(timeOf(atSecond(50)), -1);
    expect(after.score.alerted).toBe(1);
    const end = view(timeline.duration);
    expect(end.frame.ended).toBe(true);
    expect(end.frame.late.map(({ alert: item }) => item.id)).toEqual(["a"]);
    expect(end.score).toMatchObject({ alerted: 1, seen: 1 });
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
