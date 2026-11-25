import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { act, render } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { LiveView } from "../src/live/LiveView";
import { badgeBoxOf, defenseNoteBox, ENGINE_EDGE, layoutNetwork, leastHeights, markAlertedHosts, markGoalHost, pointOn, roleParts, zoneWidth } from "../src/live/networkLayout";
import type { NetworkLayout } from "../src/live/networkLayout";
import { planRoom } from "../src/live/room";
import type { RoomParts } from "../src/live/room";
import { count, stepLabel, unitWord } from "../src/live/format";
import { EventLog } from "../src/live/EventLog";
import { momentOf, runFacts, stepMatches } from "../src/live/moment";
import { fitScale, hopsOf } from "../src/live/NetworkMap";
import { buildTimeline, frameAt, stepMatchesInFiringOrder } from "../src/live/playback";
import { readRecording, timeOf } from "../src/live/recording";
import type { Alert, Host, HostKind, Network, Recording, RecordingEvent } from "../src/live/recording";
import { tableColumns } from "../src/live/StepTable";
import { alert, at, event, recording, step } from "./live-fixture";

afterEach(() => {
  vi.restoreAllMocks();
});

// ---------- what gives way when the room is short ----------

describe("the watch view in a short room", () => {
  // The parts of range one's view at 1360 by 802, as a browser measures them: the map keeps 365 px with every badge
  // above its host, and needs 319 px at the least.
  const parts = (room: number): RoomParts => ({ room, above: 147, band: 159, bar: 74, logHead: 34, logHeadAlone: 24, logLine: 26.6, most: 3, roomy: 365, least: 319 });

  it("shows the log's three lines where the room holds them and the map at its roomy height", () => {
    expect(planRoom(parts(900))).toEqual({ lines: 3, map: 365, scroll: false });
  });

  it("gives up the log's lines first, one by one, while the map keeps its roomy height", () => {
    expect(planRoom(parts(850)).lines).toBe(2);
    expect(planRoom(parts(830)).lines).toBe(1);
    expect(planRoom(parts(802))).toEqual({ lines: 0, map: 365, scroll: false });
  });

  it("then lets the map go down to its least height, the step's words still above the transport", () => {
    expect(planRoom(parts(760))).toEqual({ lines: 0, map: 319, scroll: false });
  });

  it("only below that grows past the room, with the map reaching to the fold so the step's words are under it whole", () => {
    const plan = planRoom(parts(700));
    expect(plan.scroll).toBe(true);
    // The story band starts where the transport stands, at the foot of the window, under the log's head: not cut in half by it.
    expect(147 + plan.map + 24).toBe(700 - 74);
  });
});

// ---------- range one's map ----------

const host = (id: string, kind: HostKind, role: string): Host => ({ id, name: id, role, kind });
const agent = (on: string) => ({ id: `agent-${on}`, name: "Wazuh agent 4.14.10", host: on, records: "log lines" });

/** Range one's network as its recording gives it: three networks named by their links, an agent on web, db and build. */
function rangeOne(): Network {
  const network: Network = {
    hosts: [
      host("attacker", "attacker", "attacker's machine on the internet"),
      host("inet", "internet", "stand-in internet (file server and upload drop)"),
      host("client", "host", "shop customers and the administrator's laptop"),
      host("web", "host", "web application"),
      host("db", "host", "database"),
      host("build", "host", "build server"),
      host("manager", "defense", "Wazuh manager"),
    ],
    links: [
      { from: "attacker", to: "inet", label: "edge" },
      { from: "attacker", to: "client", label: "edge" },
      { from: "attacker", to: "web", label: "edge" },
      { from: "inet", to: "client", label: "edge" },
      { from: "inet", to: "web", label: "edge" },
      { from: "client", to: "web", label: "edge" },
      { from: "web", to: "db", label: "inside, mgmt" },
      { from: "web", to: "build", label: "inside, mgmt" },
      { from: "web", to: "manager", label: "mgmt" },
      { from: "db", to: "build", label: "inside, mgmt" },
      { from: "db", to: "manager", label: "mgmt" },
      { from: "build", to: "manager", label: "mgmt" },
    ],
    sensors: [agent("web"), agent("db"), agent("build")],
    detectors: [{ id: "pinned", name: "Wazuh 4.14.10 stock rules", rules: 8454, when: "live" }],
  };
  // As the map marks them: the first alert was raised on web, and the path's goal is on inet.
  markAlertedHosts(network, ["web"]);
  markGoalHost(network, "inet");
  return network;
}

type Box = readonly [number, number, number, number];
const meets = (a: Box, b: Box): boolean => Math.min(a[2], b[2]) - Math.max(a[0], b[0]) > 1 && Math.min(a[3], b[3]) - Math.max(a[1], b[1]) > 1;

/** A host's name and role under it, as wide as the map draws them at most and as tall as their lines. */
function words(layout: NetworkLayout): { id: string; box: Box }[] {
  return layout.hosts.map((node) => {
    const width = node.roleWidth ?? 150;
    const lines = roleParts(node.host.role).reduce((sum, part) => sum + Math.ceil((part.length * 11.5 * 0.52) / width), 0);
    const wide = Math.min(width + 12, Math.max(node.host.name.length * 13 * 0.56, node.host.role.length * 11.5 * 0.52));
    const top = node.y + node.r + 8;
    return { id: node.host.id, box: [node.x - wide / 2, top, node.x + wide / 2, top + 18 + 15 * lines] as const };
  });
}

describe("the goal's badge on range one's map", () => {
  const sizes = [1280, 1360, 1440, 1840, 1920] as const;

  it.each(sizes)("never lies on the host it marks, the ring it wears when lit, or any host's name, at %i px wide at the least height and above it", (width) => {
    const network = rangeOne();
    const { least, roomy } = leastHeights(network, width);
    for (const height of [least, roomy, roomy + 120]) {
      // As the watch view lays it out, which may squeeze the map to its least layout.
      const layout = layoutNetwork(network, width, height, true);
      const goal = layout.hosts.find((node) => node.host.id === "inet");
      if (!goal) throw new Error("inet should be there");
      const badge = badgeBoxOf(goal);
      // The nearest point of the badge to the host's centre stands outside the ring a lit host wears, 14 px out from its edge.
      const nearX = Math.max(badge[0], Math.min(goal.x, badge[2]));
      const nearY = Math.max(badge[1], Math.min(goal.y, badge[3]));
      expect(Math.hypot(nearX - goal.x, nearY - goal.y), `${width} by ${height}`).toBeGreaterThan(goal.r + 14);
      for (const name of words(layout)) expect(meets(badge, name.box), `${width} by ${height}: the goal's badge on the name of ${name.id}`).toBe(false);
    }
  });
});

describe("a field's name and box on range one's map in a small window", () => {
  it.each([1024, 1100, 1280, 1440])("never stands under a line the path may run on or where a hop's number stands, at %i px wide", (width) => {
    const network = rangeOne();
    const layout = layoutNetwork(network, width, 0, true);
    for (const zone of layout.zones) {
      if (!zone.label) continue;
      const label: Box = [zone.label.x, zone.label.y - 8, zone.label.x + zoneWidth(zone.words), zone.label.y + 8];
      // A hop's number stands 13 px off its line and is 24 by 16 px: no line runs within that reach of the name.
      const reach: Box = [label[0] - 25, label[1] - 21, label[2] + 25, label[3] + 21];
      for (const line of layout.links) {
        for (let u = 0.02; u < 1; u += 0.02) {
          const point = pointOn(line.curve, u);
          const inside = point.x > reach[0] && point.x < reach[2] && point.y > reach[1] && point.y < reach[3];
          expect(inside, `${width}: the name of ${zone.words} by the line from ${line.from.host.id} to ${line.to.host.id}`).toBe(false);
        }
      }
    }
  });

  it.each([1024, 1100])("never covers a host of another field, at %i px wide, where the map folds its columns", (width) => {
    const network = rangeOne();
    const layout = layoutNetwork(network, width, 0);
    for (const zone of layout.zones) {
      if (!zone.drawn) continue;
      for (const node of layout.hosts) {
        if (zone.hosts.includes(node.host.id)) continue;
        expect(meets(zone.box, [node.x - node.r, node.y - node.r, node.x + node.r, node.y + node.r]), `${width}: ${zone.words} over ${node.host.id}`).toBe(false);
      }
    }
  });
});

// ---------- the log in a short room ----------

describe("the log with little room, at an alert raised after its step ended", () => {
  const sensed = (id: string, seconds: number): RecordingEvent => ({ id, time: at(seconds), host: "web", sensor: "agent-web", kind: "log line", text: `line ${id}`, step: "1", tied_by: "session" });
  const below = (id: string, level: "medium" | "informational", raised: number, tied: string): Alert =>
    alert(id, "1", 10.5, [tied], { host: "web", counts: false, raised: at(raised), rule: { id: `rule-${id}`, title: `Rule ${id}`, level, origin: "pinned" } });
  /**
   * Step 1 of a path into web, with two events. In the silence after it, two alerts were raised on web (Rule b, then Rule a,
   * the latest), and two published rules for review and one informational matched too, all raised after the step ended.
   */
  function path(shape: { kept?: boolean; one?: boolean } = {}): Recording {
    // Fewer events kept than were recorded: five recorded, the two the recording holds kept. One event: only the second.
    const visibility = shape.kept ? { answer: "alert" as const, basis: "rules", events: 5, kept: 2 } : { answer: "alert" as const, basis: "rules", events: shape.one ? 1 : 2 };
    const events = shape.one ? [sensed("1-2", 10.6)] : [sensed("1-1", 10.4), sensed("1-2", 10.6)];
    const tied = shape.one ? "1-2" : "1-1";
    const base = recording({
      when: "live",
      steps: [step("1", 10, 11, { host: "web", from: "attacker", outcome: "alerted", visibility }), step("2", 20, 21, { host: "web" })],
      events,
      alerts: [
        alert("a", "1", 10.6, ["1-2"], { host: "web", raised: at(12.5) }),
        alert("b", "1", 10.6, ["1-2"], { host: "web", raised: at(12.2) }),
        below("r1", "medium", 11.5, tied),
        below("r2", "medium", 11.7, tied),
        below("i1", "informational", 11.9, tied),
      ],
    });
    return {
      ...base,
      kind: "attack path",
      attacker: { kind: "scripted", description: "A path", goal: null },
      network: {
        hosts: [
          { id: "attacker", name: "attacker", role: "the attacker's machine", kind: "attacker" },
          { id: "web", name: "web", role: "web application", kind: "host" },
        ],
        links: [{ from: "attacker", to: "web", label: "edge" }],
        sensors: [{ id: "agent-web", name: "Wazuh agent 4.14", host: "web", records: "log lines" }],
        detectors: [{ id: "pinned", name: "Published rules", rules: 10, when: "live" }],
      },
    };
  }

  /** The log of `lines` lines just after the last of those matches was raised, as the watch view gives it. */
  function log(lines: number, shape: { kept?: boolean; one?: boolean } = {}) {
    const value = path(shape);
    const timeline = buildTimeline(value);
    const frame = frameAt(timeline, (timeline.fire.get("a") ?? Number.NaN) + 0.1);
    const moment = momentOf(timeline, frame, stepMatches(stepMatchesInFiringOrder(timeline, "1")));
    if (!moment || moment.late.length !== 5) throw new Error("the five matches raised after the step should have fired");
    return render(<EventLog recording={value} moment={moment} total={value.events.length} colours={new Map()} onOpen={() => undefined} lines={lines} />);
  }
  // A line's words, whole as its tooltip gives them: a test's page has no width, so the line itself is cut short.
  const lineTexts = (root: ParentNode) => [...root.querySelectorAll(".lv-log-line")].map((line) => [line.querySelector(".lv-log-kind")?.textContent ?? "", line.querySelector(".lv-log-text")?.getAttribute("title") ?? "", line.querySelector(".lv-log-mark")?.textContent ?? ""]);
  const head = (root: ParentNode) => [root.querySelector(".lv-log-count")?.textContent ?? "", root.querySelector(".lv-log-more")?.textContent ?? ""].join(" ");
  const alertLine = ["alert", "web · Rule a · raised 1.5 s after the step ended", "alert"];

  it("gives a log of one line to the alert's own line, as a log of three lines writes it, and counts no alert among the rules for review", () => {
    const three = log(3);
    expect(lineTexts(three.container)).toContainEqual(alertLine);
    three.unmount();
    const one = log(1);
    expect(lineTexts(one.container)).toEqual([alertLine]);
    one.unmount();
  });

  it("counts each kind of match it folds as what it is", () => {
    const { container, unmount } = log(3);
    // The other alert is folded with the rest: it is counted as an alert, not as a rule for review.
    const folded = [...container.querySelectorAll(".lv-log-line")].find((line) => line.querySelector(".lv-log-kind")?.textContent === "rule matches");
    expect(folded?.querySelector(".lv-log-text")?.textContent).toBe("4 more matches after the step, by 1 alert rule, 2 rules for review and 1 informational");
    unmount();
  });

  it("says in its head how many events there are and how many of them Analyse holds, when no event has a line", () => {
    const one = log(1);
    expect(head(one.container)).toBe("2 events, all 2 in Analyse");
    one.unmount();
    // Where the recording keeps fewer events than were recorded, Analyse holds the kept ones: the head says how many.
    const kept = log(1, { kept: true });
    expect(head(kept.container)).toBe("5 events recorded, 2 kept here, all 2 in Analyse");
    kept.unmount();
    const single = log(1, { one: true });
    expect(head(single.container)).toBe("1 event, listed in Analyse");
    single.unmount();
    // With an event's line shown, the head counts only the events not shown.
    const three = log(3);
    expect(head(three.container)).toBe("2 events 1 more in Analyse");
    three.unmount();
  });
});

// ---------- range one's map in every room ----------

/**
 * The rooms the map of range one is laid out in, as the watch view gives them: the width of the map and the
 * height of its stage at a window of 1024 by 768 and 1100 by 700 (where the map folds and the page scrolls), 1280 by
 * 720, 1366 by 768, 1360 by 802, 1440 by 900, and at 1840 by 982 and 1920 by 1080, where the map is drawn larger
 * and laid out on the stage made smaller by its scale. At each, the least height the map may be squeezed to, its
 * roomy height and more room than that, as the watch view may give any of them.
 */
const ROOMS = [1024, 1100, 1280, 1360, 1366, 1440, 1840 / 1.2, 1920 / 1.25] as const;

/** Laying range one out in every room takes a second or more: the tests below share one set of layouts. */
let laidOut: { room: string; layout: NetworkLayout }[] | null = null;
const LAYOUTS_TIMEOUT = 30_000;

function everyLayout(): { room: string; layout: NetworkLayout }[] {
  laidOut ??= layOutEveryRoom();
  return laidOut;
}

function layOutEveryRoom(): { room: string; layout: NetworkLayout }[] {
  const network = rangeOne();
  return ROOMS.flatMap((width) => {
    const { least, roomy } = leastHeights(network, width);
    return [
      { room: `${Math.round(width)} wide, unsqueezed`, layout: layoutNetwork(network, width, 0) },
      ...[least, roomy, roomy + 120].map((height) => ({ room: `${Math.round(width)} by ${Math.round(height)}`, layout: layoutNetwork(network, width, height, true) })),
    ];
  });
}

const grown = (box: Box, by: number): Box => [box[0] - by, box[1] - by, box[2] + by, box[3] + by];
const inside = (point: { x: number; y: number }, box: Box): boolean => point.x >= box[0] && point.x <= box[2] && point.y >= box[1] && point.y <= box[3];
const circleOf = (node: { x: number; y: number; r: number }, pad = 0): Box => [node.x - node.r - pad, node.y - node.r - pad, node.x + node.r + pad, node.y + node.r + pad];

describe("range one's fields", () => {
  it("are all drawn, each whole, or none is, in every room", () => {
    for (const { room, layout } of everyLayout()) {
      const drawn = layout.zones.filter((zone) => zone.drawn);
      if (drawn.length === 0) continue;
      expect(drawn.length, `${room}: some fields drawn and not others`).toBe(layout.zones.length);
      for (const zone of drawn) {
        expect(zone.label, `${room}: ${zone.words} drawn without its name`).not.toBeNull();
        for (const node of layout.hosts) {
          const circle = circleOf(node);
          if (!zone.hosts.includes(node.host.id)) {
            expect(meets(zone.box, circleOf(node, 6)), `${room}: ${zone.words} over ${node.host.id}`).toBe(false);
            continue;
          }
          // Each host on it inside its box, or, a host on two fields, standing on the border between them, its centre on the box's side.
          const across = circle[1] >= zone.box[1] && circle[3] <= zone.box[3];
          const whole = across && circle[0] >= zone.box[0] && circle[2] <= zone.box[2];
          const border = across && layout.zones.filter((other) => other.hosts.includes(node.host.id)).length > 1 && (Math.abs(node.x - zone.box[0]) < 1 || Math.abs(node.x - zone.box[2]) < 1);
          expect(whole || border, `${room}: the edge of ${zone.words} through ${node.host.id}`).toBe(true);
        }
        for (const other of drawn) if (other !== zone) expect(meets(zone.box, other.box), `${room}: ${zone.words} on ${other.words}`).toBe(false);
      }
    }
  }, LAYOUTS_TIMEOUT);

  it("are drawn where the columns stand side by side, and not where they fold, at 1024 and 1100 px wide", () => {
    const network = rangeOne();
    for (const width of [1024, 1100]) expect(layoutNetwork(network, width, 0).zones.filter((zone) => zone.drawn), `${width}`).toEqual([]);
    for (const width of [1280, 1440]) expect(layoutNetwork(network, width, leastHeights(network, width).roomy).zones.every((zone) => zone.drawn), `${width}`).toBe(true);
  });
});

describe("a hop of the attack's path on range one's map", () => {
  it(
    "stays inside the map's drawn fields, or under the heads and on the map where none is drawn, in every room",
    () => {
      const out: string[] = [];
      for (const { room, layout } of everyLayout()) {
        const fields = [...layout.zones.filter((zone) => zone.drawn).map((zone) => zone.box), ...(layout.defenseSide ? [layout.defenseSide.box] : [])];
        // Two fields side by side stand a gap of 10 px apart: a hop from one to the other crosses it.
        const areas = layout.zones.some((zone) => zone.drawn) ? fields.map((box) => grown(box, 6)) : [[ENGINE_EDGE, 34, layout.width - ENGINE_EDGE, layout.height] as Box];
        // Every link of the map may carry a hop: the steps of a path cross the ones the attacker took.
        for (const line of layout.links) {
          for (let u = 0; u <= 1; u += 0.02) {
            const point = pointOn(line.curve, u);
            if (!areas.some((box) => inside(point, box))) out.push(`${room}: the hop from ${line.from.host.id} to ${line.to.host.id} at ${Math.round(point.x)},${Math.round(point.y)}`);
          }
        }
      }
      expect(out).toEqual([]);
    },
    LAYOUTS_TIMEOUT,
  );
});

describe("the line about the defense's sensors on range one's map", () => {
  it("lies on no host's circle, lit ring, words or badge, in every room", () => {
    for (const { room, layout } of everyLayout()) {
      const side = layout.defenseSide;
      const note = side ? defenseNoteBox(side) : null;
      if (!note) continue;
      for (const node of layout.hosts) {
        expect(meets(note, circleOf(node, 14)), `${room}: on the circle of ${node.host.id}`).toBe(false);
        expect(meets(note, badgeBoxOf(node)), `${room}: on the badge of ${node.host.id}`).toBe(false);
      }
      for (const name of words(layout)) expect(meets(note, name.box), `${room}: on the words of ${name.id}`).toBe(false);
    }
  }, LAYOUTS_TIMEOUT);

  it("stands at the foot of the defense's side where the map folds, at 1024 and 1100 px wide", () => {
    const network = rangeOne();
    for (const width of [1024, 1100]) {
      const layout = layoutNetwork(network, width, 0);
      const note = layout.defenseSide ? defenseNoteBox(layout.defenseSide) : null;
      expect(note, `${width}: the line is left out`).not.toBeNull();
      // Under the manager's words, at the foot of the map.
      expect((note?.[3] ?? 0) > layout.height - 20, `${width}`).toBe(true);
    }
  });
});

// ---------- the shipped recordings' maps ----------

/** A shipped recording, and the host its goal is on, as the watch view finds it. */
function shippedMap(name: string): { value: Recording; goalAt: string | null } {
  const value = readRecording(JSON.parse(readFileSync(resolve(process.cwd(), `../bluefire/data/recordings/${name}.json`), "utf-8")));
  const facts = runFacts(value, buildTimeline(value));
  const goalAt = facts.goal === null ? null : (value.steps.find((item) => item.ended !== undefined && Math.abs(timeOf(item.ended) - (facts.goal ?? 0)) <= 1)?.host ?? null);
  return { value, goalAt };
}

/** The map of a shipped recording at stage sizes from a small laptop's to a large screen's, squeezed as the watch view may squeeze it and not. */
function shippedLayouts(name: string): { room: string; layout: NetworkLayout; value: Recording }[] {
  const { value, goalAt } = shippedMap(name);
  const out: { room: string; layout: NetworkLayout; value: Recording }[] = [];
  for (const width of [1240, 1280, 1320, 1360, 1400, 1440, 1520, 1600, 1680, 1760, 1840, 1880]) {
    for (const height of [220, 260, 300, 340, 380, 420, 460, 500, 540]) {
      for (const squeeze of [true, false]) out.push({ room: `${width} by ${height}${squeeze ? ", squeezed" : ""}`, layout: fitScale(value, width, height, goalAt, squeeze).layout, value });
    }
  }
  return out;
}

describe("the badges on the shipped recordings' maps", () => {
  it.each(["lab-range-one-path", "lab-linux-host"])(
    "%s: no drawn line runs through the place of a badge, the widest the host can wear, on any host a step runs on",
    (name) => {
      const found: string[] = [];
      for (const { room, layout, value } of shippedLayouts(name)) {
        const wearers = new Set(value.steps.map((item) => item.host));
        const lines = [
          ...[...layout.links, ...layout.pathLinks].map((line) => [`the line from ${line.from.host.id} to ${line.to.host.id}`, line.curve] as const),
          ...[...layout.sensorToJunction].map(([id, curve]) => [`the line of ${id}`, curve] as const),
          ...[...layout.junctionToDetector].map(([id, curve]) => [`the line to ${id}`, curve] as const),
          ...[...layout.hostToSensor].map(([id, curve]) => [`the tie of ${id}`, curve] as const),
        ];
        for (const node of layout.hosts.filter((item) => wearers.has(item.host.id))) {
          const badge = badgeBoxOf(node);
          for (const [what, curve] of lines) {
            for (let u = 0; u <= 1; u += 0.005) {
              const point = pointOn(curve, u);
              if (point.x > badge[0] && point.x < badge[2] && point.y > badge[1] && point.y < badge[3]) {
                found.push(`${room}: ${what} through the badge of ${node.host.id}`);
                break;
              }
            }
          }
        }
      }
      expect(found).toEqual([]);
    },
    LAYOUTS_TIMEOUT,
  );
});

describe("a hop's numbers on the shipped path's map", () => {
  /** The numbers' box as the browser draws them at 11 px: a figure 7 px wide, the dot 4, a space 3, and 12 px tall. */
  function numbersBox(numbers: string, at: { x: number; y: number }): Box {
    const wide = [...numbers].reduce((sum, char) => sum + (/\d/.test(char) ? 7 : char === " " ? 3 : 4), 0);
    return [at.x - wide / 2, at.y - 6, at.x + wide / 2, at.y + 6];
  }
  const away = (point: { x: number; y: number }, box: Box) => Math.hypot(Math.max(box[0] - point.x, 0, point.x - box[2]), Math.max(box[1] - point.y, 0, point.y - box[3]));

  it(
    "stand clear of their own line, lit or not, at every step and size: half the lit line's width and 3 px more",
    () => {
      const found: string[] = [];
      for (const { room, layout, value } of shippedLayouts("lab-range-one-path")) {
        if (layout.single) continue;
        for (let index = 0; index < value.steps.length; index += 1) {
          for (const hop of hopsOf(value, layout, index)) {
            const box = numbersBox(hop.numbers, hop.label);
            let nearest = Number.POSITIVE_INFINITY;
            for (let u = 0; u <= 1; u += 0.005) nearest = Math.min(nearest, away(pointOn(hop.curve, u), box));
            // The lit line is 3.2 px wide.
            if (nearest < 1.6 + 3) found.push(`${room}, step ${index + 1}: "${hop.numbers}" ${nearest.toFixed(1)} px from its line`);
          }
        }
      }
      expect([...new Set(found)]).toEqual([]);
    },
    LAYOUTS_TIMEOUT * 4,
  );
});

// ---------- the analyse table's titles ----------

describe("the titles in the analyse table", () => {
  // The table's width as a browser measures it in analyse mode, the window less the view's gutters and the detail beside it.
  const TABLE = { 1280: 742, 1440: 836, 1920: 1128 } as const;
  // Range one's eleven steps, as its recording titles them, and the published tests of the one-host recording shipped with the app.
  const PATH = [
    "SSH Credential Stuffing From Linux",
    "Linux Download File and Run",
    "List OS Information",
    "Enumerate SSH Configuration",
    "Port Scan",
    "Extract passwords with grep",
    "Discover Private SSH Keys",
    "Exfiltration Over Alternative Protocol - SSH",
    "Data Compressed - nix - tar Folder or File",
    "Exfiltrate data in a file over HTTPS using wget",
  ];
  // The path's first step, whose recording keeps 1,439 of the 1,857 events recorded, carries the note of how many it keeps.
  const PATH_NOTES = new Map([["SSH Credential Stuffing From Linux", "1,439 of 1,857 events kept"]]);
  const shipped = readRecording(JSON.parse(readFileSync(resolve(process.cwd(), "../bluefire/data/recordings/lab-linux-host.json"), "utf-8")));
  const ONE_HOST = shipped.steps.filter((item) => item.role === "test").map((item) => item.title);
  const ONE_HOST_NOTES = new Map(
    shipped.steps.flatMap((item) => (item.role === "test" && item.visibility.kept !== undefined && item.visibility.events !== undefined && item.visibility.kept < item.visibility.events ? [[item.title, `${count(item.visibility.kept)} of ${count(item.visibility.events)} events kept`] as const] : [])),
  );

  /**
   * Whether the note of how many events were recorded stands beside a step's title, as the table lays out the title's
   * cell, or in a line of its own under it: a table of a path whose first step keeps fewer events than were recorded.
   */
  function noteBeside(): boolean {
    const base = recording({
      steps: [step("1", 10, 11, { title: "SSH Credential Stuffing From Linux", visibility: { answer: "telemetry only", basis: "events", events: 1857, kept: 2 } }), step("2", 20, 21)],
      events: [event("1-1", "1", 10.2), event("1-2", "1", 10.4)],
    });
    const { container, unmount } = render(<LiveView recording={{ ...base, kind: "attack path" }} initial={{ mode: "analyse" }} />);
    const note = container.querySelector(".lv-kept-tag");
    const cell = note?.parentElement;
    if (!note || !cell) throw new Error("the table should note how many events the first step recorded");
    const around = getComputedStyle(cell);
    const beside = /flex/.test(around.display) ? !around.flexDirection.startsWith("column") : getComputedStyle(note).display.startsWith("inline");
    unmount();
    return beside;
  }

  /** The lines a title takes in its column, wrapped between words, each character half its 12.5 px font wide, as Inter's are at the most. */
  function lines(title: string, width: number): number {
    const room = width - 16;
    let count = 1;
    let line = 0;
    for (const word of title.split(" ")) {
      const wide = word.length * 6.25;
      const next = line === 0 ? wide : line + 3.5 + wide;
      if (next > room && line > 0) {
        count += 1;
        line = wide;
      } else line = next;
    }
    return count;
  }
  /** The title column's width: what the table's other columns leave it. */
  function titleWidth(table: number, sensors: number): number {
    const columns = tableColumns(table, sensors, true);
    return table - columns.first - columns.outcome - columns.technique - sensors * columns.sensor - (columns.rules ?? 0);
  }

  it.each([
    ["the path", PATH, 3, PATH_NOTES],
    ["the one-host recording", ONE_HOST, shipped.network.sensors.length, ONE_HOST_NOTES],
  ] as const)("take two lines at the most on %s at 1440 by 900 and 1920 by 1080, and three at 1280 by 720", (_, titles, sensors, notes) => {
    expect(titles.length).toBeGreaterThan(5);
    expect(notes.size).toBeGreaterThan(0);
    // A note beside its title takes its width from the title's, each character of its 10.5 px font at most 0.55 of it, and 8 px between.
    const beside = noteBeside();
    for (const [size, most] of [[1440, 2], [1920, 2], [1280, 3]] as const) {
      const width = titleWidth(TABLE[size], sensors);
      for (const title of titles) {
        const note = notes.get(title);
        const room = note && beside ? width - note.length * 10.5 * 0.55 - 8 : width;
        expect(lines(title, room), `${title}${note ? ` (${note})` : ""} at ${size}`).toBeLessThanOrEqual(most);
      }
    }
  });
});

// ---------- the analyse table's scroll ----------

describe("the analyse table when its rows change height", () => {
  // A test's page lays nothing out: the rows' places are given here as a browser gives them, a head 34 px tall and rows
  // one under the other in a box that scrolls. What a browser does on its own, wrapping titles anew as the columns get
  // their widths, is played by changing the rows' height and telling the table's observers that sizes changed.
  const HEAD = 34;
  const geometry = { row: 50, box: 300, scroll: 0 };
  const boxOf = (element: Element) => element.closest(".lv-table-wrap");
  const rowsOf = (element: Element) => [...(boxOf(element)?.querySelectorAll("tr[data-step]") ?? [])];
  const rowTop = (row: Element) => HEAD + rowsOf(row).indexOf(row) * geometry.row;
  const rect = (top: number, height: number) => ({ top, bottom: top + height, height, left: 0, right: 800, width: 800, x: 0, y: top, toJSON: () => ({}) }) as DOMRect;
  const scrollHeight = (box: Element) => {
    const rows = box.querySelectorAll("tr[data-step]").length;
    const after = [...box.children].filter((child) => child.tagName === "DIV").reduce((sum, child) => sum + (parseFloat((child as HTMLElement).style.height) || 0), 0);
    return Math.max(geometry.box, HEAD + rows * geometry.row + after + (parseFloat(getComputedStyle(box).paddingBottom) || 0));
  };
  const most = (box: Element) => Math.max(0, scrollHeight(box) - geometry.box);

  function layOut(observers: (() => void)[]) {
    vi.spyOn(HTMLElement.prototype, "clientWidth", "get").mockReturnValue(1440);
    vi.spyOn(HTMLElement.prototype, "clientHeight", "get").mockImplementation(function (this: HTMLElement) {
      return this.classList.contains("lv-table-wrap") ? geometry.box : 420;
    });
    vi.spyOn(Element.prototype, "getBoundingClientRect").mockImplementation(function (this: Element) {
      if (this.matches("tr[data-step]")) return rect(rowTop(this) - geometry.scroll, geometry.row);
      if (this.tagName === "THEAD") return rect(0, HEAD);
      if (this.classList.contains("lv-table-wrap")) return rect(0, geometry.box);
      return rect(0, 0);
    });
    vi.spyOn(HTMLElement.prototype, "offsetTop", "get").mockImplementation(function (this: HTMLElement) {
      return this.matches("tr[data-step]") ? rowTop(this) : 0;
    });
    vi.spyOn(HTMLElement.prototype, "offsetHeight", "get").mockImplementation(function (this: HTMLElement) {
      return this.matches("tr[data-step]") ? geometry.row : this.tagName === "THEAD" ? HEAD : 0;
    });
    vi.spyOn(Element.prototype, "scrollHeight", "get").mockImplementation(function (this: Element) {
      return this.classList.contains("lv-table-wrap") ? scrollHeight(this) : 0;
    });
    // As in a browser, the scroll never stands past the end of what the box holds.
    vi.spyOn(Element.prototype, "scrollTop", "get").mockImplementation(function (this: Element) {
      if (!this.classList.contains("lv-table-wrap")) return 0;
      geometry.scroll = Math.min(geometry.scroll, most(this));
      return geometry.scroll;
    });
    vi.spyOn(Element.prototype, "scrollTop", "set").mockImplementation(function (this: Element, value: number) {
      if (this.classList.contains("lv-table-wrap")) geometry.scroll = Math.max(0, Math.min(value, most(this)));
    });
    Object.assign(globalThis, {
      ResizeObserver: class {
        constructor(call: () => void) {
          observers.push(call);
        }
        observe() {}
        unobserve() {}
        disconnect() {}
      },
    });
    // As a browser has it, its fonts loaded.
    Object.defineProperty(document, "fonts", { configurable: true, value: { ready: Promise.resolve() } });
  }

  /** The table's scroll stands at a row's edge, and the chosen row is whole in the box. */
  function standing(container: HTMLElement): { atEdge: boolean; whole: boolean } {
    const box = container.querySelector(".lv-table-wrap");
    const chosen = container.querySelector('tr[data-step="25"]');
    if (!box || !chosen) throw new Error("the table and its 25th row should be there");
    const scroll = box.scrollTop;
    const edges = rowsOf(chosen).map((row) => rowTop(row) - HEAD);
    const top = rowTop(chosen) - HEAD;
    return { atEdge: edges.some((edge) => Math.abs(edge - scroll) < 0.5), whole: top >= scroll - 0.5 && top + HEAD + geometry.row <= scroll + geometry.box + 0.5 };
  }

  const testObserver = globalThis.ResizeObserver;
  afterEach(() => {
    Object.assign(globalThis, { ResizeObserver: testObserver });
    Reflect.deleteProperty(document, "fonts");
  });

  it("stands again at a row's edge under its head, the chosen row whole, when the rows' heights or the box's change", async () => {
    const observers: (() => void)[] = [];
    Object.assign(geometry, { row: 50, box: 300, scroll: 0 });
    layOut(observers);
    const steps = Array.from({ length: 30 }, (_, index) => step(String(index + 1), 10 * (index + 1), 10 * (index + 1) + 1));
    const { container, unmount } = render(<LiveView recording={recording({ steps })} initial={{ mode: "analyse", select: "25" }} />);
    await act(async () => {});
    expect(standing(container)).toEqual({ atEdge: true, whole: true });
    // The columns get their widths and every title takes one line: each row is 33 px tall, not 50.
    geometry.row = 33;
    await act(async () => {
      for (const call of observers) call();
    });
    expect(standing(container), "after the rows grew shorter").toEqual({ atEdge: true, whole: true });
    // The window is made smaller and the box with it.
    geometry.box = 240;
    await act(async () => {
      for (const call of observers) call();
    });
    expect(standing(container), "after the box grew shorter").toEqual({ atEdge: true, whole: true });
    // The rows wrap onto two lines again, the window wider and the columns narrower.
    geometry.row = 50;
    await act(async () => {
      for (const call of observers) call();
    });
    expect(standing(container), "after the rows grew taller").toEqual({ atEdge: true, whole: true });
    unmount();
  });
});

// ---------- the word for a step ----------

describe("the word for a step in each kind of recording", () => {
  // Each step runs a published test, which keeps its own title.
  const base = recording({ steps: [step("1", 10, 11, { outcome: "alerted", title: "Port Scan" }), step("2", 20, 21, { title: "Data Compressed" }), step("3", 30, 31, { title: "Exfiltration Over HTTPS" })] });
  const path: Recording = { ...base, kind: "attack path", attacker: { kind: "scripted", description: "A path", goal: null } };
  const list: Recording = { ...base, kind: "test list" };

  it("is the step on an attack path and the test in a list of tests", () => {
    expect([unitWord(path), unitWord(list)]).toEqual(["step", "test"]);
    const [first] = base.steps;
    if (!first) throw new Error("fixture");
    expect([stepLabel(path, first), stepLabel(list, first)]).toEqual(["step 1", "test 1"]);
  });

  const screen = (value: Recording) => {
    vi.spyOn(HTMLElement.prototype, "clientWidth", "get").mockReturnValue(1440);
    vi.spyOn(HTMLElement.prototype, "clientHeight", "get").mockReturnValue(420);
    return render(<LiveView recording={value} initial={{ step: "2", at: 0.5, paused: true }} />);
  };
  const texts = (root: ParentNode, selector: string) => [...root.querySelectorAll(selector)].map((node) => node.textContent?.trim() ?? "");

  it("counts and names an attack path's steps as steps in the score, the caption and the transport, and says its place once", () => {
    const { container, unmount } = screen(path);
    expect(container.querySelector(".lv-score-label")?.textContent).toBe("steps alerted so far");
    expect(container.querySelector(".lv-kicker .lv-step-chip")?.textContent).toBe("step 2");
    // The transport's name of the step says its place: no line under it says the same again.
    expect(texts(container, ".lv-stepno > b:not(.lv-stepno-sizer), .lv-stepno > span")).toEqual(["Step 2 of 3"]);
    // Nowhere in the head, the race line, the step's words or the transport is a step called a test.
    for (const part of texts(container, ".lv-score, .lv-race, .lv-caption, .lv-transport")) expect(part).not.toMatch(/\btests?\b/i);
    unmount();
  });

  it("keeps a list of tests in tests", () => {
    const { container, unmount } = screen(list);
    expect(container.querySelector(".lv-score-label")?.textContent).toBe("tests alerted so far");
    expect(container.querySelector(".lv-kicker .lv-step-chip")?.textContent).toBe("test 2");
    expect(texts(container, ".lv-stepno > b:not(.lv-stepno-sizer), .lv-stepno > span")).toEqual(["Test 2", "2 of 3 steps"]);
    unmount();
  });
});
