import { render } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { LiveView } from "../src/live/LiveView";
import { NetworkMap } from "../src/live/NetworkMap";
import { layoutNetwork, LEAST_MAP_WIDTH, roleParts, SILENCE_WORDS } from "../src/live/networkLayout";
import type { NetworkLayout } from "../src/live/networkLayout";
import { buildTimeline, frameAt, seekStep } from "../src/live/playback";
import { momentOf, stepMatches } from "../src/live/moment";
import { MAX_DEFENSE_HOSTS, MAX_DETECTORS, MAX_HOSTS, MAX_LINKS, MAX_SENSORS, MAX_SENSORS_ON_A_HOST, readRecording } from "../src/live/recording";
import type { Detector, Host, HostKind, Link, Network, Recording, RecordingEvent, Sensor } from "../src/live/recording";
import { at, recording, step } from "./live-fixture";

// ---------- networks ----------

const host = (id: string, kind: HostKind = "host", role = `${id} server`): Host => ({ id, name: id, role, kind });
const agent = (on: string, name = "Wazuh agent"): Sensor => ({ id: `agent-${on}`, name, host: on, records: "log lines" });
const engine = (id: string, when: Detector["when"] = "live"): Detector => ({ id, name: `${id} rules`, rules: 10, when });
const defenseHosts = (count: number): Host[] => Array.from({ length: count }, (_, index) => host(`m${index + 1}`, "defense", "Wazuh manager"));
const engines = (count: number): Detector[] => Array.from({ length: count }, (_, index) => engine(`d${index + 1}`));

/** One host, with `defense` defense hosts, `detectors` rule engines and `sensors` sensors on the host. */
function one(defense: number, detectors: number, sensors = 1): Network {
  return {
    hosts: [host("target", "host", "Linux host under test"), ...defenseHosts(defense)],
    sensors: [...Array.from({ length: sensors }, (_, index) => ({ id: `s${index}`, name: `Sensor ${index}`, host: "target", records: "process starts" })), ...defenseHosts(defense).map((item) => agent(item.id, "Manager log"))],
    detectors: engines(detectors),
  };
}

/** A chain of `count` field hosts from the attacker, with defense hosts and rule engines. */
function chain(count: number, defense = 1, detectors = 1): Network {
  const field = [host("attacker", "attacker"), ...Array.from({ length: count - 1 }, (_, index) => host(`h${index + 1}`))];
  const links: Link[] = field.slice(1).map((item, index) => ({ from: field[index]?.id ?? "attacker", to: item.id, label: "SSH" }));
  return { hosts: [...field, ...defenseHosts(defense)], links, sensors: [...field.slice(1).map((item) => agent(item.id)), ...defenseHosts(defense).map((item) => agent(item.id, "Manager log"))], detectors: engines(detectors) };
}

/** A star of `count` field hosts around the attacker, and a defense host. */
function star(count: number): Network {
  const leaves = Array.from({ length: count - 1 }, (_, index) => host(`h${index + 1}`));
  return { hosts: [host("attacker", "attacker"), ...leaves, ...defenseHosts(1)], links: leaves.map((item) => ({ from: "attacker", to: item.id, label: "SSH" })), sensors: [...leaves.map((item) => agent(item.id)), agent("m1", "Manager log")], detectors: engines(1) };
}

/** Range one's seven hosts, as in lab/range/range-one.yaml. */
const seven: Network = {
  hosts: [host("attacker", "attacker", "attacker's machine on the internet"), host("inet", "internet", "stand-in internet"), host("client", "host", "shop customers and the admin's laptop"), host("web", "host", "web application"), host("db", "host", "database"), host("build", "host", "build server"), host("manager", "defense", "Wazuh manager")],
  links: [
    { from: "attacker", to: "web", label: "SSH, HTTP" },
    { from: "attacker", to: "inet", label: "HTTP, HTTPS" },
    { from: "client", to: "web", label: "SSH, HTTP" },
    { from: "client", to: "inet", label: "HTTP, HTTPS" },
    { from: "web", to: "inet", label: "HTTP, HTTPS" },
    { from: "web", to: "db", label: "MariaDB" },
    { from: "web", to: "build", label: "SSH" },
    { from: "db", to: "build", label: "SSH" },
    { from: "build", to: "db", label: "MariaDB" },
    { from: "web", to: "manager", label: "Wazuh agent" },
    { from: "db", to: "manager", label: "Wazuh agent" },
    { from: "build", to: "manager", label: "Wazuh agent" },
  ],
  sensors: [agent("web"), agent("db"), agent("build"), { id: "manager-log", name: "Manager log", host: "manager", records: "the manager's own log" }],
  detectors: engines(1),
};

/** The stage's size at a window of 1440 by 900, 1920 by 1080 and 1024 by 768, and a short map of 1440 by 340. */
const STAGES = [
  [1440, 290],
  [1920, 410],
  [1024, 180],
  [1440, 340],
] as const;

// ---------- boxes, as the map draws them ----------

type Box = { what: string; x0: number; y0: number; x1: number; y1: number };
const chars = (text: string, size: number): number => text.length * size * 0.56;
const meets = (a: Box, b: Box): boolean => Math.min(a.x1, b.x1) - Math.max(a.x0, b.x0) > 1 && Math.min(a.y1, b.y1) - Math.max(a.y0, b.y0) > 1;

/**
 * Each host's circle and the words under it; each sensor's dot and its name with a line for its count; each engine's
 * hexagon and its name and rule count. On a network a sensor whose name the head tells once is a dot with no words: its
 * count is a line of its host's words, and a role whose last words are in brackets breaks before them.
 */
function things(layout: NetworkLayout): Box[] {
  const boxes: Box[] = [];
  for (const node of layout.hosts) {
    boxes.push({ what: `host ${node.host.id}`, x0: node.x - node.r, y0: node.y - node.r, x1: node.x + node.r, y1: node.y + node.r });
    // Its name (13 px) and its role (11.5 px), each cut at the role's width, the role on up to three lines.
    const width = node.roleWidth ?? 300;
    const role = chars(node.host.role, 11.5);
    const parts = layout.single ? [node.host.role] : roleParts(node.host.role);
    const lines = Math.min(3, Math.max(1, parts.reduce((sum, part) => sum + Math.ceil(chars(part, 11.5) / width), 0)));
    const wide = Math.max(Math.min(chars(node.host.name, 13), width), Math.min(role, width)) + 12;
    const top = node.y + node.r + 8;
    // The count of a sensor named once in the head is a line of its own, "agent · 1,439 events".
    const count = node.counted ? 15 : 0;
    boxes.push({ what: `words of ${node.host.id}`, x0: node.x - wide / 2, y0: top, x1: node.x + wide / 2, y1: top + 18 + 15 * lines + count });
  }
  for (const node of layout.sensors) {
    if (!node.named) {
      boxes.push({ what: `sensor ${node.sensor.id}`, x0: node.x - node.r, y0: node.y - node.r, x1: node.x + node.r, y1: node.y + node.r });
      continue;
    }
    if (!node.small) {
      // A sensor of the one host, drawn large: its name (15.5 px) beside it, its count of events above or under the name.
      // Its words stand above it when it is above its host, under it otherwise: two lines from 6 px off its centre.
      // Its name is cut where the layout says.
      boxes.push({ what: `sensor ${node.sensor.id}`, x0: node.x - node.r, y0: node.above ? node.y - 46 : node.y - node.r, x1: node.x + node.r + 14 + Math.min(node.cut, chars(node.sensor.name, 15.5)), y1: node.above ? node.y + node.r : node.y + 46 });
      continue;
    }
    // Its name (11.5 px, cut where the layout says) beside its dot; its count under or above the name, or, in a stack, on the name's line.
    const wide = Math.min(chars(node.sensor.name, 11.5), node.cut) + 8 + (node.inline ? 50 : 0);
    const [x0, x1] = node.side > 0 ? [node.x - node.r, node.x + node.r + 6 + wide] : [node.x - node.r - 6 - wide, node.x + node.r];
    const [y0, y1] = node.inline ? [node.y - 8, node.y + 8] : node.above ? [node.y - 25, node.y + 8] : [node.y - 8, node.y + 25];
    boxes.push({ what: `sensor ${node.sensor.id}`, x0, y0, x1, y1 });
  }
  for (const node of layout.detectors) boxes.push({ what: `engine ${node.detector.id}`, x0: node.x - node.r, y0: node.y - node.r, x1: Math.min(layout.width, node.x + node.r + 220), y1: node.y + 40 });
  return boxes;
}

/** A host's badge while a step runs on it ("took effect" is its longest word). */
const badgeOf = (layout: NetworkLayout, hostId: string): Box[] => {
  const node = layout.hosts.find((item) => item.host.id === hostId);
  return node ? [{ what: `badge of ${hostId}`, x0: node.badge.x - 55, y0: node.badge.y - 22, x1: node.badge.x + 55, y1: node.badge.y }] : [];
};

/** What lies outside the map, or under a column's head, or on anything else: words on words, on a host or on an engine, and a host's badge on anything but its own host. */
function misplaced(layout: NetworkLayout): string[] {
  const found: string[] = [];
  const boxes = things(layout);
  // The heads: "The network" and its count over the field, "Rule engines" and a line from the engines' left edge on.
  // On a network each head is one line along the map's top, over the field and over the defense's side.
  const heads: Box[] = layout.single
    ? [
        { what: "the field's head", x0: layout.fieldHeadX - 90, y0: 0, x1: layout.fieldHeadX + 90, y1: 46 },
        { what: "the engines' head", x0: layout.detectorsHeadX, y0: 0, x1: layout.width, y1: 46 },
      ]
    : [
        { what: "the field's head", x0: layout.fieldHeadX, y0: 0, x1: layout.detectorsHeadX, y1: 26 },
        { what: "the engines' head", x0: layout.detectorsHeadX, y0: 0, x1: layout.width, y1: 26 },
      ];
  for (const box of boxes) {
    if (box.x0 < 0 || box.x1 > layout.width + 0.5 || box.y1 > layout.height + 0.5 || box.y0 < 0) found.push(`${box.what} off the map`);
    for (const head of heads) if (meets(box, head)) found.push(`${box.what} under ${head.what}`);
  }
  boxes.forEach((a, index) => boxes.slice(index + 1).forEach((b) => (meets(a, b) ? found.push(`${a.what} on ${b.what}`) : null)));
  // A badge shows only while a step runs on its host: it may sit on its own host's circle, and on nothing else.
  for (const node of layout.hosts) {
    for (const badge of badgeOf(layout, node.host.id)) for (const box of boxes) if (box.what !== `host ${node.host.id}` && meets(badge, box)) found.push(`${badge.what} on ${box.what}`);
  }
  return found;
}

describe("every column of the map fits", () => {
  it.each([1, 2, 3].flatMap((defense) => [1, 2, 3, 4].map((detectors) => [defense, detectors] as const)))("one host with %i defense hosts and %i rule engines", (defense, detectors) => {
    const found = STAGES.flatMap(([width, height]) => misplaced(layoutNetwork(one(defense, detectors), width, height)).map((item) => `${width} by ${height}: ${item}`));
    expect(found, found.join("\n")).toEqual([]);
  });

  it.each([1, 2, 3].flatMap((defense) => [1, 4].map((detectors) => [defense, detectors] as const)))("a chain of four hosts with %i defense hosts and %i rule engines", (defense, detectors) => {
    const found = STAGES.flatMap(([width, height]) => misplaced(layoutNetwork(chain(4, defense, detectors), width, height)).map((item) => `${width} by ${height}: ${item}`));
    expect(found, found.join("\n")).toEqual([]);
  });

  it("four sensors on one host, on a map of one host and on a network", () => {
    const many: Network = { ...chain(4), sensors: [...Array.from({ length: MAX_SENSORS_ON_A_HOST }, (_, index) => ({ id: `s${index}`, name: `Sensor ${index}`, host: "h1", records: "log lines" })), agent("m1", "Manager log")] };
    const found = STAGES.flatMap(([width, height]) => [...misplaced(layoutNetwork(one(0, 2, MAX_SENSORS_ON_A_HOST), width, height)), ...misplaced(layoutNetwork(many, width, height))].map((item) => `${width} by ${height}: ${item}`));
    expect(found, found.join("\n")).toEqual([]);
  });

  it.each([
    ["one host beside three defense hosts, each with a sensor", one(MAX_DEFENSE_HOSTS, 1)],
    ["three defense hosts alone, each with a sensor", { hosts: defenseHosts(MAX_DEFENSE_HOSTS), sensors: defenseHosts(MAX_DEFENSE_HOSTS).map((item) => agent(item.id)), detectors: engines(1) }],
    ["a chain of four beside three defense hosts", chain(4, MAX_DEFENSE_HOSTS, 1)],
  ] as const)("keeps each defense host's badge, sensor and count clear of the next one's words: %s", (_, network) => {
    const found = STAGES.flatMap(([width, height]) => misplaced(layoutNetwork(network, width, height)).map((item) => `${width} by ${height}: ${item}`));
    expect(found, found.join("\n")).toEqual([]);
  });

  it("puts each host's sensor beside its own host, not on the next one", () => {
    // Five hosts, one with no link and no sensor: at 1024 by 768 the sensors once stood on the next host to the right.
    const network: Network = {
      hosts: [host("attacker", "attacker"), host("web"), host("db"), host("lonely"), host("mgr", "defense", "Wazuh manager")],
      links: [
        { from: "attacker", to: "web", label: "SSH" },
        { from: "web", to: "db", label: "SQL" },
      ],
      sensors: [agent("web"), agent("db")],
      detectors: engines(1),
    };
    const found = STAGES.flatMap(([width, height]) => misplaced(layoutNetwork(network, width, height)).map((item) => `${width} by ${height}: ${item}`));
    expect(found, found.join("\n")).toEqual([]);
  });

  it("cuts long names where neighbouring columns meet, so no host's words run into the next column's or under a rule engine", () => {
    const long = (id: string, kind: HostKind = "host"): Host => ({ id, name: `${id.toUpperCase()}${"x".repeat(199)}`, role: `${id}${" a long role in words".repeat(9)}`.slice(0, 200), kind });
    const network: Network = {
      hosts: [long("attacker", "attacker"), long("web"), long("db"), long("mgr", "defense")],
      links: [
        { from: "attacker", to: "web", label: "SSH" },
        { from: "web", to: "db", label: "SQL" },
      ],
      sensors: [agent("web"), agent("db")],
      detectors: engines(MAX_DETECTORS),
    };
    const found = STAGES.flatMap(([width, height]) => misplaced(layoutNetwork(network, width, height)).map((item) => `${width} by ${height}: ${item}`));
    expect(found, found.join("\n")).toEqual([]);
  });

  it("finds a column that leaves the map", () => {
    // The measure itself: an engine moved under the heads, and one moved past the bottom, are caught.
    const layout = layoutNetwork(one(0, 2), 1440, 290);
    const [first, second] = layout.detectors;
    if (!first || !second) throw new Error("two engines");
    expect(misplaced({ ...layout, detectors: [{ ...first, y: 20 }, { ...second, y: layout.height }] })).toEqual(expect.arrayContaining(["engine d1 under the engines' head", "engine d2 off the map"]));
  });

  it("makes the map taller rather than squeeze a column, and only as much as the column needs", () => {
    const short = layoutNetwork(one(0, MAX_DETECTORS), 1440, 290);
    expect(short.height).toBeGreaterThan(290);
    expect(short.least).toBe(short.height);
    // The least height does not depend on the height the map was given.
    expect(layoutNetwork(one(0, MAX_DETECTORS), 1440, short.height).detectors.map((node) => node.y)).toEqual(short.detectors.map((node) => node.y));
    // Two engines and no defense host fit the room a window of 1440 by 900 gives.
    expect(layoutNetwork(one(0, 2), 1440, 290).height).toBe(290);
  });
});

describe("a narrow window", () => {
  it.each([
    [375, 340],
    [640, 340],
  ])("keeps the map's columns apart and on the map at %i by %i, at the map's least width", (width, height) => {
    // A small network: one target, one defense host, one sensor and one rule engine.
    const network: Network = { hosts: [host("target"), host("m1", "defense", "Wazuh manager")], sensors: [agent("target")], detectors: engines(1) };
    const layout = layoutNetwork(network, width, height);
    expect(layout.width).toBe(LEAST_MAP_WIDTH);
    const target = layout.hosts.find((node) => node.host.id === "target");
    const defense = layout.hosts.find((node) => node.host.id === "m1");
    if (!target || !defense) throw new Error("both hosts");
    expect(defense.x - defense.r).toBeGreaterThan(target.x + target.r + 100);
    const found = misplaced(layout);
    expect(found, found.join("\n")).toEqual([]);
  });

  it.each(STAGES)("folds a chain of the most hosts into bands of rows that fit the window, at %i by %i", (width, height) => {
    // A chain of eleven field hosts and a defense host: every host and every rule engine stands inside the window's width.
    const layout = layoutNetwork(chain(MAX_HOSTS - 1), width, height);
    expect(layout.width).toBe(width);
    for (const node of [...layout.hosts, ...layout.detectors]) expect(node.x + node.r).toBeLessThanOrEqual(width);
    const xs = [...new Set(layout.hosts.filter((node) => node.host.kind !== "defense").map((node) => node.x))].sort((a, b) => a - b);
    xs.slice(1).forEach((x, index) => expect(x - (xs[index] ?? 0)).toBeGreaterThanOrEqual(112));
    const found = misplaced(layout);
    expect(found, found.join("\n")).toEqual([]);
  });

  it("keeps the width its columns need when folding them would stack too many hosts in one column", () => {
    // Columns of one, four and four hosts, and a stack of sensors with long names beside the first: two columns could not stand side by side at 1024.
    const middle = ["a", "b", "c", "d"].map((id) => host(id));
    const last = ["e", "f", "g", "h"].map((id) => host(id));
    const network: Network = {
      hosts: [host("attacker", "attacker"), ...middle, ...last, ...defenseHosts(1)],
      links: [...middle.map((item) => ({ from: "attacker", to: item.id, label: "SSH" })), ...middle.map((item, index) => ({ from: item.id, to: last[index]?.id ?? "e", label: "SSH" }))],
      sensors: [0, 1].map((index) => ({ id: `s${index}`, name: `A sensor with a long name ${index}`, host: "attacker", records: "log lines" })),
      detectors: engines(1),
    };
    const layout = layoutNetwork(network, 1024, 180);
    expect(layout.width).toBeGreaterThan(1024);
    const found = misplaced(layout);
    expect(found, found.join("\n")).toEqual([]);
  });

  it("draws the map at its own width in a narrower box, which scrolls sideways", () => {
    vi.spyOn(HTMLElement.prototype, "clientWidth", "get").mockReturnValue(640);
    vi.spyOn(HTMLElement.prototype, "clientHeight", "get").mockReturnValue(340);
    const value = recording({ steps: [step("1", 10, 20)] });
    const { container } = render(<NetworkMap recording={value} moment={null} speed={1} seek={0} colours={new Map()} labDetectors={new Set()} arrival={() => 0} />);
    expect(container.querySelector<HTMLElement>(".lv-map")?.style.width).toBe(`${LEAST_MAP_WIDTH}px`);
  });
});

// ---------- the words for silence ----------

/** Every box the words for silence must leave alone: hosts, their names, sensors, rule engines, link labels and the unseen host's own badge. Other lines may run under them. */
function covered(layout: NetworkLayout, hostId: string): string[] {
  const point = layout.silenceAt.get(hostId) ?? layout.silence;
  const words: Box = { what: "silence", x0: point.x - SILENCE_WORDS.width / 2, y0: point.y - SILENCE_WORDS.height / 2, x1: point.x + SILENCE_WORDS.width / 2, y1: point.y + SILENCE_WORDS.height / 2 };
  // A link's label as drawn: 11 px words in a pill. A network's name that several links share is told once, as a zone.
  const labels = layout.links.filter((item) => item.told && item.zone === null).map((item): Box => {
    const wide = chars(item.link.label ?? "", 11) + 16;
    return { what: `the label ${item.link.label ?? ""}`, x0: item.label.x - wide / 2, y0: item.label.y - 9, x1: item.label.x + wide / 2, y1: item.label.y + 9 };
  });
  const all = [...things(layout), ...labels, ...badgeOf(layout, hostId)];
  const found = all.filter((box) => meets(words, box)).map((box) => box.what);
  if (words.x0 < 0 || words.x1 > layout.width || words.y0 < 0 || words.y1 > layout.height) found.push("off the map");
  return found;
}

/** The networks the words for silence are placed on, a step on a defense host included. */
const HUSHED = [
  ["a chain of four", chain(4)],
  ["a star of six", star(6)],
  ["range one", seven],
  ["one host beside two defense hosts", one(2, 1)],
] as const;

describe("the words for silence on a network", () => {
  it.each(HUSHED)("cover no host, name, sensor, link label or badge of %s, for every host", (_, network) => {
    const found = [
      [1280, 260],
      ...STAGES,
    ].flatMap(([width, height]) => {
      const layout = layoutNetwork(network, width, height);
      return layout.hosts.flatMap((node) => covered(layout, node.host.id).map((item) => `${width} by ${height}, ${node.host.id}: ${item}`));
    });
    expect(found, found.join("\n")).toEqual([]);
  });

  it.each(HUSHED)("stand near the host they speak of on %s, a defense host too, in a window of 1024, 1440 or 1920", (name, network) => {
    // On range one, near the hosts its tests run on, in a window of 1440 or 1920. Its first two columns, the attacker's machine,
    // the client and the stand-in internet, are ringed by link labels the words never cover, and at 1024 every row is: there
    // the words stand at the nearest free place, which may be further off.
    const checked = (id: string): boolean => name !== "range one" || ["web", "db", "build", "manager"].includes(id);
    const far = STAGES.filter(([width]) => name !== "range one" || width >= 1440).flatMap(([width, height]) => {
      const layout = layoutNetwork(network, width, height);
      return layout.hosts
        .filter((node) => checked(node.host.id))
        .filter((node) => {
          const point = layout.silenceAt.get(node.host.id) ?? { x: Number.NaN, y: Number.NaN };
          // Within a little more than the words' own width of the host's centre.
          return !(Math.hypot(point.x - node.x, point.y - node.y) <= SILENCE_WORDS.width * 1.2);
        })
        .map((node) => `${width} by ${height}: ${node.host.id}`);
    });
    expect(far, far.join("\n")).toEqual([]);
  });
});

// ---------- the map as it is drawn ----------

function drawn(value: Recording, id: string, place: number) {
  vi.spyOn(HTMLElement.prototype, "clientWidth", "get").mockReturnValue(1440);
  vi.spyOn(HTMLElement.prototype, "clientHeight", "get").mockReturnValue(420);
  return render(<LiveView recording={value} initial={{ step: id, at: place, paused: true }} />);
}

const sevenRecording = (events: RecordingEvent[], extra: Partial<Recording["network"]> = {}): Recording => {
  const base = recording({ steps: [step("1", 10, 20, { host: "build", from: "web", visibility: { answer: "telemetry only", basis: "events", events: events.length } })], events });
  return { ...base, network: { ...seven, ...extra } };
};

const sensed = (id: string, sensor: string, on: string, seconds: number): RecordingEvent => ({ id, time: at(seconds), host: on, sensor, kind: "log line", text: `line ${id}`, step: "1", tied_by: "session" });

describe("every sensor that recorded the step is counted where it stands", () => {
  it("gives each sensor its count on the map and in the log's key, and they add up to the log's head", () => {
    // The step runs on build; web's agent and the manager's log recorded it too.
    const events = [sensed("e1", "agent-web", "web", 11), sensed("e2", "agent-build", "build", 12), sensed("e3", "agent-build", "build", 13), sensed("e4", "agent-build", "build", 14), sensed("e5", "agent-web", "web", 15), sensed("e6", "manager-log", "manager", 16)];
    const { container } = drawn(sevenRecording(events), "1", 1);
    // A sensor named beside its dot has its count there; an agent the network's head names once has its count under its host's role, "agent · 3 events".
    const counts = [...container.querySelectorAll(".lv-sensor-count, .lv-host-count")].map((node) => Number.parseInt(/\d[\d,]*/.exec(node.textContent ?? "")?.[0] ?? "", 10));
    const key = [...container.querySelectorAll(".lv-log-key b")].map((node) => Number(node.textContent));
    const head = Number(container.querySelector(".lv-log-count em")?.textContent);
    expect(head).toBe(6);
    expect(counts.reduce((sum, value) => sum + value, 0)).toBe(6);
    expect(key.reduce((sum, value) => sum + value, 0)).toBe(6);
    // Two agents of one name are told apart by their host.
    expect(container.querySelector(".lv-log-key")?.textContent).toContain("Wazuh agent on web");
  });
});

describe("nothing a recording holds is dropped without a word", () => {
  it("keys links by their place, so host ids that join alike draw every link without a warning", () => {
    const errors = vi.spyOn(console, "error").mockImplementation(() => undefined);
    vi.spyOn(HTMLElement.prototype, "clientWidth", "get").mockReturnValue(1440);
    vi.spyOn(HTMLElement.prototype, "clientHeight", "get").mockReturnValue(420);
    const network: Network = {
      hosts: [host("attacker", "attacker"), host("a-b"), host("c"), host("a"), host("b-c")],
      links: [
        { from: "attacker", to: "a-b", label: "first" },
        { from: "a-b", to: "c", label: "second" },
        { from: "attacker", to: "a", label: "third" },
        { from: "a", to: "b-c", label: "fourth" },
      ],
      sensors: [agent("a-b")],
      detectors: engines(1),
    };
    const value = { ...recording({ steps: [step("1", 10, 20, { host: "a-b" })] }), network, notes: ["Same note.", "Same note."], source: { ...recording({ steps: [] }).source, tools: [{ name: "Wazuh", version: "4", role: "rules" as const }, { name: "Wazuh", version: "4", role: "rules" as const }] } };
    const { container } = render(<LiveView recording={value} initial={{ step: "1", at: 0.5, paused: true }} />);
    expect([...container.querySelectorAll(".lv-link-label")].map((node) => node.textContent)).toEqual(expect.arrayContaining(["first", "second", "third", "fourth"]));
    expect(errors.mock.calls.filter((call) => String(call[0]).includes("same key"))).toEqual([]);
  });

  it("opens a host's detail by pointer and by keyboard, with its whole name and role, its addresses and its sensors", () => {
    const long = `web ${"long name ".repeat(12)}`.trim();
    const network: Network = { ...seven, hosts: seven.hosts.map((item) => (item.id === "web" ? { ...item, name: long, role: `${"a long role in words ".repeat(8)}`.trim(), addresses: ["10.77.0.5", "fd00::5"] } : item)) };
    const { container } = drawn(sevenRecording([], network), "1", 0.5);
    const label = [...container.querySelectorAll<HTMLElement>(".lv-host-label")].find((node) => node.querySelector(".lv-host-name")?.textContent === long);
    if (!label) throw new Error("web's words");
    expect(label.tabIndex).toBe(0);
    const detail = container.querySelector(`#${CSS.escape(label.getAttribute("aria-describedby") ?? "")}`);
    expect(detail?.textContent).toContain(long);
    expect(detail?.textContent).toContain("a long role in words a long role in words");
    expect(detail?.textContent).toContain("10.77.0.5, fd00::5");
    expect(detail?.textContent).toContain("Wazuh agent: records log lines");
  });

  it("says when each rule engine ran when they did not all run at the same time", () => {
    const { container } = drawn(sevenRecording([], { detectors: [engine("pinned", "live"), engine("batch", "after the run")] }), "1", 0.5);
    const subs = [...container.querySelectorAll(".lv-engine-sub")].map((node) => node.textContent);
    expect(subs).toEqual(["10 rules · live", "10 rules · after the run"]);
    expect(container.querySelector(".lv-head.is-left")?.textContent).toContain("each says which");
  });

  it("calls a host beside a defense host a network, and counts its hosts", () => {
    vi.spyOn(HTMLElement.prototype, "clientWidth", "get").mockReturnValue(1440);
    vi.spyOn(HTMLElement.prototype, "clientHeight", "get").mockReturnValue(420);
    const value = { ...recording({ steps: [step("1", 10, 20)] }) };
    const network = { ...value.network, hosts: [...value.network.hosts, host("m1", "defense", "Wazuh manager")] };
    const { container } = render(<LiveView recording={{ ...value, network }} initial={{ step: "1", at: 0.5, paused: true }} />);
    expect(container.querySelector(".lv-head")?.textContent).toBe("The network2 hosts, 1 sensor");
  });
});

describe("the map in a small window", () => {
  it.each([
    ["one host", recording({ steps: [step("1", 10, 20)] })],
    ["range one", sevenRecording([])],
  ] as const)("draws %s at its least height when the rows around it leave its box no height", (_, value) => {
    vi.spyOn(HTMLElement.prototype, "clientWidth", "get").mockReturnValue(375);
    vi.spyOn(HTMLElement.prototype, "clientHeight", "get").mockReturnValue(0);
    const timeline = buildTimeline(value);
    const moment = momentOf(timeline, frameAt(timeline, seekStep(timeline, "1", 0.5) ?? 0), stepMatches([]));
    const { container } = render(<NetworkMap recording={value} moment={moment} speed={1} seek={0} colours={new Map()} labDetectors={new Set()} arrival={() => 0} />);
    const least = layoutNetwork(value.network, 375, 0).least;
    expect(least).toBeGreaterThan(0);
    expect(container.querySelector<HTMLElement>(".lv-stage")?.style.minHeight).toBe(`${least}px`);
    expect(container.querySelector<HTMLElement>(".lv-map")?.style.height).toBe(`${least}px`);
    expect(container.querySelectorAll(".lv-host-label").length).toBe(value.network.hosts.length);
  });

  it("opens a host's detail within the map, however near its edge the host stands", () => {
    const network: Network = { ...seven, hosts: seven.hosts.map((item) => (item.id === "attacker" ? { ...item, name: `attacker ${"long name ".repeat(18)}`.trim() } : item)) };
    const { container } = drawn(sevenRecording([], network), "1", 0.5);
    const map = container.querySelector<HTMLElement>(".lv-map");
    const width = Number.parseFloat(map?.style.getPropertyValue("--lv-map-w") ?? "");
    const details = [...container.querySelectorAll<HTMLElement>(".lv-host-detail")];
    expect(details.length).toBe(seven.hosts.length);
    // The detail is centred on the left it is given, and at most 342 px wide, its padding included: its half must stay within the map.
    for (const detail of details) {
      const centre = Number.parseFloat(detail.style.left);
      expect(centre - 171).toBeGreaterThanOrEqual(0);
      expect(centre + 171).toBeLessThanOrEqual(width);
    }
  });
});

// ---------- the readers' limits ----------

/** A recording of `network`, otherwise a small valid one. */
function withNetwork(network: unknown): unknown {
  return { ...recording({ steps: [] }), network };
}

describe("the page's reader refuses a network the map cannot draw", () => {
  const many = (count: number, kind: HostKind = "host") => Array.from({ length: count }, (_, index) => host(`x${index}`, kind));
  it.each([
    ["too many hosts", { hosts: many(MAX_HOSTS + 1), sensors: [], detectors: [] }, `at most ${MAX_HOSTS}`],
    ["too many defense hosts", { hosts: [host("target"), ...many(MAX_DEFENSE_HOSTS + 1, "defense")], sensors: [], detectors: [] }, `at most ${MAX_DEFENSE_HOSTS}`],
    ["too many links", { hosts: [host("a"), host("b")], links: Array.from({ length: MAX_LINKS + 1 }, (_, index) => ({ from: "a", to: "b", label: `port ${index}` })), sensors: [], detectors: [] }, `at most ${MAX_LINKS}`],
    ["too many sensors", { hosts: many(MAX_HOSTS), sensors: Array.from({ length: MAX_SENSORS + 1 }, (_, index) => ({ id: `s${index}`, name: "Agent", host: `x${index % MAX_HOSTS}`, records: "lines" })), detectors: [] }, `at most ${MAX_SENSORS}`],
    ["too many sensors on one host", { hosts: [host("target")], sensors: Array.from({ length: MAX_SENSORS_ON_A_HOST + 1 }, (_, index) => ({ id: `s${index}`, name: "Agent", host: "target", records: "lines" })), detectors: [] }, `at most ${MAX_SENSORS_ON_A_HOST} on one host`],
    ["too many rule engines", { hosts: [host("target")], sensors: [], detectors: engines(MAX_DETECTORS + 1) }, `at most ${MAX_DETECTORS}`],
    ["a link from a host to itself", { hosts: [host("a"), host("b")], links: [{ from: "a", to: "a", label: "loopback" }], sensors: [], detectors: [] }, "joins a host to itself"],
    ["a link given twice", { hosts: [host("a"), host("b")], links: [{ from: "a", to: "b", label: "SSH" }, { from: "a", to: "b", label: "SSH" }], sensors: [], detectors: [] }, "repeats a link"],
  ] as const)("refuses %s, in a sentence that says why", (_, network, words) => {
    expect(() => readRecording(withNetwork(network))).toThrow(words);
  });

  it("keeps a network at every limit", () => {
    const hosts = [...many(MAX_HOSTS - MAX_DEFENSE_HOSTS), ...Array.from({ length: MAX_DEFENSE_HOSTS }, (_, index) => host(`m${index}`, "defense"))];
    const links = Array.from({ length: MAX_LINKS }, (_, index) => ({ from: `x${index % 4}`, to: `x${4 + (index % 5)}`, label: `port ${index}` }));
    const sensors = Array.from({ length: MAX_SENSORS }, (_, index) => ({ id: `s${index}`, name: "Agent", host: `x${Math.floor(index / MAX_SENSORS_ON_A_HOST)}`, records: "lines" }));
    expect(() => readRecording(withNetwork({ hosts, links, sensors, detectors: engines(MAX_DETECTORS) }))).not.toThrow();
  });
});
