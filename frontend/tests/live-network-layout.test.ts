import { describe, expect, it } from "vitest";
import { layoutNetwork, pointOn, roleParts } from "../src/live/networkLayout";
import type { Curve, NetworkLayout } from "../src/live/networkLayout";
import type { Host, HostKind, Link, Network } from "../src/live/recording";

// Networks of one to twelve hosts. Range one's seven are those of lab/range/range-one.yaml:
// three networks, an agent on web, db and build, and the manager's own log.
const host = (id: string, kind: HostKind, role: string): Host => ({ id, name: id, role, kind });
const agent = (on: string) => ({ id: `agent-${on}`, name: "Wazuh agent", host: on, records: "log lines" });
const managerLog = { id: "manager-log", name: "Manager log", host: "manager", records: "the manager's own log" };
const wazuh = [{ id: "wazuh", name: "Wazuh rules", rules: 3950, when: "live" as const }];

const one: Network = {
  hosts: [host("runner", "host", "Linux host under test")],
  sensors: [
    { id: "sysmon", name: "Sysmon for Linux", host: "runner", records: "process starts" },
    { id: "auditd", name: "auditd", host: "runner", records: "system calls" },
  ],
  detectors: [
    { id: "pinned", name: "Published Sigma rules", rules: 188, when: "after the run" },
    { id: "lab", name: "Rules written in this repository", rules: 9, when: "after the run" },
  ],
};

const two: Network = {
  hosts: [host("attacker", "attacker", "where the path starts"), host("web", "host", "web application")],
  links: [{ from: "attacker", to: "web", label: "HTTP" }],
  sensors: [agent("web")],
  detectors: wazuh,
};

const four: Network = {
  hosts: [host("attacker", "attacker", "where the path starts"), host("web", "host", "web application"), host("db", "host", "database"), host("manager", "defense", "Wazuh manager")],
  links: [
    { from: "attacker", to: "web", label: "SSH, HTTP" },
    { from: "web", to: "db", label: "MariaDB" },
    { from: "db", to: "manager", label: "Wazuh agent" },
  ],
  sensors: [agent("web"), agent("db"), managerLog],
  detectors: wazuh,
};

const seven: Network = {
  hosts: [
    host("attacker", "attacker", "attacker's machine on the internet"),
    host("inet", "internet", "stand-in internet"),
    host("client", "host", "shop customers and the admin's laptop"),
    host("web", "host", "web application"),
    host("db", "host", "database"),
    host("build", "host", "build server"),
    host("manager", "defense", "Wazuh manager"),
  ],
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
  sensors: [agent("web"), agent("db"), agent("build"), managerLog],
  detectors: wazuh,
};

/** Eleven hosts in the field in a tree from the attacker, and a manager. */
function twelve(): Network {
  const inner = ["web", "api", "db", "cache", "build", "mail", "files", "vpn", "dns"];
  const links: Link[] = [{ from: "attacker", to: "inet", label: "HTTPS" }];
  inner.forEach((name, index) => links.push({ from: index < 2 ? "inet" : (inner[Math.floor((index - 2) / 2)] ?? "inet"), to: name, label: index % 2 ? "SSH" : "HTTP" }));
  return {
    hosts: [host("attacker", "attacker", "where the path starts"), host("inet", "internet", "stand-in internet"), ...inner.map((name) => host(name, "host", `${name} server`)), host("manager", "defense", "Wazuh manager")],
    links,
    sensors: [...inner.map(agent), managerLog],
    detectors: wazuh,
  };
}

// ---------- how overlaps are measured ----------
//
// Every word the map draws is a box, its width the number of characters
// times 0.56 of its font size (near enough for Inter) plus its padding, laid
// out as the map lays it out: a host's name (13 px) and role (11.5 px, wrapped
// at the role width the layout gives) under the host; a sensor's name
// (11.5 px) beside its dot with a line for its count of events; a link's label
// (11 px, in a pill) at its place; the widest badge ("took effect") at its
// place. Two things overlap when their boxes share more than one pixel each way.

type Box = { what: string; x0: number; y0: number; x1: number; y1: number };

const chars = (text: string, size: number): number => text.length * size * 0.56;

function hostWords(layout: NetworkLayout): Box[] {
  return layout.hosts.map((node) => {
    const width = node.roleWidth ?? 150;
    const role = chars(node.host.role, 11.5);
    // A role whose last words are in brackets breaks before them; a host whose agent the head names has its count on a line of its own.
    const parts = layout.single ? [node.host.role] : roleParts(node.host.role);
    const lines = Math.max(1, parts.reduce((sum, part) => sum + Math.ceil(chars(part, 11.5) / width), 0));
    const wide = Math.max(chars(node.host.name, 13), Math.min(role, width)) + 12;
    const top = node.y + node.r + 8;
    return { what: `name of ${node.host.id}`, x0: node.x - wide / 2, y0: top, x1: node.x + wide / 2, y1: top + 18 + 15 * lines + (node.counted ? 15 : 0) };
  });
}

/** A sensor's name beside its dot, with a line for its count; a sensor the network's head names once has no words by its dot. */
function sensorWords(layout: NetworkLayout): Box[] {
  return layout.sensors.flatMap((node) => {
    if (!node.named) return [];
    const wide = Math.max(chars(node.sensor.name, 11.5), 60);
    const [x0, x1] = node.side > 0 ? [node.x + node.r + 6, node.x + node.r + 6 + wide] : [node.x - node.r - 6 - wide, node.x - node.r - 6];
    const [y0, y1] = node.above ? [node.y + 9 - 34, node.y + 9] : [node.y - 9, node.y - 9 + 34];
    return [{ what: `sensor ${node.sensor.id}`, x0, y0, x1, y1 }];
  });
}

/** The links always drawn, each with its label: a network's name that several links share is told once, as a zone, and its links are drawn only where the path runs. */
const drawnLinks = (layout: NetworkLayout) => layout.links.filter((line) => line.zone === null);

function linkWords(layout: NetworkLayout): Box[] {
  return drawnLinks(layout).map((line) => {
    const wide = chars(line.link.label, 11) + 16;
    return { what: `label of ${line.from.host.id}-${line.to.host.id}`, x0: line.label.x - wide / 2, y0: line.label.y - 9, x1: line.label.x + wide / 2, y1: line.label.y + 9 };
  });
}

function badges(layout: NetworkLayout): Box[] {
  return layout.hosts.map((node) => ({ what: `badge of ${node.host.id}`, x0: node.badge.x - 55, y0: node.badge.y - 22, x1: node.badge.x + 55, y1: node.badge.y }));
}

function circles(layout: NetworkLayout): Box[] {
  return [
    ...layout.hosts.map((node) => ({ what: `host ${node.host.id}`, x0: node.x - node.r, y0: node.y - node.r, x1: node.x + node.r, y1: node.y + node.r })),
    ...layout.sensors.map((node) => ({ what: `dot of ${node.sensor.id}`, x0: node.x - node.r, y0: node.y - node.r, x1: node.x + node.r, y1: node.y + node.r })),
    // A rule engine, and its words, which run to the right edge.
    ...layout.detectors.map((node) => ({ what: `engine ${node.detector.id}`, x0: node.x - node.r, y0: node.y - node.r, x1: layout.width, y1: node.y + 70 })),
  ];
}

const meets = (a: Box, b: Box): boolean => Math.min(a.x1, b.x1) - Math.max(a.x0, b.x0) > 1 && Math.min(a.y1, b.y1) - Math.max(a.y0, b.y0) > 1;
const holds = (box: Box, x: number, y: number): boolean => x > box.x0 + 1 && x < box.x1 - 1 && y > box.y0 + 1 && y < box.y1 - 1;
const along = (curve: Curve): { x: number; y: number }[] => Array.from({ length: 59 }, (_, index) => pointOn(curve, (index + 1) / 60));

/**
 * Every overlap on the map, in words; empty when nothing overlaps. With
 * `underLabels` false, a line under another link's label is let pass: on a
 * screen 1024 px wide the links of range one cross where their labels are.
 */
function overlaps(layout: NetworkLayout, underLabels = true): string[] {
  const found: string[] = [];
  const words = [...hostWords(layout), ...sensorWords(layout), ...linkWords(layout)];
  const things = [...words, ...circles(layout)];
  for (const [index, a] of things.entries()) for (const b of things.slice(index + 1)) if (meets(a, b)) found.push(`${a.what} on ${b.what}`);
  // A badge shows on one host at a time, so badges are measured against everything but each other, and may sit on their own host's ring.
  for (const badge of badges(layout)) for (const other of things) if (other.what !== `host ${badge.what.slice("badge of ".length)}` && meets(badge, other)) found.push(`${badge.what} on ${other.what}`);
  // No link and no sensor's line runs through a host's name, a sensor's name or dot, or another link's label;
  // no link through a host it does not join, and no sensor's line back through its own host.
  // Every link is measured, a zone's too: the attack's path draws it whenever a step crosses it.
  const names = hostWords(layout);
  const sensors = [...sensorWords(layout), ...circles(layout).filter((box) => box.what.startsWith("dot of "))];
  const labels = underLabels ? linkWords(layout) : [];
  for (const line of layout.links) {
    const what = `link ${line.from.host.id}-${line.to.host.id}`;
    for (const point of along(line.curve)) {
      for (const box of [...names, ...sensors]) if (holds(box, point.x, point.y)) found.push(`${what} through ${box.what}`);
      for (const box of labels) if (box.what !== `label of ${line.from.host.id}-${line.to.host.id}` && holds(box, point.x, point.y)) found.push(`${what} through ${box.what}`);
      for (const node of layout.hosts) if (node !== line.from && node !== line.to && Math.hypot(point.x - node.x, point.y - node.y) < node.r) found.push(`${what} through host ${node.host.id}`);
    }
  }
  for (const [id, curve] of layout.sensorToJunction) {
    const own = layout.sensors.find((node) => node.sensor.id === id);
    const host = layout.hosts.find((node) => node.host.id === own?.sensor.host && node.host.id !== layout.junction.hostId);
    for (const point of along(curve)) {
      for (const box of [...names, ...labels]) if (holds(box, point.x, point.y)) found.push(`line of ${id} through ${box.what}`);
      for (const box of sensors) if (!box.what.endsWith(` ${id}`) && holds(box, point.x, point.y)) found.push(`line of ${id} through ${box.what}`);
      if (host && Math.hypot(point.x - host.x, point.y - host.y) < host.r) found.push(`line of ${id} back through host ${host.host.id}`);
    }
  }
  // Everything stays on the map.
  for (const box of [...things, ...badges(layout)]) if (box.x0 < 0 || box.x1 > layout.width + 0.5 || box.y0 < 0 || box.y1 > layout.height) found.push(`${box.what} off the map`);
  return [...new Set(found)];
}

const SIZES = [
  [1440, 325],
  [1920, 450],
  [1024, 230],
] as const;

describe("the network map's layout of one host", () => {
  it("is today's layout, number for number", () => {
    // Today's one-host layout at 1440 by 330 pixels, kept as it was when networks of several hosts were laid out anew.
    const layout = layoutNetwork(one, 1440, 330);
    expect(layout.single).toBe(true);
    expect(layout.height).toBe(330);
    expect(layout.hosts.map(({ host: item, x, y, r }) => [item.id, x, y, r])).toEqual([["runner", 216, 175, 36]]);
    expect(layout.hosts[0]?.badge).toEqual({ x: 216, y: 119 });
    expect(layout.sensors.map(({ sensor, x, y, r, small, side, above }) => [sensor.id, x, y, r, small, side, above])).toEqual([
      ["sysmon", 395, 89, 18, false, 1, true],
      ["auditd", 395, 261, 18, false, 1, false],
    ]);
    expect(layout.detectors.map(({ detector, x, y, r }) => [detector.id, x, y, r])).toEqual([
      ["pinned", 994, 115, 22],
      ["lab", 994, 235, 22],
    ]);
    expect(layout.junction).toEqual({ x: 850, y: 175, r: 4, hostId: null });
    expect(layout.orbit).toEqual({ x: 216, y: 153 });
    expect([layout.centerY, layout.fieldHeadX, layout.detectorsHeadX, layout.silence.x, layout.silence.y]).toEqual([175, 216, 972, 631.5, 175]);
    expect(layout.sensorToJunction.get("sysmon")).toEqual([layout.sensors[0], { x: 622.5, y: 89 }, { x: 622.5, y: 175 }, layout.junction]);
  });
});

describe("the network map's layout of several hosts", () => {
  // Twelve hosts stand in six columns, which a 1024 px wide screen cannot hold side by side: they are measured on wider screens.
  it.each([
    ["two", two, SIZES],
    ["four", four, SIZES],
    ["seven", seven, SIZES],
    ["twelve", twelve(), SIZES.slice(0, 2)],
  ] as const)("lays out %s hosts with no word, badge, link or host on another", (_, network, sizes) => {
    const found = sizes.flatMap(([width, height]) => {
      const layout = layoutNetwork(network, width, height);
      expect(layout.hosts).toHaveLength(network.hosts.length);
      return overlaps(layout, width >= 1440).map((item) => `${width} by ${height}: ${item}`);
    });
    expect(found, found.join("\n")).toEqual([]);
  });

  it("finds an overlap when there is one", () => {
    // The measure itself: a second host put on top of web is caught.
    const layout = layoutNetwork(seven, 1440, 325);
    const web = layout.hosts.find((node) => node.host.id === "web");
    if (!web) throw new Error("web should be there");
    const twin = { ...web, host: { ...web.host, id: "twin" }, x: web.x + 20 };
    expect(overlaps({ ...layout, hosts: [...layout.hosts, twin] }).length).toBeGreaterThan(0);
  });

  it("finds a link through a sensor's name, a link under another's label, and a sensor's line back through its own host", () => {
    const layout = layoutNetwork(seven, 1440, 325);
    const web = layout.hosts.find((node) => node.host.id === "web");
    const sensor = layout.sensors.find((node) => node.sensor.id === "agent-web");
    const path = layout.links.find((line) => line.from.host.id === "web" && line.to.host.id === "build");
    const pair = layout.links.find((line) => line.link.label === "SSH, MariaDB");
    if (!web || !sensor || !path || !pair) throw new Error("range one's web, its sensor and its links should be there");
    // Web's sensor on the attacker's side of web, its name on the attacker's link; its line from there back across web.
    const moved = { ...sensor, x: web.x - web.r - 18, y: web.y, side: -1 as const, above: false };
    const back: Curve = [moved, { x: web.x, y: web.y }, { x: web.x, y: web.y }, layout.junction];
    // The label of db and build on web's link to build.
    const covering = { ...pair, label: pointOn(path.curve, 0.5) };
    const found = overlaps({
      ...layout,
      sensors: layout.sensors.map((node) => (node === sensor ? moved : node)),
      sensorToJunction: new Map([...layout.sensorToJunction, ["agent-web", back]]),
      links: layout.links.map((line) => (line === pair ? covering : line)),
    });
    // Range one's agents are named once, in the network's head: web's is a dot with no words, and a link through it is caught.
    expect(found, found.join("\n")).toEqual(expect.arrayContaining(["link attacker-web through dot of agent-web", "link web-build through label of db-build", "line of agent-web back through host web"]));
  });

  it("puts range one's attacker and client first, web and inet next, db and build after them, the manager and the rule engines last", () => {
    const layout = layoutNetwork(seven, 1440, 325);
    const x = (id: string) => layout.hosts.find((node) => node.host.id === id)?.x ?? Number.NaN;
    expect(x("attacker")).toBe(x("client"));
    expect(x("web")).toBe(x("inet"));
    expect(x("db")).toBe(x("build"));
    expect(x("attacker")).toBeLessThan(x("web"));
    expect(x("web")).toBeLessThan(x("db"));
    expect(x("db")).toBeLessThan(x("manager"));
    expect(layout.detectors[0]?.x ?? 0).toBeGreaterThan(x("manager"));
  });

  it("draws one line for the two links of a pair, with both labels, and leaves a host's link to the defense to its sensor's line", () => {
    const layout = layoutNetwork(seven, 1440, 325);
    const pair = layout.links.filter((line) => [line.from.host.id, line.to.host.id].sort().join() === "build,db");
    expect(pair.map((line) => line.link.label)).toEqual(["SSH, MariaDB"]);
    expect(layout.links.some((line) => line.to.host.id === "manager" || line.from.host.id === "manager")).toBe(false);
  });

  it("draws a link to the defense that no sensor's line shows: one from the defense, or one to another defense host", () => {
    const network: Network = {
      ...four,
      hosts: [...four.hosts, host("siem", "defense", "log store")],
      links: [...(four.links ?? []), { from: "manager", to: "web", label: "SSH" }, { from: "web", to: "siem", label: "syslog" }],
    };
    const drawn = layoutNetwork(network, 1440, 325).links.map((line) => `${line.from.host.id}-${line.to.host.id} ${line.link.label}`);
    expect(drawn).toEqual(expect.arrayContaining(["manager-web SSH", "web-siem syslog"]));
    expect(drawn.some((line) => line.startsWith("db-manager"))).toBe(false);
  });

  // Four layouts of seven and twelve hosts take a second or more, and longer on a busy machine: the limit the tests
  // that lay out as much have.
  it("fits range one in the room it is given, and grows taller only for a network that needs more", () => {
    const fits = layoutNetwork(seven, 1440, 325);
    expect(fits.height).toBe(325);
    expect(fits.least).toBeLessThanOrEqual(325);
    const tall = layoutNetwork(twelve(), 1440, 325);
    expect(tall.height).toBeGreaterThan(325);
    // What the network needs does not depend on the height it was given, so the map's height settles.
    const again = layoutNetwork(twelve(), 1440, tall.height);
    expect([again.least, again.height]).toEqual([tall.least, tall.height]);
  }, 30_000);
});
