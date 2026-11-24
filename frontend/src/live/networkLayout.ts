// Lays out a recording's network for the map: pure, no DOM.
//
// One grammar for one host or many. Hosts stand in the field, laid out in
// layers from left to right by walking the links from where the attacker
// starts. Each sensor is a satellite of its host. The sensors' lines join where
// the defense collects them: its own server when the network has one, a quiet
// point otherwise. The rule engines stand in a column of their own on the right.

import type { Detector, Host, Link, Network, Sensor } from "./recording";
import { maxOf } from "./playback";

export interface Point {
  x: number;
  y: number;
}

/** A cubic Bezier curve: start, two control points, end. */
export type Curve = readonly [Point, Point, Point, Point];

export interface HostNode extends Point {
  host: Host;
  r: number;
}

export interface SensorNode extends Point {
  sensor: Sensor;
  r: number;
  /** True when the sensor is drawn small beside its host, as on a network of several hosts. */
  small: boolean;
  /** The side its name sits on: 1 to the right, -1 to the left. */
  side: 1 | -1;
  /** True when it sits above its host, so its name goes above its line. */
  above: boolean;
}

export interface DetectorNode extends Point {
  detector: Detector;
  r: number;
}

export interface LinkLine {
  link: Link;
  from: HostNode;
  to: HostNode;
  curve: Curve;
  /** Where the link's label goes. */
  label: Point;
}

export interface Junction extends Point {
  r: number;
  /** The defense host the sensors' lines join at, or null for a plain point. */
  hostId: string | null;
}

export interface NetworkLayout {
  width: number;
  height: number;
  /** True when the field holds one host. */
  single: boolean;
  centerY: number;
  hosts: HostNode[];
  sensors: SensorNode[];
  detectors: DetectorNode[];
  links: LinkLine[];
  junction: Junction;
  hostToSensor: Map<string, Curve>;
  sensorToJunction: Map<string, Curve>;
  junctionToDetector: Map<string, Curve>;
  /** The radii of the ellipse sensors orbit their host on, for one host. 0 otherwise. */
  orbit: { x: number; y: number };
  /** Where the column heads go: the field's centre, and the left edge of the rule engines' column. */
  fieldHeadX: number;
  detectorsHeadX: number;
  /** Where silence is told on an unseen step: the corridor the lights would have crossed. */
  silence: Point;
}

const clamp = (value: number, low: number, high: number): number => Math.max(low, Math.min(high, value));

function spread(count: number, centre: number, gap: number): number[] {
  return Array.from({ length: count }, (_, index) => centre + (index - (count - 1) / 2) * gap);
}

function line(a: Point, b: Point): Curve {
  return [a, { x: a.x + (b.x - a.x) / 3, y: a.y + (b.y - a.y) / 3 }, { x: a.x + (2 * (b.x - a.x)) / 3, y: a.y + (2 * (b.y - a.y)) / 3 }, b];
}

function bend(a: Point, b: Point, amount = 0.5, offset = 0): Curve {
  const dx = (b.x - a.x) * amount;
  return [a, { x: a.x + dx, y: a.y + offset }, { x: b.x - dx, y: b.y + offset }, b];
}

/** The point at `u` (0 to 1) along a curve. */
export function pointOn(curve: Curve, u: number): Point {
  const [p0, p1, p2, p3] = curve;
  const v = 1 - u;
  const a = v * v * v;
  const b = 3 * v * v * u;
  const c = 3 * v * u * u;
  const d = u * u * u;
  return { x: a * p0.x + b * p1.x + c * p2.x + d * p3.x, y: a * p0.y + b * p1.y + c * p2.y + d * p3.y };
}

function edgeToward(from: Point & { r: number }, to: Point, gap = 2): Point {
  const dx = to.x - from.x;
  const dy = to.y - from.y;
  const length = Math.hypot(dx, dy) || 1;
  return { x: from.x + (dx / length) * (from.r + gap), y: from.y + (dy / length) * (from.r + gap) };
}

const round = (value: number): string => (Math.round(value * 10) / 10).toString();
const pair = (point: Point): string => `${round(point.x)},${round(point.y)}`;

/** An SVG path of one curve. */
export function curvePath(curve: Curve): string {
  return `M${pair(curve[0])} C${pair(curve[1])} ${pair(curve[2])} ${pair(curve[3])}`;
}

/** An SVG path of curves that follow each other. */
export function chainPath(curves: readonly Curve[]): string {
  const first = curves[0];
  if (!first) return "";
  return `M${pair(first[0])}${curves.map((curve) => ` C${pair(curve[1])} ${pair(curve[2])} ${pair(curve[3])}`).join("")}`;
}

/** The path a recorded event travels: from its host to the sensor, to where the lines join, to one rule engine. */
export function travelPath(layout: NetworkLayout, sensorId: string, detectorId: string): string | null {
  const hs = layout.hostToSensor.get(sensorId);
  const sj = layout.sensorToJunction.get(sensorId);
  const jd = layout.junctionToDetector.get(detectorId);
  if (!hs || !sj || !jd) return null;
  return chainPath([hs, sj, jd]);
}

type Box = [number, number, number, number];

function overlap(a: Box, b: Box): number {
  return Math.max(0, Math.min(a[2], b[2]) - Math.max(a[0], b[0])) * Math.max(0, Math.min(a[3], b[3]) - Math.max(a[1], b[1]));
}

/** Width in pixels of a short label, near enough to place it. */
function textWidth(text: string, size = 11.5): number {
  return text.length * size * 0.56;
}

/**
 * Lays out `network` in a box of `width` by `height` pixels.
 * Nothing but the network decides where things go, so any number of hosts uses the same code.
 */
export function layoutNetwork(network: Network, width: number, height: number): NetworkLayout {
  const W = Math.max(320, width);
  const H = Math.max(240, height);
  const field = network.hosts.filter((host) => host.kind !== "defense");
  const defense = network.hosts.filter((host) => host.kind === "defense");
  const single = field.length <= 1;
  const top = 64;
  const bottom = 14;
  const room = H - top - bottom;
  const railX = Math.round(W - clamp(W * 0.31, 380, 640));
  const jx = Math.round(railX - clamp(W * 0.1, 110, 200));
  const hosts = new Map<string, HostNode>();
  const sensors: SensorNode[] = [];
  let centerY: number;
  let orbit = { x: 0, y: 0 };
  let fieldHeadX: number;

  if (single) {
    centerY = Math.round(top + room * 0.44);
    const only = field[0];
    const x = Math.round(clamp(W * 0.15, 150, 330));
    if (only) hosts.set(only.id, { host: only, x, y: centerY, r: Math.round(clamp(room * 0.13, 36, 58)) });
    fieldHeadX = x;
  } else {
    centerY = Math.round(top + room * 0.5 - 8);
    const neighbours = new Map<string, string[]>(field.map((host) => [host.id, []]));
    for (const link of network.links ?? []) {
      neighbours.get(link.from)?.push(link.to);
      neighbours.get(link.to)?.push(link.from);
    }
    const start = field.find((host) => host.kind === "attacker") ?? field[0];
    const layer = new Map<string, number>();
    if (start) {
      layer.set(start.id, 0);
      const queue = [start.id];
      while (queue.length > 0) {
        const current = queue.shift() ?? "";
        const depth = layer.get(current) ?? 0;
        for (const next of neighbours.get(current) ?? []) {
          // A link to a defense host does not make a column of the field: the defense stands apart.
          if (!layer.has(next) && neighbours.has(next)) {
            layer.set(next, depth + 1);
            queue.push(next);
          }
        }
      }
    }
    let deepest = Math.max(0, maxOf(layer.values()));
    for (const host of field) if (!layer.has(host.id)) layer.set(host.id, ++deepest);
    const left = Math.round(Math.max(110, W * 0.08));
    const right = Math.round(jx - clamp(W * 0.14, 170, 260));
    // Room above the top host for its sensor, and below the bottom host for its name.
    const vertical = clamp(room - 150, 0, 480);
    for (let depth = 0; depth <= deepest; depth += 1) {
      const members = field.filter((host) => layer.get(host.id) === depth);
      const x = deepest > 0 ? left + ((right - left) * depth) / deepest : left;
      spread(members.length, centerY, members.length > 1 ? vertical / (members.length - 1) : 0).forEach((y, index) => {
        const host = members[index];
        if (host) hosts.set(host.id, { host, x: Math.round(x), y: Math.round(y), r: 30 });
      });
    }
    fieldHeadX = (left + right) / 2;
  }

  let junction: Junction;
  const firstDefense = defense[0];
  if (firstDefense) {
    spread(defense.length, centerY, 150).forEach((y, index) => {
      const host = defense[index];
      if (host) hosts.set(host.id, { host, x: jx, y: Math.round(y), r: single ? 34 : 30 });
    });
    const node = hosts.get(firstDefense.id);
    junction = { x: jx, y: node ? node.y : centerY, r: node ? node.r : 4, hostId: firstDefense.id };
  } else {
    junction = { x: jx, y: centerY, r: 4, hostId: null };
  }

  const detectorGap = single ? clamp(room * 0.46, 120, 280) : clamp(room * 0.3, 120, 240);
  const detectorRadius = Math.round(clamp(room * 0.075, 22, 32));
  const detectors: DetectorNode[] = [];
  spread(network.detectors.length, centerY, detectorGap).forEach((y, index) => {
    const detector = network.detectors[index];
    if (detector) detectors.push({ detector, x: railX, y: Math.round(y), r: detectorRadius });
  });
  // Where the lines to the rule engines leave the junction, and the lines themselves.
  const junctionOut: Point = junction.hostId ? { x: junction.x + junction.r + 1, y: junction.y } : junction;
  const junctionToDetector = new Map<string, Curve>();
  for (const node of detectors) {
    junctionToDetector.set(node.detector.id, bend(junctionOut, { x: node.x - node.r, y: node.y }, 0.5));
  }
  const wires: Point[] = [];
  for (const curve of junctionToDetector.values()) for (let u = 0.05; u < 1; u += 0.05) wires.push(pointOn(curve, u));

  // Every host's sensors are placed, the defense's own too: a defense host's sensors sit small beside it.
  for (const host of [...field, ...defense]) {
    const node = hosts.get(host.id);
    const own = network.sensors.filter((sensor) => sensor.host === host.id);
    if (!node || own.length === 0) continue;
    if (single && host.kind !== "defense") {
      // Sensors sit on an orbit that is wide when there is room, and flattened when the map is short.
      orbit = { x: Math.round(clamp(W * 0.15, 170, 300)), y: 0 };
      orbit.y = Math.round(Math.min(orbit.x, (room * 0.34) / 0.56));
      const span = own.length > 1 ? 68 : 0;
      own.forEach((sensor, index) => {
        const degrees = own.length > 1 ? -span / 2 + (span * index) / (own.length - 1) : 0;
        const angle = (degrees * Math.PI) / 180;
        sensors.push({ sensor, x: Math.round(node.x + orbit.x * Math.cos(angle)), y: Math.round(node.y + orbit.y * Math.sin(angle)), r: 18, small: false, side: 1, above: degrees < 0 });
      });
      continue;
    }
    // Several hosts: each sensor sits beside its host, where its name covers the least:
    // other hosts and their names, the links, the lines to the rule engines, and the sensors placed before it.
    const points: Point[] = [...wires];
    for (const link of network.links ?? []) {
      const a = hosts.get(link.from);
      const b = hosts.get(link.to);
      if (!a || !b) continue;
      for (let u = 0.05; u < 1; u += 0.05) points.push({ x: a.x + (b.x - a.x) * u, y: a.y + (b.y - a.y) * u });
    }
    const boxes: Box[] = [];
    for (const other of hosts.values()) {
      boxes.push([other.x - other.r - 4, other.y - other.r - 4, other.x + other.r + 4, other.y + other.r + 4]);
      if (other.host.id === host.id) continue;
      const words = Math.max(textWidth(other.host.name, 13), Math.min(200, textWidth(other.host.role)));
      boxes.push([other.x - words / 2, other.y + other.r + 4, other.x + words / 2, other.y + other.r + 46]);
    }
    for (const placed of sensors) {
      const words = textWidth(placed.sensor.name) + 16;
      boxes.push(placed.side > 0 ? [placed.x - 10, placed.y - 10, placed.x + words, placed.y + 10] : [placed.x - words, placed.y - 10, placed.x + 10, placed.y + 10]);
    }
    const label = maxOf(own.map((sensor) => textWidth(sensor.name))) + 16;
    const tall = own.length * 20;
    let best: { score: number; x: number; y: number; side: 1 | -1 } | null = null;
    for (const [degrees, penalty] of [[-90, 0], [-40, 2], [-140, 2], [0, 4], [180, 4], [40, 6], [140, 6]] as const) {
      const angle = (degrees * Math.PI) / 180;
      const x = node.x + Math.cos(angle) * (node.r + 20);
      const y = node.y + Math.sin(angle) * (node.r + 20);
      for (const side of [1, -1] as const) {
        const box: Box = side > 0 ? [x - 10, y - 10, x + label, y - 10 + tall] : [x - label, y - 10, x + 10, y - 10 + tall];
        let score: number = penalty;
        for (const other of boxes) score += overlap(box, other) / 20;
        for (const p of points) if (p.x > box[0] - 6 && p.x < box[2] + 6 && p.y > box[1] - 6 && p.y < box[3] + 6) score += 3;
        if (box[0] < 8 || box[2] > W - 8 || box[1] < top - 10) score += 200;
        if (!best || score < best.score) best = { score, x, y, side };
      }
    }
    if (!best) continue;
    const place = best;
    own.forEach((sensor, index) => {
      sensors.push({ sensor, x: Math.round(place.x), y: Math.round(place.y + index * 20), r: 7, small: true, side: place.side, above: place.y < node.y });
    });
  }

  const hostToSensor = new Map<string, Curve>();
  const sensorToJunction = new Map<string, Curve>();
  const fieldNodes = [...hosts.values()].filter((node) => node.host.id !== junction.hostId);
  const junctionEdge = (from: Point): Point => (junction.hostId ? edgeToward(junction, from, 1) : junction);
  for (const node of sensors) {
    const host = hosts.get(node.sensor.host);
    if (!host) continue;
    hostToSensor.set(node.sensor.id, line(edgeToward(host, node), node));
    if (node.sensor.host === junction.hostId) {
      // A sensor of the host where the lines join: its events go the short way, on to the rule engines.
      sensorToJunction.set(node.sensor.id, bend(node, junctionOut, 0.5));
      continue;
    }
    if (single) {
      sensorToJunction.set(node.sensor.id, bend(node, junction, 0.5));
      continue;
    }
    // A sensor's line to the defense bends around the hosts it would otherwise cross.
    let best: { score: number; curve: Curve } | null = null;
    for (const offset of [0, -70, 70, -140, 140]) {
      const curve = bend(node, junctionEdge(node), 0.5, offset);
      let score = Math.abs(offset) * 0.02;
      for (let u = 0.04; u < 0.97; u += 0.03) {
        const q = pointOn(curve, u);
        for (const other of fieldNodes) if (other.host.id !== node.sensor.host && Math.hypot(q.x - other.x, q.y - other.y) < other.r + 16) score += 1;
      }
      if (!best || score < best.score) best = { score, curve };
    }
    if (best) sensorToJunction.set(node.sensor.id, best.curve);
  }

  // Link labels go where they cover the least: along the link, nudged off it.
  const taken: Box[] = [];
  for (const node of hosts.values()) {
    taken.push([node.x - node.r - 6, node.y - node.r - 6, node.x + node.r + 6, node.y + node.r + 6]);
    const words = Math.max(textWidth(node.host.name, 13), textWidth(node.host.role, 11.5));
    taken.push([node.x - words / 2, node.y + node.r + 6, node.x + words / 2, node.y + node.r + 48]);
  }
  for (const node of sensors) {
    const words = textWidth(node.sensor.name) + 14;
    taken.push(node.side > 0 ? [node.x - node.r, node.y - 10, node.x + node.r + words, node.y + 10] : [node.x - node.r - words, node.y - 10, node.x + node.r, node.y + 10]);
  }
  const links: LinkLine[] = [];
  for (const link of network.links ?? []) {
    const from = hosts.get(link.from);
    const to = hosts.get(link.to);
    if (!from || !to) continue;
    const dx = to.x - from.x;
    const dy = to.y - from.y;
    const length = Math.hypot(dx, dy) || 1;
    const px = -dy / length;
    const py = dx / length;
    const w = textWidth(link.label ?? "", 11) + 20;
    const h = 20;
    let best: { score: number; point: Point; box: Box } | null = null;
    for (const u of [0.5, 0.42, 0.58, 0.34, 0.66]) {
      for (const d of [0, 14, -14, 24, -24]) {
        const x = from.x + dx * u + px * d;
        const y = from.y + dy * u + py * d;
        const box: Box = [x - w / 2, y - h / 2, x + w / 2, y + h / 2];
        let score = Math.abs(u - 0.5) * 40 + Math.abs(d) * 0.6;
        for (const other of taken) score += overlap(box, other);
        if (!best || score < best.score) best = { score, point: { x, y }, box };
      }
    }
    if (!best) continue;
    taken.push(best.box);
    links.push({ link, from, to, curve: line(edgeToward(from, to, 0), edgeToward(to, from, 0)), label: best.point });
  }

  // The silence is told in the field's corridor, left of every defense host and its sensors.
  const inField = (id: string): boolean => hosts.get(id)?.host.kind !== "defense";
  const sensorRight = Math.max(0, maxOf(sensors.filter((node) => inField(node.sensor.host)).map((node) => node.x + node.r)), maxOf([...hosts.values()].filter((node) => inField(node.host.id)).map((node) => node.x + node.r)));
  const firstDetector = detectors[0];
  return {
    width: W,
    height: H,
    single,
    centerY,
    hosts: [...hosts.values()],
    sensors,
    detectors,
    links,
    junction,
    hostToSensor,
    sensorToJunction,
    junctionToDetector,
    orbit,
    fieldHeadX,
    detectorsHeadX: firstDetector ? firstDetector.x - firstDetector.r : railX,
    silence: { x: (sensorRight + junction.x) / 2, y: centerY },
  };
}
