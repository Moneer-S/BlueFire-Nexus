// Lays out a recording's network for the map: pure, no DOM.
//
// One grammar for one host or many. Hosts stand in the field, laid out in
// columns from left to right by walking the links from where the attacker
// starts. Each sensor is a satellite of its host. The sensors' lines join where
// the defense collects them: its own server when the network has one, a quiet
// point otherwise. The rule engines stand in a column of their own on the right.
//
// A network takes the whole stage: the rule engines' column is as wide as
// their words, a column too tall for a short stage stands as two with its
// hosts taking turns, and the room between rows never makes the map taller
// than the stage. A network's name more than two links share is told once.

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
  /**
   * True when the network's head names the host's sensor once: its count of
   * events is a line of its own under the host's role, never beside a line.
   */
  counted?: boolean;
  /** Where the host's badge stands: the middle of its bottom edge. */
  badge: Point;
  /** On a network of several hosts, how wide the host's role may run before it wraps. Null for one host. */
  roleWidth: number | null;
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
  /** True when it stands in a stack of its host's sensors: its count of events goes on its name's line. */
  inline: boolean;
  /** The widest its name is drawn, in pixels: a longer one is cut there. */
  cut: number;
  /** False when its name is told once for the sensors of several hosts, in the network's head: beside it stands only its count. */
  named: boolean;
  /**
   * True when that count stands over its dot (`above`) or under it, starting
   * at the dot and running away from its host on `side`, not beside it.
   */
  over?: boolean;
}

/** The box of a lone count over a dot at `x`, `y`, or under it, running to `side`: the dot's own line leaves level beside it. */
function countBox(x: number, y: number, above: boolean, side: 1 | -1 = 1): Box {
  const [low, high] = side > 0 ? [x + 2, x + 4 + COUNT_WORDS] : [x - 4 - COUNT_WORDS, x - 2];
  return above ? [low, y - 27, high, y - 6] : [low, y + 6, high, y + 27];
}

export interface DetectorNode extends Point {
  detector: Detector;
  r: number;
}

export interface LinkLine {
  /** The link as drawn: one line for a pair of hosts, with the labels of both directions. */
  link: Link;
  from: HostNode;
  to: HostNode;
  curve: Curve;
  /** Where the link's label goes. */
  label: Point;
  /**
   * True when the label is drawn on this link. A label more than two links
   * share names a network: it is told once, on the one of them where it
   * covers least, and the links of that network are drawn as one zone.
   */
  told: boolean;
  /** The network the link belongs to, when its label is told once for several links: that label. Null otherwise. */
  zone: string | null;
}

/** A network that several links share, told once on the map: a soft rounded box round its hosts, and its name once. */
export interface Zone {
  /** The links' label, as the recording gives it: "edge", "inside, mgmt". */
  name: string;
  /** Its name as the map tells it: "edge", "inside + mgmt". */
  words: string;
  /** The hosts on it, by id: every host one of its links reaches, a defense host too, and a bridge whose home is another zone. */
  hosts: string[];
  /** The box round its own hosts and their names; it stops short of a bridge whose home is another zone. */
  box: Box;
  /** Where its name starts: the left end, at the middle of its line. Null where no corner of its box is free of hosts, words and lines. */
  label: Point | null;
  /**
   * True when the map draws the field. The fields are drawn only when every one can be drawn whole, as they cannot
   * where the columns fold; an undrawn field still names its network in its hosts' details.
   */
  drawn: boolean;
}

/**
 * The defense's own side of a network, at the right: its hosts and the rule
 * engines in one field, with one quiet line at its foot that says which
 * sensors report to it.
 */
export interface DefenseSide {
  box: Box;
  /**
   * Where the line about its sensors starts: its left end, the top of its first line. Null where that line would lie
   * on a host's circle, words or badge: it is then left out.
   */
  note: Point | null;
  /** How wide that line may run before it wraps. */
  noteWidth: number;
}

/** The room the line at the foot of the defense's side takes: two lines of 11.5 px words. */
export const DEFENSE_NOTE = 38;

/** The box the line about the defense's sensors takes, or null where it is left out. */
export function defenseNoteBox(side: DefenseSide): Box | null {
  return side.note ? [side.note.x, side.note.y, side.note.x + side.noteWidth, side.note.y + DEFENSE_NOTE] : null;
}

/** True when the line about the defense's sensors lies on no host's circle, lit ring, words or badge, and on no sensor's words. */
function noteClear(side: DefenseSide, hosts: readonly HostNode[], sensorWords: readonly Box[]): boolean {
  const note = defenseNoteBox(side);
  if (!note) return true;
  const near: Box = [note[0] - 4, note[1] - 4, note[2] + 4, note[3] + 4];
  return hosts.every((node) => [circleBox(node, BADGE.ring - 1), labelBox(node), badgeBoxOf(node)].every((box) => overlap(near, box) === 0)) && sensorWords.every((box) => overlap(near, box) === 0);
}

/**
 * True when a field can be drawn whole: its box holds the circle of every host on it, but for a host on two fields,
 * which may stand on the border between them, its centre on the box's side; it covers no host of another field, has
 * its name in a corner, and lies on no other field.
 */
export function fieldWhole(zone: Zone, zones: readonly Zone[], hosts: readonly HostNode[]): boolean {
  if (!zone.drawn || !zone.label) return false;
  const [x0, y0, x1, y1] = zone.box;
  for (const node of hosts) {
    if (!zone.hosts.includes(node.host.id)) {
      if (overlap(zone.box, circleBox(node, 6)) > 0) return false;
      continue;
    }
    const ring = circleBox(node, 0);
    const across = ring[1] >= y0 && ring[3] <= y1;
    const inside = across && ring[0] >= x0 && ring[2] <= x1;
    const bridge = zones.filter((other) => other.hosts.includes(node.host.id)).length > 1;
    const onBorder = across && bridge && (Math.abs(node.x - x0) < 1 || Math.abs(node.x - x1) < 1);
    if (!inside && !onBorder) return false;
  }
  return zones.every((other) => other === zone || overlap(zone.box, other.box) === 0);
}

/** The radius of a zone's corners, and the room it keeps round its hosts' rings and words. */
export const ZONE_RADIUS = 26;
const ZONE_PAD = 12;
/** The least gap between a zone's box and a bridge host whose home is another zone. */
const ZONE_GAP = 10;

export interface Junction extends Point {
  r: number;
  /** The defense host the sensors' lines join at, or null for a plain point. */
  hostId: string | null;
}

export interface NetworkLayout {
  width: number;
  /** The height the map takes: the height it was given, or more when the network needs more room. */
  height: number;
  /**
   * The least height the network needs at this width, whatever height it was
   * given, with room above every row for its badges; for a map given less,
   * the least of its least layout (`leastHeights`). 240 at the least.
   */
  least: number;
  /** True when the field holds one host. */
  single: boolean;
  /** The lines of the step's command under a single host: one where the map is too short for two above its bottom. */
  commandLines: 1 | 2;
  centerY: number;
  hosts: HostNode[];
  sensors: SensorNode[];
  detectors: DetectorNode[];
  links: LinkLine[];
  /** The networks told once, each an outline round its hosts where it is drawn. Empty for one host. */
  zones: Zone[];
  /** On a network with a defense host, the defense's own side: null otherwise. */
  defenseSide: DefenseSide | null;
  junction: Junction;
  hostToSensor: Map<string, Curve>;
  sensorToJunction: Map<string, Curve>;
  junctionToDetector: Map<string, Curve>;
  /** The radii of the ellipse sensors orbit their host on, for one host. 0 otherwise. */
  orbit: { x: number; y: number };
  /** Where the column heads go: the field's centre, and the left edge of the rule engines' column. */
  fieldHeadX: number;
  detectorsHeadX: number;
  /** Where silence is told on an unseen step of one host and no defense host: the corridor the lights would have crossed. */
  silence: Point;
  /**
   * Where silence is told, in the smaller words of `SILENCE_WORDS`, on an
   * unseen step of each host of a network: near the host, on no host, name,
   * sensor, badge or link label. Empty for one host and no defense host.
   */
  silenceAt: Map<string, Point>;
}

/** The bottom of the column heads: nothing of the field but a badge reaches above it. */
const HEADS_BOTTOM = 50;
/** On a map of one host, the highest a defense host's centre stands, and the room under its centre for its name and role. */
const SINGLE_DEFENSE_TOP = HEADS_BOTTOM + 6 + 34;
const SINGLE_DEFENSE_BELOW = 34 + 10 + 46;
/**
 * Pixels between two defense hosts beside one host: the upper one's name and
 * role, then the lower one's badge or its sensor's name and count above it.
 */
const SINGLE_DEFENSE_PITCH = SINGLE_DEFENSE_BELOW + 34 + 20 + 27 + 14;

/** The least width of the map: below it, the map keeps this width and scrolls sideways in its box. */
export const LEAST_MAP_WIDTH = 960;
/** The most hosts one column holds, one above another; a column of more stands as several. */
const ROWS_MOST = 4;
/** The least pixels between two columns of hosts: a network with more columns than fit keeps the width they need. */
const COLUMN_LEAST = 112;
/** The least width a host's role wraps at on a network of several hosts; its name is cut to the same width. */
const ROLE_LEAST = 84;
/** The least pixels between two rule engines, and the room under an engine's centre for its name, rules and matches. */
const ENGINE_PITCH = 120;
const ENGINE_BELOW = 56;
/** Pixels between two defense hosts, which never stand closer: each has its name under it and its sensors above it. */
const DEFENSE_PITCH = 150;
/** The widest a sensor's name is drawn on a network of several hosts, in pixels; a longer one is cut. */
export const SENSOR_NAME_MOST = 150;
/** The least pixels, up and down, between two of the one host's sensors when it has more than two: a name and a count stand beside each. */
const SENSOR_ORBIT_STEP = 66;
/**
 * Pixels between two small sensors of one host, one above the other. A
 * sensor alone has its count of events under its name; sensors in a stack
 * have it on the name's line, so `STACK_COUNT` more pixels of width.
 */
const SENSOR_STACK = 20;
const STACK_COUNT = 56;
/** The height of the words of `count` small sensors of one host, a lone one's count of events under its name included. */
const stackTall = (count: number): number => (count > 1 ? count * SENSOR_STACK + 4 : 36);
/** The box of the smaller words that tell silence near a host of a network, in pixels: the map draws them this size. */
export const SILENCE_WORDS = { width: 200, height: 50 } as const;
/** The box of the larger words that tell silence in the corridor of one host, near enough: two lines of up to 30 px type. */
const CORRIDOR_WORDS = { width: 320, height: 84 } as const;
/** The widest a large sensor's name of one host is drawn, in pixels; a longer one is cut. */
export const SENSOR_NAME_LARGE = 300;

const clamp = (value: number, low: number, high: number): number => Math.max(low, Math.min(high, value));

function spread(count: number, centre: number, gap: number): number[] {
  return Array.from({ length: count }, (_, index) => centre + (index - (count - 1) / 2) * gap);
}

/**
 * The centres of a column of `count` things: `gap` apart around `centre`,
 * drawn closer, down to `least`, and moved, so that every centre stands
 * between `low` and `high`. `short` is how many pixels the column lacks at
 * `least`: the map must be that much taller for it to fit.
 */
export function fitColumn(count: number, centre: number, gap: number, least: number, low: number, high: number): { ys: number[]; short: number } {
  if (count === 0) return { ys: [], short: 0 };
  const room = Math.max(0, high - low);
  const pitch = count > 1 ? Math.min(gap, Math.max(least, room / (count - 1))) : 0;
  const block = pitch * (count - 1);
  const middle = block <= room ? clamp(centre, low + block / 2, high - block / 2) : low + block / 2;
  return { ys: spread(count, middle, pitch), short: Math.max(0, block - room) };
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
  // Where the lines join at a defense host, a light ends at its ring and leaves again from its other side: it never crosses the host.
  return layout.single || layout.junction.hostId === null ? chainPath([hs, sj, jd]) : `${chainPath([hs, sj])} ${curvePath(jd)}`;
}

/** The drawn link between two hosts, either way round, with its curve running from `from` to `to`. Null when none is drawn. */
export function linkBetween(layout: NetworkLayout, from: string, to: string): { line: LinkLine; curve: Curve } | null {
  for (const item of layout.links) {
    if (item.from.host.id === from && item.to.host.id === to) return { line: item, curve: item.curve };
    if (item.from.host.id === to && item.to.host.id === from) return { line: item, curve: [item.curve[3], item.curve[2], item.curve[1], item.curve[0]] };
  }
  return null;
}

export type Box = [number, number, number, number];

function overlap(a: Box, b: Box): number {
  return Math.max(0, Math.min(a[2], b[2]) - Math.max(a[0], b[0])) * Math.max(0, Math.min(a[3], b[3]) - Math.max(a[1], b[1]));
}

/** Width in pixels of a short label, near enough to place it. */
function textWidth(text: string, size = 11.5): number {
  return text.length * size * 0.56;
}

/**
 * The sensors whose name the map tells once, in the network's head, and not
 * beside each: a name that sensors on two hosts of the field or more share,
 * such as an agent on every host. Each of them is a dot by its host, with its
 * count of events beside it while a step runs.
 */
const NAMED_ONCE = new WeakSet<Sensor>();

/** The name sensors on several hosts of the field share, which the map tells once; null when there is none. */
export function sharedSensorName(network: Network): string | null {
  const fieldHosts = new Set(network.hosts.filter((host) => host.kind !== "defense").map((host) => host.id));
  const hostsOf = new Map<string, Set<string>>();
  for (const sensor of network.sensors) {
    if (!fieldHosts.has(sensor.host)) continue;
    const hosts = hostsOf.get(sensor.name) ?? new Set<string>();
    hosts.add(sensor.host);
    hostsOf.set(sensor.name, hosts);
  }
  // One name told once: the one the most hosts share.
  const [name, hosts] = [...hostsOf].sort((a, b) => b[1].size - a[1].size)[0] ?? [null, new Set<string>()];
  return name !== null && hosts.size > 1 ? name : null;
}

/** The hosts whose sensor's name the head tells once: each has its count of events as a line under its role. */
const COUNTED = new WeakSet<Host>();

function markNamedOnce(network: Network): void {
  const name = sharedSensorName(network);
  const field = new Set(network.hosts.filter((host) => host.kind !== "defense").map((host) => host.id));
  for (const sensor of network.sensors) {
    if (name === null || sensor.name !== name || !field.has(sensor.host)) continue;
    NAMED_ONCE.add(sensor);
    const host = network.hosts.find((item) => item.id === sensor.host);
    if (host) COUNTED.add(host);
  }
}

/** The hosts an alert of the run is raised on: each keeps a line under its words for the alert's chip and its time. */
const ALERTED = new WeakSet<Host>();

/** The height of the line under a host's words that holds the chip of an alert raised on it, and its width: the chip and "◆ first alert 01:01.6". */
const ALERT_LINE = 22;
const ALERT_WORDS = 220;

/**
 * Marks the hosts of `network` that an alert of the run is raised on, by id, so
 * that their words keep room for the alert's chip under them. The map marks
 * them before it lays the network out; the room is the same at every moment.
 * A running recording gains alerts as it is followed: a host marked anew
 * drops the layouts kept for its network, so the next one keeps its room.
 */
export function markAlertedHosts(network: Network, ids: Iterable<string>): void {
  const wanted = new Set(ids);
  let added = false;
  for (const host of network.hosts) {
    if (!wanted.has(host.id) || host.kind === "defense" || ALERTED.has(host)) continue;
    ALERTED.add(host);
    added = true;
  }
  if (added) keptLayouts.delete(network);
}

/** The host an attack path's goal is on: its badge, "goal reached" and the goal's time, is wider than any other. */
const GOAL = new WeakSet<Host>();

/** The width of the goal's badge with its time: "◆ goal reached 10:28.4", and an hour's digits more. */
const GOAL_BADGE_WIDTH = 214;

/**
 * Marks the host of `network` an attack path's goal is on, by id, so that its
 * badge's place keeps room for the goal's wider badge at every moment alike. A
 * host marked anew drops the layouts kept for its network.
 */
export function markGoalHost(network: Network, id: string): void {
  const host = network.hosts.find((item) => item.id === id && item.kind !== "defense");
  if (!host || GOAL.has(host)) return;
  GOAL.add(host);
  keptLayouts.delete(network);
}

/** The box a host's badge takes where it stands: as wide as the widest badge the host shows. */
export function badgeBoxOf(node: HostNode): Box {
  const half = (GOAL.has(node.host) ? GOAL_BADGE_WIDTH : BADGE.width) / 2;
  return [node.badge.x - half, node.badge.y - BADGE.height, node.badge.x + half, node.badge.y];
}

/** The width of a sensor's count of events ("1,439 events"), which stands alone beside a sensor whose name is told once. */
const COUNT_WORDS = 96;

/** Width in pixels of a small sensor's name as the map draws it: cut at `SENSOR_NAME_MOST`, or only its count when its name is told once. */
function smallName(sensor: Sensor): number {
  // A sensor named once in the head has no words beside its dot: its count is a line under its host's role.
  return NAMED_ONCE.has(sensor) ? 0 : Math.min(SENSOR_NAME_MOST, textWidth(sensor.name));
}

/** The box of a small sensor's words beside its dot: its name, and a lone sensor's count above its name when it stands above its host, else under it. */
function smallWords(node: SensorNode): Box {
  const words = smallName(node.sensor) + 16 + (node.inline ? STACK_COUNT : 0);
  const [up, down] = node.inline ? [10, 10] : node.above ? [27, 10] : [10, 27];
  return node.side > 0 ? [node.x - 10, node.y - up, node.x + words, node.y + down] : [node.x - words, node.y - up, node.x + 10, node.y + down];
}

/**
 * The height in pixels, from the edge of a single host's node down, that its
 * label takes: the 10 px above it, then the name, the step's command on two
 * lines and the host's role, at the largest sizes the page sets them.
 */
const SINGLE_LABEL = 102;

/**
 * Lays out `network` in a box of `width` by `height` pixels.
 * Nothing but the network decides where things go, so any number of hosts uses the same code.
 * With `squeeze`, a network of several hosts given less height than its rows
 * need with room above them for their badges is laid out at its least layout
 * (`leastHeights`), a lower host's badge beside it, where that fits; the watch
 * view asks for it when its room is short.
 */
export function layoutNetwork(network: Network, width: number, height: number, squeeze = false): NetworkLayout {
  const field = network.hosts.filter((host) => host.kind !== "defense");
  // A network is laid out at widths in steps of `WIDTH_STEP`, so dragging a window's edge lays it out once a step; the map stands in the middle of its box.
  if (field.length > 1) return layoutMany(network, Math.max(LEAST_MAP_WIDTH, Math.floor(width / WIDTH_STEP) * WIDTH_STEP), height, squeeze);
  const W = Math.max(LEAST_MAP_WIDTH, width);
  const defense = network.hosts.filter((host) => host.kind === "defense");
  const top = 64;
  const bottom = 14;
  // The columns of defense hosts and of rule engines each fit the map's height; one that needs more makes the map taller.
  const engineRadius = (H: number): number => Math.round(clamp((H - top - bottom) * 0.075, 22, 32));
  // More than two sensors of the host stand `SENSOR_ORBIT_STEP` apart, each with its words, around the host's centre: 0.44 of the room down.
  const ownSensors = network.sensors.filter((sensor) => sensor.host === field[0]?.id).length;
  const sensorReach = ownSensors > 2 ? (SENSOR_ORBIT_STEP * (ownSensors - 1)) / 2 : 0;
  const columnsNeed = (H: number): number =>
    Math.max(
      ENGINE_PITCH * Math.max(0, network.detectors.length - 1) + HEADS_BOTTOM + 6 + engineRadius(H) + ENGINE_BELOW + bottom,
      SINGLE_DEFENSE_PITCH * Math.max(0, defense.length - 1) + SINGLE_DEFENSE_TOP + SINGLE_DEFENSE_BELOW + bottom,
      sensorReach > 0 ? top + bottom + Math.max((sensorReach + 46 + HEADS_BOTTOM - top) / 0.44, (sensorReach + 48) / 0.56) : 0,
    );
  let least = 240;
  for (let pass = 0; pass < 3; pass += 1) least = Math.max(least, columnsNeed(least));
  const H = Math.max(240, height, least);
  const room = H - top - bottom;
  const railX = Math.round(W - clamp(W * 0.31, 380, 640));
  const jx = Math.round(railX - clamp(W * 0.1, 110, 200));
  const hosts = new Map<string, HostNode>();
  const sensors: SensorNode[] = [];
  let commandLines: 1 | 2 = 2;
  let orbit = { x: 0, y: 0 };
  const badgeOf = (x: number, y: number, r: number): Point => ({ x, y: y - r - 20 });

  const centerY = Math.round(top + room * 0.44);
  const only = field[0];
  const fieldX = Math.round(clamp(W * 0.15, 150, 330));
  if (only) {
    const r = Math.round(clamp(room * 0.13, 36, 58));
    // The host's label under it, its name, a command of two lines and its role, ends inside the map:
    // on a short map the host alone stands higher, never so high that its badge leaves the map.
    const y = Math.round(Math.max(top + r + 8, Math.min(centerY, H - r - SINGLE_LABEL)));
    // Where even that leaves too little room, the command keeps to one line.
    if (y + r + SINGLE_LABEL > H) commandLines = 1;
    hosts.set(only.id, { host: only, x: fieldX, y, r, badge: badgeOf(fieldX, y, r), roleWidth: null });
  }
  const fieldHeadX = fieldX;

  let junction: Junction;
  const firstDefense = defense[0];
  if (firstDefense) {
    fitColumn(defense.length, centerY, SINGLE_DEFENSE_PITCH, SINGLE_DEFENSE_PITCH, SINGLE_DEFENSE_TOP, H - bottom - SINGLE_DEFENSE_BELOW).ys.forEach((y, index) => {
      const host = defense[index];
      if (host) hosts.set(host.id, { host, x: jx, y: Math.round(y), r: 34, badge: badgeOf(jx, Math.round(y), 34), roleWidth: null });
    });
    const node = hosts.get(firstDefense.id);
    junction = { x: jx, y: node ? node.y : centerY, r: node ? node.r : 4, hostId: firstDefense.id };
  } else {
    junction = { x: jx, y: centerY, r: 4, hostId: null };
  }

  const detectorGap = clamp(room * 0.46, ENGINE_PITCH, 280);
  const detectorRadius = engineRadius(H);
  const detectors: DetectorNode[] = [];
  fitColumn(network.detectors.length, centerY, detectorGap, ENGINE_PITCH, HEADS_BOTTOM + 6 + detectorRadius, H - bottom - ENGINE_BELOW).ys.forEach((y, index) => {
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
  const firstDetectorLeft = detectors[0] ? detectors[0].x - detectors[0].r : railX;

  // Every host's sensors are placed, the defense's own too: a defense host's sensors sit small beside it.
  for (const host of [...field, ...defense]) {
    const node = hosts.get(host.id);
    const own = network.sensors.filter((sensor) => sensor.host === host.id);
    if (!node || own.length === 0) continue;
    if (host.kind !== "defense") {
      // Sensors sit on an orbit that is wide when there is room, and flattened when the map is short.
      orbit = { x: Math.round(clamp(W * 0.15, 170, 300)), y: 0 };
      orbit.y = Math.round(Math.min(orbit.x, (room * 0.34) / 0.56));
      const span = own.length > 1 ? 68 : 0;
      // Three or four sensors stand far enough apart that each one's name and count clear its neighbour's dot.
      const reach = Math.min(orbit.y * 0.95, Math.max(orbit.y * Math.sin((34 * Math.PI) / 180), (SENSOR_ORBIT_STEP * (own.length - 1)) / 2));
      own.forEach((sensor, index) => {
        const degrees =
          own.length > 2 ? (Math.asin((-reach + (2 * reach * index) / (own.length - 1)) / orbit.y) * 180) / Math.PI : own.length > 1 ? -span / 2 + (span * index) / (own.length - 1) : 0;
        const angle = (degrees * Math.PI) / 180;
        const x = Math.round(node.x + orbit.x * Math.cos(angle));
        const y = Math.round(node.y + orbit.y * Math.sin(angle));
        // Its name, beside it above or under its line, stops short of the rule engines and of a defense host level with it.
        const band: Box = degrees < 0 ? [x, y - 48, W, y - 4] : [x, y + 4, W, y + 48];
        const level = [...hosts.values()].filter((other) => other.host.kind === "defense" && overlap(band, [other.x - other.r, other.y - other.r - 4, other.x + other.r, other.y + SINGLE_DEFENSE_BELOW]) > 0);
        const stop = Math.min(firstDetectorLeft, ...level.map((other) => other.x - other.r));
        const cut = clamp(stop - 12 - (x + 18 + 10) - 20, 60, SENSOR_NAME_LARGE);
        sensors.push({ sensor, x, y, r: 18, small: false, side: 1, above: degrees < 0, inline: false, cut, named: true });
      });
      continue;
    }
    // A defense host's sensors sit beside it, where their names cover the least:
    // other hosts and their names, the links, the lines to the rule engines, and the sensors placed before them.
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
      // The host's own sensors are drawn large, their names and counts beside them; a defense host's small.
      boxes.push(placed.small ? smallWords(placed) : [placed.x - placed.r, placed.y - placed.r - 22, placed.x + placed.r + 14 + Math.min(placed.cut, textWidth(placed.sensor.name, 15.5)), placed.y + placed.r + 22]);
    }
    const label = maxOf(own.map(smallName)) + 16 + (own.length > 1 ? STACK_COUNT : 0);
    // Room for each name and, while a step runs, a lone sensor's count of events, above its name when it stands above its host.
    const tall = stackTall(own.length);
    const inline = own.length > 1;
    let best: { score: number; x: number; y: number; side: 1 | -1 } | null = null;
    for (const [degrees, penalty] of [[-90, 0], [-40, 2], [-140, 2], [0, 4], [180, 4], [40, 6], [140, 6]] as const) {
      const angle = (degrees * Math.PI) / 180;
      const x = node.x + Math.cos(angle) * (node.r + 20);
      const y = node.y + Math.sin(angle) * (node.r + 20);
      for (const side of [1, -1] as const) {
        const box = sensorBox(x, y, side, label, tall, y < node.y);
        let score: number = penalty;
        for (const other of boxes) score += overlap(box, other) / 20;
        for (const p of points) if (p.x > box[0] - 6 && p.x < box[2] + 6 && p.y > box[1] - 6 && p.y < box[3] + 6) score += 3;
        if (box[0] < 8 || box[2] > W - 8 || box[1] < top - 10) score += 200;
        if (!best || score < best.score) best = { score, x, y, side };
      }
    }
    if (!best) continue;
    const place = best;
    // Several sensors of one host stand in a stack that grows away from it.
    const away = place.y < node.y ? -1 : 1;
    own.forEach((sensor, index) => {
      sensors.push({ sensor, x: Math.round(place.x), y: Math.round(place.y + away * index * SENSOR_STACK), r: 7, small: true, side: place.side, above: place.y < node.y, inline, cut: SENSOR_NAME_MOST, named: true });
    });
  }

  // A defense host's badge stands above it, or beside it where its sensors stand above it: it covers no sensor's words, no other host or its name, and no rule engine.
  const sensorWordBoxes = sensors.map((item): Box => (item.small ? smallWords(item) : [item.x - item.r, item.y - item.r - 22, item.x + item.r + 14 + Math.min(item.cut, textWidth(item.sensor.name, 15.5)), item.y + item.r + 22]));
  const engineBoxes = detectors.map((item): Box => [item.x - item.r - 8, item.y - item.r - 8, W, item.y + ENGINE_BELOW]);
  for (const node of hosts.values()) {
    if (node.host.kind !== "defense") continue;
    const others = [...hosts.values()].filter((other) => other !== node).flatMap((other): Box[] => {
      const words = Math.max(textWidth(other.host.name, 13), Math.min(200, textWidth(other.host.role)));
      return [circleBox(other, 4), [other.x - words / 2, other.y + other.r + 4, other.x + words / 2, other.y + other.r + 46]];
    });
    const taken = [...sensorWordBoxes, ...others, ...engineBoxes];
    const side = BADGE.width / 2 + node.r + 6;
    const candidates: [Point, number][] = [
      [node.badge, 0],
      // On the top of its own ring, under its sensors: plainly its own.
      [{ x: node.x, y: node.y - node.r + 12 }, 2],
      [{ x: node.x - side, y: node.y + BADGE.height / 2 }, 3],
      [{ x: node.x + side, y: node.y + BADGE.height / 2 }, 4],
      [{ x: node.x - side, y: node.y - node.r * 0.4 }, 5],
      [{ x: node.x + side, y: node.y - node.r * 0.4 }, 6],
    ];
    let best: { score: number; anchor: Point } | null = null;
    for (const [anchor, penalty] of candidates) {
      const box = badgeBox(anchor);
      let score = penalty + (box[0] < 4 || box[2] > W - 4 || box[1] < 2 || box[3] > H - 2 ? 10_000 : 0);
      for (const other of taken) score += overlap(box, other);
      if (!best || score < best.score) best = { score, anchor };
    }
    if (best) node.badge = best.anchor;
  }

  const hostToSensor = new Map<string, Curve>();
  const sensorToJunction = new Map<string, Curve>();
  for (const node of sensors) {
    const host = hosts.get(node.sensor.host);
    if (!host) continue;
    hostToSensor.set(node.sensor.id, line(edgeToward(host, node), node));
    // A sensor of the host where the lines join: its events go the short way, on to the rule engines.
    sensorToJunction.set(node.sensor.id, node.sensor.host === junction.hostId ? bend(node, junctionOut, 0.5) : bend(node, junction, 0.5));
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
    links.push({ link, from, to, curve: line(edgeToward(from, to, 0), edgeToward(to, from, 0)), label: best.point, told: true, zone: null });
  }

  // The silence is told in the field's corridor, left of every defense host and its sensors.
  const inField = (id: string): boolean => hosts.get(id)?.host.kind !== "defense";
  const sensorRight = Math.max(0, maxOf(sensors.filter((node) => inField(node.sensor.host)).map((node) => node.x + node.r)), maxOf([...hosts.values()].filter((node) => inField(node.host.id)).map((node) => node.x + node.r)));
  const firstDetector = detectors[0];
  // Beside defense hosts the corridor is no longer empty: the smaller words are placed by their box, near the host.
  const silenceAt = new Map<string, Point>();
  // A large sensor's words as the map draws them: its name, cut where the layout says, beside it and its count above or under the name.
  const bigSensors = sensors.filter((item) => !item.small).map((item): Box => [item.x - item.r, item.y - item.r - 20, item.x + item.r + 14 + Math.min(item.cut, textWidth(item.sensor.name, 15.5)), item.y + item.r + 20]);
  if (defense.length > 0) {
    const engines = detectors.map((item): Box => [item.x - item.r - 8, item.y - item.r - 8, W, item.y + ENGINE_BELOW]);
    // Every host a step may run on, the defense hosts too, has its place for the words, clear of its own badge.
    for (const node of hosts.values()) {
      silenceAt.set(node.host.id, placeSilence(node, [...taken, ...engines, badgeBox(node.badge), ...bigSensors], [node.x - 170, node.y + node.r + 10, node.x + 170, node.y + node.r + 72], W, H).point);
    }
  }
  // The corridor's words stand level with the host, or above or under the host's sensors' words when a long name reaches into the corridor.
  // A large sensor's words: its name and count, above its line when it stands above its host, under it otherwise.
  const sensorWords = sensors
    .filter((item) => !item.small)
    .map((item): Box => {
      const right = item.x + item.r + 24 + Math.min(item.cut, textWidth(item.sensor.name, 15.5));
      return item.above ? [item.x - item.r, item.y - 48, right, item.y - 4] : [item.x - item.r, item.y + 4, right, item.y + 48];
    });
  const corridorX = (sensorRight + junction.x) / 2;
  const half = { x: CORRIDOR_WORDS.width / 2, y: CORRIDOR_WORDS.height / 2 };
  const corridor = (y: number): Box => [corridorX - half.x, y - half.y, corridorX + half.x, y + half.y];
  const clear = (y: number): boolean => sensorWords.every((box) => overlap(corridor(y), box) === 0);
  const reaching = sensorWords.filter((box) => overlap(corridor(centerY), box) > 0);
  const corridorY = clear(centerY)
    ? centerY
    : ([Math.min(...reaching.map((box) => box[1])) - half.y - 4, Math.max(...reaching.map((box) => box[3])) + half.y + 4].find((y) => y - half.y >= HEADS_BOTTOM && y + half.y <= H && clear(y)) ?? centerY);
  return {
    width: W,
    height: H,
    least,
    single: true,
    commandLines,
    centerY,
    hosts: [...hosts.values()],
    sensors,
    detectors,
    links,
    zones: [],
    defenseSide: null,
    junction,
    hostToSensor,
    sensorToJunction,
    junctionToDetector,
    orbit,
    fieldHeadX,
    detectorsHeadX: firstDetector ? firstDetector.x - firstDetector.r : railX,
    silence: { x: corridorX, y: corridorY },
    silenceAt,
  };
}

/**
 * Where the words that tell silence go for one host: under its name, above
 * it, or beside it, wherever their box covers the least of `taken` (hosts,
 * names, sensors, badges, link labels and rule engines) and stays on the map.
 * `label` is the box of the host's own name and role. Each point of `lines`
 * (the host's own links) under the words costs a little, as standing further off does.
 */
function placeSilence(node: HostNode, taken: readonly Box[], label: Box, W: number, H: number, lines: readonly Point[] = []): { point: Point; covers: number } {
  const { width: w, height: h } = SILENCE_WORDS;
  const gap = 8;
  // First under the host's name, then above it, then beside it; then anywhere on the map, on a grid, nearest first.
  const aboveTop = Math.min(node.y - node.r, node.badge.y - BADGE.height);
  const candidates: Point[] = [
    { x: node.x, y: label[3] + gap + h / 2 },
    { x: node.x, y: aboveTop - gap - h / 2 },
    { x: node.x + node.r + 16 + w / 2, y: node.y },
    { x: node.x - node.r - 16 - w / 2, y: node.y },
  ];
  for (let y = HEADS_BOTTOM + h / 2; y <= H - 4 - h / 2; y += 12) for (let x = 4 + w / 2; x <= W - 4 - w / 2; x += 16) candidates.push({ x, y });
  let best: { score: number; covers: number; point: Point } | null = null;
  for (const [index, point] of candidates.entries()) {
    const box: Box = [point.x - w / 2, point.y - h / 2, point.x + w / 2, point.y + h / 2];
    // Covering anything costs far more than standing further off; the four places nearest the host come first.
    const off = box[0] < 4 || box[2] > W - 4 || box[1] < HEADS_BOTTOM || box[3] > H - 4;
    let score = (index < 4 ? index : 4 + Math.hypot(point.x - node.x, point.y - node.y) / 20) + (off ? 100_000 : 0);
    let covers = 0;
    for (const other of taken) {
      if (best && score >= best.score) break;
      const area = overlap(box, other);
      covers += area;
      score += area * 10;
    }
    for (const other of lines) {
      if (best && score >= best.score) break;
      if (inBox(other, box)) score += 1;
    }
    if (!best || score < best.score) best = { score, covers, point };
  }
  return best ? { point: best.point, covers: best.covers } : { point: candidates[0] ?? node, covers: 0 };
}

// ---------- a network of several hosts ----------

/** Radius of a host on a network of several hosts. */
const HOST_R = 28;
/**
 * A badge's size, for its longest word ("goal reached"), and the room it takes
 * above a host: its foot stands 7 px clear of the ring a lit host wears 14 px
 * out from its edge.
 */
const BADGE = { width: 124, height: 22, above: 21, ring: 15 };
/** The bottom of the column heads on a network: each head is one line. */
const HEADS_MANY = 30;
/** The clear air between the heads and the badge of a host in the top row. */
const BADGE_CLEAR = 12;
/** Pixels between the bottom of a host and the top of its name, as the map draws it. */
const NAME_GAP = 8;
/** The most pixels between two rows of hosts: a short network stands together in the middle. */
const MOST_PITCH = 190;

/** Where a sensor may stand around its host, in degrees clockwise from the right, with the cost of each, least first. */
const FIELD_SENSOR_PLACES = [[0, 0], [-35, 1], [35, 2], [180, 2], [-145, 3], [145, 4], [-90, 6], [90, 12]] as const;
/** Pixels from a defense host's edge to its sensors' dots on a network: its badge may sit on the top of its ring, under them. */
const DEFENSE_SENSOR_OFF = 26;
const DEFENSE_SENSOR_PLACES = [[-90, 0], [-40, 2], [-140, 2], [0, 4], [180, 4], [40, 6], [140, 6], [90, 12]] as const;

/** A role as the map wraps it on a network: words in brackets at its end start a line of their own, "stand-in internet" then "(file server and upload drop)". */
export function roleParts(role: string): string[] {
  const at = role.search(/\s\(/);
  return at > 0 && role.endsWith(")") ? [role.slice(0, at), role.slice(at + 1)] : [role];
}

/** The box of a host's name and role under it, as the map draws them. */
function labelBox(node: HostNode): Box {
  const roleWidth = node.roleWidth ?? 150;
  const role = textWidth(node.host.role, 11.5);
  // A role with words in brackets breaks before them, so they read as one note: one more line.
  const lines = clamp(
    roleParts(node.host.role).reduce((sum, part) => sum + Math.ceil(textWidth(part, 11.5) / roleWidth), 0),
    1,
    3,
  );
  // The map cuts a name and a role at the role's width, and a role after its third line.
  const wide = Math.max(Math.min(textWidth(node.host.name, 13), roleWidth), Math.min(role, roleWidth)) + 14;
  const top = node.y + node.r + NAME_GAP;
  // A host whose sensor the head names has its count of events on a line of its own.
  const count = COUNTED.has(node.host) ? 15 : 0;
  // A host an alert is raised on has the alert's chip and its time on a line under them.
  const alert = ALERTED.has(node.host) ? ALERT_LINE : 0;
  const chip = alert > 0 ? Math.max(wide, ALERT_WORDS) : wide;
  return [node.x - chip / 2, top, node.x + chip / 2, top + 19 + 15 * lines + count + alert];
}

/**
 * The box of the names of the sensors that stand at `x`, `y` (the first of
 * them) with their names to one side: `tall` pixels of names and an event
 * count, which grow upward for sensors above their host and downward else.
 */
function sensorBox(x: number, y: number, side: 1 | -1, label: number, tall: number, above: boolean): Box {
  const [low, high] = side > 0 ? [x - 10, x + label] : [x - label, x + 10];
  return above ? [low, y + 10 - tall, high, y + 10] : [low, y - 10, high, y - 10 + tall];
}

function fieldNodesOf(hosts: Map<string, HostNode>): HostNode[] {
  return [...hosts.values()].filter((node) => node.host.kind !== "defense");
}

function circleBox(node: Point & { r: number }, pad: number): Box {
  return [node.x - node.r - pad, node.y - node.r - pad, node.x + node.r + pad, node.y + node.r + pad];
}

function badgeBox(anchor: Point): Box {
  return [anchor.x - BADGE.width / 2, anchor.y - BADGE.height, anchor.x + BADGE.width / 2, anchor.y];
}

/** The box a curve stays inside, `pad` pixels wider each way: a Bezier curve never leaves the box of its control points. */
function curveBounds(curve: Curve, pad: number): Box {
  const xs = curve.map((point) => point.x);
  const ys = curve.map((point) => point.y);
  return [Math.min(...xs) - pad, Math.min(...ys) - pad, Math.max(...xs) + pad, Math.max(...ys) + pad];
}

/** Whether `point` is nearer than `reach` to the centre `at`: the same as comparing their distance, without a square root. */
function within(point: Point, at: Point, reach: number): boolean {
  const dx = point.x - at.x;
  const dy = point.y - at.y;
  return dx * dx + dy * dy < reach * reach;
}

/** Whether two boxes share any point, edges included. */
const meetsBox = (a: Box, b: Box): boolean => a[0] <= b[2] && b[0] <= a[2] && a[1] <= b[3] && b[1] <= a[3];

const inBox = (point: Point, box: Box, pad = 0): boolean => point.x > box[0] - pad && point.x < box[2] + pad && point.y > box[1] - pad && point.y < box[3] + pad;

function samples(curve: Curve, count = 24): Point[] {
  return Array.from({ length: count - 1 }, (_, index) => pointOn(curve, (index + 1) / count));
}

/** The links to draw on the field: one per pair of hosts, both directions' labels together. */
function drawnLinks(network: Network, skip: (link: Link) => boolean): Link[] {
  const pairs = new Map<string, Link>();
  for (const link of network.links ?? []) {
    if (link.from === link.to || skip(link)) continue;
    const key = [link.from, link.to].sort().join("\n");
    const known = pairs.get(key);
    if (!known) {
      pairs.set(key, { ...link });
      continue;
    }
    const words = known.label ? known.label.split(", ") : [];
    for (const word of (link.label ?? "").split(", ")) if (word && !words.includes(word)) words.push(word);
    known.label = words.join(", ");
  }
  return [...pairs.values()];
}

/**
 * The field's columns, from left to right. Where the attacker starts is the
 * first column, with every other host that reaches the network and that no
 * host reaches, such as a client; each host stands one column after the
 * nearest host linked to it. Hosts no link reaches stand in one more column.
 */
function columnsOf(field: readonly Host[], links: readonly Link[]): string[][] {
  const ids = new Set(field.map((host) => host.id));
  const neighbours = new Map<string, string[]>(field.map((host) => [host.id, []]));
  const into = new Map<string, number>();
  const out = new Map<string, number>();
  for (const link of links) {
    if (!ids.has(link.from) || !ids.has(link.to)) continue;
    neighbours.get(link.from)?.push(link.to);
    neighbours.get(link.to)?.push(link.from);
    out.set(link.from, (out.get(link.from) ?? 0) + 1);
    into.set(link.to, (into.get(link.to) ?? 0) + 1);
  }
  const attackers = field.filter((host) => host.kind === "attacker");
  const sources = field.filter((host) => host.kind !== "attacker" && (out.get(host.id) ?? 0) > 0 && (into.get(host.id) ?? 0) === 0);
  const starts = [...attackers, ...sources];
  const first = field[0];
  if (starts.length === 0 && first) starts.push(first);
  const depth = new Map<string, number>();
  const queue: string[] = [];
  for (const host of starts) {
    depth.set(host.id, 0);
    queue.push(host.id);
  }
  for (let index = 0; index < queue.length; index += 1) {
    const current = queue[index] ?? "";
    const next = (depth.get(current) ?? 0) + 1;
    for (const other of neighbours.get(current) ?? []) {
      if (depth.has(other)) continue;
      depth.set(other, next);
      queue.push(other);
    }
  }
  const deepest = Math.max(0, maxOf(depth.values()));
  const columns: string[][] = Array.from({ length: deepest + 1 }, () => []);
  for (const id of queue) columns[depth.get(id) ?? 0]?.push(id);
  const lone = field.filter((host) => !depth.has(host.id)).map((host) => host.id);
  if (lone.length > 0) columns.push(lone);
  orderColumns(columns, neighbours);
  // A column of more hosts than stand well one above another stands as several columns side by side, in its order.
  return columns.filter((column) => column.length > 0).flatMap((column) => Array.from({ length: Math.ceil(column.length / ROWS_MOST) }, (_, index) => column.slice(index * ROWS_MOST, (index + 1) * ROWS_MOST)));
}

/** Orders the hosts of each column by where their neighbours in the next columns stand, so fewer links cross. */
function orderColumns(columns: string[][], neighbours: Map<string, string[]>): void {
  const columnOf = new Map<string, number>();
  columns.forEach((column, index) => column.forEach((id) => columnOf.set(id, index)));
  const placeOf = () => {
    const place = new Map<string, number>();
    for (const column of columns) column.forEach((id, index) => place.set(id, (index + 0.5) / column.length));
    return place;
  };
  for (let pass = 0; pass < 6; pass += 1) {
    const forward = pass % 2 === 0;
    const order = columns.map((_, index) => index);
    if (!forward) order.reverse();
    for (const index of order.slice(1)) {
      const column = columns[index];
      if (!column || column.length < 2) continue;
      const place = placeOf();
      const side = forward ? index - 1 : index + 1;
      const centre = (id: string): number => {
        const near = (neighbours.get(id) ?? []).filter((other) => columnOf.get(other) === side).map((other) => place.get(other) ?? 0.5);
        return near.length > 0 ? near.reduce((sum, value) => sum + value, 0) / near.length : (place.get(id) ?? 0.5);
      };
      const keys = new Map(column.map((id) => [id, centre(id)]));
      column.sort((a, b) => (keys.get(a) ?? 0) - (keys.get(b) ?? 0) || (place.get(a) ?? 0) - (place.get(b) ?? 0));
    }
  }
}

/**
 * A link's curve: straight, or bowed to one side by `offset` pixels, or, with
 * `level`, leaving each host level and turning between them, so a steep link
 * never runs down through its own host's name; between two hosts of one
 * column, a bracket on one side that leaves each host at `slant` radians from
 * level toward the other.
 */
function linkCurve(from: HostNode, to: HostNode, offset: number, slant = Math.PI / 4, level = false): Curve {
  if (level && Math.abs(from.x - to.x) >= 1) {
    const way = to.x > from.x ? 1 : -1;
    return bend({ x: from.x + way * from.r, y: from.y }, { x: to.x - way * to.r, y: to.y }, 0.5, offset);
  }
  if (Math.abs(from.x - to.x) < 1) {
    const side = offset >= 0 ? 1 : -1;
    const reach = Math.abs(offset);
    const down = to.y > from.y ? 1 : -1;
    const a = { x: from.x + side * from.r * Math.cos(slant), y: from.y + down * from.r * Math.sin(slant) };
    const b = { x: to.x + side * to.r * Math.cos(slant), y: to.y - down * to.r * Math.sin(slant) };
    return [a, { x: a.x + side * reach, y: a.y + down * reach * 0.6 }, { x: b.x + side * reach, y: b.y - down * reach * 0.6 }, b];
  }
  const dx = to.x - from.x;
  const dy = to.y - from.y;
  const length = Math.hypot(dx, dy) || 1;
  const nx = -dy / length;
  const ny = dx / length;
  const c1 = { x: from.x + dx / 3 + nx * offset, y: from.y + dy / 3 + ny * offset };
  const c2 = { x: from.x + (2 * dx) / 3 + nx * offset, y: from.y + (2 * dy) / 3 + ny * offset };
  return [edgeToward(from, c1, 0), c1, c2, edgeToward(to, c2, 0)];
}

/**
 * Where the columns of a network of several hosts stand at width `W`: the
 * rule engines' rail, the defense, the field from `left` to `right`, the
 * first column at `start` and `step` pixels between columns, and the width a
 * host's role wraps at.
 */
function columnFrame(W: number, columns: readonly string[][], field: readonly Host[], reserve: number, engineWords: number) {
  // The rule engines stand at the right edge, as wide as their words: the rest of the stage is the network's.
  const railX = Math.round(W - ENGINE_EDGE - engineWords - ENGINE_GAP - ENGINE_R);
  // The defense stands just left of the rule engines, so the names of the last column's sensors clear its name.
  const jx = Math.round(railX - clamp(W * 0.07, 96, 140));
  const left = Math.round(Math.max(96, W * 0.06));
  // The last column stands at least `reserve` pixels from the defense host, so that its sensors' words clear it,
  // and with no defense host, far enough from the point where the sensors' lines join for them to gather.
  const right = Math.round(jx - Math.max(reserve, clamp(W * 0.1, 110, 190)));
  const roleWidth = Math.round(clamp((columns.length > 1 ? (right - left) / (columns.length - 1) : right - left) - 28, ROLE_LEAST, 230));
  // The first column stands far enough in for the widest name or role in it, each cut at the role's width.
  const firstWide = maxOf(
    (columns[0] ?? []).map((id) => {
      const host = field.find((item) => item.id === id);
      return host ? Math.max(Math.min(roleWidth, textWidth(host.name, 13)), Math.min(roleWidth, textWidth(host.role))) + 14 : 0;
    }),
    0,
  );
  // Its words, and the zone round them, keep to the page's side margin, as the heads and the log do.
  const start = Math.max(left, Math.round(firstWide / 2 + ENGINE_EDGE + ZONE_PAD));
  const step = columns.length > 1 ? (right - start) / (columns.length - 1) : 0;
  return { railX, jx, left, right, roleWidth, start, step };
}

/**
 * Pixels from the map's right edge to the rule engines' words on a network (the
 * page's own side margin, which the buttons and the log hold), from an engine's
 * edge to its words, and the radius the frame counts for an engine.
 */
export const ENGINE_EDGE = 30;
const ENGINE_GAP = 16;
const ENGINE_R = 26;

/**
 * How wide the rule engines' words are on a network: as wide as their matches
 * need, a chip and a title on two lines, and no more. One engine is narrow;
 * several, one under another, have a little more, as their matches share the room.
 */
function engineWordsOf(network: Network, W: number): number {
  return Math.round(clamp(W * (network.detectors.length > 1 ? 0.23 : 0.205), 270, 400));
}

/**
 * The least pixels between two columns for a column to stand as two, its
 * hosts taking turns between them: the badge of one clears the name of the
 * host above it, which stands in the other.
 */
const SPLIT_STEP = 150;
/** The grid a split column's order is chosen on: pixels between two columns and between two rows, near the stage's own. */
const UNIT_STEP = 220;
const UNIT_PITCH = 170;

/**
 * A place for hosts on the field: the hosts of a column, top to bottom, or one
 * of the two places a column stands in when it is split, and where each of
 * its hosts stands in the column's order (0 at the top), of `count`. A split
 * column's hosts stand half as far apart, one above another in turn.
 */
interface Slot {
  ids: string[];
  rows: number[];
  count: number;
  half: boolean;
  /** True for the left place of a split column: the next slot is the other. */
  first?: boolean;
}

/** A column split in two places, side by side: its hosts take turns, the ones in place `flip` of every two going left. */
function splitSlot(slot: Slot, flip: number): [Slot, Slot] {
  const left: Slot = { ids: [], rows: [], count: slot.count, half: true, first: true };
  const other: Slot = { ids: [], rows: [], count: slot.count, half: true };
  slot.ids.forEach((id, row) => {
    const place = row % 2 === flip ? left : other;
    place.ids.push(id);
    place.rows.push(row);
  });
  return [left, other];
}

/** The width of a network's name as the map tells it once: 10.5 px capitals, spaced. */
export function zoneWidth(label: string): number {
  return label.length * 10.5 * 0.78 + 12;
}

/**
 * A link label shared by several links, as the map names its zone, short so it fits in the zone's corner: "edge" is
 * the edge network, "inside, mgmt" is "inside + mgmt", the inside and mgmt networks.
 */
export function zoneName(label: string): string {
  const words = label.split(",").map((word) => word.trim()).filter(Boolean);
  return words.length > 0 ? words.join(" + ") : label;
}

/** A zone's name in a sentence: "the edge network", "the inside and mgmt networks". */
export function zoneSaid(label: string): string {
  const words = label.split(",").map((word) => word.trim()).filter(Boolean);
  const list = words.length > 1 ? `${words.slice(0, -1).join(", ")} and ${words[words.length - 1] ?? ""}` : (words[0] ?? label);
  return `the ${list} ${words.length > 1 ? "networks" : "network"}`;
}


/** Whether the segments a-b and c-d cross, not counting a shared end. */
function crosses(a: Point, b: Point, c: Point, d: Point): boolean {
  const side = (p: Point, q: Point, s: Point): number => (q.x - p.x) * (s.y - p.y) - (q.y - p.y) * (s.x - p.x);
  const d1 = side(c, d, a);
  const d2 = side(c, d, b);
  const d3 = side(a, b, c);
  const d4 = side(a, b, d);
  return ((d1 > 0 && d2 < 0) || (d1 < 0 && d2 > 0)) && ((d3 > 0 && d4 < 0) || (d3 < 0 && d4 > 0));
}

/** The distance from `p` to the segment a-b. */
function toSegment(p: Point, a: Point, b: Point): number {
  const dx = b.x - a.x;
  const dy = b.y - a.y;
  const length = dx * dx + dy * dy || 1;
  const u = clamp(((p.x - a.x) * dx + (p.y - a.y) * dy) / length, 0, 1);
  return Math.hypot(p.x - (a.x + dx * u), p.y - (a.y + dy * u));
}

/** Every order of `items`: a split column holds four hosts at most, so at most 24. */
function orders<T>(items: readonly T[]): T[][] {
  if (items.length <= 1) return [[...items]];
  return items.flatMap((item, index) => orders([...items.slice(0, index), ...items.slice(index + 1)]).map((rest) => [item, ...rest]));
}

/**
 * How badly straight links between hosts at `at` read: each crossing of two
 * links, and each link that runs close by a host it does not join, costs; a
 * long link costs a little, so linked hosts stand near each other.
 */
function tangle(links: readonly Link[], at: Map<string, Point>): number {
  const lines = links.flatMap((link) => {
    const a = at.get(link.from);
    const b = at.get(link.to);
    return a && b ? [{ link, a, b }] : [];
  });
  let score = 0;
  lines.forEach((one, index) => {
    for (const other of lines.slice(index + 1)) {
      const shared = [one.link.from, one.link.to].some((id) => id === other.link.from || id === other.link.to);
      if (!shared && crosses(one.a, one.b, other.a, other.b)) score += 10;
    }
    for (const [id, point] of at) if (id !== one.link.from && id !== one.link.to && toSegment(point, one.a, one.b) < HOST_R + 14) score += 6;
    score += Math.hypot(one.b.x - one.a.x, one.b.y - one.a.y) / 1000;
  });
  return score;
}

/** The most hosts a column holds when a network's columns fold into bands: past it, the map keeps the width its columns need. */
const FOLD_ROWS_MOST = 8;
/** The least width a name or role is cut at where two neighbouring columns share little room. */
const ROLE_SHORTEST = 60;
/** Pixels a stack of sensors' words keeps from the next column's host: its circle, and the half of a short name under it. */
const STACK_CLEAR = HOST_R + 28;

/**
 * The least pixels between two columns of hosts. A host with a stack of
 * sensors has their names and counts beside it, as wide as the widest name,
 * cut at `SENSOR_NAME_MOST`, and its count: the next column stands clear of them.
 */
function columnLeast(network: Network, field: readonly Host[], lone = false): number {
  let least = COLUMN_LEAST;
  for (const host of field) {
    const own = network.sensors.filter((sensor) => sensor.host === host.id);
    if (own.length === 0 || (own.length === 1 && !lone)) continue;
    least = Math.max(least, Math.ceil(HOST_R + 18 + maxOf(own.map(smallName)) + 18 + (own.length > 1 ? STACK_COUNT + STACK_CLEAR : HOST_R + 10)));
  }
  return least;
}

/**
 * The least pixels between the last column and the defense host: a sensor's
 * words beside its host, cut at `SENSOR_NAME_MOST`, with a stack's counts,
 * then the defense host's circle.
 */
function defenseReserve(network: Network, field: readonly Host[]): number {
  let reserve = 0;
  for (const host of field) {
    const own = network.sensors.filter((sensor) => sensor.host === host.id);
    if (own.length === 0) continue;
    reserve = Math.max(reserve, Math.ceil(HOST_R + 18 + maxOf(own.map(smallName)) + 18 + (own.length > 1 ? STACK_COUNT : 0) + HOST_R + 8));
  }
  return reserve;
}

/**
 * `columns` folded into `bands` bands of rows, one under another. The bands
 * run left to right, then right to left, and so on, so the last column of one
 * band stands over the last of the next and a chain reads on without a jump.
 * Each column of the result holds its bands' hosts in turn, centred in each
 * band, with "" for an empty place where a band's column holds fewer hosts
 * than the band's tallest.
 */
function fold(columns: readonly string[][], bands: number): string[][] {
  const per = Math.ceil(columns.length / bands);
  const folded: string[][] = Array.from({ length: per }, () => []);
  for (let band = 0; band * per < columns.length; band += 1) {
    const part = columns.slice(band * per, (band + 1) * per);
    const tall = Math.max(1, maxOf(part.map((column) => column.length)));
    folded.forEach((target, place) => {
      const column = part[band % 2 === 0 ? place : per - 1 - place] ?? [];
      const before = Math.floor((tall - column.length) / 2);
      target.push(...Array.from({ length: before }, () => ""), ...column, ...Array.from({ length: tall - column.length - before }, () => ""));
    });
  }
  return folded;
}

/** More pixels between rows to try, in turn, when a network's words crowd each other at the least room. */
const MORE_ROOM = [0, 30, 60, 90, 130, 180] as const;
/**
 * Fewer pixels between rows to try, closest first, for a short room: a lower
 * host's badge then stands beside it and needs no room above it, and the rows
 * are measured host by host.
 */
const COMPACT = [-(BADGE.height + BADGE.above - 8), -24, -12] as const;
/**
 * Lays out a field of several hosts. When its words crowd each other at the
 * least height the network needs, the rows stand further apart, as long as
 * more room helps, and the map grows taller. That choice rests on the network
 * and on the width, taken in steps of `ROOM_STEP` pixels, alone: the least
 * height is the same whatever height the map was given. What was laid out is
 * kept: a change of height alone lays the network out at most once, and a
 * change of width, which comes in steps of `WIDTH_STEP`, once, but for the
 * first width of each `ROOM_STEP`.
 */
function layoutMany(network: Network, width: number, height: number, squeeze: boolean): NetworkLayout {
  const kept = keptOf(network);
  let tight = kept.tight.get(width);
  if (!tight) {
    const extra = roomFor(network, Math.floor(width / ROOM_STEP) * ROOM_STEP, kept);
    tight = withSilenceRoom(network, width, extra, kept);
    keep(kept.tight, width, tight);
  }
  // The stage is the map's to fill, and no taller: when more room between rows would make the map taller than the
  // height it is given, the rows stand closer, as close as fits, and a line may graze a name rather than the page scroll.
  const fitAt = (extra: number) => fitOf(network, width, extra, kept);
  // A box of no height gets the network at its least height: the stage claims that height, and the map is drawn at it.
  let squeezed = false;
  if (height <= 0) {
    if (squeeze) {
      tight = leastFitOf(network, width, kept);
      squeezed = true;
    } else if (tight.extra > 0) tight = fitAt(0);
  } else if (tight.height > height) {
    for (const extra of [...MORE_ROOM].reverse()) {
      if (extra >= tight.extra) continue;
      const fit = fitAt(extra);
      if (fit.height <= height) {
        tight = fit;
        break;
      }
    }
    // Where no row spacing fits, the least layout does, a lower host's badge beside it; where even that does not, the map grows.
    if (squeeze && tight.height > height) {
      const close = leastFitOf(network, width, kept);
      squeezed = true;
      if (close.height <= height) tight = close;
    }
  }
  // The least height the network needs is the one with no more room between rows; a map squeezed below it tells the
  // least layout's. `leastHeights` tells both.
  const least = squeezed ? leastFitOf(network, width, kept).least : tight.extra > 0 ? fitAt(0).least : tight.least;
  // At the least height or less, the map is the one laid out with no height given; a taller one is kept for the next call.
  if (height <= tight.height) return least === tight.least ? tight : { ...tight, least };
  const last = kept.last;
  if (last && last.width === width && last.height === height) return last.layout;
  const layout = { ...placeMany(network, width, height, tight.extra, tight.words), least };
  kept.last = { width, height, layout };
  return layout;
}

/** The network laid out with no height given and `extra` more pixels between rows than the least, kept by width and room. */
function fitOf(network: Network, width: number, extra: number, kept: Kept): Placed & { extra: number; words: number } {
  const key = width * 1000 + extra + 100;
  let fit = kept.fits.get(key);
  if (!fit) {
    fit = { ...placeMany(network, width, 0, extra), extra, words: 0 };
    keep(kept.fits, key, fit);
  }
  return fit;
}

/**
 * The least layout: rows as close as the words allow, a lower host's badge
 * beside it rather than above, where that puts no more words or lines on
 * another than the rows a badge's height further apart do. Kept by width.
 */
function leastFitOf(network: Network, width: number, kept: Kept): Placed & { extra: number; words: number } {
  let fit = kept.least.get(width);
  if (!fit) {
    const plain = fitOf(network, width, 0, kept);
    const [words, lines] = [wordsCrowding(plain), linesCrowding(plain)];
    fit = plain;
    // From the closest rows up: the first that is shorter and crowds nothing more.
    for (const extra of COMPACT) {
      const close = fitOf(network, width, extra, kept);
      if (close.height < plain.height && wordsCrowding(close) <= words && linesCrowding(close) <= lines) {
        fit = close;
        break;
      }
    }
    keep(kept.least, width, fit);
  }
  return fit;
}

/**
 * The two least heights of a network's map at `width`, as the view shares its
 * room: `roomy`, at which every row keeps room above its hosts for their
 * badges, and `least`, below which something on the map would lie on
 * another. The view lets the log's lines go before the map goes below
 * `roomy`, and lets the page scroll only below `least`. One host's map has one.
 */
export function leastHeights(network: Network, width: number): { least: number; roomy: number } {
  const field = network.hosts.filter((host) => host.kind !== "defense");
  if (field.length <= 1) {
    const least = layoutNetwork(network, width, 0).least;
    return { least, roomy: least };
  }
  // Laid out once with no height given: that keeps the network's chosen room between rows, and its least layout, by width.
  const least = layoutNetwork(network, width, 0, true).least;
  const at = Math.max(LEAST_MAP_WIDTH, Math.floor(width / WIDTH_STEP) * WIDTH_STEP);
  const kept = keptOf(network);
  const tight = kept.tight.get(at);
  const roomy = tight && tight.extra <= 0 ? tight.least : fitOf(network, at, 0, kept).least;
  return { least: Math.min(least, roomy), roomy: Math.max(least, roomy) };
}

/** The step of widths a network is laid out at: 1024, 1440 and 1920 are steps of it. */
const WIDTH_STEP = 16;

/** The room kept under the bottom row for the words for silence, when they find no free place on the map for some host. */
const SILENCE_ROOM = SILENCE_WORDS.height + 16;

/** The more room between rows that a network needs at width `width`: the first that leaves its words uncrowded, or helps no more. */
function roomFor(network: Network, width: number, kept: Kept): number {
  const known = kept.room.get(width);
  if (known !== undefined) return known;
  let chosen = 0;
  let count = Number.POSITIVE_INFINITY;
  for (const extra of MORE_ROOM) {
    const tight = placeMany(network, width, 0, extra);
    const crowded = crowding(tight);
    // More room that does not help stops the search: rows further apart would only make the map taller.
    if (crowded >= count) break;
    chosen = extra;
    count = crowded;
    keep(kept.tight, width, { ...tight, extra, words: 0 });
    // Lines under labels alone count for less than one: they never make the map taller.
    if (crowded < 1) break;
  }
  keep(kept.room, width, chosen);
  return chosen;
}

/**
 * The network laid out at width `width` with `extra` more pixels between rows
 * and, when the words for silence find no free place on the map for some host,
 * room for them under the bottom row, if that helps. Only a network whose
 * words are crowded costs a second layout.
 */
function withSilenceRoom(network: Network, width: number, extra: number, kept: Kept): Placed & { extra: number; words: number } {
  const base = kept.tight.get(width);
  const laid = base && base.extra === extra && base.words === 0 ? base : { ...placeMany(network, width, 0, extra), extra, words: 0 };
  const roomier = laid.hushCovers > 0 ? placeMany(network, width, 0, extra, SILENCE_ROOM) : null;
  return roomier && roomier.hushCovers < laid.hushCovers ? { ...roomier, extra, words: SILENCE_ROOM } : laid;
}

/** Widths of one step share the room chosen between rows, so dragging a window's edge lays a network out once per width. */
const ROOM_STEP = 64;

interface Kept {
  /** The room chosen between rows, by width (a multiple of `ROOM_STEP`). */
  room: Map<number, number>;
  /** The layout with no height given, by width, with the room it was laid out with between rows and under them. */
  tight: Map<number, Placed & { extra: number; words: number }>;
  /** Layouts with less room between rows than chosen, for a map given less height than that room needs, by width and room. */
  fits: Map<number, Placed & { extra: number; words: number }>;
  /** The least layout, by width. */
  least: Map<number, Placed & { extra: number; words: number }>;
  /** The last layout taller than the least height, with the width and height it was laid out at. */
  last: { width: number; height: number; layout: Placed } | null;
}

/** What was laid out for each network, kept while the network is: a window being resized passes few widths twice. */
const keptLayouts = new WeakMap<Network, Kept>();
const KEPT_WIDTHS = 48;

function keptOf(network: Network): Kept {
  const found = keptLayouts.get(network);
  if (found) return found;
  const made: Kept = { room: new Map(), tight: new Map(), fits: new Map(), least: new Map(), last: null };
  keptLayouts.set(network, made);
  return made;
}

function keep<T>(map: Map<number, T>, width: number, value: T): void {
  if (!map.has(width) && map.size >= KEPT_WIDTHS) map.delete(map.keys().next().value ?? width);
  map.set(width, value);
}

/** How many pairs of things crowd each other on a map of several hosts: words on words or hosts, and lines through names, sensors or hosts. */
function crowding(layout: NetworkLayout): number {
  return crowdingOf(layout, true, 1);
}

/**
 * How many words, hosts and badges lie on another, by more than a corner of 8
 * by 8 pixels: the boxes of words are measured generously, wider than the
 * words are drawn, so a corner that touches is no crowding to the eye.
 */
function wordsCrowding(layout: NetworkLayout): number {
  return crowdingOf(layout, false, 64);
}

/** How many lines run through a host's name, a sensor or a host they do not join: each line and thing counted once. */
function linesCrowding(layout: NetworkLayout): number {
  const names = layout.hosts.map(labelBox);
  const dots = layout.sensors.map((node) => circleBox(node, 2));
  const hosts = layout.hosts.map((node) => circleBox(node, -4));
  let count = 0;
  const through = (curve: Curve, boxes: readonly Box[], skip: readonly Box[] = []) => {
    const points = samples(curve, 40);
    for (const box of boxes) if (!skip.includes(box) && points.some((point) => inBox(point, box))) count += 1;
  };
  for (const item of layout.links) through(item.curve, [...names, ...dots, ...hosts], [hosts[layout.hosts.indexOf(item.from)], hosts[layout.hosts.indexOf(item.to)]].filter((box): box is Box => box !== undefined));
  for (const curve of layout.sensorToJunction.values()) through(curve, names);
  return count;
}

/** The pairs that crowd each other, each sharing more than `least` square pixels; with `lines`, the lines through things too. */
function crowdingOf(layout: NetworkLayout, lines: boolean, least: number): number {
  const names = layout.hosts.map(labelBox);
  // A sensor's words, from beside its dot: the dot sits by its own host.
  const sensors = layout.sensors.map((node): Box => {
    if (node.over) return countBox(node.x, node.y, node.above, node.side);
    const wide = smallName(node.sensor) + (node.inline && node.named ? STACK_COUNT : 0);
    const [low, high] = node.side > 0 ? [node.x + node.r + 6, node.x + node.r + 6 + wide + 4] : [node.x - node.r - 10 - wide, node.x - node.r - 6];
    // In a stack its count stands on its name's line; alone, above or under its name.
    if (node.inline) return [low, node.y - 9, high, node.y + 9];
    return node.above ? [low, node.y - 25, high, node.y + 9] : [low, node.y - 9, high, node.y + 25];
  });
  // A link's label as drawn: 11 px words in a pill of 7 px padding, or a network's name told once; a label not drawn takes no room.
  const labelOf = new Map<number, Box>();
  layout.links.forEach((item, index) => {
    if (!item.told || !item.link.label) return;
    const w = item.zone === null ? textWidth(item.link.label, 11) + 16 : zoneWidth(item.zone);
    labelOf.set(index, [item.label.x - w / 2, item.label.y - 9, item.label.x + w / 2, item.label.y + 9]);
  });
  const labels = [...labelOf.values(), ...layout.zones.flatMap((zone): Box[] => (zone.label ? [[zone.label.x, zone.label.y - 8, zone.label.x + zoneWidth(zone.words), zone.label.y + 8]] : []))];
  const circles = layout.hosts.map((node) => circleBox(node, 2));
  const engines = layout.detectors.map((node): Box => [node.x - node.r, node.y - node.r, layout.width, node.y + 70]);
  const words = [...names, ...sensors, ...labels];
  const things = [...words, ...circles, ...engines];
  let count = 0;
  things.forEach((a, index) => {
    for (let other = index + 1; other < things.length; other += 1) if (overlap(a, things[other] ?? a) > least) count += 1;
  });
  layout.hosts.forEach((node, index) => {
    // A badge lies on no other host and on no word; it is placed clear of its own host's ring.
    const badge = badgeBoxOf(node);
    for (const other of things) if (other !== circles[index] && overlap(badge, other) > least) count += 1;
  });
  if (!lines) return count;
  // A line under another link's label counts for little: on a narrow screen links cross where their labels are.
  const UNDER_LABEL = 0.01;
  const dots = layout.sensors.map((node) => circleBox(node, 2));
  layout.links.forEach((item, index) => {
    for (const point of samples(item.curve, 40)) {
      for (const box of [...names, ...sensors, ...dots]) if (inBox(point, box)) count += 1;
      for (const box of labels) if (box !== labelOf.get(index) && inBox(point, box)) count += UNDER_LABEL;
      for (const node of layout.hosts) if (node !== item.from && node !== item.to && within(point, node, node.r)) count += 1;
    }
  });
  // A sensor's line passes no name, no other sensor, and not back through its own host.
  layout.sensors.forEach((node, own) => {
    const curve = layout.sensorToJunction.get(node.sensor.id);
    if (!curve) return;
    const host = layout.hosts.find((item) => item.host.id === node.sensor.host && item.host.id !== layout.junction.hostId);
    for (const point of samples(curve, 40)) {
      for (const box of names) if (inBox(point, box)) count += 1;
      for (const box of labels) if (inBox(point, box)) count += UNDER_LABEL;
      for (const [index, box] of [...sensors, ...dots].entries()) if (index % sensors.length !== own && inBox(point, box)) count += 1;
      if (host && within(point, host, host.r)) count += 1;
    }
  });
  return count;
}

/**
 * Lays out a field of several hosts: columns from the links, rows from the
 * column with the most hosts, every name and role under its host, and the
 * badge, sensors and link labels each where it covers the least. `extra`
 * pixels more stand between two rows than the least they need. The map grows
 * taller than `height` only when the rows need it.
 */
/** A layout of several hosts, and how many pixels the words for silence cover where no free place was found for them. */
type Placed = NetworkLayout & { hushCovers: number };

function placeMany(network: Network, width: number, height: number, extra: number, words = 0): Placed {
  markNamedOnce(network);
  const field = network.hosts.filter((host) => host.kind !== "defense");
  const defense = network.hosts.filter((host) => host.kind === "defense");
  const sensed = new Set(network.sensors.map((sensor) => sensor.host));
  // The lowest name keeps clear air above whatever stands under the map, the zone's foot between them.
  const bottom = 10;
  const r = HOST_R;

  // A sensed host's link to where its sensors' lines join is drawn by those lines: a second line beside them would say the same.
  // Any other link to the defense, the other way round or to another defense host, is drawn as usual.
  const joinsAt = defense[0]?.id;
  const drawn = drawnLinks(network, (link) => link.to === joinsAt && sensed.has(link.from));
  const columns = columnsOf(field, drawn);
  // Columns too many to stand side by side at this width fold into bands of rows, one under another, while a column holds few enough hosts.
  // A network whose columns still do not fit keeps the width they need: the map scrolls sideways.
  const spacing = columnLeast(network, field);
  const reserve = defense.length > 0 ? defenseReserve(network, field) : 0;
  let W = Math.max(LEAST_MAP_WIDTH, width);
  const engineWords = engineWordsOf(network, W);
  let laid = columns;
  let frame = columnFrame(W, laid, field, reserve, engineWords);
  // In bands, a row's neighbours stand close above and under too: folded columns stand far enough apart for a lone sensor's words beside its host.
  const folding = laid.length > 1 && frame.step < spacing;
  const roomy = folding ? columnLeast(network, field, true) : spacing;
  let folded = false;
  for (let bands = 2; laid.length > 1 && frame.step < roomy && bands <= columns.length; bands += 1) {
    const banded = fold(columns, bands);
    if (banded.length === laid.length) continue;
    if (maxOf(banded.map((column) => column.length)) > FOLD_ROWS_MOST) break;
    laid = banded;
    folded = true;
    frame = columnFrame(W, laid, field, reserve, engineWords);
  }
  while (laid.length > 1 && frame.step < spacing && W < 20_000) {
    W += 16;
    frame = columnFrame(W, laid, field, reserve, engineWords);
  }

  // The stage is wide and short: a column of three hosts or more stands as two, side by side, its hosts taking turns
  // between them, so it needs half the height. The tallest column goes first, and a column splits only while every
  // column still stands far enough apart for it.
  let slots: Slot[] = laid.map((ids) => ({ ids, rows: ids.map((_, index) => index), count: ids.length, half: false }));
  if (!folded) {
    // The column next to the defense stays whole: the sensors' lines gather there, and a column standing as two would leave them no way through.
    const tall = [...slots].filter((slot, index) => slot.count >= 3 && !(defense.length > 0 && index === slots.length - 1)).sort((a, b) => b.count - a.count);
    for (const slot of tall) {
      const trial = slots.flatMap((item) => (item === slot ? splitSlot(item, 0) : [item]));
      const trialFrame = columnFrame(W, trial.map((item) => item.ids), field, reserve, engineWords);
      if (trialFrame.step < Math.max(SPLIT_STEP, spacing)) break;
      slots = trial;
      frame = trialFrame;
    }
  }
  laid = slots.map((slot) => slot.ids);
  const { railX, jx, right, roleWidth, start, step } = frame;
  const columnX = (index: number): number => Math.round(laid.length > 1 ? start + step * index : (start + right) / 2);
  // How tall the field stands, in pitches between two rows: a split column's hosts stand half a pitch apart.
  const units = Math.max(0, maxOf(slots.map((slot) => (slot.count - 1) * (slot.half ? 0.5 : 1))));

  // Neighbouring columns share the room between them: beside a defense host, the last column's words and the defense's each take
  // half of it, and the defense's stop short of the rule engines. A longer name or role is cut there.
  // A split column's hosts may change places between its two: both are the last column when it is last.
  const lastSlot = slots[slots.length - 1];
  const lastColumn = new Set([...(lastSlot?.ids ?? []), ...(lastSlot?.half && !lastSlot.first ? (slots[slots.length - 2]?.ids ?? []) : [])]);
  const besideDefense = jx - columnX(laid.length - 1) - 22;
  const lastWidth = defense.length > 0 ? Math.max(ROLE_SHORTEST, Math.min(roleWidth, besideDefense)) : roleWidth;
  const defenseWidth = Math.max(ROLE_SHORTEST, Math.min(Math.max(roleWidth, 150), besideDefense, 2 * (railX - 32 - 12 - jx) - 14));
  const widthOf = (host: Host): number => (host.kind === "defense" ? defenseWidth : lastColumn.has(host.id) ? lastWidth : roleWidth);

  // Rows: the badge of a top host fits above it under the heads, and every name fits under its host.
  // `below` is how far under a host's centre its name and role reach, the most of any host's.
  const belowOf = (host: Host): number => Math.max(r, labelBox({ host, x: 0, y: 0, r, badge: { x: 0, y: 0 }, roleWidth: widthOf(host) })[3]);
  const below = maxOf(network.hosts.map(belowOf), r);
  const fieldOf = new Map(field.map((host) => [host.id, host]));
  // The hosts that have another under them in their column: their words, not the tallest anywhere, set the room between two rows.
  const uppers = slots.flatMap((slot) => slot.ids.filter((id, index) => id !== "" && slot.ids.slice(index + 1).some(Boolean)));
  // Only the least layout (`extra` below 0) measures host by host; any other keeps the tallest words' room under every row,
  // where the sensors' lines find their way between the rows.
  const compact = extra < 0;
  const upperBelow = compact && uppers.length > 0 ? maxOf(uppers.map((id) => { const host = fieldOf.get(id); return host ? belowOf(host) : r; }), r) : below;
  // How far under the bottom row's centre the field's words reach, with `p` pixels between rows: a host higher up reaches less far.
  const reachAt = (p: number): number =>
    maxOf(
      slots.flatMap((slot) =>
        slot.ids.map((id, index) => {
          const host = fieldOf.get(id);
          if (!host) return r;
          const fromTop = ((slot.rows[index] ?? 0) - (slot.count - 1) / 2) * (slot.half ? 0.5 : 1) + units / 2;
          return belowOf(host) - (units - fromTop) * p;
        }),
      ),
      r,
    );
  // Two defense hosts: the upper one's name and role, then the lower one's sensors' names and counts above it.
  const defenseTall = maxOf(defense.map((host) => stackTall(network.sensors.filter((sensor) => sensor.host === host.id).length)), 0);
  const defensePitch = Math.max(DEFENSE_PITCH, Math.ceil(below + r + DEFENSE_SENSOR_OFF - 10 + defenseTall + 16));
  // The top defense host stands low enough for its sensors' names and counts above it, under the column heads.
  const defenseTop = Math.max(HEADS_MANY + r + 8, HEADS_MANY + 4 + r + DEFENSE_SENSOR_OFF - 10 + defenseTall);
  // The top row stands low enough for a badge above it, or, when the room is short, just under the heads.
  // Clear air above it: the badge never stands close under the heads, and the zone's top runs between them.
  const firstBest = HEADS_MANY + BADGE_CLEAR + BADGE.height + BADGE.above + r;
  const firstLeast = HEADS_MANY + r + 8;
  // Two hosts of one column: the lower one's badge, above its ring, clears the upper one's role. With less room
  // (`extra` below 0, down to `COMPACT`), the badge stands beside its host instead.
  const pitchLeast = upperBelow + 4 + BADGE.height + BADGE.above + r + extra;
  const reach = reachAt(pitchLeast);
  // Every column fits: the hosts' rows, the defense hosts and the rule engines. The one that needs the most room sets the least height.
  const need = Math.ceil(
    Math.max(
      // `words` more pixels under the bottom row, when the words for silence need them.
      firstLeast + units * pitchLeast + reach + words + bottom,
      defenseTop + Math.max(0, defense.length - 1) * defensePitch + maxOf(defense.map(belowOf), r) + bottom,
      HEADS_MANY + 6 + 32 + Math.max(0, network.detectors.length - 1) * ENGINE_PITCH + ENGINE_BELOW + bottom,
    ),
  );
  const H = Math.max(240, height, need);
  const lastRoom = H - bottom - reach - words;
  // The badge above the top row comes before more room between rows: the rows stand further apart with what is left.
  const firstY = units > 0 ? clamp(lastRoom - units * (pitchLeast - extra), firstLeast, firstBest) : firstBest;
  const pitch = units > 0 ? Math.min(MOST_PITCH, (lastRoom - firstY) / units) : 0;
  const block = units * pitch;
  // A short network stands in the middle of the room it has.
  const startY = units > 0 ? firstY + Math.max(0, (lastRoom - firstY - block) / 2) : (firstY + lastRoom) / 2;
  const centerY = Math.round(startY + block / 2);

  // Where each slot's hosts stand, one above another, a split column's in turn half a pitch apart.
  const yOf = (slot: Slot, index: number): number => centerY + ((slot.rows[index] ?? 0) - (slot.count - 1) / 2) * pitch * (slot.half ? 0.5 : 1);
  // A split column's hosts take the order, and the side, under which the links cross least. The choice is made on a
  // grid of fixed steps, not at the stage's size, so the network keeps one arrangement at every size and only its
  // spacing changes.
  const unitAt = (slot: Slot, place: number, row: number): Point => ({ x: place * UNIT_STEP, y: ((slot.rows[row] ?? 0) - (slot.count - 1) / 2) * UNIT_PITCH * (slot.half ? 0.5 : 1) });
  slots.forEach((slot, index) => {
    const next = slots[index + 1];
    if (!slot.first || !next) return;
    const members = [...slot.ids, ...next.ids];
    const at = new Map<string, Point>();
    slots.forEach((other, place) => other.ids.forEach((id, row) => (id ? at.set(id, unitAt(other, place, row)) : null)));
    let best: { score: number; pair: [Slot, Slot] } | null = null;
    for (const order of orders(members)) {
      for (const flip of [0, 1]) {
        const pair = splitSlot({ ids: order, rows: order.map((_, row) => row), count: order.length, half: false }, flip);
        const [a, b] = pair;
        if (!a || !b) continue;
        a.ids.forEach((id, row) => at.set(id, unitAt(a, index, row)));
        b.ids.forEach((id, row) => at.set(id, unitAt(b, index + 1, row)));
        const score = tangle(drawn, at);
        if (!best || score < best.score - 1e-9) best = { score, pair: [a, b] };
      }
    }
    if (best) {
      slots[index] = best.pair[0];
      slots[index + 1] = best.pair[1];
    }
  });
  laid = slots.map((slot) => slot.ids);

  const hosts = new Map<string, HostNode>();
  slots.forEach((slot, index) => {
    const x = columnX(index);
    slot.ids.forEach((id, row) => {
      // A folded column holds an empty place where a band's column has fewer hosts than the band's tallest.
      const host = id ? field.find((item) => item.id === id) : undefined;
      const y = Math.round(yOf(slot, row));
      if (host) hosts.set(host.id, { host, x, y, r, counted: COUNTED.has(host), badge: { x, y: y - r - BADGE.above }, roleWidth: widthOf(host) });
    });
  });

  let junction: Junction;
  const firstDefense = defense[0];
  if (firstDefense) {
    fitColumn(defense.length, centerY, defensePitch, defensePitch, defenseTop, H - bottom - below).ys.forEach((y, index) => {
      const host = defense[index];
      if (host) hosts.set(host.id, { host, x: jx, y: Math.round(y), r, badge: { x: jx, y: Math.round(y) - r - BADGE.above }, roleWidth: defenseWidth });
    });
    const node = hosts.get(firstDefense.id);
    junction = { x: jx, y: node ? node.y : centerY, r: node ? node.r : 4, hostId: firstDefense.id };
  } else {
    junction = { x: jx, y: centerY, r: 4, hostId: null };
  }

  const room = H - 64 - 14;
  const detectorGap = clamp(room * 0.3, ENGINE_PITCH, 240);
  const detectorRadius = Math.round(clamp(room * 0.075, 22, 32));
  const detectors: DetectorNode[] = [];
  // The rule engines stand from the top row down, so their matches have the height of the map under them.
  // Never so high that an engine's name stands close under the heads.
  fitColumn(network.detectors.length, Math.min(centerY, startY + ((network.detectors.length - 1) * detectorGap) / 2), detectorGap, ENGINE_PITCH, HEADS_MANY + 16 + detectorRadius, H - bottom - ENGINE_BELOW).ys.forEach((y, index) => {
    const detector = network.detectors[index];
    if (detector) detectors.push({ detector, x: railX, y: Math.round(y), r: detectorRadius });
  });
  const junctionOut: Point = junction.hostId ? { x: junction.x + junction.r + 1, y: junction.y } : junction;
  const junctionToDetector = new Map<string, Curve>();
  for (const node of detectors) junctionToDetector.set(node.detector.id, bend(junctionOut, { x: node.x - node.r, y: node.y }, 0.5));

  // What everything placed so far covers: hosts, their names, the column heads.
  // The field's head starts at the left edge of the network, as the rule engines' starts at theirs: one line each.
  const fieldHeadX = Math.max(ENGINE_EDGE, Math.round(Math.min(...fieldNodesOf(hosts).map((node) => Math.min(node.x - node.r, labelBox(node)[0])))));
  const enginesHead = detectors[0];
  // The field's head tells a name its sensors share once, and on which hosts: a longer line.
  const headWide = sharedSensorName(network) === null ? 200 : 460;
  const heads: Box[] = [[fieldHeadX, 0, fieldHeadX + headWide, HEADS_MANY - 4], ...(enginesHead ? [[enginesHead.x - enginesHead.r, 0, W, HEADS_MANY - 4] as Box] : [])];
  const circles = [...hosts.values()].map((node) => circleBox(node, 6));
  const names = [...hosts.values()].map(labelBox);
  // The rule engines and their words, which run to the right edge.
  const engines = detectors.map((node): Box => [node.x - node.r - 8, node.y - node.r - 8, W, node.y + Math.max(node.r, 80)]);
  // The place above a field host's ring is kept for its badge: a badge always stands there, the same at every size.
  const fieldList = fieldNodesOf(hosts);
  const rings = fieldList.map((node) => badgeBox({ x: node.x, y: node.y - node.r - BADGE.above }));
  const solid: Box[] = [...circles, ...names, ...heads, ...engines];
  const wirePoints: Point[] = [];
  for (const curve of junctionToDetector.values()) wirePoints.push(...samples(curve));

  // Links: straight where nothing is in the way, else bowed around the hosts and names they would cross.
  const links: LinkLine[] = [];
  const linkPoints: Point[][] = [];
  // The cells, 4 pixels square, that the links placed so far pass through: two links that share cells run on top of each other.
  const cell = (point: Point): number => (Math.floor(point.x / 4) + 4096) * 8192 + Math.floor(point.y / 4) + 4096;
  const used = new Set<number>();
  const placedPaths: { ends: Set<string>; bounds: Box; points: Point[] }[] = [];
  // A label more than two links share names the network they are on: it is told once, and its links read as one zone.
  const shared = new Map<string, number>();
  for (const link of drawn) if (link.label) shared.set(link.label, (shared.get(link.label) ?? 0) + 1);
  const zoneOf = (label: string): string | null => (label && (shared.get(label) ?? 0) > 2 ? label : null);
  const hostList = [...hosts.values()];
  // Where the fields are drawn: under the column heads, from the map's left margin down to the field hosts' lowest words.
  // A link may carry the attack's path, so it stays in there: a hop never runs out over the heads or under the fields.
  const drawnArea: Box = [ENGINE_EDGE, HEADS_MANY + 4, W - ENGINE_EDGE, Math.min(H - 4, maxOf(fieldList.map((node) => labelBox(node)[3] + ZONE_PAD), H - 4))];
  const outside = (point: Point): boolean => !inBox(point, drawnArea, -6);
  for (const link of drawn) {
    const from = hosts.get(link.from);
    const to = hosts.get(link.to);
    if (!from || !to) continue;
    const sameColumn = Math.abs(from.x - to.x) < 1;
    // Between two hosts of one column: brackets on either side, near or wide, leaving steep or nearly level.
    const shapes: [number, number, boolean][] = sameColumn
      ? [70, -70, 110, -110, 150, -150].flatMap((offset): [number, number, boolean][] => [[offset, Math.PI / 4, false], [offset, Math.PI / 10, false]])
      : [0, 24, -24, 36, -36, 42, -42, 48, -48, 54, -54, 72, -72, 110, -110, 150, -150].flatMap((offset): [number, number, boolean][] => [[offset, 0, false], [offset, 0, true]]);
    let best: { score: number; curve: Curve } | null = null;
    for (const [offset, slant, level] of shapes) {
      const curve = linkCurve(from, to, offset, slant, level);
      // A straight line reads best: a turning one is taken only to keep clear.
      let score = Math.abs(offset) * 0.02 + (level ? 1.5 : 0);
      if (best && score >= best.score) continue;
      // Only what stands near the curve can meet it: a curve stays inside the box of its control points.
      const bounds = curveBounds(curve, 4);
      const nearHosts = hostList.filter((node) => node !== from && node !== to && meetsBox(circleBox(node, 48), bounds));
      const nearNames = names.filter((box) => meetsBox([box[0] - 14, box[1] - 14, box[2] + 14, box[3] + 14], bounds));
      const ownNames = [names[hostList.indexOf(from)], names[hostList.indexOf(to)]];
      // The place above another host is its badge's: a path through it would run behind the badge.
      const nearBadges = rings.filter((box, index) => fieldList[index] !== from && fieldList[index] !== to && meetsBox(box, bounds));
      // Two links that cross make the way the attacker came hard to follow: a crossing costs as much as a pass by a host.
      const path = [curve[0], ...samples(curve, 16), curve[3]];
      for (const placed of placedPaths) {
        if (placed.ends.has(link.from) || placed.ends.has(link.to) || !meetsBox(placed.bounds, bounds)) continue;
        for (let one = 1; one < path.length; one += 1) {
          for (let two = 1; two < placed.points.length; two += 1) {
            const [a, b, c, d] = [path[one - 1], path[one], placed.points[two - 1], placed.points[two]];
            if (a && b && c && d && crosses(a, b, c, d)) score += 6;
          }
        }
      }
      if (best && score >= best.score) continue;
      for (const point of samples(curve, 40)) {
        // Close by a host it does not join, a link reads as running through it: the attack would seem to pass there.
        // It clears a host it does not join by one radius beyond the ring the host wears when lit.
        for (const node of nearHosts) if (within(point, node, node.r + 2)) score += 20;
        else if (within(point, node, node.r + 10)) score += 6;
        else if (within(point, node, node.r + 28)) score += 2;
        else if (within(point, node, node.r + 44)) score += 0.6;
        // Close under a name it reads as crowded: a line keeps a little clear air from every name it passes.
        // Through another host's name it reads as reaching that host: that costs more than passing its own ends' words.
        for (const box of nearNames) if (inBox(point, box, 2)) score += ownNames.includes(box) ? 3 : 8;
        else if (inBox(point, box, 14)) score += 0.5;
        for (const box of nearBadges) if (inBox(point, box, 6)) score += 6;
        // Past the last column the sensors' lines gather toward the defense: a link keeps out of their way.
        if (point.x > right + 30) score += 1;
        // Out of the fields, over the heads or under the lowest words, costs more than passing a host's words.
        if (outside(point)) score += 20;
        if (used.has(cell(point))) score += 0.5;
        // A score only grows: once it is no better than the best, this shape cannot win.
        if (best && score >= best.score) break;
      }
      if (!best || score < best.score) best = { score, curve };
    }
    if (!best) continue;
    links.push({ link, from, to, curve: best.curve, label: pointOn(best.curve, 0.5), told: true, zone: zoneOf(link.label) });
    placedPaths.push({ ends: new Set([link.from, link.to]), bounds: curveBounds(best.curve, 2), points: [best.curve[0], ...samples(best.curve, 16), best.curve[3]] });
    const points = samples(best.curve, 40);
    linkPoints.push(points);
    for (const point of points) used.add(cell(point));
  }
  const allLinkPoints = linkPoints.flat();
  // A zone's links are drawn only where the attack's path runs: a sensor's words keep off them, but less than off a line always drawn.
  const linePoints = [...linkPoints.filter((_, index) => links[index]?.zone === null).flat(), ...wirePoints];
  const zonePoints = linkPoints.filter((_, index) => links[index]?.zone !== null).flat();

  // Sensors: beside their host, where their names cover the least. Under a host is its name, and above it, best, its badge.
  // A sensor is always there and a badge only while a step runs on its host, so a badge makes way for a sensor.
  const sensors: SensorNode[] = [];
  const sensorBoxes: Box[] = [];
  const sensorBoxOf = new Map<string, Box>();
  const hard = [...circles, ...heads, ...engines];
  // The defense hosts' sensors first: they have only the room above their hosts, and the field's sensors make way for them.
  for (const host of [...defense, ...field]) {
    const node = hosts.get(host.id);
    const own = network.sensors.filter((sensor) => sensor.host === host.id);
    if (!node || own.length === 0) continue;
    // A lone sensor whose name is told once has only its count beside its dot, on one line.
    const unnamed = own.length === 1 && own.every((sensor) => NAMED_ONCE.has(sensor));
    const label = maxOf(own.map(smallName)) + 18 + (own.length > 1 ? STACK_COUNT : 0);
    // Room for each name and, while a step runs, its count of events under it.
    const tall = unnamed ? 20 : stackTall(own.length);
    const inline = own.length > 1 || unnamed;
    let best: { score: number; x: number; y: number; side: 1 | -1; over: boolean; up: boolean } | null = null;
    // A field host's dot whose name the head tells stands on the side that faces the defense, where its events go:
    // the top of the host is its badge's, the same at every size.
    const toward = junction.x >= node.x ? 0 : 180;
    // Where the columns stand close, nearer its host, and where even that side is taken, on the other side or below.
    const turn = Math.sign(90 - toward);
    const facing = [[toward, 0], [toward - 30 * turn, 1], [toward + 30 * turn, 1], [toward - 55 * turn, 4], [toward + 55 * turn, 4], [180 - toward, 12], [180 - toward - 30 * turn, 13], [180 - toward + 30 * turn, 13], [90, 16]] as const;
    // A defense host's sensors stand above it, clear of the field and the lines to the rule engines; a field host's beside it.
    const places = host.kind === "defense" ? DEFENSE_SENSOR_PLACES : unnamed ? facing : FIELD_SENSOR_PLACES;
    const ownName = labelBox(node);
    const ownCircle = circles[hostList.indexOf(node)];
    // A defense host's sensors stand a little further off, clear of its badge on the top of its ring; a dot with no name
    // stands out where the host's own links have spread apart, so its count fits between them.
    const off = node.r + (host.kind === "defense" ? DEFENSE_SENSOR_OFF : 18);
    // Every place tried lies within this reach of the host: only the lines there can run through a sensor's words.
    const reachX = off + label + 16 + (unnamed ? COUNT_WORDS : 0);
    const reachY = off + tall + 36;
    const nearPoints = linePoints.filter((point) => Math.abs(point.x - node.x) < reachX && Math.abs(point.y - node.y) < reachY);
    const nearZone = zonePoints.filter((point) => Math.abs(point.x - node.x) < reachX && Math.abs(point.y - node.y) < reachY);
    // A lone count stands above its dot or under it, running away from its host, where its line never runs.
    // Or level with it, beyond it, where the host's own links have spread apart; its line then leaves upward or downward.
    // A dot with no name has no words beside it: it stands close by its host, plainly its own.
    const ways: { side: 1 | -1; over: boolean; up: boolean }[] = unnamed
      ? [{ side: toward === 0 ? 1 : -1, over: false, up: false }]
      : [
          { side: 1, over: false, up: false },
          { side: -1, over: false, up: false },
        ];
    // A dot with no name may also stand close by its host, where the next column stands near.
    // A defense host's sensors may stand a little further off, where the column is short and the nearer places touch its ring.
    const reaches: [number, number][] = host.kind === "defense" ? [[off, 0], [off + 10, 1]] : [[off, 0]];
    for (const [[degrees, base], [distance, nearer]] of places.flatMap((place) => reaches.map((reach) => [place, reach] as const))) {
      const penalty = base + nearer;
      const angle = (degrees * Math.PI) / 180;
      const x = node.x + Math.cos(angle) * distance;
      const y = node.y + Math.sin(angle) * distance;
      for (const way of ways) {
        // A lone count runs away from its host, on whichever side its dot stands.
        const side: 1 | -1 = unnamed ? (Math.cos(angle) < -0.01 ? -1 : 1) : way.side;
        const { over } = way;
        const up = over ? way.up : y < node.y;
        if (!over && ((degrees === 0 && side < 0) || (degrees === 180 && side > 0))) continue;
        const box = over ? countBox(x, y, up, side) : sensorBox(x, y, side, label, tall, up);
        // Kept a little apart from other words, so a sensor's name never reads as part of a host's.
        const near: Box = [box[0] - 10, box[1] - 2, box[2] + 10, box[3] + 2];
        // A count level with its dot makes the dot's line leave upward or downward: a count over or under it is better.
        let score: number = penalty;
        // The dot itself stands on no name, host or badge either.
        const dot: Box = [x - 10, y - 10, x + 10, y + 10];
        for (const other of [...names, ...rings, ...circles.filter((item) => item !== ownCircle)]) score += overlap(dot, other) * 2;
        for (const other of hard) score += overlap(box, other) / 10;
        // The column heads and the rule engines' words are words too: a sensor's name never stands under them while there is a free place.
        for (const other of [...heads, ...engines]) score += overlap(box, other) * 2;
        // The place above every field host is its badge's, its own host's too.
        for (const other of rings) score += overlap(box, other) * 2;
        // Nor on another host or on any host's name, where it would read as theirs.
        for (const other of circles) if (other !== ownCircle) score += overlap(box, other) * 2;
        // Its words never cover its own host either: the dot stands beside it, the words away from it.
        if (ownCircle) score += overlap([box[0] + 12, box[1], box[2] - 12, box[3]], circleBox(node, 0)) * 2;
        for (const other of names) score += overlap(near, other) / 10 + overlap(box, other) * 2;
        // Another host's sensors' words are never covered while there is a free place.
        for (const other of sensorBoxes) score += overlap(near, other) / 10 + overlap(box, other) * 2;
        // No link runs through a sensor's dot or name, as no line runs through a host's name.
        for (const point of nearPoints) if (inBox(point, box, 4)) score += 8;
        for (const point of nearZone) if (inBox(point, box, 2)) score += 6;
        // Its line to the defense starts clear of its own host and name: it never doubles back across its host.
        if (host.id !== junction.hostId) {
          const way = line({ x, y }, junction);
          // Its line leaves level, as the lines to the defense are drawn: that one must not run across its own words.
          const level = bend({ x, y }, junction, 0.5);
          for (let u = 0.05; u < 0.5; u += 0.05) {
            const point = pointOn(way, u);
            if (inBox(point, ownName, 2)) score += 20;
            // Never back across its own host: the light would cross the host's icon.
            if (within(point, node, node.r + 4)) score += 60;
            // Nor over its own name or count: the light it carries would run across the words.
            const leaving = pointOn(level, u);
            if (Math.hypot(leaving.x - x, leaving.y - y) > 14 && inBox(leaving, box, -2)) score += 6;
          }
        }
        // It stays on the map; the column heads are kept clear as a hard box above.
        // Off the map it is not drawn at all: any place on the map is better.
        if (box[0] < 8 || box[2] > W - 8 || box[1] < 8 || box[3] > H - 4) score += 100_000;
        if (!best || score < best.score) best = { score, x, y, side, over, up };
      }
    }
    if (!best) continue;
    const place = best;
    // Several sensors of one host stand in a stack that grows away from it.
    const away = place.y < node.y ? -1 : 1;
    own.forEach((sensor, index) => {
      sensors.push({ sensor, x: Math.round(place.x), y: Math.round(place.y + away * index * SENSOR_STACK), r: 7, small: true, side: place.side, above: place.up, inline, cut: SENSOR_NAME_MOST, named: !NAMED_ONCE.has(sensor), over: place.over });
    });
    const placed = place.over ? countBox(place.x, place.y, place.up, place.side) : sensorBox(place.x, place.y, place.side, label, tall, place.up);
    sensorBoxes.push(placed);
    sensorBoxOf.set(host.id, placed);
  }

  // A sensor's line to the defense bends around the hosts and names it would otherwise cross.
  const hostToSensor = new Map<string, Curve>();
  const sensorToJunction = new Map<string, Curve>();
  const fieldNodes = [...hosts.values()].filter((node) => node.host.id !== junction.hostId);
  // The lines arrive at the defense host on its left side, never from under it, where its name is.
  const junctionEdge = (from: Point): Point => {
    if (!junction.hostId) return junction;
    const angle = Math.PI + clamp(Math.atan2(from.y - junction.y, junction.x - from.x), -0.9, 0.9) * -1;
    return { x: junction.x + Math.cos(angle) * (junction.r + 1), y: junction.y + Math.sin(angle) * (junction.r + 1) };
  };
  const sensorPoints: Point[] = [];
  const wordBoxes = [...names, ...sensorBoxes];
  // Every line arrives at the defense host: one through its words would cross them where they gather, so they cost the most.
  const junctionHost = junction.hostId ? hosts.get(junction.hostId) : undefined;
  const junctionName = junctionHost ? names[hostList.indexOf(junctionHost)] : undefined;
  // The corridors between rows, above the top one and under the bottom one's names: where a line crosses the field clear of every name.
  const rowsY = [...new Set(fieldNodes.map((node) => node.y))].sort((a, b) => a - b);
  const corridors = [rowsY[0] === undefined ? null : rowsY[0] - r - 12, ...rowsY.slice(1).map((y, index) => ((rowsY[index] ?? y) + below + y - r) / 2), rowsY.length > 0 ? (rowsY[rowsY.length - 1] ?? 0) + below + 6 : null].filter((y): y is number => y !== null && y > HEADS_MANY && y < H - 4);
  for (const node of sensors) {
    const host = hosts.get(node.sensor.host);
    if (!host) continue;
    hostToSensor.set(node.sensor.id, line(edgeToward(host, node), node));
    if (node.sensor.host === junction.hostId) {
      // A sensor of the host where the lines join: its events go the short way, on to the rule engines.
      sensorToJunction.set(node.sensor.id, bend(node, junctionOut, 0.5));
      continue;
    }
    let best: { score: number; curve: Curve } | null = null;
    const end = junctionEdge(node);
    const ownWords = sensorBoxOf.get(node.sensor.host);
    // A bend's middle stands at the mean of its ends' heights and three quarters of its offset: one offset per corridor.
    const along = corridors.map((y) => Math.round((y - (node.y + end.y) / 2) / 0.75));
    // With little `amount` a line leaves its sensor straight up or down before it turns toward the defense.
    // Tried from the least bent on: once a shape bends more than the best scores in all, no later one can win.
    // A line may also bow at one end only: it leaves level and turns late, or turns early and arrives level, the way
    // round a name that stands close by the sensor or close by the defense host.
    const shapes = [0, -40, 40, -80, 80, -120, 120, -160, 160, -200, 200, -240, 240, ...along]
      .flatMap((offset) => [0.5, 0.25, 0.8, 0.05].flatMap((amount) => ([0, 1, 2, 3, 4] as const).map((ends): [number, number, 0 | 1 | 2 | 3 | 4, number] => [offset, amount, ends, Math.abs(offset) * 0.02 + Math.abs(amount - 0.5) + (ends === 0 ? 0 : 0.3)])))
      .sort((a, b) => a[3] - b[3]);
    // Or it arrives at the defense host's upper left, or level with it, where a line from above or a level one meets it best.
    const arrivals = [end, end, end, junctionEdge({ x: junction.x - 100, y: junction.y - 1000 }), junctionEdge({ x: junction.x - 100, y: junction.y })];
    for (const [offset, amount, ends, bent] of shapes) {
      if (best && bent >= best.score) break;
      const arrival = arrivals[ends] ?? end;
      const both = bend(node, arrival, amount, offset);
      const curve: Curve = ends === 1 ? [both[0], both[1], { x: both[2].x, y: arrival.y }, both[3]] : ends === 2 ? [both[0], { x: both[1].x, y: node.y }, both[2], both[3]] : both;
      let score = bent;
      const bounds = curveBounds(curve, 2);
      const nearHosts = fieldNodes.filter((other) => meetsBox(circleBox(other, 14), bounds));
      const nearWords = wordBoxes.filter((box) => meetsBox(box, bounds));
      const nearRings = rings.filter((box) => meetsBox(box, bounds));
      // Sampled finely enough that no sensor's dot falls between two samples.
      for (const [index, point] of samples(curve, 80).entries()) {
        // It keeps clear of the hosts, and never runs back across its own: the light would cross the host's icon.
        for (const other of nearHosts) {
          if (within(point, other, other.r + 14)) score += 1;
          // Through another host it would read as that host's events.
          if (other.host.id !== node.sensor.host && within(point, other, other.r + 2)) score += 12;
          if (other.host.id === node.sensor.host && within(point, other, other.r + 4)) score += 30;
        }
        // It passes behind no name, its own sensor's neither: the light it carries would run across the words.
        for (const box of nearWords) if ((box !== ownWords || index > 5) && inBox(point, box, 2)) score += box === ownWords ? 8 : box === junctionName ? 24 : names.includes(box) ? 8 : 30;
        // Nor through the place above a host where its badge stands.
        for (const box of nearRings) if (inBox(point, box, 2)) score += 4;
        // It stays under the column heads and on the map.
        if (point.y < HEADS_MANY + 6 || point.y > H - 4) score += 4;
        // A score only grows: once it is no better than the best, this shape cannot win.
        if (best && score >= best.score) break;
      }
      if (!best || score < best.score) best = { score, curve };
    }
    if (best) {
      sensorToJunction.set(node.sensor.id, best.curve);
      sensorPoints.push(...samples(best.curve, 40));
    }
  }

  // Link labels: on their link, where they cover no other line, name or sensor; off it a little when nothing on it is free.
  const labels: Box[] = [];
  const fixed = [...solid, ...sensorBoxes, ...rings];
  // Where each label best stands on its own link; a zone's is then told on the one of its links where it stands best.
  const placeLabel = (item: LinkLine, index: number, w: number, offLine = false): { score: number; point: Point; box: Box } | null => {
    const h = 20;
    // Every place tried lies within the reach of the largest shift and the pill around the curve: only what is there can count.
    const reach = curveBounds(item.curve, 46 + w / 2 + 9);
    // A pill sits on its own link; a network's name, which has no pill, stands beside every line, its own too.
    const others = [...linkPoints.filter((_, other) => offLine || other !== index).flat(), ...sensorPoints, ...wirePoints].filter((point) => inBox(point, reach));
    const fixedNear = fixed.filter((box) => meetsBox(box, reach));
    const [a, , , b] = item.curve;
    const length = Math.hypot(b.x - a.x, b.y - a.y) || 1;
    const across = { x: -(b.y - a.y) / length, y: (b.x - a.x) / length };
    let best: { score: number; point: Point; box: Box } | null = null;
    for (const shift of [0, 14, -14, 22, -22, 34, -34, 46, -46]) {
      for (const u of [0.5, 0.42, 0.58, 0.34, 0.66, 0.26, 0.74, 0.18, 0.82]) {
        const on = pointOn(item.curve, u);
        const point = { x: on.x + across.x * shift, y: on.y + across.y * shift };
        const box: Box = [point.x - w / 2, point.y - h / 2, point.x + w / 2, point.y + h / 2];
        // Kept a little apart from other words, so two never read as one.
        const near: Box = [box[0] - 8, box[1] - 3, box[2] + 8, box[3] + 3];
        let score = Math.abs(u - 0.5) * 12 + Math.abs(shift) * 0.8;
        // Covering a word costs far more than sitting on a line.
        for (const other of fixedNear) score += overlap(near, other) / 2 + overlap(box, other) * 2;
        for (const other of labels) score += overlap(near, other) / 2 + overlap(box, other) * 2;
        // Another line under the pill would vanish behind it: the path must read through.
        // A score only grows: once it is no better than the best, this place cannot win.
        for (const other of others) {
          if (best && score >= best.score) break;
          if (inBox(other, box, 1)) score += 15;
        }
        if (box[0] < 2 || box[2] > W - 2 || box[1] < 2 || box[3] > H - 2) score += 200;
        if (!best || score < best.score) best = { score, point, box };
      }
    }
    return best;
  };
  // A label of its own link first, in a pill on the link.
  links.forEach((item, index) => {
    const words = item.link.label ?? "";
    if (!words || item.zone !== null) return;
    const best = placeLabel(item, index, textWidth(words, 11) + 20);
    if (!best) return;
    labels.push(best.box);
    item.label = best.point;
  });
  // Then each network, once: a soft rounded box round its hosts and their names, its name in small capitals inside its
  // top left corner. Its links are not drawn one by one: the box says its hosts reach each other, and a link is drawn
  // only where the attack's path runs along it. A host on two zones that stand side by side, a bridge, stands on the
  // border between them: each box ends at its centre, square and with no outline there, so the two never overlap.
  const zones: Zone[] = [];
  // The goal's badge may stand beside its host, where a top row leaves no room above it: a network's name keeps clear of both sides.
  const goalSides: Box[] = fieldList
    .filter((node) => GOAL.has(node.host))
    .flatMap((node) => [1, -1].map((way): Box => {
      const near = node.x + way * (node.r + BADGE.ring + 4);
      const far = near + way * GOAL_BADGE_WIDTH;
      return [Math.min(near, far), node.y - node.r * 0.4 - BADGE.height, Math.max(near, far), node.y - node.r * 0.4];
    }));
  const linkLabelPoints = [...linkPoints.filter((_, index) => links[index]?.zone === null).flat(), ...sensorPoints, ...wirePoints];
  const wordsOf = (label: string): string[] =>
    label
      .split(",")
      .map((word) => word.trim())
      .filter(Boolean);
  // A host is on a zone when one of its links, drawn or not, is on that zone's networks alone. A defense host stands on
  // the defense's own side, never in a zone of the hosts it watches.
  const membersOf = (zone: string): HostNode[] => {
    const words = new Set(wordsOf(zone));
    const ids = new Set<string>();
    for (const link of network.links ?? []) {
      const own = wordsOf(link.label ?? "");
      if (own.length === 0 || !own.every((word) => words.has(word))) continue;
      ids.add(link.from);
      ids.add(link.to);
    }
    return hostList.filter((node) => ids.has(node.host.id) && node.host.kind !== "defense");
  };
  const zoneList = [...new Set(links.flatMap((item) => (item.zone === null ? [] : [item.zone])))].map((zone) => ({ zone, members: membersOf(zone) }));
  const zoneCount = new Map<HostNode, number>();
  for (const { members } of zoneList) for (const node of members) zoneCount.set(node, (zoneCount.get(node) ?? 0) + 1);
  // What a host's place in its zone takes: its lit ring, its name and role, and, for a field host, the place of its badge.
  const placeOf = (node: HostNode): Box[] => {
    const name = labelBox(node);
    const parts: Box[] = [circleBox(node, 16), [name[0] - ZONE_PAD, name[1], name[2] + ZONE_PAD, name[3] + ZONE_PAD]];
    if (node.host.kind !== "defense") {
      const badge = badgeBox({ x: node.x, y: node.y - node.r - BADGE.above });
      parts.push([badge[0], badge[1] - 10, badge[2], badge[3]]);
    }
    return parts;
  };
  const union = (boxes: readonly Box[]): Box => [Math.min(...boxes.map((box) => box[0])), Math.min(...boxes.map((box) => box[1])), Math.max(...boxes.map((box) => box[2])), Math.max(...boxes.map((box) => box[3]))];
  // A host on two zones, a bridge, has one home: the zone with more of its links, the later one when they tie. The other
  // zone's box ends short of it, with a gap the attack's path crosses.
  const linksOn = (node: HostNode, zone: string): number => {
    const words = new Set(wordsOf(zone));
    return (network.links ?? []).filter((link) => (link.from === node.host.id || link.to === node.host.id) && wordsOf(link.label ?? "").every((word) => words.has(word))).length;
  };
  const homeOf = new Map<HostNode, string>();
  for (const { zone, members } of zoneList) for (const node of members) if (!homeOf.has(node) || linksOn(node, zone) >= linksOn(node, homeOf.get(node) ?? zone)) homeOf.set(node, zone);
  const fields: { zone: string; members: HostNode[]; box: Box; hidden?: boolean }[] = [];
  for (const { zone, members } of zoneList) {
    if (members.length === 0) {
      // A network only the defense stands on is told by the defense's own side: its links are drawn as links.
      for (const item of links) if (item.zone === zone) item.zone = null;
      continue;
    }
    for (const item of links) if (item.zone === zone) item.told = false;
    const own = members.filter((node) => (zoneCount.get(node) ?? 0) < 2 || homeOf.get(node) === zone);
    const guests = own.length > 0 ? members.filter((node) => !own.includes(node)) : [];
    let box = union((own.length > 0 ? own : members).flatMap(placeOf));
    for (const node of guests) {
      const place = union(placeOf(node));
      // A bridge whose home is another zone stands outside this one, beyond its edge: the box stops short of it.
      if (place[0] >= box[2] - ZONE_GAP) box = [box[0], box[1], Math.min(box[2], place[0] - ZONE_GAP), box[3]];
      else if (place[2] <= box[0] + ZONE_GAP) box = [Math.max(box[0], place[2] + ZONE_GAP), box[1], box[2], box[3]];
    }
    // It stays under the column heads, on the map and inside the page's side margins.
    box = [Math.max(box[0], ENGINE_EDGE), Math.max(box[1], HEADS_MANY + 4), Math.min(box[2], W - ENGINE_EDGE), Math.min(box[3], H - 4)];
    fields.push({ zone, members, box });
  }
  // Two fields side by side never overlap: where their boxes meet, they share the room between their hosts, a gap apart.
  for (const one of fields) {
    for (const other of fields) {
      const [a, b] = [one.box, other.box];
      if (one === other || a[0] >= b[0] || a[1] >= b[3] || b[1] >= a[3] || a[2] <= b[0] - ZONE_GAP) continue;
      const middle = (a[2] + b[0]) / 2;
      one.box = [a[0], a[1], Math.min(a[2], middle - ZONE_GAP / 2), a[3]];
      other.box = [Math.max(b[0], middle + ZONE_GAP / 2), b[1], b[2], b[3]];
    }
  }
  // A bridge stands on the border between its two fields: they meet at its centre, so the map shows it on both networks.
  // Only where no other host of either field stands beyond that centre.
  for (const [node, home] of homeOf) {
    if ((zoneCount.get(node) ?? 0) < 2) continue;
    const own = fields.find((field) => field.zone === home);
    if (!own) continue;
    for (const guest of fields) {
      if (guest === own || !guest.members.includes(node)) continue;
      const others = (field: typeof own): HostNode[] => field.members.filter((member) => member !== node);
      if (guest.box[2] <= node.x && others(own).every((member) => member.x > node.x) && others(guest).every((member) => member.x < node.x)) {
        guest.box = [guest.box[0], guest.box[1], node.x, guest.box[3]];
        own.box = [node.x, own.box[1], own.box[2], own.box[3]];
      } else if (guest.box[0] >= node.x && others(own).every((member) => member.x < node.x) && others(guest).every((member) => member.x > node.x)) {
        guest.box = [node.x, guest.box[1], guest.box[2], guest.box[3]];
        own.box = [own.box[0], own.box[1], node.x, own.box[3]];
      }
    }
  }
  // A field never covers a host of another field: where its box reaches over one, it gives up the edge that costs it least,
  // as long as its own hosts stay inside.
  for (const one of fields) {
    const home = one.members.filter((node) => (zoneCount.get(node) ?? 0) < 2 || homeOf.get(node) === one.zone);
    if (home.length === 0) continue;
    const places = union(home.map((node) => circleBox(node, 4)));
    for (const node of hostList) {
      if (one.members.includes(node)) continue;
      const [x0, y0, x1, y1] = circleBox(node, 6);
      const b = one.box;
      const inside: Box = [Math.max(places[0], b[0]), Math.max(places[1], b[1]), Math.min(places[2], b[2]), Math.min(places[3], b[3])];
      if (overlap(b, [x0, y0, x1, y1]) <= 0) continue;
      const all: Box[] = [
        [Math.max(b[0], x1 + ZONE_GAP / 2), b[1], b[2], b[3]],
        [b[0], b[1], Math.min(b[2], x0 - ZONE_GAP / 2), b[3]],
        [b[0], Math.max(b[1], y1 + ZONE_GAP / 2), b[2], b[3]],
        [b[0], b[1], b[2], Math.min(b[3], y0 - ZONE_GAP / 2)],
      ];
      const cuts = all.filter((cut) => cut[0] <= inside[0] && cut[1] <= inside[1] && cut[2] >= inside[2] && cut[3] >= inside[3]);
      const area = (box: Box): number => (box[2] - box[0]) * (box[3] - box[1]);
      const kept = cuts.sort((a, c) => area(c) - area(a))[0];
      if (kept) one.box = kept;
      // No box round its own hosts leaves the other host out: in a folded map, where a column holds hosts of both
      // fields, the field is not drawn at all rather than drawn over a host that is not on it.
      else one.hidden = true;
    }
  }
  // Every link may carry the attack's path, and a hop's numbers stand beside its line: a network's name keeps clear of both.
  const anyLinkPoints = linkPoints.flat();
  const zoneLabels: Box[] = [];
  for (const { zone, members, box, hidden } of fields) {
    const words = zoneName(zone);
    if (hidden) {
      zones.push({ name: zone, words, hosts: members.map((node) => node.host.id), box, label: null, drawn: false });
      continue;
    }
    const w = zoneWidth(words);
    const h = 16;
    // Its name in a corner of its field, the top left first: the first corner where no host, name, badge's place, line or
    // hop's number would be under it. With no corner free, the field is not named on the map; its hosts' details name it.
    const inset = 16;
    const corners: Box[] = [
      [box[0] + inset, box[1] + 9, box[0] + inset + w, box[1] + 9 + h],
      [box[2] - 12 - w, box[1] + 9, box[2] - 12, box[1] + 9 + h],
      [box[0] + inset, box[3] - 9 - h, box[0] + inset + w, box[3] - 9],
      [box[2] - 12 - w, box[3] - 9 - h, box[2] - 12, box[3] - 9],
    ];
    const free = (place: Box): boolean =>
      place[0] >= box[0] &&
      place[2] <= box[2] &&
      place[1] >= box[1] &&
      place[3] <= box[3] &&
      [...fixed, ...labels, ...goalSides].every((other) => overlap([place[0] - 6, place[1] - 4, place[2] + 6, place[3] + 4], other) === 0) &&
      // A hop's numbers stand 13 px off its line, 24 by 16 px: no line runs within their reach of the name.
      !anyLinkPoints.some((point) => inBox(point, [place[0] - 28, place[1] - 22, place[2] + 28, place[3] + 22])) &&
      !linkLabelPoints.some((point) => inBox(point, place, 3));
    const chosen = corners.find(free) ?? null;
    if (chosen) {
      labels.push(chosen);
      zoneLabels.push(chosen);
    }
    zones.push({ name: zone, words, hosts: members.map((node) => node.host.id), box, label: chosen ? { x: chosen[0], y: chosen[1] + h / 2 } : null, drawn: true });
  }
  // Where the columns fold, a column holds hosts of several fields, and a field may be cut round its hosts or left out.
  // A map that drew some fields and not others, or a field without its name or through its own hosts, would tell the
  // networks wrongly: the fields are drawn only when every one is whole, each box round all of its own hosts and none of
  // another's, its name in a free corner, no two on each other. Otherwise none is drawn, and the hosts and lines stand alone.
  if (!zones.every((zone) => fieldWhole(zone, zones, hostList))) {
    for (const zone of zones) {
      zone.drawn = false;
      zone.label = null;
    }
    // Their names are not drawn either: they keep no place from the words placed after them.
    for (const box of zoneLabels) labels.splice(labels.indexOf(box), 1);
  }
  const drawnZones = zones.filter((zone) => zone.drawn);

  // The defense's own side: its hosts and the rule engines in one field at the right, under its head, with the line that
  // says which sensors report to it at its foot, under the rule engines' column.
  let defenseSide: DefenseSide | null = null;
  const defenseNodes = [...hosts.values()].filter((node) => node.host.kind === "defense");
  if (defenseNodes.length > 0) {
    const fieldRight = Math.max(0, ...drawnZones.map((zone) => zone.box[2]));
    const left = Math.max(fieldRight + ZONE_GAP, Math.min(...defenseNodes.flatMap((node) => [node.x - node.r - 18, labelBox(node)[0] - ZONE_PAD])));
    // Its foot is the drawn fields' foot, low enough for the line about the sensors.
    const foot = drawnZones.length > 0 ? Math.max(...drawnZones.map((zone) => zone.box[3])) : H - 4;
    const box: Box = [left, HEADS_MANY + 4, W - ENGINE_EDGE + 14, foot];
    // The line starts at the field's inner left, under the defense host it names, and takes the field's inner width.
    const noteX = Math.round(left + 16);
    defenseSide = { box, note: { x: noteX, y: Math.round(foot - DEFENSE_NOTE - 2) }, noteWidth: Math.round(box[2] - 16 - noteX) };
  }

  // Badges: above the host, 7 px clear of its lit ring, the same place at every size. Beside it or under its name only
  // where a host has no room above it at all.
  // A badge shows only while a step runs on its host, so it makes way for every word that is always there.
  const linesAll = [...allLinkPoints, ...sensorPoints, ...wirePoints];
  [...hosts.values()].forEach((node, index) => {
    // Everything but the host's own circle, and the places kept for badges.
    const taken: Box[] = [...circles.filter((box) => box !== circles[index]), ...names, ...heads, ...engines, ...sensorBoxes, ...labels];
    // The goal's badge says its time too: its place is as wide as it is.
    const wide = GOAL.has(node.host) ? GOAL_BADGE_WIDTH : BADGE.width;
    // Beside the host, a badge starts clear of the ring the host wears when lit, however wide it is.
    const side = wide / 2 + node.r + BADGE.ring + 4;
    const under = labelBox(node)[3] + BADGE.height + 4;
    const candidates: [Point, number][] = [
      [{ x: node.x, y: node.y - node.r - BADGE.above }, 0],
      [{ x: node.x + side, y: node.y - node.r * 0.4 }, 300],
      [{ x: node.x - side, y: node.y - node.r * 0.4 }, 300],
      [{ x: node.x, y: under }, 400],
    ];
    // The host's own circle and the ring it wears when lit: a badge never lies on the host it marks.
    const own = circleBox(node, BADGE.ring - 1);
    let best: { score: number; anchor: Point } | null = null;
    for (const [anchor, penalty] of candidates) {
      const box: Box = [anchor.x - wide / 2, anchor.y - BADGE.height, anchor.x + wide / 2, anchor.y];
      let score = penalty + overlap(box, own) * 20;
      // Covering a word costs far more than covering a line; a sensor's words, always there, cost the most.
      for (const other of taken) score += overlap(box, other);
      for (const other of sensorBoxes) score += overlap(box, other) * 3;
      for (const point of linesAll) {
        if (best && score >= best.score) break;
        if (inBox(point, box, 2)) score += 3;
      }
      // Off the map a badge would be cut: any place on the map is better.
      if (box[0] < 4 || box[2] > W - 4 || box[1] < 2 || box[3] > H - 2) score += 100_000;
      if (!best || score < best.score) best = { score, anchor };
    }
    if (best) node.badge = best.anchor;
  });
  // The line about the sensors stands clear of every host's circle, the ring it wears when lit, its words and its badge,
  // and of the sensors' words: where the foot of the defense's side has no such room, it is left out.
  if (defenseSide?.note && !noteClear(defenseSide, [...hosts.values()], sensorBoxes)) defenseSide.note = null;

  // The silence is told near the host it speaks of, a defense host too, where its words cover no host, name, sensor,
  // link label or the host's own badge. Other lines may run under its backing, but the host's own links, one of which
  // the step came along, only where no place near the host is free of them.
  const silenceAt = new Map<string, Point>();
  const wordsAndHosts: Box[] = [...circles, ...names, ...heads, ...engines, ...sensorBoxes, ...labels];
  let hushCovers = 0;
  for (const node of hosts.values()) {
    const ownLines = links.flatMap((item, index) => (item.from === node || item.to === node ? (linkPoints[index] ?? []) : []));
    // The unseen host's own ring, drawn dashed round it on such a step, and its badge are kept clear too.
    const placed = placeSilence(node, [...wordsAndHosts, badgeBox(node.badge), circleBox(node, 16)], labelBox(node), W, H, ownLines);
    silenceAt.set(node.host.id, placed.point);
    hushCovers += placed.covers;
  }
  const inField = (id: string): boolean => hosts.get(id)?.host.kind !== "defense";
  const sensorRight = Math.max(0, maxOf(sensors.filter((node) => inField(node.sensor.host)).map((node) => node.x + node.r)), maxOf([...hosts.values()].filter((node) => inField(node.host.id)).map((node) => node.x + node.r)));
  const firstDetector = detectors[0];
  return {
    width: W,
    height: H,
    least: Math.max(240, need),
    single: false,
    commandLines: 2,
    centerY,
    hosts: [...hosts.values()],
    sensors,
    detectors,
    links,
    zones,
    defenseSide,
    junction,
    hostToSensor,
    sensorToJunction,
    junctionToDetector,
    orbit: { x: 0, y: 0 },
    fieldHeadX,
    // The defense's head stands over its own side, the defense host and the rule engines together.
    detectorsHeadX: defenseSide ? Math.round(defenseSide.box[0] + 16) : firstDetector ? firstDetector.x - firstDetector.r : railX,
    silence: { x: (sensorRight + junction.x) / 2, y: centerY },
    silenceAt,
    hushCovers,
  };
}
