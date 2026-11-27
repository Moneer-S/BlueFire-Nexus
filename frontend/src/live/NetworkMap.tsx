// The stage: the recording's network, drawn from `recording.network` alone,
// with what the sensors recorded travelling as light to the rule engines.

import { memo, useEffect, useId, useMemo } from "react";
import type { ReactNode } from "react";
import { useSize } from "./useSize";
import type { Alert, Host, Network, Recording, Sensor } from "./recording";
import { DefenseSideHead, DefenseSideRows } from "./DefenseSide";
import type { MapJudges } from "./DefenseSide";
import { alertMoment, eventsByStep } from "./recording";
import { badgeBoxOf, curvePath, ENGINE_EDGE, layoutNetwork, leastHeights, linkBetween, markAlertedHosts, markBadgedHosts, markGoalHost, pointOn, roleParts, SENSOR_NAME_LARGE, sharedSensorName, SILENCE_WORDS, travelPath, ZONE_RADIUS, zoneSaid } from "./networkLayout";
import type { Box, Curve, HostNode, LinkLine, NetworkLayout, Point } from "./networkLayout";
import { capital, detectorParts, elapsed, kindRank, matchKind, plainMarks, plural, raisedAfterStep, sensorShortName, stepLabel, testNumbers, unseenWords } from "./format";
import type { MatchKind } from "./format";
import { FreeText } from "./FreeText";
import { TO_SENSOR, TRAVEL } from "./moment";
import type { StepMoment } from "./moment";
import { Motion } from "./motion";
import type { StyleVars } from "./motion";

interface NetworkMapProps {
  recording: Recording;
  moment: StepMoment | null;
  speed: number;
  /** Changes on every jump of the clock, so motion restarts at the right place. */
  seek: number;
  colours: Map<string, string>;
  labDetectors: Set<string>;
  /** The host an attack path reaches its goal on, once the screen tells that it has: marked on the map from then on. Null before, and without a goal. */
  goalHost?: string | null;
  /**
   * The defense's counted alerts raised so far, the screen's own count of them: on a network, the host each was raised
   * on keeps a mark from then on, and the engine names the latest of an earlier step under the step's own matches.
   */
  raised?: readonly Alert[];
  /**
   * On a network, the run's first alert once the race line tells it, and its time as the race line says it ("01:01.6"):
   * the host it was raised on carries the race line's mark and that time.
   */
  firstAlert?: { id: string; time: string } | null;
  /** The time the race line gives the goal ("10:28.4"): the goal's mark on the map says it too. */
  goalTime?: string | null;
  /** The real time the race line counts from, in ms: an alert's time on the map is counted from it, as the race line's is. */
  runStart?: number;
  /** The host an attack path's goal is on, from the first moment: its place keeps room for the goal's wider badge. */
  goalAt?: string | null;
  /**
   * Told the least height the map needs at its width, at its smallest drawing, whenever it changes: `least`, with nothing
   * on another, and `roomy`, with every badge above its host.
   */
  onLeast?: (heights: { least: number; roomy: number }) => void;
  /** The least height the view gives the map's box; without it, the box claims the map's own least height. */
  minHeight?: number;
  /**
   * For a recording judged by several defenses, whose `recording` here is the chosen one's view: the network the map
   * lays out, which holds every sensor of the run and the chosen defense's rule engines, and the alerts of every
   * defense, so that no host moves when another defense is chosen. A sensor of that network that the view does not
   * hold is another defense's: it is drawn unlit.
   */
  stage?: { network: Network; alerts: readonly Alert[] };
  /** The defenses as the map's defense side lists them (the design round's direction c). */
  judges?: MapJudges;
}

/** The tints of the networks a map tells as zones, in the order their names first appear. */
const ZONE_RGB = ["123,202,255", "160,176,255", "120,222,232"] as const;

const KIND_RGB: Record<MatchKind, string> = { alert: "255,112,69", lab: "168,146,255", review: "123,202,255", launcher: "123,202,255" };
/** The most lights in flight at once; a burst of events is thinned evenly, and every matched event keeps its light. */
const MAX_LIGHTS = 12;

function stars(width: number, height: number): Point[] {
  let seed = 7;
  const next = () => {
    seed = (seed * 16807) % 2147483647;
    return seed / 2147483647;
  };
  return Array.from({ length: Math.round((width * height) / 5200) }, () => ({ x: next() * width, y: next() * height }));
}

/** The still sky behind the map: drawn again only when the map's size changes. */
const Stars = memo(function Stars({ width, height }: { width: number; height: number }) {
  const sky = useMemo(() => stars(width, height), [width, height]);
  return (
    <svg className="lv-stars" viewBox={`0 0 ${width} ${height}`} aria-hidden="true">
      {sky.map((point, index) => (
        <rect key={index} x={point.x} y={point.y} width={index % 7 === 0 ? 1.6 : 1} height={index % 7 === 0 ? 1.6 : 1} opacity={0.05 + ((index * 37) % 17) / 100} />
      ))}
    </svg>
  );
});

function hexagon(x: number, y: number, r: number): string {
  return Array.from({ length: 6 }, (_, index) => {
    const angle = Math.PI / 6 + (index * Math.PI) / 3;
    return `${(x + r * Math.cos(angle)).toFixed(1)},${(y + r * Math.sin(angle)).toFixed(1)}`;
  }).join(" ");
}

function HostGlyph({ node }: { node: HostNode }) {
  const { x, y } = node;
  const s = node.r * 0.42;
  if (node.host.kind === "internet") {
    return (
      <g className="lv-glyph">
        <circle cx={x} cy={y} r={s} />
        <ellipse cx={x} cy={y} rx={s * 0.45} ry={s} />
        <line x1={x - s} y1={y} x2={x + s} y2={y} />
      </g>
    );
  }
  if (node.host.kind === "attacker") {
    return <path className="lv-glyph lv-glyph--attacker" d={`M${x} ${y - s} C ${x + s * 0.9} ${y - s * 0.1}, ${x + s * 0.6} ${y + s}, ${x} ${y + s} C ${x - s * 0.6} ${y + s}, ${x - s * 0.9} ${y - s * 0.1}, ${x} ${y - s}Z`} />;
  }
  if (node.host.kind === "defense") {
    return <path className="lv-glyph lv-glyph--defense" d={`M${x} ${y - s} L${x + s * 0.85} ${y - s * 0.55} L${x + s * 0.7} ${y + s * 0.35} L${x} ${y + s} L${x - s * 0.7} ${y + s * 0.35} L${x - s * 0.85} ${y - s * 0.55}Z`} />;
  }
  return (
    <g className="lv-glyph">
      {[0, 1, 2].map((row) => {
        const top = y - s * 0.75 + row * s * 0.62;
        return (
          <g key={row}>
            <rect x={x - s} y={top} width={s * 2} height={s * 0.42} rx={2} />
            <circle className="lv-glyph-led" cx={x + s * 0.65} cy={top + s * 0.21} r={1.6} />
          </g>
        );
      })}
    </g>
  );
}

function shortOs(host: Host): string {
  return host.os ? (host.os.split(",")[0] ?? host.os) : "";
}

interface MatchLine {
  key: string;
  alert: Alert;
  kind: MatchKind;
  count: number;
}

/** The matches an engine shows: one line per rule and kind, strongest first. */
function matchLines(landed: readonly { alert: Alert }[], detectorId: string, byCount = false): MatchLine[] {
  const lines = new Map<string, MatchLine>();
  for (const { alert } of landed) {
    if (alert.detector !== detectorId) continue;
    const kind = matchKind(alert);
    const key = `${alert.rule.id}:${kind}`;
    const line = lines.get(key);
    if (line) line.count += 1;
    else lines.set(key, { key, alert, kind, count: 1 });
  }
  // Strongest kind first, then the higher level, then, on a network, the rule that matched most, then the order they landed in.
  return [...lines.values()].sort((a, b) => kindRank(b.kind) - kindRank(a.kind) || (LEVEL_RANK[b.alert.rule.level] ?? 0) - (LEVEL_RANK[a.alert.rule.level] ?? 0) || (byCount ? b.count - a.count : 0));
}

const LEVEL_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, informational: 0 };

function MatchChip({ kind, level }: { kind: MatchKind; level: string }) {
  if (kind === "launcher") return <span className="lv-chip lv-chip--launcher">launcher line</span>;
  if (kind === "lab") return <span className="lv-chip lv-chip--lab" title="An ad hoc lab rule alerted. The score does not count it.">lab alert &middot; {level}</span>;
  if (kind === "alert") return <span className="lv-chip lv-chip--alert">alert &middot; {level}</span>;
  if (level === "informational") return <span className="lv-chip lv-chip--review" title="An informational match: nobody reviews it.">informational</span>;
  return <span className="lv-chip lv-chip--review">review &middot; {level}</span>;
}

/** The latest late arrival on one engine: a match of an earlier step, raised live after that step ended. */
interface LateLine {
  alert: Alert;
  kind: MatchKind;
  /** The step it belongs to, in words: "test 3". */
  label: string;
  /** The earlier late arrivals on the same engine while this step is on screen, each "Rule (test 1)". */
  earlier: string[];
}

/** How many late arrivals an engine's tooltip names, the newest ones: the rest are counted. Analyse mode names each on its step. */
const LATE_NAMES = 40;

function LateMatch({ late }: { late: LateLine }) {
  const named = [...late.earlier.slice(-(LATE_NAMES - 1)), `${late.alert.rule.title} (${late.label})`];
  const before = late.earlier.length + 1 - named.length;
  return (
    <div className="lv-match lv-match--late" title={`Raised after their steps ended: ${before > 0 ? `${before} earlier ones, then ` : ""}${named.join(", ")}`}>
      <MatchChip kind={late.kind} level={late.alert.rule.level} />
      <span className="lv-match-title">{late.alert.rule.title}</span>
      <span className="lv-match-count">
        {late.label}, raised after it ended{late.earlier.length > 0 ? ` · ${late.earlier.length} more after their steps` : ""}
      </span>
    </div>
  );
}

/** The box an engine's matches have under its name: as wide as its label, and as tall as the room above the next engine. */
interface MatchRoom {
  width: number;
  height: number;
}

/** The height of an engine's name and its count of rules above its matches, with the space under them and a few pixels to spare. */
const ENGINE_HEAD = 50;
const MATCH_GAP = 5;

/** The size of a match's words, as the page sets it (`--lv-md`) for the window's width; on a network, the map's own size, drawn larger with the map. */
function matchFont(network = false): number {
  return network ? MATCH_FONT_MANY : Math.min(15.5, Math.max(12.5, 6 + 0.0046 * window.innerWidth));
}

/** On a network, the size of a match's title in the map's pixels, and the room between two matches. */
const MATCH_FONT_MANY = 13.5;
const MATCH_GAP_MANY = 12;

/** How many lines a match's words take when they wrap, two at most, near enough: a character is about half the font wide. */
function wrappedLines(chars: number, chip: boolean, width: number, most = 2, network = false): number {
  const font = matchFont(network);
  const words = (chip ? font * 9 : 0) + chars * font * 0.55;
  return Math.min(most, Math.max(1, Math.ceil(words / Math.max(1, width))));
}

/** The height of the matches, each a row with its chip, and a wrapped title one line of words taller. */
function matchesHeight(rows: readonly number[], network = false): number {
  const font = matchFont(network);
  return rows.reduce((sum, lines) => sum + font * 1.6 + (lines - 1) * font * 1.3, 0) + Math.max(0, rows.length - 1) * (network ? MATCH_GAP_MANY : MATCH_GAP);
}

/**
 * What one engine matched: at most two chips (three when that is all), then
 * how many more, and a match on the launcher line named on a quiet line of
 * its own, since it never counts. A late arrival takes one of the lines.
 */
function EngineMatches({
  lines,
  none,
  late,
  room: box,
  inline = false,
  where,
  when,
  earlier = null,
}: {
  lines: MatchLine[];
  none: boolean;
  late: LateLine | null;
  room: MatchRoom;
  inline?: boolean;
  where?: (alert: Alert) => string;
  when?: (alert: Alert) => string;
  /** On a network, the latest alert of an earlier step: named on a quiet line while the step on screen has no alert of its own. */
  earlier?: Alert | null;
}) {
  const counted = lines.filter((line) => line.kind !== "launcher");
  const launcher = lines.filter((line) => line.kind === "launcher");
  const lateLine = late ? <LateMatch late={late} /> : null;
  const showEarlier = earlier !== null && late?.alert.id !== earlier.id && !lines.some((line) => line.kind === "alert");
  const earlierLine =
    earlier && showEarlier ? (
      <div className="lv-match lv-match--earlier" title={`${earlier.rule.title} (rule ${earlier.rule.id})`}>
        <span className="lv-match-said">earlier</span>
        <MatchChip kind="alert" level={earlier.rule.level} />
        <span className="lv-match-title">{earlier.rule.title}</span>
        {where ? <span className="lv-match-where">{where(earlier)}</span> : null}
      </div>
    ) : null;
  if (lines.length === 0) {
    return (
      <div className="lv-matches">
        {none ? <div className="lv-match lv-match--none">{inline ? "no rule matched this step" : "no rule matched"}</div> : null}
        {lateLine}
        {earlierLine}
      </div>
    );
  }
  // Three lines at most: an engine's label must not reach the one below it.
  // On a network each match is a block of its own, two at most: the strongest, and the next, the rest counted.
  const wanted = inline ? (late || counted.length > 2 ? Math.min(2, late ? 1 : 2) : 2) : late ? (counted.length > 2 || launcher.length > 0 ? 1 : 2) : counted.length > 3 || (launcher.length > 0 && counted.length > 2) ? 2 : 3;
  // A long title wraps to a second line where the engine's box has room for every line it then takes; where it has not, each line keeps to one, cut short.
  // On a network a title is never cut, and an alert has a line under it that says where it was raised.
  const most = inline ? 4 : 2;
  const plan = (room: number, withEarlier: boolean) => {
    const shown = counted.slice(0, room);
    const rest = counted.slice(room);
    const review = rest.filter((line) => line.kind === "review" && line.alert.rule.level !== "informational").length;
    const info = rest.filter((line) => line.kind === "review" && line.alert.rule.level === "informational").length;
    const other = rest.length - review - info;
    const crowded = rest.length > 0 && launcher.length > 0;
    // On a network the rest are counted as rules, as the log counts them.
    const rules = (n: number): string => (inline ? (n === 1 ? " rule" : " rules") : "");
    // "more" is said once, at the head of the line, so that on one host the line keeps to the engine's box with its last words.
    const more = [review ? `${review} more${rules(review)} for review` : "", info ? `${info} ${inline || review ? "informational" : "more informational"}` : "", other ? `${other} more` : "", crowded ? `launcher line${launcher.length === 1 ? "" : ` (${launcher.length} rules)`}, not counted` : ""].filter(Boolean).join(" · ");
    const firstLauncher = crowded ? undefined : launcher[0];
    // On a network each match is a block: its chip on a line of its own, then its title whole, then where and when an alert was raised.
    const rows = [
      ...shown.map((line) => (inline ? 1 : 0) + wrappedLines(line.alert.rule.title.length + (line.count > 1 ? 4 : 0), !inline, box.width, most, inline) + (where && line.kind === "alert" ? 1 : 0) + (when && line.kind === "alert" && when(line.alert) ? 1 : 0)),
      ...(withEarlier && earlier ? [2 + wrappedLines(earlier.rule.title.length, false, box.width, most, inline) + (where ? 1 : 0)] : []),
      ...(more ? [wrappedLines(more.length + 2, false, box.width, 2, inline)] : []),
      ...(firstLauncher ? [wrappedLines(firstLauncher.alert.rule.title.length + 40, false, box.width, 2, inline)] : []),
      ...(late ? [1] : []),
    ];
    return { shown, rest, more, crowded, firstLauncher, withEarlier, tall: matchesHeight(rows, inline) > box.height };
  };
  // On a network nothing is cut and nothing runs under the defense's note: where the blocks do not fit, fewer are shown and the rest counted.
  let chosen = plan(wanted, showEarlier);
  if (inline && chosen.tall && wanted > 1) chosen = plan(1, showEarlier);
  if (inline && chosen.tall && showEarlier) chosen = plan(1, false);
  const { shown, rest, more, crowded, firstLauncher } = chosen;
  return (
    <div className={`lv-matches${!inline && chosen.tall ? " is-tight" : ""}`}>
      {shown.map((line) => (
        <div key={line.key} className="lv-match" title={line.alert.rule.title}>
          <MatchChip kind={line.kind} level={line.alert.rule.level} />
          <span className="lv-match-title">
            {line.alert.rule.title}
            {/* On a network the count follows the title's last word, a dim figure. */}
            {inline && line.count > 1 ? <span className="lv-match-count">&times;{line.count}</span> : null}
          </span>
          {!inline && line.count > 1 ? <span className="lv-match-count">&times;{line.count}</span> : null}
          {where && line.kind === "alert" ? <span className="lv-match-where">{where(line.alert)}</span> : null}
          {when && line.kind === "alert" && when(line.alert) ? <span className="lv-match-where is-when">{when(line.alert)}</span> : null}
        </div>
      ))}
      {chosen.withEarlier ? earlierLine : null}
      {more ? (
        <div className="lv-match lv-match--more" title={[...rest, ...(crowded ? launcher : [])].map((line) => `${line.alert.rule.title} (${line.kind === "launcher" ? "launcher line, not counted" : line.alert.rule.level})`).join("\n")}>
          <span className="lv-match-title">+ {more}</span>
        </div>
      ) : null}
      {firstLauncher ? (
        <div className="lv-match lv-match--more" title={`${launcher.map((line) => line.alert.rule.title).join(", ")}: matched only the shell command that carried the test, so it never counts`}>
          <span className="lv-match-title">
            launcher line, not counted: {firstLauncher.alert.rule.title}
            {launcher.length > 1 ? ` and ${launcher.length - 1} more` : ""}
          </span>
        </div>
      ) : null}
      {lateLine}
    </div>
  );
}

interface Light {
  key: string;
  path: string;
  rgb: string;
  strong: boolean;
  age: number;
}

function lightsOf(layout: NetworkLayout, moment: StepMoment, arrival: (id: string) => number): Light[] {
  const recent = moment.events.filter((event) => {
    const age = moment.now - arrival(event.id);
    return age >= 0 && age < TRAVEL;
  });
  let chosen = recent;
  if (recent.length > MAX_LIGHTS) {
    const keep = new Set(recent.filter((event) => moment.matchOf.has(event.id)));
    const step = recent.length / MAX_LIGHTS;
    for (let index = 0; index < recent.length && keep.size < MAX_LIGHTS; index += step) {
      const event = recent[Math.floor(index)];
      if (event) keep.add(event);
    }
    chosen = recent.filter((event) => keep.has(event));
  }
  const lights: Light[] = [];
  for (const event of chosen) {
    const own = moment.matchByDetector.get(event.id);
    for (const detector of layout.detectors) {
      const path = travelPath(layout, event.sensor, detector.detector.id);
      if (!path) continue;
      const kind = own?.get(detector.detector.id);
      const strong = kind === "alert" || kind === "lab";
      // On a network the stream is one quiet colour: only an alert's light takes its own, so the attack's path stays the strongest line.
      const plain = own && layout.single ? "255,210,125" : "123,202,255";
      lights.push({ key: `${event.id}>${detector.detector.id}`, path, rgb: kind && strong ? KIND_RGB[kind] : plain, strong, age: moment.now - arrival(event.id) });
    }
  }
  return lights;
}

interface MapViewProps extends NetworkMapProps {
  layout: NetworkLayout;
  arrival: (id: string) => number;
  /** The size of the map's box, as measured, in the map's own pixels: divided by `scale`. */
  box: { width: number; height: number };
  /** How much larger the map is drawn than it is laid out: 1 but for a network on a large stage. */
  scale: number;
}

function MapView({ recording, layout, moment, speed, seek, colours, labDetectors, arrival, box, scale, goalHost = null, raised = [], firstAlert = null, goalTime = null, runStart, stage, judges }: MapViewProps) {
  const step = moment?.step ?? null;
  // Of a run judged by several defenses, the sensors the chosen one records with: any other on the map is drawn unlit.
  const lit = useMemo(() => (stage ? new Set(recording.network.sensors.map((sensor) => sensor.id)) : null), [stage, recording]);
  const isOff = (sensorId: string): boolean => lit !== null && !lit.has(sensorId);
  const unseen = moment !== null && moment.revealed && moment.outcome === "unseen";
  const stopped = moment !== null && moment.revealed && moment.outcome === "stopped";
  const currentHost = step?.host ?? null;
  // Every sensor that recorded the step, on whatever host it runs: each shows its count, so the counts add up to the step's events.
  const byStep = useMemo(() => eventsByStep(recording), [recording]);
  const stepId = step?.id;
  const recordedStep = useMemo(() => new Set((stepId === undefined ? [] : (byStep.get(stepId) ?? [])).map((event) => event.sensor)), [byStep, stepId]);
  const silenceAt = currentHost === null ? undefined : layout.silenceAt.get(currentHost);
  const mixed = ranAtDifferentTimes(recording);

  // What each sensor recorded of this step so far, and when it last flashed.
  const perSensor = new Map<string, { count: number; last: { id: string; at: number } | null }>();
  for (const sensor of recording.network.sensors) perSensor.set(sensor.id, { count: 0, last: null });
  if (moment) {
    for (const event of moment.events) {
      const own = perSensor.get(event.sensor);
      if (!own) continue;
      own.count += 1;
      const at = arrival(event.id) + TRAVEL * TO_SENSOR;
      if (at <= moment.now) own.last = { id: event.id, at };
    }
  }
  const visibility = step?.visibility;
  const keptOnly = visibility?.kept !== undefined && visibility.events !== undefined && visibility.kept < visibility.events;

  // What each rule engine shows: the strongest match whose light has landed,
  // and a late arrival of an earlier step, which lights it again when raised.
  const engine = new Map<string, { kind: MatchKind; first: number; lines: MatchLine[]; late: LateLine | null }>();
  // A step's name is worked out once, however many late arrivals are its own.
  const labels = new Map<string, string>();
  const labelOf = (stepId: string): string => {
    let label = labels.get(stepId);
    if (label === undefined) {
      const owner = recording.steps.find((item) => item.id === stepId);
      label = owner ? stepLabel(recording, owner) : stepId;
      labels.set(stepId, label);
    }
    return label;
  };
  // Where an alert was raised, under its title on a network: the host, the step and the rule's own number, to look it up by;
  // then when the event it matched happened, and how long after it the alert was raised.
  const whereOf = (alert: Alert): string => `on ${recording.network.hosts.find((host) => host.id === alert.host)?.name ?? alert.host} · ${labelOf(alert.step)} · rule ${alert.rule.id}`;
  // One measure and one wording for an alert's delay on every part of the screen: from the end of its step.
  const whenOf = (alert: Alert): string => raisedAfterStep(alert, recording.steps.find((item) => item.id === alert.step)) ?? "";
  // On a network, the hosts alerts were raised on so far keep a mark, and the engine names the latest alert of an earlier step.
  const alertedHosts = new Set(layout.single ? [] : raised.map((alert) => alert.host));
  const earlierAlert = layout.single || !moment ? null : ([...raised].reverse().find((alert) => alert.step !== moment.step.id) ?? null);
  // On a network, a match of the step on screen raised after its body ended, in the silence after it, is the step's own:
  // the engine lists it with the step's other matches, strongest first, so the first alert is named as an alert where it lands.
  const ownLate = !layout.single && moment ? moment.late.filter((fire) => fire.alert.step === moment.step.id) : [];
  const ownLanded = moment ? (ownLate.length > 0 ? [...moment.landed, ...ownLate.map(({ alert, at }) => ({ alert, at }))] : moment.landed) : [];
  for (const node of layout.detectors) {
    const lines = moment ? matchLines(ownLanded, node.detector.id, !layout.single) : [];
    let kind: MatchKind | null = null;
    let first = Number.POSITIVE_INFINITY;
    for (const { alert, at } of ownLanded) {
      if (alert.detector !== node.detector.id) continue;
      const own = matchKind(alert);
      if (own === "launcher") continue;
      if (kind === null || kindRank(own) > kindRank(kind)) {
        kind = own;
        first = at;
      } else if (own === kind) first = Math.min(first, at);
    }
    let late: LateLine | null = null;
    // The names of the arrivals before the last one, in one list that grows with the walk:
    // a copy for every arrival would cost the square of their number at every frame.
    const earlier: string[] = [];
    for (const fire of moment?.late ?? []) {
      if (fire.alert.detector !== node.detector.id || ownLate.includes(fire)) continue;
      const own = matchKind(fire.alert);
      // On a network the engine names the strongest arrival, the latest of those as strong: an alert is never folded behind a match for review.
      if (late && !layout.single && kindRank(own) < kindRank(late.kind)) {
        earlier.push(`${fire.alert.rule.title} (${labelOf(fire.alert.step)})`);
        continue;
      }
      if (late) earlier.push(`${late.alert.rule.title} (${late.label})`);
      late = { alert: fire.alert, kind: own, label: labelOf(fire.alert.step), earlier };
      if (own !== "launcher" && (kind === null || kindRank(own) >= kindRank(kind))) {
        kind = own;
        first = fire.at;
      }
    }
    engine.set(node.detector.id, { kind: kind ?? "launcher", first, lines, late });
  }

  const lights = moment && moment.running && !unseen ? lightsOf(layout, moment, arrival) : [];
  const hostNode = layout.hosts.find((node) => node.host.id === currentHost) ?? null;
  const fromNode = step?.from ? (layout.hosts.find((node) => node.host.id === step.from) ?? null) : null;
  const sinceStart = moment ? moment.now - moment.segment.bodyStart : -1;
  const alerted = moment !== null && moment.revealed && moment.outcome === "alerted";
  // Where the map lists the defenses, the head of the defense's side names the one that judges.
  const ownHead = judges !== undefined && layout.defenseSide !== null;
  const heads = useMemo(() => headsOf(recording, layout, ownHead), [recording, layout, ownHead]);
  // The way the attacker came: the links the steps before this one crossed, and the one this step crosses.
  const stepIndex = moment ? moment.segment.index : -1;
  const trail = useMemo(() => crossedBefore(recording, stepIndex), [recording, stepIndex]);
  const crossing = step?.from ? linkBetween(layout, step.from, step.host) : null;
  // Each hop the steps so far made, once a pair of hosts, the way the latest of them went, with the numbers of the steps
  // that crossed it and how many steps ago the last of them did: older hops are fainter, so the map tells the order.
  const hops = useMemo(() => (layout.single ? [] : hopsOf(recording, layout, stepIndex)), [recording, stepIndex, layout]);
  const arrowId = `lv-arrow-${useId().replace(/[^a-zA-Z0-9_-]/g, "")}`;
  const goalNode = goalHost === null ? null : (layout.hosts.find((node) => node.host.id === goalHost) ?? null);
  const defenseNote = useMemo(() => (layout.defenseSide ? defenseWords(recording) : null), [recording, layout.defenseSide]);
  // The chip under a host an alert was raised on: the latest alert raised there so far, strong while its own step is on
  // screen, quieter after, with its time on the race line's clock; the run's first alert with the race line's mark.
  const alertLineOf = (id: string): HostAlert | null => {
    const alert = [...raised].reverse().find((item) => item.host === id);
    if (!alert) return null;
    const first = firstAlert !== null && firstAlert.id === alert.id;
    const time = first ? firstAlert.time : runStart === undefined ? "" : elapsed((alertMoment(alert) - runStart) / 1000);
    return { alert, strong: moment?.step.id === alert.step, first, time };
  };

  return (
    <div
      className={`lv-map${unseen ? " is-hush" : ""}${step?.outcome === "stopped" ? " is-calm" : ""}${layout.single ? " is-single" : " is-many"}${layout.least > 0 ? " is-tall" : ""}`}
      // The map fills its box, or, when it needs more room than the box gives, keeps its own size and the box scrolls.
      // A network, laid out at a width a little under its box's, stands in the middle of it.
      style={
        {
          "--lv-map-w": `${layout.width}px`,
          ...(layout.width > box.width || !layout.single ? { width: layout.width } : {}),
          ...(layout.width < box.width && !layout.single ? { left: Math.floor(((box.width - layout.width) / 2) * scale) } : {}),
          ...(layout.height > box.height ? { height: layout.height } : scale !== 1 ? { height: box.height } : {}),
          // Drawn larger on a large stage, from its top left corner: every host, line and word alike.
          ...(scale !== 1 ? { transform: `scale(${scale})`, transformOrigin: "0 0", "--lv-map-scale": scale } : {}),
        } as StyleVars
      }
    >
      <Stars width={layout.width} height={layout.height} />

      <div className="lv-glows" aria-hidden="true">
        {hostNode ? (
          <div className={`lv-glow lv-glow--host${moment?.running && !moment.ended ? " is-on" : ""}${alerted ? " is-alert" : ""}${stopped ? " is-stopped" : ""}`} style={{ left: hostNode.x, top: hostNode.y, width: hostNode.r * 6, height: hostNode.r * 6 }} />
        ) : null}
        {layout.detectors.map((node) => {
          const state = engine.get(node.detector.id);
          const kind = state?.kind ?? "launcher";
          return <div key={node.detector.id} className={`lv-glow lv-glow--engine is-${kind}`} style={{ left: node.x, top: node.y, width: node.r * 8, height: node.r * 8 }} />;
        })}
      </div>

      <svg className="lv-net" viewBox={`0 0 ${layout.width} ${layout.height}`} aria-hidden="true">
        <defs>
          <radialGradient id="lv-node-fill" cx="50%" cy="40%" r="60%">
            <stop offset="0" stopColor="#12304a" />
            <stop offset="1" stopColor="#07182a" />
          </radialGradient>
        </defs>
        {/* Each network told once: one soft outline round its hosts, so the eye sees a zone, not a web of links. */}
        {layout.zones.map((zone, index) => (zone.drawn ? <path key={`zone-${index}`} className="lv-zone" style={{ "--rgb": ZONE_RGB[index % ZONE_RGB.length] } as StyleVars} d={boxPath(zone.box)} /> : null))}
        {/* The defense's own side: its host and the rule engines, in a field of their own at the right. */}
        {layout.defenseSide ? <path className="lv-zone lv-zone--defense" style={{ "--rgb": "120,222,232" } as StyleVars} d={boxPath(layout.defenseSide.box)} /> : null}
        {layout.hosts.map((node) => <circle key={`halo-${node.host.id}`} className="lv-halo" cx={node.x} cy={node.y} r={node.r + (layout.single ? 26 : 14)} />)}
        {layout.single && layout.orbit.x > 0 && layout.hosts[0] ? <OrbitArc node={layout.hosts[0]} radius={layout.orbit} /> : null}
        {layout.links.map((line, index) => {
          const key = pairKey(line.from.host.id, line.to.host.id);
          const used = crossing?.line === line ? " is-used" : trail.has(key) ? " is-trail" : "";
          // A link of a zone is drawn only where the attack's path runs along it: the zone tells the rest. On a network the path is
          // drawn over the links below, each hop the way the attacker went.
          if (line.zone !== null && (used === "" || !layout.single)) return null;
          // Keyed by place: host ids may hold any character, so no joined text of them is sure to be one link's own.
          return <path key={`link-${index}`} className={`lv-link${layout.single ? used : ""}`} d={curvePath(line.curve)} />;
        })}
        {layout.single ? null : (
          <>
            <defs>
              <marker id={`${arrowId}-trail`} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" markerUnits="userSpaceOnUse" orient="auto">
                <path className="lv-arrow is-trail" d="M0,1 L9,5 L0,9 Z" />
              </marker>
              <marker id={`${arrowId}-used`} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="13" markerHeight="13" markerUnits="userSpaceOnUse" orient="auto">
                <path className="lv-arrow is-used" d="M0,1 L9,5 L0,9 Z" />
              </marker>
            </defs>
            {/* The way the attacker came, quiet, each hop pointing where it went and fainter the longer ago it ran; then the hop of the step on screen, the one line that glows. */}
            {hops.map((hop, index) => (crossing?.line === hop.line ? null : <path key={`hop-${index}`} className="lv-link is-trail" style={{ opacity: hopFade(hop.age) }} d={curvePath(hop.curve)} markerEnd={`url(#${arrowId}-trail)`} />))}
            {crossing ? <path className="lv-link is-used" d={curvePath(crossing.curve)} markerEnd={`url(#${arrowId}-used)`} /> : null}
            {/* A step that stays on its host lights a mark on it while it runs: the attack acts there. */}
            {hostNode && step && (!step.from || step.from === step.host) && moment?.running ? <path className="lv-loop" d={loopPath(hostNode)} markerEnd={`url(#${arrowId}-used)`} /> : null}
          </>
        )}
        {layout.sensors.map((node) => {
          const curve = layout.sensorToJunction.get(node.sensor.id);
          const used = (perSensor.get(node.sensor.id)?.last ?? null) !== null;
          return curve ? <path key={`sj-${node.sensor.id}`} className={`lv-wire lv-wire--sj${used ? " is-used" : ""}${isOff(node.sensor.id) ? " is-off" : ""}`} d={curvePath(curve)} /> : null;
        })}
        {layout.detectors.map((node) => {
          const curve = layout.junctionToDetector.get(node.detector.id);
          const kind = engine.get(node.detector.id)?.kind ?? "launcher";
          return curve ? <path key={`jd-${node.detector.id}`} className={`lv-wire lv-wire--jd is-${kind}`} d={curvePath(curve)} /> : null;
        })}
        {layout.sensors.map((node) => {
          const curve = layout.hostToSensor.get(node.sensor.id);
          return curve ? <path key={`hs-${node.sensor.id}`} className={`lv-wire lv-wire--hs${node.sensor.host === currentHost && !isOff(node.sensor.id) ? " is-current" : ""}${isOff(node.sensor.id) ? " is-off" : ""}`} d={curvePath(curve)} /> : null;
        })}
        {layout.junction.hostId === null ? (
          <g className="lv-junction">
            <circle cx={layout.junction.x} cy={layout.junction.y} r={9} />
            <circle className="lv-junction-dot" cx={layout.junction.x} cy={layout.junction.y} r={2.6} />
          </g>
        ) : null}
        {layout.hosts.map((node) => {
          const current = node.host.id === currentHost;
          // The host the step came from is lit too: the attack's path reads from where it started to where it reached.
          const from = !layout.single && fromNode === node && !current && moment?.running === true;
          const classes = [`lv-host`, `lv-host--${node.host.kind}`, current ? "is-current" : "", current && moment?.running ? "is-running" : "", current && alerted ? "is-alerted" : "", current && stopped ? "is-stopped" : "", current && unseen ? "is-unseen" : "", from ? "is-from" : "", goalNode === node ? "is-goal" : ""].filter(Boolean).join(" ");
          return (
            <g key={node.host.id} className={classes}>
              <circle className="lv-host-body" cx={node.x} cy={node.y} r={node.r} fill="url(#lv-node-fill)" />
              <HostGlyph node={node} />
              <circle className="lv-host-ring" cx={node.x} cy={node.y} r={node.r + 14} pathLength={100} />
              {goalNode === node ? <GoalMark node={node} /> : null}
            </g>
          );
        })}
        {layout.sensors.map((node) => {
          const rgb = colours.get(node.sensor.id) ?? "123,202,255";
          const off = isOff(node.sensor.id);
          const crossed = unseen && node.sensor.host === currentHost && !off;
          return (
            <g key={node.sensor.id} className={`lv-sensor${crossed ? " is-crossed" : ""}${off ? " is-off" : ""}`} style={{ "--rgb": rgb } as StyleVars}>
              <circle className="lv-sensor-body" cx={node.x} cy={node.y} r={node.r} fill="url(#lv-node-fill)" />
              <title>{`${node.sensor.name}: records ${node.sensor.records}${off ? ". Not used by the defense that is judging." : ""}`}</title>
              <circle className="lv-sensor-ring" cx={node.x} cy={node.y} r={node.r * 0.42} />
              <circle className="lv-sensor-dot" cx={node.x} cy={node.y} r={Math.max(1.6, node.r * 0.13)} />
              {crossed ? (
                <g className="lv-cross">
                  <line x1={node.x - node.r * 0.9} y1={node.y - node.r * 0.9} x2={node.x + node.r * 0.9} y2={node.y + node.r * 0.9} />
                  <line x1={node.x + node.r * 0.9} y1={node.y - node.r * 0.9} x2={node.x - node.r * 0.9} y2={node.y + node.r * 0.9} />
                </g>
              ) : null}
            </g>
          );
        })}
        {layout.detectors.map((node) => {
          const lab = labDetectors.has(node.detector.id);
          const kind = engine.get(node.detector.id)?.kind ?? "launcher";
          return (
            <g key={node.detector.id} className={`lv-engine${lab ? " lv-engine--lab" : ""} is-${kind}`}>
              <polygon className="lv-engine-body" points={hexagon(node.x, node.y, node.r)} fill="url(#lv-node-fill)" />
              <polygon className="lv-engine-core" points={hexagon(node.x, node.y, node.r * 0.5)} />
              <polygon className="lv-engine-edge" points={hexagon(node.x, node.y, node.r + 3)} />
            </g>
          );
        })}
      </svg>

      <div className="lv-motion" aria-hidden="true">
        {lights.map((light) => (
          <Motion key={`${seek}:${light.key}`} className={`lv-light${light.strong ? " is-strong" : ""}`} age={light.age} length={TRAVEL} speed={speed} style={{ offsetPath: `path("${light.path}")`, "--rgb": light.rgb }} />
        ))}
        {hostNode && moment && sinceStart >= 0 && sinceStart < 1.2 ? (
          <Motion key={`${seek}:launch:${moment.step.id}`} className="lv-ring lv-ring--launch" age={sinceStart} length={1.2} speed={speed} style={{ left: hostNode.x, top: hostNode.y, width: hostNode.r * 2, height: hostNode.r * 2 }} />
        ) : null}
        {fromNode && hostNode && moment && sinceStart >= -0.4 && sinceStart < 0.6 ? (
          <Motion key={`${seek}:cross:${moment.step.id}`} className="lv-light lv-light--cross is-strong" age={sinceStart + 0.4} length={1} speed={speed} style={{ offsetPath: `path("${crossing ? curvePath(crossing.curve) : `M${fromNode.x},${fromNode.y} L${hostNode.x},${hostNode.y}`}")`, "--rgb": "255,112,69" }} />
        ) : null}
        {hostNode && moment && unseen && moment.now - moment.revealAt < 2 ? (
          <Motion key={`${seek}:hush:${moment.step.id}`} className="lv-ring lv-ring--hush" age={moment.now - moment.revealAt} length={2} speed={speed} style={{ left: hostNode.x, top: hostNode.y, width: (hostNode.r + 14) * 2, height: (hostNode.r + 14) * 2 }} />
        ) : null}
        {layout.sensors.map((node) => {
          const last = perSensor.get(node.sensor.id)?.last;
          if (!last || !moment || moment.now - last.at > 0.8) return null;
          return <Motion key={`${seek}:${last.id}`} className="lv-ring lv-ring--sensor" age={moment.now - last.at} length={0.8} speed={speed} style={{ left: node.x, top: node.y, width: node.r * 2 + 4, height: node.r * 2 + 4, "--rgb": colours.get(node.sensor.id) ?? "123,202,255" }} />;
        })}
        {layout.detectors.map((node) => {
          const state = engine.get(node.detector.id);
          if (!state || state.kind === "launcher" || !moment || moment.now - state.first > 1.4) return null;
          return <Motion key={`${seek}:${moment.step.id}:${node.detector.id}:${state.kind}:${state.first}`} className={`lv-ring lv-ring--engine is-${state.kind}`} age={moment.now - state.first} length={1.4} speed={speed} style={{ left: node.x, top: node.y, width: node.r * 2 + 8, height: node.r * 2 + 8 }} />;
        })}
      </div>

      <div className="lv-labels">
        {heads}
        {ownHead && judges && layout.defenseSide ? <DefenseSideHead judges={judges} left={layout.detectorsHeadX} width={layout.defenseSide.box[2] - 16 - layout.detectorsHeadX} /> : null}
        {judges && layout.defenseSide?.rows ? <DefenseSideRows judges={judges} box={layout.defenseSide.rows} mapHeight={layout.height} /> : null}
        {layout.defenseSide?.note && defenseNote ? (
          <div className="lv-defense-note" style={{ left: layout.defenseSide.note.x, top: layout.defenseSide.note.y, width: layout.defenseSide.noteWidth }} title={defenseNote}>
            <i className="lv-agent-dot" aria-hidden="true" />
            {defenseNote}
          </div>
        ) : null}
        {hops.map((hop, index) => (
          <div key={`hop-number-${index}`} className={`lv-hop-number${hop.age === 0 ? " is-current" : ""}`} style={{ left: hop.label.x, top: hop.label.y, opacity: Math.max(0.75, hopFade(hop.age)) }} title={hop.words}>
            {hop.numbers}
          </div>
        ))}
        {layout.links.map((line, index) =>
          line.link.label && line.told && line.zone === null ? (
            <div key={`label-${index}`} className="lv-link-label" style={{ left: line.label.x, top: line.label.y }}>
              {line.link.label}
            </div>
          ) : null,
        )}
        {/* A field whose corners are all taken is not named on the map. */}
        {layout.zones.map((zone, index) =>
          zone.drawn && zone.label ? (
            <div key={`zone-label-${index}`} className="lv-zone-label" style={{ left: zone.label.x, top: zone.label.y, "--rgb": ZONE_RGB[index % ZONE_RGB.length] } as StyleVars} title={`${capital(zoneSaid(zone.name))}: ${listWords(zone.hosts.map((id) => recording.network.hosts.find((host) => host.id === id)?.name ?? id))}`}>
              {zone.words}
            </div>
          ) : null,
        )}
        {layout.hosts.map((node) => (
          <HostLabel
            key={node.host.id}
            node={node}
            single={layout.single}
            commandLines={layout.commandLines}
            moment={node.host.id === currentHost ? moment : null}
            goal={goalNode === node}
            sensors={recording.network.sensors.filter((sensor) => sensor.host === node.host.id)}
            map={layout}
            count={!stage && node.counted && moment?.running ? layout.sensors.filter((item) => item.sensor.host === node.host.id && !item.named).reduce((sum, item) => sum + (perSensor.get(item.sensor.id)?.count ?? 0), 0) : null}
            countedName={layout.sensors.find((item) => item.sensor.host === node.host.id && !item.named)?.sensor.name ?? null}
            // Of a run judged by several defenses, each sensor of the chosen one that stands by the host has a line of its own.
            counts={
              stage && node.counted && moment?.running
                ? layout.sensors.filter((item) => item.sensor.host === node.host.id && !item.named && !isOff(item.sensor.id)).map((item) => ({ word: sensorKind(item.sensor.name), count: perSensor.get(item.sensor.id)?.count ?? 0, rgb: colours.get(item.sensor.id) ?? "123,202,255" }))
                : undefined
            }
            keptOnly={keptOnly}
            alert={alertedHosts.has(node.host.id) ? alertLineOf(node.host.id) : null}
            goalTime={goalTime}
            networks={listWords(layout.zones.filter((zone) => zone.hosts.includes(node.host.id)).map((zone) => zoneSaid(zone.name)))}
          />
        ))}
        {layout.sensors.map((node) => {
          const own = perSensor.get(node.sensor.id);
          const onStep = moment !== null && moment.running && (node.sensor.host === currentHost || recordedStep.has(node.sensor.id));
          const crossed = unseen && node.sensor.host === currentHost;
          // A small sensor's name stands level with it; above its host, its count of events goes above the name.
          const level = node.above ? { bottom: layout.height - (node.y + 9) } : { top: node.y - 9 };
          const place: StyleVars = node.small
            ? node.side < 0
              ? { right: layout.width - (node.x - node.r - 6), ...level }
              : { left: node.x + node.r + 6, ...level }
            : node.above
              ? { left: node.x + node.r + 10, bottom: layout.height - node.y + 6 }
              : { left: node.x + node.r + 10, top: node.y + 6 };
          const style: StyleVars = { ...place, "--rgb": colours.get(node.sensor.id) ?? "123,202,255" };
          // A name is cut where the layout says: a large sensor's stops short of the rule engines or a defense host level with it.
          const cut = node.small || node.cut < SENSOR_NAME_LARGE ? { maxWidth: node.cut } : undefined;
          // A sensor whose name the network's head tells once is a dot by its host: its count is a line under the host's role.
          if (!node.named) return null;
          return (
            <div key={node.sensor.id} className={`lv-sensor-label${node.small ? " is-small" : ""}${node.side < 0 ? " is-flip" : ""}${node.above ? " is-above" : ""}${node.inline ? " is-inline" : ""}`} style={style}>
              <div className="lv-sensor-name" title={`${node.sensor.name}: records ${node.sensor.records}`}>
                {node.small ? null : <i className="lv-dot" />}
                {/* A long name is cut where the map placed its words; the whole of it is in the title and in its host's detail. */}
                <span className="lv-cut" style={cut}>
                  {node.sensor.name}
                </span>
              </div>
              {onStep ? <div className={`lv-sensor-count${crossed ? " is-zero" : ""}`}>{plural(own?.count ?? 0, "event")}</div> : null}            </div>
          );
        })}
        {layout.detectors.map((node) => {
          const parts = detectorParts(node.detector.name);
          const lab = labDetectors.has(node.detector.id);
          const state = engine.get(node.detector.id);
          // On a network the words keep to the page's side margin, as the buttons and the log do.
          const width = Math.max(160, layout.width - (node.x + node.r + 16) - (layout.single ? 12 : ENGINE_EDGE));
          // The matches have the room between the engine's name and the next engine's label, or the map's bottom.
          // On a network the line about the sensors stands at the foot of the defense's side, under the matches.
          // Where the map lists the defenses at the foot of the side, the matches end above that list.
          const foot = judges && layout.defenseSide?.rows ? layout.defenseSide.rows[1] - 8 : layout.defenseSide?.note ? layout.defenseSide.note.y - 8 : layout.height;
          const below = layout.detectors.filter((other) => other.y > node.y).reduce((lowest, other) => Math.min(lowest, other.y - 15), foot);
          // On a map drawn larger, the engines' words are drawn larger with it, as the hosts' are: the alert reads at least as large as a host's name.
          const room = { width, height: below - (node.y - 15) - ENGINE_HEAD };
          return (
            <div key={node.detector.id} className="lv-engine-label" style={{ left: node.x + node.r + 16, top: node.y - 15, maxWidth: width }}>
              <div className="lv-engine-name" title={node.detector.name}>
                <span className="lv-cut">{parts.main}</span>
              </div>
              <div className="lv-engine-sub" title={lab ? "Not scored: ad hoc local rules, shown apart from the rules in this defense and never counted in the score" : parts.engine ? `Run by ${parts.engine}` : undefined}>
                {node.detector.rules > 0 ? plural(node.detector.rules, "rule") : parts.engine}
                {lab ? " · not counted in the score" : null}
                {/* When the engines did not all run at the same time, each says when it ran, and so how its alerts' times read. */}
                {mixed ? <span title={node.detector.when === "live" ? "It judged the events as they arrived: an alert's time is when it was raised" : "It ran after the run: an alert's time is the time of the event it matched"}>{` · ${node.detector.when === "live" ? "live" : "after the run"}`}</span> : null}
              </div>
              {moment ? <EngineMatches lines={state?.lines ?? []} none={moment.revealed && !moment.heard.some((alert) => alert.detector === node.detector.id)} late={state?.late ?? null} room={room} inline={!layout.single} where={layout.single ? undefined : whereOf} when={layout.single ? undefined : whenOf} earlier={earlierAlert?.detector === node.detector.id ? earlierAlert : null} /> : null}
            </div>
          );
        })}
        {unseen && moment && silenceAt ? (
          <div className="lv-silence is-near" style={{ left: silenceAt.x, top: silenceAt.y, width: SILENCE_WORDS.width, height: SILENCE_WORDS.height }}>
            <b>
              It <em>took effect</em>.
            </b>
            {step ? <span title={`${capital(unseenWords(step))}.`}>{capital(unseenWords(step))}.</span> : null}
          </div>
        ) : unseen && moment ? (
          <div className="lv-silence" style={{ left: layout.silence.x, top: layout.silence.y }}>
            <b>
              It <em>took effect</em>.
            </b>
            {step ? <span>{capital(unseenWords(step))}.</span> : null}
          </div>
        ) : null}
      </div>
    </div>
  );
}

/** Where an attack path reached its goal: a bright ring round the host, the white of the race line's goal diamond. */
function GoalMark({ node }: { node: HostNode }) {
  return (
    <g className="lv-goal-mark">
      <circle cx={node.x} cy={node.y} r={node.r + 7} />
    </g>
  );
}

function OrbitArc({ node, radius }: { node: HostNode; radius: { x: number; y: number } }) {
  const a0 = (-52 * Math.PI) / 180;
  const a1 = (52 * Math.PI) / 180;
  return <path className="lv-orbit" d={`M${node.x + radius.x * Math.cos(a0)},${node.y + radius.y * Math.sin(a0)} A${radius.x},${radius.y} 0 0 1 ${node.x + radius.x * Math.cos(a1)},${node.y + radius.y * Math.sin(a1)}`} />;
}

interface HostLabelProps {
  node: HostNode;
  single: boolean;
  moment: StepMoment | null;
  /** The host's own sensors, named whole in its detail. */
  sensors: readonly Sensor[];
  /** The map's size: a host in its lower part opens its detail above it, and the detail stays within the map's width. */
  map: { width: number; height: number };
  /** The lines of the step's command under a single host. */
  commandLines: 1 | 2;
  /** True when the attack path's goal was reached on this host: its badge says so while the step that reached it is on screen. */
  goal?: boolean;
  /** On a network, the events of the step that the host's sensor named in the head recorded, while a step runs. Null otherwise. */
  count?: number | null;
  /** The name of the sensor that count is of: its kind is said beside the count. */
  countedName?: string | null;
  /** True when the recording kept fewer of the step's events than were recorded: the count says "kept". */
  keptOnly?: boolean;
  /** On a network, the latest alert raised on the host so far: its chip under the host's words. */
  alert?: HostAlert | null;
  /** On a network, the zones the host is on, in words: its detail says them, a bridge's two. */
  networks?: string;
  /** The goal's time as the race line gives it: said in the goal's badge. */
  goalTime?: string | null;
  /**
   * Of a run judged by several defenses, while a step runs: what each sensor of the chosen defense that stands by the
   * host recorded of the step, each on a line of its own under the role, by its kind and in its colour.
   */
  counts?: { word: string; count: number; rgb: string }[];
}

/** A sensor's kind in a word, for its count under its host: "agent" of "Wazuh agent 4.14.10", "packets" of "Packets (placeholder)". */
function sensorKind(name: string): string {
  const words = sensorShortName(name.replace(/\s*\([^)]*\)/g, "")).split(/\s+/).filter(Boolean);
  return (words.length === 2 ? (words[1] ?? "") : words.join(" ")).toLowerCase();
}

/** An alert raised on a host, as the chip under its words tells it. */
interface HostAlert {
  alert: Alert;
  /** True while the alert's own step is on screen: the chip is strong, then quieter at every later moment. */
  strong: boolean;
  /** True for the run's first alert: it carries the race line's mark. */
  first: boolean;
  /** Its time on the race line's clock: "01:01.6". */
  time: string;
}

/** What a badge's words mean, for a reader who meets them first. */
const BADGE_TITLES: Partial<Record<string, string>> = {
  running: "The step is running on this host",
  "took effect": "The step did what it set out to do: its own check of its effect passed",
  "no effect": "The step ran, and its own check found it had no effect",
  stopped: "A hardening change stopped the step",
  "goal reached": "The attack path reached its goal on this host",
};

/** The widest a host's detail is drawn, as the map's style says (320 pixels of words and 11 of padding each side), and its least distance from the map's edges. */
const DETAIL_MOST = 342;
const DETAIL_MARGIN = 8;
/** The width of a host's words on a map of one host, as the map's style says. */
const SINGLE_LABEL = 340;

function HostLabel({ node, single, commandLines, moment, sensors, map, goal = false, count = null, countedName = null, keptOnly = false, alert = null, networks = "", goalTime = null, counts }: HostLabelProps) {
  const host = node.host;
  const sensorsWords = sensors.map((sensor) => `${sensor.name}: records ${sensor.records}`).join("\n");
  const told = badgeOf(moment);
  // The badge says what the step did, on one host or many; an alert raised on the host is its chip under its words.
  const badge = goal && moment?.running ? { text: "goal reached", className: "is-goal" } : told;
  // A sensor named once in the head is told by its kind beside its count: "agent · 513 events". The word is the counted sensor's own.
  const short = countedName ? sensorShortName(countedName).split(/\s+/) : [];
  const agent = short.length === 2 ? (short[1] ?? "") : short.join(" ");
  const os = shortOs(host);
  const roleWidth = node.roleWidth;
  const detailId = useId();
  const top = node.y + node.r + (single ? 10 : 8);
  // The detail opens under the host's words, or above the host when it stands low on the map, centred on the host as far as the map's edges allow.
  const low = node.y > map.height * 0.55;
  const centre = Math.max(DETAIL_MOST / 2 + DETAIL_MARGIN, Math.min(map.width - DETAIL_MOST / 2 - DETAIL_MARGIN, node.x));
  const place = low ? { left: centre, bottom: map.height - (node.y - node.r - 6) } : { left: centre, top: top + 4 };
  // On a map of one host, the host's words stay on the map: a host near its left edge has narrower words, cut where they end.
  const singleWidth = Math.min(SINGLE_LABEL, 2 * (node.x - DETAIL_MARGIN));
  const width = roleWidth !== null ? { width: roleWidth + 40 } : singleWidth < SINGLE_LABEL ? { width: singleWidth } : {};
  return (
    <>
      {badge ? (
        <div className={`lv-badge ${badge.className}`} style={{ left: node.badge.x, top: node.badge.y }} title={BADGE_TITLES[badge.text]}>
          {badge.text}
          {/* The goal's place on the map says its time, as the race line does. */}
          {badge.className === "is-goal" && goalTime ? <b className="lv-badge-time">{goalTime}</b> : null}
        </div>
      ) : null}
      {/* A long name or role is cut where the map placed it; the whole of it, the host's addresses and its sensors are in its detail, open by pointer or by keyboard. */}
      <div className={`lv-host-label${single ? "" : " is-small"}`} style={{ left: node.x, top, ...width }} tabIndex={0} aria-describedby={detailId}>
        <div className="lv-host-name" style={roleWidth === null ? undefined : { maxWidth: roleWidth + 12 }}>
          {host.name}
        </div>
        {single && host.kind === "host" ? (
          <div className={`lv-host-command${commandLines === 1 ? " is-one-line" : ""}`} title={plainMarks(moment?.step.command ?? "")}>
            {moment?.step.command ? (
              <span>
                <FreeText text={moment.step.command} />
              </span>
            ) : null}
          </div>
        ) : null}
        <div className="lv-host-role" title={host.os ?? ""} style={roleWidth === null ? undefined : { maxWidth: roleWidth + 12 }}>
          {single
            ? host.role
            : roleParts(host.role).map((part, index) => (
                <span key={index} className={index > 0 ? "is-note" : undefined}>
                  {part}
                </span>
              ))}
          {single && os ? ` · ${os}` : ""}
        </div>
        {/* What the host's sensor, named once in the head, recorded of the step: on a line of its own, under the role. */}
        {count !== null ? (
          <div className={`lv-host-count${count === 0 ? (moment?.revealed && moment.outcome === "unseen" ? " is-zero" : " is-none") : ""}`} title={sensorsWords}>
            <i className="lv-agent-dot" aria-hidden="true" />
            {agent ? `${agent} · ` : ""}
            {/* Where the recording kept fewer of the step's events than were recorded, the count says it counts the kept ones, as the log's head does. */}
            {keptOnly && count > 0 ? `${count.toLocaleString("en-US")} kept` : plural(count, "event")}
          </div>
        ) : null}
        {(counts ?? []).map((item, index) => (
          <div key={index} className={`lv-host-count${item.count === 0 ? (moment?.revealed && moment.outcome === "unseen" ? " is-zero" : " is-none") : ""}`} title={sensorsWords} style={{ "--rgb": item.rgb } as StyleVars}>
            <i className="lv-agent-dot is-own" aria-hidden="true" />
            {item.word ? `${item.word} · ` : ""}
            {/* Only a sensor whose events the recording cut says "kept": a step keeps the first few hundred of each. */}
            {keptOnly && item.count >= 300 ? `${item.count.toLocaleString("en-US")} kept` : plural(item.count, "event")}
          </div>
        ))}
        {/* An alert raised on the host: its chip under the host's words, strong when it fires and quieter after, with its time. */}
        {alert ? (
          <div className={`lv-host-alert${alert.strong ? " is-strong" : ""}`} title={`An alert was raised on ${host.name}: ${alert.alert.rule.title} (rule ${alert.alert.rule.id})${alert.time ? `, at ${alert.time} into the run` : ""}`}>
            <span className="lv-chip lv-chip--alert">alert &middot; {alert.alert.rule.level}</span>
            {alert.time ? <span className={`lv-host-alert-time${alert.first ? " is-first" : ""}`}>{alert.first ? `first alert ${alert.time}` : alert.time}</span> : null}
          </div>
        ) : null}
      </div>
      <div className={`lv-host-detail${low ? " is-above" : ""}`} id={detailId} role="tooltip" style={place}>
        <b>{host.name}</b>
        <span>{host.role}</span>
        {host.os ? <span>{host.os}</span> : null}
        {networks ? <span>{`On ${networks}`}</span> : null}
        <span>{host.addresses && host.addresses.length > 0 ? `${host.addresses.length === 1 ? "Address" : "Addresses"}: ${host.addresses.join(", ")}` : "No address recorded"}</span>
        {sensors.map((sensor, index) => (
          <span key={index}>{`${sensor.name}: records ${sensor.records}`}</span>
        ))}
      </div>
    </>
  );
}

/** A field's box, a zone's or the defense's, as an SVG path: a rectangle with large rounded corners. */
function boxPath(box: Box): string {
  const [x0, y0, x1, y1] = box;
  const r = Math.min(ZONE_RADIUS, (x1 - x0) / 2, (y1 - y0) / 2);
  const f = (value: number): string => value.toFixed(1);
  const arc = (x: number, y: number): string => `A${f(r)},${f(r)} 0 0 1 ${f(x)},${f(y)}`;
  return `M${f(x0 + r)},${f(y0)} L${f(x1 - r)},${f(y0)} ${arc(x1, y0 + r)} L${f(x1)},${f(y1 - r)} ${arc(x1 - r, y1)} L${f(x0 + r)},${f(y1)} ${arc(x0, y1 - r)} L${f(x0)},${f(y0 + r)} ${arc(x0 + r, y0)} Z`;
}

/** Names in a list: "web", "web and db", "web, db and build". */
function listWords(items: readonly string[]): string {
  return items.length > 1 ? `${items.slice(0, -1).join(", ")} and ${items[items.length - 1] ?? ""}` : (items[0] ?? "");
}

/** One key for a pair of hosts, whichever way round. */
function pairKey(a: string, b: string): string {
  return a < b ? `${a}\n${b}` : `${b}\n${a}`;
}

/** A hop of the attack's path on a network: a drawn link the steps crossed, the way the latest of them went. */
export interface Hop {
  line: LinkLine;
  curve: Curve;
  /** The numbers of the steps that crossed it, in order: "5 · 9". */
  numbers: string;
  /** How many steps before the one on screen the latest of them ran: 0 when the step on screen crosses it. */
  age: number;
  /** The hop in words, for its tooltip: "Test 5 and test 9, from web to build". */
  words: string;
  /** Where its numbers stand: beside the line, never on it. */
  label: Point;
}

/** The hops of the steps up to the one at `index`, each with its steps' numbers and its age. */
export function hopsOf(recording: Recording, layout: NetworkLayout, index: number): Hop[] {
  const numbers = testNumbers(recording);
  const pairs = new Map<string, { from: string; to: string; numbers: string[]; names: string[]; last: number }>();
  recording.steps.slice(0, Math.max(0, index + 1)).forEach((item, at) => {
    if (!item.from || item.from === item.host) return;
    const key = pairKey(item.from, item.host);
    const known = pairs.get(key) ?? { from: item.from, to: item.host, numbers: [], names: [], last: at };
    known.numbers.push(String(numbers.get(item.id) ?? at + 1));
    known.names.push(stepLabel(recording, item));
    pairs.set(key, { ...known, from: item.from, to: item.host, last: at });
  });
  const name = (id: string): string => recording.network.hosts.find((host) => host.id === id)?.name ?? id;
  return [...pairs.values()].flatMap((hop): Hop[] => {
    const found = linkBetween(layout, hop.from, hop.to);
    if (!found) return [];
    const steps = hop.names.length > 1 ? `${hop.names.slice(0, -1).join(", ")} and ${hop.names[hop.names.length - 1] ?? ""}` : (hop.names[0] ?? "");
    const numbers = hop.numbers.join(" · ");
    return [{ ...found, numbers, age: index - hop.last, words: `${capital(steps)}, from ${name(hop.from)} to ${name(hop.to)}`, label: hopLabel(found.line, found.curve, layout, numbers) }];
  });
}

/** How strong a hop of the way the attacker came is drawn, by how many steps ago it was last crossed: the latest strongest. */
const hopFade = (age: number): number => (age <= 0 ? 1 : Math.max(0.38, 1 - age * 0.11));

/** Half the width and height of a hop's numbers as the map draws them (11 px, tabular figures), a little generous. */
function hopLabelHalf(numbers: string): { x: number; y: number } {
  return { x: (numbers.length * 11 * 0.62) / 2, y: 7 };
}

/** Pixels kept clear between a hop's numbers and the middle of its own line: half the lit line's width and clear air. */
export const HOP_LABEL_CLEAR = 6;

/** The least distance from a point to a box: 0 inside it. */
function distanceToBox(point: Point, box: Box): number {
  const dx = Math.max(box[0] - point.x, 0, point.x - box[2]);
  const dy = Math.max(box[1] - point.y, 0, point.y - box[3]);
  return Math.hypot(dx, dy);
}

/**
 * Where a hop's numbers stand: beside its line near the host it reached, on the side where they cover the least of
 * the hosts and their words, as far off the line as their own size and the line's direction need, so that every part
 * of the line, lit or not, stays `HOP_LABEL_CLEAR` pixels from them.
 */
function hopLabel(own: LinkLine, curve: Curve, layout: NetworkLayout, numbers: string): Point {
  const half = hopLabelHalf(numbers);
  const ownPoints = Array.from({ length: 101 }, (_, index) => pointOn(curve, index / 100));
  // The hosts, their words under them, the place of their badge above them, and their badge where it stands: beside a
  // host in a short room, as wide as the goal's.
  const taken: Box[] = layout.hosts.flatMap((node): Box[] => [
    [node.x - node.r - 10, node.y - node.r - 10, node.x + node.r + 10, node.y + node.r + 10],
    [node.x - 92, node.y + node.r + 6, node.x + 92, node.y + node.r + 70],
    [node.x - 66, node.y - node.r - 46, node.x + 66, node.y - node.r - 18],
    badgeBoxOf(node),
  ]);
  // The other lines: the sensors' lines to the defense and the links, so the numbers stand clear of every line.
  const lines: Point[] = [];
  const sample = (other: Curve) => {
    if (other === curve) return;
    for (let u = 0.04; u < 1; u += 0.04) lines.push(pointOn(other, u));
  };
  for (const other of layout.sensorToJunction.values()) sample(other);
  // A link of a zone is drawn only where the path runs; any other link is always drawn.
  for (const item of layout.links) if (item !== own && item.zone === null) sample(item.curve);
  let best: { score: number; point: Point } | null = null;
  for (const u of [0.72, 0.6, 0.82, 0.5, 0.4, 0.3]) {
    const on = pointOn(curve, u);
    const ahead = pointOn(curve, Math.min(1, u + 0.02));
    const length = Math.hypot(ahead.x - on.x, ahead.y - on.y) || 1;
    const normal = { x: -(ahead.y - on.y) / length, y: (ahead.x - on.x) / length };
    for (const side of [1, -1]) {
      // Off the line by the reach of the numbers' box along the line's normal, then further where the line bends near.
      let away = half.x * Math.abs(normal.x) + half.y * Math.abs(normal.y) + HOP_LABEL_CLEAR;
      const at = (distance: number): Point => ({ x: on.x + normal.x * side * distance, y: on.y + normal.y * side * distance });
      const boxAt = (point: Point): Box => [point.x - half.x, point.y - half.y, point.x + half.x, point.y + half.y];
      while (away < 60 && ownPoints.some((item) => distanceToBox(item, boxAt(at(away))) < HOP_LABEL_CLEAR)) away += 1;
      const point = at(away);
      // Short numbers keep the room of two figures from words and other lines, so they never read as part of them.
      const box: Box = [point.x - Math.max(half.x, 12), point.y - Math.max(half.y, 8), point.x + Math.max(half.x, 12), point.y + Math.max(half.y, 8)];
      // Above the line reads first, and the nearer the host it reached, the better.
      let score = Math.abs(u - 0.72) * 4 + (point.y > on.y ? 0.5 : 0);
      for (const other of taken) {
        const w = Math.max(0, Math.min(box[2], other[2]) - Math.max(box[0], other[0]));
        const h = Math.max(0, Math.min(box[3], other[3]) - Math.max(box[1], other[1]));
        score += (w * h) / 40;
      }
      for (const other of lines) if (other.x > box[0] - 4 && other.x < box[2] + 4 && other.y > box[1] - 4 && other.y < box[3] + 4) score += 6;
      if (!best || score < best.score) best = { score, point };
    }
  }
  return best?.point ?? pointOn(curve, 0.5);
}

/** A mark on a host for a step that stays on it: a short bright arc round the upper left of its ring, pointing on. */
function loopPath(node: HostNode): string {
  const r = node.r + 9;
  const at = (degrees: number): Point => ({ x: node.x + r * Math.cos((degrees * Math.PI) / 180), y: node.y + r * Math.sin((degrees * Math.PI) / 180) });
  const start = at(196);
  const end = at(256);
  return `M${start.x.toFixed(1)},${start.y.toFixed(1)} A${r},${r} 0 0 1 ${end.x.toFixed(1)},${end.y.toFixed(1)}`;
}

/** The pairs of hosts that the steps before the one at `index` crossed, from their `from` to their `host`. */
function crossedBefore(recording: Recording, index: number): Set<string> {
  const pairs = new Set<string>();
  for (const step of recording.steps.slice(0, Math.max(0, index))) if (step.from && step.from !== step.host) pairs.add(pairKey(step.from, step.host));
  return pairs;
}

function badgeOf(moment: StepMoment | null): { text: string; className: string } | null {
  if (!moment || !moment.running) return null;
  // Until the clock reaches the step's recorded end, the step is running, whatever an alert has said of it.
  if (!moment.ended) return { text: "running", className: "is-running" };
  const answer = moment.step.happened.answer;
  // One word for one outcome: a blocked step is "stopped" on the host, in the caption and in the log.
  if (answer === "blocked") return { text: "stopped", className: "is-blocked" };
  // What the step did is known at its end; whether it was seen is told with the caption, and coloured only then.
  return { text: answer, className: moment.revealed ? `is-${moment.outcome.replace(/\s+/g, "")}` : "is-ended" };
}

/** True when a recording's rule engines did not all run at the same time: some live, some after the run. */
function ranAtDifferentTimes(recording: Recording): boolean {
  return new Set(recording.network.detectors.map((detector) => detector.when)).size > 1;
}

/**
 * The one quiet line of the defense's side: which sensors there are, on which hosts, and how they report to the defense
 * host: "Wazuh agent 4.14.10 on web, db and build, reporting to manager over mgmt."
 */
function defenseWords(recording: Recording): string {
  const network = recording.network;
  const defense = network.hosts.find((host) => host.kind === "defense");
  if (!defense) return "";
  const nameOf = (id: string): string => network.hosts.find((host) => host.id === id)?.name ?? id;
  const groups = new Map<string, string[]>();
  for (const sensor of network.sensors) {
    if (sensor.host === defense.id) continue;
    groups.set(sensor.name, [...(groups.get(sensor.name) ?? []), nameOf(sensor.host)]);
  }
  if (groups.size === 0) return `No sensor reports to ${defense.name}.`;
  const sensed = new Set(network.sensors.map((sensor) => sensor.host));
  // The networks the sensed hosts reach the defense host on, as the links name them.
  const over = [...new Set((network.links ?? []).filter((link) => link.to === defense.id && sensed.has(link.from)).flatMap((link) => (link.label ?? "").split(",").map((word) => word.trim()).filter(Boolean)))];
  const list = [...groups].map(([name, hosts]) => `${name} on ${listWords(hosts)}`).join("; ");
  return `${list}, reporting to ${defense.name}${over.length > 0 ? ` over ${listWords(over)}` : ""}.`;
}

function headsOf(recording: Recording, layout: NetworkLayout, ownDefenseHead = false): ReactNode {
  const network = recording.network;
  // How the rules ran is only said of a run that happened.
  const ran = recording.steps.length > 0 && network.detectors.length > 0;
  const live = ran && network.detectors.every((detector) => detector.when === "live");
  const mixed = ran && ranAtDifferentTimes(recording);
  // "The host" only for a map of one host; beside a defense host it is a network, and says how many hosts it holds.
  const one = network.hosts.length === 1;
  // The name sensors on several hosts share is told here, once: beside each of them stands a dot.
  const shared = layout.sensors.some((node) => !node.named) ? sharedSensorName(network) : null;
  const sharedOn = listWords(network.sensors.filter((sensor) => sensor.name === shared).map((sensor) => network.hosts.find((host) => host.id === sensor.host)?.name ?? sensor.host));
  const others = network.sensors.filter((sensor) => sensor.name !== shared).length;
  // On a network each head is one line, starting at the left edge of what it heads.
  const line = layout.single ? "" : " is-line";
  // With a defense side, its line names the sensors: the network's head says where there is none.
  const bare = network.hosts.filter((host) => host.kind !== "defense" && !network.sensors.some((sensor) => sensor.host === host.id)).map((host) => host.name);
  const unsensed = bare.length === 0 ? "a sensor on every host" : `no sensor on ${bare.length > 1 ? `${bare.slice(0, -1).join(", ")} or ${bare[bare.length - 1] ?? ""}` : (bare[0] ?? "")}`;
  return (
    <>
      <div className={`lv-head${line}`} style={{ left: layout.fieldHeadX }}>
        <b>{one ? "The host" : "The network"}</b>
        {one ? null : layout.single ? (
          <span>{`${plural(network.hosts.length, "host")}, ${plural(network.sensors.length, "sensor")}`}</span>
        ) : layout.defenseSide ? (
          <span>{`${plural(network.hosts.length, "host")} · ${unsensed}`}</span>
        ) : (
          <span>
            {plural(network.hosts.length, "host")}
            {shared === null ? `, ${plural(network.sensors.length, "sensor")}` : null}
            {shared === null ? null : (
              <>
                {" · "}
                <i className="lv-agent-dot" aria-hidden="true" />
                {`${shared} on ${sharedOn}${others > 0 ? `, and ${plural(others, "other sensor")}` : ""}`}
              </>
            )}
          </span>
        )}
      </div>
      {network.detectors.length > 0 && !ownDefenseHead ? (
        // On a network the head spans the engines' column, to the page's side margin, as the log's head does.
        <div className={`lv-head is-left${line}`} style={{ left: layout.detectorsHeadX }}>
          {/* On a network the defense host and the rule engines are one side: the defense. */}
          <b>{layout.defenseSide ? "The defense" : "Rule engines"}</b>
          {/* Rules that ran after the run are said once, where the first alert's time is shown: the race line. */}
          {live ? <span>judged the events as they arrived</span> : mixed ? <span>some live, some after the run: each says which</span> : null}
        </div>
      ) : null}
    </>
  );
}

/**
 * A network on a large stage is drawn larger, its hosts, lines and words alike:
 * it is laid out on the stage made smaller by the scale and drawn scaled up, so
 * a network looks the same place at every size. The scale grows with the stage
 * past these sizes, up to `MAP_SCALE_MOST`, while the network still fits.
 */
const MAP_SCALE_WIDTH = 1500;
const MAP_SCALE_HEIGHT = 380;
const MAP_SCALE_MOST = 1.25;

export function fitScale(recording: Recording, width: number, height: number, goalAt: string | null, squeeze: boolean, stage?: { network: Network; alerts: readonly Alert[] }): { layout: NetworkLayout; scale: number } {
  const network = stage?.network ?? recording.network;
  const many = network.hosts.filter((host) => host.kind !== "defense").length > 1;
  // The hosts the run's alerts are raised on keep room under their words for the alert's chip, at every moment alike:
  // of a run judged by several defenses, the hosts any of them raised an alert on, so the room is the same for each.
  if (many) markAlertedHosts(network, (stage?.alerts ?? recording.alerts).filter((alert) => matchKind(alert) === "alert").map((alert) => alert.host));
  // The hosts the steps run on wear a badge: every line keeps out of its place.
  if (many) markBadgedHosts(network, recording.steps.map((step) => step.host));
  if (many && goalAt) markGoalHost(network, goalAt);
  let scale = many ? Math.round(Math.max(1, Math.min(MAP_SCALE_MOST, width / MAP_SCALE_WIDTH, height / MAP_SCALE_HEIGHT)) * 20) / 20 : 1;
  for (;;) {
    const layout = layoutNetwork(network, width / scale, height / scale, squeeze);
    if (scale <= 1 || layout.least <= height / scale) return { layout, scale };
    scale = Math.max(1, Math.round((scale - 0.05) * 20) / 20);
  }
}

/** The network map: measures its box, lays the network out in it, and draws the moment. */
export function NetworkMap(props: NetworkMapProps & { arrival: (id: string) => number }) {
  const [ref, size] = useSize<HTMLDivElement>();
  // Laid out as soon as the stage has a width: a stage the rows around it squeezed to no height still claims the least height its map needs.
  const goalAt = props.goalAt ?? null;
  // The watch view, which shares its room (room.ts), may squeeze a network to its least layout; elsewhere a map keeps room above its rows.
  const squeeze = props.onLeast !== undefined;
  const { onLeast, recording, stage } = props;
  const fitted = useMemo(() => (size.width > 0 ? fitScale(recording, size.width, size.height, goalAt, squeeze, stage) : null), [recording, size.width, size.height, goalAt, squeeze, stage]);
  const scale = fitted?.scale ?? 1;
  const box = useMemo(() => ({ width: size.width / scale, height: size.height / scale }), [size.width, size.height, scale]);
  // The least heights are the map's at its smallest drawing: a map drawn larger is drawn at its own size again when the room is short.
  const laidOut = stage?.network ?? recording.network;
  const heights = useMemo(() => (onLeast && size.width > 0 ? leastHeights(laidOut, size.width) : null), [onLeast, laidOut, size.width]);
  const least = heights ? Math.ceil(heights.least) : 0;
  const roomy = heights ? Math.ceil(heights.roomy) : 0;
  useEffect(() => {
    if (least > 0) onLeast?.({ least, roomy: Math.max(least, roomy) });
  }, [least, roomy, onLeast]);
  // A network that needs more room than the screen gives makes the map taller, and the map's area scrolls.
  const minHeight = props.minHeight ?? (fitted && fitted.layout.least > 0 ? Math.ceil(fitted.layout.least * scale) : undefined);
  return (
    <section className="lv-stage" ref={ref} aria-label="Network map" style={minHeight !== undefined ? { minHeight } : undefined}>
      {fitted ? <MapView {...props} layout={fitted.layout} box={box} scale={scale} goalHost={props.goalHost ?? null} /> : null}
    </section>
  );
}
