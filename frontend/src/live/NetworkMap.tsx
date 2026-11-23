// The stage: the recording's network, drawn from `recording.network` alone,
// with what the sensors recorded travelling as light to the rule engines.

import { memo, useMemo } from "react";
import type { ReactNode } from "react";
import { useSize } from "./useSize";
import type { Alert, Host, Recording } from "./recording";
import { rulesRanAfterTheRun } from "./recording";
import { curvePath, layoutNetwork, travelPath } from "./networkLayout";
import type { HostNode, NetworkLayout, Point } from "./networkLayout";
import { detectorParts, kindRank, matchKind, plural } from "./format";
import type { MatchKind } from "./format";
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
}

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
function matchLines(landed: readonly { alert: Alert }[], detectorId: string): MatchLine[] {
  const lines = new Map<string, MatchLine>();
  for (const { alert } of landed) {
    if (alert.detector !== detectorId) continue;
    const kind = matchKind(alert);
    const key = `${alert.rule.id}:${kind}`;
    const line = lines.get(key);
    if (line) line.count += 1;
    else lines.set(key, { key, alert, kind, count: 1 });
  }
  // Strongest kind first, then the higher level, then the order they landed in.
  return [...lines.values()].sort((a, b) => kindRank(b.kind) - kindRank(a.kind) || (LEVEL_RANK[b.alert.rule.level] ?? 0) - (LEVEL_RANK[a.alert.rule.level] ?? 0));
}

const LEVEL_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, informational: 0 };

function MatchChip({ kind, level }: { kind: MatchKind; level: string }) {
  if (kind === "launcher") return <span className="lv-chip lv-chip--launcher">launcher line</span>;
  if (kind === "lab") return <span className="lv-chip lv-chip--lab" title="A rule written in this repository, at alert level. It is not in the score.">would alert &middot; {level}</span>;
  if (kind === "alert") return <span className="lv-chip lv-chip--alert">alert &middot; {level}</span>;
  return <span className="lv-chip lv-chip--review">review &middot; {level}</span>;
}

/**
 * What one engine matched: at most two chips (three when that is all), then
 * how many more, and a match on the launcher line named on a quiet line of
 * its own, since it never counts.
 */
function EngineMatches({ lines, none }: { lines: MatchLine[]; none: boolean }) {
  const counted = lines.filter((line) => line.kind !== "launcher");
  const launcher = lines.filter((line) => line.kind === "launcher");
  if (lines.length === 0) return <div className="lv-matches">{none ? <div className="lv-match lv-match--none">no rule matched</div> : null}</div>;
  // Three lines at most: an engine's label must not reach the one below it.
  const room = counted.length > 3 || (launcher.length > 0 && counted.length > 2) ? 2 : 3;
  const shown = counted.slice(0, room);
  const rest = counted.slice(room);
  const review = rest.filter((line) => line.kind === "review").length;
  const other = rest.length - review;
  const crowded = rest.length > 0 && launcher.length > 0;
  const more = [review ? `${review} more for review` : "", other ? `${other} more` : "", crowded ? `the launcher line ${launcher.length === 1 ? "matched once" : `matched ${launcher.length} times`}, not counted` : ""].filter(Boolean).join(" · ");
  const firstLauncher = crowded ? undefined : launcher[0];
  return (
    <div className="lv-matches">
      {shown.map((line) => (
        <div key={line.key} className="lv-match" title={line.alert.rule.title}>
          <MatchChip kind={line.kind} level={line.alert.rule.level} />
          <span className="lv-match-title">{line.alert.rule.title}</span>
          {line.count > 1 ? <span className="lv-match-count">&times;{line.count}</span> : null}
        </div>
      ))}
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
      lights.push({ key: `${event.id}>${detector.detector.id}`, path, rgb: kind && strong ? KIND_RGB[kind] : (own ? "255,210,125" : "123,202,255"), strong, age: moment.now - arrival(event.id) });
    }
  }
  return lights;
}

interface MapViewProps extends NetworkMapProps {
  layout: NetworkLayout;
  arrival: (id: string) => number;
}

function MapView({ recording, layout, moment, speed, seek, colours, labDetectors, arrival }: MapViewProps) {
  const step = moment?.step ?? null;
  const unseen = moment !== null && moment.revealed && moment.step.outcome === "unseen";
  const stopped = moment !== null && moment.revealed && moment.step.outcome === "stopped";
  const currentHost = step?.host ?? null;

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

  // What each rule engine shows: the strongest match whose light has landed.
  const engine = new Map<string, { kind: MatchKind; first: number; lines: MatchLine[] }>();
  for (const node of layout.detectors) {
    const lines = moment ? matchLines(moment.landed, node.detector.id) : [];
    let kind: MatchKind | null = null;
    let first = Number.POSITIVE_INFINITY;
    for (const { alert, at } of moment?.landed ?? []) {
      if (alert.detector !== node.detector.id) continue;
      const own = matchKind(alert);
      if (own === "launcher") continue;
      if (kind === null || kindRank(own) > kindRank(kind)) {
        kind = own;
        first = at;
      } else if (own === kind) first = Math.min(first, at);
    }
    if (kind) engine.set(node.detector.id, { kind, first, lines });
    else engine.set(node.detector.id, { kind: "launcher", first, lines });
  }

  const lights = moment && moment.running && !unseen ? lightsOf(layout, moment, arrival) : [];
  const hostNode = layout.hosts.find((node) => node.host.id === currentHost) ?? null;
  const fromNode = step?.from ? (layout.hosts.find((node) => node.host.id === step.from) ?? null) : null;
  const sinceStart = moment ? moment.now - moment.segment.bodyStart : -1;
  const alerted = moment !== null && moment.revealed && moment.step.outcome === "alerted";
  const heads = useMemo(() => headsOf(recording, layout), [recording, layout]);

  return (
    <div className={`lv-map${unseen ? " is-hush" : ""}${step?.outcome === "stopped" ? " is-calm" : ""}${layout.single ? " is-single" : " is-many"}`} style={{ "--lv-map-w": `${layout.width}px` } as StyleVars}>
      <Stars width={layout.width} height={layout.height} />

      <div className="lv-glows" aria-hidden="true">
        {hostNode ? (
          <div className={`lv-glow lv-glow--host${moment?.running && !moment.revealed ? " is-on" : ""}${alerted ? " is-alert" : ""}${stopped ? " is-stopped" : ""}`} style={{ left: hostNode.x, top: hostNode.y, width: hostNode.r * 6, height: hostNode.r * 6 }} />
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
        {layout.hosts.map((node) => <circle key={`halo-${node.host.id}`} className="lv-halo" cx={node.x} cy={node.y} r={node.r + (layout.single ? 26 : 14)} />)}
        {layout.single && layout.orbit.x > 0 && layout.hosts[0] ? <OrbitArc node={layout.hosts[0]} radius={layout.orbit} /> : null}
        {layout.links.map((line) => <path key={`${line.link.from}-${line.link.to}`} className={`lv-link${step && step.from === line.link.from && step.host === line.link.to ? " is-used" : ""}`} d={curvePath(line.curve)} />)}
        {layout.sensors.map((node) => {
          const curve = layout.sensorToJunction.get(node.sensor.id);
          const used = (perSensor.get(node.sensor.id)?.last ?? null) !== null;
          return curve ? <path key={`sj-${node.sensor.id}`} className={`lv-wire lv-wire--sj${used ? " is-used" : ""}`} d={curvePath(curve)} /> : null;
        })}
        {layout.detectors.map((node) => {
          const curve = layout.junctionToDetector.get(node.detector.id);
          const kind = engine.get(node.detector.id)?.kind ?? "launcher";
          return curve ? <path key={`jd-${node.detector.id}`} className={`lv-wire lv-wire--jd is-${kind}`} d={curvePath(curve)} /> : null;
        })}
        {layout.sensors.map((node) => {
          const curve = layout.hostToSensor.get(node.sensor.id);
          return curve ? <path key={`hs-${node.sensor.id}`} className={`lv-wire lv-wire--hs${node.sensor.host === currentHost ? " is-current" : ""}`} d={curvePath(curve)} /> : null;
        })}
        {layout.junction.hostId === null ? (
          <g className="lv-junction">
            <circle cx={layout.junction.x} cy={layout.junction.y} r={9} />
            <circle className="lv-junction-dot" cx={layout.junction.x} cy={layout.junction.y} r={2.6} />
          </g>
        ) : null}
        {layout.hosts.map((node) => {
          const current = node.host.id === currentHost;
          const classes = [`lv-host`, `lv-host--${node.host.kind}`, current ? "is-current" : "", current && moment?.running ? "is-running" : "", current && alerted ? "is-alerted" : "", current && stopped ? "is-stopped" : "", current && unseen ? "is-unseen" : ""].filter(Boolean).join(" ");
          return (
            <g key={node.host.id} className={classes}>
              <circle className="lv-host-body" cx={node.x} cy={node.y} r={node.r} fill="url(#lv-node-fill)" />
              <HostGlyph node={node} />
              <circle className="lv-host-ring" cx={node.x} cy={node.y} r={node.r + 14} pathLength={100} />
            </g>
          );
        })}
        {layout.sensors.map((node) => {
          const rgb = colours.get(node.sensor.id) ?? "123,202,255";
          const crossed = unseen && node.sensor.host === currentHost;
          return (
            <g key={node.sensor.id} className={`lv-sensor${crossed ? " is-crossed" : ""}`} style={{ "--rgb": rgb } as StyleVars}>
              <circle className="lv-sensor-body" cx={node.x} cy={node.y} r={node.r} fill="url(#lv-node-fill)" />
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
          <Motion key={`${seek}:cross:${moment.step.id}`} className="lv-light lv-light--cross is-strong" age={sinceStart + 0.4} length={1} speed={speed} style={{ offsetPath: `path("M${fromNode.x},${fromNode.y} L${hostNode.x},${hostNode.y}")`, "--rgb": "255,112,69" }} />
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
          return <Motion key={`${seek}:${moment.step.id}:${node.detector.id}:${state.kind}`} className={`lv-ring lv-ring--engine is-${state.kind}`} age={moment.now - state.first} length={1.4} speed={speed} style={{ left: node.x, top: node.y, width: node.r * 2 + 8, height: node.r * 2 + 8 }} />;
        })}
      </div>

      <div className="lv-labels">
        {heads}
        {layout.links.map((line) =>
          line.link.label ? (
            <div key={`label-${line.link.from}-${line.link.to}`} className="lv-link-label" style={{ left: line.label.x, top: line.label.y }}>
              {line.link.label}
            </div>
          ) : null,
        )}
        {layout.hosts.map((node) => (
          <HostLabel key={node.host.id} node={node} single={layout.single} moment={node.host.id === currentHost ? moment : null} />
        ))}
        {layout.sensors.map((node) => {
          const own = perSensor.get(node.sensor.id);
          const onStep = moment !== null && moment.running && node.sensor.host === currentHost;
          const crossed = unseen && node.sensor.host === currentHost;
          const place: StyleVars = node.small
            ? node.side < 0
              ? { right: layout.width - (node.x - node.r - 6), top: node.y - 9 }
              : { left: node.x + node.r + 6, top: node.y - 9 }
            : node.above
              ? { left: node.x + node.r + 10, bottom: layout.height - node.y + 6 }
              : { left: node.x + node.r + 10, top: node.y + 6 };
          const style: StyleVars = { ...place, "--rgb": colours.get(node.sensor.id) ?? "123,202,255" };
          return (
            <div key={node.sensor.id} className={`lv-sensor-label${node.small ? " is-small" : ""}${node.side < 0 ? " is-flip" : ""}${node.above ? " is-above" : ""}`} style={style}>
              <div className="lv-sensor-name" title={`${node.sensor.name}: records ${node.sensor.records}`}>
                {node.small ? null : <i className="lv-dot" />}
                {node.sensor.name}
              </div>
              {onStep ? <div className={`lv-sensor-count${crossed ? " is-zero" : ""}`}>{plural(own?.count ?? 0, "event")}</div> : null}            </div>
          );
        })}
        {layout.detectors.map((node) => {
          const parts = detectorParts(node.detector.name);
          const lab = labDetectors.has(node.detector.id);
          const state = engine.get(node.detector.id);
          return (
            <div key={node.detector.id} className="lv-engine-label" style={{ left: node.x + node.r + 16, top: node.y - 15, maxWidth: Math.max(160, layout.width - (node.x + node.r + 16) - 12) }}>
              <div className="lv-engine-name">
                {parts.main}
                {lab ? (
                  <span className="lv-tag" title="Our own rules, shown apart from the published ones and never counted in the score">
                    not scored
                  </span>
                ) : null}
              </div>
              <div className="lv-engine-sub" title={parts.engine ? `Run by ${parts.engine}` : undefined}>
                {node.detector.rules > 0 ? plural(node.detector.rules, "rule") : parts.engine}
              </div>
              {moment ? <EngineMatches lines={state?.lines ?? []} none={moment.revealed && !moment.all.some((alert) => alert.detector === node.detector.id)} /> : null}
            </div>
          );
        })}
        {unseen && moment ? (
          <div className="lv-silence" style={{ left: layout.silence.x, top: layout.silence.y }}>
            <b>
              It <em>took effect</em>, and
              <br />
              nothing travelled.
            </b>
          </div>
        ) : null}
      </div>
    </div>
  );
}

function OrbitArc({ node, radius }: { node: HostNode; radius: { x: number; y: number } }) {
  const a0 = (-52 * Math.PI) / 180;
  const a1 = (52 * Math.PI) / 180;
  return <path className="lv-orbit" d={`M${node.x + radius.x * Math.cos(a0)},${node.y + radius.y * Math.sin(a0)} A${radius.x},${radius.y} 0 0 1 ${node.x + radius.x * Math.cos(a1)},${node.y + radius.y * Math.sin(a1)}`} />;
}

function HostLabel({ node, single, moment }: { node: HostNode; single: boolean; moment: StepMoment | null }) {
  const host = node.host;
  const badge = badgeOf(moment);
  const os = shortOs(host);
  return (
    <>
      {badge ? (
        <div className={`lv-badge ${badge.className}`} style={{ left: node.x, top: node.y - node.r - (single ? 20 : 12) }}>
          {badge.text}
        </div>
      ) : null}
      <div className={`lv-host-label${single ? "" : " is-small"}`} style={{ left: node.x, top: node.y + node.r + (single ? 10 : 8) }}>
        <div className="lv-host-name">{host.name}</div>
        {single && host.kind === "host" ? (
          <div className="lv-host-command" title={moment?.step.command ?? ""}>
            {moment?.step.command ? <span>{moment.step.command}</span> : null}
          </div>
        ) : null}
        <div className="lv-host-role" title={host.os ?? ""}>
          {host.role}
          {single && os ? ` · ${os}` : ""}
        </div>
      </div>
    </>
  );
}

function badgeOf(moment: StepMoment | null): { text: string; className: string } | null {
  if (!moment || !moment.running) return null;
  if (!moment.revealed) return { text: "running", className: "is-running" };
  const answer = moment.step.happened.answer;
  // One word for one outcome: a blocked step is "stopped" on the host, in the caption and in the log.
  if (answer === "blocked") return { text: "stopped", className: "is-blocked" };
  return { text: answer, className: `is-${moment.step.outcome.replace(/\s+/g, "")}` };
}

function headsOf(recording: Recording, layout: NetworkLayout): ReactNode {
  const network = recording.network;
  const after = rulesRanAfterTheRun(recording);
  // How the rules ran is only said of a run that happened.
  const live = recording.steps.length > 0 && network.detectors.length > 0 && network.detectors.every((detector) => detector.when === "live");
  return (
    <>
      <div className="lv-head" style={{ left: layout.fieldHeadX }}>
        <b>{layout.single ? "The host" : "The network"}</b>
        {layout.single ? null : <span>{`${plural(network.hosts.length, "host")}, ${plural(network.sensors.length, "sensor")}`}</span>}
      </div>
      {network.detectors.length > 0 ? (
        <div className="lv-head is-left" style={{ left: layout.detectorsHeadX }}>
          <b>Rule engines</b>
          {after ? <span>ran after the run, so an alert&apos;s time is the time of its event</span> : live ? <span>judged the events as they arrived</span> : null}
        </div>
      ) : null}
    </>
  );
}

/** The network map: measures its box, lays the network out in it, and draws the moment. */
export function NetworkMap(props: NetworkMapProps & { arrival: (id: string) => number }) {
  const [ref, size] = useSize<HTMLDivElement>();
  const layout = useMemo(() => (size.width > 0 && size.height > 0 ? layoutNetwork(props.recording.network, size.width, size.height) : null), [props.recording.network, size.width, size.height]);
  return (
    <section className="lv-stage" ref={ref} aria-label="Network map">
      {layout ? <MapView {...props} layout={layout} /> : null}
    </section>
  );
}
