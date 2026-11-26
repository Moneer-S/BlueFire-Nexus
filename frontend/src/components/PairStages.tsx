// The step a change moved, drawn twice in the live view's own language: the
// host, its sensors, the rule engines, and what travelled between them in that
// run, before and after. What reads the same on both is drawn dim. The live
// view's own drawing (`NetworkMap`) plays a whole run in time; these two
// stages are still pictures of one step, so they are drawn here, in its look.

import { Wrench } from "lucide-react";
import type { CSSProperties, ReactNode } from "react";
import { Link } from "react-router-dom";
import type { DeltaStepSide } from "../lib/api";
import { alertedByLabOnly, MARK_FIELD } from "../lib/recording-pairs";
import { sameOnBoth, stageSentence, type StageEngine, type StageSide } from "../lib/pair-stage";
import { MARK_WORDS, outcomeClass, outcomeWords, plural } from "../live/format";
import type { Outcome } from "../live/recording";
import "./PairStages.css";

type Side = "before" | "after";

/** An outcome as the live view's mark: UNSEEN, SEEN, NO ALERT, ALERTED (violet when only the lab's rules alerted), STOPPED. */
export function OutcomeMark({ outcome, lab = false, big = false, times = 1, dim = false }: { outcome: Outcome; lab?: boolean; big?: boolean; times?: number; dim?: boolean }) {
  return <span className={`pmk is-${outcomeClass(outcome)}${lab ? " is-lab" : ""}${big ? " is-big" : ""}${dim ? " is-dim" : ""}`}>
    {outcomeWords(outcome)}{times > 1 ? <span className="pmk-times"><span aria-hidden="true">×</span><span className="sr-only">, </span>{times}<span className="sr-only"> steps</span></span> : null}
  </span>;
}

/** The mark of one side of a delta's step, in the one field the pair is drawn in. */
export function SideMark({ side, big = false, times = 1, dim = false }: { side: Pick<DeltaStepSide, "outcome" | "outcome_with_lab_rules">; big?: boolean; times?: number; dim?: boolean }) {
  return <OutcomeMark outcome={side[MARK_FIELD]} lab={alertedByLabOnly(side)} big={big} times={times} dim={dim} />;
}

const W = 460;
const H = 180;
const HOST = { x: 80, y: 90, r: 26 };
const SENSOR_X = 168;
const JUNCTION = { x: 262, y: 90 };
const ENGINE_X = 296;
const SR = 12;
const ER = 15;

function rows(count: number): number[] {
  if (count <= 1) return [90];
  if (count === 2) return [48, 132];
  const top = 34, bottom = 146;
  return Array.from({ length: count }, (_, index) => top + ((bottom - top) * index) / (count - 1));
}

type StyleVars = CSSProperties & { [key: `--${string}`]: string };

/** A sensor's colour as the live view passes it: an RGB triple in `--rgb`. */
function rgbStyle(rgb: string): StyleVars {
  return { "--rgb": rgb };
}

function pct(value: number, of: number): string {
  return `${((value / of) * 100).toFixed(3)}%`;
}

function hexagon(x: number, y: number, r: number): string {
  return Array.from({ length: 6 }, (_, index) => {
    const angle = Math.PI / 6 + (index * Math.PI) / 3;
    return `${(x + r * Math.cos(angle)).toFixed(1)},${(y + r * Math.sin(angle)).toFixed(1)}`;
  }).join(" ");
}

function toJunction(x: number, y: number): string {
  return `M${x},${y} C${x + 46},${(y + (JUNCTION.y - y) * 0.35).toFixed(1)} ${JUNCTION.x - 56},${JUNCTION.y} ${JUNCTION.x},${JUNCTION.y}`;
}

function toEngine(x: number, y: number): string {
  return `M${JUNCTION.x},${JUNCTION.y} C${JUNCTION.x + 14},${JUNCTION.y} ${x - 24},${y} ${x - ER},${y}`;
}

/** The command a reader needs on a stage: the file it writes when it names one, else the command. */
function shortCommand(command: string | undefined): string {
  if (!command) return "";
  const file = command.match(/>\s*(\S+)\s*$/);
  return file?.[1] ? `> ${file[1]}` : command;
}

/** An engine with no match drawn: a match on the launcher line alone is named, as the step's sentence names it. */
function noMatchWords(engine: StageEngine): string {
  return engine.launcher > 0 ? "matched only the launcher line" : "no rule matched";
}

function engineLine(engine: StageEngine): ReactNode {
  const [first] = engine.matches;
  if (!first) return <span className="pst-none">{noMatchWords(engine)}</span>;
  const more = engine.matches.length - 1;
  return <>
    {/* As analyse mode words it: a match below alert level at informational level is not one for review. */}
    {first.state === "review" && first.level === "informational"
      ? <span className="pst-chip is-review" title="An informational match: nobody reviews it.">informational</span>
      : <span className={`pst-chip is-${first.state}`}>{MARK_WORDS[first.state]} · {first.level}</span>}
    <span className="pst-rule">{first.title}</span>
    {more > 0 ? <span className="pst-none">and {more} more</span> : null}
  </>;
}

/** One stage's drawing: still, with the paths that carried something lit. */
function Drawing({ side, still }: { side: StageSide; still: { sensors: Set<string>; engines: Set<string> } }) {
  const quiet = side.events.length === 0;
  const sensorRows = rows(side.sensors.length);
  const engineRows = rows(side.engines.length);
  const ring = alertedByLabOnly({ outcome: side.step.outcome, outcome_with_lab_rules: side.outcome }) ? " is-lab" : "";
  const sensorAt = side.sensors.map((sensor, index) => ({ sensor, y: sensorRows[index] ?? 90 }));
  const engineAt = side.engines.map((engine, index) => ({ engine, y: engineRows[index] ?? 90 }));
  const dimSensor = (id: string) => (still.sensors.has(id) ? " is-still" : "");
  const dimEngine = (id: string) => (still.engines.has(id) ? " is-still" : "");
  return <div className={`pst-draw${quiet ? " is-quiet" : ""}`} aria-hidden="true">
    <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="xMidYMid meet" focusable="false">
      {engineAt.filter(({ engine }) => engine.state === "alert" || engine.state === "lab").map(({ engine, y }) => <circle key={`glow-${engine.id}`} className={`pst-glow is-${engine.state}${dimEngine(engine.id)}`} cx={ENGINE_X} cy={y} r={ER * 2.6} />)}
      {sensorAt.map(({ sensor, y }) => <g key={`wire-${sensor.id}`} style={rgbStyle(sensor.rgb)}>
        <path className={`pst-wire${sensor.events ? " is-used" : quiet ? " is-cut" : " is-idle"}${dimSensor(sensor.id)}`} d={`M${HOST.x},${HOST.y} L${SENSOR_X},${y}`} />
        {sensor.events ? <path className={`pst-wire is-used${dimSensor(sensor.id)}`} d={toJunction(SENSOR_X, y)} /> : null}
      </g>)}
      {engineAt.map(({ engine, y }) => <path key={`feed-${engine.id}`} className={`pst-wire is-${engine.state}${quiet ? " is-hush" : ""}${dimEngine(engine.id)}`} d={toEngine(ENGINE_X, y)} />)}
      <circle className={`pst-junction${quiet ? " is-hush" : ""}`} cx={JUNCTION.x} cy={JUNCTION.y} r={6} />
      <circle className="pst-halo" cx={HOST.x} cy={HOST.y} r={HOST.r + 20} />
      <circle className="pst-host" cx={HOST.x} cy={HOST.y} r={HOST.r} />
      <circle className={`pst-ring is-${outcomeClass(side.outcome)}${ring}`} cx={HOST.x} cy={HOST.y} r={HOST.r + 8} />
      {[0, 1, 2].map((row) => <rect key={row} className="pst-glyph" x={HOST.x - 11} y={HOST.y - 9 + row * 6.6} width={22} height={4.4} rx={1.5} />)}
      {sensorAt.map(({ sensor, y }) => <g key={`sensor-${sensor.id}`} className={`pst-sensor${sensor.events ? " is-used" : ""}${dimSensor(sensor.id)}`} style={rgbStyle(sensor.rgb)}>
        <circle className="pst-sensor-body" cx={SENSOR_X} cy={y} r={SR} />
        <circle className="pst-sensor-ring" cx={SENSOR_X} cy={y} r={SR * 0.45} />
        {!sensor.events && (quiet || !still.sensors.has(sensor.id)) ? <g className="pst-cross">
          <line x1={SENSOR_X - SR} y1={y - SR} x2={SENSOR_X + SR} y2={y + SR} />
          <line x1={SENSOR_X - SR} y1={y + SR} x2={SENSOR_X + SR} y2={y - SR} />
        </g> : null}
      </g>)}
      {engineAt.map(({ engine, y }) => <g key={`engine-${engine.id}`} className={`pst-engine is-${engine.state}${engine.lab ? " is-labset" : ""}${dimEngine(engine.id)}`}>
        <polygon className="pst-engine-body" points={hexagon(ENGINE_X, y, ER)} />
        <polygon className="pst-engine-core" points={hexagon(ENGINE_X, y, ER * 0.5)} />
      </g>)}
    </svg>
    <span className={`pst-badge${quiet ? " is-quiet" : ""}`} style={{ left: pct(HOST.x, W), top: pct(HOST.y - HOST.r - 10, H) }}>{side.step.happened.answer}</span>
    <span className="pst-host-label" style={{ left: pct(HOST.x, W), top: pct(HOST.y + HOST.r + 8, H) }}>
      <b>{side.host}</b>
      {side.step.command ? <code title={side.step.command}>{shortCommand(side.step.command)}</code> : null}
    </span>
    {sensorAt.map(({ sensor, y }, index) => <span key={sensor.id} className={`pst-sensor-label${index === 0 && sensorAt.length > 1 ? " is-above" : ""}${dimSensor(sensor.id)}`} style={{ left: pct(SENSOR_X, W), top: pct(index === 0 && sensorAt.length > 1 ? y - SR - 4 : y + SR + 4, H) }}>
      <b><i style={rgbStyle(sensor.rgb)} />{sensor.name}</b>
      <span className={sensor.events === 0 && (quiet || !still.sensors.has(sensor.id)) ? "is-zero" : undefined}>{plural(sensor.events, "event")}</span>
    </span>)}
    {engineAt.map(({ engine, y }) => <span key={engine.id} className={`pst-engine-label is-${engine.state}${dimEngine(engine.id)}`} style={{ left: pct(ENGINE_X + ER + 8, W), top: pct(y, H), width: pct(W - ENGINE_X - ER - 10, W) }}>
      <b>{engine.name}</b>
      {engineLine(engine)}
    </span>)}
    {quiet ? <span className="pst-silence" style={{ left: pct((SENSOR_X + JUNCTION.x) / 2 + 8, W), top: pct(JUNCTION.y, H) }}>No event tied to this step.</span> : null}
  </div>;
}

export interface StageLinks {
  play: string;
  playWords: string;
  fix?: string;
}

/** One stage: which side, the drawing, the outcome mark with a sentence, and where to watch it. */
function Stage({ which, words, run, side, still, newRules, links, judged }: { which: Side; words: string; run: string | null; side: StageSide; still: { sensors: Set<string>; engines: Set<string> }; newRules: ReadonlySet<string>; links: StageLinks; judged: boolean }) {
  const heading = `pst-${which}`;
  return <article className={`pst-stage is-${which}${judged ? "" : " is-unjudged"}`} aria-labelledby={heading}>
    <header>
      <h3 id={heading}><span className="pst-side">{which === "before" ? "Before" : "After"}</span>{" "}<span className="pst-words">{words}</span></h3>
      {run ? <span className="pst-run">run <code>{run}</code></span> : null}
    </header>
    <Drawing side={side} still={still} />
    <p className="pst-verdict">
      <OutcomeMark outcome={side.outcome} lab={alertedByLabOnly({ outcome: side.step.outcome, outcome_with_lab_rules: side.outcome })} dim={!judged} />
      <span>{stageSentence(side, newRules)}</span>
    </p>
    <p className="pst-actions">
      <Link to={links.play}>{links.playWords}</Link>
      {links.fix ? <Link className="pst-fix" to={links.fix}><Wrench aria-hidden="true" />Fix this</Link> : null}
    </p>
  </article>;
}

export interface StagesProps {
  before: StageSide;
  after: StageSide;
  words: Record<Side, string>;
  runs: Record<Side, string | null>;
  links: Record<Side, StageLinks>;
  newRules: ReadonlySet<string>;
  /** False when the comparison gives no verdict on the step: the stages are drawn, their marks greyed. */
  judged: boolean;
  /** Drawn at the end of the line under the stages. */
  footer?: ReactNode;
}

/** The two stages side by side, and what was drawn dim named once under them. */
export function Stages({ before, after, words, runs, links, newRules, judged, footer }: StagesProps) {
  const same = sameOnBoth(before, after);
  // When nothing differs, nothing is drawn dim: there is no "same" to set apart.
  const all = same.sensors.size === after.sensors.length && same.engines.size === after.engines.length;
  const still = all ? { sensors: new Set<string>(), engines: new Set<string>() } : same;
  const named = [
    ...after.sensors.filter((sensor) => still.sensors.has(sensor.id)).map((sensor) => `${sensor.name}, ${plural(sensor.events, "event")}`),
    ...after.engines.filter((engine) => still.engines.has(engine.id)).map((engine) => `${engine.name}, ${engine.matches.length ? `${engine.matches[0]?.state === "review" ? "a match below alert level" : engine.matches[0]?.state === "lab" ? `a ${MARK_WORDS.lab}` : "an alert"}` : noMatchWords(engine)}`),
  ];
  return <div className={`pst${judged ? "" : " is-unjudged"}`}>
    <div className="pst-pair">
      <Stage which="before" words={words.before} run={runs.before} side={before} still={still} newRules={newRules} links={links.before} judged={judged} />
      <span className="pst-arrow" aria-hidden="true" />
      <Stage which="after" words={words.after} run={runs.after} side={after} still={still} newRules={newRules} links={links.after} judged={judged} />
    </div>
    <div className="pst-foot">
      {named.length ? <p className="pst-still"><i aria-hidden="true" />Drawn dim, the same in both: {named.join("; ")}.</p> : <span />}
      {footer}
    </div>
  </div>;
}

/**
 * The one path of a moved step, small, for a card: the host, the sensor that
 * did or did not record it, the rules that did or did not alert. Drawn from the
 * delta's own fields of the step: whether it was recorded and its mark.
 */
export function PathThumb({ side, label }: { side: DeltaStepSide; label: string }) {
  const recorded = side.recorded === "recorded";
  const outcome = side[MARK_FIELD];
  const lab = alertedByLabOnly(side);
  const engine = outcome === "alerted" ? (lab ? "lab" : "alert") : recorded ? "seen" : "none";
  return <figure className="pth">
    <svg viewBox="0 0 120 40" aria-hidden="true" focusable="false">
      <path className={`pth-wire${recorded ? " is-used" : " is-cut"}`} d="M22,20 L58,20" />
      <path className={`pth-wire is-${engine}`} d="M58,20 L94,20" />
      <circle className={`pth-host is-${outcomeClass(outcome)}${lab ? " is-lab" : ""}`} cx={18} cy={20} r={10} />
      <circle className={`pth-sensor${recorded ? " is-used" : ""}`} cx={60} cy={20} r={5.5} />
      {recorded ? null : <g className="pth-cross"><line x1={55} y1={15} x2={65} y2={25} /><line x1={55} y1={25} x2={65} y2={15} /></g>}
      <polygon className={`pth-engine is-${engine}`} points={hexagon(100, 20, 8)} />
    </svg>
    <figcaption>{label}</figcaption>
  </figure>;
}
