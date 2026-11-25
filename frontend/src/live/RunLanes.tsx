// The whole run on one axis, the top of analyse mode: a cell for every step,
// each sensor's events as ticks, matches for review, alerts and the rules
// written in this repository, with the silences between steps shortened and
// marked, and the bracket that says how many tests ran before the first alert.

import { useMemo, useRef } from "react";
import type { KeyboardEvent } from "react";
import type { Recording, Step } from "./recording";
import { countsAsAlert, countsForScore, rulesRanAfterTheRun } from "./recording";
import type { Timeline } from "./playback";
import { maxOf, PLAYBACK_RULE } from "./playback";
import type { RunFacts } from "./moment";
import { firstAlertClock } from "./moment";
import { capital, elapsed, outcomeClass, plural, sensorLabel, stepLabel, stepShortName, testNumbers, unitWord, unseenWords } from "./format";
import { roleCount, roleRuns } from "./analyse";
import { useSize } from "./useSize";
import type { StyleVars } from "./motion";

interface RunLanesProps {
  recording: Recording;
  timeline: Timeline;
  facts: RunFacts;
  colours: Map<string, string>;
  selected: string | undefined;
  onSelect: (stepId: string) => void;
}

/** Heights of the parts, in pixels, from the top. */
const TOP = 52;
const STEPS = 20;
const GAP = 8;
const AXIS = 30;
/** Lane heights: the same whether or not a step is chosen, so nothing below moves on a click. */
const SENSOR = 24;
const REVIEW = 28;
const MARK = 20;
/** No axis label starts this close to a silence mark, in pixels. */
const MARK_ROOM = 24;
/** A silence at least this long, in real seconds, gets a break mark on the axis. */
const MARKED_SILENCE = 15;
/** The longest step name an axis label holds, "canary 1"; a longer one is left to the label's tooltip. */
const SHORT_NAME = 8;
const BIN = 2;
const REVIEW_Y: Record<string, number> = { medium: 0.3, low: 0.55, informational: 0.8 };

interface Row {
  key: string;
  label: string;
  sub: string;
  title?: string;
  y: number;
  h: number;
  className: string;
  rgb?: string;
}

function silence(seconds: number): string {
  if (seconds >= 60) return `${Math.floor(seconds / 60)} min ${Math.round(seconds % 60)} s`;
  return seconds >= 10 ? `${Math.round(seconds)} s` : `${seconds.toFixed(1)} s`;
}

function laneLabel(recording: Recording, step: Step): string {
  return `${capital(stepLabel(recording, step))}, ${step.outcome}: ${step.title}`;
}

export function RunLanes({ recording, timeline, facts, colours, selected, onSelect }: RunLanesProps) {
  const [plotRef, size] = useSize<HTMLDivElement>();
  const buttons = useRef<(HTMLButtonElement | null)[]>([]);
  const width = Math.max(1, size.width);
  const duration = Math.max(timeline.duration, 1e-6);
  const x = (at: number) => (at / duration) * width;
  const pct = (at: number) => `${(at / duration) * 100}%`;

  const sensors = recording.network.sensors.filter((sensor) => recording.events.some((event) => event.sensor === sensor.id));
  const hosts = new Set(recording.network.hosts.filter((host) => host.kind === "host").map((host) => host.id));
  const rows: Row[] = [];
  let y = TOP + STEPS + GAP;
  for (const sensor of sensors) {
    const host = recording.network.hosts.find((item) => item.id === sensor.host);
    const count = recording.events.filter((event) => event.sensor === sensor.id).length;
    const label = sensorLabel(recording, sensor);
    // The host once: in the label when another sensor shares the name, or else after the count.
    const onHost = hosts.size > 1 && host && !label.endsWith(` on ${host.name}`) ? ` on ${host.name}` : "";
    rows.push({
      key: `s:${sensor.id}`,
      label,
      sub: `${plural(count, "event")}${onHost}`,
      title: `${sensor.name}: records ${sensor.records}`,
      y,
      h: SENSOR,
      className: "is-sensor",
      rgb: colours.get(sensor.id),
    });
    y += SENSOR;
  }
  rows.push({ key: "review", label: "Matches for review", sub: "below alert level", title: "Higher dots are higher levels. Violet dots are rules written in this repository. A hollow ring matched only the launcher line, which never counts.", y, h: REVIEW, className: "is-review" });
  y += REVIEW;
  rows.push({ key: "alert", label: "Alerts", sub: "high or critical", title: "Published rules at high or critical: they make the score", y, h: MARK, className: "is-alert" });
  y += MARK;
  const hasLab = recording.network.detectors.some((detector) => detector.id === "lab") || recording.alerts.some((alert) => alert.rule.origin === "lab");
  if (hasLab) {
    rows.push({ key: "lab", label: "Lab rules", sub: "written here, not in the score", y, h: MARK, className: "is-lab" });
    y += MARK;
  }
  const bottom = y;
  const height = bottom + AXIS;
  const sensorTop = rows[0]?.y ?? bottom;
  const row = (key: string) => rows.find((item) => item.key === key);

  // Ticks are binned by pixel, so a long run stays a calm waveform. A few
  // thousand events at most: cheap enough to work out on each render.
  const sensorPaths = (() => {
    const paths = new Map<string, string>();
    for (const sensor of sensors) {
      const lane = rows.find((item) => item.key === `s:${sensor.id}`);
      if (!lane) continue;
      const bins = new Map<number, number>();
      for (const { event, at } of timeline.arrivals) {
        if (event.sensor !== sensor.id) continue;
        const bin = Math.floor(x(at) / BIN);
        bins.set(bin, (bins.get(bin) ?? 0) + 1);
      }
      const middle = lane.y + lane.h / 2;
      const amplitude = lane.h / 2 - 4;
      let path = "";
      for (const [bin, count] of bins) {
        const half = Math.min(amplitude, amplitude * (0.22 + 0.16 * Math.log2(1 + count)));
        path += `M${(bin * BIN).toFixed(1)} ${(middle - half).toFixed(1)}h${BIN - 0.5}v${(half * 2).toFixed(1)}h-${BIN - 0.5}Z`;
      }
      paths.set(sensor.id, path);
    }
    return paths;
  })();

  const marks = (() => {
    const review: { x: number; y: number; launcher: boolean; lab: boolean }[] = [];
    const alerts: number[] = [];
    const lab: number[] = [];
    const seen = new Set<string>();
    const reviewRow = rows.find((item) => item.key === "review");
    for (const { alert, at } of timeline.fires) {
      const px = x(at);
      if (countsForScore(alert)) alerts.push(px);
      else if (countsAsAlert(alert) && alert.rule.origin === "lab") lab.push(px);
      else if (reviewRow) {
        const launcher = alert.launcher_only === true;
        const level = REVIEW_Y[alert.rule.level] ?? 0.3;
        const key = `${Math.round(px / 3)}:${level}:${launcher ? 1 : 0}`;
        if (seen.has(key)) continue;
        seen.add(key);
        review.push({ x: px, y: reviewRow.y + reviewRow.h * level, launcher, lab: alert.rule.origin === "lab" });
      }
    }
    return { review, alerts, lab };
  })();

  const runs = useMemo(() => roleRuns(recording.steps), [recording]);
  const checks = recording.steps.some((step) => step.role === "canary" || step.role === "control");
  const first = timeline.firstAlert;
  const firstTest = timeline.segments.find((segment) => segment.step.role === "test");
  const longest = Math.max(0, maxOf(timeline.gaps.map((gap) => (gap.realEnd - gap.realStart) / 1000)));
  const marked = timeline.gaps.filter((gap) => (gap.realEnd - gap.realStart) / 1000 >= MARKED_SILENCE);
  // One mark per place: silences that fall within a few pixels of each other share it.
  const breaks: { x: number; seconds: number[] }[] = [];
  for (const gap of marked) {
    const middle = x((gap.start + gap.end) / 2);
    const last = breaks[breaks.length - 1];
    const seconds = (gap.realEnd - gap.realStart) / 1000;
    if (last && middle - last.x < 14) last.seconds.push(seconds);
    else breaks.push({ x: middle, seconds: [seconds] });
  }

  // Axis labels: the first step, then every tenth, as long as they do not crowd each other or a silence mark.
  // A label that would crowd one moves to the next step that has room. Each names its step as the table
  // does, a test of a list by its number ("#28"), a step of an attack path by its name ("step 10"), which
  // the table and the detail use too, and any other step by its short name where that is short ("canary 1");
  // a longer name, a rerun's, is left to the label's tooltip, which holds every label's whole name. Only the
  // choice of which steps get one goes by their place in the run.
  const numbers = unitWord(recording) === "step" ? new Map<string, number>() : testNumbers(recording);
  const ticks: { x: number; text: string; full: string }[] = [];
  let lastRight = -Infinity;
  let wanted = 0;
  for (const segment of timeline.segments) {
    const place = segment.index + 1;
    const due = segment.index === 0 || place >= wanted;
    if (!due) continue;
    const left = x(segment.start);
    const number = numbers.get(segment.step.id);
    const time = elapsed((segment.realStart - facts.start) / 1000, 0);
    const name = number === undefined ? stepShortName(recording, segment.step) : `#${number}`;
    const text = name.length <= SHORT_NAME ? `${name}  ${time}` : time;
    const right = left + text.length * 6.6 + 6;
    if (right > width || left < lastRight + 12 || breaks.some((mark) => mark.x > left - MARK_ROOM && mark.x < right + 6)) continue;
    ticks.push({ x: left, text, full: `${capital(stepLabel(recording, segment.step))}, ${time} into the run` });
    lastRight = right;
    wanted = Math.floor(place / 10) * 10 + 10;
  }

  const current = timeline.segments.find((segment) => segment.step.id === selected);
  const focusIndex = current ? current.index : 0;
  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const last = timeline.segments.length - 1;
    const moves: Record<string, number> = { ArrowRight: focusIndex + 1, ArrowLeft: focusIndex - 1, Home: 0, End: last };
    const wanted = moves[event.key];
    if (wanted === undefined) return;
    event.preventDefault();
    const next = Math.min(last, Math.max(0, wanted));
    const target = timeline.segments[next];
    if (!target) return;
    onSelect(target.step.id);
    buttons.current[next]?.focus();
  };

  let bracket: { a: number; b: number; text: string; full: string; right: boolean } | null = null;
  if (first && firstTest) {
    const a = x(firstTest.start);
    const b = x(first.at);
    const clock = firstAlertClock(recording, facts, first);
    const unit = unitWord(recording);
    const full = `${first.testsBefore === 0 ? `No other ${unit} had started` : `${plural(first.testsBefore, `other ${unit}`)} had started`} when the first alert on a ${unit} fired${clock ? `, ${elapsed(clock.seconds)} ${clock.words}` : ""}`;
    const room = (words: string) => words.length * 6.4 + 16;
    // In a narrow plot where the sentence fits on neither side of the alert, a shorter one does; the whole one is its tooltip.
    const short = `${first.testsBefore === 0 ? `no other ${unit}` : plural(first.testsBefore, `other ${unit}`)} had started${clock ? `, ${elapsed(clock.seconds)}` : ""}`;
    const text = b - a > room(full) || b + room(full) <= width ? full : short;
    bracket = { a, b, text, full, right: b - a > room(text) || (b + room(text) > width && b > width - b) };
  }

  return (
    <section className="lv-lanes-panel" aria-label="The whole run on one axis">
      <div className="lv-ln-labels" style={{ height }}>
        <span className="lv-ln-label is-steps" style={{ top: TOP, height: STEPS }} title={plural(recording.steps.length, "step")}>
          <i />
          {recording.kind === "attack path" ? "Attacker" : "Steps"}
        </span>
        {rows.map((item) => (
          <span key={item.key} className={`lv-ln-label ${item.className}`} title={[item.sub, item.title].filter(Boolean).join(". ")} style={{ top: item.y, height: item.h, ...(item.rgb ? ({ "--rgb": item.rgb } as StyleVars) : {}) }}>
            <i />
            {item.label}
          </span>
        ))}
      </div>
      <div className="lv-ln-plot" ref={plotRef} style={{ height }}>
        <svg className="lv-ln-svg" width={width} height={height} viewBox={`0 0 ${width} ${height}`} aria-hidden="true">
          <defs>
            <pattern id="lv-hatch" width="7" height="7" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
              <rect width="7" height="7" fill="rgba(255,110,121,0.08)" />
              <line x1="0" y1="0" x2="0" y2="7" stroke="rgba(255,110,121,0.45)" strokeWidth="1.6" />
            </pattern>
          </defs>
          {rows.map((item) => (
            <line key={item.key} className="lv-ln-rule" x1={0} x2={width} y1={item.y + 0.5} y2={item.y + 0.5} />
          ))}
          <line className="lv-ln-base" x1={0} x2={width} y1={bottom + 0.5} y2={bottom + 0.5} />
          {/* role runs: which part of the run is which kind of step */}
          {runs.map((run) => {
            const a = timeline.segments[run.first];
            const b = timeline.segments[run.last];
            if (!a || !b) return null;
            const left = x(a.start) + 1;
            const right = x(b.end) - 1;
            const text = run.count > 1 ? roleCount(run.role, run.count, unitWord(recording)) : run.role === "test" ? unitWord(recording) : run.role;
            if (right - left < text.length * 6.2 + 10) return null;
            return (
              <g key={`${run.role}:${run.first}`} className="lv-ln-run">
                <path d={`M${left} ${TOP - 6}v-4H${right}v4`} />
                <text x={left + 1} y={TOP - 14}>
                  {text}
                </text>
              </g>
            );
          })}
          {/* the step nobody saw: silence across the sensors */}
          {timeline.segments
            .filter((segment) => segment.step.outcome === "unseen")
            .map((segment) => (
              <rect key={`u:${segment.step.id}`} x={x(segment.start)} y={sensorTop} width={Math.max(3, x(segment.end) - x(segment.start))} height={bottom - sensorTop} fill="url(#lv-hatch)">
                <title>{`${capital(stepLabel(recording, segment.step))}, unseen: it took effect, and ${unseenWords(segment.step)}`}</title>
              </rect>
            ))}
          {current ? <rect className="lv-ln-selected" x={x(current.start) - 1.5} y={TOP - 3} width={Math.max(4, x(current.end) - x(current.start) + 3)} height={bottom - TOP + 3} rx={2} /> : null}
          {sensors.map((sensor) => (
            <path key={sensor.id} className="lv-ln-ticks" d={sensorPaths.get(sensor.id) ?? ""} style={{ "--rgb": colours.get(sensor.id) ?? "123,202,255" } as StyleVars} />
          ))}
          {marks.review.map((mark, index) => (
            <circle key={index} className={`lv-ln-review${mark.launcher ? " is-launcher" : ""}${mark.lab ? " is-lab" : ""}`} cx={mark.x} cy={mark.y} r={mark.launcher ? 2.4 : 2.1} />
          ))}
          {(() => {
            const alertRow = row("alert");
            const labRow = row("lab");
            return (
              <>
                {alertRow ? marks.alerts.map((at, index) => <rect key={`a${index}`} className="lv-ln-alert" x={at - 1} y={alertRow.y + 4} width={2.2} height={alertRow.h - 8} />) : null}
                {labRow ? marks.lab.map((at, index) => <rect key={`l${index}`} className="lv-ln-lab" x={at - 0.8} y={labRow.y + 5} width={1.8} height={labRow.h - 10} />) : null}
              </>
            );
          })()}
          {bracket ? (
            <g className="lv-ln-bracket">
              <path d={`M${bracket.a} ${11}v6M${bracket.a} 14H${bracket.b}M${bracket.b} 9V${bottom}`} />
              <text x={bracket.right ? bracket.b - 7 : bracket.b + 7} y={10} textAnchor={bracket.right ? "end" : "start"}>
                <title>{bracket.full}</title>
                {bracket.text}
              </text>
            </g>
          ) : null}
          {breaks.map((mark) => (
            <g key={`g${mark.x}`} className="lv-ln-break">
              <title>{mark.seconds.length === 1 ? `A quiet gap of ${silence(mark.seconds[0] ?? 0)} between steps, drawn shorter` : `${mark.seconds.length} quiet gaps between steps (${mark.seconds.map(silence).join(", ")}), drawn shorter`}</title>
              <rect x={mark.x - 6} y={bottom - 4} width={12} height={8} />
              <path d={`M${mark.x - 4} ${bottom + 4}l3 -8M${mark.x + 1} ${bottom + 4}l3 -8`} />
            </g>
          ))}
          {ticks.map((tick) => (
            <g key={tick.text} className="lv-ln-tick">
              <title>{tick.full}</title>
              <line x1={tick.x + 0.5} x2={tick.x + 0.5} y1={bottom} y2={bottom + 5} />
              <text x={tick.x + 2} y={bottom + 20}>
                {tick.text}
              </text>
            </g>
          ))}
        </svg>
        <div className="lv-ln-steps" role="group" aria-label="Steps: arrow keys move between them" style={{ top: TOP, height: STEPS }} onKeyDown={onKeyDown}>
          {timeline.segments.map((segment) => (
            <button
              key={segment.step.id}
              ref={(element) => {
                buttons.current[segment.index] = element;
              }}
              type="button"
              data-step={segment.step.id}
              tabIndex={segment.index === focusIndex ? 0 : -1}
              className={`lv-ln-step is-${outcomeClass(segment.step.outcome)}${segment.step.role === "test" ? "" : " is-short"}${segment.step.role === "canary" || segment.step.role === "control" ? " is-check" : ""}${segment.step.id === selected ? " is-selected" : ""}`}
              style={{ left: pct(segment.start), width: `max(2px, calc(${pct(segment.end - segment.start)} - 1px))` }}
              aria-label={laneLabel(recording, segment.step)}
              aria-pressed={segment.step.id === selected}
              title={laneLabel(recording, segment.step)}
              onClick={() => onSelect(segment.step.id)}
            />
          ))}
        </div>
      </div>
      <div className="lv-ln-foot">
        <span title={`Times count from ${facts.startWords}. Every step keeps its own length; the quiet time between two steps is drawn shorter than it lasted.`}>
          Quiet gaps are shortened{marked.length > 0 ? <>, those over {MARKED_SILENCE} s marked <b className="lv-ln-breakkey">//</b></> : null}
          {longest > 0 ? ` (the longest, ${silence(longest)}, takes ${PLAYBACK_RULE.beat} s)` : ""}.{checks ? " Outlined: canary and control steps, which check the lab and are not counted in the score." : ""}
        </span>
        {rulesRanAfterTheRun(recording) ? <span>The rules ran after the run, so an alert&apos;s time is the time of its event.</span> : null}
      </div>
    </section>
  );
}
