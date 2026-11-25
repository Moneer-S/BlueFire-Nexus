// The scrubber: one even bar per step, so the strip reads as the rhythm of
// the run, with two slim rows under it (every sensor's events, and the alerts
// that count). It moves the clock by pointer and by keyboard. Analyse mode
// has the same steps on their true lengths.

import { memo, useMemo, useRef } from "react";
import type { KeyboardEvent, PointerEvent } from "react";
import type { Recording, StepRole } from "./recording";
import { countsForScore } from "./recording";
import { evenPosition, evenTime, maxOf, outcomeAt, PLAYBACK_RULE, segmentIndexAt } from "./playback";
import type { Timeline } from "./playback";
import { capital, clockTime, elapsed, outcomeClass, outcomeWords, sensorWord, stepLabel } from "./format";
import type { StyleVars } from "./motion";
import { firstAlertOnScreen } from "./moment";

interface ScrubberProps {
  recording: Recording;
  timeline: Timeline;
  time: number;
  real: number;
  /** True once the current step's outcome is told: until then the timeline does not say it either. */
  revealed: boolean;
  onSeek: (time: number) => void;
}

const BINS = 720;
const WIDTH = 1000;
const ROW = 4;
const GAP = 2;

interface Lane {
  key: string;
  label: string;
  className: string;
  path: string;
}

/** Ticks binned by position, so a busy run stays a calm row. */
function lanePath(positions: readonly number[], row: number, height: number): string {
  const bins = new Set<number>();
  for (const at of positions) bins.add(Math.min(BINS - 1, Math.max(0, Math.floor(at * BINS))));
  const width = WIDTH / BINS;
  return [...bins]
    .sort((a, b) => a - b)
    .map((bin) => `M${(bin * width).toFixed(2)} ${row}h${Math.max(1.1, width * 0.8).toFixed(2)}v${height}h-${Math.max(1.1, width * 0.8).toFixed(2)}Z`)
    .join("");
}

/** Canary and control steps are checks on the lab, not attacks: drawn as outlines. */
function isCheck(role: StepRole): boolean {
  return role === "canary" || role === "control";
}

interface CellsProps {
  recording: Recording;
  timeline: Timeline;
  time: number;
  current: number;
  revealed: boolean;
  /** How many late arrivals have fired by `time`: a step alerted by one is told so on its bar from then. */
  lateFired: number;
}

/**
 * One bar per step, in the outcome the screen has told so far: the current
 * step's once it is told. It changes only when the current step, its telling
 * or a late arrival does, not on every frame.
 */
const ScrubberCells = memo(
  function ScrubberCells({ recording, timeline, time, current, revealed }: CellsProps) {
    const count = timeline.segments.length;
    return (
      <div className="lv-cells">
        {timeline.segments.map((item, index) => {
          const state = index < current ? " is-past" : index === current ? " is-now" : "";
          const role = item.step.role === "test" ? "" : isCheck(item.step.role) ? " is-short is-check" : " is-short";
          const told = index < current || (index === current && revealed) ? ` is-${outcomeClass(outcomeAt(timeline, item, time))}` : "";
          return <div key={item.step.id} className={`lv-cell${told}${role}${state}`} style={{ left: `${(index / Math.max(1, count)) * 100}%` }} title={`${capital(stepLabel(recording, item.step))}: ${item.step.title}`} />;
        })}
      </div>
    );
  },
  (a, b) => a.recording === b.recording && a.timeline === b.timeline && a.current === b.current && a.revealed === b.revealed && a.lateFired === b.lateFired,
);

export function Scrubber({ recording, timeline, time, real, revealed, onSeek }: ScrubberProps) {
  const track = useRef<HTMLDivElement | null>(null);
  const dragging = useRef(false);
  const duration = timeline.duration;
  const count = timeline.segments.length;
  const pct = (position: number) => `${position * 100}%`;

  // Two quiet rows only: every sensor's events in one colour, and the alerts that count. Analyse mode has the full lanes.
  const lanes = useMemo<Lane[]>(() => {
    const rows: (Omit<Lane, "path"> & { positions: number[] })[] = [];
    const sensorNames = recording.network.sensors.filter((sensor) => timeline.arrivals.some(({ event }) => event.sensor === sensor.id)).map((sensor) => sensorWord(sensor.name));
    const events = timeline.arrivals.map(({ at }) => evenPosition(timeline, at));
    const alerts = timeline.fires.filter(({ alert }) => countsForScore(alert)).map(({ at }) => evenPosition(timeline, at));
    if (events.length > 0) rows.push({ key: "events", label: `events recorded by ${[...new Set(sensorNames)].join(" and ")}`, className: "is-events", positions: events });
    if (alerts.length > 0) rows.push({ key: "alert", label: "alerts of published rules", className: "is-alert", positions: alerts });
    return rows.map((row, index) => ({ key: row.key, label: row.label, className: row.className, path: lanePath(row.positions, index * (ROW + GAP), ROW) }));
  }, [recording, timeline]);

  const lanesHeight = Math.max(0, lanes.length * (ROW + GAP) - GAP);
  const current = segmentIndexAt(timeline, time);
  const segment = timeline.segments[current];
  const longest = useMemo(() => Math.max(0, maxOf(timeline.gaps.map((gap) => (gap.realEnd - gap.realStart) / 1000))), [timeline]);
  const shortRoles = [...new Set(recording.steps.filter((step) => step.role !== "test").map((step) => (step.role === "hardened" || step.role === "variant" ? "reruns" : step.role)))];
  // The legend in plain words: canary and control steps check the lab, reruns repeat a test.
  const shortWords = [...new Set(shortRoles.map((role) => (role === "canary" || role === "control" ? "checks" : role === "reruns" ? "repeats" : role)))];
  const shortList = shortWords.length > 1 ? `${shortWords.slice(0, -1).join(", ")} and ${shortWords[shortWords.length - 1] ?? ""}` : (shortWords[0] ?? "");
  const checks = recording.steps.some((step) => isCheck(step.role));
  const noEffect = recording.steps.some((step) => !isCheck(step.role) && (step.outcome === "no effect" || step.outcome === "inconclusive"));
  const head = evenPosition(timeline, time);
  const late = useMemo(() => timeline.fires.filter((fire) => fire.late), [timeline]);
  const lateFired = late.filter((fire) => fire.at <= time).length;

  const timeAtPointer = (clientX: number): number => {
    const box = track.current?.getBoundingClientRect();
    if (!box || box.width <= 0) return time;
    return evenTime(timeline, (clientX - box.left) / box.width);
  };
  const onPointerDown = (event: PointerEvent<HTMLDivElement>) => {
    dragging.current = true;
    event.currentTarget.setPointerCapture(event.pointerId);
    onSeek(timeAtPointer(event.clientX));
  };
  const onPointerMove = (event: PointerEvent<HTMLDivElement>) => {
    if (dragging.current) onSeek(timeAtPointer(event.clientX));
  };
  const onPointerUp = () => {
    dragging.current = false;
  };
  const stepTo = (index: number) => {
    const target = timeline.segments[Math.min(count - 1, Math.max(0, index))];
    if (target) onSeek(target.start);
  };
  // A move on never goes back: past the last step's start it goes to the end of the run.
  const stepOn = (index: number) => {
    const target = timeline.segments[index];
    onSeek(target && target.start > time ? target.start : duration);
  };
  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const index = Math.max(0, current);
    let handled = true;
    if (event.key === "ArrowRight" || event.key === "ArrowUp") {
      if (event.shiftKey) onSeek(Math.min(duration, time + 1));
      else stepOn(index + 1);
    } else if (event.key === "ArrowLeft" || event.key === "ArrowDown") {
      if (event.shiftKey) onSeek(Math.max(0, time - 1));
      else stepTo(segment && time - segment.start > 0.4 ? index : index - 1);
    } else if (event.key === "PageUp") stepOn(Math.min(count - 1, index + 10));
    else if (event.key === "PageDown") stepTo(index - 10);
    else if (event.key === "Home") onSeek(0);
    else if (event.key === "End") onSeek(duration);
    else handled = false;
    if (handled) event.preventDefault();
  };

  const first = firstAlertOnScreen(timeline.firstAlert, time, segment, revealed);
  return (
    <div className="lv-scrub-wrap">
      <div
        className="lv-scrub"
        ref={track}
        role="slider"
        tabIndex={0}
        aria-label="Timeline: arrow keys move by step, Shift and an arrow key by a second"
        aria-valuemin={0}
        aria-valuemax={Math.round(duration)}
        aria-valuenow={Math.round(time)}
        aria-valuetext={segment ? `${capital(stepLabel(recording, segment.step))}, ${revealed ? outcomeWords(outcomeAt(timeline, segment, time)) : "running"}: ${segment.step.title}, ${segment.index + 1} of ${count} steps, ${clockTime(real)} UTC` : "No steps"}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        onPointerCancel={onPointerUp}
        onKeyDown={onKeyDown}
        style={{ "--lanes-h": `${lanesHeight}px`, "--slot": pct(count > 0 ? 1 / count : 1) } as StyleVars}
      >
        <ScrubberCells recording={recording} timeline={timeline} time={time} current={current} revealed={revealed} lateFired={lateFired} />
        <svg className="lv-lanes" viewBox={`0 0 ${WIDTH} ${Math.max(1, lanesHeight)}`} preserveAspectRatio="none" aria-hidden="true">
          {lanes.map((lane) => (
            <path key={lane.key} className={`lv-lane ${lane.className}`} d={lane.path} />
          ))}
        </svg>
        <div className="lv-lanes-hint" title={lanes.map((lane, index) => `${index === 0 ? "Upper" : "Lower"} row: ${lane.label}`).join("\n")} />
        <div className="lv-future" style={{ left: pct(head) }} />
        {first ? <div className="lv-first-mark" style={{ left: pct(evenPosition(timeline, first.at)) }} title={`First alert on a test: ${stepLabel(recording, first.step)}`} /> : null}
        <div className="lv-playhead" style={{ left: pct(head) }} />
      </div>
      <div className="lv-legend">
        <span>
          <i className="is-alerted" />
          alerted
        </span>
        <span>
          <i className="is-seen" />
          seen, no alert
        </span>
        <span>
          <i className="is-unseen" />
          unseen
        </span>
        <span>
          <i className="is-stopped" />
          stopped
        </span>
        {noEffect ? (
          <span>
            <i className="is-noeffect" />
            no effect or inconclusive
          </span>
        ) : null}
        <span>
          <i className="is-future" />
          still to come
        </span>
        <span className="lv-legend-sep" />
        {shortRoles.length > 0 ? (
          <span title={`Short marks, not tests: ${shortRoles.join(", ")}.${checks ? " Canary and control steps check the lab itself and are drawn as outlines: solid when they alerted, dashed otherwise." : ""}${shortRoles.includes("reruns") ? " Reruns repeat a test, on a hardened host or with other input arguments." : ""} None of these is in the score of tests.`}>
            <i className="is-short" />
            short: {shortList}
          </span>
        ) : null}
        <span title={longest > 0 ? `Every step gets one bar. Silences between steps play as a short beat; the longest, ${elapsed(longest, 0)}, plays as ${PLAYBACK_RULE.beat} s.` : "Every step gets one bar."}>silences shortened</span>
      </div>
    </div>
  );
}
