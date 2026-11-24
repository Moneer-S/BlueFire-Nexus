// The live view: replays a recording on its network map, step by step, next to
// what the defenses saw, and keeps score. It owns one animation-frame clock.
// This file and the parts beside it import nothing from the rest of the app.

import { memo, useCallback, useEffect, useId, useMemo, useRef, useState } from "react";
import "./live.css";
import type { Recording } from "./recording";
import { eventsByStep } from "./recording";
import { buildTimeline, frameAt, seekStep, stepMatchesInFiringOrder } from "./playback";
import type { Timeline } from "./playback";
import { clockTime, day, elapsed, isLabDetector, placeInRole, plural, runLink, sensorColours } from "./format";
import { lateWords, momentOf, runFacts, scoreOnScreen, stepMatches } from "./moment";
import { NetworkMap } from "./NetworkMap";
import { EventLog } from "./EventLog";
import { StepCaption } from "./StepCaption";
import { RaceLine } from "./RaceLine";
import { Scrubber } from "./Scrubber";
import { AnalyseView } from "./AnalyseView";

export type LiveMode = "watch" | "analyse";

/** Where the viewer is: the same shape as `initial`, so a page can write it into its address and open there again. */
export interface LiveMoment {
  step?: string;
  /** The position inside the step, 0 to 1. While playing it is 0: the step's start. */
  at?: number;
  paused: boolean;
  mode: LiveMode;
  select?: string;
}

export interface LiveViewProps {
  recording: Recording;
  /** Where the recording comes from, in the words of whoever shows it: shown, as text, under the title. */
  origin?: string;
  initial?: { step?: string; at?: number; paused?: boolean; mode?: LiveMode; select?: string };
  /** Starts fixing a step. When absent, "Fix this" in watch mode opens the step's detail, and the detail offers no "Fix this". */
  onFix?: (stepId: string) => void;
  /** Told where the viewer is when the step, the mode, the chosen step or the pause changes, and when the clock moves while paused. */
  onMoment?: (moment: LiveMoment) => void;
}

const SPEEDS = [1, 4, 16] as const;
/** The most screen seconds, before speed, that one animation frame may move the clock. */
const MAX_TICK = 0.1;

function startTime(timeline: Timeline, initial: LiveViewProps["initial"]): number {
  if (initial?.step === undefined) return 0;
  return seekStep(timeline, initial.step, initial.at ?? 0.6) ?? 0;
}

/** Where the recording comes from: a line under the title that opens the tool versions. It does not change while playing. */
const Provenance = memo(function Provenance({ recording }: { recording: Recording }) {
  const [open, setOpen] = useState(false);
  const trigger = useRef<HTMLButtonElement | null>(null);
  const popId = useId();
  const source = recording.source;
  const runUrl = runLink(source);
  const ran = recording.steps.length > 0;
  const close = () => {
    setOpen(false);
    trigger.current?.focus();
  };
  return (
    <div
      className="lv-prov"
      onKeyDown={(event) => {
        if (event.key !== "Escape" || !open) return;
        event.stopPropagation();
        close();
      }}
    >
      {ran ? (
        <button type="button" className="lv-prov-button" ref={trigger} aria-expanded={open} aria-controls={popId} onClick={() => setOpen((value) => !value)}>
          {source.finished ? "Recorded" : "Recording"} on a {source.environment}, {day(source.started)} &middot; <u>tool versions</u>
        </button>
      ) : (
        <span className="lv-prov-plan">A plan: nothing has run on this network yet</span>
      )}
      {ran && runUrl ? (
        <>
          <span className="lv-prov-sep"> &middot; </span>
          <a className="lv-prov-link" href={runUrl} target="_blank" rel="noreferrer noopener" title={`The CI run that made this recording: ${runUrl}`}>
            CI run (github.com)
          </a>
        </>
      ) : null}
      {open ? (
        <div className="lv-prov-pop" id={popId}>
          <h3>Where this recording comes from</h3>
          <dl>
            {source.tools.map((tool) => (
              <div key={`${tool.name}:${tool.role}`}>
                <dt>
                  {tool.name} <span>{tool.role}</span>
                </dt>
                <dd title={tool.version}>{tool.version}</dd>
              </div>
            ))}
          </dl>
          <p>
            {source.engine} on a {source.environment}, {source.finished ? `${source.started} to ${source.finished}` : `from ${source.started}, still running`}.
          </p>
          {runUrl ? (
            <p>
              <a href={runUrl} target="_blank" rel="noreferrer noopener">
                The run that made this recording (github.com)
              </a>
            </p>
          ) : null}
          {recording.notes.length > 0 ? (
            <ul>
              {recording.notes.map((note) => (
                <li key={note}>{note}</li>
              ))}
            </ul>
          ) : null}
          <button type="button" className="lv-button" onClick={close}>
            Close
          </button>
        </div>
      ) : null}
    </div>
  );
});

/** The wordmark, the run's title and where the recording comes from. */
const Brand = memo(function Brand({ recording, origin }: { recording: Recording; origin: string | undefined }) {
  return (
    <div className="lv-brand">
      <div className="lv-brand-row">
        <span className="lv-wordmark">
          <i />
          <span>
            Blue<b>Fire</b>
          </span>
        </span>
        <h1 className="lv-run-title">{recording.title}</h1>
      </div>
      <Provenance recording={recording} />
      {origin === undefined ? null : <p className="lv-origin">{origin}</p>}
    </div>
  );
});

/** A plan in one line: "6 hosts. Sensors: Wazuh agent on web, build and db, which records log lines and file changes." */
function planWords(recording: Recording): string {
  const network = recording.network;
  const groups = new Map<string, { hosts: string[]; records: string }>();
  for (const sensor of network.sensors) {
    const host = network.hosts.find((item) => item.id === sensor.host)?.name ?? sensor.host;
    const group = groups.get(sensor.name) ?? { hosts: [], records: sensor.records };
    group.hosts.push(host);
    groups.set(sensor.name, group);
  }
  const list = (items: string[]) => (items.length > 1 ? `${items.slice(0, -1).join(", ")} and ${items[items.length - 1] ?? ""}` : (items[0] ?? ""));
  const sensors = [...groups].map(([name, group]) => `${name} on ${list(group.hosts)}, which records ${group.records}`);
  return `${plural(network.hosts.length, "host")}. ${sensors.length > 0 ? `Sensors: ${sensors.join("; ")}.` : "No sensor yet."}`;
}

function PlayIcon({ playing }: { playing: boolean }) {
  return playing ? (
    <svg width="13" height="13" viewBox="0 0 12 12" aria-hidden="true">
      <rect x="2.5" y="1.5" width="2.6" height="9" rx=".6" />
      <rect x="7" y="1.5" width="2.6" height="9" rx=".6" />
    </svg>
  ) : (
    <svg width="13" height="13" viewBox="0 0 12 12" aria-hidden="true">
      <path d="M3 1.5v9l7.5-4.5z" />
    </svg>
  );
}

export function LiveView({ recording, origin, initial, onFix, onMoment }: LiveViewProps) {
  const timeline = useMemo(() => buildTimeline(recording), [recording]);
  const firstMode: LiveMode = recording.steps.length > 0 ? (initial?.mode ?? "watch") : "watch";
  const [time, setTime] = useState(() => startTime(timeline, initial));
  // Nothing plays in analyse mode, so a page opened there starts paused.
  const [playing, setPlaying] = useState(() => initial?.paused !== true && timeline.duration > 0 && firstMode === "watch");
  const [speed, setSpeed] = useState<number>(1);
  const [mode, setMode] = useState<LiveMode>(firstMode);
  const [select, setSelect] = useState<string | undefined>(initial?.select);
  // Whether analyse mode opens with keyboard focus on the chosen step's detail:
  // true when a control that goes away with watch mode opened it.
  const [focusDetail, setFocusDetail] = useState(false);
  const [seek, setSeek] = useState(0);
  const timeRef = useRef(time);
  const playButton = useRef<HTMLButtonElement | null>(null);
  const focusPlayOnWatch = useRef(false);

  // The one clock: while playing in watch mode, screen time follows the animation frames.
  useEffect(() => {
    if (!playing || mode !== "watch") return undefined;
    let last: number | null = null;
    let id = 0;
    const tick = (now: number) => {
      if (last !== null) {
        // A frame never moves the clock more than a tenth of a second, so a
        // hidden tab or a stalled page does not skip steps nobody saw.
        const step = Math.min(MAX_TICK, Math.max(0, (now - last) / 1000));
        const next = Math.min(timeline.duration, timeRef.current + step * speed);
        timeRef.current = next;
        setTime(next);
        if (next >= timeline.duration) {
          setPlaying(false);
          return;
        }
      }
      last = now;
      id = requestAnimationFrame(tick);
    };
    const onVisible = () => {
      if (document.visibilityState === "visible") last = null;
    };
    document.addEventListener("visibilitychange", onVisible);
    id = requestAnimationFrame(tick);
    return () => {
      cancelAnimationFrame(id);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [playing, speed, mode, timeline]);

  const jump = useCallback(
    (to: number) => {
      const next = Math.min(timeline.duration, Math.max(0, to));
      timeRef.current = next;
      setTime(next);
      setSeek((count) => count + 1);
    },
    [timeline],
  );

  const togglePlay = useCallback(() => {
    if (!playing && timeRef.current >= timeline.duration) jump(0);
    setPlaying((value) => !value && timeline.duration > 0);
    setSeek((count) => count + 1);
  }, [playing, timeline, jump]);

  // Space plays and pauses anywhere on the page in watch mode, also once focus
  // has fallen back to the page itself, unless a control has its own use for it.
  useEffect(() => {
    if (mode !== "watch") return undefined;
    const onKey = (event: globalThis.KeyboardEvent) => {
      if (event.key !== " " || event.defaultPrevented || event.altKey || event.ctrlKey || event.metaKey) return;
      const target = event.target;
      if (target instanceof Element && target.closest("button, a, input, select, textarea, summary, [role='slider'], [contenteditable='true']")) return;
      event.preventDefault();
      togglePlay();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [mode, togglePlay]);

  // After "Watch from here" or the Watch button, focus goes to the play button, not back to the page.
  useEffect(() => {
    if (mode !== "watch" || !focusPlayOnWatch.current) return;
    focusPlayOnWatch.current = false;
    playButton.current?.focus();
  }, [mode]);
  const focusPlay = useCallback(() => playButton.current?.focus(), []);

  const frame = useMemo(() => frameAt(timeline, time), [timeline, time]);
  const byStepEvents = useMemo(() => eventsByStep(recording), [recording]);
  const colours = useMemo(() => sensorColours(recording.network.sensors), [recording]);
  const labDetectors = useMemo(() => new Set(recording.network.detectors.filter((detector) => isLabDetector(recording, detector.id)).map((detector) => detector.id)), [recording]);
  const facts = useMemo(() => runFacts(recording, timeline), [recording, timeline]);
  const stepId = frame.step?.id;
  // The step's matches in the order playback fires them, fired or not: only the lights of its events read them all. What is said reads `moment.heard`.
  const stepAlerts = useMemo(() => (stepId === undefined ? [] : stepMatchesInFiringOrder(timeline, stepId)), [timeline, stepId]);
  const matches = useMemo(() => stepMatches(stepAlerts), [stepAlerts]);
  const moment = momentOf(timeline, frame, stepAlerts, matches);
  const lastLate = frame.late[frame.late.length - 1];
  const late = useMemo(() => (lastLate ? lateWords(recording, timeline, lastLate) : null), [recording, timeline, lastLate]);
  const arrival = useCallback((id: string) => timeline.arrival.get(id) ?? 0, [timeline]);
  const total = stepId === undefined ? 0 : (byStepEvents.get(stepId)?.length ?? 0);
  // Watching, the score is the score so far; analysing, it is the whole run's.
  const totals = recording.score;
  const score = mode === "watch" ? scoreOnScreen(timeline, frame, moment) : { ...frame.score, alerted: totals.alerted, seen: totals.seen, unseen: totals.unseen, stopped: totals.stopped };
  const decided = score.alerted + score.seen + score.unseen;
  const segment = frame.segment;
  const hasSteps = recording.steps.length > 0;
  const hardened = useMemo(() => recording.steps.filter((step) => step.role === "hardened").length, [recording]);
  const onlyHardenedStop = useMemo(() => recording.steps.every((step) => step.outcome !== "stopped" || step.role === "hardened"), [recording]);
  const allSteps = `${plural(recording.steps.length, "step")} in all`;
  const widestPlace = useMemo(() => recording.steps.map((step) => placeInRole(recording, step)).reduce((widest, place) => (place.length > widest.length ? place : widest), ""), [recording]);
  // Ordinary activity has no times in a recording, so while watching, its false alerts are told only at the end.
  const falseAlerts = mode === "analyse" || frame.ended ? recording.score.false_alerts : undefined;

  // One rule for entering watch mode, however the page was opened: playback
  // starts from where the clock stands, and plays unless it is at the end.
  const enterWatch = () => {
    focusPlayOnWatch.current = true;
    setPlaying(timeline.duration > 0 && timeRef.current < timeline.duration);
    setSeek((count) => count + 1);
    setMode("watch");
  };
  const switchMode = (next: LiveMode) => {
    if (next === mode) return;
    if (next === "analyse") {
      setPlaying(false);
      // Analysing from watch mode opens the step that was on screen.
      setSelect(stepId);
      setFocusDetail(false);
      setMode("analyse");
      return;
    }
    enterWatch();
  };
  const openInAnalyse = useCallback((id: string) => {
    setPlaying(false);
    setSelect(id);
    setFocusDetail(true);
    setMode("analyse");
  }, []);
  const watchStep = (id: string) => {
    const at = seekStep(timeline, id, 0);
    if (at !== null) jump(at);
    setSelect(id);
    enterWatch();
  };
  const openStep = useMemo(() => (stepId === undefined ? undefined : () => openInAnalyse(stepId)), [stepId, openInAnalyse]);

  // Not every frame: while playing only the step counts, while paused the position too.
  const momentAt = playing ? 0 : Math.round(frame.progress * 1000) / 1000;
  useEffect(() => {
    onMoment?.({ step: stepId, at: momentAt, paused: !playing, mode, select });
  }, [onMoment, stepId, momentAt, playing, mode, select]);

  return (
    <div className={`lv lv--${mode}${hasSteps ? "" : " lv--plan"}${playing ? "" : " is-paused"}`}>
      <header className="lv-top">
        <Brand recording={recording} origin={origin} />
        <div className="lv-score-wrap">
          {hasSteps ? (
            <div className="lv-score" aria-label={mode === "watch" ? "The score so far" : "The score"}>
              <div className={`lv-score-lead${score.alerted === 0 ? " is-zero" : ""}`} title={mode === "watch" ? "Tests that raised an alert, of the tests decided so far" : "Tests that raised an alert, of the tests that took effect"}>
                <div className="lv-score-n">
                  <b>{score.alerted}</b>
                  <span>/ {decided}</span>
                </div>
                <span className="lv-score-label">tests alerted</span>
              </div>
              <div className={`lv-score-item is-seen${score.seen === 0 ? " is-zero" : ""}`} title="Tests a sensor recorded, and no published rule at alert level matched">
                <b>{score.seen}</b>
                <span>seen, no alert</span>
              </div>
              <div className={`lv-score-item is-unseen${score.unseen === 0 ? " is-zero" : ""}`} title="Tests that took effect, and nothing of them was recorded">
                <b>{score.unseen}</b>
                <span>unseen</span>
              </div>
              {falseAlerts !== undefined ? (
                <div
                  className={`lv-score-item lv-score-false${falseAlerts === 0 ? " is-zero" : ""}`}
                  title={`Published rules that alerted on ordinary activity, outside every step${recording.ordinary ? ` (${plural(recording.ordinary.events, "event")} in all)` : ""}. Each rule counts once.`}
                >
                  <b>{falseAlerts}</b>
                  <span>{falseAlerts === 1 ? "false alert" : "false alerts"}</span>
                </div>
              ) : null}
              {hardened > 0 || score.stopped > 0 ? (
                <div className={`lv-score-item lv-score-reruns is-stopped${score.stopped === 0 ? " is-zero" : ""}`} title="Not tests: tests run again with a hardening change in place, and how many the change stopped">
                  <b>
                    {score.stopped}
                    {onlyHardenedStop && hardened > 0 ? <small> / {hardened}</small> : null}
                  </b>
                  <span>{onlyHardenedStop && hardened > 0 ? "reruns stopped" : "steps stopped"}</span>
                </div>
              ) : null}
            </div>
          ) : null}
          <div className="lv-modes" role="group" aria-label="Mode">
            <button type="button" aria-pressed={mode === "watch"} onClick={() => switchMode("watch")}>
              Watch
            </button>
            <button type="button" aria-pressed={mode === "analyse"} onClick={() => switchMode("analyse")} disabled={!hasSteps} title={hasSteps ? undefined : "Nothing has run on this network yet, so there is nothing to analyse"}>
              Analyse
            </button>
          </div>
        </div>
      </header>

      {mode === "watch" && !hasSteps ? (
        <div className="lv-main is-plan">
          <NetworkMap recording={recording} moment={null} speed={speed} seek={seek} colours={colours} labDetectors={labDetectors} arrival={arrival} />
          <p className="lv-plan-note">{planWords(recording)}</p>
        </div>
      ) : mode === "watch" ? (
        <>
          <RaceLine recording={recording} timeline={timeline} frame={frame} facts={facts} score={score} revealed={moment?.revealed ?? false} />
          <div className="lv-main">
            <NetworkMap recording={recording} moment={moment} speed={speed} seek={seek} colours={colours} labDetectors={labDetectors} arrival={arrival} />
            <EventLog recording={recording} moment={moment} total={total} colours={colours} onOpen={openStep} />
          </div>
          {/* Without the app, "Fix this" opens the step's detail, which says where the gap is. */}
          <StepCaption recording={recording} moment={moment} total={total} onFix={onFix ?? openInAnalyse} quiet={playing && speed >= 4} onLoseFocus={focusPlay} late={late} />
          <footer className="lv-transport">
            <div className="lv-controls">
              <button type="button" className="lv-play" ref={playButton} aria-label={playing ? "Pause" : "Play"} onClick={togglePlay} disabled={timeline.duration <= 0}>
                <PlayIcon playing={playing} />
              </button>
              <div className="lv-speed" role="group" aria-label="Playback speed">
                {SPEEDS.map((value) => (
                  <button
                    key={value}
                    type="button"
                    aria-pressed={speed === value}
                    onClick={() => {
                      setSpeed(value);
                      setSeek((count) => count + 1);
                    }}
                  >
                    {value}&times;
                  </button>
                ))}
              </div>
            </div>
            <div className="lv-clock">
              <b>
                {clockTime(frame.real)}
                <small>UTC</small>
              </b>
              <span title={`Counted from the first recorded event of the first step, ${clockTime(facts.start)} UTC`}>{elapsed((frame.real - facts.start) / 1000)} into the run</span>
            </div>
            <Scrubber recording={recording} timeline={timeline} time={time} real={frame.real} revealed={moment?.revealed ?? false} onSeek={jump} />
            <div className="lv-stepno">
              <b>{segment ? placeInRole(recording, segment.step) : ""}</b>
              {/* Holds the column at the width of the longest place, so the scrubber beside it does not move under the pointer. */}
              <b className="lv-stepno-sizer" aria-hidden="true">
                {widestPlace}
              </b>
              <span>{allSteps}</span>
            </div>
          </footer>
        </>
      ) : (
        <AnalyseView recording={recording} timeline={timeline} facts={facts} colours={colours} select={select} focusSelected={focusDetail} onSelect={setSelect} onWatch={watchStep} onFix={onFix} />
      )}
    </div>
  );
}
