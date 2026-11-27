// The live view: replays a recording on its network map, step by step, next to
// what the defenses saw, and keeps score. It owns one animation-frame clock.
// This file and the parts beside it import nothing from the rest of the app.

import { memo, useCallback, useEffect, useId, useLayoutEffect, useMemo, useRef, useState } from "react";
import "./live.css";
import { planRoom } from "./room";
import type { RoomPlan } from "./room";
import type { Recording } from "./recording";
import { alertMoment, eventsByStep, timeOf } from "./recording";
import { buildTimeline, frameAt, seekStep, stepMatchesInFiringOrder, stepPosition } from "./playback";
import type { Timeline } from "./playback";
import { capital, clockTime, day, elapsed, isLabDetector, matchKind, onEnvironment, plural, runLink, sensorColours, sharedUnseenWords, stepLabel, unitWord } from "./format";
import { firstAlertClock, firstAlertOnScreen, lateLine, momentOf, runFacts, scoreOnScreen, stepMatches } from "./moment";
import { FreeText } from "./FreeText";
import { NetworkMap } from "./NetworkMap";
import { EventLog } from "./EventLog";
import { StepCaption } from "./StepCaption";
import { goalReached, RaceLine } from "./RaceLine";
import { quietRows, Scrubber } from "./Scrubber";
import { AnalyseView } from "./AnalyseView";
import { judgeAll, sameMoment, tallyOf } from "./defenses";
import { DefenseTable, OutcomeLead } from "./DefenseParts";

export type LiveMode = "watch" | "analyse";

/** Where the viewer is: the same shape as `initial`, so a page can write it into its address and open there again. */
export interface LiveMoment {
  step?: string;
  /** The position inside the step, 0 to 1, or above 1 inside the silence after it. While playing it is 0: the step's start. */
  at?: number;
  paused: boolean;
  mode: LiveMode;
  select?: string;
  /** The defense that judges, of a recording judged by several: its `id`. */
  defense?: string;
}

export interface LiveViewProps {
  recording: Recording;
  /** Where the recording comes from, in the words of whoever shows it: who checked what. Shown, as text, when the line under the title is opened. */
  origin?: string;
  /**
   * What the line under the title calls the run: "A real run" for one shipped
   * with BlueFire or recorded by the lab's own CI, "An imported run, not
   * verified by BlueFire", "A run of unknown origin" for a page that does not
   * say, and "A run" when nothing is given.
   */
  originKind?: OriginKind;
  /** Where the view opens. `defense` is the id of the defense that judges. */
  initial?: { step?: string; at?: number; paused?: boolean; mode?: LiveMode; select?: string; defense?: string };
  /** Starts fixing a step. When absent, "Fix this" in watch mode opens the step's detail, and the detail offers no "Fix this". */
  onFix?: (stepId: string) => void;
  /** Told where the viewer is when the step, the mode, the chosen step or the pause changes, and when the clock moves while paused. */
  onMoment?: (moment: LiveMoment) => void;
}

export type OriginKind = "shipped" | "lab run" | "imported" | "unsaid";

/** The run in a few plain words, by where it comes from. */
function runWords(kind: OriginKind | undefined): string {
  if (kind === "shipped" || kind === "lab run") return "A real run";
  if (kind === "imported") return "An imported run, not verified by BlueFire";
  if (kind === "unsaid") return "A run of unknown origin";
  return "A run";
}

const SPEEDS = [1, 4, 16] as const;
/** The most screen seconds, before speed, that one animation frame may move the clock. */
const MAX_TICK = 0.1;

/**
 * A place in a step for an address, in thousandths, rounded up: opening it
 * again never lands before the moment on screen, so a match or a late arrival
 * that had fired is still there, and a moment just inside a silence stays in
 * it. It is rounded to the millionth first, so that 0.6000000000000001 is 0.6.
 */
function addressPosition(position: number): number {
  return Math.ceil(Math.round(position * 1e6) / 1e3) / 1e3;
}

function startTime(timeline: Timeline, initial: LiveViewProps["initial"]): number {
  if (initial?.step === undefined) return 0;
  return seekStep(timeline, initial.step, initial.at ?? 0.6) ?? 0;
}

/**
 * Where the recording comes from: one quiet line under the title that says what
 * the run is and when it was recorded, and opens to the rest: who checked what,
 * the CI run that made it, the tool versions and the notes. It does not change
 * while playing.
 */
const Provenance = memo(function Provenance({ recording, origin, originKind }: { recording: Recording; origin: string | undefined; originKind: OriginKind | undefined }) {
  const [open, setOpen] = useState(false);
  const trigger = useRef<HTMLButtonElement | null>(null);
  const popId = useId();
  const source = recording.source;
  const runUrl = runLink(source);
  // A run that finished has run, also when it holds no step; only a recording with neither is a plan.
  const ran = recording.steps.length > 0 || source.finished !== undefined;
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
          <span className="lv-prov-what">
            {runWords(originKind)}, {source.finished ? `recorded ${day(source.started)}` : `recording since ${day(source.started)}`} {onEnvironment(source.environment)}
          </span>
          {/* Where the line is cut short, its end, which opens the rest, stays on screen. */}
          <span className="lv-prov-more">
            {" "}
            &middot; <u>details</u>
          </span>
        </button>
      ) : (
        <span className="lv-prov-plan">A plan: nothing has run on this network yet</span>
      )}
      {open ? (
        <div className="lv-prov-pop" id={popId}>
          <h3>Where this recording comes from</h3>
          {origin === undefined ? null : <p className="lv-prov-origin">{origin}</p>}
          {runUrl ? (
            <p>
              <a href={runUrl} target="_blank" rel="noreferrer noopener" title={runUrl}>
                The CI run that made this recording (github.com)
              </a>
            </p>
          ) : null}
          <dl>
            {/* Keyed by place: a recording may name one tool twice, and every entry is shown. */}
            {source.tools.map((tool, index) => (
              <div key={index}>
                <dt>
                  {tool.name} <span>{tool.role}</span>
                </dt>
                <dd title={tool.version}>{tool.version}</dd>
              </div>
            ))}
          </dl>
          <p>
            {source.engine} {onEnvironment(source.environment)}, {source.finished ? `${source.started} to ${source.finished}` : `from ${source.started}, still running`}.
          </p>
          {recording.notes.length > 0 ? (
            <ul>
              {recording.notes.map((note, index) => (
                <li key={index}>
                  <FreeText text={note} />
                </li>
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
const Brand = memo(function Brand({ recording, origin, originKind, notice }: { recording: Recording; origin: string | undefined; originKind: OriginKind | undefined; notice: AddressNotice | null }) {
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
      <Provenance recording={recording} origin={origin} originKind={originKind} />
      {notice === null ? null : <AddressLine notice={notice} />}
    </div>
  );
});

/**
 * One calm line when the page's address names a step the recording does not
 * hold, so a mistyped or stale link does not look as if it worked. Null when
 * every step it names is there.
 */
function addressNotice(recording: Recording, initial: LiveViewProps["initial"]): AddressNotice | null {
  const known = new Set(recording.steps.map((step) => step.id));
  const step = initial?.step !== undefined && !known.has(initial.step) ? initial.step : null;
  const select = initial?.select !== undefined && !known.has(initial.select) ? initial.select : null;
  if (step === null && select === null) return null;
  const names = [...new Set([step, select].filter((id): id is string => id !== null))].map((id) => JSON.stringify(id));
  const what = names.length === 1 ? `step ${names[0] ?? ""}` : `steps ${names.join(" and ")}`;
  const instead = [step !== null ? "the view opened at the start of the run" : "", select !== null ? "analyse mode opened on the whole run" : ""].filter(Boolean).join(", and ");
  // The line stays true for the whole visit; how the view opened is its tooltip.
  const line = names.length === 1 ? `Step ${names[0] ?? ""} is not in this recording.` : `Steps ${names.join(" and ")} are not in this recording.`;
  return { line, full: `The page's address names ${what}, which this recording does not hold, so ${instead}.` };
}

interface AddressNotice {
  line: string;
  full: string;
}

/**
 * The address notice, in a status region that is on the page before its words
 * arrive, so that a screen reader speaks them.
 */
function AddressLine({ notice }: { notice: AddressNotice }) {
  const [words, setWords] = useState("");
  // Filled after the empty region has been drawn.
  useEffect(() => setWords(notice.line), [notice.line]);
  return (
    <p className="lv-address" role="status" title={notice.full}>
      {words}
    </p>
  );
}

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

/**
 * Whether the transport stands stuck at the foot of the window, over the rest
 * of the view scrolling under it: it then sits 1 pixel past the window's edge
 * (live.css), so less than all of it is in view. Never where the view fits.
 */
/** The room under the log's head that a log of no line drops: its head's 6 px margin and its own 4 px foot (live.css). */
const LOG_UNDER = 10;

/**
 * Where the view's top stands in the window when the page is at its top.
 * Whatever scrolls the view, the document in the app and the page's own box on
 * the single page, is counted back to its start, so the answer is the same
 * however far the page is scrolled when the view measures its room.
 */
function topAtPageTop(view: HTMLElement): number {
  let top = view.getBoundingClientRect().top;
  for (let box = view.parentElement; box; box = box.parentElement) top += box.scrollTop;
  return top;
}

/**
 * How the watch view shares the height it is given (room.ts): it measures the
 * parts that never give way, and plans how many lines the log holds and the
 * least height of the map. Null until the view is laid out, and outside watch
 * mode.
 */
function useRoomPlan(view: HTMLElement | null, active: boolean, map: MapHeights | null, most: number): RoomPlan | null {
  const [plan, setPlan] = useState<RoomPlan | null>(null);
  useLayoutEffect(() => {
    if (!view || !active || !map || typeof ResizeObserver === "undefined") {
      setPlan(null);
      return undefined;
    }
    const measure = () => {
      const parent = view.parentElement;
      const main = view.querySelector<HTMLElement>(":scope > .lv-main");
      const band = view.querySelector<HTMLElement>(":scope > .lv-caption");
      const bar = view.querySelector<HTMLElement>(":scope > .lv-transport");
      const log = main?.querySelector<HTMLElement>(".lv-log");
      const lines = log?.querySelector<HTMLElement>(".lv-log-lines");
      if (!parent || !main || !band || !bar || !log || !lines) return;
      // The room is the box the view is given, and never more than the window: a page that grows with the view still has a fold.
      // Where the view grows with what it holds (live.css), its box grows with it and says nothing of the room: the room is then
      // what the window shows under the view's top at the top of the page, below any page head above the view.
      const grows = getComputedStyle(view).getPropertyValue("--lv-grows").trim() === "1";
      const room = grows ? Math.floor(window.innerHeight - topAtPageTop(view)) : Math.min(parent.clientHeight, window.innerHeight);
      if (room <= 0) return;
      const font = Number.parseFloat(getComputedStyle(lines).fontSize) || 15;
      // The log's head as measured now, with or without the room under it that a log of no line drops (live.css).
      const head = log.offsetHeight - lines.offsetHeight;
      const alone = log.classList.contains("is-head");
      const next = planRoom({
        room,
        above: main.offsetTop,
        // The band's own margin pulls it up into the log's empty lines: what it takes of the view is its height less that.
        band: band.offsetHeight + (Number.parseFloat(getComputedStyle(band).marginTop) || 0),
        bar: bar.offsetHeight,
        logHead: alone ? head + LOG_UNDER : head,
        logHeadAlone: alone ? head : head - LOG_UNDER,
        logLine: 1.6 * font + 2,
        most,
        roomy: map.roomy,
        least: map.least,
      });
      setPlan((old) => (old && old.lines === next.lines && old.map === next.map && old.scroll === next.scroll ? old : next));
    };
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(view);
    if (view.parentElement) observer.observe(view.parentElement);
    for (const child of Array.from(view.children)) observer.observe(child);
    window.addEventListener("resize", measure);
    return () => {
      observer.disconnect();
      window.removeEventListener("resize", measure);
    };
  }, [view, active, map, most]);
  return active ? plan : null;
}

/** The map's least heights, as it tells them: with every badge above its host, and with nothing on another. */
interface MapHeights {
  least: number;
  roomy: number;
}

function useStuck(element: HTMLElement | null): boolean {
  const [stuck, setStuck] = useState(false);
  useEffect(() => {
    if (!element || typeof IntersectionObserver === "undefined") return undefined;
    const observer = new IntersectionObserver(
      (entries) => {
        const entry = entries[entries.length - 1];
        // Cut at its foot by the pixel it stands past the edge, not by a fraction of a pixel of rounding.
        if (entry) setStuck(entry.isIntersecting && entry.boundingClientRect.bottom - entry.intersectionRect.bottom >= 0.5);
      },
      { threshold: [0.5, 0.999, 1] },
    );
    observer.observe(element);
    return () => {
      observer.disconnect();
      setStuck(false);
    };
  }, [element]);
  return stuck;
}

export function LiveView({ recording: held, origin, originKind, initial, onFix, onMoment }: LiveViewProps) {
  // A recording judged by several defenses plays as the chosen one's view of it; one judged by one defense, or none, as it is.
  const judged = useMemo(() => judgeAll(held), [held]);
  const [defenseId, setDefenseId] = useState<string | undefined>(() => (judged.find((item) => item.defense.id === initial?.defense) ?? judged[0])?.defense.id);
  const chosen = judged.find((item) => item.defense.id === defenseId) ?? judged[0] ?? null;
  const recording = chosen ? chosen.view : held;
  const timeline = useMemo(() => (chosen ? chosen.timeline : buildTimeline(held)), [chosen, held]);
  const firstMode: LiveMode = recording.steps.length > 0 ? (initial?.mode ?? "watch") : "watch";
  const [time, setTime] = useState(() => startTime(timeline, initial));
  // Nothing plays in analyse mode, so a page opened there starts paused.
  const [playing, setPlaying] = useState(() => initial?.paused !== true && timeline.duration > 0 && firstMode === "watch");
  const [speed, setSpeed] = useState<number>(1);
  const [mode, setMode] = useState<LiveMode>(firstMode);
  // A step the address names that the recording does not hold is not chosen; the notice says so.
  const notice = useMemo(() => addressNotice(recording, initial), [recording, initial]);
  const [select, setSelect] = useState<string | undefined>(() => (initial?.select !== undefined && recording.steps.some((step) => step.id === initial.select) ? initial.select : undefined));
  // Whether analyse mode opens with keyboard focus on the chosen step's detail:
  // true when a control that goes away with watch mode opened it.
  const [focusDetail, setFocusDetail] = useState(false);
  const [seek, setSeek] = useState(0);
  const timeRef = useRef(time);
  const playButton = useRef<HTMLButtonElement | null>(null);
  const focusPlayOnWatch = useRef(false);
  const [transport, setTransport] = useState<HTMLElement | null>(null);
  const stuck = useStuck(transport);
  const [view, setView] = useState<HTMLDivElement | null>(null);
  const [mapHeights, setMapHeights] = useState<MapHeights | null>(null);
  // A new object only when a height changes, so the plan is not made again for nothing.
  const onMapHeights = useCallback((next: MapHeights) => setMapHeights((old) => (old && old.least === next.least && old.roomy === next.roomy ? old : next)), []);

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

  // Another defense judges the same moment: the same step, the same time on the clock.
  const chooseDefense = useCallback(
    (id: string) => {
      const next = judged.find((item) => item.defense.id === id);
      if (!next || next === chosen) return;
      const at = sameMoment(timeline, next.timeline, timeRef.current);
      timeRef.current = at;
      setTime(at);
      setDefenseId(id);
      setSeek((count) => count + 1);
    },
    [judged, chosen, timeline],
  );

  // A defense's number chooses it, anywhere on the page, in both modes, unless a field is being typed in.
  useEffect(() => {
    if (judged.length < 2) return undefined;
    const onKey = (event: globalThis.KeyboardEvent) => {
      if (event.defaultPrevented || event.altKey || event.ctrlKey || event.metaKey || !/^[1-8]$/.test(event.key)) return;
      const target = event.target;
      if (target instanceof Element && target.closest("input, select, textarea, [contenteditable='true']")) return;
      const wanted = judged[Number(event.key) - 1];
      if (!wanted) return;
      event.preventDefault();
      chooseDefense(wanted.defense.id);
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [judged, chooseDefense]);

  // After "Watch from here" or the Watch button, focus goes to the play button, not back to the page.
  useEffect(() => {
    if (mode !== "watch" || !focusPlayOnWatch.current) return;
    focusPlayOnWatch.current = false;
    playButton.current?.focus();
  }, [mode]);
  const focusPlay = useCallback(() => playButton.current?.focus(), []);

  const frame = useMemo(() => frameAt(timeline, time), [timeline, time]);
  const byStepEvents = useMemo(() => eventsByStep(recording), [recording]);
  // A sensor keeps its colour whichever defense judges: the colours are given over every sensor of the run.
  const colours = useMemo(() => sensorColours(held.network.sensors), [held]);
  const labDetectors = useMemo(() => new Set(recording.network.detectors.filter((detector) => isLabDetector(recording, detector.id)).map((detector) => detector.id)), [recording]);
  const facts = useMemo(() => runFacts(recording, timeline), [recording, timeline]);
  const stepId = frame.step?.id;
  // The step's matches in the order playback fires them, fired or not: only the thinning of a burst of lights reads them all. What is said, and a light's colour, read the fired ones.
  const stepAlerts = useMemo(() => (stepId === undefined ? [] : stepMatchesInFiringOrder(timeline, stepId)), [timeline, stepId]);
  const matches = useMemo(() => stepMatches(stepAlerts), [stepAlerts]);
  const moment = momentOf(timeline, frame, matches);
  const lateFires = frame.late;
  // On a network the engine lists the step's own matches raised in the silence after it with its others, and its sentence
  // names its alert: the late line names earlier steps' only there.
  const network = useMemo(() => recording.network.hosts.filter((host) => host.kind !== "defense").length > 1, [recording]);
  const late = useMemo(() => lateLine(recording, timeline, network ? lateFires.filter((fire) => fire.alert.step !== stepId) : lateFires), [recording, timeline, lateFires, stepId, network]);
  const arrival = useCallback((id: string) => timeline.arrival.get(id) ?? 0, [timeline]);
  // The host an attack path reached its goal on: the host of the step whose end is the goal. Marked on the map once the race line tells the goal.
  const goalStepHost = useMemo(() => (facts.goal === null ? null : (recording.steps.find((item) => item.ended !== undefined && Math.abs(timeOf(item.ended) - (facts.goal ?? 0)) <= 1)?.host ?? null)), [recording, facts]);
  const firstTold = firstAlertOnScreen(frame.race.firstAlert, frame.time, frame.segment, moment?.revealed ?? false);
  const goalTold = goalReached(frame, facts, firstTold);
  const goalHost = goalStepHost !== null && goalTold ? goalStepHost : null;
  // The first alert and the goal are places on the map too, each with the time the race line gives it.
  const firstClock = firstTold ? firstAlertClock(recording, facts, firstTold) : null;
  const mapFirst = firstTold && firstClock ? { id: firstTold.alert.id, time: elapsed(firstClock.seconds) } : null;
  const goalTime = recording.score.goal_seconds === undefined || recording.score.goal_seconds === null ? null : elapsed(recording.score.goal_seconds);
  // The published rules' alerts raised so far, as the score counts them: earlier steps' by their time, the step's own once fired.
  const alertsOfRun = useMemo(() => (network ? recording.alerts.filter((alert) => matchKind(alert) === "alert").sort((a, b) => alertMoment(a) - alertMoment(b)) : []), [recording, network]);
  const heard = moment?.heard;
  const raised = useMemo(() => alertsOfRun.filter((alert) => (alert.step === stepId ? (heard ?? []).includes(alert) : alertMoment(alert) <= frame.real)), [alertsOfRun, stepId, heard, frame.real]);
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
  const widestName = useMemo(() => recording.steps.map((step) => capital(stepLabel(recording, step))).reduce((widest, name) => (name.length > widest.length ? name : widest), ""), [recording]);
  const unseenBasis = useMemo(() => sharedUnseenWords(recording), [recording]);
  // Ordinary activity has no times in a recording, so while watching, its false alerts are told only at the end.
  // They are counted from ordinary activity, so they are shown only with it: the reader refuses the count without it.
  const falseAlerts = recording.ordinary && (mode === "analyse" || frame.ended) ? recording.score.false_alerts : undefined;
  // What a step is called and counted as: "step" on an attack path, "test" in a list of tests.
  const unit = unitWord(recording);
  const units = `${unit}s`;
  // The log holds 3 lines on a network and 4 on one host, fewer where the room is short.
  const logMost = network ? 3 : 4;
  const room = useRoomPlan(view, mode === "watch" && hasSteps, mapHeights, logMost);

  // What each defense has made of the run by this moment, each as its own view of the moment tells it.
  const tallies = useMemo(() => judged.map((item) => tallyOf(item, item === chosen ? time : sameMoment(timeline, item.timeline, time), mode === "analyse")), [judged, chosen, timeline, time, mode]);
  const multi = chosen !== null && tallies.length > 1;
  // The timeline keeps room for the quiet rows of the defense that has the most, so nothing moves when another is chosen.
  const scrubRows = useMemo(() => judged.reduce((most, item) => Math.max(most, quietRows(item.timeline)), 0), [judged]);
  // The network the map lays out: every sensor of the run, so that no host moves when another defense is chosen.
  const stage = useMemo(() => (chosen ? { network: chosen.stage, alerts: held.alerts } : undefined), [chosen, held]);
  const mapJudges = useMemo(() => (multi && chosen ? { tallies, chosen: chosen.defense.id, onChoose: chooseDefense, goalTold, current: frame.segment?.index ?? -1 } : undefined), [multi, chosen, tallies, chooseDefense, goalTold, frame.segment]);

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

  // Not every frame: while playing only the step counts, while paused the position too,
  // also inside the silence after the step, where a late alert may already be on screen.
  const momentAt = playing ? 0 : addressPosition(stepPosition(frame));
  // The defense that judges is part of the moment, for a recording judged by several.
  const defenseOnScreen = multi && chosen ? chosen.defense.id : undefined;
  useEffect(() => {
    onMoment?.({ step: stepId, at: momentAt, paused: !playing, mode, select, ...(defenseOnScreen === undefined ? {} : { defense: defenseOnScreen }) });
  }, [onMoment, stepId, momentAt, playing, mode, select, defenseOnScreen]);

  const modes = (
    <div className="lv-modes" role="group" aria-label="Mode">
      <button type="button" aria-pressed={mode === "watch"} onClick={() => switchMode("watch")}>
        Watch
      </button>
      <button type="button" aria-pressed={mode === "analyse"} onClick={() => switchMode("analyse")} disabled={!hasSteps} title={hasSteps ? undefined : recording.source.finished !== undefined ? "This run holds no step, so there is nothing to analyse" : "Nothing has run on this network yet, so there is nothing to analyse"}>
        Analyse
      </button>
    </div>
  );

  return (
    <div className={`lv lv--${mode}${hasSteps ? "" : " lv--plan"}${playing ? "" : " is-paused"}`} ref={setView}>
      <header className="lv-top">
        <Brand recording={recording} origin={origin} originKind={originKind} notice={notice} />
        {multi && chosen && recording.kind === "attack path" ? (
          // Judged by several defenses: the outcome of the run leads, and the counts of the chosen defense are a detail under it.
          <div className="lv-score-wrap is-judged">
            {hasSteps ? <OutcomeLead recording={recording} real={frame.real} goalTold={goalTold} whole={mode === "analyse"} /> : null}
            {modes}
          </div>
        ) : (
        <div className="lv-score-wrap">
          {hasSteps ? (
            <div className="lv-score" aria-label={mode === "watch" ? "The score so far" : "The score"}>
              <div className={`lv-score-lead${score.alerted === 0 ? " is-zero" : ""}`} title={mode === "watch" ? `${capital(units)} that raised an alert, of the ${units} decided so far` : `${capital(units)} that raised an alert, of the ${units} that took effect`}>
                <div className="lv-score-n">
                  <b>{score.alerted}</b>
                  {/* Before any step is decided there is nothing to count it of: "0 / 0" would read as a result. */}
                  {decided > 0 ? <span>/ {decided}</span> : null}
                </div>
                {/* While the run plays the counts go up: the head says so, so two moments of one run do not read as two runs. */}
                <span className="lv-score-label">{mode === "watch" && !frame.ended ? `${units} alerted so far` : `${units} alerted`}</span>
              </div>
              <div className={`lv-score-item is-seen${score.seen === 0 ? " is-zero" : ""}`} title={`${capital(units)} a sensor recorded, and no published rule at alert level matched`}>
                <b>{score.seen}</b>
                <span>seen, no alert</span>
              </div>
              <div className={`lv-score-item is-unseen${score.unseen === 0 ? " is-zero" : ""}`} title={unseenBasis ? `${capital(units)} that took effect and were not seen. The recording says: ${capital(unseenBasis)}.` : `${capital(units)} that took effect and were not seen: each one's detail says what the recording holds of it`}>
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
              ) : network && recording.ordinary && recording.score.false_alerts !== undefined ? (
                // On a network the counters keep their places from the first moment: this one is told at the end.
                <div className="lv-score-item lv-score-false is-zero is-later" title="Published rules that alerted on ordinary activity, outside every step. Ordinary activity has no times in a recording, so this count is told at the end of the run.">
                  <b>&ndash;</b>
                  <span>false alerts</span>
                </div>
              ) : null}
              {hardened > 0 || score.stopped > 0 ? (
                <div className={`lv-score-item lv-score-reruns is-stopped${score.stopped === 0 ? " is-zero" : ""}`} title="Hardened reruns, not in the score of tests: tests run again with a hardening change in place, and how many the change stopped">
                  <b>
                    {score.stopped}
                    {onlyHardenedStop && hardened > 0 ? <small> of {hardened}</small> : null}
                  </b>
                  <span>{onlyHardenedStop && hardened > 0 ? "hardened reruns stopped" : "steps stopped"}</span>
                </div>
              ) : null}
            </div>
          ) : null}
          {modes}
        </div>
        )}
      </header>

      {mode === "watch" && !hasSteps ? (
        <div className="lv-main is-plan">
          <NetworkMap recording={recording} moment={null} speed={speed} seek={seek} colours={colours} labDetectors={labDetectors} arrival={arrival} stage={stage} />
          <p className="lv-plan-note">
            {recording.source.finished !== undefined ? "This run finished with no steps: nothing ran as a step on this network. " : ""}
            {planWords(recording)}
          </p>
        </div>
      ) : mode === "watch" ? (
        <>
          <RaceLine
            recording={recording}
            timeline={timeline}
            frame={frame}
            facts={facts}
            score={score}
            revealed={moment?.revealed ?? false}
            ended={moment?.ended ?? false}
            judge={multi && chosen ? chosen.defense.name : undefined}
          />
          <div className="lv-main">
            <NetworkMap
              recording={recording}
              moment={moment}
              speed={speed}
              seek={seek}
              colours={colours}
              labDetectors={labDetectors}
              arrival={arrival}
              goalHost={goalHost}
              raised={raised}
              firstAlert={mapFirst}
              goalTime={goalTime}
              runStart={facts.start}
              goalAt={goalStepHost}
              onLeast={onMapHeights}
              minHeight={room?.map}
              stage={stage}
              judges={mapJudges}
            />
            <EventLog recording={recording} moment={moment} total={total} colours={colours} onOpen={openStep} lines={room?.lines ?? logMost} />
          </div>
          {/* Without the app, "Fix this" opens the step's detail, which says where the gap is. */}
          <StepCaption recording={recording} moment={moment} total={total} onFix={onFix ?? openInAnalyse} quiet={playing && speed >= 4} onLoseFocus={focusPlay} late={late} />
          <footer className={`lv-transport${stuck ? " is-stuck" : ""}`} ref={setTransport}>
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
              <span title={`Counted from ${facts.startWords}, ${clockTime(facts.start)} UTC`}>{elapsed((frame.real - facts.start) / 1000)} into the run</span>
            </div>
            <Scrubber recording={recording} timeline={timeline} time={time} real={frame.real} revealed={moment?.revealed ?? false} ended={moment?.ended ?? false} onSeek={jump} rows={scrubRows} />
            <div className="lv-stepno">
              {/* On an attack path a step's name is its place on the path: one line says both, "Step 9 of 11". */}
              <b>{segment ? (unit === "step" ? `${capital(stepLabel(recording, segment.step))} of ${recording.steps.length}` : capital(stepLabel(recording, segment.step))) : ""}</b>
              {/* Holds the column at the width of the longest name, so the scrubber beside it does not move under the pointer. */}
              <b className="lv-stepno-sizer" aria-hidden="true">
                {unit === "step" ? `${widestName} of ${recording.steps.length}` : widestName}
              </b>
              {unit === "step" && segment ? null : <span>{segment ? `${segment.index + 1} of ${plural(recording.steps.length, "step")}` : allSteps}</span>}
            </div>
          </footer>
        </>
      ) : (
        <AnalyseView
          recording={recording}
          timeline={timeline}
          facts={facts}
          colours={colours}
          select={select}
          focusSelected={focusDetail}
          onSelect={setSelect}
          onWatch={watchStep}
          onFix={onFix}
          defenses={multi && chosen ? <DefenseTable recording={recording} tallies={tallies} chosen={chosen.defense.id} onChoose={chooseDefense} goalTold /> : undefined}
        />
      )}
    </div>
  );
}
