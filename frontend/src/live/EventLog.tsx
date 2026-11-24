// What the sensors recorded for the current step: a log a few lines tall, with
// each line's real time, and a mark where a rule matched it.

import { memo } from "react";
import type { Alert, Recording, RecordingEvent } from "./recording";
import { alertMoment, timeOf } from "./recording";
import { clockTime, count, kindRank, matchKind, middleCut, sensorWord, stepLabel, strongerKind } from "./format";
import type { MatchKind } from "./format";
import type { StepMoment } from "./moment";
import { useSize } from "./useSize";
import type { StyleVars } from "./motion";

interface EventLogProps {
  recording: Recording;
  moment: StepMoment | null;
  /** How many events the recording holds for the current step. */
  total: number;
  colours: Map<string, string>;
  /** Opens the step in analyse mode, where every event is listed. */
  onOpen?: () => void;
}

const LINES = 4;
const MARK_WORDS: Record<MatchKind, string> = { alert: "alert", lab: "would alert", review: "review", launcher: "" };

/** A stopped step's proof: the line where the host refused what the step tried. */
export function refusalOf(events: readonly RecordingEvent[]): RecordingEvent | undefined {
  return events.find((event) => event.fields?.success === "no");
}

/**
 * The log changes when the step, its telling, its events or the matches that
 * have landed do, not on every animation frame. Inside a step both lists only
 * grow, so their lengths say when they changed.
 */
export const EventLog = memo(
  EventLogView,
  (a, b) =>
    a.recording === b.recording &&
    a.total === b.total &&
    a.colours === b.colours &&
    a.onOpen === b.onOpen &&
    a.moment?.step.id === b.moment?.step.id &&
    a.moment?.revealed === b.moment?.revealed &&
    a.moment?.events.length === b.moment?.events.length &&
    a.moment?.landed.length === b.moment?.landed.length &&
    a.moment?.late.length === b.moment?.late.length,
);

/** At most this many late arrivals have a line of the log: the latest ones. */
const LATE_LINES = 2;
const KIND_RGB: Record<MatchKind, string> = { alert: "255,112,69", lab: "168,146,255", review: "255,210,125", launcher: "123,202,255" };

function EventLogView({ recording, moment, total, colours, onOpen }: EventLogProps) {
  const [ref, size] = useSize<HTMLDivElement>();
  const sensors = moment ? recording.network.sensors.filter((sensor) => sensor.host === moment.step.host) : [];
  const events = moment?.events ?? [];

  // Marks come from the matches whose light has reached its rule engine, so a
  // line is marked at the moment the engine on the map shows the same match.
  const marks = new Map<string, MatchKind>();
  for (const { alert } of moment?.landed ?? []) {
    const kind = matchKind(alert);
    if (kind === "launcher") continue;
    for (const id of alert.events) marks.set(id, strongerKind(marks.get(id) ?? null, kind));
  }
  const refusal = moment?.step.outcome === "stopped" ? refusalOf(events) : undefined;
  // A late arrival, a match of an earlier step raised after that step ended,
  // takes a line at the foot of the log. Past the room for them, the first
  // line counts and names the earlier ones, so the log never says fewer than the score counts.
  const allLate = moment?.late ?? [];
  const late = allLate.slice(-LATE_LINES + (allLate.length > LATE_LINES ? 1 : 0));
  const earlier = allLate.slice(0, allLate.length - late.length);
  const lines = LINES - late.length - (earlier.length > 0 ? 1 : 0);
  const lateName = (alert: Alert) => {
    const owner = recording.steps.find((item) => item.id === alert.step);
    return `${owner ? stepLabel(recording, owner) : alert.step}: ${alert.rule.title}`;
  };
  const lastEarlier = earlier[earlier.length - 1];
  const earlierLine = lastEarlier
    ? {
        text: earlier.map(({ alert }) => lateName(alert)).join(", "),
        kind: earlier.reduce<MatchKind | null>((kind, { alert }) => strongerKind(kind, matchKind(alert)), null) ?? "launcher",
        time: clockTime(alertMoment(lastEarlier.alert)),
      }
    : null;
  const pinned = events.filter((event) => event === refusal || marks.has(event.id)).sort((a, b) => kindRank(marks.get(b.id) ?? "launcher") - kindRank(marks.get(a.id) ?? "launcher")).slice(0, lines - 1);
  const rest = events.filter((event) => !pinned.includes(event));
  const shown = [...rest.slice(-(lines - pinned.length)), ...pinned].sort((a, b) => events.indexOf(a) - events.indexOf(b));
  const room = Math.max(24, Math.floor((size.width - 330) / 7.4));

  const visibility = moment?.step.visibility;
  let shownCount: { lead: string; after: string } | null = null;
  if (moment && events.length > 0) {
    if (events.length < total) shownCount = { lead: count(events.length), after: `of ${count(total)} events` };
    else if (visibility?.kept !== undefined && visibility.events !== undefined) shownCount = { lead: count(visibility.events), after: `events recorded, ${count(visibility.kept)} kept here` };
    else shownCount = { lead: count(total), after: total === 1 ? "event" : "events" };
  }

  return (
    <section className="lv-log" aria-label="What the sensors recorded">
      <div className="lv-log-head">
        <b>Recorded</b>
        <span className="lv-log-count">
          {shownCount ? (
            <>
              <em>{shownCount.lead}</em> {shownCount.after}
            </>
          ) : null}
        </span>
        {onOpen && events.length > shown.length ? (
          <button type="button" className="lv-log-more" onClick={onOpen} title="Open this step in Analyse, where every event is listed">
            {count(events.length - shown.length)} more in Analyse
          </button>
        ) : null}
        <span className="lv-log-key">
          {sensors.map((sensor) => (
            <span key={sensor.id} title={`${sensor.name}: records ${sensor.records}`} style={{ "--rgb": colours.get(sensor.id) ?? "123,202,255" } as StyleVars}>
              <i className="lv-dot" />
              {sensorWord(sensor.name)} <b>{events.filter((event) => event.sensor === sensor.id).length}</b>
            </span>
          ))}
        </span>
      </div>
      <div className="lv-log-lines" ref={ref}>
        {shown.map((event, index) => {
          const mark = marks.get(event.id);
          const refused = event === refusal;
          const text = event.text || event.image || "";
          const classes = ["lv-log-line", mark ? `is-${mark}` : "", refused ? "is-refused" : "", !mark && !refused && index < shown.length - 1 ? "is-old" : ""].filter(Boolean).join(" ");
          return (
            <div key={event.id} className={classes} style={{ "--rgb": colours.get(event.sensor) ?? "123,202,255" } as StyleVars}>
              <span className="lv-log-time">{clockTime(timeOf(event.time))}</span>
              <i className="lv-dot" title={recording.network.sensors.find((sensor) => sensor.id === event.sensor)?.name ?? event.sensor} />
              <span className="lv-log-kind">{event.kind}</span>
              <span className="lv-log-text" title={text}>
                {middleCut(text, room)}
              </span>
              <span className="lv-log-mark">{refused ? "stopped" : mark ? MARK_WORDS[mark] : ""}</span>
            </div>
          );
        })}
        {moment && moment.revealed && events.length === 0 ? <div className="lv-log-none">Nothing recorded.</div> : null}
        {earlierLine ? (
          <div className={`lv-log-line is-late${earlierLine.kind === "launcher" ? "" : ` is-${earlierLine.kind}`}`} style={{ "--rgb": KIND_RGB[earlierLine.kind] } as StyleVars}>
            <span className="lv-log-time">{earlierLine.time}</span>
            <i className="lv-dot" title="Raised after their steps ended" />
            <span className="lv-log-kind">{earlier.length} more late</span>
            <span className="lv-log-text" title={earlierLine.text}>
              {middleCut(earlierLine.text, room)}
            </span>
            <span className="lv-log-mark">{MARK_WORDS[earlierLine.kind]}</span>
          </div>
        ) : null}
        {late.map(({ alert }) => {
          const kind = matchKind(alert);
          const text = lateName(alert);
          return (
            <div key={`late:${alert.id}`} className={`lv-log-line is-late${kind === "launcher" ? "" : ` is-${kind}`}`} style={{ "--rgb": KIND_RGB[kind] } as StyleVars}>
              <span className="lv-log-time">{clockTime(alertMoment(alert))}</span>
              <i className="lv-dot" title="Raised after its step ended" />
              <span className="lv-log-kind">raised late</span>
              <span className="lv-log-text" title={text}>
                {middleCut(text, room)}
              </span>
              <span className="lv-log-mark">{MARK_WORDS[kind]}</span>
            </div>
          );
        })}
      </div>
    </section>
  );
}
