// What the sensors recorded for the current step: a log a few lines tall, with
// each line's real time, and a mark where a rule matched it.

import { memo } from "react";
import type { Alert, Recording, RecordingEvent } from "./recording";
import { alertMoment, timeOf } from "./recording";
import { capital, clockTime, count, eventMarks, kindRank, markOf, matchKind, middleCut, raisedAfterStep, sensorLabel, stepLabel, unseenWords } from "./format";
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
  /** How many lines the log holds: on a network 3, so the step's words below keep their room. */
  lines?: number;
}

const LINES = 4;

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
    a.lines === b.lines &&
    a.moment?.step.id === b.moment?.step.id &&
    a.moment?.revealed === b.moment?.revealed &&
    a.moment?.ended === b.moment?.ended &&
    a.moment?.events.length === b.moment?.events.length &&
    a.moment?.landed.length === b.moment?.landed.length &&
    a.moment?.late.length === b.moment?.late.length,
);

/**
 * The rules of some matches folded into one line, counted by kind in the screen's own words: "1 alert rule, 5 rules
 * for review and 2 informational". A rule is counted once, under the kind of its match.
 */
export function foldedWords(alerts: readonly Alert[]): string {
  const rules = (kind: MatchKind | "info") =>
    new Set(alerts.filter((alert) => (kind === "info" ? matchKind(alert) === "review" && alert.rule.level === "informational" : matchKind(alert) === kind && !(kind === "review" && alert.rule.level === "informational"))).map((alert) => alert.rule.id)).size;
  const parts = [
    [rules("alert"), "alert rule", "alert rules"],
    [rules("lab"), "lab alert rule", "lab alert rules"],
    [rules("review"), "rule for review", "rules for review"],
    [rules("info"), "informational", "informational"],
    [rules("launcher"), "rule on the launcher line", "rules on the launcher line"],
  ] as const;
  const words = parts.filter(([value]) => value > 0).map(([value, one, many]) => `${count(value)} ${value === 1 ? one : many}`);
  return words.length > 1 ? `${words.slice(0, -1).join(", ")} and ${words[words.length - 1] ?? ""}` : (words[0] ?? "");
}

/** At most this many late arrivals have a line of the log: the latest ones. */
const LATE_LINES = 2;
const KIND_RGB: Record<MatchKind, string> = { alert: "255,112,69", lab: "168,146,255", review: "255,210,125", launcher: "123,202,255" };

function EventLogView({ recording, moment, total, colours, onOpen, lines: most = LINES }: EventLogProps) {
  const [ref, size] = useSize<HTMLDivElement>();
  const events = moment?.events ?? [];
  // The step's host's sensors, and any other that recorded it: in a range, the agent of the host a step ran from.
  const sensors = moment ? recording.network.sensors.filter((sensor) => sensor.host === moment.step.host || events.some((event) => event.sensor === sensor.id)) : [];

  // Marks come from the matches whose light has reached its rule engine, so a
  // line is marked at the moment the engine on the map shows the same match.
  const marks = eventMarks((moment?.landed ?? []).map(({ alert }) => alert));
  // The line where the host refused is marked "stopped" once the step's clock has reached its end: until then nothing says how the step ended.
  const refusal = moment?.step.outcome === "stopped" && moment.ended ? refusalOf(events) : undefined;
  // A late arrival, a match of an earlier step raised after that step ended,
  // takes a line at the foot of the log. Past the room for them, the first
  // line counts and names the earlier ones, so the log never says fewer than the score counts.
  // A log with no line, where the room is short, keeps only its head: its count of events and the way to the rest in Analyse.
  const allLate = most > 0 ? (moment?.late ?? []) : [];
  // The strongest arrivals have their lines, the latest of those as strong: an alert is never folded into the count of the rest.
  const ranked = [...allLate].sort((a, b) => kindRank(matchKind(b.alert)) - kindRank(matchKind(a.alert)) || b.at - a.at);
  let lateRoom = allLate.length > LATE_LINES ? 1 : allLate.length;
  let foldRest = allLate.length > lateRoom;
  if (lateRoom + (foldRest ? 1 : 0) > most) {
    // A log of one line: an alert keeps it, its own line as a longer log writes it, and the matches weaker than it are
    // left to the engine on the map. With no alert among them, the arrivals are folded into one line that counts them.
    const top = ranked[0];
    const alert = top !== undefined && (matchKind(top.alert) === "alert" || matchKind(top.alert) === "lab");
    lateRoom = alert ? 1 : 0;
    foldRest = !alert;
  }
  const strongest = new Set(ranked.slice(0, lateRoom));
  const late = allLate.filter((fire) => strongest.has(fire));
  const earlier = foldRest ? allLate.filter((fire) => !strongest.has(fire)) : [];
  const lines = most - late.length - (earlier.length > 0 ? 1 : 0);
  const lateName = (alert: Alert) => {
    const owner = recording.steps.find((item) => item.id === alert.step);
    return `${owner ? stepLabel(recording, owner) : alert.step}: ${alert.rule.title}`;
  };
  const earlierMark = markOf(earlier.map(({ alert }) => alert));
  // The folded line takes the time of the last match it folds, so the lines stand in the order they were raised.
  const lastRaised = earlier.reduce((latest, { alert }) => Math.max(latest, alertMoment(alert)), Number.NEGATIVE_INFINITY);
  // When every folded match is the step's own, raised after it ended, the line says so in the words the rest of the screen uses,
  // and counts their rules by kind, each as what it is: an alert is never counted among the rules for review. The titles are in its title.
  const allOwn = earlier.length > 0 && earlier.every(({ alert }) => alert.step === moment?.step.id);
  const ownSummary = foldedWords(earlier.map(({ alert }) => alert));
  const earlierLine =
    earlier.length > 0
      ? {
          text: allOwn ? `${earlier.length} more matches after the step, by ${ownSummary}` : earlier.map(({ alert }) => lateName(alert)).join(", "),
          full: earlier.map(({ alert }) => (allOwn ? alert.rule.title : lateName(alert))).join(", "),
          kind: earlierMark?.kind ?? "launcher",
          word: earlierMark?.word ?? "",
          at: lastRaised,
          time: clockTime(lastRaised),
        }
      : null;
  // A marked line keeps its place; of one line, the latest event takes it.
  const pinned = events.filter((event) => event === refusal || marks.has(event.id)).sort((a, b) => kindRank(marks.get(b.id)?.kind ?? "launcher") - kindRank(marks.get(a.id)?.kind ?? "launcher")).slice(0, Math.max(0, lines - 1));
  const rest = events.filter((event) => !pinned.includes(event));
  const shown = lines > 0 ? [...rest.slice(-(lines - pinned.length)), ...pinned].sort((a, b) => events.indexOf(a) - events.indexOf(b)) : [];
  const room = Math.max(24, Math.floor((size.width - 330) / 7.4));
  // No event of the step has a line: every one of them is in Analyse.
  const allInAnalyse = onOpen !== undefined && events.length > 0 && shown.length === 0;

  // A told step with nothing recorded says so on a line of the log, where it has one.
  const none = most > 0 && moment !== null && moment.revealed && events.length === 0;
  const visibility = moment?.step.visibility;
  let shownCount: { lead: string; after: string; title?: string } | null = null;
  if (moment && events.length > 0) {
    // When the recording keeps fewer events than the defense recorded, the head says both at every moment of the step.
    const kept = visibility?.kept !== undefined && visibility.events !== undefined && visibility.kept < visibility.events ? { kept: visibility.kept, recorded: visibility.events } : null;
    const title = kept ? `The defense recorded ${count(kept.recorded)} events of this step; the recording keeps ${count(kept.kept)} of them, every one listed in Analyse.` : undefined;
    if (events.length < total) shownCount = { lead: count(events.length), after: kept ? `of ${count(kept.kept)} kept, ${count(kept.recorded)} recorded` : `of ${count(total)} events`, title };
    else if (kept) shownCount = { lead: count(kept.recorded), after: `events recorded, ${count(kept.kept)} kept here`, title };
    else shownCount = { lead: count(total), after: total === 1 ? "event" : "events" };
  }

  return (
    // How many of its lines the log leaves empty: on a network the step's words below take that room.
    <section
      className={`lv-log${most > 0 ? "" : " is-head"}`}
      aria-label="What the sensors recorded"
      data-free={moment ? Math.max(0, most - shown.length - late.length - (earlierLine ? 1 : 0) - (none ? 1 : 0)) : 0}
      style={{ "--lv-lines": most } as StyleVars}
    >
      <div className="lv-log-head">
        <b>Recorded</b>
        <span className="lv-log-count" title={shownCount?.title}>
          {shownCount ? (
            <>
              <em>{shownCount.lead}</em> {shownCount.after}
              {allInAnalyse ? "," : ""}
            </>
          ) : null}
        </span>
        {onOpen && events.length > shown.length ? (
          <button type="button" className="lv-log-more" onClick={onOpen} title="Open this step in Analyse, where every event is listed">
            {/* With no line of the log shown, the way to Analyse says how many of the step's events it holds: every one the recording keeps. */}
            {allInAnalyse ? (total === 1 ? "listed in Analyse" : `all ${count(total)} in Analyse`) : `${count(events.length - shown.length)} more in Analyse`}
          </button>
        ) : null}
        <span className="lv-log-key">
          {sensors.map((sensor) => (
            <span key={sensor.id} title={`${sensor.name}: records ${sensor.records}`} style={{ "--rgb": colours.get(sensor.id) ?? "123,202,255" } as StyleVars}>
              <i className="lv-dot" />
              {sensorLabel(recording, sensor, "word")} <b>{count(events.filter((event) => event.sensor === sensor.id).length)}</b>
            </span>
          ))}
        </span>
      </div>
      <div className="lv-log-lines" ref={ref}>
        {shown.map((event, index) => {
          const mark = marks.get(event.id);
          const refused = event === refusal;
          const text = event.text || event.image || "";
          const classes = ["lv-log-line", mark ? `is-${mark.kind}` : "", refused ? "is-refused" : "", !mark && !refused && index < shown.length - 1 ? "is-old" : ""].filter(Boolean).join(" ");
          return (
            <div key={event.id} className={classes} style={{ "--rgb": colours.get(event.sensor) ?? "123,202,255" } as StyleVars}>
              <span className="lv-log-time">{clockTime(timeOf(event.time))}</span>
              <i className="lv-dot" title={recording.network.sensors.find((sensor) => sensor.id === event.sensor)?.name ?? event.sensor} />
              <span className="lv-log-kind">{event.kind}</span>
              <span className="lv-log-text" title={text}>
                {middleCut(text, room)}
              </span>
              <span className="lv-log-mark">{refused ? "stopped" : (mark?.word ?? "")}</span>
            </div>
          );
        })}
        {moment && none ? <div className="lv-log-none">{moment.step.outcome === "unseen" ? `${capital(unseenWords(moment.step))}.` : "Nothing recorded."}</div> : null}
        {[
          ...(earlierLine
            ? [
                {
                  at: earlierLine.at,
                  line: (
                    <div key="earlier" className={`lv-log-line is-late${earlierLine.kind === "launcher" ? "" : ` is-${earlierLine.kind}`}`} style={{ "--rgb": KIND_RGB[earlierLine.kind] } as StyleVars}>
                      <span className="lv-log-time">{earlierLine.time}</span>
                      <i className="lv-dot" title={allOwn ? "Raised after this step ended" : "Raised after their steps ended"} />
                      <span className="lv-log-kind">{allOwn ? "rule matches" : `${earlier.length} more`}</span>
                      <span className="lv-log-text" title={earlierLine.full}>
                        {allOwn ? earlierLine.text : middleCut(earlierLine.text, room)}
                      </span>
                      <span className="lv-log-mark">{earlierLine.word}</span>
                    </div>
                  ),
                },
              ]
            : []),
          ...late.map(({ alert }) => {
            const kind = matchKind(alert);
            // A match of the step on screen, raised in the silence after it, is its own: it needs no step's name, and says on which host it was raised.
            const own = alert.step === moment?.step.id;
            const where = recording.network.hosts.find((item) => item.id === alert.host)?.name ?? alert.host;
            // Its delay in the words the engine and the caption use: "raised 922 ms after the step ended".
            const after = raisedAfterStep(alert, recording.steps.find((item) => item.id === alert.step), own ? "the step" : "its step");
            const text = own ? `${where} · ${alert.rule.title} · ${after ?? "raised after the step ended"}` : `${lateName(alert)} · ${after ?? "raised after its step ended"}`;
            return {
              at: alertMoment(alert),
              line: (
                <div key={`late:${alert.id}`} className={`lv-log-line is-late${kind === "launcher" ? "" : ` is-${kind}`}`} style={{ "--rgb": KIND_RGB[kind] } as StyleVars}>
                  <span className="lv-log-time">{clockTime(alertMoment(alert))}</span>
                  <i className="lv-dot" title="Raised after its step ended" />
                  {/* An alert is called an alert; any other match raised after its step is a match. */}
                  <span className="lv-log-kind">{kind === "alert" ? "alert" : kind === "lab" ? "lab alert" : own ? "rule match" : "after its step"}</span>
                  <span className="lv-log-text" title={text}>
                    {middleCut(text, room)}
                  </span>
                  <span className="lv-log-mark">{markOf([alert])?.word ?? ""}</span>
                </div>
              ),
            };
          }),
        ]
          .sort((a, b) => a.at - b.at)
          .map((row) => row.line)}
      </div>
    </section>
  );
}
