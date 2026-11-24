// Words and addresses for recorded runs: the recordings the service keeps, as
// the Runs screen lists them and the recorded run page plays them.

import type { LiveMoment, LiveViewProps } from "../live/LiveView";
import { count, day, plural, span } from "../live/format";
import type { RecordingList, RecordingOrigin, RecordingSummary } from "./api";

/** Newest first, by when the run started; the service lists shipped recordings before imported ones. */
export function newestFirst(recordings: readonly RecordingSummary[]): RecordingSummary[] {
  return [...recordings].sort((a, b) => Date.parse(b.source.started) - Date.parse(a.source.started));
}

/** "Test list" or "Attack path". */
export function recordingKindWords(kind: RecordingSummary["kind"]): string {
  return kind === "attack path" ? "Attack path" : "Test list";
}

/** "Recorded on a GitHub-hosted runner, 23 Nov 2026", or, while it runs, "Recording on a ..., started 23 Nov 2026". */
export function recordedWhere(summary: Pick<RecordingSummary, "source" | "running">): string {
  const date = day(summary.source.started);
  const where = onEnvironment(summary.source.environment);
  return summary.running ? `Recording ${where}, started ${date}` : `Recorded ${where}, ${date}`;
}

/** "on a GitHub-hosted runner", but "on containers on a developer machine": no article before a plural. */
function onEnvironment(environment: string): string {
  const first = environment.trim().split(/\s+/)[0] ?? "";
  if (/^(a|an|the)$/i.test(first) || /[^s]s$/i.test(first)) return `on ${environment}`;
  return `on ${/^[aeiou]/i.test(first) ? "an" : "a"} ${environment}`;
}

/** The origin in a word or three: "Shipped with BlueFire" or "Imported". */
export function originWords(origin: Pick<RecordingOrigin, "kind">): string {
  return origin.kind === "shipped" ? "Shipped with BlueFire" : "Imported";
}

/**
 * The score in plain words: "3 of 60 tests alerted, 56 seen, 1 unseen". When
 * some tests did not take effect, the count says of how many: only a test that
 * took effect can alert, be seen or go unseen.
 */
export function recordedScoreWords(summary: Pick<RecordingSummary, "score" | "running">): string {
  const score = summary.score;
  const soFar = summary.running ? " so far" : "";
  if (score.steps === 0) return summary.running ? "No test has run yet" : "No tests ran";
  const rest = `${count(score.seen)} seen, ${count(score.unseen)} unseen${soFar}`;
  if (score.took_effect === score.steps) return `${count(score.alerted)} of ${plural(score.steps, "test")} alerted, ${rest}`;
  return `${count(score.alerted)} of the ${plural(score.took_effect, "test")} that took effect alerted, ${rest} (${plural(score.steps, "test")} ran)`;
}

/** For an attack path, the race in plain words when the recording measured it: "First alert after 4 min 12 s, the goal after 9 min 3 s". */
export function recordedRaceWords(summary: Pick<RecordingSummary, "score" | "kind">): string | null {
  if (summary.kind !== "attack path") return null;
  const { first_alert_seconds: alert, goal_seconds: goal } = summary.score;
  const parts: string[] = [];
  if (alert !== undefined) parts.push(`first alert after ${span(alert * 1000)}`);
  if (goal !== undefined) parts.push(`the goal after ${span(goal * 1000)}`);
  if (parts.length === 0) return null;
  const text = parts.join(", ");
  return text.charAt(0).toUpperCase() + text.slice(1);
}

/**
 * The list with this recording's entry as `summary` gives it, or null when the
 * list does not hold it. A recorded run's page that has a newer answer about
 * its run puts it in the list, so the list does not show an older version.
 */
export function withSummary(list: RecordingList, summary: RecordingSummary): RecordingList | null {
  if (!list.recordings.some((entry) => entry.id === summary.id)) return null;
  return { ...list, recordings: list.recordings.map((entry) => (entry.id === summary.id ? summary : entry)) };
}

/** The path of a recorded run's page inside the app. */
export function recordedRunPath(id: string): string {
  return `/runs/recorded/${encodeURIComponent(id)}`;
}

/**
 * Whether the browser's address still shows `pathname`. The app keeps its
 * addresses after the `#`. A page someone has just left keeps its old location
 * from the router until the next page has rendered, which takes a while on a
 * busy machine, so a page that writes its address later asks the browser.
 */
export function addressShows(pathname: string): boolean {
  return (window.location.hash.slice(1).split("?")[0] ?? "") === pathname;
}

/** Where to open the live view, from the page's address: ?step=<id>&at=<0..1>&paused=1&mode=watch|analyse&select=<id>. */
export function momentFromSearch(query: URLSearchParams): NonNullable<LiveViewProps["initial"]> {
  const initial: NonNullable<LiveViewProps["initial"]> = {};
  const step = query.get("step");
  if (step) initial.step = step;
  const at = Number(query.get("at"));
  if (query.has("at") && Number.isFinite(at)) initial.at = at;
  if (query.get("paused") === "1") initial.paused = true;
  const mode = query.get("mode");
  if (mode === "watch" || mode === "analyse") initial.mode = mode;
  const select = query.get("select");
  if (select) initial.select = select;
  return initial;
}

/**
 * The address query of a moment: only what differs from opening the recording
 * fresh. The position goes with every step, 0 included: a step without one
 * opens partway through.
 */
export function momentSearch(moment: Partial<LiveMoment>): URLSearchParams {
  const query = new URLSearchParams();
  if (moment.step !== undefined) {
    query.set("step", moment.step);
    if (moment.at !== undefined) query.set("at", String(moment.at));
  }
  if (moment.paused) query.set("paused", "1");
  if (moment.mode === "analyse") query.set("mode", "analyse");
  if (moment.select !== undefined) query.set("select", moment.select);
  return query;
}
