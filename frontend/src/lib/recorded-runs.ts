// Words and addresses for recorded runs: the recordings the service keeps, as
// the Runs screen lists them and the recorded run page plays them.

import type { LiveMoment, LiveViewProps } from "../live/LiveView";
import type { Recording } from "../live/recording";
import { count, day, onEnvironment, plural, span, unitWord } from "../live/format";
import type { DeltaSummary, RecordingList, RecordingOrigin, RecordingSummary } from "./api";

/** How often a recording that is still running is asked for again, by every page that shows one. */
export const RUNNING_POLL_MS = 4_000;

/**
 * The runs shipped with BlueFire first, then the imported ones, whatever their
 * dates, each newest first by when the run started: an imported copy never
 * takes a shipped run's place.
 */
export function inListOrder(recordings: readonly RecordingSummary[]): RecordingSummary[] {
  const rank = (summary: RecordingSummary) => (summary.origin.kind === "shipped" ? 0 : 1);
  return [...recordings].sort((a, b) => rank(a) - rank(b) || Date.parse(b.source.started) - Date.parse(a.source.started));
}

/**
 * The recordings the Runs screen lists on their own, in list order: a recording
 * that is one side of a listed pair is listed with its pair instead, so that two
 * near-identical runs of one pair do not read as two unrelated runs.
 */
export function ownRuns(recordings: readonly RecordingSummary[], pairs: readonly DeltaSummary[]): RecordingSummary[] {
  const paired = new Set(pairs.flatMap((pair) => [pair.before.id, pair.after.id]));
  return inListOrder(recordings).filter((summary) => !paired.has(summary.id));
}

/** When the later of a pair's two runs started, from the recordings the service keeps. */
function pairStarted(pair: DeltaSummary): number {
  return Math.max(Date.parse(pair.recordings.before.source.started), Date.parse(pair.recordings.after.source.started));
}

/**
 * The newest thing the Runs screen lists: the first recorded run it lists on its
 * own, or a pair of runs when the pair's later run started after that run. What
 * was shipped with BlueFire goes before what was imported, whatever the dates,
 * so an imported pair never takes a shipped run's place, nor an imported run a
 * shipped pair's.
 */
export function newestListed(recordings: readonly RecordingSummary[], pairs: readonly DeltaSummary[]): { run: RecordingSummary } | { pair: DeltaSummary } | null {
  const rank = (origin: Pick<RecordingOrigin, "kind">) => (origin.kind === "shipped" ? 0 : 1);
  const [run] = ownRuns(recordings, pairs);
  const [pair] = [...pairs].sort((a, b) => rank(a.origin) - rank(b.origin) || pairStarted(b) - pairStarted(a));
  if (!pair) return run ? { run } : null;
  if (!run) return { pair };
  const byOrigin = rank(pair.origin) - rank(run.origin);
  return byOrigin < 0 || (byOrigin === 0 && pairStarted(pair) > Date.parse(run.source.started)) ? { pair } : { run };
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

/** The origin in a few words: "Shipped with BlueFire" or "Imported, not verified by BlueFire". */
export function originWords(origin: Pick<RecordingOrigin, "kind">): string {
  return origin.kind === "shipped" ? "Shipped with BlueFire" : "Imported, not verified by BlueFire";
}

/**
 * The score in plain words: "3 of 60 tests alerted, 56 seen, 1 unseen", and of
 * an attack path, in the live view's word for its steps: "1 of 11 steps
 * alerted, 10 seen, 0 unseen". When some did not take effect, the count says
 * of how many: only one that took effect can alert, be seen or go unseen.
 */
export function recordedScoreWords(summary: Pick<RecordingSummary, "score" | "running" | "kind">): string {
  const score = summary.score;
  const unit = unitWord(summary);
  const soFar = summary.running ? " so far" : "";
  if (score.steps === 0) return summary.running ? `No ${unit} has run yet` : `No ${unit}s ran`;
  const rest = `${count(score.seen)} seen, ${count(score.unseen)} unseen${soFar}`;
  if (score.took_effect === score.steps) return `${count(score.alerted)} of ${plural(score.steps, unit)} alerted, ${rest}`;
  return `${count(score.alerted)} of the ${plural(score.took_effect, unit)} that took effect alerted, ${rest} (${plural(score.steps, unit)} ran)`;
}

/**
 * For an attack path, the race in plain words when the recording measured it,
 * and who won it: "The first alert came after 1 min 16 s, 10 min 54 s before
 * the attacker reached the goal", or "The attacker reached the goal after
 * 3 min, 12 s before the first alert". Both times count from the start of the
 * first step.
 */
export function recordedRaceWords(summary: Pick<RecordingSummary, "score" | "kind">): string | null {
  if (summary.kind !== "attack path") return null;
  const { first_alert_seconds: alert, goal_seconds: goal, alerted } = summary.score;
  if (alert !== undefined && goal !== undefined) {
    const gap = span(Math.abs(goal - alert) * 1000);
    return alert <= goal
      ? `The first alert came after ${span(alert * 1000)}, ${gap} before the attacker reached the goal`
      : `The attacker reached the goal after ${span(goal * 1000)}, ${gap} before the first alert`;
  }
  if (alert !== undefined) return `The first alert came after ${span(alert * 1000)}`;
  if (goal !== undefined) return `The attacker reached the goal after ${span(goal * 1000)}${alerted === 0 ? " with no alert" : ""}`;
  return null;
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

/**
 * The path of a recorded run's page inside the app: of the first file kept for
 * its id, or, with `sha256`, of that file, which a run evaluated more than once
 * needs to tell its evaluations apart.
 */
export function recordedRunPath(id: string, sha256?: string): string {
  return `/runs/recorded/${encodeURIComponent(id)}${sha256 ? `/${sha256}` : ""}`;
}

/**
 * The pairs as the Runs screen lists them: those shipped with BlueFire first,
 * then the imported ones, whatever their dates, each part in the order it
 * happened, by when the later of its runs started. An imported comparison
 * never takes a shipped turn's place.
 */
export function pairsInOrder(pairs: readonly DeltaSummary[]): DeltaSummary[] {
  const rank = (pair: DeltaSummary) => (pair.origin.kind === "shipped" ? 0 : 1);
  return [...pairs].sort((a, b) => rank(a) - rank(b) || pairStarted(a) - pairStarted(b));
}

/**
 * The turns of the defender loop: the pairs in list order that declare a
 * change. A comparison that declares none is listed and opened as a
 * comparison, outside the loop, and is never a turn.
 */
export function loopTurns(pairs: readonly DeltaSummary[]): DeltaSummary[] {
  return pairsInOrder(pairs).filter((pair) => pair.declared_change !== null);
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
  const defense = query.get("defense");
  if (defense) initial.defense = defense;
  return initial;
}

/**
 * Whether the moment to open at names a step, or a step to choose, that the
 * recording does not hold. The live view then opens at the start of the run, or
 * on the whole run, and says so in a line under the title.
 */
export function namesMissingStep(recording: Pick<Recording, "steps">, initial: LiveViewProps["initial"]): boolean {
  const held = new Set(recording.steps.map((step) => step.id));
  return (initial?.step !== undefined && !held.has(initial.step)) || (initial?.select !== undefined && !held.has(initial.select));
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
  if (moment.defense !== undefined) query.set("defense", moment.defense);
  return query;
}
