// The race, on the recording's real clock: how far the attacker has got, and
// where the defense's first alert came, with one sentence that says who is winning.

import type { Recording } from "./recording";
import { rulesRanAfterTheRun } from "./recording";
import type { FirstAlert, Frame, ScoreSoFar, Timeline } from "./playback";
import { capital, clockTime, elapsed, ordinaryAlertEvents, plainMarks, plural, span, stepLabel } from "./format";
import { firstAlertClock, firstAlertOnScreen } from "./moment";
import type { RunFacts } from "./moment";

interface RaceLineProps {
  recording: Recording;
  timeline: Timeline;
  frame: Frame;
  facts: RunFacts;
  score: ScoreSoFar;
  /** True once the current step's outcome is told. */
  revealed: boolean;
}

/**
 * True once the screen tells that the attacker reached the goal: the clock has
 * passed it, and the run's first alert, when it was raised before the goal,
 * has been told (`told`, the first alert as the screen tells it), also when
 * that alert fires on screen only after the clock has passed the goal. The
 * goal never comes first on screen when the alert came first in the
 * recording, and once told it is not taken back.
 */
export function goalReached(frame: Frame, facts: RunFacts, told: FirstAlert | null): boolean {
  if (facts.goal === null || frame.real < facts.goal) return false;
  const first = facts.firstAlert;
  return told !== null || first === null || first.real > facts.goal;
}

/** The attacker's goal as the end of a sentence: its own words without a closing full stop. */
export function goalWords(goal: string): string {
  return goal.trim().replace(/[.\s]+$/, "");
}

/**
 * One sentence that says who is winning so far. For an attack path it is the
 * race between the first alert and the goal, both on the recording's real
 * clock: the goal falls `score.goal_seconds` after the first step's recorded start.
 */
export function whoIsWinning(recording: Recording, frame: Frame, score: ScoreSoFar, facts: RunFacts, firstAlert: FirstAlert | null = frame.race.firstAlert): string {
  const { race } = frame;
  if (frame.segment === null) return "Nothing has run yet.";
  if (recording.kind === "attack path") {
    const first = firstAlert;
    const goalReal = facts.goal;
    if (goalReal !== null && goalReached(frame, facts, first)) {
      // The goal is named where it is claimed: the format refuses a goal time without a goal.
      const goal = recording.attacker.goal === null ? "" : `: ${plainMarks(goalWords(recording.attacker.goal))}`;
      if (!first) return `The attacker reached the goal with no alert${goal}.`;
      const gap = span(Math.abs(goalReal - first.real));
      return first.real <= goalReal ? `The defense alerted ${gap} before the attacker reached the goal${goal}.` : `The attacker reached the goal ${gap} before the first alert${goal}.`;
    }
    if (first) {
      const clock = firstAlertClock(recording, facts, first);
      const where = stepLabel(recording, first.step);
      return clock ? `The defense raised its first alert on ${where}, ${elapsed(clock.seconds)} ${clock.words}.` : `The defense raised its first alert on ${where}.`;
    }
    return frame.ended ? "No alert on any step." : "No alert yet.";
  }
  const decided = score.alerted + score.seen + score.unseen;
  if (decided === 0) {
    if (race.testsRun === 0) return "No test has run yet.";
    if (race.testsRun === 1 && score.testsDone === 0) return "The first test is running.";
    return `${score.testsDone} of ${plural(race.testsTotal, "test")} ${score.testsDone === 1 ? "has" : "have"} run; none ${frame.ended ? "was" : "is yet"} alerted, seen or unseen.`;
  }
  // Once every test has run and the reruns play, the tests' count is final: no "so far".
  const final = frame.ended || (score.testsDone === race.testsTotal && frame.segment.step.role !== "test");
  const soFar = final ? "" : " so far";
  const through = score.seen + score.unseen;
  if (through === 0) return `Every test${soFar} raised an alert: ${score.alerted} of ${decided}.`;
  // Only the count fits here: the caption, the map and analyse mode say what the recording holds of an unseen test.
  const unseen = score.unseen > 0 ? `, ${score.unseen} unseen` : "";
  return `${through} of ${plural(decided, "test")}${soFar} got through without an alert${unseen}.`;
}

/** While hardened reruns play: how many of those told so far their change stopped. Null at any other step. */
export function rerunsSoFar(timeline: Timeline, frame: Frame, revealed: boolean): { stopped: number; told: number } | null {
  const current = frame.segment;
  if (!current || current.step.role !== "hardened") return null;
  const told = timeline.segments.filter((segment) => segment.step.role === "hardened" && (segment.end <= frame.time || (segment === current && revealed)));
  return { stopped: told.filter((segment) => segment.step.outcome === "stopped").length, told: told.length };
}

export function RaceLine({ recording, timeline, frame, facts, score, revealed }: RaceLineProps) {
  const length = Math.max(1, facts.end - facts.start);
  const at = (real: number) => `${(Math.min(1, Math.max(0, (real - facts.start) / length)) * 100).toFixed(3)}%`;
  const head = at(frame.real);
  const first = timeline.firstAlert;
  const reached = firstAlertOnScreen(frame.race.firstAlert, frame.time, frame.segment, revealed);
  const goal = recording.score.goal_seconds;
  const goalReal = facts.goal;
  const other = facts.otherFirst && frame.time >= facts.otherFirst.at ? facts.otherFirst : null;
  const firstLeft = first ? (first.real - facts.start) / length : 0;
  const testList = recording.kind === "test list";
  const segmentsBegun = timeline.segments.filter((segment) => segment.start <= frame.time).length;
  // While a step that is not a test plays, the counter also says how many of those have run.
  const others = timeline.segments.filter((segment) => segment.step.role !== "test");
  const otherTotal = others.length;
  const otherBegun = others.filter((segment) => segment.start <= frame.time).length;
  const otherNow = testList && frame.segment !== null && frame.segment.step.role !== "test" && otherBegun > 0;
  const otherRoles = [...new Set(others.map((segment) => segment.step.role))].join(", ");
  const reruns = rerunsSoFar(timeline, frame, revealed);
  const startLabel = firstLeft > 0.14 || !first || !reached;
  const otherNote = other ? `${capital(stepLabel(recording, other.step))} alerted at ${elapsed((other.real - facts.start) / 1000)} into the run${other.step.role === "canary" ? ", as expected: it is built to be caught" : ""}.` : undefined;
  // The flagged alert itself: the counting published match that fires first.
  const firstRule = first?.alert.rule.title;
  const firstFalse = firstRule ? ordinaryAlertEvents(recording, firstRule) : 0;
  const firstClock = first ? firstAlertClock(recording, facts, first) : null;
  const winning = whoIsWinning(recording, frame, score, facts, reached);
  // Rules that ran after the run have no time of their own: said once, here, where the first alert's time is shown.
  const eventTime = rulesRanAfterTheRun(recording);
  const eventTimeWords = "The rules ran after the run, so an alert's time is the time of the event it matched.";
  // The count of tests that got through leads the sentence, in the attacker's colour.
  const lead = winning.includes("got through") ? (/^\d[\d,]* of [\d,]+ tests?/.exec(winning)?.[0] ?? "") : "";

  return (
    <section className="lv-race" aria-label="The race">
      <div className="lv-race-side">
        <span className="lv-race-key">
          <i />
          Attacker
        </span>
        <span className="lv-race-value">
          {testList ? frame.race.testsRun : segmentsBegun}
          <small>of {testList ? plural(frame.race.testsTotal, "test") : plural(timeline.segments.length, "step")}</small>
        </span>
        <span className="lv-race-more" title={`Steps that are not tests (${otherRoles}), which are not in the score of tests`}>
          {otherNow ? `${otherBegun} of ${plural(otherTotal, "other step")}` : ""}
        </span>
      </div>
      <div className="lv-race-body">
        <div className="lv-track">
          {startLabel ? (
            <span className="lv-track-start" title={`Times count from ${facts.startWords}, ${clockTime(facts.start)} UTC`}>
              00:00
            </span>
          ) : null}
          <div className="lv-rail" />
          <div className="lv-fill" style={{ width: head }} />
          {other ? <div className="lv-pin" style={{ left: at(other.real) }} title={otherNote} /> : null}
          <div className="lv-head-dot" style={{ left: head }} title="The playhead" />
          {first && reached ? (
            <div
              className={`lv-flag${firstLeft > (eventTime ? 0.6 : 0.78) ? " is-end" : ""}`}
              style={{ left: at(first.real) }}
              title={[firstClock ? `${elapsed(firstClock.seconds)} ${firstClock.words}.` : "", eventTime ? eventTimeWords : "", `${capital(plural(first.testsBefore, "other test"))} had started when it fired.`, firstRule ? `Rule: ${firstRule}.` : "", firstFalse > 0 ? `Its rule also alerted on ${plural(firstFalse, "event")} of ordinary activity, outside every step.` : "", otherNote].filter(Boolean).join(" ")}
            >
              <span>
                {firstClock ? <b>{elapsed(firstClock.seconds)}</b> : null} first alert on a test &middot; {stepLabel(recording, first.step)}
                {eventTime ? <small className="lv-flag-note"> (the time of the event it matched)</small> : null}
              </span>
              <i />
            </div>
          ) : timeline.segments.length === 0 ? null : (
            <div className="lv-flag-wait">{frame.ended ? (testList ? "no test raised an alert" : "no alert") : testList ? "first alert on a test: not yet" : "first alert: not yet"}</div>
          )}
          {goalReal !== null && goalReached(frame, facts, reached) ? (
            <div className="lv-flag is-goal" style={{ left: at(goalReal) }} title={recording.attacker.goal === null ? undefined : `The attacker's goal: ${plainMarks(recording.attacker.goal)}`}>
              <span>
                <b>{elapsed(goal ?? 0)}</b> goal reached
              </span>
              <i />
            </div>
          ) : null}
        </div>
        <div className="lv-race-notes">
          <span className="lv-winning" title={reruns ? `${winning} Hardened reruns: ${reruns.stopped} of ${reruns.told} stopped so far.` : winning}>
            {lead ? <em>{lead}</em> : null}
            {winning.slice(lead.length)}
            {reruns ? (
              <span className="lv-phase">
                {" "}
                Hardened reruns: <b>{reruns.stopped}</b> of {reruns.told} stopped so far.
              </span>
            ) : null}
          </span>
          <span className="lv-race-end" title={`From ${facts.startWords} to the end of the last step${recording.source.finished ? "" : " so far"}, ${clockTime(facts.end)} UTC`}>
            {elapsed(length / 1000, 0)} {recording.source.finished ? "from the first step to the last" : "so far"}
          </span>
        </div>
      </div>
    </section>
  );
}
