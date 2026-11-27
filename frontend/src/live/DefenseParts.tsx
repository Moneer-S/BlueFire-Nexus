// Shared parts of the live view when several defenses judge one run.

import "./defenses.css";
import type { Recording } from "./recording";
import { timeOf } from "./recording";
import type { Tally } from "./defenses";
import { firstAlertWords } from "./defenses";
import { capital, elapsed, plainMarks, plural, stepLabel, unitWord } from "./format";

export function runOutcome(recording: Recording, real: number, goalTold: boolean, whole: boolean): { reached: boolean; lead: string; detail: string } {
  const goal = recording.score.goal_seconds;
  const final = whole && recording.source.finished !== undefined;
  const reached = goal !== undefined && (goalTold || whole);
  const stopped = recording.steps.filter((step) => step.outcome === "stopped" && (whole || (step.ended !== undefined && timeOf(step.ended) <= real)));
  const stops = stopped.length === 0 ? (reached || final ? "no step stopped" : "no step stopped so far") : `${plural(stopped.length, "step")} stopped: ${stopped.map((step) => stepLabel(recording, step)).join(", ")}`;
  return {
    reached,
    lead: reached ? "The attacker reached its goal" : final ? "The attacker did not reach its goal" : "The attacker has not reached its goal",
    detail: reached && goal !== undefined ? `${elapsed(goal)} into the run, with ${stops}` : capital(stops),
  };
}

export function OutcomeLead({ recording, real, goalTold, whole }: { recording: Recording; real: number; goalTold: boolean; whole: boolean }) {
  if (recording.kind !== "attack path") return null;
  const said = runOutcome(recording, real, goalTold, whole);
  return (
    <div className={`lv-outcome${said.reached ? " is-reached" : ""}`} aria-label="The outcome" title={recording.attacker.goal === null ? undefined : `The attacker's goal: ${plainMarks(recording.attacker.goal)}`}>
      <b><i aria-hidden="true" />{said.lead}</b>
      <span>{said.detail}</span>
    </div>
  );
}

export function outcomeWords(outcome: Tally["steps"][number]): string {
  if (outcome === null) return "still to come";
  if (outcome === "running") return "running";
  if (outcome === "seen") return "seen, no alert";
  return outcome;
}

function markClass(outcome: Tally["steps"][number]): string {
  return outcome === null ? "is-future" : `is-${outcome.replace(/\s+/g, "")}`;
}

export function StepMark({ outcome, label }: { outcome: Tally["steps"][number]; label: string }) {
  const words = outcomeWords(outcome);
  return <i className={`lv-smark ${markClass(outcome)}`} role="img" aria-label={`${label}: ${words}`} title={`${label}: ${words}`} />;
}

export function StepMarks({ recording, tally }: { recording: Recording; tally: Tally }) {
  const unit = unitWord(recording);
  return (
    <span className="lv-smarks" aria-label={`${tally.name}, every ${unit}`}>
      {tally.steps.map((outcome, index) => <StepMark key={index} outcome={outcome} label={`${capital(unit)} ${index + 1}`} />)}
    </span>
  );
}

interface DefenseTableProps {
  recording: Recording;
  tallies: readonly Tally[];
  chosen: string;
  onChoose: (id: string) => void;
  goalTold: boolean;
}

export function DefenseTable({ recording, tallies, chosen, onChoose, goalTold }: DefenseTableProps) {
  const unit = unitWord(recording);
  return (
    <div className="lv-dtab" role="group" aria-label="The defenses side by side">
      <div className="lv-dtab-head" aria-hidden="true">
        <span /><span>Judged by</span><span>{`${capital(unit)}s 1 to ${recording.steps.length}`}</span>
        <span className="is-num">Alerted</span><span className="is-num">Seen, no alert</span><span className="is-num">Unseen</span>
        <span>First alert</span><span className="is-num">False alerts</span>
      </div>
      {tallies.map((tally) => {
        const first = firstAlertWords(tally, elapsed, goalTold);
        const picked = tally.id === chosen;
        return (
          <button key={tally.id} type="button" className={`lv-dtab-row${picked ? " is-chosen" : ""}`} aria-pressed={picked} aria-label={tallySaid(tally, goalTold)} onClick={() => onChoose(tally.id)} title={`${tally.name}. ${tally.when}. ${tally.made}`}>
            <kbd title={`Key ${tally.key} chooses this defense`}>{tally.key}</kbd>
            <span className="lv-dtab-name">{tally.name}</span>
            <StepMarks recording={recording} tally={tally} />
            <span className={`lv-dtab-n is-alerted${tally.alerted === 0 ? " is-zero" : ""}`}>{tally.alerted}</span>
            <span className={`lv-dtab-n is-seen${tally.seen === 0 ? " is-zero" : ""}`}>{tally.seen}</span>
            <span className={`lv-dtab-n is-unseen${tally.unseen === 0 ? " is-zero" : ""}`}>{tally.unseen}</span>
            <span className={`lv-dtab-first${tally.firstAlert ? "" : " is-none"}`}>
              {tally.firstAlert ? <i aria-hidden="true" /> : null}{first.when}{first.against ? <small>{first.against}</small> : null}
            </span>
            <span className={`lv-dtab-n is-false${tally.falseAlerts === 0 || tally.falseAlerts === null ? " is-zero" : ""}`}>
              {tally.falseAlerts === undefined ? "not scored" : tally.falseAlerts === null ? "–" : tally.falseAlerts}
            </span>
          </button>
        );
      })}
    </div>
  );
}

export function tallySaid(tally: Tally, goalTold: boolean): string {
  const first = firstAlertWords(tally, elapsed, goalTold);
  const counts = `${tally.alerted} alerted, ${tally.seen} seen with no alert, ${tally.unseen} unseen${tally.final ? "" : " so far"}`;
  const falseAlerts = tally.falseAlerts === undefined ? "; false alerts not scored" : tally.falseAlerts === null ? "" : `; ${plural(tally.falseAlerts, "false alert")} on ordinary activity`;
  return `${tally.name}: ${counts}; ${tally.firstAlert ? "first alert " : ""}${first.when}${first.against ? `, ${first.against}` : ""}${falseAlerts}. ${tally.when}. ${tally.made}`;
}
