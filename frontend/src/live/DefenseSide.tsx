// The chosen direction: the defense side of the map names the judge and lists
// every defense with its current-step mark and counts.

import "./defenses-c.css";
import type { Tally } from "./defenses";
import { outcomeWords, tallySaid } from "./DefenseParts";
import type { Box } from "./networkLayout";

export interface MapJudges {
  tallies: readonly Tally[];
  chosen: string;
  onChoose: (id: string) => void;
  goalTold: boolean;
  current: number;
}

function markClass(outcome: Tally["steps"][number]): string {
  return outcome === null ? "is-future" : `is-${outcome.replace(/\s+/g, "")}`;
}

export function DefenseSideHead({ judges, left, width }: { judges: MapJudges; left: number; width: number }) {
  const tally = judges.tallies.find((item) => item.id === judges.chosen);
  if (!tally) return null;
  return (
    <div className="lv-head is-left is-line lv-ds-head" style={{ left, width }} title={`${tally.name}. ${tally.when}. ${tally.made}`}>
      <b>Judged by</b>
      <span className="lv-ds-name">{tally.name}</span>
      <small>{tally.when}</small>
    </div>
  );
}

export function DefenseSideRows({ judges, box, mapHeight }: { judges: MapJudges; box: Box; mapHeight: number }) {
  return (
    <div className="lv-ds-rows" role="group" aria-label="The defenses that judge this run" style={{ left: box[0], bottom: mapHeight - box[3], width: box[2] - box[0], minHeight: box[3] - box[1] }}>
      <div className="lv-ds-row is-heads" aria-hidden="true">
        <span /><span /><span>alerted</span><span>seen</span><span>unseen</span><span>false alerts</span>
      </div>
      {judges.tallies.map((tally) => {
        const picked = tally.id === judges.chosen;
        const outcome = tally.steps[judges.current] ?? null;
        const step = judges.current >= 0 ? `Step ${judges.current + 1}` : "The current step";
        return (
          <button key={tally.id} type="button" className={`lv-ds-row${picked ? " is-chosen" : ""}`} aria-pressed={picked} aria-label={tallySaid(tally, judges.goalTold)} onClick={() => judges.onChoose(tally.id)} title={tallySaid(tally, judges.goalTold)}>
            <kbd className={markClass(outcome)} title={`Key ${tally.key}. ${step}: ${outcomeWords(outcome)}`} aria-label={`Key ${tally.key}. ${step}: ${outcomeWords(outcome)}`}>{tally.key}</kbd>
            <span className="lv-ds-rname" title={tally.name}>{tally.name}</span>
            <span className={`lv-ds-n is-alerted${tally.alerted === 0 ? " is-zero" : ""}`}>{tally.alerted}</span>
            <span className={`lv-ds-n is-seen${tally.seen === 0 ? " is-zero" : ""}`}>{tally.seen}</span>
            <span className={`lv-ds-n is-unseen${tally.unseen === 0 ? " is-zero" : ""}`}>{tally.unseen}</span>
            <span className={`lv-ds-n is-false${!tally.falseAlerts ? " is-zero" : ""}`}>{tally.falseAlerts === undefined ? "" : tally.falseAlerts === null ? "–" : tally.falseAlerts}</span>
          </button>
        );
      })}
    </div>
  );
}
