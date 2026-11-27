// Analyse mode: the whole run on one axis on top; below it, the table of every
// step and the chosen step's detail, or the whole run's when none is chosen.

import { useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import type { Recording } from "./recording";
import type { Timeline } from "./playback";
import type { RunFacts } from "./moment";
import { stepRows } from "./analyse";
import { testNumbers } from "./format";
import { RunLanes } from "./RunLanes";
import { FIRST_TABLE_STATE, StepTable } from "./StepTable";
import type { TableState } from "./StepTable";
import { StepDetail } from "./StepDetail";
import { RunSummary } from "./RunSummary";

interface AnalyseViewProps {
  recording: Recording;
  timeline: Timeline;
  facts: RunFacts;
  colours: Map<string, string>;
  select: string | undefined;
  /** True when the chosen step's detail takes keyboard focus as the view opens. */
  focusSelected?: boolean;
  onSelect: (stepId: string | undefined) => void;
  onWatch: (stepId: string) => void;
  onFix?: (stepId: string) => void;
  /** Every defense's verdict on the run, above the chosen defense's lanes. */
  defenses?: ReactNode;
}

export function AnalyseView({ recording, timeline, facts, colours, select, focusSelected = false, onSelect, onWatch, onFix, defenses }: AnalyseViewProps) {
  const rows = useMemo(() => stepRows(recording, timeline), [recording, timeline]);
  const numbers = useMemo(() => testNumbers(recording), [recording]);
  const sensors = recording.network.sensors.filter((sensor) => rows.some((row) => row.bySensor.has(sensor.id)));
  const row = select === undefined ? undefined : rows.find((item) => item.step.id === select);
  // The table opens on the tests, unless the chosen step is not one: then on every step, so its row is there.
  const [table, setTable] = useState<TableState>(() => (row && row.step.role !== FIRST_TABLE_STATE.role ? { ...FIRST_TABLE_STATE, role: "all" } : FIRST_TABLE_STATE));
  const detail = useRef<HTMLDivElement | null>(null);
  const panel = useRef<HTMLElement | null>(null);
  // A step chosen in the table, or from a link in the detail or the summary,
  // moves focus to its detail, whose actions are then the next stops. A step
  // chosen in the lanes keeps focus there for the arrow keys, and one named in
  // the page's address takes nothing. A step opened from watch mode, whose
  // control went away with it, takes focus too.
  const [focusDetail, setFocusDetail] = useState(focusSelected);

  const choose = (stepId: string | undefined) => {
    setFocusDetail(false);
    onSelect(stepId);
    const chosen = stepId === undefined ? undefined : rows.find((item) => item.step.id === stepId);
    if (chosen && ((table.role !== "all" && chosen.step.role !== table.role) || (table.outcome !== null && chosen.step.outcome !== table.outcome))) setTable({ ...table, role: "all", outcome: null });
    if (detail.current) detail.current.scrollTop = 0;
  };
  // A filter that hides the chosen step closes its detail, so the detail always shows a step the table lists.
  const filterTable = (next: TableState) => {
    setTable(next);
    if (row && ((next.role !== "all" && row.step.role !== next.role) || (next.outcome !== null && row.step.outcome !== next.outcome))) onSelect(undefined);
  };
  const chooseInTable = (stepId: string) => {
    choose(stepId);
    setFocusDetail(true);
  };
  // Closing the detail puts focus back on the step's own place in the lanes.
  const close = () => {
    const closed = row?.step.id;
    choose(undefined);
    if (closed === undefined) return;
    requestAnimationFrame(() => {
      const button = [...(panel.current?.querySelectorAll<HTMLButtonElement>(".lv-ln-steps button") ?? [])].find((item) => item.dataset.step === closed);
      button?.focus();
    });
  };

  return (
    <section className={`lv-analyse${defenses ? " has-defenses" : ""}`} aria-label="Analyse" ref={panel}>
      {defenses ? <div className="lv-an-defenses">{defenses}</div> : null}
      <RunLanes recording={recording} timeline={timeline} facts={facts} colours={colours} selected={row?.step.id} onSelect={choose} />
      <div className="lv-an-body">
        <StepTable recording={recording} rows={rows} sensors={sensors} colours={colours} state={table} onState={filterTable} selected={row?.step.id} onSelect={chooseInTable} />
        <div className="lv-an-detail" ref={detail}>
          {row ? (
            <StepDetail
              key={row.step.id}
              recording={recording}
              row={row}
              colours={colours}
              testNumber={numbers.get(row.step.id)}
              testsTotal={numbers.size}
              origin={facts.start}
              originWords={facts.startWords}
              onSelect={chooseInTable}
              onWatch={onWatch}
              onFix={onFix}
              onClose={close}
              takeFocus={focusDetail}
            />
          ) : (
            <RunSummary recording={recording} timeline={timeline} facts={facts} onSelect={chooseInTable} />
          )}
        </div>
      </div>
    </section>
  );
}
