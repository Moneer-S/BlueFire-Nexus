// The table of every step in analyse mode: filters by role and by outcome,
// the step nobody saw first, the events each sensor recorded, and the rules
// that matched, published and lab apart.

import { useEffect, useRef } from "react";
import type { KeyboardEvent } from "react";
import type { Outcome, Sensor, Step, StepRole } from "./recording";
import { OUTCOME_ORDER, ROLE_ORDER, roleCount, tableRows } from "./analyse";
import type { SortKey, StepRow } from "./analyse";
import { count, outcomeClass, outcomeWords, plural, sensorWord } from "./format";
import type { StyleVars } from "./motion";

export interface TableState {
  role: StepRole | "all";
  outcome: Outcome | null;
  sort: SortKey;
  ascending: boolean;
}

/** The table opens on the tests, so its counts are the same as the score's. */
export const FIRST_TABLE_STATE: TableState = { role: "test", outcome: null, sort: "outcome", ascending: true };

interface StepTableProps {
  rows: StepRow[];
  sensors: Sensor[];
  colours: Map<string, string>;
  state: TableState;
  onState: (state: TableState) => void;
  selected: string | undefined;
  onSelect: (stepId: string) => void;
}

const ROLE_LABEL: Record<StepRole | "all", string> = { all: "All", test: "Tests", canary: "Canary", control: "Control", hardened: "Hardened", variant: "Variants" };

/** A hardened rerun whose change did not block it: the question a rerun asks is answered "no". */
function notStopped(step: Step): boolean {
  return step.role === "hardened" && step.outcome !== "stopped" && step.happened.answer === "took effect";
}

function MatchCell({ row }: { row: StepRow }) {
  const m = row.matches;
  // Informational matches are listed apart: nobody reviews them, so they do not swell "review".
  const reviewing = [...m.review, ...m.labReview];
  const info = reviewing.filter((alert) => alert.rule.level === "informational").length;
  const review = reviewing.length - info;
  const parts = [
    m.alert.length > 0 ? (
      <span key="a" className="is-alert">
        {m.alert.length} alert{m.alert.length === 1 ? "" : "s"}
      </span>
    ) : null,
    m.labAlert.length > 0 ? (
      <span key="l" className="is-lab" title="Rules written in this repository at alert level, not in the score">
        {m.labAlert.length} would alert
      </span>
    ) : null,
    review > 0 ? (
      <span key="r" className="is-review" title="Published rules at low or medium level">
        {review} review
      </span>
    ) : null,
    info > 0 ? (
      <span key="i" className="is-info" title="Rules at informational level">
        {info} info
      </span>
    ) : null,
    m.launcher.length > 0 ? (
      <span key="x" className="is-launcher" title="Matched only the shell command that carried the test, which never counts">
        {m.launcher.length} launcher
      </span>
    ) : null,
  ].filter((part) => part !== null);
  if (parts.length === 0) return <span className="is-none">none</span>;
  return <>{parts}</>;
}

export function StepTable({ rows, sensors, colours, state, onState, selected, onSelect }: StepTableProps) {
  const wrap = useRef<HTMLDivElement | null>(null);
  const roles = ([...ROLE_ORDER, "all"] as const).filter((kind) => kind === "all" || rows.some((row) => row.step.role === kind));
  // A role the recording has no step of, such as the tests the table opens on, reads as All: the table never opens empty with no filter pressed.
  const role = roles.includes(state.role) ? state.role : "all";
  const inRole = rows.filter((row) => role === "all" || row.step.role === role);
  const outcomes = OUTCOME_ORDER.filter((outcome) => inRole.some((row) => row.step.outcome === outcome));
  const outcome = state.outcome !== null && outcomes.includes(state.outcome) ? state.outcome : null;
  const shown = tableRows(rows, { role, outcome }, { key: state.sort, ascending: state.ascending });
  // One tab stop for the rows: the chosen one, or the first shown. Up and down move between them.
  const buttons = useRef<(HTMLButtonElement | null)[]>([]);
  const chosenAt = shown.findIndex((row) => row.step.id === selected);
  const stop = chosenAt >= 0 ? chosenAt : 0;
  const onRowKey = (event: KeyboardEvent<HTMLButtonElement>, index: number) => {
    const moves: Record<string, number> = { ArrowDown: index + 1, ArrowUp: index - 1, Home: 0, End: shown.length - 1 };
    const wanted = moves[event.key];
    if (wanted === undefined) return;
    event.preventDefault();
    buttons.current[Math.min(shown.length - 1, Math.max(0, wanted))]?.focus();
  };

  // Keep the selected row in view when it is chosen elsewhere, without moving the page.
  useEffect(() => {
    const box = wrap.current;
    if (!box || selected === undefined) return undefined;
    const reveal = () => {
      const line = [...box.querySelectorAll<HTMLTableRowElement>("tr[data-step]")].find((item) => item.dataset.step === selected);
      if (!line) return;
      const head = box.querySelector("thead")?.offsetHeight ?? 0;
      const top = line.offsetTop - head;
      const room = line.offsetHeight * 1.5;
      if (top < box.scrollTop || line.offsetTop + line.offsetHeight + room > box.scrollTop + box.clientHeight) box.scrollTop = Math.max(0, top - box.clientHeight / 3);
    };
    reveal();
    // Rows can grow once the page's font has loaded: look again then.
    let live = true;
    void document.fonts.ready.then(() => {
      if (live) reveal();
    });
    return () => {
      live = false;
    };
  }, [selected, state]);

  const sortBy = (key: SortKey) => onState({ ...state, sort: key, ascending: state.sort === key ? !state.ascending : key !== "events" && key !== "matches" });
  const header = (key: SortKey, label: string, className = "") => (
    <th className={className} aria-sort={state.sort === key ? (state.ascending ? "ascending" : "descending") : undefined} scope="col">
      <button type="button" onClick={() => sortBy(key)}>
        {label}
        {state.sort === key ? <i aria-hidden="true">{state.ascending ? "↑" : "↓"}</i> : null}
      </button>
    </th>
  );
  // The role column only says something when the table holds more than one role.
  const mixed = role === "all";
  const scope = role !== "all" ? roleCount(role, inRole.length) : rows.length === 1 ? "the one step" : `all ${plural(rows.length, "step")}`;

  return (
    <div className="lv-table-side">
      <div className="lv-filters">
        <div className="lv-seg" role="group" aria-label="Role">
          {roles.map((choice) => (
            <button
              key={choice}
              type="button"
              aria-pressed={role === choice}
              onClick={() => {
                const keep = outcome !== null && rows.some((row) => (choice === "all" || row.step.role === choice) && row.step.outcome === outcome);
                onState({ ...state, role: choice, outcome: keep ? outcome : null });
              }}
            >
              {ROLE_LABEL[choice]}
              <b>{choice === "all" ? rows.length : rows.filter((row) => row.step.role === choice).length}</b>
            </button>
          ))}
        </div>
        <div className="lv-chips" role="group" aria-label={`Outcomes of ${scope}`}>
          <span className="lv-chips-scope">{scope}:</span>
          {outcomes.map((chip) => (
            <button key={chip} type="button" className="lv-filter-chip" aria-pressed={outcome === chip} onClick={() => onState({ ...state, role, outcome: outcome === chip ? null : chip })}>
              <span className={`lv-ow is-${outcomeClass(chip)}`}>{outcomeWords(chip)}</span>
              <b>{inRole.filter((row) => row.step.outcome === chip).length}</b>
            </button>
          ))}
        </div>
        <span className="lv-filter-count">
          {shown.length} of {rows.length}
        </span>
      </div>
      <div className="lv-table-wrap" ref={wrap}>
        <table className="lv-table">
          <colgroup>
            <col className="is-n" />
            <col className="is-out" />
            {mixed ? <col className="is-role" /> : null}
            <col />
            <col className="is-tech" />
            {sensors.map((sensor) => (
              <col key={sensor.id} className="is-num" />
            ))}
            <col className="is-rules" />
          </colgroup>
          <thead>
            <tr>
              {header("order", "#", "is-n")}
              {header("outcome", "Outcome")}
              {mixed ? (
                <th scope="col" className="is-plain">
                  Role
                </th>
              ) : null}
              {header("title", "Step")}
              {header("technique", "Technique")}
              {sensors.map((sensor) => (
                <th key={sensor.id} className="is-num" scope="col" title={`Events ${sensor.name} recorded for the step`}>
                  <span style={{ "--rgb": colours.get(sensor.id) ?? "123,202,255" } as StyleVars}>
                    <i className="lv-dot" />
                    {sensorWord(sensor.name)}
                  </span>
                </th>
              ))}
              {header("matches", "Rules matched")}
            </tr>
          </thead>
          <tbody>
            {shown.map((row, place) => {
              const step = row.step;
              const lab = step.outcome_with_lab_rules !== undefined && step.outcome_with_lab_rules !== step.outcome ? step.outcome_with_lab_rules : null;
              const kept = step.visibility.kept !== undefined && row.recorded !== null && row.recorded > row.events.length;
              return (
                <tr key={step.id} data-step={step.id} className={`${step.role === "test" ? "" : "is-quiet"}${step.id === selected ? " is-selected" : ""}`} onClick={() => onSelect(step.id)}>
                  <td className="is-n">{row.index + 1}</td>
                  <td title={lab ? `With the rules written in this repository: ${lab}` : undefined}>
                    <span className={`lv-ow is-${outcomeClass(step.outcome)}`}>{step.outcome}</span>
                    {notStopped(step) ? <span className="lv-ow-note"> &middot; not stopped</span> : null}
                  </td>
                  {mixed ? <td className="is-role">{step.role}</td> : null}
                  <td className="is-title">
                    <div>
                      <button
                        type="button"
                        className="lv-row-button"
                        ref={(element) => {
                          buttons.current[place] = element;
                        }}
                        tabIndex={place === stop ? 0 : -1}
                        onKeyDown={(event) => onRowKey(event, place)}
                        aria-pressed={step.id === selected}
                        onClick={(event) => {
                          event.stopPropagation();
                          onSelect(step.id);
                        }}
                        title={step.title}
                      >
                        {step.title}
                      </button>
                      {kept ? (
                        <span className="lv-kept-tag" title="The recording keeps the first events of the step and every event a rule matched">
                          {count(row.recorded ?? 0)} recorded
                        </span>
                      ) : null}
                    </div>
                  </td>
                  <td className="is-tech" title={[step.technique.name, step.technique.tactic].filter(Boolean).join(", ")}>
                    {step.technique.id}
                  </td>
                  {sensors.map((sensor) => {
                    const count = row.bySensor.get(sensor.id) ?? 0;
                    return (
                      <td key={sensor.id} className={`is-num${count === 0 ? (step.outcome === "unseen" ? " is-gap" : " is-zero") : ""}`}>
                        {count}
                      </td>
                    );
                  })}
                  <td className="is-rules">
                    <MatchCell row={row} />
                  </td>
                </tr>
              );
            })}
            {shown.length === 0 ? (
              <tr>
                <td colSpan={(mixed ? 6 : 5) + sensors.length} className="lv-table-empty">
                  No step has this role and outcome.
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>
    </div>
  );
}
