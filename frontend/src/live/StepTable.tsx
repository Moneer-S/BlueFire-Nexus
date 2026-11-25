// The table of every step in analyse mode: filters by role and by outcome,
// the step nobody saw first, the events each sensor recorded, and the rules
// that matched, published and lab apart.

import { useEffect, useMemo, useRef } from "react";
import type { KeyboardEvent } from "react";
import type { Outcome, Recording, Sensor, Step, StepRole } from "./recording";
import { OUTCOME_ORDER, ROLE_ORDER, roleCount, tableRows } from "./analyse";
import type { SortKey, StepRow } from "./analyse";
import { capital, count, outcomeClass, outcomeWords, plural, sensorLabel, stepLabel, stepShortName, testNumbers, unitWord } from "./format";
import type { StyleVars } from "./motion";
import { useSize } from "./useSize";

export interface TableState {
  role: StepRole | "all";
  outcome: Outcome | null;
  sort: SortKey;
  ascending: boolean;
}

/** The table opens on the tests, so its counts are the same as the score's. */
export const FIRST_TABLE_STATE: TableState = { role: "test", outcome: null, sort: "outcome", ascending: true };

interface StepTableProps {
  recording: Recording;
  rows: StepRow[];
  sensors: Sensor[];
  colours: Map<string, string>;
  state: TableState;
  onState: (state: TableState) => void;
  selected: string | undefined;
  onSelect: (stepId: string) => void;
}

/** The room a step's title is given before the counts of rules take more than their least: two lines of a long title. */
const TITLE_ROOM = 330;
/** The counts of rules matched on one line, the longest a step has ("1 alert · 1 lab alert · 1 review · 1 launcher"). */
const RULES_MOST = 272;

/**
 * The widths of the columns of a table `width` pixels wide, each as its contents need it: the step's number or short
 * name ("rerun of test 12"), the outcome in the words the filter and the score use ("seen, no alert"), a technique's
 * id, a sensor's short name and count in its head ("Sysmon"), and the counts of rules matched, which take a sixth of
 * the table and wrap between counts where they need more, and more room once the title has its own. The title takes
 * the rest, so a long title wraps onto as few lines as the table allows. Null for the counts of rules before the
 * table is measured.
 */
export function tableColumns(width: number, sensors: number, numbered: boolean): { first: number; outcome: number; technique: number; sensor: number; rules: number | null } {
  const columns = { first: numbered ? 40 : 132, outcome: 124, technique: 92, sensor: 64 };
  const fixed = columns.first + columns.outcome + columns.technique + sensors * columns.sensor;
  const rules = width > 0 ? Math.round(Math.max(width * 0.17, Math.min(width - fixed - TITLE_ROOM, RULES_MOST))) : null;
  return { ...columns, rules };
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
      <span key="l" className="is-lab" title="The lab's own rules at alert level, which the score does not count">
        {m.labAlert.length} lab alert{m.labAlert.length === 1 ? "" : "s"}
      </span>
    ) : null,
    review > 0 ? (
      <span key="r" className="is-review" title="Published rules at low or medium level">
        {count(review)} review
      </span>
    ) : null,
    info > 0 ? (
      // The one word a table shortens, so the counts stay on one line: its whole word is its title.
      <span key="i" className="is-info" title={`${info} informational: rules at informational level`}>
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
  // A space between the counts lets the cell wrap between them: a count is never cut.
  return <>{parts.flatMap((part, index) => (index === 0 ? [part] : [" ", part]))}</>;
}

export function StepTable({ recording, rows, sensors, colours, state, onState, selected, onSelect }: StepTableProps) {
  // The box the rows scroll in: its width sets the columns' widths.
  const [wrap, wrapSize] = useSize<HTMLDivElement>();
  const numbers = useMemo(() => testNumbers(recording), [recording]);
  const unit = unitWord(recording);
  // On an attack path whose every step runs a published test, a tab of tests would hold the same rows as a tab of all:
  // one tab of steps holds them.
  const oneKind = unit === "step" && rows.every((row) => row.step.role === "test");
  const roles = oneKind ? (["all"] as const) : ([...ROLE_ORDER, "all"] as const).filter((kind) => kind === "all" || rows.some((row) => row.step.role === kind));
  // A role the recording has no step of, such as the tests the table opens on, reads as All: the table never opens empty with no filter pressed.
  const role = (roles as readonly (StepRole | "all")[]).includes(state.role) ? state.role : "all";
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

  // Keep the selected row in view when it is chosen elsewhere, without moving the page. The table stands at a row's
  // edge, so no row shows cut under the head: the first row in view is whole, and the selected one with it. The rows'
  // heights change after that (the columns' widths measured, the font loaded, the window resized): each time the
  // table or its box changes size, it stands again at the nearest row's edge, the selected row whole if it was in view.
  const end = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    const box = wrap.current;
    const table = box?.querySelector("table");
    if (!box || !table) return undefined;
    // Whether the selected row was in view, at least in part, when the table last stood still: it is then kept whole
    // when the rows move. Out of view, where one has scrolled away from it, it is left there.
    let seen = false;
    // Where the table last placed its scroll, and the sizes it was placed at. The scroll event of its own move comes
    // later, after the rows may have moved again, and a scroll that comes with a change of size is the browser keeping
    // the scroll inside a shorter list: neither says where one wants to look, and the change of size places it anew.
    let placed = 0;
    const sizes = () => [table.offsetWidth, table.offsetHeight, box.clientWidth, box.clientHeight].join(" ");
    let placedSizes = "";
    const inView = () => {
      const line = [...box.querySelectorAll<HTMLTableRowElement>("tr[data-step]")].find((item) => item.dataset.step === selected);
      if (!line) return false;
      const head = box.querySelector("thead")?.getBoundingClientRect().height ?? 0;
      const top = box.getBoundingClientRect().top + box.clientTop;
      const rect = line.getBoundingClientRect();
      return rect.bottom > top + head + 0.5 && rect.top < top + box.clientHeight - 0.5;
    };
    const place = (revealing: boolean) => {
      const head = box.querySelector("thead")?.getBoundingClientRect().height ?? 0;
      const top = box.getBoundingClientRect().top + box.clientTop;
      // Each row's edge: where the box's scroll stands when the row's top meets the head's foot.
      const lines = [...box.querySelectorAll<HTMLTableRowElement>("tr[data-step]")].map((item) => {
        const rect = item.getBoundingClientRect();
        return { id: item.dataset.step, edge: rect.top - top + box.scrollTop - head, height: rect.height };
      });
      const last = lines[lines.length - 1];
      if (!last) return;
      // The box's room after the list, where its last rows fade out (live.css).
      const fade = parseFloat(getComputedStyle(box).paddingBottom) || 0;
      // The list ends where the table stands at a row's edge with the last row whole above the fade: the room after the
      // last row grows by what that takes, so the end of the list is a row's edge too.
      const foot = last.edge + head + last.height;
      const lastEdge = lines.find((item) => item.edge >= foot + fade - box.clientHeight - 0.5)?.edge ?? 0;
      if (end.current) {
        const more = lastEdge > 0 ? `${Math.max(0, lastEdge + box.clientHeight - foot - fade)}px` : "0px";
        if (end.current.style.height !== more) end.current.style.height = more;
      }
      const now = box.scrollTop;
      const most = Math.max(0, box.scrollHeight - box.clientHeight);
      const line = lines.find((item) => item.id === selected);
      // The selected row is whole when the table stands at `edge`, with room under it for the next rows, or, the last
      // row, above the fade.
      const under = line === last ? fade : Math.max(fade, (line?.height ?? 0) * 1.5);
      const whole = (edge: number) => !line || (line.edge >= edge - 0.5 && line.edge + head + line.height + under <= edge + box.clientHeight + 0.5);
      const keep = line !== undefined && (revealing || seen);
      const reachable = lines.map((item) => item.edge).filter((edge) => edge <= most + 0.5);
      const fitting = keep ? reachable.filter(whole) : reachable;
      const edges = fitting.length > 0 ? fitting : keep && line && line.edge <= most + 0.5 ? [line.edge] : reachable;
      // Where it was, or, for a row just chosen that is not whole in view, a third of the way down.
      const wanted = keep && line && !whole(now) ? line.edge - box.clientHeight / 3 : now;
      const nearest = edges.reduce((best, edge) => (Math.abs(edge - wanted) < Math.abs(best - wanted) ? edge : best), edges[0] ?? 0);
      if (Math.abs(nearest - now) > 0.5) box.scrollTop = Math.max(0, nearest);
      seen = inView();
      placed = box.scrollTop;
      placedSizes = sizes();
    };
    place(true);
    const observer = new ResizeObserver(() => place(false));
    observer.observe(box);
    observer.observe(table);
    const scrolled = () => {
      if (Math.abs(box.scrollTop - placed) < 1 || sizes() !== placedSizes) return;
      seen = inView();
    };
    box.addEventListener("scroll", scrolled, { passive: true });
    return () => {
      observer.disconnect();
      box.removeEventListener("scroll", scrolled);
    };
  }, [selected, state, wrap]);

  const sortBy = (key: SortKey) => onState({ ...state, sort: key, ascending: state.sort === key ? !state.ascending : key !== "events" && key !== "matches" });
  const header = (key: SortKey, label: string, className = "") => (
    <th className={className} aria-sort={state.sort === key ? (state.ascending ? "ascending" : "descending") : undefined} scope="col">
      <button type="button" onClick={() => sortBy(key)}>
        {label}
        {state.sort === key ? <i aria-hidden="true">{state.ascending ? "↑" : "↓"}</i> : null}
      </button>
    </th>
  );
  // The first column names each row's step as the captions do: among the tests alone, by its number; otherwise by its short name, which says its role.
  const numbered = role === "test" || oneKind;
  const columns = tableColumns(wrapSize.width, sensors.length, numbered);
  const scope = role !== "all" ? roleCount(role, inRole.length, unit) : rows.length === 1 ? "the one step" : oneKind ? plural(rows.length, "step") : `all ${plural(rows.length, "step")}`;

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
              {oneKind ? "Steps" : ROLE_LABEL[choice]}
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
            <col style={{ width: columns.first }} />
            <col style={{ width: columns.outcome }} />
            <col />
            <col style={{ width: columns.technique }} />
            {sensors.map((sensor) => (
              <col key={sensor.id} style={{ width: columns.sensor }} />
            ))}
            <col style={columns.rules === null ? undefined : { width: columns.rules }} />
          </colgroup>
          <thead>
            <tr>
              {header("order", numbered ? capital(unit) : "Step", "is-n")}
              {header("outcome", "Outcome")}
              {header("title", "Title")}
              {header("technique", "Technique")}
              {sensors.map((sensor) => (
                <th key={sensor.id} className="is-num" scope="col" title={`The step's events from ${sensorLabel(recording, sensor)} that the recording keeps`}>
                  <span style={{ "--rgb": colours.get(sensor.id) ?? "123,202,255" } as StyleVars}>
                    <i className="lv-dot" />
                    {sensorLabel(recording, sensor, "column")}
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
                  <td className="is-n" title={stepLabel(recording, step)}>
                    {numbered ? (numbers.get(step.id) ?? "") : stepShortName(recording, step)}
                  </td>
                  <td className="is-outcome" title={lab ? `With the lab's own rules, which the score does not count: ${outcomeWords(lab)}` : undefined}>
                    <span className={`lv-ow is-${outcomeClass(step.outcome)}`}>{outcomeWords(step.outcome)}</span>
                    {/* On a line of its own under the outcome, so the cell is never cut; read as one phrase. */}
                    {notStopped(step) ? <span className="lv-ow-note"><span className="lv-sr"> &middot; </span>not stopped</span> : null}
                  </td>
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
                        <span className="lv-kept-tag" title="The recording keeps the first events of the step and every event a rule matched. The sensors' columns count the events it keeps.">
                          {count(row.events.length)} of {count(row.recorded ?? 0)} events kept
                        </span>
                      ) : null}
                    </div>
                  </td>
                  <td className="is-tech" title={[step.technique.name, step.technique.tactic].filter(Boolean).join(", ")}>
                    {step.technique.id}
                  </td>
                  {sensors.map((sensor) => {
                    const recorded = row.bySensor.get(sensor.id) ?? 0;
                    return (
                      <td key={sensor.id} className={`is-num${recorded === 0 ? (step.outcome === "unseen" ? " is-gap" : " is-zero") : ""}`}>
                        {count(recorded)}
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
                <td colSpan={5 + sensors.length} className="lv-table-empty">
                  No step has this role and outcome.
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
        {/* The room after the list that brings its end to a row's edge, set as the rows are measured. */}
        <div ref={end} aria-hidden="true" />
      </div>
    </div>
  );
}
