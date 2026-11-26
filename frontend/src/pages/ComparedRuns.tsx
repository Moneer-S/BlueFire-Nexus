// One change to the defense, before against after, drawn from the delta that
// `bluefire-lab compare` wrote and the two recordings it names, and nothing
// else. The page answers in order: what the change did, what made the
// difference, what it cost, what else moved, how we know the comparison is
// fair, and where to go next. No difference is worked out here: every verdict,
// count and price is the delta's, and the recordings are read only to draw
// what each holds of a step.

import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, ArrowRight, Play } from "lucide-react";
import { useEffect, useMemo, useRef, type ReactNode } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { api, type Delta, type DeltaLabRule, type DeltaStep, type DeltaSummary } from "../lib/api";
import { fixPath, stepMoment } from "../lib/fix-step";
import { loopTurns, originWords, recordedRunPath } from "../lib/recorded-runs";
import { stageSide, type StageSide } from "../lib/pair-stage";
import { alertedByLabOnly, basisWords, creditedCount, headlineNamesStep, isCredited, isOneRun, judgedWords, keptNewRule, LAB_RULES, MARK_FIELD, pairHeadline, pairPath, priceSentence, priceWord, ruleAlerts, ruleChangeWords, ruleText, sideWhere, titlesWords, turnName } from "../lib/recording-pairs";
import { stepRows } from "../live/analyse";
import { capital, count, MARK_WORDS, plural, sensorColours, sensorShortName, testNumbers } from "../live/format";
import { runFacts } from "../live/moment";
import { buildTimeline } from "../live/playback";
import { readRecording, RecordingError, type Recording, type RecordingEvent } from "../live/recording";
import { StepDetail } from "../live/StepDetail";
import { ErrorState, LoadingState } from "../components/Primitives";
import { OutcomeMark, SideMark, Stages, type StageLinks } from "../components/PairStages";
import { FairLine, LabText, LimitBox, Records, Refused } from "../components/PairProof";
import "../live/live.css";
import "./RecordedRun.css";
import "./ComparedRuns.css";

type Side = "before" | "after";
const SIDES: readonly Side[] = ["before", "after"];

export function ComparedRunsPage() {
  const { deltaId = "" } = useParams<{ deltaId: string }>();
  return <ComparedRuns key={deltaId} deltaId={deltaId} />;
}

function ComparedRuns({ deltaId }: { deltaId: string }) {
  const entry = useQuery({ queryKey: ["recording-delta", deltaId], queryFn: () => api.recordingDelta(deltaId), retry: false });
  // The comparisons the service keeps that declare a change, shipped first, in the order they were made: the
  // turns of the loop this one is part of. A comparison that declares none is opened here outside the loop.
  const list = useQuery({ queryKey: ["recording-deltas"], queryFn: api.recordingDeltas, retry: false });
  const loop = loopTurns(list.data?.deltas ?? []);
  const place = loop.findIndex((pair) => pair.id === deltaId);
  if (entry.isPending) return <div className="compared is-message"><LoadingState label="Loading the compared runs" /></div>;
  if (!entry.data) {
    return <div className="compared is-message">
      <ComparedBar />
      <div className="compared-message"><ErrorState title="These compared runs could not be loaded" error={entry.error} retry={() => { void entry.refetch(); }} /></div>
    </div>;
  }
  return <div className="compared">
    <ComparedBar summary={entry.data.summary} place={place} />
    <PairView delta={entry.data.delta} summary={entry.data.summary} loop={loop} place={place} />
  </div>;
}

/** The quiet line under the app's header: back to Runs, and which turn of the loop this is. */
function ComparedBar({ summary, place = -1 }: { summary?: DeltaSummary; place?: number }) {
  return <header className="recorded-run-bar">
    <nav className="recorded-run-line" aria-label="Compared runs">
      <Link className="recorded-run-back" to="/runs"><ArrowLeft aria-hidden="true" />Runs</Link>
      {summary ? <p className="recorded-run-facts">
        <span>Before against after</span>
        <span className="recorded-run-title">{place >= 0 ? `Turn ${place + 1}: ` : ""}{turnName(summary)}</span>
        <span className={`recorded-run-origin is-${summary.origin.kind}`}>{summary.origin.kind === "shipped" ? "Shipped with BlueFire" : "Imported"}</span>
      </p> : null}
    </nav>
    {summary && summary.origin.kind !== "shipped" ? <p className="recorded-run-note">{summary.origin.note}</p> : null}
  </header>;
}

function read(value: unknown): { recording: Recording } | { problem: string } {
  try {
    return { recording: readRecording(value) };
  } catch (error) {
    return { problem: error instanceof RecordingError ? error.message : "The recording could not be read." };
  }
}

type Loaded = { recording: Recording } | { problem: string } | null;

/** Both recordings the delta names, each by its file: one run evaluated twice keeps two files under its one id. */
function usePairRecordings(delta: Delta): Record<Side, Loaded> {
  const load = (side: Side) => ({
    queryKey: ["recording-file", delta[side].id, delta[side].sha256],
    queryFn: () => api.recordingFile(delta[side].id, delta[side].sha256),
    retry: false,
  });
  const before = useQuery(load("before"));
  const after = useQuery(load("after"));
  return useMemo(() => {
    const state = (query: typeof before, side: Side): Loaded => {
      if (query.data) return read(query.data.recording);
      if (query.isError) return { problem: `The ${side} recording could not be loaded: ${query.error instanceof Error ? query.error.message : "the request failed"}.` };
      return null;
    };
    return { before: state(before, "before"), after: state(after, "after") };
  }, [before, after]);
}

function recordingOf(loaded: Loaded): Recording | null {
  return loaded && "recording" in loaded ? loaded.recording : null;
}

/** The steps the page can put on the stages, in the order its rows list them. */
function stageable(delta: Delta): { credited: DeltaStep[]; unjudged: DeltaStep[]; uncredited: DeltaStep[] } {
  const credited = delta.steps.filter((step) => isCredited(step.result));
  const unjudged = delta.steps.filter((step) => step.result === "no verdict");
  const uncredited = delta.steps.filter((step) => step.result === "not attributable" || step.result === "without cause");
  return { credited, unjudged, uncredited };
}

/** The address of a step in a recorded run's live view: paused at its start, to play from there, or open in analyse mode where Fix this says where the gap is. */
function playAt(delta: Delta, side: Side, stepId: string): string {
  return `${recordedRunPath(delta[side].id, delta[side].sha256)}?step=${encodeURIComponent(stepId)}&at=0&paused=1`;
}

/** The tests of a run that raise no alert, counting the lab's own rules too, and how many of them went unseen; with what the run's score, which counts only published rules, gives. */
function noAlert(recording: Recording): { left: number; unseen: number; scored: number; noEffect: number; inconclusive: number } {
  const tests = recording.steps.filter((step) => step.role === "test");
  const mark = (step: (typeof tests)[number]) => step.outcome_with_lab_rules ?? step.outcome;
  return {
    left: tests.filter((step) => mark(step) === "seen" || mark(step) === "unseen").length,
    unseen: tests.filter((step) => mark(step) === "unseen").length,
    scored: recording.score.seen + recording.score.unseen,
    noEffect: tests.filter((step) => mark(step) === "no effect").length,
    inconclusive: tests.filter((step) => mark(step) === "inconclusive").length,
  };
}

/** With no test left without an alert: what that says, and of which tests. */
function noneLeftWords({ noEffect, inconclusive }: { noEffect: number; inconclusive: number }): { lead: string; rest: string } {
  if (noEffect + inconclusive === 0) return { lead: "Every test raised an alert or was stopped", rest: "" };
  const parts = [
    ...(noEffect ? [`${plural(noEffect, "test")} had no effect`] : []),
    ...(inconclusive ? [`${plural(inconclusive, "test")} ${inconclusive === 1 ? "was" : "were"} inconclusive`] : []),
  ];
  return { lead: "Every test the run can judge raised an alert or was stopped", rest: `${parts.join(" and ")}, so the run says nothing about ${noEffect + inconclusive === 1 ? "it" : "them"}` };
}

/** "41 tests still raised no alert", counted with the lab's own rules. */
function leftWords(left: number): string {
  return `${plural(left, "test")} still raised no alert`;
}

/** The page "Fix this" opens for the step in the run after, whose Back goes to the step in analyse mode there. */
function fixAt(delta: Delta, stepId: string): string {
  return `${fixPath(delta.after.id, delta.after.sha256, stepId)}?${stepMoment(stepId).toString()}`;
}

/** For a turn that was imported, the words the app gives an imported file; for one shipped with BlueFire, nothing. */
function importedWords(pair: DeltaSummary): string | null {
  return pair.origin.kind === "shipped" ? null : originWords(pair.origin);
}

function beforeId(step: DeltaStep): string {
  return step.before_id ?? step.id;
}

/** The change as the arrow between the marks carries it, small: "new auditd settings", "a new rule". */
function changeLabel(delta: Delta): string {
  const name = turnName(delta);
  return name.charAt(0).toLowerCase() + name.slice(1);
}

function singleRule(delta: Delta): DeltaLabRule | null {
  const rules = delta.declared_change === LAB_RULES ? delta.lab_rules ?? [] : [];
  const [only] = rules;
  return rules.length === 1 && only ? only : null;
}

function PairView({ delta, summary, loop, place }: { delta: Delta; summary: DeltaSummary; loop: readonly DeltaSummary[]; place: number }) {
  const [params, setParams] = useSearchParams();
  const groups = stageable(delta);
  const candidates = [...groups.credited, ...groups.unjudged, ...groups.uncredited];
  const asked = params.get("step");
  // The stages show a step the page lists. An address that names any other step, one the change did not move, opens the
  // page as if it named none: its stages would stand beside the move of another step and under what made that difference.
  const staged = candidates.find((step) => step.id === asked) ?? candidates[0] ?? null;
  const detailOpen = params.get("detail") === "1" && staged !== null;
  const recordings = usePairRecordings(delta);
  const next = place >= 0 ? loop[place + 1] ?? null : null;
  const previous = place > 0 ? loop[place - 1] ?? null : null;

  const choose = (stepId: string, detail = false) => {
    const nextParams = new URLSearchParams(params);
    nextParams.set("step", stepId);
    if (detail) nextParams.set("detail", "1");
    else nextParams.delete("detail");
    // A step on the stages is a place of its own: Back returns to the one before.
    setParams(nextParams, { preventScrollReset: true });
  };
  const closeDetail = () => {
    const nextParams = new URLSearchParams(params);
    nextParams.delete("detail");
    setParams(nextParams, { preventScrollReset: true });
  };

  return <div className="lv compared-view">
    <div className="cmp-page">
      {loop.length > 0 && place >= 0 ? <LoopBar loop={loop} place={place} /> : null}
      <Answer delta={delta} moved={groups.credited} after={recordingOf(recordings.after)} />
      {!delta.comparable ? <Refused delta={delta} /> : null}
      {delta.comparable && delta.limit ? <LimitBox delta={delta} limit={delta.limit} /> : null}

      <section className="cmp-did" aria-labelledby="cmp-did-heading">
        <h2 id="cmp-did-heading" className="lv-sr">What the change did</h2>
        <Move delta={delta} groups={groups} staged={staged} onChoose={(id) => choose(id)} />
        {staged ? <StagesSlot delta={delta} step={staged} recordings={recordings} judged={isCredited(staged.result)} onDetail={() => choose(staged.id, !detailOpen)} detailOpen={detailOpen} /> : null}
      </section>
      {detailOpen && staged ? <PairDetail delta={delta} step={staged} onClose={closeDetail} /> : null}

      <div className="cmp-row">
        <Cost delta={delta} moved={groups.credited} recordings={recordings} />
        <Else delta={delta} moved={groups.credited} staged={staged} />
        <Next delta={delta} moved={groups.credited} next={next} after={recordingOf(recordings.after)} />
      </div>

      <FairLine delta={delta} summary={summary} />

      <Difference delta={delta} moved={groups.credited} staged={staged} recordings={recordings} />
      {staged ? <Ways delta={delta} staged={staged} moved={groups.credited} after={recordingOf(recordings.after)} /> : null}
      <GoFrom delta={delta} previous={previous} next={next} place={place} after={recordingOf(recordings.after)} />
    </div>
  </div>;
}

/** Where this turn stands in the loop: the comparisons the service keeps, in the order they were made, each by its name. */
function LoopBar({ loop, place }: { loop: readonly DeltaSummary[]; place: number }) {
  const last = loop[loop.length - 1];
  return <nav className="cmp-loop" aria-label="The defender loop">
    <span className="cmp-loop-label" aria-hidden="true">The defender loop</span>
    <ol>
      {loop.map((pair, index) => {
        const current = index === place;
        const kind = pair.declared_change?.startsWith("sensors:") ? "" : " is-rule";
        const imported = importedWords(pair);
        const body = <><span className="cmp-loop-n" aria-hidden="true">{index + 1}</span><span className="cmp-loop-name"><span className="lv-sr">Turn {index + 1}: </span>{turnName(pair)}</span>{imported ? <span className="cmp-loop-origin"><span className="lv-sr">, </span>{imported}</span> : null}</>;
        return <li key={pair.id}>{current
          ? <span className={`cmp-loop-turn is-on${kind}`} aria-current="page">{body}</span>
          : <Link className={`cmp-loop-turn${kind}`} to={pairPath(pair.id)}>{body}</Link>}</li>;
      })}
      {last ? <li><Link className="cmp-loop-turn is-todo" to={`${recordedRunPath(last.after.id, last.after.sha256)}?mode=analyse`}><span className="cmp-loop-n" aria-hidden="true">+</span><span className="cmp-loop-name">Next change</span></Link></li> : null}
    </ol>
  </nav>;
}

/** What the change did, first and large, with the tests named in plain words and the basis of the verdict in one small line. */
function Answer({ delta, moved, after }: { delta: Delta; moved: readonly DeltaStep[]; after: Recording | null }) {
  const headline = pairHeadline(delta, moved);
  const variants = moved.some((step) => step.role === "variant");
  const [first] = moved;
  const recorded = first && after ? after.steps.find((step) => step.id === first.id) : undefined;
  const titles = titlesWords(moved);
  const labOnly = first !== undefined && moved.every((step) => alertedByLabOnly(step.after) && !alertedByLabOnly(step.before));
  let sub: ReactNode = null;
  if (!delta.comparable) sub = "The comparison was refused, so nothing here is credited to the change. It still lists what differed.";
  else if (delta.declared_change === null) sub = "So no step is credited to a change: a step that differs is run variation, not an effect.";
  else if (moved.length === 0) sub = "Every step the change could move reads as it did before.";
  else if (headlineNamesStep(delta, moved) && first) {
    // The headline names the step: the line under it says what the step is.
    const what = recorded?.test ? `A published test of ${recorded.test.project} for ${recorded.technique.id}${recorded.technique.name ? `, ${recorded.technique.name}` : ""}.` : `Technique ${first.technique}.`;
    sub = <>{what}{labOnly ? " Alerted by the lab's own rules." : null}</>;
  } else {
    const what = variants ? ", each as published and again with other arguments."
      : ` (${[...new Set(moved.map((step) => step.technique))].join(", ")}).`;
    sub = <><b>{titles}</b>{what}{labOnly ? " Alerted by the lab's own rules." : null}</>;
  }
  return <header className={`cmp-answer${delta.comparable ? "" : " is-refused"}`}>
    <h1>{headline}</h1>
    {sub ? <p className="cmp-sub">{sub}</p> : null}
    <p className="cmp-basis">{basisWords(delta)}</p>
  </header>;
}

function roleWords(step: Pick<DeltaStep, "role">): string {
  if (step.role === "variant") return "with other arguments";
  if (step.role === "test") return "as published";
  if (step.role === "canary" || step.role === "control") return "a check of the lab itself";
  if (step.role === "hardened") return "on the hardened target";
  return step.role;
}

/** The move: where the step stood, the one change, where it stands; with several steps, one aligned row each, and the row chooses what the stages show. */
function Move({ delta, groups, staged, onChoose }: { delta: Delta; groups: ReturnType<typeof stageable>; staged: DeltaStep | null; onChoose: (id: string) => void }) {
  const { credited, unjudged, uncredited } = groups;
  const [first] = credited;
  const uniform = first !== undefined && credited.every((step) => step.before[MARK_FIELD] === first.before[MARK_FIELD] && step.after[MARK_FIELD] === first.after[MARK_FIELD]);
  const rule = singleRule(delta);
  const label = <div className="cmp-change-label">
    <span className="cmp-change-key">{delta.comparable && !delta.limit ? "The one change" : "The declared change"}</span>
    <span className="cmp-change-value">{changeLabel(delta)}</span>
    {rule ? <span className="cmp-change-sub">{rule.title}</span> : null}
  </div>;
  const row = (step: DeltaStep, judged: boolean, note?: string) => <li key={step.id}>
    <button type="button" className={`cmp-row-step${staged?.id === step.id ? " is-on" : ""}${judged ? "" : " is-unjudged"}`} aria-pressed={staged?.id === step.id} onClick={() => onChoose(step.id)}>
      <b className="cmp-row-title">{step.title}</b>{" "}
      <small className="cmp-row-role">{roleWords(step)}{note ? ` · ${note}` : ""}{step.mark ? " · credited by the change's own mark" : ""}</small>
      <span className="cmp-row-marks">
        <span className="lv-sr">Before </span><SideMark side={step.before} dim={!judged} />
        <span className="cmp-row-to" aria-hidden="true">{judged ? "→" : "·"}</span>
        <span className="lv-sr">{judged ? ", after " : " and after "}</span><SideMark side={step.after} dim={!judged} />
      </span>
    </button>
  </li>;
  const single = credited.length === 1 && unjudged.length === 0 && uncredited.length === 0 && first;
  return <div className="cmp-move">
    {single ? <div className="cmp-move-one">
      <div className="cmp-move-side"><span className="cmp-move-key">Before</span><SideMark side={first.before} big /></div>
      <div className="cmp-move-down">{label}</div>
      <div className="cmp-move-side"><span className="cmp-move-key">After</span><SideMark side={first.after} big /></div>
    </div> : first && uniform ? <div className="cmp-move-head">
      <p className="cmp-move-line"><span className="lv-sr">Before </span><SideMark side={first.before} /><ArrowRight className="cmp-move-arrow" aria-hidden="true" /><span className="lv-sr">, after </span><SideMark side={first.after} times={creditedCount(delta.counts)} /></p>
      {label}
    </div> : label}
    {credited.length > 1 || (credited.length === 1 && !single) ? <>
      <p className="cmp-rows-key">{credited.length > 1 ? `The ${count(credited.length)} steps that moved` : "The step that moved"}<span>choose one for the stages</span></p>
      <ul className="cmp-rows">{credited.map((step) => row(step, true))}</ul>
    </> : null}
    {unjudged.length ? <>
      <p className="cmp-rows-key is-warn">Steps that differ, not judged<span>the comparison gives no verdict</span></p>
      <ul className="cmp-rows">{unjudged.map((step) => row(step, false, "not judged"))}</ul>
    </> : null}
    {uncredited.length ? <>
      <p className="cmp-rows-key is-warn">{delta.limit ? "Also moved, not credited to the change" : "Changed without a cause"}<span>{delta.limit ? "the two runners differed, and could have moved these" : "run variation, not an effect"}</span></p>
      <ul className="cmp-rows">{uncredited.map((step) => row(step, false, step.result === "not attributable" ? "not attributable" : "changed without a cause"))}</ul>
    </> : null}
    {credited.length === 0 && unjudged.length === 0 && uncredited.length === 0 ? <p className="cmp-empty">{delta.declared_change === null ? "Nothing was declared as changed, so no step is credited to a change." : "No step moved in what this change can move."}</p> : null}
  </div>;
}

/** The words over each stage, by what changed. */
function stageWords(delta: Delta, sensorName: string | null): Record<Side, string> {
  const declared = delta.declared_change ?? "";
  if (!delta.comparable) return { before: "the run before", after: "the run after" };
  if (declared.startsWith("sensors:")) {
    const name = sensorName ?? declared.slice("sensors:".length);
    return { before: `${name}'s earlier settings`, after: `${name}'s new settings` };
  }
  const rule = singleRule(delta);
  if (rule?.change === "new") return { before: "without the new rule", after: "with the new rule" };
  if (rule?.change === "gone") return { before: "with the rule", after: "without the rule" };
  if (declared === LAB_RULES) return { before: "the lab's rules before", after: "the lab's rules after" };
  return { before: "before the change", after: "after the change" };
}

function StagesSlot({ delta, step, recordings, judged, onDetail, detailOpen }: { delta: Delta; step: DeltaStep; recordings: Record<Side, Loaded>; judged: boolean; onDetail: () => void; detailOpen: boolean }) {
  const before = recordingOf(recordings.before);
  const after = recordingOf(recordings.after);
  const problem = SIDES.map((side) => recordings[side]).find((loaded): loaded is { problem: string } => loaded !== null && "problem" in loaded);
  const sides: Record<Side, StageSide | null> = {
    before: before ? stageSide(before, beforeId(step)) : null,
    after: after ? stageSide(after, step.id) : null,
  };
  const toggle = <button type="button" className="cmp-detail-toggle" aria-expanded={detailOpen} onClick={onDetail}>{detailOpen ? "Close the step's detail" : "Every detail of this step, from both runs"}</button>;
  let body;
  if (problem) body = <p className="cmp-stages-wait" role="status">{problem.problem}</p>;
  else if (!before || !after) body = <p className="cmp-stages-wait" role="status">Loading what each run recorded of {step.title}.</p>;
  else if (!sides.before || !sides.after) body = <p className="cmp-stages-wait" role="status">A recording has no step {!sides.before ? beforeId(step) : step.id}.</p>;
  else {
    const declared = delta.declared_change ?? "";
    const sensorId = declared.startsWith("sensors:") ? declared.slice("sensors:".length) : null;
    const sensor = sensorId ? after.network.sensors.find((item) => item.id === sensorId) : undefined;
    const newRules = new Set((delta.lab_rules ?? []).filter((row) => row.change === "new" || row.change === "changed").map((row) => row.rule));
    const oneRun = isOneRun(delta);
    const links: Record<Side, StageLinks> = {
      before: { play: playAt(delta, "before", beforeId(step)), playWords: oneRun ? "Play it with the rules before" : "Play it in the run before" },
      after: {
        play: playAt(delta, "after", step.id),
        playWords: oneRun ? "Play it with the rules after" : "Play it in the run after",
        ...(sides.after.outcome === "seen" || sides.after.outcome === "unseen" ? { fix: fixAt(delta, step.id) } : {}),
      },
    };
    body = <Stages
      before={sides.before}
      after={sides.after}
      words={stageWords(delta, sensor ? sensorShortName(sensor.name) : sensorId)}
      runs={oneRun ? { before: null, after: null } : { before: delta.before.id, after: delta.after.id }}
      links={links}
      newRules={newRules}
      judged={judged}
      footer={toggle}
    />;
  }
  return <div className="cmp-stages" aria-label={`${step.title}, before and after`} role="group">
    {body}
    {sides.before && sides.after ? null : toggle}
  </div>;
}

/** What the change cost: false alerts on ordinary activity, before and after, or why the files hold no such count. */
function Cost({ delta, moved, recordings }: { delta: Delta; moved: readonly DeltaStep[]; recordings: Record<Side, Loaded> }) {
  const price = moved.find((step) => step.price)?.price ?? "";
  const before = recordingOf(recordings.before);
  const after = recordingOf(recordings.after);
  const kept = keptNewRule(delta);
  let body;
  if (!delta.comparable) {
    body = <><p className="cmp-cost-big is-word">Not judged</p><p>With no verdict there is no price either.</p></>;
  } else if (!price) {
    body = moved.length ? <><p className="cmp-cost-big is-word">Not stated</p><p>The comparison gives no price for these steps.</p></> : <><p className="cmp-cost-big is-word">Nothing to pay</p><p>No step moved, so the comparison gives no price.</p></>;
  } else if (price.startsWith("price not counted") && kept) {
    // The run after kept the one new rule, which it does only for a rule that alerted on no ordinary activity in it.
    const reason = kept.after?.reason;
    body = <>
      <p className="cmp-cost-big is-word">{priceWord(price, delta)}</p>
      <p>{priceSentence(price, delta)} One run is a test the rule passed, not a price measured over time.</p>
      <details className="cmp-more"><summary>The price in the lab's words</summary>
        {reason ? <p>Why the run kept the rule: <LabText text={reason} />.</p> : null}
        <p className="cmp-small">In the lab's words: <LabText text={price} /></p>
      </details>
    </>;
  } else if (price.startsWith("price not counted")) {
    const rule = singleRule(delta);
    body = <>
      <p className="cmp-cost-big is-word">{priceWord(price, delta)}</p>
      <p>{priceSentence(price, delta)} The files hold no price for these rules.</p>
      <details className="cmp-more"><summary>{rule?.after?.accepted ? "Why the run used the rule" : "The price in the lab's words"}</summary>
        {rule?.after?.accepted && rule.after.reason ? <p>Because {rule.after.reason}: a test it passed in this run, not a price measured over time.</p> : null}
        <p className="cmp-small">In the lab's words: <LabText text={price} /></p>
      </details>
    </>;
  } else if (price.startsWith("price not known")) {
    body = <>
      <p className="cmp-cost-big is-word">{priceWord(price, delta)}</p>
      <p>{priceSentence(price, delta)}</p>
      <details className="cmp-more"><summary>The price in the lab's words</summary><p><LabText text={price} /></p></details>
    </>;
  } else {
    const fa = [before?.score.false_alerts, after?.score.false_alerts];
    const high = (recording: Recording | null) => (recording?.ordinary?.matches ?? []).filter((match) => match.level === "high" || match.level === "critical");
    const rulesBefore = high(before), rulesAfter = high(after);
    const names = [...new Set([...rulesBefore, ...rulesAfter].map((match) => match.rule))];
    // The events of ordinary activity each rule matched: a rule that alerted there is one false alert, however many events it matched.
    const events = (list: typeof rulesBefore, rule: string) => list.filter((match) => match.rule === rule).reduce((sum, match) => sum + match.count, 0);
    body = <>
      {fa[0] !== undefined && fa[1] !== undefined ? <p className="cmp-cost-big"><b>{fa[0]}</b> before, <b>{fa[1]}</b> after</p> : null}
      <p>{priceSentence(price, delta)}</p>
      <details className="cmp-more"><summary>Which rules, and on how much activity</summary>
        {names.length ? <ul>{names.map((rule) => <li key={rule}><b>{rule}</b>: {plural(events(rulesBefore, rule), "event")} before, {count(events(rulesAfter, rule))} after</li>)}</ul> : null}
        {before?.ordinary && after?.ordinary ? <p>Ordinary activity: {count(before.ordinary.events)} events before, {count(after.ordinary.events)} after. The lab does not say how alike the two were. The lab's own rules are not counted here.</p> : null}
        <p className="cmp-small">In the lab's words: <LabText text={price} /></p>
      </details>
    </>;
  }
  return <section className="cmp-side cmp-cost" aria-labelledby="cmp-cost-heading">
    <h2 id="cmp-cost-heading">What it cost</h2>
    {body}
  </section>;
}

/** Every step of the run before and after as one cell each, in order, the moved ones marked. */
function Else({ delta, moved, staged }: { delta: Delta; moved: readonly DeltaStep[]; staged: DeltaStep | null }) {
  const ids = new Set(moved.map((step) => step.id));
  const c = delta.counts;
  const others = c["without cause"] + c["not attributable"] + c["no verdict"];
  const cell = (step: DeltaStep, side: Side) => {
    const outcome = step[side][MARK_FIELD];
    const classes = ["cmp-cell", `is-${outcome.replace(/\s+/g, "")}`];
    if (alertedByLabOnly(step[side])) classes.push("is-lab");
    if (step.role === "canary" || step.role === "control") classes.push("is-check");
    if (ids.has(step.id)) classes.push("is-moved");
    if (!ids.has(step.id) && step.result !== "same") classes.push("is-differs");
    if (staged?.id === step.id) classes.push("is-staged");
    return <span key={step.id} className={classes.join(" ")} title={`${step.title} (${roleWords(step)}): ${outcome === "seen" ? "seen, no alert" : outcome}`} />;
  };
  // The moved cells named where they stand, one label for each run of neighbours.
  const runs: { from: number; to: number; steps: DeltaStep[] }[] = [];
  delta.steps.forEach((step, index) => {
    if (!ids.has(step.id)) return;
    const last = runs[runs.length - 1];
    if (last && last.to === index - 1) {
      last.to = index;
      last.steps.push(step);
    } else runs.push({ from: index, to: index, steps: [step] });
  });
  const total = delta.steps.length;
  const credited = creditedCount(c);
  const headline = !delta.comparable ? "Not judged" : others > 0 ? `${count(others)} more ${others === 1 ? "step differed" : "steps differed"}` : credited > 0 ? "Nothing else" : "Nothing";
  return <section className="cmp-side cmp-else" aria-labelledby="cmp-else-heading">
    <h2 id="cmp-else-heading">What else moved</h2>
    <p className="cmp-else-big">{headline}</p>
    <div className="cmp-strip" role="img" aria-label={`Every step of the run, before and after, in order: ${plural(total, "step")}, ${plural(credited, "moved step")} marked.`}>
      <span className="cmp-strip-key">Before</span><div className="cmp-cells">{delta.steps.map((step) => cell(step, "before"))}</div>
      <span className="cmp-strip-key">After</span><div className="cmp-cells">{delta.steps.map((step) => cell(step, "after"))}</div>
      <span />
      {/* One label fits under one run of moved cells; several are named by the rows above. */}
      <div className="cmp-pointers" aria-hidden="true">{runs.length > 1 ? null : runs.map((run) => {
        const middle = ((run.from + run.to + 1) / 2 / total) * 100;
        const where = middle > 70 ? "is-end" : middle < 25 ? "is-start" : "is-mid";
        const style = where === "is-end" ? { right: `${(1 - (run.to + 1) / total) * 100}%` } : where === "is-start" ? { left: `${(run.from / total) * 100}%` } : { left: `${middle}%` };
        return <span key={run.from} className={`cmp-pointer ${where}`} style={style}>{titlesWords(run.steps)}{run.steps.every((step) => step.role === "variant") ? ", with other arguments" : ""}</span>;
      })}</div>
    </div>
    <p className="cmp-else-count"><b>{!delta.comparable ? `${plural(c.paired, "paired step")}, none judged.` : credited === 0 ? `None of ${plural(c.paired, "step")} moved.` : `${count(credited)} of ${plural(c.paired, "step")} moved.`}</b> {count(c.same)} {c.same === 1 ? "is" : "are"} the same{others > 0 ? `, ${count(others)} ${others === 1 ? "differs" : "differ"} without a verdict for the change` : ""}{c.new + c.gone > 0 ? `; ${count(c.new + c.gone)} new or gone, listed under How we know` : ""}.</p>
    <p className="cmp-legend" aria-hidden="true">
      <span><i className="cmp-cell is-alerted" />alerted</span>
      <span><i className="cmp-cell is-alerted is-lab" />by the lab's rule</span>
      <span><i className="cmp-cell is-seen" />seen, no alert</span>
      <span><i className="cmp-cell is-unseen" />unseen</span>
      <span><i className="cmp-cell is-stopped" />stopped</span>
      <span><i className="cmp-cell is-check" />lab check</span>
    </p>
  </section>;
}

/** What comes next: the next turn of the loop when the moved step still raises no alert, else how many tests still raise none. */
function Next({ delta, moved, next, after }: { delta: Delta; moved: readonly DeltaStep[]; next: DeltaSummary | null; after: Recording | null }) {
  const notAlerted = moved.filter((step) => step.after[MARK_FIELD] === "seen" || step.after[MARK_FIELD] === "unseen");
  const [first] = notAlerted;
  let body;
  if (!delta.comparable) {
    body = <><p className="cmp-next-lead">First, a comparison with a verdict.</p><p>Make the two runs again with only the one change between them.</p></>;
  } else if (first) {
    const unseen = first.after[MARK_FIELD] === "unseen";
    const which = notAlerted.length === 1 ? first.title : `these ${plural(notAlerted.length, "step")}`;
    body = <>
      <p className="cmp-next-lead">{unseen ? `${capital(which)} ${notAlerted.length === 1 ? "was" : "were"} still unseen in the run after.` : `No rule alerted on ${which} in the run after.`}</p>
      <p>{unseen ? "A sensor has to record it first." : "A rule has to turn the event into an alert."}</p>
      {next ? <NextLink next={next} /> : null}
    </>;
  } else {
    const counts = after ? noAlert(after) : null;
    const none = counts ? noneLeftWords(counts) : null;
    body = counts === null || none === null ? <p>Loading the run after.</p> : <>
      <p className="cmp-next-lead">{counts.left === 0 ? `${none.lead}.` : `${leftWords(counts.left)}.`}</p>
      <p>In the run after, with the lab's own rules too{counts.left === 0 ? `.${none.rest ? ` ${none.rest}.` : ""}` : counts.unseen ? `; ${count(counts.unseen)} of them went unseen.` : "; none went unseen."}</p>
      {next ? <NextLink next={next} /> : null}
      {counts.left ? <Link className="cmp-go" to={`${recordedRunPath(delta.after.id, delta.after.sha256)}?mode=analyse`}>See the run after<ArrowRight aria-hidden="true" /></Link> : null}
      <p className="cmp-small">{counts.scored !== counts.left ? `Its score counts only published rules: ${count(counts.scored)} with no alert. ` : ""}Each test counted once, as published, each with Fix this.</p>
    </>;
  }
  return <section className="cmp-side cmp-next" aria-labelledby="cmp-next-heading">
    <h2 id="cmp-next-heading">What comes next</h2>
    {body}
  </section>;
}

/** The link to the next turn, by its name, with the imported mark when it was imported. */
function NextLink({ next }: { next: DeltaSummary }) {
  const imported = importedWords(next);
  return <Link className="cmp-go" to={pairPath(next.id)}>Next turn: {turnName(next)}{imported ? <small className="cmp-go-origin">{imported}</small> : null}<ArrowRight aria-hidden="true" /></Link>;
}

/** One event line as a sensor recorded it: time, sensor, kind, what it names. */
function EventLine({ event, tag }: { event: RecordingEvent; tag?: ReactNode }) {
  return <div className="cmp-ev">
    <span className="cmp-ev-time">{event.time.slice(11, 23)}</span>
    <span className="cmp-ev-sensor">{event.sensor}</span>
    <span className="cmp-ev-kind">{event.kind}</span>
    <span className="cmp-ev-text">{event.text}</span>
    {tag ?? <span />}
  </div>;
}

/** What made the difference: the events the sensor now records, or the rule that now fires, with its text. */
function Difference({ delta, moved, staged, recordings }: { delta: Delta; moved: readonly DeltaStep[]; staged: DeltaStep | null; recordings: Record<Side, Loaded> }) {
  const after = recordingOf(recordings.after);
  const before = recordingOf(recordings.before);
  const declared = delta.declared_change ?? "";
  const rules = delta.lab_rules ?? [];
  if (!delta.comparable || !staged) return null;
  let body;
  if (declared.startsWith("sensors:")) {
    const sensorId = declared.slice("sensors:".length);
    const events = after ? after.events.filter((event) => event.step === staged.id && event.sensor === sensorId) : [];
    const fresh = new Set(staged.records?.new.lines ?? []);
    const recordedBefore = before?.steps.find((step) => step.id === beforeId(staged));
    const matches = after ? after.alerts.filter((alert) => alert.step === staged.id && alert.launcher_only !== true) : [];
    const keys = Object.entries(delta.audit_keys?.only_after ?? {});
    body = <>
      <article className="cmp-card" aria-labelledby="cmp-diff-card">
        <header>
          <h3 id="cmp-diff-card">{staged.records?.new.count && staged.before.recorded !== "recorded" ? `${sensorId} recorded ${staged.title} in the run after` : `What ${sensorId} recorded of ${staged.title}`}</h3>
          <span className="cmp-fromto"><SideMark side={staged.before} /><ArrowRight aria-hidden="true" /><SideMark side={staged.after} /></span>
        </header>
        {events.length ? <div className="cmp-evs">{events.map((event) => <EventLine key={event.id} event={event} tag={fresh.has(event.text ? `${event.kind}: ${event.text}` : event.kind) ? <span className="cmp-tag is-new">only after</span> : undefined} />)}</div> : null}
        {recordedBefore && recordedBefore.visibility.events === 0 ? <p className="cmp-note">Before: {recordedBefore.visibility.basis}.</p> : null}
        {matches.map((alert) => <p key={alert.id} className="cmp-note">Matched after by {alert.rule.title}, {alert.rule.origin === "lab" ? "a rule of the lab's own" : "a published rule"}, at level {alert.rule.level}: {!alert.counts ? "below the alert level" : alert.rule.origin === "lab" ? `a ${MARK_WORDS.lab}, which the score does not count` : "an alert"}.</p>)}
        {staged.records ? <Records records={staged.records} /> : null}
      </article>
      {keys.map(([key, entry]) => <p key={key} className="cmp-aside">
        Events of the after run carry an audit key the before run's events never do: <code>{key}</code>. It marks {plural(entry.events, "event")} on {plural(entry.steps.length, "step")}.
        <small>A key is a label on a rule of {sensorId}'s settings, not proof of what the settings changed.</small>
      </p>)}
    </>;
  } else if (rules.length) {
    const changed = new Set(rules.map((row) => row.rule));
    const evidence = moved.flatMap((step) => {
      for (const side of ["after", "before"] as const) {
        const recording = recordingOf(recordings[side]);
        const alerts = recording ? ruleAlerts(recording, changed, side === "before" ? beforeId(step) : step.id) : [];
        if (alerts.length) return [{ step, side, alerts }];
      }
      return [];
    });
    body = <>
      {evidence.length ? <article className="cmp-card" aria-labelledby="cmp-diff-card">
        <header><h3 id="cmp-diff-card">What the alerts rest on</h3></header>
        <div className="cmp-evs">{evidence.flatMap(({ step, side, alerts }) => alerts.flatMap((alert) => alert.events.map((event) => <div key={`${step.id}-${alert.id}-${event.id}`} className="cmp-ev-row">
          <span className="cmp-ev-who"><b>{step.title}</b><small>{roleWords(step)}{side === "before" ? ", with the rules before" : ""}</small></span>
          <EventLine event={event} tag={<span className="cmp-tag is-lab">{MARK_WORDS.lab} · {alert.level}</span>} />
          <EvidenceFacts event={event} />
        </div>)))}</div>
      </article> : after ? null : <p className="cmp-empty">Loading the events the alerts rest on.</p>}
      {rules.map((row) => <RuleCard key={row.rule} row={row} recordings={recordings} />)}
    </>;
  } else {
    body = staged.underneath.length ? <ul className="cmp-under">{staged.underneath.map((item) => <li key={item}>{item}</li>)}</ul> : <p className="cmp-empty">The comparison names nothing underneath this step.</p>;
  }
  return <section className="cmp-sec" aria-labelledby="cmp-diff-heading">
    <h2 id="cmp-diff-heading">What made the difference</h2>
    {body}
  </section>;
}

/** The command and audit key of an event an alert rests on, as text. */
function EvidenceFacts({ event }: { event: RecordingEvent }) {
  const command = event.fields?.command;
  const key = event.fields?.key;
  if (typeof command !== "string" && typeof key !== "string") return null;
  return <span className="cmp-ev-facts">
    {typeof command === "string" ? <small>by <code>{command}</code></small> : null}
    {typeof key === "string" ? <small>audit key <code>{key}</code></small> : null}
  </span>;
}

/** A rule of the lab's own that differs: its change, title and file, how each evaluation judged it, and its text as the recording carries it. */
function RuleCard({ row, recordings }: { row: DeltaLabRule; recordings: Record<Side, Loaded> }) {
  const file = row.after?.file ?? row.before?.file;
  const side: Side = row.after !== null ? "after" : "before";
  const recording = recordingOf(recordings[side]);
  const text = recording ? ruleText(recording, row.rule) : null;
  const heading = `cmp-rule-${row.rule.replace(/[^A-Za-z0-9_-]/g, "-")}`;
  return <article className="cmp-card cmp-rule" aria-labelledby={heading}>
    <header>
      <span className="cmp-rule-change">{ruleChangeWords(row.change)}</span>
      <h3 id={heading}>{row.title}</h3>
      {file ? <code className="cmp-rule-file">{file}</code> : null}
    </header>
    <dl className="cmp-rule-judged" aria-label="How each evaluation judged it">
      {SIDES.map((which) => {
        const said = judgedWords(row[which]);
        return <div key={which}>
          <dt>{which === "before" ? "Before" : "After"}</dt>
          <dd><span className={`cmp-judged is-${said.word.replace(/\s+/g, "-")}`}>{said.word}</span>{said.reason ? <span className="cmp-judged-why"><LabText text={said.reason} /></span> : null}</dd>
        </div>;
      })}
    </dl>
    {text ? <figure className="cmp-rule-text">
      <figcaption>The rule's text, as the {side} recording carries it</figcaption>
      <pre tabIndex={0} aria-label={`The text of the rule ${row.title}`}>{text.lines.join("\n")}</pre>
    </figure> : <p className="cmp-empty">{recordings[side] === null ? "Loading the rule's text from the recording." : "The recording does not carry the rule's text."}</p>}
  </article>;
}

/**
 * The published tests of the staged step's technique that ran in the run after, each once, the canary's among
 * them, with its mark and the rules that alerted on it. A test as published counts over a canary run of the
 * same test, and the first of a canary's runs stands for them.
 */
function Ways({ delta, staged, moved, after }: { delta: Delta; staged: DeltaStep; moved: readonly DeltaStep[]; after: Recording | null }) {
  if (!after || !delta.comparable) return null;
  const order = new Map(after.steps.map((step, index) => [step.id, index]));
  const once = new Map<string, Recording["steps"][number]>();
  for (const role of ["test", "canary"] as const) {
    for (const step of after.steps) {
      if (step.role !== role || step.technique.id !== staged.technique || !step.test) continue;
      if (!once.has(step.test.guid)) once.set(step.test.guid, step);
    }
  }
  const tests = [...once.values()].sort((a, b) => (order.get(a.id) ?? 0) - (order.get(b.id) ?? 0));
  if (tests.length < 2) return null;
  const movedIds = new Set(moved.map((step) => step.id));
  const alerted = tests.filter((step) => (step.outcome_with_lab_rules ?? step.outcome) === "alerted").length;
  const published = tests.filter((step) => step.outcome === "alerted").length;
  const name = after.steps.find((step) => step.technique.id === staged.technique)?.technique.name;
  const canary = tests.some((step) => step.role === "canary");
  return <section className="cmp-sec" aria-labelledby="cmp-ways-heading">
    <h2 id="cmp-ways-heading">The {count(tests.length)} published tests of {staged.technique} that ran</h2>
    <p className="cmp-sec-lead">Each published test of {name ?? "the technique"} in the {isOneRun(delta) ? "run, with the rules after" : "run after"}{canary ? ", the canary among them" : ""}. {published === alerted
      ? `${count(alerted)} of ${count(tests.length)} alerted.`
      : `With published rules, ${count(published)} of ${count(tests.length)} alerted; with the lab's own rules too, ${count(alerted)} of ${count(tests.length)}.`}</p>
    <ul className="cmp-ways">{tests.map((step) => {
      const alerts = after.alerts.filter((alert) => alert.step === step.id && alert.counts && alert.launcher_only !== true);
      const by = [...new Map(alerts.map((alert) => [alert.rule.title, alert.rule.origin])).entries()];
      const outcome = step.outcome_with_lab_rules ?? step.outcome;
      return <li key={step.id} className={movedIds.has(step.id) ? "is-moved" : undefined}>
        <code className="cmp-ways-cmd">{step.command ?? step.title}</code>
        <OutcomeMark outcome={outcome} lab={outcome === "alerted" && step.outcome !== "alerted"} />
        <span>
          {movedIds.has(step.id) ? <b>Moved here by this change. </b> : null}
          {step.role === "canary" ? "The canary, a check of the lab itself. " : null}
          {by.length ? <>By {by.map(([title, origin], index) => <span key={title}>{index ? " and " : ""}{title} ({origin === "lab" ? "the lab's own" : "published"})</span>)}.</> : "No rule alerted on it."}
        </span>
      </li>;
    })}</ul>
  </section>;
}

/** Where to go from here: play either run, the turn before or after this one, and the next change. */
function GoFrom({ delta, previous, next, place, after }: { delta: Delta; previous: DeltaSummary | null; next: DeltaSummary | null; place: number; after: Recording | null }) {
  const oneRun = isOneRun(delta);
  const counts = after ? noAlert(after) : null;
  const none = counts && counts.left === 0 ? noneLeftWords(counts) : null;
  const marks = { previous: previous ? importedWords(previous) : null, next: next ? importedWords(next) : null };
  return <section className="cmp-sec" aria-labelledby="cmp-go-heading">
    <h2 id="cmp-go-heading">Where to go from here</h2>
    <div className="cmp-go-row">
      <div className="cmp-plays">
        {SIDES.map((side) => <Link key={side} className="cmp-play" to={recordedRunPath(delta[side].id, delta[side].sha256)}>
          <span className="cmp-play-button" aria-hidden="true"><Play /></span>
          <span>{oneRun ? `Play with the rules ${side}` : `Play the run ${side}`}<small>{sideWhere(delta[side])}</small></span>
        </Link>)}
      </div>
      <div className="cmp-turns">
        {previous ? <Link className={`cmp-turn-card${previous.declared_change?.startsWith("sensors:") ? "" : " is-rule"}`} to={pairPath(previous.id)}>
          <small>The turn before, turn {place}{marks.previous ? ` · ${marks.previous}` : ""}</small><b>{turnName(previous)}</b><span>{pairHeadline(previous, previous.moved ?? [])}</span>
        </Link> : null}
        {next ? <Link className={`cmp-turn-card${next.declared_change?.startsWith("sensors:") ? "" : " is-rule"}`} to={pairPath(next.id)}>
          <small>Next turn, turn {place + 2}{marks.next ? ` · ${marks.next}` : ""}</small><b>{turnName(next)}<ArrowRight aria-hidden="true" /></b><span>{pairHeadline(next, next.moved ?? [])}</span>
        </Link> : place < 0 ? null : <Link className="cmp-turn-card is-todo" to={`${recordedRunPath(delta.after.id, delta.after.sha256)}?mode=analyse`}>
          <small>Next change, not made yet</small>{none
            ? <><b>{none.lead}</b><span>See the run after{none.rest ? `. ${none.rest}` : ""}</span></>
            : <><b>{counts === null ? "The tests with no alert" : `${leftWords(counts.left)}, with the lab's own rules too`}</b><span>See the run after: each of them has Fix this there{counts && counts.scored !== counts.left ? `. Its score counts only published rules: ${count(counts.scored)} with no alert` : ""}</span></>}
        </Link>}
      </div>
    </div>
  </section>;
}

/** The step's whole detail in each recording, before and after next to each other, from the live view. */
function PairDetail({ delta, step, onClose }: { delta: Delta; step: DeltaStep; onClose: () => void }) {
  const heading = useRef<HTMLHeadingElement | null>(null);
  const id = `cmp-detail-${step.id.replace(/[^A-Za-z0-9_-]/g, "-")}`;
  useEffect(() => {
    heading.current?.focus({ preventScroll: false });
  }, []);
  return <section className="cmp-detail" id={id} aria-labelledby={`${id}-heading`}>
    <div className="cmp-detail-head">
      <h3 id={`${id}-heading`} ref={heading} tabIndex={-1}>{step.title}, every detail before and after</h3>
      <button type="button" className="lv-button is-close" onClick={onClose} aria-label="Close the step's detail">Close</button>
    </div>
    <div className="cmp-detail-sides">
      {SIDES.map((side) => <SideDetail key={side} side={side} recordingId={delta[side].id} sha256={delta[side].sha256} stepId={side === "before" ? beforeId(step) : step.id} />)}
    </div>
  </section>;
}

function SideDetail({ side, recordingId, sha256, stepId }: { side: Side; recordingId: string; sha256: string; stepId: string }) {
  const navigate = useNavigate();
  const entry = useQuery({ queryKey: ["recording-file", recordingId, sha256], queryFn: () => api.recordingFile(recordingId, sha256), retry: false });
  const reading = useMemo(() => (entry.data ? read(entry.data.recording) : null), [entry.data]);
  const recording = reading && "recording" in reading ? reading.recording : null;
  const view = useMemo(() => {
    if (!recording) return null;
    const timeline = buildTimeline(recording);
    const row = stepRows(recording, timeline).find((item) => item.step.id === stepId);
    if (!row) return null;
    const numbers = testNumbers(recording);
    const facts = runFacts(recording, timeline);
    return { row, colours: sensorColours(recording.network.sensors), number: numbers.get(stepId), tests: numbers.size, origin: facts.start, originWords: facts.startWords };
  }, [recording, stepId]);
  let body;
  if (entry.isPending) body = <p className="cmp-empty">Loading the {side} recording.</p>;
  else if (!entry.data) body = <p className="cmp-empty" role="status">The {side} recording could not be loaded: {entry.error instanceof Error ? entry.error.message : "the request failed"}.</p>;
  else if (!recording) body = <p className="cmp-empty" role="status">{reading && "problem" in reading ? reading.problem : "The recording could not be read."}</p>;
  else if (!view) body = <p className="cmp-empty" role="status">The {side} recording has no step {stepId}.</p>;
  else body = <StepDetail
    recording={recording}
    row={view.row}
    colours={view.colours}
    testNumber={view.number}
    testsTotal={view.tests}
    origin={view.origin}
    originWords={view.originWords}
    onSelect={(other) => navigate(`${recordedRunPath(recordingId, sha256)}?mode=analyse&select=${encodeURIComponent(other)}`)}
    takeFocus={false}
  />;
  return <div className={`cmp-detail-side is-${side}`}>
    <p className="cmp-side-word">{side === "before" ? "Before" : "After"}</p>
    <div className="lv-an-detail">{body}</div>
  </div>;
}
