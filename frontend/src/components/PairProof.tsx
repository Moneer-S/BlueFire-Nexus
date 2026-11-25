// How we know a comparison is fair: one calm line on the page, and behind it the
// runs before and after with the one change highlighted, their commits, CI runs
// and files' hashes, what was the same, the control, and each step that differs
// in the delta's own words. Also the two states that come before any verdict:
// a refused comparison and a limited one. Every fact is the delta's.

import { ArrowRight } from "lucide-react";
import { Link } from "react-router-dom";
import type { Delta, DeltaLimit, DeltaStep, DeltaSummary } from "../lib/api";
import { recordedRunPath } from "../lib/recorded-runs";
import { codeSpans, controlWords, creditsWords, isDigest, isOneRun, noMarkKeys, raceWords, recordsParts, resultWords, runnerDifferences, setupLede, setupWords, shortValue, sideWhere, variationWords, verdictParts } from "../lib/recording-pairs";
import { plural, runLink } from "../live/format";

type Side = "before" | "after";
const SIDES: readonly Side[] = ["before", "after"];

/** The lab's words, with its `code spans` drawn as code: text through React, never HTML. */
export function LabText({ text }: { text: string }) {
  return <>{codeSpans(text).map((part, index) => (part.code ? <code key={index}>{part.text}</code> : part.text))}</>;
}

/** A digest shortened to its start, whole on hover or focus, and whole for a screen reader. */
export function Value({ value }: { value: string | null }) {
  if (!isDigest(value)) return <code className="cmp-value">{shortValue(value)}</code>;
  return <code className="cmp-value cmp-digest" tabIndex={0} title={value}>
    <span className="is-short" aria-hidden="true">{shortValue(value)}</span>
    <span className="is-whole">{value}</span>
  </code>;
}

/** No verdict: every reason, and every difference with both values, as prominently as a verdict. */
export function Refused({ delta }: { delta: Delta }) {
  const declared = delta.declared_change;
  const known = delta.differences.filter((item) => item.before !== null || item.after !== null);
  return <section className="cmp-refused" aria-labelledby="cmp-refused-heading">
    <h2 id="cmp-refused-heading">{declared === null ? "Nothing was declared as changed, and the comparison was refused" : <>Declared change: {setupWords(declared)}. The comparison was refused</>}</h2>
    <ul className="cmp-reasons">{delta.refused_because.map((reason, index) => <li key={index}><LabText text={reason} /></li>)}</ul>
    {known.length ? <table className="cmp-table">
      <caption className="lv-sr">What differed between the two runs</caption>
      <thead><tr><th scope="col">What differed</th><th scope="col">Before</th><th scope="col">After</th></tr></thead>
      <tbody>{known.map((item) => <tr key={item.what} className={item.what === declared ? "is-declared" : undefined}>
        <th scope="row">{setupWords(item.what)}{item.what === declared ? <span className="cmp-declared">declared</span> : null}</th>
        <td><Value value={item.before} /></td>
        <td><Value value={item.after} /></td>
      </tr>)}</tbody>
    </table> : null}
  </section>;
}

/** A limited verdict, near the top: why, in what the runners differed with both values, and what alone is credited, in the delta's words. */
export function LimitBox({ delta, limit }: { delta: Delta; limit: DeltaLimit }) {
  const credits = creditsWords(limit);
  return <section className="cmp-limit" aria-labelledby="cmp-limit-heading">
    <h2 id="cmp-limit-heading">A limited verdict: {limit.why}</h2>
    <table className="cmp-table">
      <caption className="lv-sr">What differed between the two runners</caption>
      <thead><tr><th scope="col">The runners</th><th scope="col">Before</th><th scope="col">After</th></tr></thead>
      <tbody>{runnerDifferences(delta).map((item) => <tr key={item.what}>
        <th scope="row">{setupWords(item.what)}</th>
        <td><Value value={item.before} /></td>
        <td><Value value={item.after} /></td>
      </tr>)}</tbody>
    </table>
    <details className="cmp-more">
      <summary>Credited: {credits.lead}</summary>
      {credits.rest ? <p className="cmp-limit-credits"><LabText text={credits.rest} />.</p> : null}
    </details>
    <p className="cmp-limit-credits">Every other step that differs is not attributable, since the runners' difference could have moved it. No price is known: each run counted its ordinary activity on a runner of its own.</p>
    <p className="cmp-limit-count">{plural(limit.credited, "step")} credited by the mark, {limit.not_attributable} not attributable.</p>
  </section>;
}

/** What the declared sensor recorded of a step in one run only, with the first lines the delta gives. */
export function Records({ records }: { records: NonNullable<DeltaStep["records"]> }) {
  const parts = recordsParts(records);
  if (parts.length === 0) return null;
  return <div className="cmp-records">
    <p className="cmp-side-word">What sensor {records.sensor} recorded of it in one run only</p>
    {parts.map((part) => <div key={part.label} className="cmp-records-part">
      <span className="cmp-records-label">{part.label}, {plural(part.count, "event")}</span>
      <ul>{part.lines.map((text, index) => <li key={index}><code>{text}</code></li>)}</ul>
      {part.more > 0 ? <p className="cmp-records-more">and {plural(part.more, "more event")}, not listed in the comparison</p> : null}
    </div>)}
  </div>;
}

/** The one line of the fair comparison, in words a careful reader finds without opening it. The basis stands once, under the headline. */
function fairWords(delta: Delta): { label: string; text: string; warn: boolean } {
  if (!delta.comparable) {
    const [first] = delta.refused_because;
    const more = delta.refused_because.length - 1;
    return { label: "No verdict", text: `${(first ?? "the comparison was refused").replaceAll("`", "")}${more > 0 ? ` (and ${plural(more, "more reason")})` : ""}.`, warn: true };
  }
  if (delta.declared_change === null) return { label: "Nothing declared", text: "Nothing was declared as changed.", warn: true };
  if (delta.limit) return { label: "Limited", text: `Credited only where the change left its own mark: ${delta.limit.why}.`, warn: true };
  return { label: "Fair comparison", text: `Only ${setupWords(delta.declared_change)} differed.`, warn: false };
}

/** Where a pair comes from: the one CI run that made both recordings and the comparison, for a shipped pair. */
function madeIn(summary: DeltaSummary): { words: string; link: string } | null {
  const link = summary.origin.kind === "shipped" && summary.origin.run_url ? runLink({ run_url: summary.origin.run_url }) : null;
  if (!link) return null;
  return { words: isOneRun(summary) ? "The run, both evaluations and this comparison were made in CI" : "Both runs and this comparison were made in CI", link };
}

function ciRun(summary: DeltaSummary, delta: Delta, side: Side) {
  const facts = delta[side];
  const shipped = summary.recordings[side].origin.kind === "shipped";
  // Only a shipped recording's CI run is linked as the run that made it; an imported file's is only what the file says.
  const link = shipped ? runLink({ run_url: facts.run_url }) : null;
  if (link) return <a href={link} target="_blank" rel="noreferrer">{link.replace(/^.*\/runs\//, "run ")}</a>;
  if (facts.run_url) return <span className="cmp-claimed" title="The file names this CI run, which BlueFire cannot confirm">{facts.run_url} <small>(named by the file, not confirmed)</small></span>;
  return "not recorded";
}

/** The line that opens, and behind it how we know. */
export function FairLine({ delta, summary }: { delta: Delta; summary: DeltaSummary }) {
  const said = fairWords(delta);
  const made = madeIn(summary);
  const declared = delta.declared_change;
  const change = declared === null ? undefined : delta.differences.find((item) => item.what === declared);
  const runners = delta.limit ? runnerDifferences(delta) : [];
  const race = raceWords(delta.race);
  const steps = delta.steps.filter((step) => step.result !== "same");
  const code = delta.lab_code;
  const rulesFrom = (side: Side) => (isOneRun(delta) ? delta[side].lab_rules_commit ?? delta[side].defense_commit : delta[side].defense_commit);
  return <details className="cmp-fair" id="cmp-fair">
    <summary>
      <span className={`cmp-fair-key${said.warn ? " is-warn" : ""}`}>{said.label}</span>
      <span className="cmp-fair-text"><LabText text={said.text} /></span>
      <span className="cmp-fair-more">How we know</span>
    </summary>
    <div className="cmp-fair-body">
      <section aria-labelledby="cmp-claim-heading">
        <h3 id="cmp-claim-heading">The claim</h3>
        <p>Every verdict on this page rests on {delta.claim}. {setupLede(delta)}</p>
        {made ? <p>{made.words} <a href={made.link} target="_blank" rel="noreferrer">{made.link.replace(/^.*\/runs\//, "run ")}</a>.</p> : null}
        <p className="cmp-small">{summary.origin.note}</p>
      </section>

      <table className="cmp-table cmp-proof">
        <caption className="lv-sr">The two {isOneRun(delta) ? "evaluations" : "runs"}, before and after</caption>
        <thead><tr><th scope="col"><span className="lv-sr">What</span></th><th scope="col">Before</th><th scope="col">After</th></tr></thead>
        <tbody>
          {change ? <tr className="is-declared">
            <th scope="row">{setupWords(change.what)}<small>the one change</small></th>
            <td><Value value={change.before} /></td>
            <td><Value value={change.after} /></td>
          </tr> : null}
          {runners.map((item) => <tr key={item.what} className="is-runner">
            <th scope="row">{setupWords(item.what)}<small>the runners differed</small></th>
            <td><Value value={item.before} /></td>
            <td><Value value={item.after} /></td>
          </tr>)}
          <tr><th scope="row">The run</th>{SIDES.map((side) => <td key={side}><code>{delta[side].id}</code>, {sideWhere(delta[side])}</td>)}</tr>
          <tr><th scope="row">The lab's commit</th>{SIDES.map((side) => <td key={side}>{delta[side].commit ? <code>{delta[side].commit?.slice(0, 8)}</code> : "not recorded"}</td>)}</tr>
          <tr><th scope="row">{isOneRun(delta) ? "The lab's rules from commit" : "Rules and sensor settings from commit"}</th>{SIDES.map((side) => {
            const commit = rulesFrom(side);
            return <td key={side}>{commit ? <code>{commit.slice(0, 8)}</code> : "not recorded"}{commit && commit === delta[side].commit ? " (the lab's commit)" : null}</td>;
          })}</tr>
          <tr><th scope="row">CI run</th>{SIDES.map((side) => <td key={side}>{ciRun(summary, delta, side)}</td>)}</tr>
          <tr><th scope="row">Recording file<small>its SHA-256, to check a download</small></th>{SIDES.map((side) => <td key={side}><Value value={delta[side].sha256} /></td>)}</tr>
          <tr><th scope="row">Open it</th>{SIDES.map((side) => <td key={side}><Link className="cmp-open" to={recordedRunPath(delta[side].id, delta[side].sha256)}>{isOneRun(delta) ? `Open with the rules ${side}` : `Open the run ${side}`}<ArrowRight aria-hidden="true" /></Link></td>)}</tr>
        </tbody>
      </table>

      <section aria-labelledby="cmp-same-heading">
        <h3 id="cmp-same-heading">The same in both</h3>
        <p>{delta.same_in_both.length ? `Recorded as the same in both: ${delta.same_in_both.map(setupWords).join(", ")}.` : "The comparison records nothing as the same in both."}</p>
        {!code.same ? <p className="cmp-note">
          The lab's code {code.before || code.after ? <>differed (<code>{code.before ? code.before.slice(0, 8) : "not recorded"}</code> before, <code>{code.after ? code.after.slice(0, 8) : "not recorded"}</code> after)</> : "is not recorded in either run"}. The comparison does not check what a change of it did, so a step that differs may also come from it.
        </p> : null}
      </section>

      <section aria-labelledby="cmp-control-heading">
        <h3 id="cmp-control-heading">The control</h3>
        <p>{controlWords(delta)}</p>
        {delta.control.varied.length ? <p>It varied on {plural(delta.control.varied.length, "step")}: that is {variationWords(delta)}, not an effect.</p> : null}
        <p className={race.quiet ? "cmp-small" : undefined}>{race.text}</p>
        {delta.new.length || delta.gone.length ? <div className="cmp-listed">
          <p className="cmp-side-word">New and gone, listed, not counted</p>
          {([["Only in the after run", delta.new], ["Only in the before run", delta.gone]] as const).map(([label, listed]) => listed.length ? <div key={label}>
            <span className="cmp-side-word">{label}</span>
            <ul>{listed.map((step) => <li key={step.id}><span className="lv-tech">{step.technique}</span> {step.title}{step.role !== "test" ? <span className="lv-role-tag">{step.role}</span> : null}</li>)}</ul>
          </div> : null)}
        </div> : null}
      </section>

      {steps.length ? <section aria-labelledby="cmp-words-heading" className="cmp-words">
        <h3 id="cmp-words-heading">Each step that differs, in the comparison's words</h3>
        <ol className="cmp-verdicts">{steps.map((step) => <StepVerdict key={step.id} delta={delta} step={step} />)}</ol>
      </section> : null}
    </div>
  </details>;
}

/** One step that differs, as the delta words it: its result, its verdict with the price, what changed underneath, and its mark. */
function StepVerdict({ delta, step }: { delta: Delta; step: DeltaStep }) {
  const parts = verdictParts(step);
  const result = step.result.replace(/\s+/g, "-");
  return <li className={`cmp-verdict-step is-${result}`}>
    <p className="cmp-verdict-title"><b>{step.title}</b> <span className="lv-tech">{step.technique}</span>{step.role !== "test" ? <span className="lv-role-tag">{step.role}</span> : null}</p>
    <p className="cmp-verdict">
      <span className={`cmp-result is-${result}`}>{resultWords(step.result)}</span>
      {step.mark ? <> <span className="cmp-result is-mark">by the change's own mark<span className="lv-sr">, on two runners that differed</span></span></> : null}
      <span className="lv-sr">: </span>
      <LabText text={parts.before} />
      {parts.price ? <span className={`cmp-price${parts.price.startsWith("price not known") ? " is-unknown" : ""}`}><LabText text={parts.price} /></span> : null}
      <LabText text={parts.after} />
    </p>
    {step.underneath.length ? <ul className="cmp-under" aria-label="What changed underneath">{step.underneath.map((item) => <li key={item}>{item}</li>)}</ul> : null}
    {step.result === "not attributable" ? noMarkKeys(delta, step).map((item) => <p key={`${item.run}-${item.key}`} className="cmp-nomark">
      No mark of the change's own from the audit key <code>{item.key}</code>, only in the {item.run} run's events: <LabText text={item.why} />.
    </p>) : null}
    {step.paired_by !== "id" ? <p className="cmp-paired">Paired by {step.paired_by}.</p> : null}
  </li>;
}
