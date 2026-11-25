// The changes to the defense the service keeps, as the turns of one loop: each
// named by what it did, with its marks, its price and how it was compared, in
// the order the changes were made. The Runs screen and the Overview show it.
// Every word comes from a comparison's list entry: no two turns are compared.

import { ArrowRight } from "lucide-react";
import { Link } from "react-router-dom";
import type { DeltaSummary } from "../lib/api";
import { originWords, recordedRunPath, recordedWhere } from "../lib/recorded-runs";
import { alertedByLabOnly, codeSpans, creditedCount, headlineNamesStep, isOneRun, listedPrice, methodWords, pairHeadline, pairPath, pairResultWords, setupWords, titlesWords, turnName } from "../lib/recording-pairs";
import { count, plural } from "../live/format";
import { PathThumb, SideMark } from "./PairStages";
import "./DefenderLoop.css";

/** What the turn changed, small, under its name: the rule's title, or the declared change in words. */
function whichWords(pair: DeltaSummary): string | null {
  const rules = pair.lab_rules ?? [];
  const [only] = rules;
  if (rules.length === 1 && only) return only.title;
  return pair.declared_change === null ? null : setupWords(pair.declared_change);
}

function LabWords({ text }: { text: string }) {
  return <>{codeSpans(text).map((part, index) => (part.code ? <code key={index}>{part.text}</code> : part.text))}</>;
}

/** The result in a line: how many steps read the same, or, for a limited or refused comparison, the delta's own count in words. */
function resultLine(pair: DeltaSummary): { text: string; warn: boolean } {
  const c = pair.counts;
  if (!pair.comparable || pair.limit || c["without cause"] + c["not attributable"] > 0) return { text: pairResultWords(pair), warn: !pair.comparable || Boolean(pair.limit) };
  return { text: `${count(c.same)} of ${plural(c.paired, "step")} the same`, warn: false };
}

function Turn({ pair, number, compact }: { pair: DeltaSummary; number: number; compact: boolean }) {
  const moved = pair.moved ?? [];
  const [first] = moved;
  const total = creditedCount(pair.counts);
  const uniform = first !== undefined && moved.every((step) => step.before.outcome_with_lab_rules === first.before.outcome_with_lab_rules && step.after.outcome_with_lab_rules === first.after.outcome_with_lab_rules);
  const kind = pair.declared_change?.startsWith("sensors:") ? "is-sensor" : "is-rule";
  const price = pair.comparable ? listedPrice(moved) : null;
  const result = resultLine(pair);
  const which = whichWords(pair);
  const variants = moved.some((step) => step.role === "variant");
  const oneRun = isOneRun(pair);
  return <li className={`dl-turn ${kind}${pair.comparable ? "" : " is-refused"}${pair.limit ? " is-limited" : ""}`}>
    <p className="dl-top"><span className="dl-n" aria-hidden="true">{number}</span><span className="dl-name"><span className="sr-only">Turn {number}: </span>{turnName(pair)}</span></p>
    {which ? <p className="dl-which">{which}</p> : null}
    {pair.comparable && first && uniform ? <p className="dl-marks">
      <span className="sr-only">Before </span><SideMark side={first.before} />
      <ArrowRight className="dl-arrow" aria-hidden="true" />
      <span className="sr-only">, after </span><SideMark side={first.after} times={total} />
      {alertedByLabOnly(first.after) ? <small>with the lab's rules</small> : null}
    </p> : null}
    {!compact && pair.comparable && first && uniform ? <div className="dl-thumbs" aria-hidden="true">
      <PathThumb side={first.before} label="Before" />
      <span className="dl-thumb-arrow" />
      <PathThumb side={first.after} label="After" />
    </div> : null}
    <h4><Link className="dl-link" to={pairPath(pair.id)}>{pairHeadline(pair, moved)}</Link></h4>
    {/* The headline names one moved step itself; several are named here, under it. */}
    {pair.comparable && moved.length && !headlineNamesStep(pair, moved) ? <p className="dl-moved">{titlesWords(moved)}{variants ? ", each also with other arguments" : ""}</p> : null}
    <p className="dl-method"><span>{methodWords(pair)}</span><span className={`recorded-run-origin is-${pair.origin.kind}`}>{originWords(pair.origin)}</span></p>
    {price ? <p className="dl-price"><span className="dl-price-key">Price</span><span>{price.words}</span></p> : null}
    <p className={`dl-result${result.warn ? " is-warn" : ""}`}><LabWords text={result.text} /></p>
    {compact ? null : <p className="dl-links">
      <Link className="dl-open" to={pairPath(pair.id)}>See the difference<ArrowRight aria-hidden="true" /></Link>
      {(["before", "after"] as const).map((side) => <Link key={side} to={recordedRunPath(pair[side].id, pair[side].sha256)}>{oneRun ? `Play with the rules ${side}` : `Play the ${side} run`}<span className="sr-only">, {recordedWhere(pair.recordings[side])}</span></Link>)}
    </p>}
  </li>;
}

/** The turns of the loop, in the order they were made, joined by arrows. */
export function DefenderLoop({ pairs, compact = false, label }: { pairs: readonly DeltaSummary[]; compact?: boolean; label: string }) {
  return <ol className={`dl${compact ? " is-compact" : ""}`} aria-label={label}>
    {pairs.map((pair, index) => <Turn key={pair.id} pair={pair} number={index + 1} compact={compact} />)}
  </ol>;
}
