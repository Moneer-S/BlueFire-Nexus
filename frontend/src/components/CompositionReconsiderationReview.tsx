import { Link } from "react-router-dom";
import type { CompositionObjective, CompositionProposal } from "../lib/composition";
import type { CompositionEvidenceContext } from "../lib/composition-evidence";
import { DataList, sentence } from "./Primitives";

export function CompositionReconsiderationReview({ context, proposal, objective }: { context: CompositionEvidenceContext; proposal: NonNullable<CompositionProposal["proposal"]>; objective: CompositionObjective }) {
  const history = context.historical_context;
  const review = proposal.reconsideration!;
  const number = (id: string) => objective.attempts.findIndex(attempt => attempt.request.composition_attempt.attempt_id === id) + 1;
  return <section className="composition-reconsideration" aria-label="Captured historical reasoning">
    <h3>Captured historical reasoning</h3>
    <p>Selected records informed this proposal. They describe past attempts; the explanations below do not establish current resource state or prove that a refresh happened.</p>
    <ul>{review.reconsidered_choices.map(choice => {
      const saved = history.choices.find(item => item.attempt_id === choice.attempt_id && item.step_id === choice.step_id)!;
      return <li key={`${choice.attempt_id}:${choice.step_id}`}>
        <h4>Attempt {number(choice.attempt_id)} · Step {choice.step_id}</h4><p>{choice.reason}</p>
        <details><summary>Earlier choice and source findings</summary>
          <DataList items={[{ label: "Method", value: <code>{saved.behavior_id}</code> }, { label: "Parameters", value: <code>{JSON.stringify(saved.parameters)}</code> }, { label: "Inputs", value: <code>{JSON.stringify(saved.inputs)}</code> }, { label: "Compiled digest", value: <code>{saved.compiled_digest}</code> }, { label: "Semantic digest", value: <code>{saved.semantic_digest}</code> }]} />
          <ul>{choice.finding_refs.map(reference => {
            const finding = history.attempts.flatMap(attempt => attempt.findings).find(item => item.finding_id === reference.finding_id)!;
            return <li key={reference.finding_id}><p><strong>{sentence(finding.semantic_kind)}</strong> · {sentence(finding.provenance)} · Attempt {number(reference.record_ref.attempt_id)} · Step {finding.step_id}</p><p>{Object.entries(finding.summary).slice(0, 4).map(([key, value]) => `${sentence(key)}: ${String(value)}`).join(" · ")}</p><Link to={`/runs/${encodeURIComponent(reference.record_ref.run_id)}`}>Open captured source run</Link><DataList items={[{ label: "Finding", value: <code>{reference.finding_id}</code> }, { label: "Record", value: <code>{JSON.stringify(reference.record_ref)}</code> }]} /></li>;
          })}</ul>
        </details>
      </li>;
    })}</ul>
    <details open><summary>Model reasoning about required refreshes</summary><DataList items={review.refresh_requirements.map(item => ({ label: sentence(item.prerequisite), value: item.explanation }))} /></details>
    <details><summary>Captured selection identity</summary><code>{history.knowledge_digest}</code><p>{history.attempt_ids.map(id => `Attempt ${number(id)}`).join(" · ")}</p></details>
  </section>;
}
