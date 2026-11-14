import { Link } from "react-router-dom";
import type { CompositionObjective } from "../lib/composition";
import type { RetainedCompositionArtifacts, RetainedCompositionSource } from "../lib/composition-retained";
import { DataList, sentence } from "./Primitives";

export function retainedSourceLabel(source: RetainedCompositionSource, objective: CompositionObjective) {
  const number = objective.attempts.findIndex(attempt => attempt.request.composition_attempt.attempt_id === source.attempt_id) + 1;
  return `${number ? `Attempt ${number}` : "Earlier attempt"} · Step ${source.step_id}`;
}

export function CompositionRetentionPolicy() {
  return <div className="composition-retention-policy">
    <h3>Keep and reuse generated results</h3>
    <p>Keep at most one successfully generated public JSONL result per attempt, up to 256 KiB. Reuse stays within this objective and its reviewed environment.</p>
    <p>The sealed result remains until its source run bundle is deleted. Each reuse creates a fresh workspace file and receipt. Cleanup removes owned workspace files while preserving the sealed source.</p>
    <p>The retained file stays private to its source run. Exports include its metadata and omit the retained bytes.</p>
    <p>Reuse transfers can remain in task and transport records until those records are deleted. Two transfer copies are reserved within the existing cumulative budgets.</p>
  </div>;
}

export function CompositionRetainedSources({ artifacts, objective, captured = false, attempted = false, receiverDecision }: { artifacts: RetainedCompositionArtifacts; objective: CompositionObjective; captured?: boolean; attempted?: boolean; receiverDecision?: string }) {
  const title = attempted ? "Generated result kept before a later failure" : captured ? "Captured available results" : "Available generated results";
  return <section className="composition-retained-sources" aria-label={title}>
    <h3>{title}</h3>
    <p>{attempted ? `A successful generated result was kept before a later step failed. ${receiverDecision ? `Recorded receiver decision: ${sentence(receiverDecision)}.` : "Receiver delivery remains unknown."} Its availability must be checked before reuse.` : captured ? "These source summaries were captured for this proposal. Current source availability and execution authority are checked separately before a fresh attempt." : artifacts.availability === "available" ? `${artifacts.available_sources.length} verified generated JSONL result${artifacts.available_sources.length === 1 ? " is" : "s are"} available for a fresh workspace copy under this objective.` : "No retained result is currently available. A graph can still generate fresh records within the grant."}</p>
    {artifacts.available_sources.length ? <ul>{artifacts.available_sources.map(source => <li key={source.source_ref}>
      <details><summary>{retainedSourceLabel(source, objective)} · {source.size_bytes.toLocaleString()} bytes</summary>
        <p>Historical byte custody preserves the original producer lineage. It does not establish current mutable access or successful receiver delivery.</p>
        <Link to={`/runs/${encodeURIComponent(source.run_id)}`}>Inspect retained source run</Link>
        <DataList items={Object.entries(source).map(([label, value]) => ({ label: sentence(label), value: <code>{String(value)}</code> }))} />
      </details>
    </li>)}</ul> : null}
  </section>;
}
