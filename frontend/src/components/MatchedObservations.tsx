import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { api } from "../lib/api";
import type { DetectionRunEvaluation, EvidenceRecord, RunRecord } from "../types";
import { Button, ErrorState, LoadingState, sentence } from "./Primitives";

function boundMatches(report: DetectionRunEvaluation, run: RunRecord): EvidenceRecord[] | null {
  const records = run.evidence?.records;
  const hashes = report.result.matched_evidence_hashes;
  const ids = report.result.matched_evidence_ids;
  if (run.run_id !== report.source.run_id || run.manifest?.run_id !== run.run_id || !records || records.length !== report.source.evidence_count || !hashes || ids.length !== report.result.match_count || new Set(ids).size !== ids.length) return null;
  const byId = new Map(records.map(record => [record.evidence_id, record]));
  if (byId.size !== records.length) return null;
  const matches = ids.map(id => byId.get(id));
  if (matches.some((record, index) => !record || record.run_id !== run.run_id || record.provenance !== "observed" || !hashes[ids[index]!] || record.record_hash !== hashes[ids[index]!])) return null;
  return matches as EvidenceRecord[];
}

/** Display pagination only: the retained SQL result always covers one whole dataset. */
export function MatchedObservations({ report }: { report: DetectionRunEvaluation }) {
  const [open, setOpen] = useState(false);
  const [page, setPage] = useState(0);
  const query = useQuery({ queryKey: ["run", report.source.run_id], queryFn: () => api.runDetail(report.source.run_id), enabled: open && Boolean(report.result.matched_evidence_hashes), retry: false });
  const records = query.data ? boundMatches(report, query.data) : null;
  const size = 25;
  if (!report.result.matched_evidence_ids.length) return <p>No matched observations to inspect.</p>;
  return <details open={open} onToggle={event => setOpen(event.currentTarget.open)}>
    <summary>Inspect matched observations ({report.result.matched_evidence_ids.length})</summary>
    {open ? <>{!report.result.matched_evidence_hashes ? <p>This older report retains match identities only. Its immutable record remains available below; observation contents cannot be bound to this report.</p> : query.isError ? <ErrorState title="Matched observations unavailable" error={query.error} retry={() => { void query.refetch(); }} /> : query.isPending ? <LoadingState label="Loading matched observations" /> : !records ? <p role="alert">The available observations do not match the retained evaluation. No substituted contents are shown.</p> : <>
      <p>Showing {page * size + 1}–{Math.min((page + 1) * size, records.length)} of {records.length} matches. These are normalized observed fields, not raw file contents.</p>
      <ol start={page * size + 1}>{records.slice(page * size, (page + 1) * size).map(record => <li key={record.evidence_id}>
        <strong>{sentence(String(record.content?.observation_kind ?? record.content?.artifact_type ?? "Observed record"))}</strong>
        {typeof record.content?.path === "string" ? <p>{record.content.path}</p> : null}
        <details><summary>Recorded fields and identity</summary><pre>{JSON.stringify(record.content, null, 2)}</pre><dl><dt>Evidence ID</dt><dd><code>{record.evidence_id}</code></dd><dt>Step</dt><dd>{record.step_id ?? "Unknown"}</dd><dt>Recorded hash</dt><dd><code>{record.record_hash}</code></dd></dl></details>
      </li>)}</ol>
      {records.length > size ? <div className="candidate-actions"><Button size="small" disabled={page === 0} onClick={() => setPage(value => value - 1)}>Previous matches</Button><Button size="small" disabled={(page + 1) * size >= records.length} onClick={() => setPage(value => value + 1)}>Next matches</Button></div> : null}
    </>}</> : null}
  </details>;
}
