import { Link } from "react-router-dom";
import { Badge, DataList, sentence } from "./Primitives";
import type { S3AccessComparison, S3AccessComparisonAvailable, S3AccessComparisonCell } from "../types";

const changeLabel = { changed: "Changed", unchanged: "Unchanged", unknown: "Unknown" } as const;

export function S3AccessComparisonResults({ result }: { result: S3AccessComparison }) {
  if (result.state === "unavailable") {
    return <section className="comparison-detail" aria-label="S3 access comparison">
      <h2>S3 access outcomes</h2>
      <p role="status">S3 comparison unavailable: {sentence(result.reason)}. No S3 outcomes are inferred.</p>
    </section>;
  }
  return <AvailableResults result={result} />;
}

function AvailableResults({ result }: { result: S3AccessComparisonAvailable }) {
  return <section className="comparison-detail" aria-label="S3 access comparison">
    <header className="panel-header"><div><h2>S3 access outcomes</h2><p>Saved read results only. This comparison does not establish defensive effectiveness.</p></div>
      <div><Badge>{sentence(result.state)}</Badge><Badge tone={result.change_state === "unknown" ? "warning" : result.change_state === "changed" ? "info" : "neutral"}>{changeLabel[result.change_state]}</Badge></div>
    </header>
    <DataList items={[
      { label: "Baseline", value: phaseLabel(result.baseline) },
      { label: "Retest", value: phaseLabel(result.retest) },
      { label: "Workflow", value: <Link to={`/s3-access?exercise=${encodeURIComponent(result.workflow_job_id)}`}>Open saved S3 exercise</Link> },
    ]} />
    <div className="table-scroll" role="region" aria-label="S3 baseline and retest outcomes" tabIndex={0}>
      <table className="comparison-outcomes"><caption>Read results by purpose; unknown values remain unknown.</caption><thead><tr>
        <th scope="col">Reader / purpose</th><th scope="col">Baseline</th><th scope="col">Retest</th><th scope="col">Reported change</th>
      </tr></thead><tbody>{result.rows.map((row) => <tr key={`${row.reader}-${row.purpose}`}>
        <th scope="row">{sentence(row.reader)}<small>{sentence(row.purpose)}</small></th>
        <td><CellResult value={row.baseline} label={`${row.reader} ${row.purpose} baseline`} /></td>
        <td><CellResult value={row.retest} label={`${row.reader} ${row.purpose} retest`} /></td>
        <td>{row.changed === null ? <Badge tone="warning">Unknown</Badge> : row.changed ? <Badge tone="info">Changed</Badge> : <Badge>Unchanged</Badge>}</td>
      </tr>)}</tbody></table>
    </div>
    {result.gaps.length ? <div aria-label="S3 comparison gaps"><h3>Recorded gaps</h3><ul>{result.gaps.map((gap) => <li key={gap}>{sentence(gap)}</li>)}</ul></div> : null}
    <details><summary>Comparison identity and source</summary><DataList items={[
      { label: "Workflow job", value: <code>{result.workflow_job_id}</code> },
      { label: "Scope digest", value: <code>{result.scope_digest}</code> },
      { label: "Source digest", value: <code>{result.source_digest}</code> },
    ]} /></details>
  </section>;
}

function phaseLabel(value: S3AccessComparisonAvailable["baseline"]): string {
  if (!value) return "Not recorded";
  if (!value.selection_complete || !value.observation_complete) return "Partial results";
  return value.cleanup === "unknown" ? "Recorded; cleanup unknown" : "Recorded; cleanup verified";
}

function CellResult({ value, label }: { value: S3AccessComparisonCell; label: string }) {
  return <div>
    <Badge tone={value.state === "read" ? "info" : value.state === "service_denied" ? "neutral" : "warning"}>{sentence(value.state)}</Badge>
    <small>{value.provenance === null ? "Provenance not reported" : value.provenance === "synthetic" ? "Synthetic" : "Runner reported"}</small>
    <small>Cleanup: {value.cleanup === null ? "Not recorded" : sentence(value.cleanup)}</small>
    {value.run_id ? <Link to={`/runs/${encodeURIComponent(value.run_id)}`} aria-label={`Inspect ${label} run ${value.run_id}`}>Inspect run</Link> : null}
  </div>;
}
