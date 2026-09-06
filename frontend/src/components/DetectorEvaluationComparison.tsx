import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import { compareDetectorEvaluations, evaluationLabel } from "../lib/detection-results";
import type { DetectionResource, DetectionRunEvaluation } from "../types";
import { Badge, Button, EmptyState, ErrorState, Field, LoadingState, Panel, PanelHeader, sentence } from "./Primitives";

function download(name: string, content: string, type: string) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  link.click();
  URL.revokeObjectURL(url);
}

export function DetectorEvaluationTable({ baseline, revised, baselineLabel, revisedLabel, runIds }: {
  baseline: DetectionRunEvaluation[];
  revised: DetectionRunEvaluation[];
  baselineLabel: string;
  revisedLabel: string;
  runIds?: string[];
}) {
  const rows = compareDetectorEvaluations(baseline, revised, runIds);
  return rows.length ? <div className="detector-comparison-table" role="region" aria-label="Measured detector comparison" tabIndex={0}>
    <table><caption>Retained query evaluations by run and detector revision</caption><thead><tr><th scope="col">Run / case</th><th scope="col">{baselineLabel}</th><th scope="col">{revisedLabel}</th><th scope="col">Measured change</th></tr></thead>
      <tbody>{rows.map((row) => <tr key={row.runId}><th scope="row"><Link to={`/runs/${encodeURIComponent(row.runId)}`}>{row.runId}</Link><small>{row.roles.length ? row.roles.map(sentence).join(" / ") : "Case not assigned"}</small></th>
        <td><EvaluationCell reports={row.baseline} /></td><td><EvaluationCell reports={row.revised} /></td><td>{row.change}</td></tr>)}</tbody>
    </table>
  </div> : <EmptyState title="No run evaluations yet" description="Evaluate both revisions in Detection Lab on separate attack, benign, and replay runs. Their actual results will appear here." />;
}

function EvaluationCell({ reports }: { reports: DetectionRunEvaluation[] }) {
  if (!reports.length) return <span>Not evaluated</span>;
  const labels = [...new Set(reports.map(evaluationLabel))];
  return <><strong>{labels.length === 1 ? labels[0] : "Mixed results"}</strong><small>{reports.length} retained evaluation{reports.length === 1 ? "" : "s"}</small>
    <details><summary>Evidence and engine</summary>{reports.map((report) => <article key={report.evaluation_id}>
      <Badge tone={evaluationLabel(report).includes("evidence") || report.result.state === "backend_error" ? "warning" : "info"}>{evaluationLabel(report)}</Badge>
      <p>{report.question}</p><p>{report.source.observed_count} independently observed events · {report.source.evidence_count} total records</p>
      <p>{report.backend.name} {report.backend.version ?? ""} · {report.backend.executed ? "Executed" : "Not executed"}</p>
      <p>Matched evidence: {report.result.matched_evidence_ids.join(", ") || "None"}</p>
      <p>Evidence gaps: {report.result.gap_count}. Missing fields: {report.result.missing_fields.join(", ") || "None reported"}.</p>
      <Link to={`/detection-lab?run=${encodeURIComponent(report.source.run_id)}&candidate=${encodeURIComponent(report.candidate.candidate_id)}`}>Open detector and run</Link>
      <details><summary>Full evaluation record</summary><pre>{JSON.stringify(report, null, 2)}</pre></details>
    </article>)}</details></>;
}

export function DetectorEvaluationComparison({ runIds }: { runIds: string[] }) {
  const candidates = useQuery({ queryKey: ["detections"], queryFn: api.detections });
  const [baselineId, setBaselineId] = useState("");
  const [revisedId, setRevisedId] = useState("");
  const resources = (candidates.data?.candidates ?? []).filter((item) => ["sqlite", "sigma"].includes(item.document.target_language ?? item.document.language ?? ""));
  const baseline = resources.find((item) => item.id === baselineId);
  const family = baseline?.document.revision_root_id ?? baselineId;
  const revisions = resources.filter((item) => item.id !== baselineId && (item.document.revision_root_id ?? item.id) === family);
  const revised = revisions.find((item) => item.id === revisedId);
  const left = useQuery({ queryKey: ["detection-evaluations", baselineId], queryFn: () => api.detectionRunEvaluations(baselineId), enabled: Boolean(baseline) });
  const right = useQuery({ queryKey: ["detection-evaluations", revisedId], queryFn: () => api.detectionRunEvaluations(revisedId), enabled: Boolean(revised) });
  const ready = baseline && revised && left.isSuccess && right.isSuccess;
  const exportResults = () => {
    if (!ready) return;
    const selected = new Set(runIds);
    const evaluations = [...left.data.evaluations, ...right.data.evaluations].filter((report) => selected.has(report.source.run_id));
    download("bluefire-detector-comparison.json", JSON.stringify({ schema_version: "bluefire.detector-comparison-export.v1", run_ids: runIds, baseline, revised, evaluations, limitations: ["Case roles are operator assigned. These results describe query execution on retained observations, not deployed host prevention.", "Missing evaluations and missing telemetry do not establish defense success."] }, null, 2) + "\n", "application/json");
  };
  const exportRule = (resource: DetectionResource) => {
    if (!resource.document.rule_source) return;
    const extension = resource.document.target_language === "sigma" ? "yml" : "sql";
    download(`${resource.id}.${extension}`, resource.document.rule_source + "\n", "text/plain");
  };
  const label = (item: DetectionResource) => `${item.document.title ?? item.id} · revision ${item.document.revision ?? 1}`;
  return <Panel className="detector-comparison">
    <PanelHeader eyebrow="Detection improvement" title="Compare detector results" detail="Choose the original rule and its revision. Results come from retained query evaluations on the selected runs." />
    <div className="detail-body">
      {candidates.isPending ? <LoadingState label="Loading detector revisions" /> : candidates.isError ? <ErrorState title="Detector revisions unavailable" error={candidates.error} retry={() => { void candidates.refetch(); }} /> : !resources.length ? <p>Save and evaluate a SQLite or Sigma rule in <Link to={runIds[0] ? `/detection-lab?run=${encodeURIComponent(runIds[0])}` : "/detection-lab"}>Detection Lab</Link> to compare its revisions here.</p> : <>
        <div className="two-column"><Field label="Original detector"><select value={baselineId} onChange={(event) => { setBaselineId(event.target.value); setRevisedId(""); }}><option value="">Choose a detector</option>{resources.map((item) => <option key={item.id} value={item.id}>{label(item)}</option>)}</select></Field>
          <Field label="Revised detector"><select value={revised?.id ?? ""} disabled={!baseline} onChange={(event) => setRevisedId(event.target.value)}><option value="">Choose a revision</option>{revisions.map((item) => <option key={item.id} value={item.id}>{label(item)}</option>)}</select></Field></div>
        {baseline && !revisions.length ? <p>This detector has no saved revisions yet. Create one in Detection Lab.</p> : null}
        {left.isError || right.isError ? <ErrorState title="Detector evaluations unavailable" error={left.error ?? right.error} retry={() => { if (baseline) void left.refetch(); if (revised) void right.refetch(); }} /> : baseline && revised && !ready ? <LoadingState label="Loading retained detector results" /> : ready ? <>
          <DetectorEvaluationTable baseline={left.data.evaluations} revised={right.data.evaluations} baselineLabel={`Original · revision ${baseline.document.revision ?? 1}`} revisedLabel={`Revised · revision ${revised.document.revision ?? 1}`} runIds={runIds} />
          <p className="field-note">Case labels describe the operator's test setup. Counts are matched observed events. Query evaluation does not establish deployed prevention.</p>
          <div className="candidate-actions"><Button onClick={exportResults}>Export comparison and evidence</Button><Button onClick={() => exportRule(revised)} disabled={!revised.document.rule_source}>Download revised rule</Button></div>
        </> : null}
      </>}
    </div>
  </Panel>;
}
