import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { registeredDetectionLink } from "../lib/run-handoffs";
import { api } from "../lib/api";
import { compareDetectorEvaluations, evaluationLabel } from "../lib/detection-results";
import type { DetectionResource, DetectionRunEvaluation } from "../types";
import { Badge, Button, Callout, EmptyState, ErrorState, Field, LoadingState, Panel, PanelHeader, sentence } from "./Primitives";
import { MatchedObservations } from "./MatchedObservations";
import { RunReference } from "./RunReference";

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
    <table><caption>Retained detector evaluations by run and revision</caption><thead><tr><th scope="col">Run / case</th><th scope="col">{baselineLabel}</th><th scope="col">{revisedLabel}</th><th scope="col">Measured change</th></tr></thead>
      <tbody>{rows.map((row) => <tr key={row.runId}><th scope="row"><RunReference runId={row.runId} /><small>{row.roles.length ? row.roles.map(sentence).join(" / ") : "Case not assigned"}</small></th>
        <td><EvaluationCell reports={row.baseline} /></td><td><EvaluationCell reports={row.revised} /></td><td>{row.change}</td></tr>)}</tbody>
    </table>
  </div> : <EmptyState title="No run evaluations yet" description="Evaluate both revisions in Detection Lab on separate attack, benign, and replay runs. Their actual results will appear here." />;
}

function EvaluationCell({ reports }: { reports: DetectionRunEvaluation[] }) {
  if (!reports.length) return <span>Not evaluated</span>;
  const labels = [...new Set(reports.map(evaluationLabel))];
  return <><strong>{labels.length === 1 ? labels[0] : "Mixed results"}</strong><small>{reports.length} retained evaluation{reports.length === 1 ? "" : "s"}</small>
    {reports.some((report) => report.development_case) ? <small>Includes development data; not an untouched independent test</small> : null}
    <details><summary>Evidence and engine</summary>{reports.map((report) => <article key={report.evaluation_id}>
      <Badge tone={evaluationLabel(report).includes("evidence") || report.result.state === "backend_error" ? "warning" : "info"}>{evaluationLabel(report)}</Badge>
      <p>{report.question}</p><p>{report.source.observed_count} independently observed events · {report.source.evidence_count} total records</p>
      <p>{report.backend.name} {report.backend.version ?? ""} · {report.backend.executed ? "Executed" : "Not executed"}</p>
      <MatchedObservations key={report.evaluation_id} report={report} />
      <p>Evidence gaps: {report.result.gap_count}. Missing fields: {report.result.missing_fields.join(", ") || "None reported"}.</p>
      <Link to={registeredDetectionLink(report.source.run_id, report.candidate.candidate_id)}>Open detector and run</Link>
      <details><summary>Full evaluation record</summary><pre>{JSON.stringify(report, null, 2)}</pre></details>
    </article>)}</details></>;
}

type DetectorSelection = { baselineId: string; revisedId: string };

function evaluationsMatch(reports: DetectionRunEvaluation[], resource: DetectionResource): boolean {
  return reports.every(report => report.candidate.candidate_id === resource.id
    && report.candidate.revision_root_id === (resource.document.revision_root_id ?? resource.id)
    && report.candidate.revision === (resource.document.revision ?? 1)
    && (!resource.document.definition_digest || report.candidate.definition_digest === resource.document.definition_digest));
}

export function DetectorEvaluationComparison({ runIds, selection, onSelectionChange }: { runIds: string[]; selection?: DetectorSelection; onSelectionChange?: (selection: DetectorSelection) => void }) {
  const candidates = useQuery({ queryKey: ["detections"], queryFn: api.detections });
  const [localSelection, setLocalSelection] = useState<DetectorSelection>({ baselineId: "", revisedId: "" });
  const { baselineId, revisedId } = selection ?? localSelection;
  const changeSelection = onSelectionChange ?? setLocalSelection;
  const resources = useMemo(() => {
    const registered = candidates.data?.candidates ?? [];
    const counts = new Map<string, number>();
    for (const item of registered) counts.set(item.id, (counts.get(item.id) ?? 0) + 1);
    return registered.filter(item => item.document.candidate_id === item.id && counts.get(item.id) === 1
      && ["internal", "sqlite", "sigma"].includes(item.document.target_language ?? item.document.language ?? ""));
  }, [candidates.data]);
  const baseline = resources.find((item) => item.id === baselineId);
  const family = baseline?.document.revision_root_id ?? baselineId;
  const revisions = baseline ? resources.filter((item) => item.id !== baselineId && (item.document.revision_root_id ?? item.id) === family) : [];
  const revised = revisions.find((item) => item.id === revisedId);
  const left = useQuery({ queryKey: ["detection-evaluations", baselineId], queryFn: () => api.detectionRunEvaluations(baselineId), enabled: Boolean(baseline) });
  const right = useQuery({ queryKey: ["detection-evaluations", revisedId], queryFn: () => api.detectionRunEvaluations(revisedId), enabled: Boolean(revised) });
  const revisionsReady = candidates.isSuccess && !candidates.isFetching;
  const identityMismatch = Boolean(baseline && revised && left.isSuccess && right.isSuccess
    && (!evaluationsMatch(left.data.evaluations, baseline) || !evaluationsMatch(right.data.evaluations, revised)));
  const ready = revisionsReady && baseline && revised && left.isSuccess && right.isSuccess
    && !left.isFetching && !right.isFetching && !identityMismatch;
  const exportResults = () => {
    if (!ready) return;
    const selected = new Set(runIds);
    const evaluations = [...left.data.evaluations, ...right.data.evaluations].filter((report) => selected.has(report.source.run_id));
    download("bluefire-detector-comparison.json", JSON.stringify({ schema_version: "bluefire.detector-comparison-export.v1", run_ids: runIds, baseline, revised, evaluations, limitations: ["Case roles are operator assigned. These results describe the recorded detector engine evaluating retained observations, not deployed host prevention.", "Missing evaluations and missing telemetry do not establish defense success."] }, null, 2) + "\n", "application/json");
  };
  const exportRule = (resource: DetectionResource) => {
    if (resource.document.target_language === "internal") {
      download(`${resource.id}.json`, JSON.stringify(resource.document, null, 2) + "\n", "application/json");
      return;
    }
    if (!resource.document.rule_source) return;
    const extension = resource.document.target_language === "sigma" ? "yml" : "sql";
    download(`${resource.id}.${extension}`, resource.document.rule_source + "\n", "text/plain");
  };
  const label = (item: DetectionResource) => `${item.document.title ?? item.id} · revision ${item.document.revision ?? 1}`;
  return <Panel className="detector-comparison">
    <PanelHeader title="Compare detector results" />
    <div className="detail-body">
      {candidates.isPending ? <LoadingState label="Loading detector revisions" /> : candidates.isError ? <ErrorState title="Detector revisions unavailable" error={candidates.error} retry={() => { void candidates.refetch(); }} /> : !resources.length && !baselineId && !revisedId ? <p>Save and evaluate a structured matcher, SQLite or Sigma rule in <Link to={runIds[0] ? `/detection-lab?run=${encodeURIComponent(runIds[0])}` : "/detection-lab"}>Detection Lab</Link> to compare its revisions here.</p> : <>
        {revisionsReady && baselineId && !baseline ? <Callout tone="warning" title="Original detector unavailable">The selected saved detector is missing, ambiguous or unsupported. Choose another detector or clear the selection.</Callout> : null}
        {revisionsReady && revisedId && !revised ? <Callout tone="warning" title="Revised detector unavailable">The selected revision is missing, ambiguous or outside the original detector's lineage. Choose a revision from that lineage or clear the selection.</Callout> : null}
        {(baselineId && !baseline) || (revisedId && !revised) ? <Button onClick={() => changeSelection({ baselineId: "", revisedId: "" })}>Clear detector selection</Button> : null}
        <div className="two-column"><Field label="Original detector"><select value={baselineId} disabled={!revisionsReady} onChange={(event) => changeSelection({ baselineId: event.target.value, revisedId: "" })}><option value="">Choose a detector</option>{baselineId && !baseline ? <option value={baselineId}>Unavailable original detector</option> : null}{resources.map((item) => <option key={item.id} value={item.id}>{label(item)}</option>)}</select></Field>
          <Field label="Revised detector"><select value={revisedId} disabled={!baseline || !revisionsReady} onChange={(event) => changeSelection({ baselineId, revisedId: event.target.value })}><option value="">Choose a revision</option>{revisedId && !revised ? <option value={revisedId}>Unavailable revised detector</option> : null}{revisions.map((item) => <option key={item.id} value={item.id}>{label(item)}</option>)}</select></Field></div>
        {baseline && !revisions.length ? <p>This detector has no saved revisions yet. Create one in Detection Lab.</p> : null}
        {left.isError || right.isError ? <ErrorState title="Detector evaluations unavailable" error={left.error ?? right.error} retry={() => { if (baseline) void left.refetch(); if (revised) void right.refetch(); }} /> : identityMismatch ? <Callout tone="warning" title="Detector evaluation identity mismatch"><p>Retained evaluations do not match the selected saved revisions. Refresh the detector records before comparing or exporting.</p><Button disabled={candidates.isFetching || left.isFetching || right.isFetching} onClick={() => { void candidates.refetch(); if (baseline) void left.refetch(); if (revised) void right.refetch(); }}>Refresh detector records</Button></Callout> : baseline && revised && !ready ? <LoadingState label="Loading retained detector results" /> : ready ? <>
          <DetectorEvaluationTable baseline={left.data.evaluations} revised={right.data.evaluations} baselineLabel={`Original · revision ${baseline.document.revision ?? 1}`} revisedLabel={`Revised · revision ${revised.document.revision ?? 1}`} runIds={runIds} />
          <p className="field-note">Case labels describe the operator's test setup. Counts are matched observed events. Detector evaluation does not establish deployed prevention.</p>
          <div className="candidate-actions"><Button onClick={exportResults}>Export comparison and evidence</Button><Button onClick={() => exportRule(revised)} disabled={revised.document.target_language !== "internal" && !revised.document.rule_source}>Download revised rule</Button></div>
        </> : null}
      </>}
    </div>
  </Panel>;
}
