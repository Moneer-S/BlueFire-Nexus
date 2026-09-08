import { runLabel } from "../lib/run-presentation";
import { formatDate } from "./Primitives";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { RunReference } from "./RunReference";
import { api } from "../lib/api";
import { DetectorEvaluationTable } from "./DetectorEvaluationComparison";
import { evaluationLabel } from "../lib/detection-results";
import type { DetectionCandidate, DetectionCaseRole, DetectionRunEvaluation, RunRecord } from "../types";
import { Badge, Button, Callout, DataList, EmptyState, ErrorState, Field, LoadingState, sentence } from "./Primitives";

const questionSeed = "Does this detector identify bounded collection staging while avoiding observed benign activity?";

export function DetectionRunEvaluations({ candidate, resourceId, sourceRunId, runs, revisions }: {
  candidate: DetectionCandidate;
  resourceId?: string;
  sourceRunId: string;
  runs: RunRecord[];
  revisions: Array<{ id: string; label: string }>;
}) {
  const client = useQueryClient();
  const [runId, setRunId] = useState(sourceRunId);
  const [question, setQuestion] = useState(questionSeed);
  const [role, setRole] = useState<DetectionCaseRole>("attack");
  const [relatedId, setRelatedId] = useState("");
  useEffect(() => { setRunId(sourceRunId); }, [sourceRunId]);
  useEffect(() => { setRelatedId(""); }, [resourceId]);
  const reports = useQuery({ queryKey: ["detection-evaluations", resourceId], queryFn: () => api.detectionRunEvaluations(resourceId!), enabled: Boolean(resourceId) });
  const related = useQuery({ queryKey: ["detection-evaluations", relatedId], queryFn: () => api.detectionRunEvaluations(relatedId), enabled: Boolean(relatedId) });
  const evaluate = useMutation({
    mutationFn: (body: { candidateId: string; run_id: string; question: string; case_role: DetectionCaseRole }) => api.evaluateDetectionRun(body.candidateId, { run_id: body.run_id, question: body.question, case_role: body.case_role }),
    onSuccess: (_result, body) => { void client.invalidateQueries({ queryKey: ["detection-evaluations", body.candidateId] }); },
  });
  const language = candidate.target_language ?? candidate.language ?? "internal";
  const canEvaluate = resourceId && ["sqlite", "sigma"].includes(language) && ["parsed", "fixture_exercised", "observed_exercised", "benign_evaluated"].includes(candidate.state);
  const rows = [...(reports.data?.evaluations ?? []), ...(related.data?.evaluations ?? [])];
  const resultForSelection = evaluate.variables?.candidateId === resourceId && evaluate.variables?.run_id === runId;
  return <>
    <p>Test this rule on the selected run's independently observed events, then repeat on separate benign activity and a replay. Missing telemetry stays visible as not enough evidence.</p>
    {!canEvaluate ? <Callout tone="warning" title="Parsed query candidate required">Save and parse a SQLite or Sigma candidate to evaluate a run. Internal matcher results retain internal semantics, and YARA cannot inspect file bytes from metadata alone.</Callout> : null}
    <Field label="Experiment question"><textarea rows={2} maxLength={1000} value={question} onChange={(event) => setQuestion(event.target.value)} /></Field>
    <Field label="Evaluation source run"><select value={runId} onChange={(event) => setRunId(event.target.value)}><option value="">Select a run</option>{runId && !runs.some((run) => run.run_id === runId) ? <option value={runId}>{runId}</option> : null}{runs.map((run) => <option key={run.run_id} value={run.run_id}>{runLabel(run)} · {sentence(run.mode)} · {formatDate(run.created_at)}</option>)}</select></Field>
    <Field label="Operator-assigned case role" hint="This label supplies context; it cannot assert intent or determine the measured result."><select value={role} onChange={(event) => setRole(event.target.value as DetectionCaseRole)}><option value="attack">Attack case</option><option value="benign">Benign activity</option><option value="replay">Replay</option><option value="heldout">Held-out variation</option></select></Field>
    <Button onClick={() => resourceId && evaluate.mutate({ candidateId: resourceId, run_id: runId, question: question.trim(), case_role: role })} disabled={!canEvaluate || !runId || !question.trim() || evaluate.isPending}>{evaluate.isPending ? "Evaluating immutable evidence" : "Evaluate full observed run"}</Button>
    {resultForSelection && evaluate.isError ? <ErrorState title="Evaluation refused" error={evaluate.error} /> : null}
    {resultForSelection && evaluate.data ? <Callout title="Evaluation retained">{evaluationLabel(evaluate.data.evaluation)}. The measured result comes from the query and source evidence.</Callout> : null}
    {revisions.some((revision) => revision.id !== resourceId) ? <Field label="Related revision reports"><select value={relatedId} onChange={(event) => setRelatedId(event.target.value)}><option value="">Selected revision only</option>{revisions.filter((revision) => revision.id !== resourceId).map((revision) => <option key={revision.id} value={revision.id}>{revision.label}</option>)}</select></Field> : null}
    {reports.isError ? <ErrorState title="Evaluation history unavailable" error={reports.error} retry={() => { void reports.refetch(); }} /> : null}
    {related.isError ? <ErrorState title="Related revision history unavailable" error={related.error} retry={() => { void related.refetch(); }} /> : null}
    {resourceId && reports.isPending ? <LoadingState label="Loading immutable evaluation reports" /> : null}
    {relatedId && reports.isSuccess && related.isSuccess ? <DetectorEvaluationTable baseline={related.data.evaluations} revised={reports.data.evaluations} baselineLabel={revisions.find((revision) => revision.id === relatedId)?.label ?? "Related revision"} revisedLabel={`Selected · revision ${candidate.revision ?? 1}`} /> : null}
    {rows.length ? <details className="evaluation-history" open={!relatedId}><summary>All retained evaluation records ({rows.length})</summary><div className="structured-list" aria-label="Immutable run evaluations">{rows.map((report) => <EvaluationReport key={report.evaluation_id} report={report} />)}</div></details> : reports.isSuccess ? <EmptyState title="No retained run evaluations" description="Evaluate an immutable run to record its actual query matches, case role, and evidence limits." /> : null}
  </>;
}

export function EvaluationReport({ report, compact = false }: { report: DetectionRunEvaluation; compact?: boolean }) {
  const result = report.result;
  const measured = result.match_count === null ? "Insufficient evidence or backend unavailable" : `${result.match_count} matched ${result.match_count === 1 ? "record" : "records"}`;
  const backend = `${report.backend.name}${report.backend.version ? ` · ${report.backend.version}` : ""} · ${report.backend.executed ? "Executed" : "Not executed"}`;
  const detail = <><DataList items={[
    { label: "Source run", value: <RunReference runId={report.source.run_id} /> },
    { label: "Detector revision", value: <span>{report.candidate.revision} · <code>{report.candidate.candidate_id}</code></span> },
    ...(!compact ? [{ label: "Observed / all records", value: `${report.source.observed_count} / ${report.source.evidence_count}` }, { label: "Query result", value: measured }] : []),
    { label: "Matched evidence", value: result.matched_evidence_ids.join(", ") || "None" },
    { label: "Missing fields", value: result.missing_fields.join(", ") || "None reported" },
    { label: "Evidence gaps", value: result.gap_count },
    { label: "Diagnostics", value: result.diagnostic_codes.map(sentence).join(", ") || "None" },
    { label: "Query backend", value: backend },
    { label: "Query digest", value: <code>{report.candidate.query_sha256}</code> },
  ]} /><details><summary>Inspect immutable evaluation record</summary><pre>{JSON.stringify(report, null, 2)}</pre></details></>;
  return <article className={compact ? "creation-result" : undefined}>
    {compact ? <><h3>{measured}</h3><p>{report.source.observed_count} independently observed · {report.source.evidence_count} total records</p></> : <strong>{report.question}</strong>}
    {report.development_case ? compact ? <p className="creation-evidence-note"><strong>Development evidence</strong> · AI used this run to propose the rule. Test separate benign and withheld cases before judging coverage.</p> : <Callout title="Development evidence">AI used this run while proposing the rule. Evaluate separate benign and withheld cases before judging improvement.</Callout> : null}
    <div><Badge>{sentence(report.case_role)} · operator assigned</Badge><Badge tone={result.state === "insufficient_evidence" || result.state === "backend_error" ? "warning" : "info"}>{sentence(result.state)}</Badge></div>
    {report.case_role === "benign" && result.state === "matched" ? <Callout tone="warning" title="Match in a declared benign case">This query matched observed records in an operator-assigned benign case. Review this potential false positive; the label does not suppress the measured match.</Callout> : null}
    {compact ? <><p>{backend}</p>{result.gap_count > 0 || result.missing_fields.length > 0 || result.diagnostic_codes.length > 0 ? <Callout tone="warning" title="Evidence needs review">{result.gap_count} evidence gaps. {result.missing_fields.length ? `Missing fields: ${result.missing_fields.join(", ")}. ` : ""}{result.diagnostic_codes.map(sentence).join(", ")}</Callout> : null}<details><summary>Matched observations and evaluation details</summary><p>{report.question}</p>{detail}</details></> : detail}
  </article>;
}
