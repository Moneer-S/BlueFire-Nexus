import { evaluationReportMarkdown, type EvaluationReportGroup } from "../lib/evaluation-report";
import * as Dialog from "@radix-ui/react-dialog";
import { runLabel } from "../lib/run-presentation";
import { formatDate } from "./Primitives";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { detectionDraftIdentity, useDetectionDraft } from "../state/useDetectionDraft";
import { MatchedObservations } from "./MatchedObservations";
import { RunReference } from "./RunReference";
import { api } from "../lib/api";
import { DetectorEvaluationTable } from "./DetectorEvaluationComparison";
import { activityLabel, evaluationUseLabel, evaluationLabel } from "../lib/detection-results";
import type { DetectionCandidate, DetectionCaseRole, DetectionRunEvaluation, RunRecord } from "../types";
import { Badge, Button, Callout, DataList, EmptyState, ErrorState, Field, LoadingState, sentence } from "./Primitives";

const questionSeed = "";

export function DetectionRunEvaluations({ candidate, resourceId, resourceDigest, sourceRunId, runs, revisions }: {
  candidate: DetectionCandidate;
  resourceId?: string;
  resourceDigest?: string;
  sourceRunId: string;
  runs: RunRecord[];
  revisions: Array<{ id: string; label: string }>;
}) {
  const client = useQueryClient();
  const binding = useMemo(() => detectionDraftIdentity({ workspace: "evaluation-inputs", resourceId: resourceId ?? null, resourceDigest: resourceDigest ?? null, candidate, sourceRunId }), [candidate, resourceId, resourceDigest, sourceRunId]);
  const draft = useDetectionDraft(binding, { runId: sourceRunId, question: questionSeed, role: "unknown" as DetectionCaseRole, relatedId: "" });
  const { runId, question, role, relatedId } = draft.value;
  // A separate record preserves all older evaluation drafts without rewriting their shape.
  const useDraft = useDetectionDraft(`${binding}:data-use-v1`, { evaluationUse: "unspecified" as "development" | "independent" | "unspecified" });
  const activity = role === "attack" || role === "benign" ? role : "unknown";
  const evaluationUse = useDraft.value.evaluationUse;
  const setRunId = (value: string) => draft.update("runId", value);
  const setQuestion = (value: string) => draft.update("question", value);
  const setRole = (value: DetectionCaseRole) => draft.update("role", value);
  const setRelatedId = (value: string) => draft.update("relatedId", value);
  const [discardFor, setDiscardFor] = useState<string | null>(null);
  useEffect(() => setDiscardFor(null), [binding]);
  const exportInputs = () => {
    const payload = { schema_version: "bluefire.detection-evaluation-inputs.v1", binding, inputs: { ...draft.value, ...useDraft.value } };
    const url = URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2) + "\n"], { type: "application/json" }));
    const link = document.createElement("a"); link.href = url; link.download = "detection-evaluation-inputs.json"; link.click(); URL.revokeObjectURL(url);
  };
  const reports = useQuery({ queryKey: ["detection-evaluations", resourceId], queryFn: () => api.detectionRunEvaluations(resourceId!), enabled: Boolean(resourceId) });
  const related = useQuery({ queryKey: ["detection-evaluations", relatedId], queryFn: () => api.detectionRunEvaluations(relatedId), enabled: Boolean(relatedId) });
  const evaluate = useMutation({
    mutationFn: (body: { candidateId: string; run_id: string; question: string; case_role: DetectionCaseRole; activity_label: "attack" | "benign" | "unknown"; evaluation_use: typeof evaluationUse; binding: string }) => api.evaluateDetectionRun(body.candidateId, { run_id: body.run_id, question: body.question, case_role: body.case_role, activity_label: body.activity_label, evaluation_use: body.evaluation_use }),
    onSuccess: (_result, body) => { void client.invalidateQueries({ queryKey: ["detection-evaluations", body.candidateId] }); },
  });
  const language = candidate.target_language ?? candidate.language ?? "internal";
  const canEvaluate = resourceId && ["sqlite", "sigma"].includes(language) && ["parsed", "fixture_exercised", "observed_exercised", "benign_evaluated"].includes(candidate.state);
  const rows = [...(reports.data?.evaluations ?? []), ...(related.data?.evaluations ?? [])];
  const [downloadError, setDownloadError] = useState<string>();
  useEffect(() => setDownloadError(undefined), [binding, relatedId]);
  const reportDownload = useMemo(() => {
    const groups: EvaluationReportGroup[] = [{ id: resourceId ?? "", label: `Selected · ${candidate.title ?? "Detector"} · revision ${candidate.revision ?? 1}`,
      status: reports.isFetching ? "loading" : reports.isSuccess ? "loaded" : reports.isError ? "unavailable" : "loading", reports: reports.isSuccess && !reports.isFetching ? reports.data.evaluations : [] }];
    if (relatedId) groups.push({ id: relatedId, label: revisions.find(revision => revision.id === relatedId)?.label ?? "Related revision",
      status: related.isFetching ? "loading" : related.isSuccess ? "loaded" : related.isError ? "unavailable" : "loading", reports: related.isSuccess && !related.isFetching ? related.data.evaluations : [] });
    const partial = groups.some(group => group.status !== "loaded");
    if (!groups.some(group => group.reports.length)) return { partial, markdown: undefined, error: undefined };
    try {
      if (candidate.candidate_id && candidate.candidate_id !== resourceId) throw new Error("The displayed candidate does not match the selected revision. Reload its history before exporting.");
      if (relatedId && !revisions.some(revision => revision.id === relatedId)) throw new Error("The related revision is no longer in this selection. Select its current history before exporting.");
      return { partial, markdown: evaluationReportMarkdown(groups, runs), error: undefined };
    }
    catch (error) { return { partial, markdown: undefined, error: error instanceof Error ? error.message : "The retained reports could not be exported." }; }
  }, [resourceId, candidate.candidate_id, candidate.title, candidate.revision, reports.isFetching, reports.isSuccess, reports.isError, reports.data, relatedId, related.isFetching, related.isSuccess, related.isError, related.data, revisions, runs]);
  const downloadReport = () => {
    if (!reportDownload.markdown) return;
    let url: string | undefined;
    try {
      url = URL.createObjectURL(new Blob([reportDownload.markdown], { type: "text/markdown;charset=utf-8" }));
      const link = document.createElement("a"); link.href = url; link.download = "bluefire-evaluation-report.md"; link.click(); setDownloadError(undefined);
    } catch { setDownloadError("The report could not be downloaded. Its retained results remain available."); }
    finally { if (url) URL.revokeObjectURL(url); }
  };

  const resultForSelection = evaluate.variables?.binding === binding && evaluate.variables?.candidateId === resourceId && evaluate.variables?.run_id === runId && evaluate.variables.question === question.trim() && evaluate.variables.case_role === role && evaluate.variables.evaluation_use === evaluationUse;
  return <>
    <p>Test this rule against the entire observed dataset in one query. Up to 10,000 records and 16 MiB of normalized fields are supported; resource refusals never become partial results. AI context has a separate, smaller limit.</p>
    {!canEvaluate ? <Callout tone="warning" title="Parsed query candidate required">Save and parse a SQLite or Sigma candidate to evaluate a run. Internal matcher results retain internal semantics, and YARA cannot inspect file bytes from metadata alone.</Callout> : null}
    {useDraft.warning ? <p role="alert">{useDraft.warning}</p> : null}
    {draft.warning ? <p role="alert">{draft.warning}</p> : draft.retained ? <p role="status">Evaluation inputs kept in this browser tab. They are not a saved evaluation.</p> : null}
    <div className="candidate-actions"><Button variant="ghost" size="small" onClick={exportInputs}>Export evaluation inputs</Button>
      <Dialog.Root open={discardFor === binding} onOpenChange={open => setDiscardFor(open ? binding : null)}>
        <Dialog.Trigger asChild><Button variant="ghost" size="small" disabled={evaluate.isPending}>Discard evaluation inputs</Button></Dialog.Trigger>
        <Dialog.Portal><Dialog.Overlay className="dialog-overlay"/><Dialog.Content className="dialog-content">
          <Dialog.Title>Discard these evaluation inputs?</Dialog.Title><Dialog.Description>Reset the question, source choice, assigned role and related revision selection for this candidate and source context. Retained evaluation records stay intact.</Dialog.Description>
          <div className="dialog-actions"><Dialog.Close asChild><Button>Keep editing</Button></Dialog.Close><Button variant="danger" onClick={() => { if (discardFor !== binding) return; draft.discard(); useDraft.discard(); setDiscardFor(null); }}>Discard these inputs</Button></div>
        </Dialog.Content></Dialog.Portal>
      </Dialog.Root>
    </div>
    <p>Question is optional. Leave it blank to use the selected rule and run.</p><Field label="Experiment question"><textarea rows={2} maxLength={1000} value={question} onChange={(event) => setQuestion(event.target.value)} /></Field>
    <Field label="Evaluation source run"><select value={runId} onChange={(event) => setRunId(event.target.value)}><option value="">Select a run</option>{runId && !runs.some((run) => run.run_id === runId) ? <option value={runId}>{runId}</option> : null}{runs.map((run) => <option key={run.run_id} value={run.run_id}>{runLabel(run)} · {sentence(run.mode)} · {formatDate(run.created_at)}</option>)}</select></Field>
    <Field label="Activity label" hint="Your description of the activity, separate from replay lineage and use during development."><select value={role} onChange={(event) => setRole(event.target.value as DetectionCaseRole)}><option value="unknown">Unknown / not assigned</option><option value="attack">Attack activity</option><option value="benign">Benign activity</option>{["replay", "heldout"].includes(role) ? <option value={role}>Earlier {role} label (activity unknown)</option> : null}</select></Field>
    <Field label="Use of this data" hint="Independent test data means data not used to write or tune this rule. Recorded development use takes precedence; an operator label alone cannot prove independence."><select value={evaluationUse} onChange={event => useDraft.update("evaluationUse", event.target.value as typeof evaluationUse)}><option value="unspecified">Not specified</option><option value="development">Development data</option><option value="independent">Independent test data</option></select></Field>
    <Button onClick={() => resourceId && evaluate.mutate({ binding, candidateId: resourceId, run_id: runId, question: question.trim(), case_role: role, activity_label: activity, evaluation_use: evaluationUse })} disabled={!canEvaluate || !runId || evaluate.isPending}>{evaluate.isPending ? "Evaluating immutable evidence" : "Evaluate full observed run"}</Button>
    {resultForSelection && evaluate.isError ? <ErrorState title="Evaluation refused" error={evaluate.error} /> : null}
    {resultForSelection && evaluate.data ? <Callout title="Evaluation retained">{evaluationLabel(evaluate.data.evaluation)}. The measured result comes from the query and source evidence.</Callout> : null}
    {revisions.some((revision) => revision.id !== resourceId) ? <Field label="Related revision reports"><select value={relatedId} onChange={(event) => setRelatedId(event.target.value)}><option value="">Selected revision only</option>{revisions.filter((revision) => revision.id !== resourceId).map((revision) => <option key={revision.id} value={revision.id}>{revision.label}</option>)}</select></Field> : null}
    {reports.isError ? <ErrorState title="Evaluation history unavailable" error={reports.error} retry={() => { void reports.refetch(); }} /> : null}
    {related.isError ? <ErrorState title="Related revision history unavailable" error={related.error} retry={() => { void related.refetch(); }} /> : null}
    {resourceId && reports.isPending ? <LoadingState label="Loading immutable evaluation reports" /> : null}
    <div className="candidate-actions"><Button onClick={downloadReport} disabled={!reportDownload.markdown}>{reportDownload.partial ? "Download available reports" : "Download evaluation report"}</Button></div>
    {reportDownload.partial && (resourceId || relatedId) ? <p role="status">Some selected revision history is loading or unavailable. Only successfully loaded retained reports can be downloaded; the export will be marked partial.</p> : null}
    {reportDownload.error ? <p role="alert">{reportDownload.error}</p> : null}
    {downloadError ? <p role="alert">{downloadError}</p> : null}
    {relatedId && reports.isSuccess && related.isSuccess ? <DetectorEvaluationTable baseline={related.data.evaluations} revised={reports.data.evaluations} baselineLabel={revisions.find((revision) => revision.id === relatedId)?.label ?? "Related revision"} revisedLabel={`Selected · revision ${candidate.revision ?? 1}`} /> : null}
    {rows.length ? <details className="evaluation-history" open={!relatedId}><summary>All retained evaluation records ({rows.length})</summary><div className="structured-list" aria-label="Immutable run evaluations">{rows.map((report) => <EvaluationReport key={report.evaluation_id} report={report} />)}</div></details> : reports.isSuccess ? <EmptyState title="No retained run evaluations" description="Evaluate an immutable run to record its actual query matches, activity, data use, and evidence limits." /> : null}
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
    { label: "Source lineage", value: report.classification ? sentence(report.classification.source_lineage) : "Unknown (legacy report)" },
    { label: "Data use", value: evaluationUseLabel(report) },
    { label: "Missing fields", value: result.missing_fields.join(", ") || "None reported" },
    { label: "Evidence gaps", value: result.gap_count },
    { label: "Diagnostics", value: result.diagnostic_codes.map(sentence).join(", ") || "None" },
    { label: "Query backend", value: backend },
    { label: "Query digest", value: <code>{report.candidate.query_sha256}</code> },
  ]} /><MatchedObservations key={report.evaluation_id} report={report} /><details><summary>Inspect immutable evaluation record</summary><pre>{JSON.stringify(report, null, 2)}</pre></details></>;
  return <article className={compact ? "creation-result" : undefined}>
    {compact ? <><h3>{measured}</h3><p>{report.source.observed_count} independently observed · {report.source.evidence_count} total records</p></> : <strong>{report.question}</strong>}
    {report.development_case ? compact ? <p className="creation-evidence-note"><strong>Development evidence</strong> · This data was used while developing the rule. Test separate data before judging effectiveness.</p> : <Callout title="Development evidence">This data was used or declared for rule development. An independent label cannot make it unseen. Evaluate separate data before judging improvement.</Callout> : null}
    <div><Badge>{sentence(activityLabel(report))} activity · operator assigned</Badge><Badge tone={result.state === "insufficient_evidence" || result.state === "backend_error" ? "warning" : "info"}>{sentence(result.state)}</Badge></div>
    {activityLabel(report) === "benign" && result.state === "matched" ? <Callout tone="warning" title="Match in a declared benign case">This query matched observed records in an operator-assigned benign case. Review this potential false positive; the label does not suppress the measured match.</Callout> : null}
    {compact ? <><p>{backend}</p>{result.gap_count > 0 || result.missing_fields.length > 0 || result.diagnostic_codes.length > 0 ? <Callout tone="warning" title="Evidence needs review">{result.gap_count} evidence gaps. {result.missing_fields.length ? `Missing fields: ${result.missing_fields.join(", ")}. ` : ""}{result.diagnostic_codes.map(sentence).join(", ")}</Callout> : null}<details><summary>Matched observations and evaluation details</summary><p>{report.question}</p>{detail}</details></> : detail}
  </article>;
}
