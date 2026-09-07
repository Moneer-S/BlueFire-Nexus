import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowRight, MessageSquareText } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import { checkedGraphEnvelope, validGraphJob } from "../lib/graph-assistance";
import { checkedAssistanceRun, runIntent, validSavedGraphSelection, type RunPreparationDecision, readRunDecision, storeRunDecision, type SavedGraphSelection } from "../lib/run-assistance";
import { sameJson } from "../lib/replay-review";
import { useProduct } from "../state/ProductContext";
import { useAssistancePanel, usePublishSavedGraphSelection } from "../state/AssistanceContext";
import { CanonicalPlanReview } from "../components/CanonicalPlanReview";
import { RunConfigurationPanel } from "../components/RunConfiguration";
import { Button, Callout, DataList, ErrorState, LoadingState, PageHeader, sentence } from "../components/Primitives";
import type { CatalogResponse, RunConfiguration, ScenarioVersion } from "../types";
import type { GraphApplication } from "../lib/graph-assistance";
import "./Runs.css";

export function SavedGraphRunSetup({ jobId }: { jobId: string }) {
  const graph = useQuery({ queryKey: ["graph-proposal", jobId], queryFn: async () => checkedGraphEnvelope(await api.graphProposal(jobId), jobId), enabled: validGraphJob(jobId), retry: false });
  const application = graph.data?.application;
  const saved = useQuery({ queryKey: ["graph-saved-version", application?.scenario_id, application?.version, application?.digest], enabled: Boolean(application), retry: false,
    queryFn: async () => {
      const { scenario } = await api.immutableScenarioVersion(application!.scenario_id, application!.version);
      if (scenario.scenario_id !== application!.scenario_id || scenario.version !== application!.version || scenario.digest !== application!.digest || scenario.document.id !== application!.scenario_id) throw new Error("The experiment does not match its saved review. Check the original proposal before continuing.");
      return scenario;
    } });
  const catalog = useQuery({ queryKey: ["catalog"], queryFn: api.catalog });
  if (!validGraphJob(jobId)) return <div className="page"><ErrorState error={new Error("This run link is incomplete. Open the saved experiment from Assistant.")} /></div>;
  if (graph.error || saved.error || catalog.error) return <div className="page"><ErrorState title="Saved experiment is unavailable" error={graph.error ?? saved.error ?? catalog.error} retry={() => { void graph.refetch(); void saved.refetch(); void catalog.refetch(); }} /></div>;
  if (graph.data && !application) return <div className="page"><Callout title="Save the experiment first">Review and save the proposed graph before preparing a run. <Link to={`/builder?graph_job=${encodeURIComponent(jobId)}`}>Review graph proposal</Link></Callout></div>;
  if (!saved.data || !catalog.data || !application) return <div className="page"><LoadingState label="Opening the saved experiment" /></div>;
  return <SavedGraphConfiguration key={`${jobId}:${application.digest}`} saved={saved.data} application={application} catalog={catalog.data} />;
}

function SavedGraphConfiguration({ saved, application, catalog }: { saved: ScenarioVersion; application: GraphApplication; catalog: CatalogResponse }) {
  const { runConfig } = useProduct();
  const setupKey = `bluefire.saved-graph-run.${application.proposal_job_id}.${application.digest}`;
  const [config, setConfig] = useState<RunConfiguration>(() => {
    const defaults = { ...structuredClone(runConfig), actionImplementations: {}, approved: false, approvedBy: "" };
    try {
      const raw = sessionStorage.getItem(setupKey);
      if (!raw || raw.length > 16000) return defaults;
      const selected: unknown = JSON.parse(raw);
      if (!validSavedGraphSelection(selected) || !sameJson(selected.application, application)) return defaults;
      const intent = selected.run_intent;
      return { ...defaults, mode: intent.mode, autonomy: intent.autonomy, provider: intent.ai_provider_id ?? "", profileId: intent.runner_profile_id ?? "",
        scopeRefs: intent.target_scope.scope_refs, collectors: intent.collectors ?? defaults.collectors, actionImplementations: intent.action_implementations ?? {} };
    } catch { return defaults; }
  });
  const [setupError, setSetupError] = useState<Error>();
  const panel = useAssistancePanel();
  const selection = useMemo<SavedGraphSelection>(() => ({ kind: "saved_graph", proposal_job_id: application.proposal_job_id, application, run_intent: runIntent(config) }), [application, config]);
  usePublishSavedGraphSelection(selection, saved.title);
  useEffect(() => {
    try { const raw = JSON.stringify(selection); sessionStorage.setItem(setupKey, raw); if (sessionStorage.getItem(setupKey) !== raw) throw new Error(); setSetupError(undefined); }
    catch { setSetupError(new Error("These settings could not be retained for returning to this page. Keep this page open until the Assistant has saved your request.")); }
  }, [selection, setupKey]);
  return <div className="page runs-page">
    <PageHeader eyebrow="Saved experiment" title={saved.title} description={`Version ${saved.version} · Choose where and how this experiment will run.`} actions={<Button variant="primary" onClick={() => panel?.setOpen(true)} disabled={!panel}><MessageSquareText />Run with Assistant</Button>} />
    <Callout title="Run this reviewed version">The Assistant prepares this saved experiment using the settings below, then inspects the completed run. Your Builder draft stays available. Assist asks you to review the plan; Execute requires approval for the resulting job.</Callout>
    {setupError ? <ErrorState title="Settings are only available on this page" error={setupError} /> : null}
    <div className="assisted-run-layout">
      <RunConfigurationPanel scenario={saved.document} config={config} onChange={(next) => setConfig({ ...next, approved: false, approvedBy: "" })} catalog={catalog} assistedSetup />
      <section className="assisted-run-overview" aria-label="Saved experiment overview"><h2>Experiment to run</h2><DataList items={[{ label: "Version", value: saved.version }, { label: "Steps and routes", value: `${saved.document.steps.length} steps · ${saved.document.edges.length} routes` }, { label: "Effects", value: config.mode === "simulate" ? "Synthetic evidence only" : "Actions in the selected authorized lab" }, { label: "Scope", value: config.scopeRefs.join(", ") || "Choose a target scope" }]} /><ol>{saved.document.steps.map((step) => <li key={step.id}>{catalog.behaviors.find((item) => item.id === step.behavior_id)?.title ?? step.id}</li>)}</ol><Link to={`/builder?graph_job=${encodeURIComponent(application.proposal_job_id)}`}>Review the saved graph<ArrowRight /></Link></section>
    </div>
  </div>;
}

export function AssistedRunReview({ jobId }: { jobId: string }) {
  const client = useQueryClient();
  const panel = useAssistancePanel();
  const locked = useRef(false);
  const [retained] = useState(() => { try { return { decision: readRunDecision(jobId), error: undefined }; } catch { return { decision: undefined, error: new Error("The retained review could not be read. Check browser session storage before reviewing this run.") }; } });
  const [pendingDecision, setPendingDecision] = useState(retained.decision);
  const [localError, setLocalError] = useState<Error | undefined>(retained.error);
  const work = useQuery({ queryKey: ["assistance-run", jobId], queryFn: async () => checkedAssistanceRun(await api.assistanceRun(jobId), jobId), enabled: validGraphJob(jobId), retry: false,
    refetchInterval: (query) => query.state.data && !query.state.error && !query.state.data.result && query.state.data.decision?.decision !== "reject" && (query.state.data.decision || query.state.data.run_job || !["failed", "cancelled", "interrupted"].includes(query.state.data.job.state)) ? 1500 : false });
  const review = useMutation({ mutationFn: async (body: RunPreparationDecision & { decision: "accept" | "reject" }) => {
    if (locked.current) throw new Error("The saved decision is still being checked.");
    locked.current = true;
    try {
      const result = checkedAssistanceRun(await api.reviewAssistanceRun(jobId, body), jobId);
      if (!sameJson(result.decision, body)) throw new Error("The response does not match your decision. Retry the same decision to check its saved outcome.");
      return result;
    } finally { locked.current = false; }
  }, onSuccess: (result) => { client.setQueryData(["assistance-run", jobId], result); void client.invalidateQueries({ queryKey: ["assistance-turn"] }); } });
  const envelope = work.data;
  const preparation = envelope?.preparation;
  const parentBinding = envelope?.job.request?.assistance_turn;
  const parentId = parentBinding && typeof parentBinding === "object" && "parent_job_id" in parentBinding && typeof parentBinding.parent_job_id === "string" && validGraphJob(parentBinding.parent_job_id) ? parentBinding.parent_job_id : undefined;
  const choose = (decision: "accept" | "reject") => {
    if (!preparation || review.isPending || pendingDecision || localError || !envelope?.review_ready) return;
    const body = { decision, preparation_digest: preparation.preparation_digest };
    if (!storeRunDecision(jobId, body)) { setLocalError(new Error("Enable browser session storage before reviewing this run. Your decision must survive a disconnect without creating conflicting requests.")); return; }
    setPendingDecision(body); review.mutate(body);
  };
  if (!validGraphJob(jobId)) return <div className="page"><ErrorState error={new Error("This run-review link is incomplete. Open the saved work from Assistant.")} /></div>;
  return <div className="page runs-page">
    <PageHeader eyebrow="Assistant run review" title={preparation?.scenario.title ?? "Preparing the experiment"} description="Review the saved version, selected settings, and complete plan." />
    {work.error ? <ErrorState title="Saved run preparation is unavailable" error={work.error} retry={() => { void work.refetch(); }} /> : null}
    {!envelope && !work.error ? <LoadingState label="Checking saved run preparation" /> : null}
    {preparation ? <>
      <dl className="assisted-review-context"><div><dt>Saved version</dt><dd>{preparation.selection.application.version}</dd></div><div><dt>AI during the run</dt><dd>{sentence(preparation.selection.run_intent.autonomy)} · {preparation.selection.run_intent.ai_provider_id ?? "No provider"}</dd></div><div><dt>Run status</dt><dd>{envelope?.run_job ? sentence(envelope.run_job.state) : "Not started"}</dd></div></dl>
      {preparation.preflight.plan ? <>{envelope?.decision ? <details><summary>{envelope.result?.runtime_modified ? "Original preparation before reviewed runtime changes" : "Reviewed preparation"}</summary><CanonicalPlanReview plan={preparation.preflight.plan} cleanup={preparation.preflight.cleanup} scope={preparation.preflight.scope} binding={preparation.preflight.approval_binding} envelope={preparation.preflight.approval_envelope} /></details> : <CanonicalPlanReview plan={preparation.preflight.plan} cleanup={preparation.preflight.cleanup} scope={preparation.preflight.scope} binding={preparation.preflight.approval_binding} envelope={preparation.preflight.approval_envelope} />}</> : <Callout title="Plan unavailable">The saved preparation has no reviewable plan. Return to Assistant to check the operation.</Callout>}
      {preparation.preflight.findings?.length ? <ul>{preparation.preflight.findings.map((item, index) => <li key={index}>{typeof item === "string" ? item : item.message ?? item.code}</li>)}</ul> : null}
      {!envelope?.decision ? <section className="assisted-run-decision" aria-label="Review decision"><p>{preparation.selection.run_intent.mode === "execute" ? "Accepting creates the run request. It waits for a separate, fresh Execute approval before actions can start." : "Accepting submits this exact Simulate plan. The Assistant will inspect the saved result afterward."}</p>
        {pendingDecision ? <Button disabled={review.isPending || Boolean(work.error) || Boolean(localError) || pendingDecision.preparation_digest !== preparation.preparation_digest} onClick={() => review.mutate(pendingDecision)}>{review.isPending ? "Saving your decision…" : `Retry ${pendingDecision.decision === "accept" ? "acceptance" : "decline"}`}</Button> : <><Button variant="primary" disabled={!envelope?.review_ready || !preparation.preflight.plan || Boolean(work.error) || Boolean(localError)} onClick={() => choose("accept")}>Accept and prepare run<ArrowRight /></Button><Button disabled={!envelope?.review_ready || Boolean(work.error) || Boolean(localError)} onClick={() => choose("reject")}>Decline this run</Button></>}
      </section> : <p role="status">{envelope.decision.decision === "reject" ? "Run declined. No run was submitted." : envelope.decision.decision === "policy" ? "The selected Auto policy accepted this preparation." : "Your review is saved."}</p>}
    </> : envelope ? <p role="status">{sentence(envelope.job.state)} · {["failed", "cancelled", "interrupted"].includes(envelope.job.state) ? "Preparation did not finish. Open the Assistant to check the saved operation and its recovery options." : "The Assistant is checking the saved experiment and selected settings."}</p> : null}
    {envelope?.run_job ? <Link className="button button-primary button-medium" to={`/runs?job=${encodeURIComponent(envelope.run_job.job_id)}`}>{envelope.run_job.state === "awaiting_approval" ? envelope.run_job.progress.approval_kind === "ai_proposal" ? "Review runtime proposal" : "Review Execute approval" : "Open run progress"}<ArrowRight /></Link> : null}
    {envelope?.result?.runtime_modified ? <Callout title="Reviewed runtime changes applied">The completed run includes an accepted runtime proposal. The original saved version and preparation are retained; open the run record to inspect what actually ran.</Callout> : null}
    {envelope?.inspection ? <section aria-label="Evidence inspection"><h2>{envelope.inspection.status === "insufficient" ? "Not enough evidence" : "What the evidence shows"}</h2><p>{envelope.inspection.summary}</p>{!envelope.inspection.model_interpretation ? <p>Recorded facts only; no model interpretation was requested.</p> : null}<DataList items={[{ label: "Independent observations", value: envelope.inspection.observed_records }, { label: "Total records", value: envelope.inspection.total_records }]} /><ul>{envelope.inspection.findings.map((finding, index) => <li key={index}>{finding.claim}<details><summary>Evidence references</summary>{finding.evidence_refs.map((reference) => <code key={reference}>{reference}</code>)}</details></li>)}</ul>{envelope.inspection.limitations.map((limitation, index) => <p key={index}>{limitation}</p>)}<Link to={`/runs/${encodeURIComponent(envelope.inspection.run_id)}`}>Review run evidence and export<ArrowRight /></Link></section> : null}
    {envelope ? <div><Button variant="ghost" onClick={() => parentId ? panel?.openJob(parentId) : panel?.setOpen(true)} disabled={!panel}>Open Assistant work</Button></div> : null}
    {review.error || localError ? <ErrorState title="Your run decision needs attention" error={review.error ?? localError} /> : null}
  </div>;
}
