import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import { checkedCreationEnvelope, checkedCreationSource, creationDigest, creationJobId, creationWorkActive, detectionCreationPath, readCreationDraft, storeCreationDraft, validCreationText,
  type DetectionCreationDecision, type DetectionCreationDraft, type DetectionCreationEnvelope, type DetectionCreationLanguage, type DetectionCreationProposal, type DetectionCreationRole, type DetectionCreationValidation, type RunDetectionSelection } from "../lib/detection-creation";
import { sameJson } from "../lib/replay-review";
import { useAssistancePanel, usePublishRunDetectionSelection } from "../state/AssistanceContext";
import { EvaluationReport } from "./DetectionRunEvaluations";
import { Button, Callout, ErrorState, Field, LoadingState, sentence } from "./Primitives";
import "./DetectionAICreation.css";

export function DetectionAICreation({ runId, jobId }: { runId: string; jobId?: string }) {
  if (jobId !== undefined) return <CreationReview key={jobId} jobId={jobId} selectedRunId={runId} />;
  return <CreationSetup key={runId} runId={runId} />;
}

function CreationSetup({ runId }: { runId: string }) {
  const panel = useAssistancePanel();
  const source = useQuery({ queryKey: ["detection-creation-source", runId], queryFn: async () => checkedCreationSource(await api.detectionCreationSource(runId), runId), enabled: Boolean(runId), retry: false });
  const [chosenBehavior, setChosenBehavior] = useState<string>();
  const [chosenLanguage, setChosenLanguage] = useState<DetectionCreationLanguage>();
  const [role, setRole] = useState<DetectionCreationRole>("attack");
  const data = source.data;
  const behavior = chosenBehavior ?? (data?.behaviors.length === 1 ? data.behaviors[0]!.behavior_id : "");
  const language = chosenLanguage ?? (data?.languages.find((item) => item.id === "sqlite" && item.available)?.id ?? data?.languages.find((item) => item.available)?.id);
  const selected = useMemo<RunDetectionSelection | undefined>(() => data?.available && data.behaviors.some((item) => item.behavior_id === behavior)
    && language && data.languages.some((item) => item.id === language && item.available) ? { kind: "run_detection", run_id: runId, source_binding_digest: data.source_binding_digest, behavior_id: behavior, target_language: language, case_role: role } : undefined,
  [data, behavior, language, role, runId]);
  usePublishRunDetectionSelection(selected, data?.behaviors.find((item) => item.behavior_id === behavior)?.title);
  return <section className="detection-creation" aria-label="Create detection from run">
    <header><h2>Create a detection from this run</h2><p>Draft a query from independent observations, review its source, then measure what it matches.</p></header>
    {!runId ? <Callout title="Choose a source run">Select a completed run above. The rule will use that run's independently observed evidence.</Callout> : source.isPending ? <LoadingState label="Checking source observations and query engines" /> : source.error ? <ErrorState title="Source evidence unavailable" error={source.error} retry={() => { void source.refetch(); }} /> : data ? <>
      <p>{data.observed_count} independent observations · {data.evidence_count} total records · {sentence(data.mode)}</p>
      {!data.available ? <Callout title="This source cannot support a draft">{data.reason ?? "Choose a run with usable independent observations."} <Link to={`/runs/${encodeURIComponent(runId)}`}>Review source evidence</Link></Callout> : <>
        <div className="creation-choices">
          <Field label="Behavior to detect" hint={data.behaviors.length > 1 ? "Choose the behavior this rule should identify." : undefined}><select value={behavior} onChange={(event) => setChosenBehavior(event.target.value)}><option value="">Choose a behavior</option>{data.behaviors.map((item) => <option key={item.behavior_id} value={item.behavior_id}>{item.title} · {item.observed_count} observations</option>)}</select></Field>
          <Field label="Rule language"><select value={language ?? ""} onChange={(event) => setChosenLanguage(event.target.value as DetectionCreationLanguage)}><option value="" disabled>Choose an available engine</option>{data.languages.map((item) => <option key={item.id} value={item.id} disabled={!item.available}>{item.id === "sqlite" ? "SQLite query" : "Sigma rule"}{item.available ? "" : " · unavailable"}</option>)}</select></Field>
          <Field label="Development case" hint="Your label supplies context; actual matches determine the result."><select value={role} onChange={(event) => setRole(event.target.value as DetectionCreationRole)}><option value="attack">Attack case</option><option value="benign">Benign activity</option><option value="replay">Replay</option></select></Field>
        </div>
        {data.languages.filter((item) => !item.available).map((item) => <p key={item.id}>{sentence(item.id)} unavailable: {item.reason ?? "The query engine is not ready."}</p>)}
        <p className="creation-evidence-note">This run becomes development input. Test separate benign and withheld cases before judging detection coverage.</p>
        <Button variant="primary" disabled={!selected || !panel} onClick={() => panel?.setOpen(true)}>Draft rule with Assistant</Button>
        {!behavior ? <p>Choose a behavior before opening the drafting request.</p> : null}
      </>}
      {data.limitations.length ? <details><summary>Source and backend limitations</summary><ul>{data.limitations.map((item, index) => <li key={index}>{item}</li>)}</ul></details> : null}
    </> : null}
    <Link to={runId ? `/detection-lab?run=${encodeURIComponent(runId)}` : "/detection-lab"}>Return to saved rules and manual tools</Link>
  </section>;
}

function CreationReview({ jobId, selectedRunId }: { jobId: string; selectedRunId: string }) {
  const client = useQueryClient();
  const panel = useAssistancePanel();
  const heading = useRef<HTMLHeadingElement>(null), focusPending = useRef(true);
  const query = useQuery({ queryKey: ["detection-creation", jobId], queryFn: async () => checkedCreationEnvelope(await api.detectionCreation(jobId), jobId), enabled: creationJobId(jobId), retry: false,
    refetchInterval: (state) => state.state.data && (creationWorkActive(state.state.data.job) || creationWorkActive(state.state.data.application_job)) && !state.state.error ? 1000 : false });
  useEffect(() => { const yieldFocus = () => { focusPending.current = false; }; document.addEventListener("focusin", yieldFocus); return () => document.removeEventListener("focusin", yieldFocus); }, []);
  useEffect(() => { if (!query.isPending && focusPending.current) { heading.current?.focus(); focusPending.current = false; } }, [query.isPending]);
  const data = query.data;
  const binding = data?.job.request?.assistance_turn;
  const parentId = binding && typeof binding === "object" && "parent_job_id" in binding && typeof binding.parent_job_id === "string" && creationJobId(binding.parent_job_id) ? binding.parent_job_id : undefined;
  const stop = useMutation({ mutationFn: () => api.controlJob(parentId ?? jobId, "cancel"), onSettled: () => { void query.refetch(); } });
  const cache = (value: DetectionCreationEnvelope) => {
    client.setQueryData(["detection-creation", jobId], value);
    if (value.application) { void client.invalidateQueries({ queryKey: ["detections"] }); void client.invalidateQueries({ queryKey: ["detection-evaluations", value.application.candidate_id] }); }
    void client.invalidateQueries({ queryKey: ["assistance-turn"] });
  };
  if (!creationJobId(jobId)) return <ErrorState title="Incomplete rule review link" error={new Error("Open the saved detection work from Assistant.")} />;
  return <section className="detection-creation" aria-label="Review new detection">
    <header><h2 ref={heading} tabIndex={-1}>{data?.application ? "Rule saved and evaluated" : data?.proposal ? "Review the proposed rule" : "Drafting the rule"}</h2><p>The proposal and your edits stay separate from saved rules until you approve them.</p></header>
    {query.isPending ? <LoadingState label="Finding the saved detection work" /> : query.error ? <ErrorState title="Saved detection work unavailable" error={query.error} retry={() => { void query.refetch(); }} /> : null}
    {data ? <>
      {data.proposal && data.proposal.selected.run_id !== selectedRunId ? <Callout title="This draft belongs to another run">Its source remains unchanged. <Link to={detectionCreationPath(data.proposal.selected.run_id, jobId)}>Open the draft with its source run</Link></Callout> : null}
      {!data.proposal ? <p role="status">{creationWorkActive(data.job) ? "Preparing a source proposal from the selected observations…" : `${sentence(data.job.state)} · no rule has been saved.`}</p> : null}
      {data.job.error ? <ErrorState title="Drafting needs attention" error={new Error(data.job.error.message ?? "Open Assistant to inspect and recover the saved operation.")} /> : null}
      {data.proposal ? <CreationEditor key={data.proposal.proposal_digest} jobId={jobId} envelope={data} proposal={data.proposal} cache={cache} refreshing={query.isFetching} lookupError={Boolean(query.error)} /> : null}
      {!data.application && (creationWorkActive(data.job) || creationWorkActive(data.application_job) || data.review_ready) ? <Button disabled={stop.isPending || data.job.state === "cancelling" || data.application_job?.state === "cancelling"} onClick={() => stop.mutate()}>{stop.isPending || data.job.state === "cancelling" || data.application_job?.state === "cancelling" ? "Stop requested…" : "Stop this operation"}</Button> : null}
      {parentId ? <Button variant="ghost" onClick={() => panel?.openJob(parentId)} disabled={!panel}>Open Assistant work</Button> : null}
    </> : null}
    {stop.error ? <ErrorState title="Stop needs attention" error={stop.error} /> : null}
  </section>;
}

function CreationEditor({ jobId, envelope, proposal, cache, refreshing, lookupError }: { jobId: string; envelope: DetectionCreationEnvelope; proposal: DetectionCreationProposal; cache: (value: DetectionCreationEnvelope) => void; refreshing: boolean; lookupError: boolean }) {
  const [initial] = useState(() => { try { return { draft: readCreationDraft(jobId, proposal) ?? { proposal_digest: proposal.proposal_digest, title: proposal.title, source: proposal.source } }; } catch { return { error: new Error("Your retained edits could not be read. They have not been replaced. Restore access to browser storage and reopen this draft.") }; } });
  const [draft, setDraft] = useState(initial.draft);
  const [localError, setLocalError] = useState<Error | undefined>(initial.error);
  const [reviewer, setReviewer] = useState("");
  const [validation, setValidation] = useState<DetectionCreationValidation>();
  const lock = useRef(false);
  const currentDraft = useRef(draft); currentDraft.current = draft;
  const decision = envelope.decision ?? draft?.decision;
  const persist = (next: DetectionCreationDraft) => {
    setDraft(next); currentDraft.current = next;
    const retained = storeCreationDraft(jobId, proposal, next);
    setLocalError(retained ? undefined : new Error("Your edits are visible here but could not be retained. Restore browser storage before saving this rule."));
    return retained;
  };
  const validate = useMutation({ mutationFn: async (value: DetectionCreationDraft) => {
    const result = await api.validateDetectionCreation(jobId, { proposal_digest: proposal.proposal_digest, title: value.title, source: value.source });
    if (result.proposal_digest !== proposal.proposal_digest || !creationDigest(result.reviewed_digest) || result.title !== value.title || result.source !== value.source || result.validation?.valid !== true || result.validation.target_language !== proposal.selected.target_language) throw new Error("The source check does not match your edits. Check the current source again.");
    return result;
  }, onSuccess: (value, submitted) => { if (sameJson(submitted, currentDraft.current)) { setValidation(value); setLocalError(undefined); } } });
  const review = useMutation({ mutationFn: async (body: DetectionCreationDecision) => {
    const result = checkedCreationEnvelope(await api.reviewDetectionCreation(jobId, body), jobId);
    if (!sameJson(result.decision, body)) throw new Error("The saved decision could not be confirmed. Keep this decision and retry it unchanged.");
    return result;
  }, onSuccess: cache, onSettled: () => { lock.current = false; } });
  const submitDecision = async (choice: "accept" | "reject") => {
    if (!draft || decision || lock.current || !envelope.review_ready || !reviewer.trim() || localError || lookupError) return;
    lock.current = true;
    try {
      let body: DetectionCreationDecision;
      if (choice === "accept") {
        const checked = validation && validation.title === draft.title && validation.source === draft.source ? validation : await validate.mutateAsync(draft);
        if (!sameJson(draft, currentDraft.current)) throw new Error("The source changed during validation. Review the current text before saving.");
        body = { decision: "accept", proposal_digest: proposal.proposal_digest, reviewed_digest: checked.reviewed_digest, title: draft.title, source: draft.source, reviewed_by: reviewer.trim() };
      } else body = { decision: "reject", proposal_digest: proposal.proposal_digest, reviewed_by: reviewer.trim() };
      if (!persist({ ...draft, decision: body })) return;
      await review.mutateAsync(body);
    } catch (error) { setLocalError(error instanceof Error ? error : new Error("The decision could not be saved.")); }
    finally { lock.current = false; }
  };
  const busy = validate.isPending || review.isPending;
  const visibleDraft = decision?.decision === "accept" ? decision : draft;
  const edited = visibleDraft && (visibleDraft.source !== proposal.source || visibleDraft.title !== proposal.title);
  const differentDecision = Boolean(envelope.decision && draft?.decision && !sameJson(envelope.decision, draft.decision));
  const differentLocalDraft = decision?.decision === "accept" && draft && (decision.title !== draft.title || decision.source !== draft.source);
  const application = envelope.application;
  const stopped = envelope.job.progress.stopped === true;
  if (!draft) return <ErrorState title="Retained draft unavailable" error={initial.error} />;
  return <>
    <p>{sentence(proposal.selected.target_language)} · {sentence(proposal.selected.case_role)} development case · {edited ? "Includes your edits" : "Generated source"}</p>
    <p>{proposal.reason}</p>
    {!decision && !envelope.review_ready ? <Callout title={stopped ? "Operation stopped" : "This draft is not ready to save"}>{stopped ? "Your draft is retained. Stopping prevents it from creating a rule." : "Open Assistant to check the saved operation and its recovery options before reviewing this source."}</Callout> : stopped && !application ? <Callout title="Operation stopped">The decision is retained, but this operation cannot start further work. Open Assistant to inspect the final status.</Callout> : null}
    {application ? <>
      {envelope.evaluation ? <div className="creation-evaluation"><EvaluationReport report={envelope.evaluation} /></div> : <Callout title="Evaluation record unavailable">The save receipt is retained. Refresh this review to retrieve the actual evaluation before judging its result.</Callout>}
      <Link className="button button-primary button-medium" to={`/detection-lab?${new URLSearchParams({ run: application.run_id, candidate: application.candidate_id, candidate_scope: "registry" })}`}>Open saved rule</Link>
    </> : null}
    <div className="creation-source-editor">
      <Field label="Rule title"><input maxLength={200} value={visibleDraft!.title} readOnly={Boolean(decision)} disabled={busy} onChange={(event) => { setValidation(undefined); validate.reset(); review.reset(); persist({ ...draft, title: event.target.value }); }} /></Field>
      <Field label="Rule source" hint={decision ? "This is the source retained with the review decision." : "Review the exact query that will be saved and evaluated. Editing clears the previous source check."}><textarea spellCheck={false} rows={14} value={visibleDraft!.source} readOnly={Boolean(decision)} disabled={busy} onChange={(event) => { setValidation(undefined); validate.reset(); review.reset(); persist({ ...draft, source: event.target.value }); }} /></Field>
      {validation && !decision ? <p role="status">Source validated · {sentence(validation.validation.target_language)}. It has not been saved or evaluated.</p> : null}
    </div>
    {differentDecision ? <Callout title="A different decision is already saved">The server's retained decision is shown. Your earlier local text remains in browser storage; it will not be submitted over the saved decision.</Callout> : null}
    {differentLocalDraft ? <details><summary>Your earlier local draft</summary><p>This text remains separate from the accepted source shown above.</p><h3>{draft.title}</h3><pre>{draft.source}</pre></details> : null}
    <details><summary>Generated source and evidence references</summary><h3>Original generated source</h3><pre>{proposal.source}</pre><p>Referenced observations from <Link to={`/runs/${encodeURIComponent(proposal.selected.run_id)}`}>the source run</Link>:</p><ul>{proposal.evidence_refs.map((ref) => <li key={ref}><code>{ref}</code></li>)}</ul><p>Provider information</p><pre>{JSON.stringify(proposal.provider, null, 2)}</pre>{proposal.limitations.map((item, index) => <p key={index}>{item}</p>)}</details>
    {!decision ? <div className="creation-review-actions"><Field label="Reviewed by"><input autoComplete="off" maxLength={200} value={reviewer} onChange={(event) => setReviewer(event.target.value)} disabled={busy} /></Field><p>Saving creates one rule and evaluates this development run. It does not deploy a detection or establish independent coverage.</p><div className="candidate-actions"><Button variant="primary" disabled={!validCreationText(draft.title, draft.source) || !reviewer.trim() || busy || Boolean(localError) || lookupError || !envelope.review_ready} onClick={() => { void submitDecision("accept"); }}>{busy ? "Checking and saving source…" : "Save and evaluate this rule"}</Button><Button disabled={!validCreationText(draft.title, draft.source) || busy || !envelope.review_ready || lookupError} onClick={() => validate.mutate(draft)}>Check source</Button><Button disabled={!reviewer.trim() || busy || !envelope.review_ready || Boolean(localError) || lookupError} onClick={() => { void submitDecision("reject"); }}>Reject draft</Button></div></div> : decision.decision === "reject" ? <p role="status">{envelope.decision ? "Draft rejected. No rule was saved." : "Rejection awaits confirmation."}</p> : !application ? <p role="status">{envelope.application_job ? `Save and evaluation: ${sentence(envelope.application_job.state)}` : "Your acceptance is retained. Checking its save operation…"}</p> : null}
    {decision && !application && !stopped && (!envelope.decision || (decision.decision === "accept" && !creationWorkActive(envelope.application_job))) ? <Button disabled={busy || refreshing || lookupError} onClick={() => {
      if (lock.current) return;
      // A failed initial write leaves the visible draft intact, but it never
      // authorizes a recovery POST. A server-retained decision is already durable.
      if (!envelope.decision && !persist({ ...draft, decision })) return;
      lock.current = true; setLocalError(undefined); review.mutate(decision);
    }}>Recover saved decision</Button> : null}
    {envelope.application_job?.error ? <ErrorState title="Save and evaluation needs attention" error={new Error(envelope.application_job.error.message ?? "Recover the saved decision or open Assistant for the retained operation.")} /> : null}
    {localError || validate.error || review.error ? <ErrorState title="Rule review needs attention" error={localError ?? validate.error ?? review.error} /> : null}
  </>;
}
