import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as Dialog from "@radix-ui/react-dialog";
import { ArrowLeft, ArrowRight, Check, X } from "lucide-react";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../lib/api";
import { checkedGraphEnvelope, graphDocument, matchesGraphEditSource, readGraphReviewDraft, storeGraphReviewDraft, validGraphJob, type GraphDecision, type GraphEditorDraft, type GraphEnvelope, type GraphProposal } from "../lib/graph-assistance";
import { sameJson } from "../lib/replay-review";
import { useProduct } from "../state/ProductContext";
import type { Behavior, Scenario } from "../types";
import { Button, ErrorState, LoadingState, PageHeader, sentence } from "./Primitives";
import "./GraphProposalReview.css";

type Props = { jobId: string; behaviors: Behavior[]; renderEditor: (draft: GraphEditorDraft) => ReactNode };
export function GraphProposalReview(props: Props) {
  const query = useQuery({ queryKey: ["graph-proposal", props.jobId], queryFn: async () => checkedGraphEnvelope(await api.graphProposal(props.jobId), props.jobId),
    enabled: validGraphJob(props.jobId), retry: false, refetchInterval: (state) => state.state.data && !["completed", "failed", "interrupted", "cancelled"].includes(state.state.data.job.state) && !state.state.error ? 1500 : false });
  const heading = useRef<HTMLDivElement>(null);
  useEffect(() => { heading.current?.focus({ preventScroll: true }); }, [props.jobId]);
  if (!validGraphJob(props.jobId)) return <div className="page"><ErrorState error={new Error("This graph proposal link is invalid. Open the retained operation in Assistant.")} /><Link to="/builder">Return to your experiment</Link></div>;
  if (query.data?.proposal) return <GraphReviewEditor key={query.data.proposal.proposal_digest} {...props} envelope={query.data} proposal={query.data.proposal} unavailable={query.isError} />;
  return <div className="page graph-review-waiting" ref={heading} tabIndex={-1}>
    <PageHeader eyebrow="Builder" title="Preparing your experiment" description="This proposal is retained with the Assistant operation. You can return to the current experiment while it is prepared." />
    {query.isPending ? <LoadingState label="Opening saved graph work" /> : null}
    {query.isError ? <ErrorState error={query.error} retry={() => { void query.refetch(); }} /> : null}
    {query.data ? <p role="status">{["failed", "interrupted", "cancelled"].includes(query.data.job.state) ? "Proposal work stopped. Open Assistant to inspect the operation and its next step." : "Checking registered steps and preparing a graph for review…"}</p> : null}
    <Link className="button button-secondary button-medium" to="/builder"><ArrowLeft />Return to your experiment</Link>
  </div>;
}

function GraphReviewEditor({ jobId, proposal, envelope, unavailable, behaviors, renderEditor }: Props & { proposal: GraphProposal; envelope: GraphEnvelope; unavailable: boolean }) {
  const client = useQueryClient();
  const product = useProduct();
  const latestProduct = useRef(product); latestProduct.current = product;
  const navigate = useNavigate();
  const sourceChanged = Boolean(proposal.edit_source && !matchesGraphEditSource(product.scenario, proposal.edit_source.scenario));
  const requireCurrentSource = () => {
    if (proposal.edit_source && !matchesGraphEditSource(latestProduct.current.scenario, proposal.edit_source.scenario)) throw new Error("Your working graph changed after this proposal was prepared. Return to the current experiment and request a new step edit. This proposal cannot replace newer work.");
  };

  const live = useRef(true);
  useEffect(() => { live.current = true; return () => { live.current = false; }; }, []);
  const [retained] = useState(() => readGraphReviewDraft(jobId, proposal));
  const [scenario, setDraft] = useState<Scenario>(() => structuredClone(retained?.scenario ?? proposal.scenario));
  const [decision, setDecision] = useState<GraphDecision | undefined>(retained?.decision);
  const [localError, setLocalError] = useState<Error>();
  const [opened, setOpened] = useState(false);
  const locked = useRef(false);
  const title = useRef<HTMLHeadingElement>(null);
  useEffect(() => { title.current?.focus({ preventScroll: true }); }, []);
  const application = envelope.application;
  const savedVersion = useQuery({ queryKey: ["graph-saved-version", application?.scenario_id, application?.version, application?.digest],
    enabled: Boolean(application), retry: false, queryFn: async () => {
      const { scenario: saved } = await api.immutableScenarioVersion(application!.scenario_id, application!.version);
      if (saved.scenario_id !== application!.scenario_id || saved.version !== application!.version || saved.digest !== application!.digest || saved.document.id !== application!.scenario_id) throw new Error("The saved version does not match this review. Your active experiment is unchanged.");
      return saved;
    } });
  const rejected = envelope.job.progress?.decision && (envelope.job.progress.decision as GraphDecision).decision === "reject";
  const stopped = envelope.job.progress?.stopped === true || ["failed", "cancelled", "cancelling"].includes(envelope.job.state)
    || (envelope.job.state === "interrupted" && !envelope.review_ready);
  const displayed = application && savedVersion.data ? savedVersion.data.document : scenario;
  const changed = !sameJson(graphDocument(displayed), graphDocument(proposal.scenario));
  const updateDraft = (next: Scenario) => {
    if (locked.current || decision || application || rejected || stopped || unavailable || !envelope.review_ready) return;
    if (!storeGraphReviewDraft(jobId, { proposal_digest: proposal.proposal_digest, scenario: next })) { setLocalError(new Error("These edits could not be retained for reload. Check browser session storage before continuing.")); return; }
    setDraft(next); setLocalError(undefined);
  };
  const apply = useMutation({ mutationFn: async (intent: "accept" | "reject" | "retry") => {
    if (locked.current) throw new Error("The previous review is still being checked.");
    locked.current = true;
    try {
      let body = decision;
      if (!body) {
        if (intent === "retry") throw new Error("There is no retained save decision to retry.");
        if (intent === "reject") body = { decision: "reject", proposal_digest: proposal.proposal_digest };
        else {
          requireCurrentSource();
          const submitted = graphDocument(structuredClone(scenario));
          const validation = await api.validateGraphProposal(jobId, { proposal_digest: proposal.proposal_digest, scenario: submitted });
          if (validation.proposal_digest !== proposal.proposal_digest || validation.validation?.valid !== true || !/^sha256:[0-9a-f]{64}$/.test(validation.reviewed_digest)
            || !sameJson(validation.scenario, submitted)) throw new Error("Validation returned a different graph. Your edits remain available; no save was requested.");
          requireCurrentSource();
          body = { decision: "accept", proposal_digest: proposal.proposal_digest, reviewed_digest: validation.reviewed_digest, scenario: submitted };
        }
        if (!storeGraphReviewDraft(jobId, { proposal_digest: proposal.proposal_digest, scenario, decision: body })) throw new Error("The save decision could not be retained. Enable browser session storage before saving.");
        setDecision(body);
      }
      const result = checkedGraphEnvelope(await api.reviewGraphProposal(jobId, body), jobId);
      if (!sameJson(result.job.progress?.decision, body) || (body.decision === "accept" && (!result.application || result.application.reviewed_digest !== body.reviewed_digest))) throw new Error("The save response did not match your review. The exact decision is retained so it can be checked safely.");
      return result;
    } finally { locked.current = false; }
  }, onSuccess: (result) => {
    client.setQueryData(["graph-proposal", jobId], result);
    void client.invalidateQueries({ queryKey: ["assistance-turn"] });
    void client.invalidateQueries({ queryKey: ["scenario-versions"] });
  } });
  const openSaved = useMutation({ mutationFn: async () => {
    if (!application) throw new Error("Save the reviewed experiment first.");
    requireCurrentSource();
    const { scenario: saved } = await api.immutableScenarioVersion(application.scenario_id, application.version);
    if (!live.current) return false;
    if (saved.scenario_id !== application.scenario_id || saved.version !== application.version || saved.digest !== application.digest || saved.document.id !== application.scenario_id) throw new Error("The saved version does not match this review. Your active experiment is unchanged.");
    // Check current manual work after the request, including changes made while it was in flight.
    requireCurrentSource();
    const current = latestProduct.current;
    if (!proposal.edit_source && current.dirty && !window.confirm("Open the saved experiment and replace your current unsaved graph? Export or save your current graph first if you want to keep those edits.")) return false;
    current.setScenario(structuredClone(saved.document), false);
    return true;
  }, onSuccess: (didOpen) => { if (didOpen && live.current) { setOpened(true); navigate("/builder"); } } });
  const disabled = apply.isPending || Boolean(decision) || Boolean(application) || Boolean(rejected) || stopped || unavailable || !envelope.review_ready;
  const names = new Map(behaviors.map((item) => [item.id, item.title]));
  const changes = graphChanges(proposal.scenario, displayed, names);
  const controls = application ? <Button variant="primary" disabled={openSaved.isPending || opened || sourceChanged} onClick={() => openSaved.mutate()}>Open saved experiment<ArrowRight /></Button>
    : rejected || stopped ? <Link className="button button-secondary button-medium" to="/builder">Return to your experiment</Link>
    : decision ? <Button variant="primary" disabled={apply.isPending || unavailable} onClick={() => apply.mutate("retry")}>{apply.isPending ? "Checking saved decision…" : "Retry saved decision"}</Button>
    : <Button variant="primary" disabled={disabled || sourceChanged} onClick={() => apply.mutate("accept")}><Check />{apply.isPending ? "Validating and saving…" : "Save experiment"}</Button>;
  const details = <section className="graph-proposal-review" aria-label="Graph proposal review">
    <div className="graph-review-heading"><div><h2 ref={title} tabIndex={-1}>{application ? "Experiment saved" : rejected ? "Proposal declined" : stopped ? "Proposal stopped" : `Proposed by ${proposal.provider.model}`}</h2>{application ? <p>Version {application.version} is saved. <Link to={`/runs?graph_job=${encodeURIComponent(jobId)}`}>Run with Assistant</Link>, or open it in your workspace. No execution has started.</p> : null}</div><Link to="/builder"><ArrowLeft />Current experiment</Link></div>
    {sourceChanged ? <p role="alert">Your working graph changed after preparation. This proposal cannot replace newer work. Return to the current experiment and request a new step edit.</p> : null}
    {proposal.edit_source ? <SelectedStepChanges proposal={proposal} displayed={displayed} /> : null}
    {unavailable ? <ErrorState title="Saved proposal status is unavailable" error={new Error("Reconnect and check the proposal before saving.")} retry={() => { void client.invalidateQueries({ queryKey: ["graph-proposal", jobId] }); }} /> : null}
    <Dialog.Root><Dialog.Trigger asChild><button className="graph-plan-review">Plan, assumptions, and your changes{changed ? ` · ${changes.length} change${changes.length === 1 ? "" : "s"}` : ""}</button></Dialog.Trigger>
      <Dialog.Portal><Dialog.Overlay className="dialog-overlay" /><Dialog.Content className="dialog-content graph-plan-dialog"><Dialog.Title>Review plan and changes</Dialog.Title><Dialog.Description>Compare your edits with the retained proposal before saving.</Dialog.Description><Dialog.Close asChild><button className="dialog-close" aria-label="Close plan review"><X /></button></Dialog.Close><p>{proposal.rationale}</p><p>{proposal.scenario.steps.length} proposed steps · {proposal.scenario.edges.length} routes · {proposal.provider.model}</p>
      {proposal.assumptions.length ? <ul>{proposal.assumptions.map((item, index) => <li key={index}>{item}</li>)}</ul> : null}
      {changes.length ? <ul aria-label="Changes from proposal">{changes.map((item, index) => <li key={index}>{item}</li>)}</ul> : <p>No changes to the proposed steps or content.</p>}
      {proposal.limitations.map((item, index) => <p key={index}>{item}</p>)}
      <details><summary>Technical record</summary><p>Provider: {proposal.provider.effective_provider_id} · No fallback</p><code>{jobId}</code><p>{proposal.proposal_digest}</p></details>
      {!application && !rejected && !stopped && !decision ? <button className="graph-decline" disabled={disabled} onClick={() => apply.mutate("reject")}>Decline proposal</button> : null}
      </Dialog.Content></Dialog.Portal></Dialog.Root>
    {decision && !application && !rejected ? <p role="status">Your exact decision is retained. Further edits are paused until the saved outcome is known.</p> : null}
    {!envelope.review_ready && !application && !rejected && !stopped && !decision ? <p role="status">The proposal is still being finalized. Review becomes available when the saved work is ready.</p> : null}
    {localError || apply.error || openSaved.error ? <ErrorState title="Graph review needs attention" error={localError ?? apply.error ?? openSaved.error} /> : null}
  </section>;
  if (application && !savedVersion.data) return <div className="page">{details}{savedVersion.isError ? <ErrorState error={savedVersion.error} retry={() => { void savedVersion.refetch(); }} /> : <LoadingState label="Opening the exact saved experiment" />}</div>;
  return renderEditor({ scenario: displayed, setScenario: updateDraft, dirty: changed, controls, details, readOnly: disabled,
    validated: Boolean(application) || !changed,
    statusLabel: application ? `Saved · v${application.version}` : rejected ? "Declined" : stopped ? "Stopped" : decision ? "Decision retained" : changed ? "Edited proposal" : "Proposal" });
}

function graphChanges(before: Scenario, after: Scenario, names: Map<string, string>): string[] {
  const changes: string[] = [];
  if (before.title !== after.title) changes.push(`Name: “${before.title}” → “${after.title}”`);
  if (before.purpose !== after.purpose) changes.push("Experiment objective edited.");
  for (const step of after.steps) {
    const original = before.steps.find((item) => item.id === step.id);
    const title = names.get(step.behavior_id) ?? step.behavior_id;
    if (!original) changes.push(`Added ${title}.`);
    else {
      if (original.behavior_id !== step.behavior_id) changes.push(`Changed ${names.get(original.behavior_id) ?? original.behavior_id} to ${title}.`);
      if (!sameJson(original.parameters, step.parameters)) changes.push(`Updated parameters for ${title}.`);
      if (!sameJson(original.inputs, step.inputs)) changes.push(`Changed required inputs for ${title}.`);
      if (!sameJson(original.alternates, step.alternates)) changes.push(`Changed alternate methods for ${title}.`);
    }
  }
  for (const step of before.steps) if (!after.steps.some((item) => item.id === step.id)) changes.push(`Removed ${names.get(step.behavior_id) ?? step.behavior_id}.`);
  if (before.start !== after.start) changes.push("Changed the starting step.");
  if (!sameJson(before.edges, after.edges)) changes.push(`Changed routes: ${before.edges.length} before, ${after.edges.length} now. Inspect all branches in the editor.`);
  return changes;
}

function SelectedStepChanges({ proposal, displayed }: { proposal: GraphProposal; displayed: Scenario }) {
  const source = proposal.edit_source!;
  const before = source.scenario.steps.find(step => step.id === source.step_id)!.parameters;
  const after = displayed.steps.find(step => step.id === source.step_id)?.parameters ?? {};
  const names = [...new Set([...Object.keys(before), ...Object.keys(after)])].filter(name => !sameJson(before[name], after[name]));
  return <section className="graph-step-changes" aria-label="Selected step changes"><h3>Review selected step parameters</h3>
    <p>Purpose: {source.scenario.purpose}</p><p>{source.dirty ? "Unsaved working graph" : "Current working graph"} · {source.scenario.title}. Only this step’s parameters may change; all other graph content remains fixed. Saving creates a separate experiment and does not run it.</p>
    {names.length ? <table><thead><tr><th>Parameter</th><th>Before</th><th>Proposed</th></tr></thead><tbody>{names.map(name => <tr key={name}><th>{sentence(name)}</th><td>{JSON.stringify(before[name]) ?? "Not set"}</td><td>{JSON.stringify(after[name]) ?? "Not set"}</td></tr>)}</tbody></table> : <p>No parameter values changed.</p>}
    <p>{proposal.rationale}</p><details><summary>Model data boundary and limitations</summary><p>The model received the reviewed objective, selected step and parameter schema. The complete source graph stayed in this product.</p>{proposal.limitations.map((item, index) => <p key={index}>{item}</p>)}</details>
  </section>;
}
