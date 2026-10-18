import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { ArrowRight, ClipboardCheck, FileSearch, History, Plus, RefreshCw, Square, Undo2, X } from "lucide-react";
import { Badge, Button, Callout, DataList, ErrorState, Field, LoadingState, PageHeader, formatDate, sentence } from "../components/Primitives";
import { ObjectiveContext } from "../components/ObjectiveContext";
import { adConfirmed, adJobId, adJobValid, adPhaseCurrent, adPhaseLabels, adReadinessLabels, adSmbApi, checkedAdEnvironments, checkedAdList, checkedAdReview, checkedAdWorkflow, clearAdPending, readAdPending, storeAdPending, type AdBudget, type AdChange, type AdEnvironment, type AdOperation, type AdPending, type AdPhase, type AdReview, type AdWorkflow } from "../lib/ad-smb";
import "./AdSmb.css";

export function AdSmbPage() {
  const client = useQueryClient();
  const [params, setParams] = useSearchParams();
  const adSmbPath = (values: Record<string, string>, remove: string[] = []) => {
    const next = new URLSearchParams(params);
    remove.forEach(key => next.delete(key));
    Object.entries(values).forEach(([key, value]) => next.set(key, value));
    const query = next.toString();
    return "/ad-smb" + (query ? "?" + query : "");
  };
  const [restored] = useState(() => { try { return { pending: readAdPending(), error: undefined }; } catch (error) { return { pending: undefined, error }; } });
  const [pending, setPending] = useState(restored.pending);
  const [localError, setLocalError] = useState<unknown>(restored.error);
  const [review, setReview] = useState<AdReview>();
  const [now, setNow] = useState(Date.now());
  const locked = useRef(false);
  const pendingOwner = pending ? pending.kind === "create" ? pending.id : pending.workflow : "";
  const owner = params.get("workflow") ?? pendingOwner;
  const environments = useQuery({ queryKey: ["ad-smb-environments"], queryFn: async () => checkedAdEnvironments(await adSmbApi.environments()), retry: false });
  const saved = useQuery({ queryKey: ["ad-smb-workflows"], queryFn: async () => checkedAdList(await adSmbApi.list()), retry: false });
  const workflow = useQuery({ queryKey: ["ad-smb-workflow", owner], queryFn: async () => checkedAdWorkflow(await adSmbApi.workflow(owner), owner), enabled: adJobValid(owner), retry: false, refetchInterval: query => query.state.data?.pending ? 1500 : false });
  const value = workflow.error ? undefined : workflow.data;
  useEffect(() => { const timer = window.setInterval(() => setNow(Date.now()), 1000); return () => window.clearInterval(timer); }, []);
  const cancelReads = async () => { await Promise.all([client.cancelQueries({ queryKey: ["ad-smb-workflow"] }), client.cancelQueries({ queryKey: ["ad-smb-workflows"] })]); };
  const refresh = async () => {
    await cancelReads();
    await Promise.all([client.invalidateQueries({ queryKey: ["ad-smb-workflow"] }), client.invalidateQueries({ queryKey: ["ad-smb-workflows"] }), client.invalidateQueries({ queryKey: ["ad-smb-environments"] })]);
  };
  const confirm = (submitted: AdPending) => { clearAdPending(submitted); setPending(undefined); setLocalError(undefined); };
  const write = useMutation({ mutationFn: async (submitted: AdPending) => {
    storeAdPending(submitted);
    await cancelReads();
    if (submitted.kind === "create") {
      const response = await adSmbApi.create(submitted.body);
      checkedAdWorkflow(response, submitted.id);
      if (!adConfirmed((response as { workflow: unknown }).workflow, submitted)) throw new Error("The saved AD exercise did not confirm the original request.");
      return;
    }
    if (!adConfirmed(await adSmbApi.submit(submitted.workflow, submitted.body), submitted)) throw new Error("The saved AD operation did not confirm the exact reviewed request.");
  }, onSuccess: async (_, submitted) => { confirm(submitted); await refresh(); }, onSettled: () => { locked.current = false; } });
  const checkPending = useMutation({ mutationFn: async () => {
    if (!pending) return;
    if (!adConfirmed(await adSmbApi.job(pending.id), pending)) throw new Error("The original request remains unconfirmed. No replacement work was sent.");
    confirm(pending);
    await refresh();
  } });
  const loadReview = useMutation({ mutationFn: async ({ selected, phase }: { selected: AdWorkflow; phase: AdPhase }) => checkedAdReview(await adSmbApi.review(selected.id, phase), selected, phase), onSuccess: setReview });
  const control = useMutation({ mutationFn: async ({ id, operation }: { id: string; operation: "stop" | "recover" }) => {
    await cancelReads();
    const response = await adSmbApi[operation](id);
    checkedAdWorkflow(response, id);
    return response;
  }, onSuccess: async () => { setReview(undefined); await refresh(); } });
  const selectedEnvironment = value && !environments.error ? environments.data?.environments.find(entry => entry.environment.id === value.environment.id) : undefined;
  const ready = Boolean(selectedEnvironment?.available && value?.integration !== "unavailable");
  const busy = write.isPending || checkPending.isPending || control.isPending || loadReview.isPending;
  const canReview = Boolean(value && ready && !value.pending && !pending && !localError && !busy && !workflow.isFetching && !environments.isFetching);
  const shownReview = review?.workflow === value?.id && review?.revision === value?.revision ? review : undefined;
  const send = (submitted: AdPending) => {
    if (locked.current || pending || localError) return;
    try {
      storeAdPending(submitted); locked.current = true; setPending(submitted); setReview(undefined);
      setParams((current) => { const next = new URLSearchParams(current); next.set("workflow", submitted.kind === "create" ? submitted.id : submitted.workflow); return next; });
      write.mutate(submitted);
    } catch (error) { locked.current = false; setLocalError(error); }
  };
  const start = (environment: AdEnvironment) => { const submission = crypto.randomUUID(); send({ kind: "create", id: adJobId(submission), body: { submission_id: submission, environment_id: environment.id } }); };
  const submit = (current: AdReview, reviewedBy: string) => {
    if (!value || !canReview || current.workflow !== value.id || current.revision !== value.revision || !value.allowed.includes(current.phase) || !adPhaseCurrent(value, current.phase)) return;
    const submission = crypto.randomUUID();
    send({ kind: "submit", id: adJobId(submission), workflow: value.id, body: { submission_id: submission, phase: current.phase, review_digest: current.digest, reviewed_by: reviewedBy } });
  };
  return <div className="page ad-smb-page">
    <PageHeader title="AD share access" actions={<Button disabled={busy || environments.isFetching || workflow.isFetching} onClick={() => { void refresh(); }}><RefreshCw />Refresh state</Button>} />
    <ObjectiveContext expected="ad-access" />
    {localError ? <ErrorState title="Retained request needs attention" error={localError} /> : null}
    {pending ? <Callout tone="warning" title={write.isPending ? "Saving reviewed request" : "Original request not yet confirmed"}>
      <p>No replacement operation will be sent on reload.</p>
      <div className="ad-smb-actions"><Button disabled={write.isPending || checkPending.isPending} onClick={() => checkPending.mutate()}><RefreshCw />Check saved request</Button>
        {!write.isPending ? <Button disabled={locked.current || checkPending.isPending || Boolean(localError)} onClick={() => { if (!locked.current) { locked.current = true; write.mutate(pending); } }}><History />Resubmit original request</Button> : null}
        {owner !== pendingOwner ? <Link to={adSmbPath({ workflow: pendingOwner })}>Open original exercise</Link> : null}
      </div>
    </Callout> : null}
    {[write.error, checkPending.error, loadReview.error, control.error].filter(Boolean).map((error, index) => <ErrorState key={index} error={error} />)}
    <div className="ad-smb-layout">
      <aside className="ad-smb-saved" aria-label="Saved AD exercises"><div className="ad-smb-section-heading"><h2>Saved exercises</h2><Link to={adSmbPath({}, ["workflow"])} aria-label="Environment selection"><Plus size={18} /></Link></div>
        {saved.isPending ? <LoadingState label="Opening saved AD exercises" /> : saved.error ? <ErrorState error={saved.error} /> : <ul>{saved.data?.map(entry => <li key={entry.id}><Link aria-current={owner === entry.id ? "page" : undefined} to={adSmbPath({ workflow: entry.id })}><strong>{entry.environment.member}</strong><span>{entry.stopped ? "New work stopped" : sentence(entry.policy)} / revision {entry.revision}</span><small>{entry.environment.provenance === "synthetic_fixture" ? "Synthetic fixture" : "Runner-reported evidence"}</small></Link></li>)}</ul>}
        {saved.data?.length === 0 ? <p>No saved exercises.</p> : null}
      </aside>
      <div className="ad-smb-workspace">
        {!owner ? <section className="ad-smb-section" aria-label="AD environment readiness"><h2>Prepared environments</h2>
          {environments.isPending ? <LoadingState label="Checking AD enrollment" /> : environments.error ? <ErrorState error={environments.error} /> : <>
            {!environments.data?.nativeAvailable ? <Callout tone="warning" title="Live AD execution unavailable">No valid current member and client enrollment is available for live execution.</Callout> : null}
            {environments.data?.environments.length === 0 ? <DataList items={[{ label: "Controller enrollment", value: "Unavailable" }, { label: "Member and client channels", value: "Not checked" }, { label: "Share access", value: "Not tested" }]} /> : null}
            {environments.data?.environments.map(entry => {
              const current = Date.parse(entry.environment.createdAt) <= now && now < Date.parse(entry.environment.expiresAt);
              const ready = entry.available && current;
              const problem = !current ? "scope_not_current" : entry.readiness.problem;
              return <div className="ad-smb-environment" key={entry.environment.id}>
                <div className="ad-smb-section-heading"><h3>{entry.environment.domain}</h3><Badge tone={entry.environment.provenance === "synthetic_fixture" ? "warning" : "neutral"}>{entry.environment.provenance === "synthetic_fixture" ? "Synthetic fixture" : ready ? "Configured channels" : "Unavailable"}</Badge></div>
                <p className="ad-smb-target">{entry.environment.share}</p><EnvironmentFacts environment={entry.environment} />
                <DataList items={[{ label: "Scope window", value: current ? "Current" : Date.parse(entry.environment.createdAt) > now ? "Not started" : "Expired" }, { label: "Member channel", value: entry.readiness.member && current ? "Configuration confirmed" : "Unavailable" }, { label: "Client channel", value: entry.readiness.client && current ? "Configuration confirmed" : "Unavailable" }, { label: "Protected channel binding", value: entry.readiness.channel && current ? "Configuration confirmed" : "Unavailable" }]} />
                {problem ? <Callout tone="warning" title="Enrollment needs attention">{adReadinessLabels[problem]}</Callout> : null}
                <p className="ad-smb-limits">Configuration checks only. Share access, remote reader identity, and credential usability are not established.</p>
                <Button disabled={!ready || busy || environments.isFetching || Boolean(pending) || Boolean(localError)} onClick={() => start(entry.environment)}><Plus />Save exercise</Button>
              </div>;
            })}
          </>}
        </section> : !adJobValid(owner) ? <ErrorState error={new Error("Open an exact saved AD exercise from the list.")} /> : workflow.error ? <ErrorState title="Saved AD exercise unavailable" error={workflow.error} retry={() => { void workflow.refetch(); }} /> : !value ? <LoadingState label="Opening saved AD exercise" /> : <>
          <section className="ad-smb-section ad-smb-objective" aria-label="Selected AD objective"><div className="ad-smb-section-heading"><div><h2>Remove probe access, preserve legitimate reads</h2><p className="ad-smb-target">{value.environment.share}</p></div><Badge tone={value.environment.provenance === "synthetic_fixture" ? "warning" : "neutral"}>{value.environment.provenance === "synthetic_fixture" ? "Synthetic fixture" : "Runner-reported"}</Badge></div>
            <EnvironmentFacts environment={value.environment} />
            <div className="ad-smb-actions">{value.allowed.filter(phase => adPhaseCurrent(value, phase, now)).map(phase => <Button key={phase} disabled={!canReview} onClick={() => loadReview.mutate({ selected: value, phase })}>{phase === "rollback" ? <Undo2 /> : phase === "inspect" || phase === "audit" ? <FileSearch /> : <ClipboardCheck />}Review {adPhaseLabels[phase].toLowerCase()}</Button>)}
              <Button disabled={control.isPending || (value.stopped && !value.pending)} onClick={() => control.mutate({ id: value.id, operation: "stop" })}><Square />{value.pending ? "Stop current operation" : "Stop new work"}</Button>
              {value.pending ? <Button disabled={control.isPending} onClick={() => control.mutate({ id: value.id, operation: "recover" })}><History />Check original results</Button> : null}
            </div>
            {value.stopped ? <Callout title="New work stopped">Retained results remain available. Any offered recovery stage still requires a separate review.</Callout> : null}
            {value.pending ? <Callout tone="warning" title="Original operation unsettled">Cleanup and original results must settle before another stage. Checking original results does not execute replacement work.</Callout> : null}
            {!ready ? <Callout tone="warning" title="Native admission unavailable">Saved evidence is still readable. No current execution readiness is inferred from these records.</Callout> : null}
            <p className="ad-smb-limits">Effective access not established. Local read observations do not authenticate the remote reader or prove a fresh server logon.</p>
          </section>
          {shownReview ? <Review key={`${shownReview.workflow}:${shownReview.revision}:${shownReview.phase}`} value={shownReview} environment={value.environment} disabled={!canReview || !adPhaseCurrent(value, shownReview.phase, now)} onSubmit={submit} onClose={() => setReview(undefined)} /> : null}
          <ReadComparison workflow={value} />
          <section className="ad-smb-section" aria-label="Remaining AD authority"><h2>Remaining authority</h2><Budget value={value.remaining} /><p className="ad-smb-limits">Reserved attempts are not refunded.</p></section>
          <Evidence workflow={value} />
        </>}
      </div>
    </div>
  </div>;
}

function EnvironmentFacts({ environment }: { environment: AdEnvironment }) {
  return <DataList items={[{ label: "Domain", value: environment.domain }, { label: "Member", value: environment.member }, { label: "Client", value: environment.client }, { label: "Scope expires", value: formatDate(environment.expiresAt) }]} />;
}
function Budget({ value }: { value: AdBudget }) { return <dl className="ad-smb-budget">{([["Read attempts", value.business_attempts], ["Sessions", value.sessions], ["Share changes", value.share_changes], ["Restores", value.rollbacks]] as const).map(([label, count]) => <div key={label}><dt>{label}</dt><dd>{count}</dd></div>)}</dl>; }
function role(environment: AdEnvironment, sid: string): string { return Object.entries(environment.principals).find(([, value]) => value === sid)?.[0] ?? "Other trustee"; }
function AclChange({ change, environment, restoring = false }: { change: AdChange; environment: AdEnvironment; restoring?: boolean }) {
  return <div className="ad-smb-acl"><h3>{restoring ? "Restore share permission" : "Exact share permission change"}</h3><div className="ad-smb-table-wrap"><table><thead><tr><th>Principal</th><th>{restoring ? "Current" : "Before"}</th><th>{restoring ? "Restored" : "After"}</th></tr></thead><tbody>{change.before.aces.map(ace => {
    const hardened = change.after.aces.find(after => after.digest === ace.digest)?.right;
    return <tr key={ace.digest}><th>{sentence(role(environment, ace.sid))}</th><td>{restoring ? hardened ?? "No explicit allow" : ace.right}</td><td>{restoring ? ace.right : hardened ?? "Explicit allow removed"}</td></tr>;
  })}</tbody></table></div><p>{restoring ? "The probe's explicit Read entry is restored. Owner, group, and retained entries remain unchanged." : "Only the probe's explicit Read entry is removed. Owner, group, and retained entries remain unchanged in this structural plan."}</p><details><summary>Descriptor references</summary><DataList items={[{ label: restoring ? "Current" : "Before", value: <code>{restoring ? change.afterDigest : change.beforeDigest}</code> }, { label: restoring ? "Restored" : "After", value: <code>{restoring ? change.beforeDigest : change.afterDigest}</code> }, { label: "Probe SID", value: <code>{change.removed.sid}</code> }]} /></details></div>;
}
function Review({ value, environment, disabled, onSubmit, onClose }: { value: AdReview; environment: AdEnvironment; disabled: boolean; onSubmit: (value: AdReview, reviewer: string) => void; onClose: () => void }) {
  const [reviewer, setReviewer] = useState(""); const [consent, setConsent] = useState(false);
  const validReviewer = /^[A-Za-z0-9][A-Za-z0-9_. -]{0,99}$/.test(reviewer);
  return <section className="ad-smb-section ad-smb-review" aria-label="Explicit AD stage review"><div className="ad-smb-section-heading"><h2>{adPhaseLabels[value.phase]}</h2><Button aria-label="Close stage review" onClick={onClose}><X /></Button></div><p>{environment.share}</p>
    <ol className="ad-smb-review-steps">{value.steps.map(step => <li key={step}>{({ inspect_member: "Inspect exact member share and descriptor", read_probe_primary: "Probe: records.jsonl", read_legitimate_primary: "Legitimate reader: records.jsonl", read_legitimate_health: "Legitimate reader: health.jsonl", harden_share: "Remove the reviewed probe Read entry", rollback_share: "Restore the exact reviewed descriptor", collect_audit: "Collect the bounded audit window" } as Record<string, string>)[step]}</li>)}</ol>
    {value.change ? <AclChange change={value.change} environment={environment} restoring={value.phase === "rollback"} /> : null}
    {value.phase === "rollback" ? <Callout tone="warning" title="Restore direction">Restore the Before descriptor only from its exact reviewed hardened postimage.</Callout> : null}
    <h3>Stage reservation</h3><Budget value={value.budget} />
    <Field label="Reviewed by"><input value={reviewer} maxLength={100} autoComplete="off" onChange={event => setReviewer(event.target.value)} /></Field>
    <label className="ad-smb-consent"><input type="checkbox" checked={consent} onChange={event => setConsent(event.target.checked)} /><span>I approve this exact stage and its reserved scope.</span></label>
    <div className="ad-smb-actions"><Button variant="primary" disabled={disabled || !consent || !validReviewer} onClick={() => onSubmit(value, reviewer)}><ArrowRight />Submit reviewed stage</Button></div>
    <details><summary>Review binding</summary><code>{value.digest}</code><p>Revision {value.revision}</p></details>
  </section>;
}
function readText(operation: AdOperation | undefined, reader: string, purpose: string): string {
  const read = operation?.executions.find(execution => execution.read?.reader === reader && execution.read.purpose === purpose)?.read;
  return read ? ({ bytes_matched: "Content matched", open_access_denied: "Open denied", unknown: "Unknown", deadline: "Deadline reached", cancelled: "Cancelled", not_started: "Not started" } as Record<string, string>)[read.state] ?? "Unknown" : "Not observed";
}
function ReadComparison({ workflow }: { workflow: AdWorkflow }) {
  const baseline = workflow.operations.find(row => row.phase === "baseline"), retest = workflow.operations.find(row => row.phase === "retest");
  return <section className="ad-smb-section" aria-label="Baseline and fresh read comparison"><h2>Read outcomes</h2><div className="ad-smb-table-wrap"><table><thead><tr><th>Reader / generated file</th><th>Baseline</th><th>Fresh checks</th></tr></thead><tbody>{([ ["Probe / records.jsonl", "probe", "primary"], ["Legitimate / records.jsonl", "legitimate", "primary"], ["Legitimate / health.jsonl", "legitimate", "health"] ] as const).map(([label, reader, purpose]) => <tr key={label}><th>{label}</th><td>{readText(baseline, reader, purpose)}</td><td>{readText(retest, reader, purpose)}</td></tr>)}</tbody></table></div>
    {retest?.expectation === "not_met" ? <Callout tone="warning" title="Read expectations not met">The observed retest is settled, but probe denial and both legitimate reads did not all match the intended outcome. Review the retained observations and restore option.</Callout> : retest?.expectation === "matched" ? <Callout title="Read expectations matched">Retained observations match the requested read outcomes. Remote identity and effective access remain unproven.</Callout> : baseline?.expectation === "not_met" ? <Callout tone="warning" title="Baseline expectations not met">All three baseline reads must match before hardening is offered.</Callout> : null}
    {retest?.distinctContexts === false || baseline?.distinctContexts === false ? <Callout tone="warning" title="Local contexts reused">Distinct local logon contexts were not established for this read sequence.</Callout> : null}
  </section>;
}
function Evidence({ workflow }: { workflow: AdWorkflow }) {
  const change = workflow.operations.flatMap(row => row.executions).find(row => row.change)?.change;
  const audit = workflow.operations.find(row => row.phase === "audit");
  const auditObservation = audit?.executions.find(row => row.audit)?.audit;
  return <section className="ad-smb-section" aria-label="Retained AD evidence"><h2>Evidence and settlement</h2>
    {change ? <AclChange change={change} environment={workflow.environment} /> : null}
    {auditObservation ? <p>Audit retained: {auditObservation.events} events{auditObservation.truncated ? ", truncated" : ""}. Source authentication and independence are not established.</p> : <p>{audit ? "No audit observation retained." : "Audit not collected."} No independent observation is reported.</p>}
    <ol className="ad-smb-history">{workflow.operations.map(row => <li key={row.id}><div className="ad-smb-section-heading"><h3>{adPhaseLabels[row.phase]}</h3><Badge tone={row.state === "unknown" || row.expectation === "not_met" ? "warning" : "neutral"}>{sentence(row.state)}</Badge></div><DataList items={[{ label: "Cleanup", value: sentence(row.cleanup) }, { label: "Evidence", value: row.executions.every(execution => execution.provenance === "synthetic_fixture") ? "Synthetic fixture" : row.executions.some(execution => execution.provenance === "synthetic_fixture") ? "Mixed synthetic and runner-reported" : "Runner-reported" }]} /><Link to={`/runs/${encodeURIComponent(row.runId)}`}>Open retained run</Link><details><summary>Evidence references</summary><code>{row.digest}</code><ul>{row.executions.filter(execution => execution.read).map((execution, index) => <li key={index}>{execution.read?.reader} / {execution.read?.purpose}: {execution.read?.bytes} returned bytes; local context <code>{execution.read?.localContext ?? "Not recorded"}</code></li>)}</ul></details></li>)}</ol>
    {!workflow.operations.length ? <p>No stage evidence retained.</p> : null}
    <details><summary>Saved workflow reference</summary><code>{workflow.id}</code><p>Revision {workflow.revision}; share state {sentence(workflow.policy)}.</p></details>
  </section>;
}
