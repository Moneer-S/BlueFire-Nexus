import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Check, Cloud, FileSearch, Pause, Play, Plus, RefreshCw, RotateCcw, Settings2, Trash2 } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Badge, Button, Callout, DataList, ErrorState, Field, LoadingState, PageHeader, sentence } from "../components/Primitives";
import { ObjectiveContext } from "../components/ObjectiveContext";
import { useRememberDefensiveWork } from "../state/activeDefensiveWork";
import { clearS3Pending, clearS3Stop, confirmsS3Pending, phaseName, readS3Pending, readS3Stops, s3Api, s3JobId, s3ReviewCurrent, s3StageAvailable, storeS3Pending, storeS3Stop, validS3Job, type S3Exercise, type S3Operation, type S3Pending, type S3Phase, type S3Review } from "../lib/s3-access";
import { auditBudgetKeys, type AuditStageReview, type AuditWorkspace } from "../lib/s3-audit-workspace";
import { writeComparisonContext } from "../lib/comparison-context";
import { resourceNames, S3FixtureReview, S3Fixtures } from "./S3Fixtures";
import { S3Setup } from "./S3Setup";
import { S3Audit } from "./S3Audit";
import "./S3Access.css";

export function S3AccessPage() {
  const [params, setParams] = useSearchParams();
  const owner = params.get("exercise") ?? "";
  const setupOpen = params.get("setup") === "1";
  const showSetup = (open: boolean) => { const next = new URLSearchParams(params); if (open) next.set("setup", "1"); else next.delete("setup"); setParams(next); };
  const client = useQueryClient();
  const [localError, setLocalError] = useState<unknown>();
  const [pending, setPending] = useState<S3Pending | null>(null);
  const [stops, setStops] = useState<string[]>([]);
  const [hydrated, setHydrated] = useState(false);
  const [review, setReview] = useState<S3Review | null>(null);
  const [reviewer, setReviewer] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [recheckNotice, setRecheckNotice] = useState<string | null>(null);
  const lock = useRef(false);
  const ownerRef = useRef(owner);
  ownerRef.current = owner;
  const environment = useQuery({ queryKey: ["s3-environments"], queryFn: s3Api.environments, retry: false });
  const list = useQuery({ queryKey: ["s3-exercises"], queryFn: s3Api.list, retry: false });
  const exercise = useQuery({ queryKey: ["s3-exercise", owner], queryFn: () => s3Api.read(owner), enabled: validS3Job(owner), retry: false, refetchInterval: query => query.state.data?.active_job && !query.state.data.saved_result_recovery_available ? 2000 : false });
  useRememberDefensiveWork("cloud", exercise.isSuccess && exercise.data?.workflow_job_id === owner ? owner : undefined);
  const exerciseParams = (next: string) => {
    const value = new URLSearchParams(params);
    if (next !== owner) {
      value.delete("audit_review");
      value.delete("audit_digest");
    }
    if (next) value.set("exercise", next);
    else value.delete("exercise");
    return value;
  };
  const exerciseHref = (next: string) => {
    const query = exerciseParams(next).toString();
    return query ? `/s3-access?${query}` : "/s3-access";
  };
  const navigate = (next: string) => { setReview(null); setConfirmed(false); setParams(exerciseParams(next)); };
  const save = useMutation({ mutationFn: s3Api.send, onSuccess: value => { client.setQueryData(["s3-exercise", value.workflow_job_id], value); void list.refetch(); setReview(null); }, onSettled: () => { lock.current = false; } });
  const inspect = useMutation({ mutationFn: (phase: S3Phase) => s3Api.review(owner, phase), onSuccess: value => { if (value.workflow_job_id === owner) { setReview(value); setConfirmed(false); setReviewer(""); } } });
  const control = useMutation({ mutationFn: (command: { identifier: string; action: "stop" | "recover"; finalizedRecheck?: boolean }) => s3Api.control(command.identifier, command.action), onMutate: command => { if (command.finalizedRecheck) setRecheckNotice(current => current === command.identifier ? null : current); }, onSuccess: (value, command) => { if (value.workflow_job_id === command.identifier) client.setQueryData(["s3-exercise", value.workflow_job_id], value); if (ownerRef.current === command.identifier) { setReview(null); if (command.finalizedRecheck) setRecheckNotice(finalizedAuditRecheckOperations(value).length > 0 ? command.identifier : null); } void list.refetch(); } });
  useEffect(() => { try { setPending(readS3Pending()); setStops(readS3Stops()); } catch (error) { setLocalError(error); } finally { setHydrated(true); } }, []);
  useEffect(() => {
    if (!pending || !exercise.data || !confirmsS3Pending(exercise.data, pending)) return;
    try { clearS3Pending(pending); setPending(null); } catch (error) { setLocalError(error); }
  }, [pending, exercise.data]);
  useEffect(() => { if (exercise.data?.stopped && !exercise.data.active_job && stops.includes(owner)) { try { clearS3Stop(owner); setStops(readS3Stops()); } catch (error) { setLocalError(error); } } }, [exercise.data?.stopped, exercise.data?.active_job, owner, stops]);
  useEffect(() => { if (review && (review.workflow_job_id !== owner || !exercise.data || !s3ReviewCurrent(exercise.data, review))) { setReview(null); setConfirmed(false); } }, [owner, exercise.data, review]);
  const send = (value: S3Pending) => {
    if (lock.current || localError || !hydrated || stops.includes(value.owner)) return;
    try { storeS3Pending(value); lock.current = true; setPending(value); navigate(value.owner); save.mutate(value); }
    catch (error) { setLocalError(error); }
  };
  const stop = () => { setStops(current => [...new Set([...current, owner])]); setReview(null); try { storeS3Stop(owner); } catch (error) { setLocalError(error); } control.mutate({ identifier: owner, action: "stop" }); };
  const blocked = Boolean(!hydrated || pending || localError || stops.includes(owner) || exercise.error || save.isPending || control.isPending || inspect.isPending);
  const value = exercise.data;
  const finalizedRecheckOperations = finalizedAuditRecheckOperations(value);
  return <div className="page s3-access-page">
    <PageHeader title={value ? value.environment.display_name : "S3 access"} eyebrow="Cloud access review" actions={<><Button disabled={environment.isFetching || exercise.isFetching} onClick={() => { void environment.refetch(); void list.refetch(); if (owner) void exercise.refetch(); }}><RefreshCw />Refresh</Button>{validS3Job(owner) ? <Button variant="danger" disabled={control.isPending || Boolean(value?.stopped && !value.active_job)} onClick={stop}><Pause />{stops.includes(owner) ? "Retry stop" : value?.active_job ? "Stop current operation" : value?.stopped ? "Stopped" : "Stop new work"}</Button> : null}</>} />
    <ObjectiveContext expected="s3-access" />
    {localError ? <ErrorState title="Saved request needs attention" error={localError} /> : null}
    {pending ? <Callout tone="warning" title="Submission confirmation pending"><p>The original request may already be saved. No automatic retry has been sent.</p><div className="s3-actions"><Button disabled={save.isPending} onClick={() => { navigate(pending.owner); void client.invalidateQueries({ queryKey: ["s3-exercise", pending.owner] }); }}><FileSearch />Check saved status</Button><Button disabled={save.isPending || Boolean(localError) || stops.includes(pending.owner)} onClick={() => send(pending)}><RefreshCw />Retry exact submission</Button></div></Callout> : null}
    {save.error ? <ErrorState title="Submission not confirmed" error={save.error} /> : null}
    {stops.includes(owner) ? <Callout tone="warning" title="Stop confirmation pending">New operations remain disabled until the saved stop is confirmed.</Callout> : null}
    {control.error && control.variables?.identifier === owner ? <ErrorState title={control.variables?.finalizedRecheck ? "Original task check failed" : "Control request not confirmed"} error={control.error} /> : null}
    <div className="s3-actions"><Button onClick={() => showSetup(!setupOpen)}><Settings2 />{setupOpen ? "Close connection setup" : "Connection setup"}</Button></div>
    {setupOpen ? <S3Setup onClose={() => showSetup(false)} /> : null}
    {!owner ? <>
      <section className="s3-band" aria-label="Enrolled environments"><h2>Enrolled environments</h2>{environment.isPending ? <LoadingState label="Checking S3 enrollment" /> : environment.error ? <ErrorState error={environment.error} /> : !environment.data?.environments.length ? <Callout tone="warning" title="Unavailable"><p>{environment.data?.problem}</p><Button onClick={() => showSetup(true)}><Settings2 />Set up connection</Button></Callout> : <div className="s3-environments">{environment.data.environments.map(row => <article key={row.environment.environment_id} className="s3-environment"><Cloud aria-hidden="true" /><div><h3>{row.environment.display_name}</h3><p>{row.environment.scope.bucket} · {row.environment.scope.region}</p>{row.problem ? <p>{row.problem}</p> : null}</div><Badge tone={row.available ? "info" : "warning"}>{row.available ? "Ready for review" : "Unavailable"}</Badge><Button disabled={blocked || !row.available} onClick={() => { const submission_id = crypto.randomUUID(); send({ kind: "create", owner: s3JobId(submission_id), request: { submission_id, environment_id: row.environment.environment_id, context_digest: row.context_digest } }); }}><Play />Open exercise</Button></article>)}</div>}</section>
      <section className="s3-band" aria-label="Saved S3 exercises"><h2>Saved exercises</h2>{list.error ? <ErrorState error={list.error} /> : list.isPending ? <LoadingState label="Opening saved work" /> : <div className="s3-saved">{list.data?.exercises.map(row => validS3Job(row.workflow_job_id) ? <Link key={row.workflow_job_id} to={exerciseHref(row.workflow_job_id)}><span><strong>{row.name}</strong><small>{row.bucket}</small></span><Badge>{sentence(row.policy_state)}</Badge></Link> : null)}{!list.data?.exercises.length ? <p>No saved exercises.</p> : null}{list.data?.truncated ? <p>Showing the most recent 100 exercises.</p> : null}</div>}</section>
    </> : <>
      <Link to={exerciseHref("")}><ArrowLeft size={16} />Saved exercises</Link>
      {exercise.error ? <ErrorState title="Saved status unavailable" error={exercise.error} retry={() => { void exercise.refetch(); }} /> : null}
      {!validS3Job(owner) ? <ErrorState error={new Error("This saved exercise link is invalid.")} /> : !value ? exercise.error ? null : <LoadingState label="Opening S3 exercise" /> : <>
        <section className="s3-objective" aria-label="Access objective"><div><h2>Remove unintended read access</h2><p>{value.environment.scope.bucket} · {value.environment.scope.region}</p></div><Badge tone={value.policy_state === "uncertain" || value.policy_state === "drift" ? "warning" : "neutral"}>{sentence(value.policy_state)} policy</Badge></section>
        {value.problem ? <Callout tone="warning" title="Execution unavailable">{value.problem}</Callout> : null}
        {value.active_job ? <Callout tone="warning" title={value.saved_result_recovery_available ? "Interrupted work needs reconciliation" : "Original operation in progress"}><p>{sentence(value.active_job.state)}</p>{value.saved_result_recovery_available ? <Button disabled={control.isPending} onClick={() => control.mutate({ identifier: owner, action: "recover" })}><FileSearch />Recover saved results</Button> : null}</Callout> : null}
        {finalizedRecheckOperations.length ? <Callout tone="warning" title="Collection cleanup unresolved"><Badge tone="warning">Cleanup unresolved</Badge><p>The original result records unresolved cleanup.</p><div className="s3-actions">{finalizedRecheckOperations.flatMap(operation => operation.run_ids.map((id, index) => <Link key={`${operation.operation_job_id}-${id}`} to={`/runs/${id}`}>Original collection run evidence {index + 1}</Link>))}<Button disabled={control.isPending || Boolean(localError)} onClick={() => control.mutate({ identifier: owner, action: "recover", finalizedRecheck: true })}><FileSearch />Check original task</Button></div>{recheckNotice === owner ? <p>Original task checked; cleanup remains unresolved.</p> : null}</Callout> : null}
        <div className="s3-stage-toolbar" aria-label="Available stages">{value.allowed_phases.map(phase => <Button key={phase} disabled={blocked || !s3StageAvailable(value, phase)} onClick={() => { if (s3StageAvailable(value, phase)) inspect.mutate(phase); }}>{phase === "rollback" ? <RotateCcw /> : phase === "cleanup" ? <Trash2 /> : phase === "prepare" ? <Plus /> : <FileSearch />}{phaseName[phase]}</Button>)}</div>
        {inspect.error ? <ErrorState title="Stage review unavailable" error={inspect.error} /> : null}
        <div className="s3-workspace"><div className="s3-evidence-main"><S3Fixtures value={value} /><S3Facts value={value} /><S3AuditCollection value={value} /><S3Audit owner={owner} /><section className="s3-band"><h2>Operation evidence</h2>{value.operations.length ? value.operations.map((row, index) => <article className="s3-operation" key={row.operation_job_id}><div className="s3-operation-heading"><strong>{index + 1}. {phaseName[row.phase]}</strong><Badge tone={row.outcome.state === "uncertain" || row.outcome.cleanup === "unknown" ? "warning" : "neutral"}>{sentence(row.outcome.state)}</Badge><Badge>{row.outcome.provenance === "synthetic" ? "Synthetic" : "Runner reported"}</Badge></div><div className="s3-actions">{row.run_ids.map((id, number) => <Link key={id} to={`/runs/${id}`}>Run evidence {number + 1}</Link>)}<span>Worker cleanup: {sentence(row.outcome.cleanup)}</span></div><details><summary>Technical evidence</summary><pre>{JSON.stringify(row, null, 2)}</pre></details></article>) : <p>No observations recorded.</p>}</section></div><aside className="s3-review-side" aria-label="Review and remaining authority">
          {review ? <section className="s3-band s3-review"><h2>{phaseName[review.phase]}</h2><StageBudget review={review} />{review.audit_collection && value.audit_collection ? <S3AuditStageReview review={review.audit_collection} workspace={value.audit_collection} /> : null}{review.fixture_lifecycle ? <S3FixtureReview value={review.fixture_lifecycle} cleanup={review.phase === "cleanup"} /> : null}{review.policy_change ? <details><summary>Exact policy change</summary><h3>Before</h3><pre>{JSON.stringify(review.policy_change.before, null, 2)}</pre><h3>After</h3><pre>{JSON.stringify(review.policy_change.after, null, 2)}</pre></details> : null}<Field label="Reviewed by"><input value={reviewer} maxLength={100} onChange={event => setReviewer(event.target.value)} /></Field><label className="s3-consent"><input type="checkbox" checked={confirmed} onChange={event => setConfirmed(event.target.checked)} /><span>{review.phase === "cleanup" ? "I approve removing these test objects and retaining the current policy." : "I approve this exact stage and its reserved limits."}</span></label><Button variant="primary" disabled={blocked || !s3ReviewCurrent(value, review) || !reviewer.trim() || !confirmed} onClick={() => { if (!s3ReviewCurrent(value, review)) return; const submission_id = crypto.randomUUID(); send({ kind: "stage", owner, operation: s3JobId(submission_id), request: { submission_id, phase: review.phase, review_digest: review.review_digest, reviewed_by: reviewer.trim() } }); }}><Check />Confirm stage</Button></section> : <section className="s3-band"><h2>Remaining authority</h2><DataList items={Object.entries(value.remaining).map(([key, amount]) => ({ label: sentence(key), value: amount }))} /></section>}
          <section className="s3-band"><h2>Unresolved evidence</h2><DataList items={[{ label: "Independent observations", value: "None collected" }, { label: "Cloud audit", value: value.audit === "authenticated_retrieval" ? "Authenticated source retrieval; integrity unverified" : "Not collected" }, { label: "Generated resources", value: resourceNames[value.resource_disposition] }]} /><p>No live defensive effectiveness has been independently verified.</p><details><summary>Enrolled scope</summary><pre>{JSON.stringify(value.environment.scope, null, 2)}</pre></details></section>
        </aside></div>
      </>}
    </>}
  </div>;
}

function finalizedAuditRecheckOperations(value?: S3Exercise): S3Operation[] {
  if (value?.schema_version !== "bluefire.s3-exercise.v3" || value.active_job || !value.saved_result_recovery_available || !value.audit_collection) return [];
  return value.operations.filter(operation => value.audit_collection!.slots.some(slot => slot.state === "failed"
    && slot.problem === "phase_consumed" && slot.operation_job_id === operation.operation_job_id
    && operation.phase === slot.stage && operation.outcome.cleanup === "unknown"));
}

function S3AuditCollection({ value }: { value: S3Exercise }) {
  const workspace = value.schema_version === "bluefire.s3-exercise.v3" ? value.audit_collection : null;
  if (!workspace) return null;
  return <section className="s3-band" aria-label="Audit collection slots"><h2>Audit collection</h2><div className="s3-audit-results">{workspace.slots.map(slot => <article key={slot.phase} aria-label={`${sentence(slot.phase)} audit slot`}><div className="s3-operation-heading"><h3>{sentence(slot.phase)}</h3><Badge tone={slot.state === "ready" ? "info" : slot.state === "failed" || slot.state === "unavailable" ? "warning" : "neutral"}>{sentence(slot.state)}</Badge></div>{slot.problem ? <p>{sentence(slot.problem)}</p> : null}{slot.original_pair ? <div className="s3-actions">{slot.original_pair.reads.map(read => <Link key={read.run_id} to={`/runs/${read.run_id}`}>{sentence(read.reader)} original read</Link>)}</div> : <p>Original read pair unavailable.</p>}{slot.operation_job_id ? <div className="s3-actions">{value.operations.find(row => row.operation_job_id === slot.operation_job_id)?.run_ids.map(id => <Link key={id} to={`/runs/${id}`}>{sentence(slot.phase)} collection run</Link>)}</div> : null}</article>)}</div><details><summary>Collection allowance</summary><DataList items={Object.entries(workspace.budget.workflow).map(([key, amount]) => ({ label: sentence(key), value: `${workspace.reserved[key]} reserved; ${workspace.held[key]} held / ${amount}` }))} /></details></section>;
}

function S3AuditStageReview({ review, workspace }: { review: AuditStageReview; workspace: AuditWorkspace }) {
  return <div aria-label="Audit collection review"><h3>Audit source</h3><DataList items={[{ label: "Bucket", value: review.source.audit_bucket }, { label: "Bucket region", value: review.source.audit_bucket_region }, { label: "Expected owner", value: review.source.source_account_id }, { label: "Event region", value: review.source.event_region }, { label: "Listing date (UTC)", value: review.listing_date }, { label: "Collection expires", value: review.collection_expires_at }]} /><h3>Original reads</h3>{review.original_pair.reads.map(read => <div key={read.run_id}><Link to={`/runs/${read.run_id}`}>{sentence(read.reader)} original read</Link><p>Original deadline: {String(read.request.deadline)}</p></div>)}<h3>Exact listing scope</h3>{review.list_parameters.map(row => <div key={row.Prefix}><DataList items={[{ label: "Prefix", value: <code className="s3-object-key">{row.Prefix}</code> }, { label: "Start after", value: <code className="s3-object-key">{row.StartAfter}</code> }, { label: "Maximum keys", value: row.MaxKeys }]} /></div>)}<h3>Collection limits</h3><DataList items={auditBudgetKeys.map(key => ({ label: sentence(key), value: workspace.budget.per_batch[key] }))} /><p>Authenticated source retrieval. Integrity and complete delivery remain unverified.</p></div>;
}

function StageBudget({ review }: { review: S3Review }) {
  const followup = Object.entries(review.required_remaining)
    .map(([key, amount]) => ({ key, amount: amount - (review.reserved[key] ?? 0) }))
    .filter(row => row.amount > 0);
  return <>
    <DataList items={Object.entries(review.reserved).map(([key, amount]) => ({ label: sentence(key), value: `${amount} / ${review.remaining[key]} remaining` }))} />
    {followup.length ? <div aria-label="Follow-up allowance"><h3>{review.phase === "apply" ? "Fresh checks and recovery allowance" : "Recovery allowance"}</h3><DataList items={followup.map(row => ({ label: sentence(row.key), value: row.amount }))} /><p>Held within the existing limits, not spent by this stage.</p></div> : null}
  </>;
}

function S3Facts({ value }: { value: S3Exercise }) {
  const baseline = value.operations.filter(row => row.phase === "baseline").at(-1);
  const retest = value.operations.filter(row => row.phase === "retest").at(-1);
  const read = (phase: typeof baseline, reader: string, purpose: string) => phase?.outcome.facts.find(fact => fact.reader === reader && fact.purpose === (purpose === "canary" ? "health" : purpose))?.result;
  const fact = (result: string | undefined) => result ? result === "service_denied" ? "Service denied" : sentence(result) : "Not observed";
  const comparison = baseline?.run_ids[0] && retest?.run_ids[0] ? writeComparisonContext(new URLSearchParams(), { runIds: [...baseline.run_ids, ...retest.run_ids], baselineId: "", revisedId: "" }).toString() : null;
  return <section className="s3-band" aria-label="Access comparison"><h2>Access comparison</h2><div className="s3-facts"><article><h3>Probe reader</h3><dl><div><dt>Baseline</dt><dd>{fact(read(baseline, "probe", "primary"))}</dd></div><div><dt>Fresh retest</dt><dd>{fact(read(retest, "probe", "primary"))}</dd></div></dl></article><article><h3>Legitimate reader</h3><dl><div><dt>Baseline</dt><dd>{fact(read(baseline, "legitimate", "primary"))}</dd></div><div><dt>Fresh retest</dt><dd>{fact(read(retest, "legitimate", "primary"))}</dd></div></dl></article><article><h3>Canary object</h3><dl><div><dt>Baseline</dt><dd>{fact(read(baseline, "legitimate", "canary"))}</dd></div><div><dt>Fresh retest</dt><dd>{fact(read(retest, "legitimate", "canary"))}</dd></div></dl></article></div>{comparison ? <Link to={`/compare?${comparison}`}>Compare saved runs</Link> : null}</section>;
}
