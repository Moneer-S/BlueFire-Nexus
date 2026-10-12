import { useQuery } from "@tanstack/react-query";
import { FileSearch, MessageSquareText, Plus, RefreshCw, Save } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { Badge, Button, Callout, DataList, ErrorState, Field, LoadingState, sentence } from "../components/Primitives";
import { auditDelivery, auditFiles, auditInputDigest, clearAuditPending, readAuditPending, s3AuditApi, saveAuditPending, type AuditDelivery, type AuditPending, type AuditReview } from "../lib/s3-audit";
import { phaseName, s3JobId } from "../lib/s3-access";
import { useAssistancePanel } from "../state/AssistanceContext";

export function S3Audit({ owner }: { owner: string }) { return <AuditWorkspace key={owner} owner={owner} />; }

function AuditWorkspace({ owner }: { owner: string }) {
  const history = useQuery({ queryKey: ["s3-audit", owner], queryFn: () => s3AuditApi.list(owner), retry: false });
  const [run, setRun] = useState("");
  const [delivery, setDelivery] = useState<AuditDelivery>("unknown");
  const [files, setFiles] = useState<File[]>([]);
  const [pending, setPending] = useState<AuditPending | null>(null);
  const [review, setReview] = useState<AuditReview | null>(null);
  const [error, setError] = useState<unknown>();
  const [storageError, setStorageError] = useState<unknown>();
  const [ready, setReady] = useState(false);
  const [busy, setBusy] = useState(false);
  const lock = useRef(false);
  const mounted = useRef(false);
  const fileInput = useRef<HTMLInputElement>(null);
  useEffect(() => {
    mounted.current = true;
    try { const saved = readAuditPending(owner); setPending(saved); if (saved) { setRun(saved.run_id); setDelivery(saved.delivery_state); } }
    catch (reason) { setStorageError(reason); }
    setReady(true);
    return () => { mounted.current = false; };
  }, [owner]);
  const act = async (task: () => Promise<void>) => {
    if (lock.current) return;
    lock.current = true; setBusy(true); setError(undefined);
    try { await task(); } catch (reason) { if (mounted.current) setError(reason); }
    finally { lock.current = false; if (mounted.current) setBusy(false); }
  };
  const accept = (value: AuditReview, original?: AuditPending) => {
    if (!mounted.current) return;
    if (original) {
      if (value.source.run_id !== original.run_id || value.input_digest !== original.input_digest) throw new Error("The saved review does not match the original import.");
      try { clearAuditPending(original); setPending(null); } catch (reason) { setStorageError(reason); }
    }
    setReview(value); setFiles([]); if (fileInput.current) fileInput.current.value = "";
    void history.refetch();
  };
  const save = () => { void act(async () => {
    const original = pending;
    const request = { submission_id: original?.submission_id ?? crypto.randomUUID(), run_id: run, delivery_state: delivery, logs: await auditFiles(files) };
    const digest = await auditInputDigest(request);
    if (!mounted.current) return;
    if (original && digest !== original.input_digest) throw new Error("These files or selections differ from the pending import. The original request was not resent.");
    const marker: AuditPending = { owner, submission_id: request.submission_id, run_id: run, delivery_state: delivery, input_digest: digest };
    saveAuditPending(marker); setPending(marker);
    accept(await s3AuditApi.save(owner, request), marker);
  }); };
  const open = (id: string, original?: AuditPending) => { void act(async () => accept(await s3AuditApi.read(owner, id), original)); };
  const newReview = () => { if (!pending || busy) return; try { clearAuditPending(pending); setPending(null); setReview(null); setFiles([]); if (fileInput.current) fileInput.current.value = ""; setError(undefined); void history.refetch(); } catch (reason) { setStorageError(reason); } };
  const selected = history.data?.reads.find(row => row.run_id === run);
  return <section className="s3-band s3-audit" aria-label="Imported cloud audit">
    <div className="s3-setup-heading"><h2>Imported cloud audit</h2><Button aria-label="Refresh audit reviews" disabled={busy || history.isFetching} onClick={() => { void history.refetch(); }}><RefreshCw /></Button></div>
    <div className="s3-actions"><Badge>Operator supplied</Badge><Badge tone="warning">Collection not independently verified</Badge></div>
    {history.isPending ? <LoadingState label="Opening saved audit reviews" /> : history.error ? <ErrorState title="Audit history unavailable" error={history.error} /> : <>
      <div className="s3-audit-form">
        <Field label="Original read attempt"><select aria-label="Original read attempt" disabled={busy || Boolean(pending)} value={run} onChange={event => setRun(event.target.value)}><option value="">Select saved read</option>{history.data?.reads.map(row => <option key={row.run_id} value={row.run_id}>{phaseName[row.phase]} · {sentence(row.reader)} · {row.run_id}</option>)}</select></Field>
        <Field label="Reported delivery"><select aria-label="Reported delivery" disabled={busy || Boolean(pending)} value={delivery} onChange={event => setDelivery(event.target.value as AuditDelivery)}>{auditDelivery.map(state => <option key={state} value={state}>{sentence(state)}</option>)}</select></Field>
        <Field label="Audit files"><input ref={fileInput} aria-label="Audit files" type="file" multiple accept=".json,.gz" disabled={busy} onChange={event => setFiles(Array.from(event.target.files ?? []))} /></Field>
        <Button variant="primary" disabled={!ready || busy || Boolean(storageError) || !selected || !files.length || (history.data?.reviews.length === 32 && !pending)} onClick={save}><Save />{busy ? "Reviewing" : pending ? "Retry original import" : "Save audit review"}</Button>
      </div>
      {!history.data?.reads.length ? <p>No finalized read attempts available.</p> : null}
      {history.data?.reviews.length === 32 ? <Callout tone="warning" title="Review limit reached">All 32 saved reviews remain available.</Callout> : null}
      {selected ? <div className="s3-actions"><Link to={`/runs/${selected.run_id}`}>Original run</Link><Badge>{selected.provenance === "synthetic" ? "Synthetic runner source" : "Runner reported source"}</Badge><span>Cleanup: {sentence(selected.cleanup)}</span></div> : null}
      {pending ? <Callout tone="warning" title="Import confirmation pending"><p>The review may already be saved. Raw files are not retained in this browser. Starting another review keeps any saved history.</p><div className="s3-actions"><Button disabled={busy} onClick={() => open(s3JobId(pending.submission_id), pending)}><FileSearch />Check saved review</Button><Button disabled={busy} onClick={newReview}><Plus />Start another review</Button></div></Callout> : null}
      <div className="s3-audit-history" aria-label="Saved audit reviews">{history.data?.reviews.map(row => <article key={row.review_id}><Button disabled={busy} onClick={() => open(row.review_id, pending && s3JobId(pending.submission_id) === row.review_id ? pending : undefined)}><FileSearch />{phaseName[row.source.phase]} · {sentence(row.source.reader)}</Button><time dateTime={row.created_at}>{new Date(row.created_at).toLocaleString()}</time><span>{row.statuses.map(sentence).join(" · ")}</span></article>)}{!history.data?.reviews.length ? <p>No saved audit reviews.</p> : null}</div>
    </>}
    {storageError ? <ErrorState title="Local import recovery unavailable" error={storageError} /> : null}
    {error ? <ErrorState title="Audit review not confirmed" error={error} /> : null}
    {review ? <AuditDetail value={review} /> : null}
  </section>;
}

function AuditDetail({ value }: { value: AuditReview }) {
  const audit = value.correlation.audit;
  const assistant = useAssistancePanel();
  const explain = () => { if (!assistant) return; assistant.publish(Symbol("audit-review"), { kind: "audit", selected: { kind: "s3_audit_review", workflow_job_id: value.workflow_job_id, review_id: value.review_id, review_digest: value.review_digest }, title: `${phaseName[value.source.phase]} audit review`, manualEdits: false }); assistant.setOpen(true); };
  return <div className="s3-audit-detail" aria-label="Saved audit review detail"><div className="s3-setup-heading"><h3>{phaseName[value.source.phase]} · {sentence(value.source.reader)}</h3>{assistant ? <Button onClick={explain}><MessageSquareText />Explain review</Button> : null}</div><div className="s3-actions"><Link to={`/runs/${value.source.run_id}`}>Original run evidence</Link><Badge>{value.source.provenance === "synthetic" ? "Synthetic runner source" : "Runner reported source"}</Badge></div><div className="s3-audit-results">{value.correlation.reads.map(row => <article key={row.purpose}><h3>{row.purpose === "health" ? "Canary object" : "Primary object"}</h3><Badge tone={row.status === "matched" ? "info" : "warning"}>{sentence(row.status)}</Badge><DataList items={[{ label: "Runner", value: sentence(row.worker_outcome) }, { label: "Imported events", value: row.audit_event_ids.length }, { label: "Full object bytes", value: "Not proven" }]} /></article>)}</div><DataList items={[{ label: "Reported delivery", value: sentence(audit.reported_delivery_state) }, { label: "Imported records", value: audit.source_event_count }, { label: "Excluded", value: audit.counts.excluded }, { label: "Unknown", value: audit.counts.unknown }, { label: "Duplicates", value: audit.counts.duplicates }]} /><p>Operator-supplied records do not verify collection completeness or defensive effectiveness.</p><details><summary>Source bindings and minimized evidence</summary><pre>{JSON.stringify(value, null, 2)}</pre></details></div>;
}
