import * as Dialog from "@radix-ui/react-dialog";
import { useQuery } from "@tanstack/react-query";
import { Copy, Download, FilePlus2, Upload } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { api } from "../lib/api";
import { sameJson } from "../lib/replay-review";
import { parseScenarioDocument } from "../lib/scenario";
import { useProduct } from "../state/ProductContext";
import type { Scenario } from "../types";
import { Button, Field, PageHeader } from "../components/Primitives";
import "./Scenarios.css";

export { parseScenarioDocument } from "../lib/scenario";

function downloadJson(value: unknown, name: string) {
  const url = URL.createObjectURL(new Blob([`${JSON.stringify(value, null, 2)}\n`], { type: "application/json" }));
  const link = document.createElement("a"); link.href = url; link.download = name; link.click(); URL.revokeObjectURL(url);
}

function readScenarioFile(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error("The scenario file could not be read."));
    reader.onload = () => typeof reader.result === "string" ? resolve(reader.result) : reject(new Error("The scenario file was not text."));
    reader.readAsText(file);
  });
}

type Replacement = { document: Scenario; action: "Open" | "Import" | "Duplicate" | "Create"; clean: boolean; navigate: boolean; previous: Scenario };

export function ScenariosPage() {
  const query = useQuery({ queryKey: ["scenarios"], queryFn: api.scenarios });
  const versionsQuery = useQuery({ queryKey: ["scenario-versions"], queryFn: api.scenarioVersions });
  const { scenario, setScenario, dirty } = useProduct();
  const [notice, setNotice] = useState<string>();
  const [pending, setPending] = useState<Replacement>();
  const [creating, setCreating] = useState(false);
  const [reading, setReading] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);
  const originRef = useRef<HTMLElement | null>(null);
  const rememberOrigin = () => { originRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null; };
  const restoreFocus = (event: Event) => { event.preventDefault(); if (originRef.current?.isConnected) originRef.current.focus(); };
  const selectedRef = useRef<HTMLElement>(null);
  const mounted = useRef(true);
  const operation = useRef(0);
  const current = useRef({ scenario, dirty });
  useEffect(() => { current.current = { scenario, dirty }; }, [scenario, dirty]);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const currentParams = useRef(params);
  useEffect(() => { currentParams.current = params; }, [params]);
  const search = params.get("q") ?? "";
  const selected = params.get("selected");
  const selectedView = params.get("view");
  const [selectionRequest, setSelectionRequest] = useState(0);
  const arrivalFocus = useRef(true);
  useEffect(() => {
    arrivalFocus.current = true;
    const yieldFocus = () => { arrivalFocus.current = false; };
    document.addEventListener("focusin", yieldFocus);
    document.addEventListener("pointerdown", yieldFocus);
    return () => { document.removeEventListener("focusin", yieldFocus); document.removeEventListener("pointerdown", yieldFocus); };
  }, [selected, selectedView, selectionRequest]);
  const records = useMemo(() => {
    const saved = versionsQuery.data?.scenarios ?? [];
    const match = saved.find((item) => item.scenario_id === scenario.id && sameJson(item.document, scenario));
    const packagedMatch = (query.data?.scenarios ?? []).some((item) => sameJson(item, scenario));
    const savedIds = new Set(saved.map((item) => item.scenario_id));
    return [
      { key: "working", document: scenario, label: match ? `Saved v${match.version}` : packagedMatch ? "Packaged" : "Working draft", working: true },
      ...saved.filter((item) => item !== match).map((item) => ({ key: `saved:${item.scenario_id}:${item.version}`, document: item.document, label: `Saved v${item.version}`, working: false })),
      ...(query.data?.scenarios ?? []).filter((item) => !savedIds.has(item.id) && !sameJson(item, scenario)).map((item) => ({ key: `packaged:${item.id}`, document: item, label: "Packaged", working: false })),
    ];
  }, [scenario, query.data, versionsQuery.data]);
  const selectedKey = selectedView === "draft" && scenario.id === selected ? "working" : records.find((item) => item.document.id === selected && item.label.startsWith("Saved v"))?.key
    ?? records.find((item) => item.document.id === selected)?.key;
  const selectionReady = !query.isPending && !versionsQuery.isPending;
  useEffect(() => {
    if (arrivalFocus.current && selected && selectedKey && selectionReady) {
      arrivalFocus.current = false;
      selectedRef.current?.focus({ preventScroll: true });
      selectedRef.current?.scrollIntoView({ block: "nearest" });
    }
  }, [selected, selectedView, selectedKey, selectionReady, selectionRequest]);
  const matches = (item: typeof records[number]) => `${item.document.title} ${item.document.id} ${item.document.purpose} ${item.label}`.toLowerCase().includes(search.toLowerCase().trim());
  const visible = records.filter((item) => matches(item) || item.key === selectedKey);
  const choose = (id: string, working: boolean) => { const next = new URLSearchParams(params); next.set("selected", id); if (working) next.set("view", "draft"); else next.delete("view"); setSelectionRequest((value) => value + 1); setParams(next); };
  const apply = (replacement: Replacement) => {
    setScenario(structuredClone(replacement.document), !replacement.clean);
    setNotice(`${replacement.action === "Open" ? "Opened" : replacement.action === "Import" ? "Imported" : replacement.action === "Duplicate" ? "Duplicated" : "Created"} ${replacement.document.title}${replacement.clean ? "." : " as a local draft."}`);
    setPending(undefined);
    if (replacement.navigate) navigate("/builder");
    else { const next = new URLSearchParams(currentParams.current); next.set("selected", replacement.document.id); next.set("view", "draft"); setParams(next); }
  };
  const request = (document: Scenario, action: Replacement["action"], clean = false, go = false) => {
    operation.current += 1;
    const latest = current.current;
    if (action === "Open" && sameJson(document, latest.scenario)) { navigate("/builder"); return; }
    setNotice(undefined);
    const replacement = { document: structuredClone(document), action, clean, navigate: go, previous: structuredClone(latest.scenario) };
    if (latest.dirty) setPending(replacement); else apply(replacement);
  };
  const confirmReplacement = () => {
    if (!pending) return;
    if (!sameJson(pending.previous, current.current.scenario)) {
      setPending({ ...pending, previous: structuredClone(current.current.scenario) });
      setNotice("Your working draft changed while this dialog was open. Review it again before replacing it.");
      return;
    }
    apply(pending);
  };
  const importScenario = async (file?: File) => {
    if (!file || reading) return;
    setReading(true);
    const generation = ++operation.current;
    try {
      const parsed = parseScenarioDocument(JSON.parse(await readScenarioFile(file)) as unknown);
      if (mounted.current && generation === operation.current) request(parsed, "Import");
    } catch (error) { if (mounted.current && generation === operation.current) setNotice(error instanceof Error ? error.message : "Import failed."); }
    finally { if (mounted.current) { setReading(false); if (fileRef.current) fileRef.current.value = ""; } }
  };

  return <div className="page experiments-page">
    <PageHeader title="Experiments" description="" actions={<><input aria-label="Import experiment JSON file" ref={fileRef} className="sr-only" type="file" accept="application/json,.json" onChange={(event) => void importScenario(event.target.files?.[0])}/><Button variant="secondary" disabled={reading} onClick={() => { rememberOrigin(); fileRef.current?.click(); }}><Upload/>{reading ? "Reading file" : "Import"}</Button><Button variant="primary" onClick={() => { rememberOrigin(); operation.current += 1; setCreating(true); }}><FilePlus2/>New experiment</Button></>} />
    {notice ? <p role="status" className="experiments-notice">{notice}</p> : null}
    <div className="experiments-search"><label htmlFor="experiment-search">Find an experiment</label><input id="experiment-search" type="search" value={search} placeholder="Search by name or ID" onChange={(event) => { const next = new URLSearchParams(params); if (event.target.value) next.set("q", event.target.value); else next.delete("q"); setParams(next, { replace: true }); }}/><span>{visible.length} {visible.length === 1 ? "experiment" : "experiments"}</span></div>
    {([{ query, label: "Packaged experiments" }, { query: versionsQuery, label: "Saved versions" }]).map(({ query: resource, label }) => resource.isPending ? <p role="status" key={label}>{label} loading. Your working draft remains available.</p> : resource.isError ? <div role="alert" className="experiments-unavailable" key={label}><div><strong>{label} unavailable</strong><p>{resource.data ? "Showing previously loaded records." : "The list could not be loaded."} Your working draft is preserved.</p><details><summary>Technical details</summary>{resource.error instanceof Error ? resource.error.message : "Request failed"}</details></div><Button variant="secondary" onClick={() => void resource.refetch()}>Retry {label.toLowerCase()}</Button></div> : null)}
    {selected && !selectedKey && selectionReady ? <p role="status">The selected experiment is not in the available records. Search or retry the unavailable list.</p> : null}
    <section className="experiments-list" aria-label="Experiments">
      {visible.map(({ document: item, label, key, working }) => <article className="experiment-row" key={key} ref={key === selectedKey ? selectedRef : undefined} tabIndex={-1} aria-label={`${item.title} - ${label}`} aria-current={key === selectedKey ? "true" : undefined}>
        <div className="experiment-summary"><h2><button type="button" onClick={() => choose(item.id, working)}>{item.title}</button></h2><p>{item.purpose}</p><div className="experiment-meta"><span>{label}{working ? " · Current working copy" : ""}</span><span>{item.steps.length} {item.steps.length === 1 ? "Step" : "Steps"} · {item.edges.length} routes</span></div>{key === selectedKey && !matches({ document: item, label, key, working }) ? <p>Selected experiment · outside this search</p> : null}
        <details><summary>Experiment details</summary><dl><div><dt>Experiment ID</dt><dd><code>{item.id}</code></dd></div><div><dt>Starting Step</dt><dd>{item.start}</dd></div><div><dt>Source</dt><dd>{item.provenance?.source ?? "Not declared"}</dd></div></dl>{item.limitations?.length ? <><h3>Limitations</h3><ul>{item.limitations.map((value, index) => <li key={index}>{value}</li>)}</ul></> : null}</details></div>
        <div className="experiment-actions"><Button size="small" variant="secondary" onClick={() => { rememberOrigin(); request(item, "Open", true, true); }}>{working ? "Continue editing" : "Open"}</Button><Button size="small" variant="ghost" onClick={() => { rememberOrigin(); request({ ...structuredClone(item), id: `${item.id.replace(/\.v\d+$/, "")}.copy.${crypto.randomUUID()}.v1`, title: `${item.title} copy` }, "Duplicate"); }}><Copy/>Duplicate</Button><Button size="small" variant="ghost" onClick={() => downloadJson(item, `${item.id}.json`)}><Download/>Export</Button></div>
      </article>)}
      {!visible.length ? <p className="experiments-empty">No experiments match this search. <button type="button" onClick={() => { const next = new URLSearchParams(params); next.delete("q"); setParams(next, { replace: true }); }}>Clear search</button></p> : null}
    </section>
    <Dialog.Root open={creating} onOpenChange={setCreating}><Dialog.Portal><Dialog.Overlay className="dialog-overlay"/><Dialog.Content className="dialog-content experiments-dialog" onCloseAutoFocus={(event) => { if (!pending) restoreFocus(event); }}><Dialog.Title>New experiment</Dialog.Title><Dialog.Description>Create a local draft. Save a validated version in the editor.</Dialog.Description><NewScenarioForm onCreate={(next) => { setCreating(false); request(next, "Create", false, true); }}/></Dialog.Content></Dialog.Portal></Dialog.Root>
    <Dialog.Root open={Boolean(pending)} onOpenChange={(open) => { if (!open) setPending(undefined); }}><Dialog.Portal><Dialog.Overlay className="dialog-overlay"/><Dialog.Content className="dialog-content experiments-dialog" onCloseAutoFocus={restoreFocus}><Dialog.Title>Replace your working draft?</Dialog.Title><Dialog.Description>Your unsaved changes to {pending?.previous.title} will leave this workspace. Export them first if you want to keep a copy.</Dialog.Description>{notice?.startsWith("Your working draft changed") ? <p role="status">{notice}</p> : null}{pending ? <><dl><div><dt>Working draft</dt><dd>{pending.previous.title} · {pending.previous.steps.length} Steps</dd></div><div><dt>{pending.action === "Open" ? "Open experiment" : `${pending.action} as draft`}</dt><dd>{pending.document.title} · {pending.document.steps.length} Steps</dd></div></dl><details><summary>Review draft and replacement</summary><h3>Current draft</h3><pre>{JSON.stringify(pending.previous, null, 2)}</pre><h3>Replacement</h3><pre>{JSON.stringify(pending.document, null, 2)}</pre></details><Button variant="secondary" onClick={() => downloadJson(current.current.scenario, `${current.current.scenario.id}.json`)}><Download/>Export working draft</Button><div className="dialog-actions"><Dialog.Close asChild><Button variant="secondary">Keep working draft</Button></Dialog.Close><Button variant="primary" onClick={confirmReplacement}>Replace draft and {pending.action.toLowerCase()}</Button></div></> : null}</Dialog.Content></Dialog.Portal></Dialog.Root>
  </div>;
}

function NewScenarioForm({ onCreate }: { onCreate: (scenario: Scenario) => void }) {
  const [title, setTitle] = useState("Untitled experiment");
  return <form className="dialog-form" onSubmit={(event) => { event.preventDefault(); const stem = title.toLowerCase().replace(/[^a-z0-9]+/g, ".").replace(/^\.|\.$/g, "") || "local.experiment"; const id = `${stem}.${crypto.randomUUID()}.v1`; onCreate({ schema_version: "bluefire.scenario.v1", id, title, purpose: `Validate observable outcomes for ${title}.`, start: "missing_start", steps: [], edges: [], provenance: { source: "local operator draft", reference: id, license: "private", derived: true, notes: "Authored as an unsaved local working draft." }, limitations: ["Runner and policy readiness must be resolved during preflight."], layout: {} }); }}>
    <Field label="Experiment name"><input value={title} onChange={(event) => setTitle(event.target.value)} maxLength={100} required autoFocus /></Field>
    <div className="dialog-actions"><Dialog.Close asChild><Button variant="ghost" type="button">Cancel</Button></Dialog.Close><Button variant="primary" type="submit">Create draft</Button></div>
  </form>;
}
