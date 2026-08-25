import * as Dialog from "@radix-ui/react-dialog";
import { useQuery } from "@tanstack/react-query";
import { Copy, Download, FilePlus2, GitBranch, Upload } from "lucide-react";
import { useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../lib/api";
import { useProduct } from "../state/ProductContext";
import type { Scenario } from "../types";
import { Badge, Button, Callout, EmptyState, ErrorState, Field, LoadingState, Modal, PageHeader, Panel } from "../components/Primitives";

function downloadJson(value: unknown, name: string) {
  const url = URL.createObjectURL(new Blob([`${JSON.stringify(value, null, 2)}\n`], { type: "application/json" }));
  const link = document.createElement("a"); link.href = url; link.download = name; link.click(); URL.revokeObjectURL(url);
}

export function ScenariosPage() {
  const query = useQuery({ queryKey: ["scenarios"], queryFn: api.scenarios });
  const versionsQuery = useQuery({ queryKey: ["scenario-versions"], queryFn: api.scenarioVersions });
  const { scenario, setScenario } = useProduct();
  const [notice, setNotice] = useState<string>();
  const fileRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();
  if (query.isPending) return <LoadingState label="Loading scenarios" />;
  if (query.isError) return <ErrorState error={query.error} retry={() => query.refetch()} />;
  const saved = versionsQuery.data?.scenarios ?? [];
  const savedIds = new Set(saved.map((item) => item.scenario_id));
  const currentSaved = saved.find((item) => item.scenario_id === scenario.id);
  const records = [
    { document: scenario, label: currentSaved ? `Working copy · saved v${currentSaved.version}` : "Working draft", tone: "info" as const },
    ...saved.filter((item) => item.scenario_id !== scenario.id).map((item) => ({ document: item.document, label: `Saved v${item.version}`, tone: "success" as const })),
    ...(query.data?.scenarios ?? []).filter((item) => item.id !== scenario.id && !savedIds.has(item.id)).map((item) => ({ document: item, label: "Packaged", tone: "neutral" as const })),
  ];

  const open = (next: Scenario) => { setScenario(structuredClone(next), false); navigate("/builder"); };
  const importScenario = async (file?: File) => {
    if (!file) return;
    try {
      const parsed = JSON.parse(await file.text()) as Scenario;
      if (!parsed.id || !Array.isArray(parsed.steps) || !Array.isArray(parsed.edges)) throw new Error("The document is not a BlueFire scenario.");
      setScenario(parsed); setNotice(`Imported ${parsed.title} as a local draft.`);
    } catch (error) { setNotice(error instanceof Error ? error.message : "Import failed."); }
    finally { if (fileRef.current) fileRef.current.value = ""; }
  };

  return <div className="page">
    <PageHeader eyebrow="Scenario library" title="Reusable security experiments" description="Version typed behavior graphs, keep provenance visible, and validate every route before a run." actions={<><input aria-label="Import scenario JSON file" ref={fileRef} className="sr-only" type="file" accept="application/json,.json" onChange={(event) => importScenario(event.target.files?.[0])}/><Button variant="secondary" onClick={() => fileRef.current?.click()}><Upload/>Import</Button><Modal title="Create scenario" description="Create a working draft, then validate and save a durable version from Builder." trigger={<Button variant="primary"><FilePlus2/>New scenario</Button>}><NewScenarioForm onCreate={(next) => { setScenario(next); setNotice("Working scenario draft created. Save a version from Builder when it is valid."); navigate("/builder"); }} /></Modal></>} />
    {notice ? <Callout title="Scenario workspace">{notice}</Callout> : null}
    {versionsQuery.isError ? <Callout tone="warning" title="Saved versions unavailable">Packaged scenarios and the current browser draft remain available. Retry after the local service is ready.</Callout> : null}
    <div className="scenario-grid">
      {records.map(({ document: item, label, tone }, index) => <Panel className="scenario-card" key={`${item.id}-${label}-${index}`}>
        <header><Badge tone={tone}>{label}</Badge><span>{item.steps.length} nodes · {item.edges.length} routes</span></header>
        <div><GitBranch/><h2>{item.title}</h2><p>{item.purpose}</p></div>
        <dl><div><dt>Start node</dt><dd><code>{item.start}</code></dd></div><div><dt>Provenance</dt><dd>{item.provenance?.source ?? "Not declared"}</dd></div></dl>
        {item.limitations?.length ? <p className="limitation">{item.limitations[0]}</p> : null}
        <footer><Button size="small" variant="primary" onClick={() => open(item)}>Open builder</Button><Button size="small" variant="ghost" onClick={() => { const copy = { ...structuredClone(item), id: item.id.replace(/\.v\d+$/, "") + ".copy.v1", title: `${item.title} copy` }; setScenario(copy); setNotice("Duplicated as a local draft."); }}><Copy/>Duplicate</Button><Button size="small" variant="ghost" onClick={() => downloadJson(item, `${item.id}.json`)}><Download/>Export</Button></footer>
      </Panel>)}
    </div>
    {!records.length ? <EmptyState title="No scenarios" description="Import a declarative scenario or create a local draft." /> : null}
  </div>;
}

function NewScenarioForm({ onCreate }: { onCreate: (scenario: Scenario) => void }) {
  const [title, setTitle] = useState("Untitled control validation");
  return <form className="dialog-form" onSubmit={(event) => { event.preventDefault(); const stem = title.toLowerCase().replace(/[^a-z0-9]+/g, ".").replace(/^\.|\.$/g, "") || "local.scenario"; const id = `${stem}.v1`; onCreate({ schema_version: "bluefire.scenario.v1", id, title, purpose: `Validate observable outcomes for ${title}.`, start: "missing_start", steps: [], edges: [], provenance: { source: "local operator draft", reference: id, license: "private", derived: true, notes: "Authored as an unsaved local working draft." }, limitations: ["Runner and policy readiness must be resolved during preflight."], layout: {} }); }}>
    <Field label="Scenario title" hint="Creates a working draft; Builder saves validated, content-addressed versions."><input value={title} onChange={(event) => setTitle(event.target.value)} maxLength={100} required autoFocus /></Field>
    <div className="dialog-actions"><Dialog.Close asChild><Button variant="ghost" type="button">Cancel</Button></Dialog.Close><Dialog.Close asChild><Button variant="primary" type="submit">Create draft</Button></Dialog.Close></div>
  </form>;
}
