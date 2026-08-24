import { useMutation, useQuery } from "@tanstack/react-query";
import {
  applyEdgeChanges, applyNodeChanges, Background, BackgroundVariant, Controls, Handle, MarkerType,
  MiniMap, Position, ReactFlow, ReactFlowProvider, useReactFlow,
  type Connection, type Edge, type EdgeChange, type Node, type NodeChange, type NodeProps,
} from "@xyflow/react";
import { Check, Clipboard, Copy, Download, Filter, GitBranch, Redo2, RotateCcw, Search, Sparkles, Trash2, Undo2 } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState, type DragEvent, type KeyboardEvent as ReactKeyboardEvent } from "react";
import { api } from "../lib/api";
import { useProduct } from "../state/ProductContext";
import type { AIGraphDraftResult, Behavior, Outcome, Scenario, ScenarioEdge, ScenarioStep } from "../types";
import { Badge, Button, Callout, DataList, EmptyState, ErrorState, Field, IconButton, LoadingState, PageHeader, Panel, PanelHeader, sentence } from "../components/Primitives";

const outcomes: Outcome[] = ["success", "partial", "blocked", "failed"];
const outcomeColors: Record<Outcome, string> = { success: "#45d39d", partial: "#f7b84b", blocked: "#ff7145", failed: "#ff6e79" };

interface BehaviorNodeData extends Record<string, unknown> { step: ScenarioStep; behavior?: Behavior; invalid?: boolean; }
type BehaviorFlowNode = Node<BehaviorNodeData, "behavior">;
type FlowEdge = Edge<{ kind: "route" | "artifact"; outcome?: Outcome; artifactType?: string }>;

function initialValue(spec: Behavior["parameters"][number]) {
  if (spec.default !== undefined) return structuredClone(spec.default);
  if (spec.enum?.length) return spec.enum[0];
  if (spec.type === "boolean") return false;
  if (spec.type === "integer" || spec.type === "number") return spec.minimum ?? 0;
  if (spec.type === "string_list") return [];
  return "";
}

function behaviorNode(step: ScenarioStep, behavior: Behavior | undefined, index: number, scenario: Scenario, invalid = false): BehaviorFlowNode {
  return { id: step.id, type: "behavior", position: scenario.layout?.[step.id] ?? { x: 40 + (index % 3) * 310, y: 50 + Math.floor(index / 3) * 220 }, data: { step, behavior, invalid } };
}

function flowEdges(scenario: Scenario, behaviors: Map<string, Behavior>): FlowEdge[] {
  const routes: FlowEdge[] = scenario.edges.map((edge, index) => ({ id: `route-${edge.from_step}-${edge.outcome}-${edge.to_step}-${index}`, source: edge.from_step, target: edge.to_step, sourceHandle: `route:${edge.outcome}`, targetHandle: "route:in", label: edge.outcome, type: "smoothstep", animated: edge.outcome === "partial", markerEnd: { type: MarkerType.ArrowClosed, color: outcomeColors[edge.outcome] }, style: { stroke: outcomeColors[edge.outcome], strokeWidth: 2 }, labelStyle: { fill: outcomeColors[edge.outcome], fontWeight: 700 }, data: { kind: "route", outcome: edge.outcome } }));
  const artifacts: FlowEdge[] = [];
  for (const target of scenario.steps) for (const [input, binding] of Object.entries(target.inputs)) {
    const source = scenario.steps.find((item) => item.id === binding.from_step);
    const output = behaviors.get(source?.behavior_id ?? "")?.outputs.find((item) => item.name === binding.artifact);
    artifacts.push({ id: `artifact-${binding.from_step}-${binding.artifact}-${target.id}-${input}`, source: binding.from_step, target: target.id, sourceHandle: `out:${binding.artifact}`, targetHandle: `in:${input}`, label: output?.type.split(".").at(-2) ?? binding.artifact, type: "smoothstep", style: { stroke: "#3ee2dc", strokeWidth: 1.5, strokeDasharray: "5 5" }, data: { kind: "artifact", artifactType: output?.type } });
  }
  return [...routes, ...artifacts];
}

function BehaviorNode({ data, selected }: NodeProps<BehaviorFlowNode>) {
  const behavior = data.behavior;
  return <article className={`flow-node tier-${behavior?.safety_tier ?? "safe"} ${selected ? "selected" : ""} ${data.invalid ? "invalid" : ""}`}>
    <Handle type="target" position={Position.Top} id="route:in" className="route-handle route-in" title="Outcome route input" />
    {(behavior?.inputs ?? []).slice(0, 4).map((input, index) => <Handle key={input.name} type="target" position={Position.Left} id={`in:${input.name}`} className="typed-handle input-handle" style={{ top: 55 + index * 18 }} title={`${input.name}: ${input.type}`} />)}
    <header><span>{behavior?.techniques[0] ?? "behavior"}</span><Badge tone={behavior?.execution_state === "action" ? "success" : behavior?.execution_state === "simulation" ? "info" : "neutral"}>{behavior?.execution_state === "action" ? "Action" : behavior?.execution_state === "simulation" ? "Simulation" : "Research"}</Badge></header>
    <strong>{behavior?.title ?? data.step.behavior_id}</strong><code>{data.step.id}</code>
    <footer><span>{sentence(behavior?.safety_tier ?? "unknown")}</span><span>{behavior?.platforms.slice(0, 2).join(" · ") || "Any"}</span></footer>
    {(behavior?.outputs ?? []).slice(0, 4).map((output, index) => <Handle key={output.name} type="source" position={Position.Right} id={`out:${output.name}`} className="typed-handle output-handle" style={{ top: 55 + index * 18 }} title={`${output.name}: ${output.type}`} />)}
    <div className="route-handles">{outcomes.map((outcome, index) => <Handle key={outcome} type="source" position={Position.Bottom} id={`route:${outcome}`} className={`route-handle route-${outcome}`} style={{ left: `${18 + index * 22}%` }} title={`${outcome} outcome route`} />)}</div>
  </article>;
}

const nodeTypes = { behavior: BehaviorNode };

export function BuilderPage() {
  const query = useQuery({ queryKey: ["catalog"], queryFn: api.catalog });
  if (query.isPending) return <LoadingState label="Opening graph editor" />;
  if (query.isError) return <ErrorState error={query.error} retry={() => query.refetch()} />;
  return <ReactFlowProvider><GraphWorkspace behaviors={query.data.behaviors} /></ReactFlowProvider>;
}

function GraphWorkspace({ behaviors }: { behaviors: Behavior[] }) {
  const { scenario, setScenario, dirty, markSaved, runConfig, setRunConfig } = useProduct();
  const behaviorMap = useMemo(() => new Map(behaviors.map((item) => [item.id, item])), [behaviors]);
  const [invalidNodes, setInvalidNodes] = useState<Set<string>>(new Set());
  const makeNodes = useCallback((value: Scenario) => value.steps.map((step, index) => behaviorNode(step, behaviorMap.get(step.behavior_id), index, value, invalidNodes.has(step.id))), [behaviorMap, invalidNodes]);
  const [nodes, setNodes] = useState<BehaviorFlowNode[]>(() => makeNodes(scenario));
  const [edges, setEdges] = useState<FlowEdge[]>(() => flowEdges(scenario, behaviorMap));
  const [selectedId, setSelectedId] = useState(scenario.steps[0]?.id ?? "");
  const [search, setSearch] = useState(""); const [platform, setPlatform] = useState("all"); const [tier, setTier] = useState("all");
  const [compatibility, setCompatibility] = useState<string>(); const [objective, setObjective] = useState(""); const [draftResult, setDraftResult] = useState<AIGraphDraftResult>();
  const [validationIssues, setValidationIssues] = useState<string[]>([]); const [validationState, setValidationState] = useState<"idle" | "valid" | "invalid">("idle");
  const [history, setHistory] = useState<Scenario[]>([structuredClone(scenario)]); const [historyIndex, setHistoryIndex] = useState(0);
  const clipboard = useRef<ScenarioStep | undefined>(undefined); const flow = useReactFlow<BehaviorFlowNode, FlowEdge>();

  useEffect(() => { setNodes(makeNodes(scenario)); setEdges(flowEdges(scenario, behaviorMap)); }, [scenario, behaviorMap, makeNodes]);
  const applyScenario = useCallback((next: Scenario, record = true) => {
    setScenario(next);
    if (record) { setHistory((items) => [...items.slice(0, historyIndex + 1), structuredClone(next)]); setHistoryIndex((index) => index + 1); }
    setValidationState("idle"); setValidationIssues([]); setInvalidNodes(new Set());
  }, [historyIndex, setScenario]);

  const undo = useCallback(() => { if (historyIndex <= 0) return; const index = historyIndex - 1; setHistoryIndex(index); setScenario(structuredClone(history[index]!), true); }, [history, historyIndex, setScenario]);
  const redo = useCallback(() => { if (historyIndex >= history.length - 1) return; const index = historyIndex + 1; setHistoryIndex(index); setScenario(structuredClone(history[index]!), true); }, [history, historyIndex, setScenario]);

  const uniqueId = (title: string) => { const root = title.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "").replace(/^[^a-z]+/, "") || "step"; let id = root; let suffix = 2; while (scenario.steps.some((step) => step.id === id)) id = `${root}_${suffix++}`; return id; };
  const addBehavior = (behavior: Behavior, position?: { x: number; y: number }) => {
    const id = uniqueId(behavior.title); const step: ScenarioStep = { id, behavior_id: behavior.id, parameters: Object.fromEntries(behavior.parameters.filter((item) => item.required || item.default !== undefined).map((item) => [item.name, initialValue(item)])), inputs: {}, alternates: [] };
    const previous = scenario.steps.at(-1); const next: Scenario = { ...scenario, start: scenario.steps.length ? scenario.start : id, steps: [...scenario.steps, step], edges: previous ? [...scenario.edges, { from_step: previous.id, outcome: "success", to_step: id }] : scenario.edges, layout: { ...scenario.layout, [id]: position ?? { x: 70 + (scenario.steps.length % 3) * 310, y: 70 + Math.floor(scenario.steps.length / 3) * 220 } } };
    applyScenario(next); setSelectedId(id); setCompatibility(`${behavior.title} added with a typed local draft contract.`);
  };

  const updateStep = (stepId: string, update: (step: ScenarioStep) => ScenarioStep) => applyScenario({ ...scenario, steps: scenario.steps.map((step) => step.id === stepId ? update(structuredClone(step)) : step) });
  const removeSteps = (ids: string[]) => { const removed = new Set(ids); const remaining = scenario.steps.filter((step) => !removed.has(step.id)).map((step) => ({ ...step, inputs: Object.fromEntries(Object.entries(step.inputs).filter(([, binding]) => !removed.has(binding.from_step))) })); applyScenario({ ...scenario, start: removed.has(scenario.start) ? remaining[0]?.id ?? "missing_start" : scenario.start, steps: remaining, edges: scenario.edges.filter((edge) => !removed.has(edge.from_step) && !removed.has(edge.to_step)), layout: Object.fromEntries(Object.entries(scenario.layout ?? {}).filter(([id]) => !removed.has(id))) }); setSelectedId(remaining[0]?.id ?? ""); };

  const onNodesChange = (changes: NodeChange<BehaviorFlowNode>[]) => setNodes((items) => applyNodeChanges(changes, items));
  const onEdgesChange = (changes: EdgeChange<FlowEdge>[]) => setEdges((items) => applyEdgeChanges(changes, items));
  const onNodeDragStop = (_: unknown, node: BehaviorFlowNode) => applyScenario({ ...scenario, layout: { ...scenario.layout, [node.id]: { x: Math.round(node.position.x), y: Math.round(node.position.y) } } });
  const onNodesDelete = (deleted: BehaviorFlowNode[]) => removeSteps(deleted.map((node) => node.id));
  const onEdgesDelete = (deleted: FlowEdge[]) => {
    const next = structuredClone(scenario);
    for (const edge of deleted) if (edge.data?.kind === "route") next.edges = next.edges.filter((item) => !(item.from_step === edge.source && item.to_step === edge.target && item.outcome === edge.data?.outcome)); else { const target = next.steps.find((item) => item.id === edge.target); if (target) target.inputs = Object.fromEntries(Object.entries(target.inputs).filter(([, binding]) => !(binding.from_step === edge.source && edge.sourceHandle === `out:${binding.artifact}`))); }
    applyScenario(next);
  };

  const onConnect = (connection: Connection) => {
    const source = scenario.steps.find((item) => item.id === connection.source); const target = scenario.steps.find((item) => item.id === connection.target);
    if (!source || !target || !connection.sourceHandle || !connection.targetHandle) return;
    if (connection.sourceHandle.startsWith("route:") && connection.targetHandle === "route:in") {
      const outcome = connection.sourceHandle.split(":")[1] as Outcome;
      const nextEdges = scenario.edges.filter((item) => !(item.from_step === source.id && item.outcome === outcome));
      applyScenario({ ...scenario, edges: [...nextEdges, { from_step: source.id, outcome, to_step: target.id }] }); setCompatibility(`${sentence(outcome)} route connected.`); return;
    }
    if (connection.sourceHandle.startsWith("out:") && connection.targetHandle.startsWith("in:")) {
      const outputName = connection.sourceHandle.slice(4); const inputName = connection.targetHandle.slice(3);
      const output = behaviorMap.get(source.behavior_id)?.outputs.find((item) => item.name === outputName); const input = behaviorMap.get(target.behavior_id)?.inputs.find((item) => item.name === inputName);
      if (!output || !input || output.type !== input.type || Boolean(output.multiple) !== Boolean(input.multiple)) { setCompatibility(`Incompatible artifact contract: ${output?.type ?? "unknown"} cannot satisfy ${input?.type ?? "unknown"}.`); return; }
      updateStep(target.id, (step) => ({ ...step, inputs: { ...step.inputs, [inputName]: { from_step: source.id, artifact: outputName } } })); setCompatibility(`Connected ${outputName} → ${inputName} (${input.type}).`);
    }
  };

  const copySelected = () => { const selected = scenario.steps.find((step) => step.id === selectedId); if (selected) { clipboard.current = structuredClone(selected); setCompatibility(`${selected.id} copied.`); } };
  const paste = () => { if (!clipboard.current) return; const source = clipboard.current; const behavior = behaviorMap.get(source.behavior_id); if (!behavior) return; const id = uniqueId(`${source.id} copy`); const step = { ...structuredClone(source), id, inputs: {} }; const origin = scenario.layout?.[source.id] ?? { x: 60, y: 60 }; applyScenario({ ...scenario, steps: [...scenario.steps, step], layout: { ...scenario.layout, [id]: { x: origin.x + 36, y: origin.y + 36 } } }); setSelectedId(id); };
  const duplicateSelected = () => { copySelected(); window.setTimeout(paste, 0); };
  const keyboard = (event: ReactKeyboardEvent<HTMLDivElement>) => { const target = event.target as HTMLElement; if (["INPUT", "SELECT", "TEXTAREA"].includes(target.tagName)) return; const command = event.ctrlKey || event.metaKey; if (command && event.key.toLowerCase() === "z") { event.preventDefault(); if (event.shiftKey) redo(); else undo(); } else if (command && event.key.toLowerCase() === "c") { event.preventDefault(); copySelected(); } else if (command && event.key.toLowerCase() === "v") { event.preventDefault(); paste(); } else if (command && event.key.toLowerCase() === "d") { event.preventDefault(); duplicateSelected(); } };

  const validateMutation = useMutation({ mutationFn: () => api.validate(scenario), onSuccess: (result) => { const issues = (result.issues ?? []).map((item) => typeof item === "string" ? item : JSON.stringify(item)); setValidationIssues(issues); setValidationState(result.valid ? "valid" : "invalid"); setInvalidNodes(new Set(scenario.steps.filter((step) => issues.some((issue) => issue.includes(step.id))).map((step) => step.id))); }, onError: (error) => { const message = error instanceof Error ? error.message : "Validation failed."; setValidationIssues([message]); setValidationState("invalid"); } });
  const saveMutation = useMutation({ mutationFn: () => api.saveScenarioVersion(scenario), onSuccess: ({ scenario: saved }) => { markSaved(); setCompatibility(`Durable scenario version ${saved.version} saved · ${saved.digest.slice(0, 12)}…`); }, onError: (error) => setCompatibility(`Save refused: ${error instanceof Error ? error.message : "The scenario version could not be saved."}`) });
  const serverDraftMutation = useMutation({ mutationFn: () => api.aiDraft(objective.trim(), runConfig.provider || null, 8, 16), onSuccess: (result) => { setDraftResult(result); setCompatibility(`${result.draft_id} is an unsaved preview. Review its audit before importing it.`); }, onError: (error) => setCompatibility(`Draft refused: ${error instanceof Error ? error.message : "The control-plane draft was unavailable."}`) });
  const selected = scenario.steps.find((step) => step.id === selectedId); const selectedBehavior = behaviorMap.get(selected?.behavior_id ?? "");
  const filtered = behaviors.filter((behavior) => { const haystack = `${behavior.title} ${behavior.purpose} ${behavior.capabilities.join(" ")}`.toLowerCase(); return (!search || haystack.includes(search.toLowerCase())) && (platform === "all" || behavior.platforms.includes(platform)) && (tier === "all" || behavior.safety_tier === tier); });
  const platforms = [...new Set(behaviors.flatMap((item) => item.platforms))].sort();

  const drop = (event: DragEvent<HTMLDivElement>) => { event.preventDefault(); const id = event.dataTransfer.getData("application/x-bluefire-behavior"); const behavior = behaviorMap.get(id); if (!behavior) return; addBehavior(behavior, flow.screenToFlowPosition({ x: event.clientX, y: event.clientY })); };
  const offlineDraft = () => { const terms = objective.toLowerCase(); const picks = behaviors.filter((item) => item.execution_state !== "metadata_only" && `${item.title} ${item.purpose} ${item.techniques.join(" ")}`.toLowerCase().split(/\s+/).some((word) => word.length > 5 && terms.includes(word))).slice(0, 4); const selectedPicks = picks.length ? picks : behaviors.filter((item) => item.execution_state !== "metadata_only").slice(0, 4); const steps = selectedPicks.map((behavior, index) => ({ id: `local_draft_${index + 1}_${behavior.title.toLowerCase().replace(/[^a-z0-9]+/g, "_").slice(0, 20)}`, behavior_id: behavior.id, parameters: Object.fromEntries(behavior.parameters.filter((item) => item.default !== undefined).map((item) => [item.name, initialValue(item)])), inputs: {}, alternates: [] })); const edges: ScenarioEdge[] = steps.slice(0, -1).map((step, index) => ({ from_step: step.id, outcome: "success", to_step: steps[index + 1]!.id })); const localScenario = { ...scenario, title: objective.slice(0, 80) || "Local fallback draft", purpose: objective || scenario.purpose, start: steps[0]?.id ?? "missing_start", steps, edges, layout: undefined }; setDraftResult({ schema_version: "bluefire.ai-graph-draft-result.v1", draft_id: `local-fallback-${Date.now()}`, saved: false, scenario: localScenario, rationale: "Browser-local deterministic keyword ranking over the loaded registered catalog.", assumptions: ["No provider or server draft endpoint was used."], audit: { unsaved: true, provider: { effective_provider_id: "browser-local-fallback", model: "keyword-ranking", attempts: 0, used_fallback: true, fallback_reason: "operator_selected_local_fallback" }, selected_behavior_ids: steps.map((step) => step.behavior_id), validation: { authority: "none", catalog_snapshot_only: true } } }); setCompatibility("Local fallback preview created. It has not changed, saved, authorized, or run the active graph."); };
  const importDraft = () => { if (!draftResult) return; applyScenario({ ...draftResult.scenario, layout: Object.fromEntries(draftResult.scenario.steps.map((step, index) => [step.id, { x: 70 + (index % 4) * 300, y: 110 + Math.floor(index / 4) * 230 }])) }); setSelectedId(draftResult.scenario.steps[0]?.id ?? ""); setCompatibility(`${draftResult.draft_id} imported as unsaved graph changes. Validate before saving or preflight.`); setDraftResult(undefined); };

  return <div className="page builder-page" onKeyDown={keyboard}>
    <PageHeader eyebrow="Scenario builder" title="Compose a typed adaptive graph" description="Connect artifact contracts and explicit outcome routes. Model proposals remain separate from policy authorization and runner execution." actions={<div className="builder-actions"><Badge tone={dirty ? "warning" : "success"} dot>{dirty ? "Unsaved graph changes" : "No unsaved edits"}</Badge><IconButton label="Undo" onClick={undo} disabled={historyIndex <= 0}><Undo2/></IconButton><IconButton label="Redo" onClick={redo} disabled={historyIndex >= history.length - 1}><Redo2/></IconButton><Button variant="secondary" onClick={() => { navigator.clipboard?.writeText(JSON.stringify(scenario, null, 2)); const url = URL.createObjectURL(new Blob([JSON.stringify(scenario, null, 2)], { type: "application/json" })); const link = document.createElement("a"); link.href = url; link.download = `${scenario.id}.json`; link.click(); URL.revokeObjectURL(url); }}><Download/>Export</Button><Button variant="secondary" onClick={() => validateMutation.mutate()} disabled={validateMutation.isPending}><Check/>Validate</Button><Button variant="primary" onClick={() => saveMutation.mutate()} disabled={saveMutation.isPending}>{saveMutation.isPending ? "Saving version" : "Save version"}</Button></div>} />
    <Panel className="objective-bar"><Sparkles/><Field label="Natural-language objective" hint="Control-plane drafting returns registered behavior contracts and typed parameters as an unsaved preview; it cannot authorize effects."><input value={objective} maxLength={4000} onChange={(event) => { setObjective(event.target.value); setDraftResult(undefined); }} placeholder="Validate fixture execution, discovery, staging, a blocked transport, and cleanup" /></Field><Button variant="secondary" onClick={() => serverDraftMutation.mutate()} disabled={!objective.trim() || serverDraftMutation.isPending}>{serverDraftMutation.isPending ? "Generating preview" : "Draft registered graph"}</Button><Button variant="ghost" onClick={offlineDraft} disabled={!objective.trim() || serverDraftMutation.isPending}>Local fallback</Button></Panel>
    {draftResult ? <Panel><PanelHeader eyebrow="Unsaved draft preview" title={draftResult.scenario.title} detail={draftResult.rationale} actions={<Badge tone="warning">Not imported · not authorized</Badge>}/><DataList items={[{ label: "Draft ID", value: <code>{draftResult.draft_id}</code> }, { label: "Provider", value: draftResult.audit.provider?.effective_provider_id ?? "Not reported" }, { label: "Fallback", value: draftResult.audit.provider?.used_fallback ? sentence(draftResult.audit.provider.fallback_reason ?? "used") : "No fallback reported" }, { label: "Graph", value: `${draftResult.scenario.steps.length} nodes · ${draftResult.scenario.edges.length} edges` }, { label: "Validation metadata", value: draftResult.audit.validation ? "Returned for review" : "Not reported" }]} />{draftResult.assumptions.length ? <Callout title="Assumptions"><ul>{draftResult.assumptions.map((item) => <li key={item}>{item}</li>)}</ul></Callout> : null}<details><summary>Provider, normalization, and validation audit</summary><pre>{JSON.stringify(draftResult.audit, null, 2)}</pre></details><Button variant="primary" onClick={importDraft}>Import as unsaved graph</Button></Panel> : null}
    {compatibility ? <div className={`compatibility-banner ${compatibility.startsWith("Incompatible") ? "error" : ""}`} role="status"><GitBranch/>{compatibility}<button onClick={() => setCompatibility(undefined)} aria-label="Dismiss compatibility message">×</button></div> : null}
    <div className="builder-layout">
      <Panel className="palette-panel"><PanelHeader eyebrow="Registry" title="Behavior palette" actions={<Badge>{filtered.length}</Badge>} /><div className="palette-filters"><label className="search-box"><Search/><input aria-label="Search palette" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search behaviors" /></label><div><label><span className="sr-only">Platform filter</span><select aria-label="Platform filter" value={platform} onChange={(event) => setPlatform(event.target.value)}><option value="all">All platforms</option>{platforms.map((item) => <option key={item}>{item}</option>)}</select></label><label><span className="sr-only">Tier filter</span><select aria-label="Safety tier filter" value={tier} onChange={(event) => setTier(event.target.value)}><option value="all">All tiers</option><option value="safe">Safe</option><option value="controlled">Controlled</option><option value="restricted">Restricted</option></select></label></div></div><div className="palette-list">{filtered.map((behavior) => <button key={behavior.id} draggable onDragStart={(event) => { event.dataTransfer.setData("application/x-bluefire-behavior", behavior.id); event.dataTransfer.effectAllowed = "copy"; }} onClick={() => addBehavior(behavior)}><span className={`palette-icon tier-${behavior.safety_tier}`}><GitBranch/></span><span><strong>{behavior.title}</strong><small>{behavior.purpose}</small><em>{behavior.platforms.slice(0, 3).join(" · ")}</em></span><Badge tone={behavior.execution_state === "action" ? "success" : behavior.execution_state === "simulation" ? "info" : "neutral"}>{behavior.execution_state === "action" ? "Action" : behavior.execution_state === "simulation" ? "Simulation" : "Research"}</Badge></button>)}</div><p className="panel-footnote"><Filter/> Drag or select a behavior. Metadata-only entries are clearly labeled and cannot imply Execute readiness.</p></Panel>
      <Panel className="graph-panel"><div className="graph-topbar"><div><Field label="Scenario name"><input value={scenario.title} onChange={(event) => applyScenario({ ...scenario, title: event.target.value }, false)} /></Field><Badge tone={validationState === "valid" ? "success" : validationState === "invalid" ? "danger" : "neutral"}>{validationState === "valid" ? "Contract valid" : validationState === "invalid" ? "Needs attention" : "Not validated"}</Badge></div><div className="graph-edit-actions"><IconButton label="Copy selected node" onClick={copySelected}><Copy/></IconButton><IconButton label="Paste node" onClick={paste} disabled={!clipboard.current}><Clipboard/></IconButton><IconButton label="Duplicate selected node" onClick={duplicateSelected} disabled={!selected}><RotateCcw/></IconButton><IconButton label="Delete selected node" onClick={() => selected && removeSteps([selected.id])} disabled={!selected}><Trash2/></IconButton></div></div><div className="graph-canvas" tabIndex={0} aria-label="Scenario graph canvas" onPointerDown={(event) => { const target = event.target as HTMLElement; if (!target.closest("button, input, select, textarea")) event.currentTarget.focus(); }} onDragOver={(event) => { if (event.dataTransfer.types.includes("application/x-bluefire-behavior")) event.preventDefault(); }} onDrop={drop}>
        <ReactFlow<BehaviorFlowNode, FlowEdge> nodes={nodes} edges={edges} nodeTypes={nodeTypes} onNodesChange={onNodesChange} onEdgesChange={onEdgesChange} onNodeClick={(_, node) => setSelectedId(node.id)} onNodeDragStop={onNodeDragStop} onNodesDelete={onNodesDelete} onEdgesDelete={onEdgesDelete} onConnect={onConnect} fitView minZoom={0.25} maxZoom={1.6} deleteKeyCode={["Backspace", "Delete"]} connectionLineStyle={{ stroke: "#38a8ff", strokeWidth: 2 }} proOptions={{ hideAttribution: true }}>
          <Background variant={BackgroundVariant.Dots} gap={22} size={1.2} color="rgba(117,198,255,.18)"/><MiniMap pannable zoomable nodeColor={(node) => { const behavior = behaviorMap.get((node.data as BehaviorNodeData).step.behavior_id); return behavior?.safety_tier === "restricted" ? "#ff6e79" : behavior?.safety_tier === "controlled" ? "#f7b84b" : "#38a8ff"; }} maskColor="rgba(5,9,19,.74)"/><Controls showInteractive={false}/>
        </ReactFlow>{!nodes.length ? <div className="graph-empty-overlay"><GitBranch/><strong>Start with a registered behavior</strong><span>Select one from the palette or create an offline planner draft.</span></div> : null}</div>
        <div className={`validation-bar ${validationState}`}><div><strong>{validationState === "valid" ? "Deterministic validation passed" : validationState === "invalid" ? "Graph validation returned findings" : "Validate before preflight"}</strong><span>{validationIssues[0] ?? `${scenario.steps.length} nodes · ${scenario.edges.length} outcome routes`}</span></div>{validationIssues.length > 1 ? <details><summary>{validationIssues.length} findings</summary><ul>{validationIssues.map((item) => <li key={item}>{item}</li>)}</ul></details> : null}</div>
      </Panel>
      <Panel className="inspector-panel"><PanelHeader eyebrow="Selected node" title={selectedBehavior?.title ?? "Inspector"} detail={selected ? selected.id : "Select a node to inspect its contract."} />{selected && selectedBehavior ? <Inspector scenario={scenario} step={selected} behavior={selectedBehavior} behaviors={behaviorMap} updateStep={updateStep} updateScenario={applyScenario} selectedAction={runConfig.mode === "execute" ? runConfig.actionImplementations?.[selected.id] ?? "" : ""} executeMode={runConfig.mode === "execute"} onAction={(actionId) => { const next = { ...(runConfig.actionImplementations ?? {}) }; if (actionId) next[selected.id] = actionId; else delete next[selected.id]; setRunConfig({ ...runConfig, actionImplementations: next }); }} /> : <EmptyState title="No node selected" description="Select a graph node to edit its contract, parameters, routes, and implementation choice." />}</Panel>
    </div>
  </div>;
}

function Inspector({ scenario, step, behavior, behaviors, updateStep, updateScenario, selectedAction, executeMode, onAction }: { scenario: Scenario; step: ScenarioStep; behavior: Behavior; behaviors: Map<string, Behavior>; updateStep: (id: string, update: (step: ScenarioStep) => ScenarioStep) => void; updateScenario: (scenario: Scenario) => void; selectedAction: string; executeMode: boolean; onAction: (id: string) => void }) {
  const outputs = scenario.steps.flatMap((source) => (behaviors.get(source.behavior_id)?.outputs ?? []).map((output) => ({ source, output }))).filter((item) => item.source.id !== step.id);
  const changeId = (id: string) => { if (!/^[a-z][a-z0-9_]*$/.test(id) || scenario.steps.some((item) => item.id === id && item.id !== step.id)) return; updateScenario({ ...scenario, start: scenario.start === step.id ? id : scenario.start, steps: scenario.steps.map((item) => item.id === step.id ? { ...item, id } : { ...item, inputs: Object.fromEntries(Object.entries(item.inputs).map(([name, binding]) => [name, binding.from_step === step.id ? { ...binding, from_step: id } : binding])) }), edges: scenario.edges.map((edge) => ({ ...edge, from_step: edge.from_step === step.id ? id : edge.from_step, to_step: edge.to_step === step.id ? id : edge.to_step })), layout: Object.fromEntries(Object.entries(scenario.layout ?? {}).map(([key, value]) => [key === step.id ? id : key, value])) }); };
  return <div className="inspector-body"><section><Field label="Step ID" hint="Unique lowercase snake_case identifier."><input value={step.id} onChange={(event) => changeId(event.target.value)} pattern="[a-z][a-z0-9_]*" /></Field><div className="chip-list"><Badge tone={behavior.safety_tier === "restricted" ? "danger" : behavior.safety_tier === "controlled" ? "warning" : "success"}>{behavior.safety_tier}</Badge>{behavior.platforms.map((item) => <Badge key={item}>{item}</Badge>)}</div><p>{behavior.purpose}</p></section>
    <section><h3>Action implementation</h3><Field label="Registered Execute action" hint={!executeMode ? "Simulate ignores and clears action selections." : behavior.action_ids.length ? "Execute preflight validates this registered action and binds it into the exact plan and one-time approval envelope." : "No Execute action is installed."}><select value={selectedAction} onChange={(event) => onAction(event.target.value)} disabled={!executeMode || !behavior.action_ids.length}><option value="">Resolve deterministically</option>{behavior.action_ids.map((id) => <option key={id}>{id}</option>)}</select></Field></section>
    <section><h3>Typed inputs</h3>{behavior.inputs.length ? behavior.inputs.map((input) => <Field key={input.name} label={`${input.name} · ${input.type}`} hint={input.required ? "Required artifact" : "Optional artifact"}><select value={step.inputs[input.name] ? `${step.inputs[input.name]!.from_step}:${step.inputs[input.name]!.artifact}` : ""} onChange={(event) => updateStep(step.id, (next) => { if (!event.target.value) { delete next.inputs[input.name]; return next; } const [from_step, artifact] = event.target.value.split(":", 2); return { ...next, inputs: { ...next.inputs, [input.name]: { from_step: from_step!, artifact: artifact! } } }; })}><option value="">{input.required ? "Choose compatible output" : "No binding"}</option>{outputs.filter(({ output }) => output.type === input.type && Boolean(output.multiple) === Boolean(input.multiple)).map(({ source, output }) => <option key={`${source.id}:${output.name}`} value={`${source.id}:${output.name}`}>{source.id} · {output.name}</option>)}</select></Field>) : <p>No artifact inputs.</p>}</section>
    <section><h3>Parameters</h3>{behavior.parameters.length ? behavior.parameters.map((spec) => <ParameterField key={spec.name} spec={spec} value={step.parameters[spec.name]} onChange={(value) => updateStep(step.id, (next) => ({ ...next, parameters: { ...next.parameters, [spec.name]: value } }))} />) : <p>No configurable parameters.</p>}</section>
    <section><h3>Outcome routes</h3>{outcomes.map((outcome) => { const edge = scenario.edges.find((item) => item.from_step === step.id && item.outcome === outcome); return <Field key={outcome} label={sentence(outcome)}><select value={edge?.to_step ?? ""} onChange={(event) => updateScenario({ ...scenario, edges: [...scenario.edges.filter((item) => !(item.from_step === step.id && item.outcome === outcome)), ...(event.target.value ? [{ from_step: step.id, outcome, to_step: event.target.value }] : [])] })}><option value="">End path</option>{scenario.steps.filter((item) => item.id !== step.id).map((item) => <option key={item.id}>{item.id}</option>)}</select></Field>; })}</section>
    <section><h3>Expected observables</h3><div className="chip-list">{behavior.telemetry.map((item) => <Badge key={item} tone="info">{item}</Badge>)}</div></section>
  </div>;
}

function ParameterField({ spec, value, onChange }: { spec: Behavior["parameters"][number]; value: unknown; onChange: (value: unknown) => void }) {
  if (spec.enum?.length) return <Field label={spec.name} hint={spec.description}><select value={String(value ?? "")} onChange={(event) => onChange(event.target.value)}>{spec.enum.map((item) => <option key={String(item)} value={String(item)}>{String(item)}</option>)}</select></Field>;
  if (spec.type === "boolean") return <label className="check-row"><input type="checkbox" checked={Boolean(value)} onChange={(event) => onChange(event.target.checked)} /><span><strong>{spec.name}</strong><small>{spec.description ?? "Boolean parameter"}</small></span></label>;
  return <Field label={spec.name} hint={spec.description}><input type={spec.type === "integer" || spec.type === "number" ? "number" : "text"} value={Array.isArray(value) ? value.join(", ") : String(value ?? "")} min={spec.minimum} max={spec.maximum} required={spec.required} onChange={(event) => onChange(spec.type === "integer" ? Number.parseInt(event.target.value, 10) : spec.type === "number" ? Number(event.target.value) : spec.type === "string_list" ? event.target.value.split(",").map((item) => item.trim()).filter(Boolean) : event.target.value)} /></Field>;
}
