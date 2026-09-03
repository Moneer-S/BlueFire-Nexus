import { useMutation, useQuery } from "@tanstack/react-query";
import * as Dialog from "@radix-ui/react-dialog";
import {
  applyEdgeChanges, applyNodeChanges, Background, BackgroundVariant, Controls, Handle, MarkerType,
  MiniMap, Position, ReactFlow, ReactFlowProvider, useReactFlow,
  type Connection, type Edge, type EdgeChange, type Node, type NodeChange, type NodeProps,
} from "@xyflow/react";
import {
  Check, Clipboard, Command as CommandIcon, Copy, Download, Filter, GitBranch, LayoutGrid, Maximize2, Minimize2,
  PanelLeftClose, PanelLeftOpen, PanelRightClose, PanelRightOpen, Redo2, RotateCcw,
  ScanSearch, Search, Sparkles, Trash2, Undo2, X,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState, type CSSProperties, type DragEvent, type KeyboardEvent as ReactKeyboardEvent } from "react";
import { api } from "../lib/api";
import { initialParameterValue, parameterValuesEqual, shouldInitializeParameter } from "../lib/parameters";
import { useProduct } from "../state/ProductContext";
import type { AIGraphDraftResult, Behavior, Outcome, Scenario, ScenarioEdge, ScenarioStep } from "../types";
import { Badge, Button, Callout, DataList, EmptyState, ErrorState, Field, IconButton, LoadingState, PageHeader, Panel, PanelHeader, sentence } from "../components/Primitives";

const outcomes: Outcome[] = ["success", "partial", "blocked", "failed"];
const outcomeColors: Record<Outcome, string> = { success: "#45d39d", partial: "#f7b84b", blocked: "#ff7145", failed: "#ff6e79" };

interface BehaviorNodeData extends Record<string, unknown> { step: ScenarioStep; behavior?: Behavior; invalid?: boolean; }
type BehaviorFlowNode = Node<BehaviorNodeData, "behavior">;
type FlowEdge = Edge<{ kind: "route" | "artifact"; outcome?: Outcome; artifactType?: string }>;

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
  const [focusMode, setFocusMode] = useState(false); const [paletteOpen, setPaletteOpen] = useState(true); const [inspectorOpen, setInspectorOpen] = useState(true); const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  const [paletteWidth, setPaletteWidth] = useState(290); const [inspectorWidth, setInspectorWidth] = useState(330);
  const clipboard = useRef<ScenarioStep | undefined>(undefined); const flow = useReactFlow<BehaviorFlowNode, FlowEdge>();

  useEffect(() => { setNodes(makeNodes(scenario)); setEdges(flowEdges(scenario, behaviorMap)); }, [scenario, behaviorMap, makeNodes]);
  useEffect(() => {
    if (!focusMode) return;
    const exitFocus = (event: globalThis.KeyboardEvent) => { if (event.key === "Escape" && !commandPaletteOpen) setFocusMode(false); };
    window.addEventListener("keydown", exitFocus);
    return () => window.removeEventListener("keydown", exitFocus);
  }, [commandPaletteOpen, focusMode]);
  useEffect(() => {
    const openCommands = (event: globalThis.KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") { event.preventDefault(); setCommandPaletteOpen(true); }
    };
    window.addEventListener("keydown", openCommands);
    return () => window.removeEventListener("keydown", openCommands);
  }, []);
  useEffect(() => {
    const timer = window.setTimeout(() => { void flow.fitView({ padding: 0.22, duration: 250, maxZoom: 1.15 }); }, 0);
    return () => window.clearTimeout(timer);
  }, [flow, focusMode, inspectorOpen, inspectorWidth, paletteOpen, paletteWidth]);
  const applyScenario = useCallback((next: Scenario, record = true) => {
    setScenario(next);
    if (record) { setHistory((items) => [...items.slice(0, historyIndex + 1), structuredClone(next)]); setHistoryIndex((index) => index + 1); }
    setValidationState("idle"); setValidationIssues([]); setInvalidNodes(new Set());
  }, [historyIndex, setScenario]);

  const undo = useCallback(() => { if (historyIndex <= 0) return; const index = historyIndex - 1; setHistoryIndex(index); setScenario(structuredClone(history[index]!), true); }, [history, historyIndex, setScenario]);
  const redo = useCallback(() => { if (historyIndex >= history.length - 1) return; const index = historyIndex + 1; setHistoryIndex(index); setScenario(structuredClone(history[index]!), true); }, [history, historyIndex, setScenario]);

  const uniqueId = (title: string) => { const root = title.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "").replace(/^[^a-z]+/, "") || "step"; let id = root; let suffix = 2; while (scenario.steps.some((step) => step.id === id)) id = `${root}_${suffix++}`; return id; };
  const addBehavior = (behavior: Behavior, position?: { x: number; y: number }) => {
    const id = uniqueId(behavior.title); const step: ScenarioStep = { id, behavior_id: behavior.id, parameters: Object.fromEntries(behavior.parameters.filter(shouldInitializeParameter).map((item) => [item.name, initialParameterValue(item)])), inputs: {}, alternates: [] };
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
  const confirmDelete = useCallback(async ({ nodes: requestedNodes, edges: requestedEdges }: { nodes: BehaviorFlowNode[]; edges: FlowEdge[] }) => {
    const parts = [requestedNodes.length ? `${requestedNodes.length} node${requestedNodes.length === 1 ? "" : "s"}` : "", requestedEdges.length ? `${requestedEdges.length} edge${requestedEdges.length === 1 ? "" : "s"}` : ""].filter(Boolean);
    return window.confirm(`Delete ${parts.join(" and ")} from this scenario?\n\nConnected routes and artifact bindings may also be removed. You can undo the confirmed change.`);
  }, []);

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
  const fitGraph = () => { void flow.fitView({ padding: 0.22, duration: 300, maxZoom: 1.15 }); };
  const fitSelection = () => { if (selectedId) void flow.fitView({ nodes: [{ id: selectedId }], padding: 0.48, duration: 300, maxZoom: 1.15 }); };
  const autoLayout = () => {
    if (!scenario.steps.length) return;
    const depth = new Map<string, number>([[scenario.start, 0]]); const queue = [scenario.start];
    while (queue.length) {
      const source = queue.shift()!; const sourceDepth = depth.get(source) ?? 0;
      for (const edge of scenario.edges.filter((item) => item.from_step === source)) if (!depth.has(edge.to_step)) { depth.set(edge.to_step, sourceDepth + 1); queue.push(edge.to_step); }
    }
    const reachableMax = Math.max(0, ...depth.values());
    for (const step of scenario.steps) if (!depth.has(step.id)) depth.set(step.id, reachableMax + 1);
    const columns = new Map<number, ScenarioStep[]>();
    for (const step of scenario.steps) { const column = depth.get(step.id) ?? 0; columns.set(column, [...(columns.get(column) ?? []), step]); }
    const layout = Object.fromEntries([...columns.entries()].sort(([left], [right]) => left - right).flatMap(([column, steps]) => steps.map((step, row) => [step.id, { x: 70 + column * 310, y: 70 + row * 190 }])));
    applyScenario({ ...scenario, layout }); setCompatibility("Graph arranged by outcome-route depth. Disconnected nodes are grouped in the final column.");
    window.setTimeout(fitGraph, 0);
  };
  const runCommand = (action: () => void) => { setCommandPaletteOpen(false); action(); };
  const offlineDraft = () => { const terms = objective.toLowerCase(); const picks = behaviors.filter((item) => item.execution_state !== "metadata_only" && `${item.title} ${item.purpose} ${item.techniques.join(" ")}`.toLowerCase().split(/\s+/).some((word) => word.length > 5 && terms.includes(word))).slice(0, 4); const selectedPicks = picks.length ? picks : behaviors.filter((item) => item.execution_state !== "metadata_only").slice(0, 4); const steps = selectedPicks.map((behavior, index) => ({ id: `local_draft_${index + 1}_${behavior.title.toLowerCase().replace(/[^a-z0-9]+/g, "_").slice(0, 20)}`, behavior_id: behavior.id, parameters: Object.fromEntries(behavior.parameters.filter(shouldInitializeParameter).map((item) => [item.name, initialParameterValue(item)])), inputs: {}, alternates: [] })); const edges: ScenarioEdge[] = steps.slice(0, -1).map((step, index) => ({ from_step: step.id, outcome: "success", to_step: steps[index + 1]!.id })); const localScenario = { ...scenario, title: objective.slice(0, 80) || "Local fallback draft", purpose: objective || scenario.purpose, start: steps[0]?.id ?? "missing_start", steps, edges, layout: undefined }; setDraftResult({ schema_version: "bluefire.ai-graph-draft-result.v1", draft_id: `local-fallback-${Date.now()}`, saved: false, scenario: localScenario, rationale: "Browser-local deterministic keyword ranking over the loaded registered catalog.", assumptions: ["No provider or server draft endpoint was used."], audit: { unsaved: true, provider: { effective_provider_id: "browser-local-fallback", model: "keyword-ranking", attempts: 0, used_fallback: true, fallback_reason: "operator_selected_local_fallback" }, selected_behavior_ids: steps.map((step) => step.behavior_id), validation: { authority: "none", catalog_snapshot_only: true } } }); setCompatibility("Local fallback preview created. It has not changed, saved, authorized, or run the active graph."); };
  const importDraft = () => { if (!draftResult) return; applyScenario({ ...draftResult.scenario, layout: Object.fromEntries(draftResult.scenario.steps.map((step, index) => [step.id, { x: 70 + (index % 4) * 300, y: 110 + Math.floor(index / 4) * 230 }])) }); setSelectedId(draftResult.scenario.steps[0]?.id ?? ""); setCompatibility(`${draftResult.draft_id} imported as unsaved graph changes. Validate before saving or preflight.`); setDraftResult(undefined); };

  return <div className={`page builder-page ${focusMode ? "builder-focus" : ""}`} onKeyDown={keyboard}>
    <PageHeader eyebrow="Scenario builder" title="Compose a typed adaptive graph" description="Connect artifact contracts and explicit outcome routes. Model proposals remain separate from policy authorization and runner execution." actions={<div className="builder-actions"><Badge tone={dirty ? "warning" : "success"} dot>{dirty ? "Unsaved graph changes" : "No unsaved edits"}</Badge><IconButton label="Undo" onClick={undo} disabled={historyIndex <= 0}><Undo2/></IconButton><IconButton label="Redo" onClick={redo} disabled={historyIndex >= history.length - 1}><Redo2/></IconButton><Button variant="secondary" onClick={() => { navigator.clipboard?.writeText(JSON.stringify(scenario, null, 2)); const url = URL.createObjectURL(new Blob([JSON.stringify(scenario, null, 2)], { type: "application/json" })); const link = document.createElement("a"); link.href = url; link.download = `${scenario.id}.json`; link.click(); URL.revokeObjectURL(url); }}><Download/>Export</Button><Button variant="secondary" onClick={() => validateMutation.mutate()} disabled={validateMutation.isPending}><Check/>Validate</Button><Button variant="primary" onClick={() => saveMutation.mutate()} disabled={saveMutation.isPending}>{saveMutation.isPending ? "Saving version" : "Save version"}</Button></div>} />
    <Panel className="objective-bar"><Sparkles/><Field label="Natural-language objective" hint="Control-plane drafting returns registered behavior contracts and typed parameters as an unsaved preview; it cannot authorize effects."><input value={objective} maxLength={4000} onChange={(event) => { setObjective(event.target.value); setDraftResult(undefined); }} placeholder="Validate fixture execution, discovery, staging, a blocked transport, and cleanup" /></Field><Button variant="secondary" onClick={() => serverDraftMutation.mutate()} disabled={!objective.trim() || serverDraftMutation.isPending}>{serverDraftMutation.isPending ? "Generating preview" : "Draft registered graph"}</Button><Button variant="ghost" onClick={offlineDraft} disabled={!objective.trim() || serverDraftMutation.isPending}>Local fallback</Button></Panel>
    {draftResult ? <Panel><PanelHeader eyebrow="Unsaved draft preview" title={draftResult.scenario.title} detail={draftResult.rationale} actions={<Badge tone="warning">Not imported · not authorized</Badge>}/><DataList items={[{ label: "Draft ID", value: <code>{draftResult.draft_id}</code> }, { label: "Provider", value: draftResult.audit.provider?.effective_provider_id ?? "Not reported" }, { label: "Fallback", value: draftResult.audit.provider?.used_fallback ? sentence(draftResult.audit.provider.fallback_reason ?? "used") : "No fallback reported" }, { label: "Graph", value: `${draftResult.scenario.steps.length} nodes · ${draftResult.scenario.edges.length} edges` }, { label: "Validation metadata", value: draftResult.audit.validation ? "Returned for review" : "Not reported" }]} />{draftResult.assumptions.length ? <Callout title="Assumptions"><ul>{draftResult.assumptions.map((item) => <li key={item}>{item}</li>)}</ul></Callout> : null}<details><summary>Provider, normalization, and validation audit</summary><pre>{JSON.stringify(draftResult.audit, null, 2)}</pre></details><Button variant="primary" onClick={importDraft}>Import as unsaved graph</Button></Panel> : null}
    {compatibility ? <div className={`compatibility-banner ${compatibility.startsWith("Incompatible") ? "error" : ""}`} role="status"><GitBranch/>{compatibility}<button onClick={() => setCompatibility(undefined)} aria-label="Dismiss compatibility message">×</button></div> : null}
    <div className={`builder-layout ${paletteOpen ? "" : "palette-hidden"} ${inspectorOpen ? "" : "inspector-hidden"}`} style={{ "--palette-width": `${paletteWidth}px`, "--inspector-width": `${inspectorWidth}px` } as CSSProperties}>
      <Panel className="palette-panel"><PanelHeader eyebrow="Registry" title="Behavior palette" actions={<Badge>{filtered.length}</Badge>} /><div className="palette-filters"><label className="search-box"><Search/><input aria-label="Search palette" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search behaviors" /></label><div><label><span className="sr-only">Platform filter</span><select aria-label="Platform filter" value={platform} onChange={(event) => setPlatform(event.target.value)}><option value="all">All platforms</option>{platforms.map((item) => <option key={item}>{item}</option>)}</select></label><label><span className="sr-only">Tier filter</span><select aria-label="Safety tier filter" value={tier} onChange={(event) => setTier(event.target.value)}><option value="all">All tiers</option><option value="safe">Safe</option><option value="controlled">Controlled</option><option value="restricted">Restricted</option></select></label></div></div><div className="palette-list">{filtered.map((behavior) => <button key={behavior.id} draggable onDragStart={(event) => { event.dataTransfer.setData("application/x-bluefire-behavior", behavior.id); event.dataTransfer.effectAllowed = "copy"; }} onClick={() => addBehavior(behavior)}><span className={`palette-icon tier-${behavior.safety_tier}`}><GitBranch/></span><span><strong>{behavior.title}</strong><small>{behavior.purpose}</small><em>{behavior.platforms.slice(0, 3).join(" · ")}</em></span><Badge tone={behavior.execution_state === "action" ? "success" : behavior.execution_state === "simulation" ? "info" : "neutral"}>{behavior.execution_state === "action" ? "Action" : behavior.execution_state === "simulation" ? "Simulation" : "Research"}</Badge></button>)}</div><p className="panel-footnote"><Filter/> Drag or select a behavior. Metadata-only entries are clearly labeled and cannot imply Execute readiness.</p></Panel>
      <Panel className="graph-panel">
        <div className="graph-topbar">
          <div className="graph-title-controls"><Field label="Scenario name"><input value={scenario.title} onChange={(event) => applyScenario({ ...scenario, title: event.target.value }, false)} /></Field><Badge tone={validationState === "valid" ? "success" : validationState === "invalid" ? "danger" : "neutral"}>{validationState === "valid" ? "Contract valid" : validationState === "invalid" ? "Needs attention" : "Not validated"}</Badge></div>
          <div className="graph-view-actions" aria-label="Graph workspace controls">
            <IconButton label={paletteOpen ? "Hide behavior palette" : "Show behavior palette"} aria-pressed={paletteOpen} onClick={() => setPaletteOpen((open) => !open)}>{paletteOpen ? <PanelLeftClose/> : <PanelLeftOpen/>}</IconButton>
            <Button size="small" variant="ghost" onClick={autoLayout} disabled={!nodes.length}><LayoutGrid/>Auto-layout</Button>
            <Button size="small" variant="ghost" onClick={fitGraph} disabled={!nodes.length}><ScanSearch/>Fit graph</Button>
            <Button size="small" variant="ghost" onClick={fitSelection} disabled={!selected}><ScanSearch/>Fit selection</Button>
            <IconButton label={inspectorOpen ? "Hide node inspector" : "Show node inspector"} aria-pressed={inspectorOpen} onClick={() => setInspectorOpen((open) => !open)}>{inspectorOpen ? <PanelRightClose/> : <PanelRightOpen/>}</IconButton>
            <IconButton label={focusMode ? "Exit graph focus mode" : "Enter graph focus mode"} aria-pressed={focusMode} onClick={() => setFocusMode((active) => !active)}>{focusMode ? <Minimize2/> : <Maximize2/>}</IconButton>
            <Button size="small" variant="ghost" onClick={() => setCommandPaletteOpen(true)}><CommandIcon/>Commands <kbd>Ctrl/Cmd K</kbd></Button>
            <label className="panel-width-control"><span>Palette width</span><input aria-label="Behavior palette width" type="range" min="220" max="420" step="10" value={paletteWidth} disabled={!paletteOpen} onChange={(event) => setPaletteWidth(Number(event.target.value))}/><output>{paletteWidth}px</output></label>
            <label className="panel-width-control"><span>Inspector width</span><input aria-label="Node inspector width" type="range" min="260" max="480" step="10" value={inspectorWidth} disabled={!inspectorOpen} onChange={(event) => setInspectorWidth(Number(event.target.value))}/><output>{inspectorWidth}px</output></label>
            {focusMode ? <span className="focus-hint">Esc to exit</span> : null}
          </div>
          <div className="graph-edit-actions"><IconButton label="Copy selected node" onClick={copySelected}><Copy/></IconButton><IconButton label="Paste node" onClick={paste} disabled={!clipboard.current}><Clipboard/></IconButton><IconButton label="Duplicate selected node" onClick={duplicateSelected} disabled={!selected}><RotateCcw/></IconButton><IconButton label="Delete selected node" onClick={() => { if (selected) void flow.deleteElements({ nodes: [{ id: selected.id }] }); }} disabled={!selected}><Trash2/></IconButton></div>
        </div>
        <div className="graph-legend" aria-label="Graph legend">
          <div><strong>Layers</strong><span>Environment <em>profile + scope</em></span><span>Behavior <em>typed intent</em></span><span>Evidence <em>artifacts + telemetry</em></span></div>
          <div><strong>Execution</strong><span><i className="legend-state state-action"/>Action <em>runner effect</em></span><span><i className="legend-state state-simulation"/>Simulation <em>safe preview</em></span><span><i className="legend-state state-research"/>Research <em>metadata only</em></span></div>
          <div><strong>Outcome routes</strong><span><i className="legend-status status-success"/>Success</span><span><i className="legend-status status-partial"/>Partial</span><span><i className="legend-status status-blocked"/>Blocked</span><span><i className="legend-status status-failed"/>Failed</span><span><i className="legend-artifact"/>Typed artifact</span></div>
        </div>
        <div className="graph-canvas" tabIndex={0} aria-label="Scenario graph canvas" onPointerDown={(event) => { const target = event.target as HTMLElement; if (!target.closest("button, input, select, textarea")) event.currentTarget.focus(); }} onDragOver={(event) => { if (event.dataTransfer.types.includes("application/x-bluefire-behavior")) event.preventDefault(); }} onDrop={drop}>
        <ReactFlow<BehaviorFlowNode, FlowEdge> nodes={nodes} edges={edges} nodeTypes={nodeTypes} onNodesChange={onNodesChange} onEdgesChange={onEdgesChange} onNodeClick={(_, node) => setSelectedId(node.id)} onNodeDragStop={onNodeDragStop} onNodesDelete={onNodesDelete} onEdgesDelete={onEdgesDelete} onBeforeDelete={confirmDelete} onConnect={onConnect} fitView minZoom={0.25} maxZoom={1.6} deleteKeyCode={["Backspace", "Delete"]} connectionLineStyle={{ stroke: "#38a8ff", strokeWidth: 2 }} proOptions={{ hideAttribution: true }}>
          <Background variant={BackgroundVariant.Dots} gap={22} size={1.2} color="rgba(117,198,255,.18)"/><MiniMap pannable zoomable nodeColor={(node) => { const behavior = behaviorMap.get((node.data as BehaviorNodeData).step.behavior_id); return behavior?.safety_tier === "restricted" ? "#ff6e79" : behavior?.safety_tier === "controlled" ? "#f7b84b" : "#38a8ff"; }} maskColor="rgba(5,9,19,.74)"/><Controls showInteractive={false}/>
        </ReactFlow>{!nodes.length ? <div className="graph-empty-overlay"><GitBranch/><strong>Start with a registered behavior</strong><span>Select one from the palette or create an offline planner draft.</span></div> : null}</div>
        <div className={`validation-bar ${validationState}`}><div><strong>{validationState === "valid" ? "Deterministic validation passed" : validationState === "invalid" ? "Graph validation returned findings" : "Validate before preflight"}</strong><span>{validationIssues[0] ?? `${scenario.steps.length} nodes · ${scenario.edges.length} outcome routes`}</span></div>{validationIssues.length > 1 ? <details><summary>{validationIssues.length} findings</summary><ul>{validationIssues.map((item) => <li key={item}>{item}</li>)}</ul></details> : null}</div>
      </Panel>
      <Panel className="inspector-panel"><PanelHeader eyebrow="Selected node" title={selectedBehavior?.title ?? "Inspector"} detail={selected ? selected.id : "Select a node to inspect its contract."} />{selected && selectedBehavior ? <Inspector scenario={scenario} step={selected} behavior={selectedBehavior} behaviors={behaviorMap} updateStep={updateStep} updateScenario={applyScenario} selectedAction={runConfig.mode === "execute" ? runConfig.actionImplementations?.[selected.id] ?? "" : ""} executeMode={runConfig.mode === "execute"} onAction={(actionId) => { const next = { ...(runConfig.actionImplementations ?? {}) }; if (actionId) next[selected.id] = actionId; else delete next[selected.id]; setRunConfig({ ...runConfig, actionImplementations: next }); }} /> : <EmptyState title="No node selected" description="Select a graph node to edit its contract, parameters, routes, and implementation choice." />}</Panel>
    </div>
    <Dialog.Root open={commandPaletteOpen} onOpenChange={setCommandPaletteOpen}>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay builder-command-overlay" />
        <Dialog.Content className="dialog-content builder-command-dialog" onEscapeKeyDown={(event) => event.stopPropagation()}>
          <div><Dialog.Title>Builder commands</Dialog.Title><Dialog.Description>Run an existing graph-editor action. Commands never authorize or start execution.</Dialog.Description></div>
          <Dialog.Close asChild><button className="dialog-close" aria-label="Close Builder commands"><X/></button></Dialog.Close>
          <div className="builder-command-list">
            <button onClick={() => runCommand(autoLayout)} disabled={!nodes.length}><LayoutGrid/><span><strong>Auto-layout</strong><small>Arrange nodes by outcome-route depth.</small></span></button>
            <button onClick={() => runCommand(fitGraph)} disabled={!nodes.length}><ScanSearch/><span><strong>Fit graph</strong><small>Frame every node in the canvas.</small></span></button>
            <button onClick={() => runCommand(fitSelection)} disabled={!selected}><ScanSearch/><span><strong>Fit selection</strong><small>Frame the selected node.</small></span></button>
            <button onClick={() => runCommand(() => setPaletteOpen((open) => !open))}>{paletteOpen ? <PanelLeftClose/> : <PanelLeftOpen/>}<span><strong>{paletteOpen ? "Hide behavior palette" : "Show behavior palette"}</strong><small>Toggle the registered behavior catalog.</small></span></button>
            <button onClick={() => runCommand(() => setInspectorOpen((open) => !open))}>{inspectorOpen ? <PanelRightClose/> : <PanelRightOpen/>}<span><strong>{inspectorOpen ? "Hide node inspector" : "Show node inspector"}</strong><small>Toggle selected-node configuration.</small></span></button>
            <button onClick={() => runCommand(() => setFocusMode((active) => !active))}>{focusMode ? <Minimize2/> : <Maximize2/>}<span><strong>{focusMode ? "Exit graph focus mode" : "Enter graph focus mode"}</strong><small>Toggle the full-window Builder workspace.</small></span></button>
            <button onClick={() => runCommand(() => validateMutation.mutate())} disabled={validateMutation.isPending}><Check/><span><strong>Validate graph</strong><small>Run deterministic contract validation.</small></span></button>
            <button onClick={() => runCommand(undo)} disabled={historyIndex <= 0}><Undo2/><span><strong>Undo</strong><small>Restore the previous graph edit.</small></span></button>
            <button onClick={() => runCommand(redo)} disabled={historyIndex >= history.length - 1}><Redo2/><span><strong>Redo</strong><small>Reapply the next graph edit.</small></span></button>
          </div>
          <p className="builder-command-footnote"><kbd>Ctrl/Cmd K</kbd> opens commands <span aria-hidden="true">·</span> <kbd>Esc</kbd> closes them</p>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  </div>;
}

function Inspector({ scenario, step, behavior, behaviors, updateStep, updateScenario, selectedAction, executeMode, onAction }: { scenario: Scenario; step: ScenarioStep; behavior: Behavior; behaviors: Map<string, Behavior>; updateStep: (id: string, update: (step: ScenarioStep) => ScenarioStep) => void; updateScenario: (scenario: Scenario) => void; selectedAction: string; executeMode: boolean; onAction: (id: string) => void }) {
  const outputs = scenario.steps.flatMap((source) => (behaviors.get(source.behavior_id)?.outputs ?? []).map((output) => ({ source, output }))).filter((item) => item.source.id !== step.id);
  const changeId = (id: string) => { if (!/^[a-z][a-z0-9_]*$/.test(id) || scenario.steps.some((item) => item.id === id && item.id !== step.id)) return; updateScenario({ ...scenario, start: scenario.start === step.id ? id : scenario.start, steps: scenario.steps.map((item) => item.id === step.id ? { ...item, id } : { ...item, inputs: Object.fromEntries(Object.entries(item.inputs).map(([name, binding]) => [name, binding.from_step === step.id ? { ...binding, from_step: id } : binding])) }), edges: scenario.edges.map((edge) => ({ ...edge, from_step: edge.from_step === step.id ? id : edge.from_step, to_step: edge.to_step === step.id ? id : edge.to_step })), layout: Object.fromEntries(Object.entries(scenario.layout ?? {}).map(([key, value]) => [key === step.id ? id : key, value])) }); };
  return <div className="inspector-body"><section><Field label="Step ID" hint="Unique lowercase snake_case identifier."><input value={step.id} onChange={(event) => changeId(event.target.value)} pattern="[a-z][a-z0-9_]*" /></Field><div className="chip-list"><Badge tone={behavior.safety_tier === "restricted" ? "danger" : behavior.safety_tier === "controlled" ? "warning" : "success"}>{behavior.safety_tier}</Badge>{behavior.platforms.map((item) => <Badge key={item}>{item}</Badge>)}</div><p>{behavior.purpose}</p></section>
    <section><h3>Action implementation</h3><Field label="Registered Execute action" hint={!executeMode ? "Simulate ignores and clears action selections." : behavior.action_ids.length ? "Execute preflight validates this registered action and binds it into the exact plan and one-time approval envelope." : "No Execute action is installed."}><select value={selectedAction} onChange={(event) => onAction(event.target.value)} disabled={!executeMode || !behavior.action_ids.length}><option value="">Resolve deterministically</option>{behavior.action_ids.map((id) => <option key={id}>{id}</option>)}</select></Field></section>
    <section><h3>Typed inputs</h3>{behavior.inputs.length ? behavior.inputs.map((input) => <Field key={input.name} label={`${input.name} · ${input.type}`} hint={input.required ? "Required artifact" : "Optional artifact"}><select value={step.inputs[input.name] ? `${step.inputs[input.name]!.from_step}:${step.inputs[input.name]!.artifact}` : ""} onChange={(event) => updateStep(step.id, (next) => { if (!event.target.value) { delete next.inputs[input.name]; return next; } const [from_step, artifact] = event.target.value.split(":", 2); return { ...next, inputs: { ...next.inputs, [input.name]: { from_step: from_step!, artifact: artifact! } } }; })}><option value="">{input.required ? "Choose compatible output" : "No binding"}</option>{outputs.filter(({ output }) => output.type === input.type && Boolean(output.multiple) === Boolean(input.multiple)).map(({ source, output }) => <option key={`${source.id}:${output.name}`} value={`${source.id}:${output.name}`}>{source.id} · {output.name}</option>)}</select></Field>) : <p>No artifact inputs.</p>}</section>
    <section><h3>Parameters</h3>{behavior.parameters.length ? behavior.parameters.map((spec) => <ParameterField key={spec.name} spec={spec} value={step.parameters[spec.name]} onChange={(value) => updateStep(step.id, (next) => ({ ...next, parameters: updateParameter(next.parameters, spec.name, value) }))} />) : <p>No configurable parameters.</p>}</section>
    <section><h3>Outcome routes</h3>{outcomes.map((outcome) => { const edge = scenario.edges.find((item) => item.from_step === step.id && item.outcome === outcome); return <Field key={outcome} label={sentence(outcome)}><select value={edge?.to_step ?? ""} onChange={(event) => updateScenario({ ...scenario, edges: [...scenario.edges.filter((item) => !(item.from_step === step.id && item.outcome === outcome)), ...(event.target.value ? [{ from_step: step.id, outcome, to_step: event.target.value }] : [])] })}><option value="">End path</option>{scenario.steps.filter((item) => item.id !== step.id).map((item) => <option key={item.id}>{item.id}</option>)}</select></Field>; })}</section>
    <section><h3>Expected observables</h3><div className="chip-list">{behavior.telemetry.map((item) => <Badge key={item} tone="info">{item}</Badge>)}</div></section>
  </div>;
}

function ParameterField({ spec, value, onChange }: { spec: Behavior["parameters"][number]; value: unknown; onChange: (value: unknown) => void }) {
  if (spec.enum?.length) {
    const selectedIndex = spec.enum.findIndex((item) => parameterValuesEqual(item, value));
    return <Field label={spec.name} hint={spec.description}><select value={selectedIndex < 0 ? "" : String(selectedIndex)} onChange={(event) => { const index = Number.parseInt(event.target.value, 10); const member = spec.enum?.[index]; if (member !== undefined) onChange(structuredClone(member)); }}><option value="" disabled>Choose an allowed value</option>{spec.enum.map((item, index) => <option key={index} value={String(index)}>{Array.isArray(item) ? item.join(", ") : String(item)}</option>)}</select></Field>;
  }
  if (spec.type === "boolean") return <label className="check-row"><input type="checkbox" checked={Boolean(value)} onChange={(event) => onChange(event.target.checked)} /><span><strong>{spec.name}</strong><small>{spec.description ?? "Boolean parameter"}</small></span></label>;
  return <Field label={spec.name} hint={spec.description}><input type={spec.type === "integer" || spec.type === "number" ? "number" : "text"} value={Array.isArray(value) ? value.join(", ") : String(value ?? "")} min={spec.minimum ?? undefined} max={spec.maximum ?? undefined} step={spec.type === "integer" ? 1 : spec.type === "number" ? "any" : undefined} required={spec.required} onChange={(event) => {
    if (spec.type === "integer" || spec.type === "number") {
      if (!event.target.value) { onChange(undefined); return; }
      const numericValue = Number(event.target.value);
      if (Number.isFinite(numericValue) && (spec.type !== "integer" || Number.isInteger(numericValue))) onChange(numericValue);
      return;
    }
    onChange(spec.type === "string_list" ? event.target.value.split(",").map((item) => item.trim()).filter(Boolean) : event.target.value);
  }} /></Field>;
}

function updateParameter(parameters: Record<string, unknown>, name: string, value: unknown) {
  const next = { ...parameters };
  if (value === undefined) delete next[name];
  else next[name] = value;
  return next;
}
