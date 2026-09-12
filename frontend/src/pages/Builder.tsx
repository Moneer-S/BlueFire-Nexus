import { useMutation, useQuery } from "@tanstack/react-query";
import * as Dialog from "@radix-ui/react-dialog";
import {
  applyEdgeChanges, applyNodeChanges, Background, BackgroundVariant, Controls, Handle, MarkerType,
  MiniMap, Position, ReactFlow, ReactFlowProvider, useNodesInitialized, useReactFlow, useUpdateNodeInternals,
  type Connection, type EdgeChange, type Node, type NodeChange, type NodeProps,
} from "@xyflow/react";
import {
  ArrowRight, Check, Clipboard, Command as CommandIcon, Copy, Download, Filter, GitBranch, LayoutGrid, Maximize2, Minimize2,
  PanelLeftClose, PanelLeftOpen, PanelRightClose, PanelRightOpen, Redo2, RotateCcw,
  ListOrdered, Network, Plus, ScanSearch, Search, Trash2, Undo2, X,
} from "lucide-react";
import { useCallback, useEffect, useId, useMemo, useRef, useState, type CSSProperties, type DragEvent, type KeyboardEvent as ReactKeyboardEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";
import "./Builder.css";
import { guaranteedInputSources, stepParameterSummary } from "../lib/graph-authoring";
import { ParameterField } from "../components/ParameterField";
import { branchLabels, GRAPH_SECTION_SIZE, graphSections, graphView, initialGraphLayout, inputLabel, inputTypeLabel, type ScenarioGraph } from "../lib/graph-view";
import { api } from "../lib/api";
import { defaultGraphView, readWorkingGraphView, writeWorkingGraphView } from "../lib/graph-view-retention";
import { initialParameterValue, shouldInitializeParameter } from "../lib/parameters";
import { deleteScenarioGraphElements, selectScenarioAlternative } from "../lib/scenario";
import { useProduct } from "../state/ProductContext";
import { useAssistancePanel, usePublishGraphAssistanceSelection } from "../state/AssistanceContext";
import { graphEditDocument, type GraphEditorDraft } from "../lib/graph-assistance";
import { GraphProposalReview } from "../components/GraphProposalReview";
import { SavedExperimentReview } from "../components/SavedExperimentReview";
import { BuilderRouteEdge } from "../components/BuilderRouteEdge";
import { BuilderRoutes } from "../components/BuilderRoutes";
import { AdaptiveMethodEditor, AdaptiveRepair } from "../components/AdaptiveMethodEditor";
import { adaptiveExecutionIssues } from "../lib/adaptive-execution";
import type { BuilderFlowEdge } from "../lib/graph-routes";
import type { ActionDefinition, Behavior, Outcome, Scenario, ScenarioStep } from "../types";
import { Badge, Button, EmptyState, ErrorState, Field, IconButton, LoadingState, PageHeader, Panel, PanelHeader, sentence } from "../components/Primitives";

const outcomes: Outcome[] = ["success", "partial", "blocked", "failed"];
const outcomeColors: Record<Outcome, string> = { success: "#45d39d", partial: "#f7b84b", blocked: "#ff7145", failed: "#ff6e79" };

interface BehaviorNodeData extends Record<string, unknown> { step: ScenarioStep; behavior?: Behavior; invalid?: boolean; method?: string; }
type BehaviorFlowNode = Node<BehaviorNodeData, "behavior">;
type FlowEdge = BuilderFlowEdge;

function behaviorNode(step: ScenarioStep, behavior: Behavior | undefined, index: number, scenario: ScenarioGraph, invalid = false): BehaviorFlowNode {
  return { id: step.id, type: "behavior", position: scenario.layout?.[step.id] ?? initialGraphLayout(scenario)[step.id] ?? { x: 48 + (index % 3) * 320, y: 48 + Math.floor(index / 3) * 210 }, data: { step, behavior, invalid } };
}

function flowEdges(scenario: ScenarioGraph, behaviors: Map<string, Behavior>): FlowEdge[] {
  const incoming = new Map<string, number>();
  const title = (id: string) => behaviors.get(scenario.steps.find((step) => step.id === id)?.behavior_id ?? "")?.title ?? id;
  const routes: FlowEdge[] = scenario.edges.map((edge, index) => {
    const lane = incoming.get(edge.to_step) ?? 0;
    incoming.set(edge.to_step, lane + 1);
    return { id: `route-${edge.from_step}-${edge.outcome}-${edge.to_step}-${index}`, source: edge.from_step, target: edge.to_step, sourceHandle: `route:${edge.outcome}`, targetHandle: "route:in", type: "outcomeRoute", ariaLabel: `Route ${index + 1}: ${title(edge.from_step)} — ${branchLabels[edge.outcome]} → ${title(edge.to_step)} (${edge.from_step} → ${edge.to_step})`, markerEnd: { type: MarkerType.ArrowClosed, color: outcomeColors[edge.outcome] }, style: { stroke: outcomeColors[edge.outcome], strokeWidth: 2 }, data: { kind: "route", outcome: edge.outcome, number: index + 1, lane, sourceTitle: title(edge.from_step), targetTitle: title(edge.to_step) } };
  });
  const artifacts: FlowEdge[] = [];
  for (const target of scenario.steps) for (const [input, binding] of Object.entries(target.inputs)) {
    const source = scenario.steps.find((item) => item.id === binding.from_step);
    const output = behaviors.get(source?.behavior_id ?? "")?.outputs.find((item) => item.name === binding.artifact);
    artifacts.push({ id: `artifact-${binding.from_step}-${binding.artifact}-${target.id}-${input}`, source: binding.from_step, target: target.id, sourceHandle: `out:${binding.artifact}`, targetHandle: `in:${input}`, label: output?.type.split(".").at(-2) ?? binding.artifact, type: "smoothstep", style: { stroke: "#3ee2dc", strokeWidth: 1.5, strokeDasharray: "5 5" }, data: { kind: "artifact", artifactType: output?.type } });
  }
  return [...routes, ...artifacts];
}

function BehaviorNode({ id, data, selected }: NodeProps<BehaviorFlowNode>) {
  const behavior = data.behavior;
  const updateNodeInternals = useUpdateNodeInternals();
  const handleSignature = JSON.stringify([
    behavior?.inputs.slice(0, 4).map((input) => input.name) ?? [],
    behavior?.outputs.slice(0, 4).map((output) => output.name) ?? [],
  ]);
  // A new method can change handles without changing the node's dimensions.
  // Refresh their bounds after rendering while preserving selection focus.
  useEffect(() => { updateNodeInternals(id); }, [id, handleSignature, updateNodeInternals]);
  return <article className={`flow-node tier-${behavior?.safety_tier ?? "safe"} ${selected ? "selected" : ""} ${data.invalid ? "invalid" : ""}`}>
    <Handle type="target" position={Position.Top} id="route:in" className="route-handle route-in" title="Continue from another step" />
    {(behavior?.inputs ?? []).slice(0, 4).map((input, index) => <Handle key={input.name} type="target" position={Position.Left} id={`in:${input.name}`} className="typed-handle input-handle" style={{ top: 55 + index * 18 }} title={`Requires ${inputTypeLabel(input.type)}: ${inputLabel(input.name)}`} />)}
    <header><span>{data.invalid ? "Needs attention" : behavior?.execution_state === "metadata_only" ? "Research only" : behavior?.execution_state === "simulation" ? "Simulation step" : "Executable step"}</span></header>
    <strong>{behavior?.title ?? "Unavailable step"}</strong>
    {data.method ? <p className="node-context">Run override: {data.method}</p> : null}
    {stepParameterSummary(data.step, behavior) ? <p className="node-context">{stepParameterSummary(data.step, behavior)}</p> : null}
    {(behavior?.outputs ?? []).slice(0, 4).map((output, index) => <Handle key={output.name} type="source" position={Position.Right} id={`out:${output.name}`} className="typed-handle output-handle" style={{ top: 55 + index * 18 }} title={`Produces ${inputTypeLabel(output.type)}: ${inputLabel(output.name)}`} />)}
    <div className="route-handles">{outcomes.map((outcome, index) => <Handle key={outcome} type="source" position={Position.Bottom} id={`route:${outcome}`} className={`route-handle route-${outcome}`} style={{ left: `${18 + index * 22}%` }} title={branchLabels[outcome]} />)}</div>
  </article>;
}

const nodeTypes = { behavior: BehaviorNode };
const edgeTypes = { outcomeRoute: BuilderRouteEdge };
const minimumGraphZoom = 0.1;
const fitViewOptions = { padding: 0.18, minZoom: minimumGraphZoom, maxZoom: 1.05 };
const deleteKeys = ["Backspace", "Delete"];
const connectionLineStyle = { stroke: "#38a8ff", strokeWidth: 2 };
const proOptions = { hideAttribution: true };

export function BuilderPage() {
  const { scenario } = useProduct();
  const [params] = useSearchParams();
  const graphJob = params.get("graph_job");
  const savedScenario = params.get("saved_scenario");
  const query = useQuery({ queryKey: ["catalog"], queryFn: api.catalog });
  if (query.isPending) return <LoadingState label="Opening graph editor" />;
  if (query.isError) return <ErrorState error={query.error} retry={() => query.refetch()} />;
  if (savedScenario) return <ReactFlowProvider><SavedExperimentReview key={`${savedScenario}:${params.get("version")}:${params.get("digest")}`} id={savedScenario} version={Number(params.get("version"))} digest={params.get("digest") ?? ""} receiverJob={params.get("receiver_job") ?? undefined} renderEditor={(review) => <GraphWorkspace behaviors={query.data.behaviors} actions={query.data.actions} review={review} />} /></ReactFlowProvider>;
  return <ReactFlowProvider>{graphJob ? <GraphProposalReview key={graphJob} jobId={graphJob} behaviors={query.data.behaviors} renderEditor={(review) => <GraphWorkspace behaviors={query.data.behaviors} actions={query.data.actions} review={review} />} /> : <GraphWorkspace key={`working:${scenario.id}`} behaviors={query.data.behaviors} actions={query.data.actions} />}</ReactFlowProvider>;
}

function GraphWorkspace({ behaviors, actions, review }: { behaviors: Behavior[]; actions: ActionDefinition[]; review?: GraphEditorDraft }) {
  const product = useProduct();
  const assistant = useAssistancePanel();
  const { scenario, setScenario, dirty } = review ?? product;
  const { markSaved, setRunConfig } = product;
  const runConfig = review ? { ...product.runConfig, mode: "simulate" as const, actionImplementations: {} } : product.runConfig;
  // Naming and other metadata edits keep the graph's presentation inputs stable.
  // The complete scenario still updates immediately for history, saves, and review.
  const graph = useMemo(() => ({ steps: scenario.steps, edges: scenario.edges, start: scenario.start, layout: scenario.layout }), [scenario.steps, scenario.edges, scenario.start, scenario.layout]);
  const behaviorMap = useMemo(() => new Map(behaviors.map((item) => [item.id, item])), [behaviors]);
  const actionMap = useMemo(() => new Map(actions.map((item) => [item.id, item])), [actions]);
  const [invalidNodes, setInvalidNodes] = useState<Set<string>>(new Set());
  const makeNodes = useCallback((value: ScenarioGraph) => value.steps.map((step, index) => behaviorNode(step, behaviorMap.get(step.behavior_id), index, value, invalidNodes.has(step.id))), [behaviorMap, invalidNodes]);
  const [initialView] = useState(() => review ? defaultGraphView(scenario) : readWorkingGraphView(scenario));
  const [nodes, setNodes] = useState<BehaviorFlowNode[]>(() => makeNodes(graph).map((node) => ({ ...node, selected: node.id === initialView.selected?.id })));
  const [edges, setEdges] = useState<FlowEdge[]>(() => flowEdges(graph, behaviorMap));
  const [selectedId, setSelectedId] = useState(initialView.selected?.id ?? "");
  const editContext = useMemo(() => {
    if (!selectedId || !scenario.steps.some(step => step.id === selectedId)) return {};
    try { return { selection: { scenario: graphEditDocument(scenario), step_id: selectedId, dirty } }; }
    catch { return { unavailable: "Complete the current graph fields before requesting a step edit. Your manual draft remains editable." }; }
  }, [scenario, selectedId, dirty]);
  const editTitle = selectedId ? behaviorMap.get(scenario.steps.find(step => step.id === selectedId)?.behavior_id ?? "")?.title ?? selectedId : undefined;
  usePublishGraphAssistanceSelection(!review, editContext.selection, editTitle, editContext.unavailable);
  const [search, setSearch] = useState(""); const [platform, setPlatform] = useState("all"); const [tier, setTier] = useState("all");
  const [compatibility, setCompatibility] = useState<string>();
  const [purposeOpen, setPurposeOpen] = useState(!scenario.purpose.trim());
  const [purposeMissing, setPurposeMissing] = useState(false);
  const purposeInput = useRef<HTMLTextAreaElement>(null);
  const [validationIssues, setValidationIssues] = useState<string[]>([]); const [validationState, setValidationState] = useState<"idle" | "valid" | "invalid">("idle");
  const [history, setHistory] = useState<Scenario[]>([structuredClone(scenario)]); const [historyIndex, setHistoryIndex] = useState(0);
  const currentScenario = useRef(scenario);
  // Local edits retain their history; a context replacement starts a new history.
  const locallyAppliedScenario = useRef(scenario);
  currentScenario.current = scenario;
  useEffect(() => {
    if (locallyAppliedScenario.current !== scenario) {
      setHistory([structuredClone(scenario)]);
      setHistoryIndex(0);
      locallyAppliedScenario.current = scenario;
    }
    setValidationState("idle"); setValidationIssues((current) => current.length ? [] : current); setInvalidNodes((current) => current.size ? new Set() : current);
  }, [scenario]);
  const [focusMode, setFocusMode] = useState(false); const [paletteOpen, setPaletteOpen] = useState(false); const [inspectorOpen, setInspectorOpen] = useState(initialView.inspector); const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  const [viewMode, setViewMode] = useState(initialView.mode);
  const [allBranches, setAllBranches] = useState(initialView.allBranches);
  const [routesOpen, setRoutesOpen] = useState(initialView.routes);
  const [showInputs, setShowInputs] = useState(initialView.inputs);
  const [expandedBranches, setExpandedBranches] = useState<Set<string>>(new Set(initialView.expanded.map(step => step.id)));
  const visibleGraph = useMemo(() => graphView(graph, allBranches, expandedBranches), [graph, allBranches, expandedBranches]);
  const [focusedSection, setFocusedSection] = useState<number | null>(initialView.section);
  // Store only presentation after a view change. Loading a malformed record does
  // not replace its bytes merely by mounting the editor.
  const viewInteracted = useRef(false);
  const lastView = useRef(JSON.stringify(initialView));
  useEffect(() => {
    if (review || !viewInteracted.current) return;
    const selected = scenario.steps.find(step => step.id === selectedId);
    const view = { selected: selected ? { id: selected.id, behavior: selected.behavior_id } : null,
      mode: viewMode, allBranches, expanded: scenario.steps.filter(step => expandedBranches.has(step.id)).map(step => ({ id: step.id, behavior: step.behavior_id })),
      section: focusedSection, inspector: inspectorOpen, routes: routesOpen, inputs: showInputs };
    const serialized = JSON.stringify(view);
    if (serialized === lastView.current) return;
    lastView.current = serialized;
    writeWorkingGraphView(scenario, view);
  }, [review, scenario, selectedId, viewMode, allBranches, expandedBranches, focusedSection, inspectorOpen, routesOpen, showInputs]);
  const [summaryZoom, setSummaryZoom] = useState(false);
  const sections = useMemo(() => graphSections(visibleGraph.ordered), [visibleGraph]);
  const sectionIndex = Math.min(focusedSection ?? 0, sections.length - 1);
  const shownSteps = viewMode === "graph" && focusedSection !== null ? sections[sectionIndex]!.steps : visibleGraph.ordered;
  const shownIds = useMemo(() => new Set(shownSteps.map((step) => step.id)), [shownSteps]);
  const displayNodes = useMemo(() => nodes.map((node) => ({ ...node, hidden: !shownIds.has(node.id), selected: node.selected && shownIds.has(node.id), data: { ...node.data, method: actionMap.get(runConfig.actionImplementations?.[node.id] ?? "")?.title } })), [actionMap, nodes, runConfig.actionImplementations, shownIds]);
  const edgeIsShown = useCallback((edge: FlowEdge) => shownIds.has(edge.source) && shownIds.has(edge.target) && (edge.data?.kind !== "artifact" || showInputs) && (edge.data?.kind !== "route" || edge.data.outcome === "success" || allBranches || expandedBranches.has(edge.source)), [allBranches, expandedBranches, showInputs, shownIds]);
  const selectedRouteId = edges.find((edge) => edge.selected && edge.data?.kind === "route" && edgeIsShown(edge))?.id;
  const displayEdges = useMemo(() => edges.map((edge) => ({ ...edge, hidden: !edgeIsShown(edge), selected: edge.selected && edgeIsShown(edge), style: { ...edge.style, opacity: selectedRouteId && edge.id !== selectedRouteId ? .45 : 1 } })), [edgeIsShown, edges, selectedRouteId]);
  const visibleRoutes = displayEdges.filter((edge) => !edge.hidden && edge.data?.kind === "route");
  const selectedRoute = visibleRoutes.find((edge) => edge.id === selectedRouteId);
  useEffect(() => {
    setSelectedId((current) => shownIds.has(current) ? current : "");
    setNodes((current) => current.some((node) => node.selected && !shownIds.has(node.id)) ? current.map((node) => ({ ...node, selected: node.selected && shownIds.has(node.id) })) : current);
    setEdges((current) => current.some((edge) => edge.selected && !edgeIsShown(edge)) ? current.map((edge) => ({ ...edge, selected: edge.selected && edgeIsShown(edge) })) : current);
  }, [edgeIsShown, shownIds, review?.readOnly]);
  useEffect(() => { if (selectedRouteId) setRoutesOpen(true); }, [selectedRouteId]);
  const routesToggleId = useId();
  const hiddenBranches = displayEdges.filter((edge) => edge.hidden && edge.data?.kind === "route").length;
  useEffect(() => {
    const index = visibleGraph.ordered.findIndex((step) => step.id === selectedId);
    if (focusedSection !== null && sections.length > 1 && index >= 0) setFocusedSection(Math.floor(index / GRAPH_SECTION_SIZE));
  }, [focusedSection, sections.length, selectedId, visibleGraph]);
  const selectStep = useCallback((id: string) => { setSelectedId(id); setNodes((items) => items.map((node) => ({ ...node, selected: node.id === id }))); setEdges((items) => items.map((edge) => ({ ...edge, selected: false }))); setInspectorOpen(true); setPaletteOpen(false); }, []);
  const selectRoute = useCallback((id: string) => { setRoutesOpen(true); setSelectedId(""); setNodes((items) => items.map((node) => ({ ...node, selected: false }))); setEdges((items) => items.map((edge) => ({ ...edge, selected: edge.id === id }))); setInspectorOpen(false); setPaletteOpen(false); }, []);
  const onEdgeClick = useCallback((_: unknown, edge: FlowEdge) => { if (edge.data?.kind === "route") selectRoute(edge.id); }, [selectRoute]);
  const onNodeClick = useCallback((_: unknown, node: BehaviorFlowNode) => selectStep(node.id), [selectStep]);
  const onSelectionChange = useCallback(({ nodes: selection }: { nodes: BehaviorFlowNode[] }) => setSelectedId(selection.at(-1)?.id ?? ""), []);
  const onMove = useCallback((_: unknown, viewport: { zoom: number }) => setSummaryZoom(viewport.zoom < 0.8), []);
  const togglePalette = () => { setPaletteOpen((open) => !open); setInspectorOpen(false); };
  const toggleInspector = () => { setInspectorOpen((open) => !open); setPaletteOpen(false); };
  const inspectorToggleId = useId();
  const [paletteWidth, setPaletteWidth] = useState(290); const [inspectorWidth, setInspectorWidth] = useState(330);
  const clipboard = useRef<ScenarioStep | undefined>(undefined); const flow = useReactFlow<BehaviorFlowNode, FlowEdge>();
  const nodesInitialized = useNodesInitialized();
  const initialFrameDone = useRef(false);
  useEffect(() => {
    if (initialFrameDone.current || !nodesInitialized || viewMode !== "graph" || !nodes.length) return;
    initialFrameDone.current = true;
    // Frame once after every visible step is measured. Later edits, panel changes,
    // and resizes preserve the operator's viewport and arranged positions.
    void flow.fitView({ ...fitViewOptions, duration: 0 });
  }, [flow, nodesInitialized, nodes.length, viewMode]);

  useEffect(() => {
    setNodes((current) => makeNodes(graph).map((node) => {
      const previous = current.find((item) => item.id === node.id);
      // Retain measurements while refreshing node data so selection never hides
      // a focused node before ResizeObserver can measure it again.
      return { ...node, measured: previous?.measured, selected: previous?.selected ?? node.id === selectedId };
    }));
    setEdges((current) => flowEdges(graph, behaviorMap).map((edge) => ({ ...edge, selected: current.some((item) => item.id === edge.id && item.selected) })));
  }, [graph, behaviorMap, makeNodes, selectedId]);
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
  const replaceScenario = useCallback((next: Scenario) => {
    locallyAppliedScenario.current = next;
    currentScenario.current = next;
    setScenario(next);
    setValidationState("idle"); setValidationIssues((current) => current.length ? [] : current); setInvalidNodes((current) => current.size ? new Set() : current);
  }, [setScenario]);
  const applyScenario = useCallback((next: Scenario, record = true) => {
    if (review?.readOnly) return;
    replaceScenario(next);
    if (record) { setHistory((items) => [...items.slice(0, historyIndex + 1), structuredClone(next)]); setHistoryIndex((index) => index + 1); }
    else setHistory((items) => [...items.slice(0, historyIndex), structuredClone(next)]);
  }, [historyIndex, replaceScenario, review?.readOnly]);

  const undo = useCallback(() => { if (review?.readOnly || historyIndex <= 0) return; const index = historyIndex - 1; setHistoryIndex(index); replaceScenario(structuredClone(history[index]!)); }, [history, historyIndex, replaceScenario, review?.readOnly]);
  const redo = useCallback(() => { if (review?.readOnly || historyIndex >= history.length - 1) return; const index = historyIndex + 1; setHistoryIndex(index); replaceScenario(structuredClone(history[index]!)); }, [history, historyIndex, replaceScenario, review?.readOnly]);

  const uniqueId = (title: string) => { const root = title.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "").replace(/^[^a-z]+/, "") || "step"; let id = root; let suffix = 2; while (scenario.steps.some((step) => step.id === id)) id = `${root}_${suffix++}`; return id; };
  const addBehavior = (behavior: Behavior, position?: { x: number; y: number }) => {
    if (review?.readOnly) return;
    const id = uniqueId(behavior.title); const step: ScenarioStep = { id, behavior_id: behavior.id, parameters: Object.fromEntries(behavior.parameters.filter(shouldInitializeParameter).map((item) => [item.name, initialParameterValue(item)])), inputs: {}, alternates: [] };
    const previous = scenario.steps.at(-1); const next: Scenario = { ...scenario, start: scenario.steps.length ? scenario.start : id, steps: [...scenario.steps, step], edges: previous ? [...scenario.edges, { from_step: previous.id, outcome: "success", to_step: id }] : scenario.edges, layout: { ...scenario.layout, [id]: position ?? { x: 70 + (scenario.steps.length % 3) * 310, y: 70 + Math.floor(scenario.steps.length / 3) * 220 } } };
    applyScenario(next); setAllBranches(true); selectStep(id); setCompatibility(`${behavior.title} added. Set its inputs and parameters in step details.`);
  };

  const updateStep = (stepId: string, update: (step: ScenarioStep) => ScenarioStep) => applyScenario({ ...scenario, steps: scenario.steps.map((step) => step.id === stepId ? update(structuredClone(step)) : step) });
  const useAlternative = (stepId: string, behaviorId: string) => {
    if (review?.readOnly) return;
    try {
      applyScenario(selectScenarioAlternative(scenario, stepId, behaviorId, behaviorMap));
      setCompatibility(`${behaviorMap.get(behaviorId)!.title} selected. Inputs, parameters, and connections are preserved. Validate and review the changed run before executing.`);
    } catch (error) { setCompatibility(error instanceof Error ? error.message : "This alternative is unavailable."); }
  };
  const onNodesChange = useCallback((changes: NodeChange<BehaviorFlowNode>[]) => setNodes((items) => applyNodeChanges(review?.readOnly ? changes.filter((change) => change.type === "select" || change.type === "dimensions") : changes, items)), [review?.readOnly]);
  const onEdgesChange = useCallback((changes: EdgeChange<FlowEdge>[]) => setEdges((items) => applyEdgeChanges(review?.readOnly ? changes.filter((change) => change.type === "select") : changes, items)), [review?.readOnly]);
  const onNodeDragStop = (_: unknown, node: BehaviorFlowNode) => applyScenario({ ...scenario, layout: { ...scenario.layout, [node.id]: { x: Math.round(node.position.x), y: Math.round(node.position.y) } } });
  const onDelete = ({ nodes: deletedNodes, edges: deletedEdges }: { nodes: BehaviorFlowNode[]; edges: FlowEdge[] }) => {
    if (review?.readOnly) return;
    const deletedNodeIds = deletedNodes.map((node) => node.id);
    const next = deleteScenarioGraphElements(scenario, deletedNodeIds, deletedEdges.map((edge) => ({
      kind: edge.data?.kind,
      outcome: edge.data?.outcome,
      source: edge.source,
      target: edge.target,
      sourceHandle: edge.sourceHandle,
      targetHandle: edge.targetHandle,
    })));
    applyScenario(next);
    if (deletedNodeIds.includes(selectedId)) setSelectedId(next.steps[0]?.id ?? "");
  };
  const confirmDelete = useCallback(async ({ nodes: requestedNodes, edges: requestedEdges }: { nodes: BehaviorFlowNode[]; edges: FlowEdge[] }) => {
    if (review?.readOnly) return false;
    const visibleNodes = requestedNodes.filter((node) => shownIds.has(node.id));
    const visibleEdges = requestedEdges.filter(edgeIsShown);
    if (!visibleNodes.length && !visibleEdges.length) return false;
    const parts = [visibleNodes.length ? `${visibleNodes.length} node${visibleNodes.length === 1 ? "" : "s"}` : "", visibleEdges.length ? `${visibleEdges.length} edge${visibleEdges.length === 1 ? "" : "s"}` : ""].filter(Boolean);
    return window.confirm(`Delete ${parts.join(" and ")} from this scenario?\n\nConnections to the deleted steps will also be removed. You can undo the confirmed change.`) ? { nodes: visibleNodes, edges: visibleEdges } : false;
  }, [edgeIsShown, shownIds, review?.readOnly]);

  const onConnect = (connection: Connection) => {
    if (review?.readOnly) return;
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
      if (!output || !input || output.type !== input.type || Boolean(output.multiple) !== Boolean(input.multiple)) { setCompatibility(`This step requires ${inputTypeLabel(input?.type ?? "compatible results")}${input?.multiple ? " (multiple values)" : ""}; the selected output provides ${inputTypeLabel(output?.type ?? "unknown results")}${output?.multiple ? " (multiple values)" : ""}. Choose a compatible output in step details.`); return; }
      if (!guaranteedInputSources(scenario, target.id).has(source.id)) { setCompatibility("Connect the producer before this step on every incoming path, then choose its output in step details."); return; }
      updateStep(target.id, (step) => ({ ...step, inputs: { ...step.inputs, [inputName]: { from_step: source.id, artifact: outputName } } })); setCompatibility(`Connected ${inputLabel(outputName)} to ${inputLabel(inputName)}.`);
    }
  };

  const copySelected = () => { const selected = scenario.steps.find((step) => step.id === selectedId && shownIds.has(step.id)); if (!selected) return false; clipboard.current = structuredClone(selected); setCompatibility(`${selected.id} copied.`); return true; };
  const paste = () => { if (review?.readOnly || !clipboard.current) return; const source = clipboard.current; const behavior = behaviorMap.get(source.behavior_id); if (!behavior) return; const id = uniqueId(`${source.id} copy`); const step = { ...structuredClone(source), id, inputs: {} }; const origin = scenario.layout?.[source.id] ?? { x: 60, y: 60 }; applyScenario({ ...scenario, steps: [...scenario.steps, step], layout: { ...scenario.layout, [id]: { x: origin.x + 36, y: origin.y + 36 } } }); setAllBranches(true); selectStep(id); };
  const duplicateSelected = () => { if (!review?.readOnly && copySelected()) window.setTimeout(paste, 0); };
  const keyboard = (event: ReactKeyboardEvent<HTMLDivElement>) => {
    const target = event.target as HTMLElement;
    if (event.defaultPrevented || commandPaletteOpen || target.closest("input, select, textarea, [contenteditable]:not([contenteditable='false'])")) return;
    if (!(event.ctrlKey || event.metaKey) || event.altKey) return;
    const key = event.key.toLowerCase();
    if (!["z", "c", "v", "d"].includes(key)) return;
    event.preventDefault();
    event.stopPropagation();
    if (key === "z") { if (event.shiftKey) redo(); else undo(); }
    else if (key === "c") copySelected();
    else if (key === "v") paste();
    else duplicateSelected();
  };

  const validateMutation = useMutation({
    mutationFn: (submitted: Scenario) => {
      const issues = adaptiveExecutionIssues(submitted, behaviorMap, actionMap);
      return issues.length ? Promise.resolve({ valid: false, issues: issues.map(issue => issue.message) }) : api.validate(submitted);
    },
    onSuccess: (result, submitted) => {
      if (JSON.stringify(currentScenario.current) !== JSON.stringify(submitted)) return;
      const issues = (result.issues ?? []).map((item) => typeof item === "string" ? item : JSON.stringify(item));
      setValidationIssues(issues); setValidationState(result.valid ? "valid" : "invalid");
      setInvalidNodes(new Set(submitted.steps.filter((step) => issues.some((issue) => issue.includes(step.id))).map((step) => step.id)));
    },
    onError: (error, submitted) => {
      if (JSON.stringify(currentScenario.current) !== JSON.stringify(submitted)) return;
      const message = error instanceof Error ? error.message : "Validation failed.";
      setValidationIssues([message]); setValidationState("invalid");
    },
  });
  const saveMutation = useMutation({ mutationFn: (submitted: Scenario) => api.saveScenarioVersion(submitted), onSuccess: ({ scenario: saved }, submitted) => { const currentSaved = markSaved(submitted); setCompatibility(`Version ${saved.version} saved${currentSaved ? "." : "; newer changes remain unsaved."}`); }, onError: (error) => setCompatibility(`Save refused: ${error instanceof Error ? error.message : "The scenario version could not be saved."}`) });
  const selected = scenario.steps.find((step) => step.id === selectedId && shownIds.has(step.id)); const selectedBehavior = behaviorMap.get(selected?.behavior_id ?? "");
  const filtered = behaviors.filter((behavior) => { const haystack = `${behavior.title} ${behavior.purpose} ${behavior.capabilities.join(" ")}`.toLowerCase(); return (!search || haystack.includes(search.toLowerCase())) && (platform === "all" || behavior.platforms.includes(platform)) && (tier === "all" || behavior.safety_tier === tier); });
  const platforms = [...new Set(behaviors.flatMap((item) => item.platforms))].sort();

  const drop = (event: DragEvent<HTMLDivElement>) => { event.preventDefault(); const id = event.dataTransfer.getData("application/x-bluefire-behavior"); const behavior = behaviorMap.get(id); if (!behavior) return; addBehavior(behavior, flow.screenToFlowPosition({ x: event.clientX, y: event.clientY })); };
  const fitGraph = () => { void flow.fitView({ padding: 0.18, duration: 300, maxZoom: 1.05, minZoom: minimumGraphZoom }); };
  const showSection = (value: string) => {
    setFocusedSection(value === "all" ? null : Number(value));
    const first = value === "all" ? undefined : sections[Number(value)]?.steps[0];
    if (first) { setSelectedId(first.id); setNodes((items) => items.map((node) => ({ ...node, selected: node.id === first.id }))); }
    setInspectorOpen(false); setPaletteOpen(false);
    window.setTimeout(fitGraph, 0);
  };
  const fitSelection = () => { if (selectedId) void flow.fitView({ nodes: [{ id: selectedId }], padding: 0.48, duration: 300, maxZoom: 1.15 }); };
  const autoLayout = () => {
    if (review?.readOnly || !scenario.steps.length) return;
    applyScenario({ ...scenario, layout: initialGraphLayout(scenario) }); setCompatibility("Steps arranged in reading order. Use Undo to restore your positions.");
    window.setTimeout(fitGraph, 0);
  };
  const runCommand = (action: () => void) => { setCommandPaletteOpen(false); action(); };

  const saveVersion = () => {
    if (!scenario.purpose.trim()) {
      setPurposeMissing(true); setPurposeOpen(true);
      setCompatibility("Describe the question this experiment will answer before saving.");
      window.requestAnimationFrame(() => purposeInput.current?.focus());
      return;
    }
    if (!scenario.steps.length) { setCompatibility("Add the first step before saving this experiment."); setPaletteOpen(true); return; }
    const retryIssues = adaptiveExecutionIssues(scenario, behaviorMap, actionMap);
    if (retryIssues.length) { setCompatibility(retryIssues[0]!.message); if (!retryIssues[0]!.missingStep) selectStep(retryIssues[0]!.stepId); return; }
    saveMutation.mutate(structuredClone(scenario));
  };

  const displayedValidation = validationState === "idle" && review?.validated ? "valid" : validationState;
  return <div className={`page builder-page workbench-builder ${focusMode ? "builder-focus" : ""} ${showInputs ? "show-inputs" : ""} ${summaryZoom ? "graph-summary-zoom" : ""}`} onPointerDownCapture={() => { viewInteracted.current = true; }} onClickCapture={() => { viewInteracted.current = true; }} onKeyDownCapture={(event) => { viewInteracted.current = true; keyboard(event); }}>
    <PageHeader title={scenario.title} description={review ? review.description : undefined} actions={<div className="builder-actions"><Badge tone={review?.readOnly ? "neutral" : dirty ? "warning" : "neutral"} dot>{review?.statusLabel ?? (dirty ? "Unsaved changes" : "Working copy")}</Badge><IconButton label="Undo" onClick={undo} disabled={review?.readOnly || historyIndex <= 0}><Undo2/></IconButton><IconButton label="Redo" onClick={redo} disabled={review?.readOnly || historyIndex >= history.length - 1}><Redo2/></IconButton><Button variant="secondary" onClick={() => { const url = URL.createObjectURL(new Blob([JSON.stringify(scenario, null, 2)], { type: "application/json" })); const link = document.createElement("a"); link.href = url; link.download = `${scenario.id}.json`; link.click(); URL.revokeObjectURL(url); }}><Download/>Export</Button><Button variant="secondary" onClick={() => validateMutation.mutate(structuredClone(scenario))} disabled={validateMutation.isPending}><Check/>Validate</Button>{review ? review.controls : <><Button variant="secondary" onClick={saveVersion} disabled={saveMutation.isPending}>{saveMutation.isPending ? "Saving version" : "Save version"}</Button><Link className="button button-primary button-medium" to="/runs?prepare=1">Review run<ArrowRight/></Link></>}</div>} />
    {review?.details}
    <AdaptiveRepair scenario={scenario} behaviors={behaviorMap} actions={actionMap} overrides={runConfig.actionImplementations} onSelect={selectStep} onChange={applyScenario} readOnly={review?.readOnly} />
    <div className="experiment-summary"><details open={purposeOpen} onToggle={(event) => setPurposeOpen(event.currentTarget.open)}><summary>{scenario.purpose.trim() ? "Experiment purpose" : "Describe the experiment question"}</summary><Field label="Experiment question" hint="What do you want to learn or verify? Required before saving."><textarea aria-label="Experiment question" ref={purposeInput} rows={2} disabled={review?.readOnly} value={scenario.purpose} required aria-invalid={purposeMissing && !scenario.purpose.trim()} onChange={(event) => { setPurposeMissing(false); applyScenario({ ...scenario, purpose: event.target.value }, false); }} placeholder="Describe the behavior, observation or detection you want to test." /></Field></details>{!review ? <div className="builder-assistance-actions"><Button variant="ghost" size="small" onClick={() => assistant?.setOpen(true)} disabled={!assistant}>Plan with Assistant</Button><Link className="button button-ghost button-small" to="/scenarios">Browse examples</Link></div> : null}</div>
    {compatibility ? <div className={`compatibility-banner ${compatibility.startsWith("Incompatible") ? "error" : ""}`} role="status"><GitBranch/>{compatibility}<button onClick={() => setCompatibility(undefined)} aria-label="Dismiss compatibility message">×</button></div> : null}
    <div className="graph-review-editor">
    <div className={`builder-layout ${paletteOpen ? "" : "palette-hidden"} ${inspectorOpen ? "" : "inspector-hidden"}`} style={{ "--palette-width": `${paletteWidth}px`, "--inspector-width": `${inspectorWidth}px` } as CSSProperties}>
      <Panel className="palette-panel" hidden={!paletteOpen}>{paletteOpen ? <><PanelHeader eyebrow="Available steps" title="Add a step" actions={<Badge>{filtered.length}</Badge>} /><div className="palette-filters"><label className="search-box"><Search/><input aria-label="Search palette" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Find a step" /></label><div><label><span className="sr-only">Platform filter</span><select aria-label="Platform filter" value={platform} onChange={(event) => setPlatform(event.target.value)}><option value="all">All platforms</option>{platforms.map((item) => <option key={item}>{item}</option>)}</select></label><label><span className="sr-only">Tier filter</span><select aria-label="Safety tier filter" value={tier} onChange={(event) => setTier(event.target.value)}><option value="all">All tiers</option><option value="safe">Safe</option><option value="controlled">Controlled</option><option value="restricted">Restricted</option></select></label></div></div><div className="palette-list">{filtered.map((behavior) => <button key={behavior.id} disabled={review?.readOnly} draggable={!review?.readOnly} onDragStart={(event) => { event.dataTransfer.setData("application/x-bluefire-behavior", behavior.id); event.dataTransfer.effectAllowed = "copy"; }} onClick={() => addBehavior(behavior)}><span className={`palette-icon tier-${behavior.safety_tier}`}><GitBranch/></span><span><strong>{behavior.title}</strong><small>{behavior.purpose}</small><em>{behavior.platforms.slice(0, 3).join(" · ")}</em></span><Badge tone={behavior.execution_state === "action" ? "success" : behavior.execution_state === "simulation" ? "info" : "neutral"}>{behavior.execution_state === "action" ? "Action" : behavior.execution_state === "simulation" ? "Simulation" : "Research"}</Badge></button>)}</div><p className="panel-footnote"><Filter/> Choose a step to add it. Research entries describe techniques and cannot execute.</p></> : null}</Panel>
      <Panel className="graph-panel">
        <div className="graph-topbar">
          <div className="graph-title-controls"><Field label="Experiment name"><input disabled={review?.readOnly} value={scenario.title} onChange={(event) => applyScenario({ ...scenario, title: event.target.value }, false)} /></Field><Badge tone={displayedValidation === "valid" ? "success" : displayedValidation === "invalid" ? "danger" : "neutral"}>{displayedValidation === "valid" ? "Ready for review" : displayedValidation === "invalid" ? "Needs attention" : "Not validated"}</Badge></div>
          <div className="graph-view-actions" aria-label="Graph workspace controls">
            <IconButton label={paletteOpen ? "Hide behavior palette" : "Show behavior palette"} aria-pressed={paletteOpen} onClick={togglePalette}>{paletteOpen ? <PanelLeftClose/> : <PanelLeftOpen/>}</IconButton><Button size="small" variant="secondary" onClick={togglePalette}><Plus/>Add step</Button><div className="view-toggle" aria-label="Experiment view"><button aria-pressed={viewMode === "graph"} onClick={() => setViewMode("graph")}><Network/>Canvas</button><button aria-pressed={viewMode === "steps"} onClick={() => setViewMode("steps")}><ListOrdered/>Steps</button></div>
            <Button size="small" variant="ghost" onClick={autoLayout} disabled={review?.readOnly || !nodes.length}><LayoutGrid/>Auto-layout</Button>
            <Button size="small" variant="ghost" onClick={fitGraph} disabled={!nodes.length}><ScanSearch/>Fit graph</Button>
            <Button size="small" variant="ghost" onClick={fitSelection} disabled={!selected}><ScanSearch/>Fit selection</Button>
            <IconButton id={inspectorToggleId} label={inspectorOpen ? "Hide node inspector" : "Show node inspector"} aria-pressed={inspectorOpen} onClick={toggleInspector}>{inspectorOpen ? <PanelRightClose/> : <PanelRightOpen/>}</IconButton>
            <IconButton label={focusMode ? "Exit graph focus mode" : "Enter graph focus mode"} aria-pressed={focusMode} onClick={() => setFocusMode((active) => !active)}>{focusMode ? <Minimize2/> : <Maximize2/>}</IconButton>
            <Button size="small" variant="ghost" onClick={() => setCommandPaletteOpen(true)}><CommandIcon/>Commands <kbd>Ctrl/Cmd K</kbd></Button>
            <details className="graph-options"><summary>View options</summary><div>
            <label className="check-row"><input type="checkbox" checked={allBranches} onChange={(event) => setAllBranches(event.target.checked)}/>Show all branches and disconnected steps</label>
            <label className="check-row"><input type="checkbox" checked={showInputs} onChange={(event) => setShowInputs(event.target.checked)}/>Show input connections</label>
            <label className="panel-width-control"><span>Palette width</span><input aria-label="Behavior palette width" type="range" min="220" max="420" step="10" value={paletteWidth} disabled={!paletteOpen} onChange={(event) => setPaletteWidth(Number(event.target.value))}/><output>{paletteWidth}px</output></label>
            <label className="panel-width-control"><span>Inspector width</span><input aria-label="Node inspector width" type="range" min="260" max="480" step="10" value={inspectorWidth} disabled={!inspectorOpen} onChange={(event) => setInspectorWidth(Number(event.target.value))}/><output>{inspectorWidth}px</output></label></div></details>
            {focusMode ? <span className="focus-hint">Esc to exit</span> : null}
          </div>
          <div className="graph-edit-actions"><IconButton label="Copy selected node" onClick={copySelected} disabled={!selected}><Copy/></IconButton><IconButton label="Paste node" onClick={paste} disabled={review?.readOnly || !clipboard.current}><Clipboard/></IconButton><IconButton label="Duplicate selected node" onClick={duplicateSelected} disabled={review?.readOnly || !selected}><RotateCcw/></IconButton><IconButton label="Delete selected node" onClick={() => { if (selected) void flow.deleteElements({ nodes: [{ id: selected.id }] }); }} disabled={review?.readOnly || !selected}><Trash2/></IconButton></div>
        </div>
        {viewMode === "graph" && sections.length > 1 ? <nav className="graph-sections" aria-label="Experiment sections"><Button size="small" variant="ghost" disabled={focusedSection === null || sectionIndex === 0} onClick={() => showSection(String(sectionIndex - 1))}>Previous section</Button><label>Path section<select value={focusedSection === null ? "all" : sectionIndex} onChange={(event) => showSection(event.target.value)}>{sections.map((section, index) => <option key={index} value={index}>{section.title}</option>)}<option value="all">All sections</option></select></label><Button size="small" variant="ghost" disabled={focusedSection === null || sectionIndex === sections.length - 1} onClick={() => showSection(String(sectionIndex + 1))}>Next section</Button><small>Focus a section to read and edit it. All sections shows their connections.</small></nav> : null}
        <div className="graph-disclosure" role="status"><span>{shownIds.size} of {scenario.steps.length} steps shown{scenario.steps.length - shownIds.size ? ` · ${scenario.steps.length - shownIds.size} hidden` : ""} · {hiddenBranches} branches hidden. Review run includes the whole experiment.</span><button onClick={() => { setAllBranches((value) => !value); if (!allBranches) { setRoutesOpen(true); setInspectorOpen(false); setPaletteOpen(false); } }}>{allBranches ? "Focus on success path" : "Show all branches"}</button>{viewMode === "graph" ? <button id={routesToggleId} aria-expanded={routesOpen} onClick={() => { setRoutesOpen((value) => !value); if (!routesOpen) { setInspectorOpen(false); setPaletteOpen(false); } }}>{routesOpen ? "Hide route list" : "Show route list"}</button> : null}{selected && scenario.edges.some((edge) => edge.from_step === selected.id && edge.outcome !== "success") && !allBranches ? <button onClick={() => setExpandedBranches((previous) => { const next = new Set(previous); if (next.has(selected.id)) next.delete(selected.id); else next.add(selected.id); return next; })}>{expandedBranches.has(selected.id) ? "Collapse selected branches" : "Expand selected branches"}</button> : null}</div>
        {viewMode === "steps" ? <ol className="ordered-steps" aria-label="Experiment steps">{visibleGraph.ordered.map((step, index) => { const behavior = behaviorMap.get(step.behavior_id); return <li key={step.id}><button aria-pressed={selectedId === step.id} onClick={() => selectStep(step.id)}><span className="step-number">{index + 1}</span><span><strong>{behavior?.title ?? "Unavailable step"}</strong><small>{behavior?.purpose}</small><span className="step-routes">{scenario.edges.filter((edge) => edge.from_step === step.id).map((edge) => <em key={edge.outcome}>{branchLabels[edge.outcome]} → {behaviorMap.get(scenario.steps.find((item) => item.id === edge.to_step)?.behavior_id ?? "")?.title ?? edge.to_step}</em>)}</span></span><Badge>{behavior?.execution_state === "action" ? "Executable" : behavior?.execution_state === "simulation" ? "Simulated" : "Research"}</Badge></button></li>; })}</ol> : null}
        <div className={`graph-stage ${routesOpen ? "routes-open" : ""}`} hidden={viewMode !== "graph"}>
        <div className="graph-canvas" tabIndex={0} aria-label="Scenario graph canvas" onKeyDown={(event) => {
          if (event.key !== "Enter" && event.key !== " ") return;
          const id = event.target instanceof Element ? event.target.closest(".react-flow__edge")?.getAttribute("data-id") : null;
          if (id && visibleRoutes.some((edge) => edge.id === id)) { event.preventDefault(); selectRoute(id); }
        }} onPointerDown={(event) => { const target = event.target as HTMLElement; if (!target.closest("button, input, select, textarea")) event.currentTarget.focus(); }} onDragOver={(event) => { if (event.dataTransfer.types.includes("application/x-bluefire-behavior")) event.preventDefault(); }} onDrop={drop}>
        <ReactFlow<BehaviorFlowNode, FlowEdge> nodes={displayNodes} edges={displayEdges} nodesDraggable={!review?.readOnly} nodesConnectable={!review?.readOnly} nodeTypes={nodeTypes} edgeTypes={edgeTypes} onEdgeClick={onEdgeClick} onNodesChange={onNodesChange} onEdgesChange={onEdgesChange} onNodeClick={onNodeClick} onSelectionChange={onSelectionChange} onMove={onMove} onNodeDragStop={onNodeDragStop} onDelete={onDelete} onBeforeDelete={confirmDelete} onConnect={onConnect} fitView fitViewOptions={fitViewOptions} minZoom={minimumGraphZoom} maxZoom={1.6} deleteKeyCode={review?.readOnly ? null : deleteKeys} connectionLineStyle={connectionLineStyle} proOptions={proOptions}>
          <Background variant={BackgroundVariant.Dots} gap={22} size={1.2} color="rgba(117,198,255,.18)"/>{allBranches && scenario.steps.length > 12 ? <MiniMap pannable zoomable nodeColor={(node) => { const behavior = behaviorMap.get((node.data as BehaviorNodeData).step.behavior_id); return behavior?.safety_tier === "restricted" ? "#ff6e79" : behavior?.safety_tier === "controlled" ? "#f7b84b" : "#38a8ff"; }} maskColor="rgba(5,9,19,.74)"/> : null}<Controls showInteractive={false}/>
        </ReactFlow>{!nodes.length ? <div className="graph-empty-overlay"><GitBranch/><strong>Add the first step</strong><span>Choose a method to begin designing this experiment.</span><Button variant="primary" disabled={review?.readOnly} onClick={() => { setPaletteOpen(true); setInspectorOpen(false); }}>Add first step</Button></div> : null}</div>
        {routesOpen ? <BuilderRoutes routes={visibleRoutes} total={scenario.edges.length} selected={selectedRoute} readOnly={Boolean(review?.readOnly)} select={selectRoute} inspect={(source) => { selectStep(source); setRoutesOpen(false); window.requestAnimationFrame(() => document.getElementById(inspectorToggleId)?.focus()); }} remove={(id) => { void flow.deleteElements({ edges: [{ id }] }); }} close={() => { setRoutesOpen(false); document.getElementById(routesToggleId)?.focus(); }} /> : null}
        </div>
        <div className={`validation-bar ${displayedValidation}`}><div><strong>{displayedValidation === "valid" ? "Experiment validated" : displayedValidation === "invalid" ? "Check the highlighted steps" : review?.readOnly ? "Read-only view · not validated here" : "Validate this experiment before run review"}</strong><span>{validationIssues[0] ?? `${scenario.steps.length} steps · ${scenario.edges.length} branches`}</span></div>{validationIssues.length > 1 ? <details><summary>{validationIssues.length} findings</summary><ul>{validationIssues.map((item) => <li key={item}>{item}</li>)}</ul></details> : null}</div>
      </Panel>
      <Panel className="inspector-panel" hidden={!inspectorOpen}>{inspectorOpen ? <><PanelHeader eyebrow="Step details" title={selectedBehavior?.title ?? "Select a step"} actions={<IconButton label="Close step details" onClick={() => { setInspectorOpen(false); document.getElementById(inspectorToggleId)?.focus(); }}><X/></IconButton>} />{selected && selectedBehavior ? <fieldset className="graph-review-editor" disabled={review?.readOnly}><Inspector scenario={scenario} step={selected} behavior={selectedBehavior} behaviors={behaviorMap} actions={actionMap} onAlternative={useAlternative} updateStep={updateStep} updateScenario={applyScenario} selectedAction={runConfig.actionImplementations?.[selected.id] ?? ""} allowRunOverride={!review} onAction={(actionId) => { const next = { ...(runConfig.actionImplementations ?? {}) }; if (actionId) next[selected.id] = actionId; else delete next[selected.id]; setRunConfig({ ...runConfig, actionImplementations: next }); }} /></fieldset> : <EmptyState title="Select a step" description="Select a step on the canvas or in the list to choose its method, inputs, and branches." />}</> : null}</Panel>
    </div>
    </div>
    <Dialog.Root open={commandPaletteOpen} onOpenChange={setCommandPaletteOpen}>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay builder-command-overlay" />
        <Dialog.Content className="dialog-content builder-command-dialog" onEscapeKeyDown={(event) => event.stopPropagation()}>
          <div><Dialog.Title>Builder commands</Dialog.Title><Dialog.Description>Run an existing graph-editor action. Commands never authorize or start execution.</Dialog.Description></div>
          <Dialog.Close asChild><button className="dialog-close" aria-label="Close Builder commands"><X/></button></Dialog.Close>
          <div className="builder-command-list">
            <button onClick={() => runCommand(autoLayout)} disabled={review?.readOnly || !nodes.length}><LayoutGrid/><span><strong>Auto-layout</strong><small>Arrange steps in reading order.</small></span></button>
            <button onClick={() => runCommand(fitGraph)} disabled={!nodes.length}><ScanSearch/><span><strong>Fit graph</strong><small>Frame the visible path at a readable scale.</small></span></button>
            <button onClick={() => runCommand(fitSelection)} disabled={!selected}><ScanSearch/><span><strong>Fit selection</strong><small>Frame the selected node.</small></span></button>
            <button onClick={() => runCommand(togglePalette)}>{paletteOpen ? <PanelLeftClose/> : <PanelLeftOpen/>}<span><strong>{paletteOpen ? "Hide behavior palette" : "Show behavior palette"}</strong><small>Toggle the registered behavior catalog.</small></span></button>
            <button onClick={() => runCommand(toggleInspector)}>{inspectorOpen ? <PanelRightClose/> : <PanelRightOpen/>}<span><strong>{inspectorOpen ? "Hide node inspector" : "Show node inspector"}</strong><small>Toggle selected-node configuration.</small></span></button>
            <button onClick={() => runCommand(() => setFocusMode((active) => !active))}>{focusMode ? <Minimize2/> : <Maximize2/>}<span><strong>{focusMode ? "Exit graph focus mode" : "Enter graph focus mode"}</strong><small>Toggle the full-window Builder workspace.</small></span></button>
            <button onClick={() => runCommand(() => validateMutation.mutate(structuredClone(scenario)))} disabled={validateMutation.isPending}><Check/><span><strong>Validate graph</strong><small>Run deterministic contract validation.</small></span></button>
            <button onClick={() => runCommand(undo)} disabled={review?.readOnly || historyIndex <= 0}><Undo2/><span><strong>Undo</strong><small>Restore the previous graph edit.</small></span></button>
            <button onClick={() => runCommand(redo)} disabled={review?.readOnly || historyIndex >= history.length - 1}><Redo2/><span><strong>Redo</strong><small>Reapply the next graph edit.</small></span></button>
          </div>
          <p className="builder-command-footnote"><kbd>Ctrl/Cmd K</kbd> opens commands <span aria-hidden="true">·</span> <kbd>Esc</kbd> closes them</p>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  </div>;
}

function Inspector({ scenario, step, behavior, behaviors, actions, updateStep, updateScenario, selectedAction, allowRunOverride, onAction, onAlternative }: { scenario: Scenario; step: ScenarioStep; behavior: Behavior; behaviors: Map<string, Behavior>; actions: Map<string, ActionDefinition>; updateStep: (id: string, update: (step: ScenarioStep) => ScenarioStep) => void; updateScenario: (scenario: Scenario) => void; selectedAction: string; allowRunOverride: boolean; onAction: (id: string) => void; onAlternative: (stepId: string, behaviorId: string) => void }) {
  const sources = guaranteedInputSources(scenario, step.id);
  const outputs = scenario.steps.flatMap((source) => (behaviors.get(source.behavior_id)?.outputs ?? []).map((output) => ({ source, output }))).filter((item) => sources.has(item.source.id));
  const changeId = (id: string) => { if (!/^[a-z][a-z0-9_]*$/.test(id) || scenario.steps.some((item) => item.id === id && item.id !== step.id)) return; updateScenario({ ...scenario, ...(scenario.adaptive_execution ? { adaptive_execution: { ...scenario.adaptive_execution, steps: scenario.adaptive_execution.steps.map(item => item.step_id === step.id ? { ...item, step_id: id } : item) } } : {}), start: scenario.start === step.id ? id : scenario.start, steps: scenario.steps.map((item) => item.id === step.id ? { ...item, id } : { ...item, inputs: Object.fromEntries(Object.entries(item.inputs).map(([name, binding]) => [name, binding.from_step === step.id ? { ...binding, from_step: id } : binding])) }), edges: scenario.edges.map((edge) => ({ ...edge, from_step: edge.from_step === step.id ? id : edge.from_step, to_step: edge.to_step === step.id ? id : edge.to_step })), layout: Object.fromEntries(Object.entries(scenario.layout ?? {}).map(([key, value]) => [key === step.id ? id : key, value])) }); };
  return <div className="inspector-body"><section><div className="chip-list"><Badge tone={behavior.safety_tier === "restricted" ? "danger" : behavior.safety_tier === "controlled" ? "warning" : "success"}>{behavior.safety_tier}</Badge>{behavior.platforms.map((item) => <Badge key={item}>{item}</Badge>)}</div><p>{behavior.purpose}</p></section>
    <section><h3>Method</h3><p><strong>{behavior.title}</strong> is saved with this experiment. Choose an alternative below to change the reusable step.</p><Field label="Run method override" hint={!allowRunOverride ? "Adopt this reviewed experiment before choosing a run override." : behavior.action_ids.length ? "Optional for the current run. Retained across Simulate and Execute; reviewed for compatibility and approval before execution. It is not part of the saved experiment." : "This step has no executable method. Choose a supported alternative to execute it."}><select aria-label="Run method override" value={selectedAction} onChange={(event) => onAction(event.target.value)} disabled={!allowRunOverride || !behavior.action_ids.length}><option value="">Recommended at run review</option>{behavior.action_ids.map((id) => <option key={id} value={id}>{actions.get(id)?.title ?? id}{actions.get(id)?.platforms.length ? ` · ${actions.get(id)!.platforms.join(" / ")}` : ""}</option>)}</select></Field></section>
    {(behavior.compatible_behaviors?.length || step.alternates.length) ? <section><h3>Alternatives</h3><p>Save compatible methods for reuse, or choose a different primary method now. Configure an adaptive retry below to permit changes during execution.</p>{[...new Set([...(behavior.compatible_behaviors ?? []), ...step.alternates])].filter((id) => id !== behavior.id).map((id) => <div className="alternative-method" key={id}><label className="check-row"><input type="checkbox" checked={step.alternates.includes(id)} onChange={(event) => updateStep(step.id, (next) => ({ ...next, alternates: event.target.checked ? [...next.alternates, id] : next.alternates.filter((value) => value !== id) }))}/><span>{behaviors.get(id)?.title ?? id}</span></label><p>{behaviors.get(id)?.purpose ?? "This method is unavailable in the loaded catalog."}</p><Button size="small" variant="secondary" disabled={!behaviors.has(id)} onClick={() => onAlternative(step.id, id)} aria-label={`Use ${behaviors.get(id)?.title ?? id} for this step`}>Use this method</Button></div>)}</section> : null}
    <AdaptiveMethodEditor key={`${step.id}:${JSON.stringify(scenario.adaptive_execution)}:${selectedAction}`} scenario={scenario} step={step} behaviors={behaviors} actions={actions} selectedAction={selectedAction} onChange={updateScenario} />
    <section><h3>Required input</h3>{behavior.inputs.length ? behavior.inputs.map((input) => {
      const options = outputs.filter(({ output }) => output.type === input.type && Boolean(output.multiple) === Boolean(input.multiple));
      const binding = step.inputs[input.name];
      const selectedValue = binding ? `${binding.from_step}:${binding.artifact}` : "";
      const invalidBinding = Boolean(binding && !options.some(({ source, output }) => source.id === binding.from_step && output.name === binding.artifact));
      const hint = invalidBinding ? "This connection is not guaranteed on every path or its output no longer matches. Reconnect it or choose a compatible earlier step." : options.length ? `${input.required ? "Required" : "Optional"}: ${inputTypeLabel(input.type)} from a step that runs on every incoming path.` : `Add or connect an earlier step that produces ${inputTypeLabel(input.type)} on every incoming path.`;
      return <Field key={input.name} label={inputLabel(input.name)} hint={hint}><select aria-label={inputLabel(input.name)} aria-invalid={invalidBinding} value={selectedValue} onChange={(event) => updateStep(step.id, (next) => { if (!event.target.value) { delete next.inputs[input.name]; return next; } const [from_step, artifact] = event.target.value.split(":", 2); return { ...next, inputs: { ...next.inputs, [input.name]: { from_step: from_step!, artifact: artifact! } } }; })}><option value="">{input.required ? "Choose compatible output" : "No input"}</option>{invalidBinding ? <option value={selectedValue} disabled>Current connection needs attention</option> : null}{options.map(({ source, output }) => <option key={`${source.id}:${output.name}`} value={`${source.id}:${output.name}`}>{behaviors.get(source.behavior_id)?.title ?? source.id} · {inputLabel(output.name)}</option>)}</select></Field>;
    }) : <p>This step needs no input from another step.</p>}</section>
    <section><h3>Parameters</h3>{behavior.parameters.length ? behavior.parameters.map((spec) => <ParameterField key={spec.name} behaviorId={step.behavior_id} spec={spec} value={step.parameters[spec.name]} onChange={(value) => updateStep(step.id, (next) => ({ ...next, parameters: updateParameter(next.parameters, spec.name, value) }))} />) : <p>No configurable parameters.</p>}</section>
    <section><h3>Next step</h3>{outcomes.map((outcome) => { const edge = scenario.edges.find((item) => item.from_step === step.id && item.outcome === outcome); return <Field key={outcome} label={branchLabels[outcome]}><select value={edge?.to_step ?? ""} onChange={(event) => updateScenario({ ...scenario, edges: [...scenario.edges.filter((item) => !(item.from_step === step.id && item.outcome === outcome)), ...(event.target.value ? [{ from_step: step.id, outcome, to_step: event.target.value }] : [])] })}><option value="">End path</option>{scenario.steps.filter((item) => item.id !== step.id).map((item) => <option key={item.id} value={item.id}>{behaviors.get(item.behavior_id)?.title ?? item.id}</option>)}</select></Field>; })}</section>
    <details className="step-technical-details"><summary>Technical details</summary><Field label="Step ID" hint="Changing this also updates connected steps."><input value={step.id} onChange={(event) => changeId(event.target.value)} pattern="[a-z][a-z0-9_]*" /></Field><p><code>{behavior.id}</code></p><h3>Expected observations</h3><div className="chip-list">{behavior.telemetry.map((item) => <Badge key={item} tone="info">{item}</Badge>)}</div></details>
  </div>;
}

function updateParameter(parameters: Record<string, unknown>, name: string, value: unknown) {
  const next = { ...parameters };
  if (value === undefined) delete next[name];
  else next[name] = value;
  return next;
}
