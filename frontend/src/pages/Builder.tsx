import { displayTitle } from "../lib/display-title";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as Dialog from "@radix-ui/react-dialog";
import {
  applyEdgeChanges, applyNodeChanges, Background, BackgroundVariant, Controls, Handle, MarkerType,
  MiniMap, Position, ReactFlow, ReactFlowProvider, ViewportPortal, useNodesInitialized, useReactFlow, useUpdateNodeInternals,
  type Connection, type EdgeChange, type Node, type NodeChange, type NodeProps,
} from "@xyflow/react";
import {
  ArrowRight, Check, Clipboard, Command as CommandIcon, Copy, Download, FileText, Filter, GitBranch, LayoutGrid, Maximize2, Minimize2, MoreHorizontal,
  PanelLeftClose, PanelLeftOpen, PanelRightClose, PanelRightOpen, Redo2, RotateCcw,
  ListOrdered, Network, Plus, ScanSearch, Search, Trash2, Undo2, X,
} from "lucide-react";
import { memo, useCallback, useEffect, useId, useMemo, useRef, useState, type CSSProperties, type DragEvent, type KeyboardEvent as ReactKeyboardEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";
import "./Builder.css";
import { guaranteedInputSources, stepParameterSummary } from "../lib/graph-authoring";
import { ParameterField } from "../components/ParameterField";
import { BuilderEvidenceTray } from "../components/BuilderEvidenceTray";
import { connectedRunBands } from "../lib/connected-run-bands";
import { graphNodeTitle } from "../lib/graph-node-title";
import { inspectorMethodTitle } from "../lib/inspector-method-title";
import { branchLabels, focusedGraphLayout, focusedGraphViewport, GRAPH_NODE_HEIGHT, GRAPH_NODE_WIDTH, graphBoundsViewport, graphSections, graphView, initialGraphLayout, inputLabel, inputTypeLabel, readableGraphViewport, revealGraphContext, type GraphFrame, type GraphViewport, type ScenarioGraph } from "../lib/graph-view";
import { api } from "../lib/api";
import { defaultGraphView, readWorkingGraphView, writeWorkingGraphView } from "../lib/graph-view-retention";
import { initialParameterValue, shouldInitializeParameter } from "../lib/parameters";
import { deleteScenarioGraphElements, selectScenarioAlternative } from "../lib/scenario";
import { useProduct } from "../state/ProductContext";
import { useAssistancePanel, usePublishGraphAssistanceSelection } from "../state/AssistanceContext";
import { graphEditDocument, type GraphEditorDraft } from "../lib/graph-assistance";
import { GraphProposalReview } from "../components/GraphProposalReview";
import { SavedExperimentReview } from "../components/SavedExperimentReview";
import { BuilderStepSearch } from "../components/BuilderStepSearch";
import { BuilderRouteEdge } from "../components/BuilderRouteEdge";
import { BuilderRoutes } from "../components/BuilderRoutes";
import { GraphDeleteDialog, graphDeletionSummary, graphStepName } from "../components/GraphDeleteDialog";
import { GraphValidationFeedback } from "../components/GraphValidationFeedback";
import { scenarioAuthoringFailure, scenarioDiagnostics, type ScenarioDiagnostic } from "../lib/scenario-diagnostics";
import { useGraphDeletion } from "../state/useGraphDeletion";
import { AdaptiveMethodEditor, AdaptiveRepair } from "../components/AdaptiveMethodEditor";
import { adaptiveExecutionIssues, type AdaptiveExecution } from "../lib/adaptive-execution";
import type { BuilderFlowEdge, RouteObstacle } from "../lib/graph-routes";
import type { ActionDefinition, Behavior, Outcome, Scenario, ScenarioStep } from "../types";
import { Badge, Button, EmptyState, ErrorState, Field, IconButton, LoadingState, Panel, PanelHeader, sentence } from "../components/Primitives";

const outcomes: Outcome[] = ["success", "partial", "blocked", "failed"];
const outcomeColors: Record<Outcome, string> = { success: "#8dabc4", partial: "#d9b364", blocked: "#dc9066", failed: "#dc7f8b" };

interface BehaviorNodeData extends Record<string, unknown> { step: ScenarioStep; behavior?: Behavior; invalid?: boolean; method?: string; ordinal: number; routeIn?: Position; routeOut?: Position; }
type BehaviorFlowNode = Node<BehaviorNodeData, "behavior">;
type FlowEdge = BuilderFlowEdge;

function renameAdaptiveExecutionStep(policy: AdaptiveExecution, previousId: string, nextId: string): AdaptiveExecution {
  if (policy.schema_version === "bluefire.adaptive-execution.v2") {
    return { ...policy, steps: policy.steps.map(item => item.step_id === previousId ? { ...item, step_id: nextId } : item) };
  }
  return { ...policy, steps: policy.steps.map(item => item.step_id === previousId ? { ...item, step_id: nextId } : item) };
}

function behaviorNode(step: ScenarioStep, behavior: Behavior | undefined, index: number, scenario: ScenarioGraph, fallbackLayout: NonNullable<Scenario["layout"]>, invalid = false): BehaviorFlowNode {
  return { id: step.id, type: "behavior", position: scenario.layout?.[step.id] ?? fallbackLayout[step.id] ?? { x: 48, y: 48 + index * (GRAPH_NODE_HEIGHT + 96) }, data: { step, behavior, invalid, ordinal: index + 1 } };
}

function flowEdges(scenario: ScenarioGraph, behaviors: Map<string, Behavior>): FlowEdge[] {
  const incoming = new Map<string, number>();
  const title = (id: string) => { const value = behaviors.get(scenario.steps.find((step) => step.id === id)?.behavior_id ?? "")?.title; return value ? displayTitle(value) : id; };
  const routes: FlowEdge[] = scenario.edges.map((edge, index) => {
    const lane = incoming.get(edge.to_step) ?? 0;
    incoming.set(edge.to_step, lane + 1);
    return { id: `route-${edge.from_step}-${edge.outcome}-${edge.to_step}-${index}`, source: edge.from_step, target: edge.to_step, sourceHandle: `route:${edge.outcome}`, targetHandle: "route:in", type: "outcomeRoute", ariaLabel: `Route ${index + 1}: ${title(edge.from_step)}: ${branchLabels[edge.outcome]} → ${title(edge.to_step)} (${edge.from_step} → ${edge.to_step})`, markerEnd: { type: MarkerType.ArrowClosed, color: outcomeColors[edge.outcome] }, style: { stroke: outcomeColors[edge.outcome], strokeWidth: 2, strokeDasharray: edge.outcome === "success" ? undefined : "8 5" }, data: { kind: "route", outcome: edge.outcome, number: index + 1, lane, sourceTitle: title(edge.from_step), targetTitle: title(edge.to_step) } };
  });
  const artifacts: FlowEdge[] = [];
  for (const target of scenario.steps) for (const [input, binding] of Object.entries(target.inputs)) {
    const source = scenario.steps.find((item) => item.id === binding.from_step);
    const output = behaviors.get(source?.behavior_id ?? "")?.outputs.find((item) => item.name === binding.artifact);
    artifacts.push({ id: `artifact-${binding.from_step}-${binding.artifact}-${target.id}-${input}`, source: binding.from_step, target: target.id, sourceHandle: `out:${binding.artifact}`, targetHandle: `in:${input}`, ariaLabel: `${title(binding.from_step)} produces ${inputLabel(binding.artifact)} for ${title(target.id)}: ${inputLabel(input)}`, type: "outcomeRoute", style: { stroke: "#3ee2dc", strokeWidth: 1.5, strokeDasharray: "2 5" }, data: { kind: "artifact", artifactType: output?.type, artifactLabel: inputLabel(output?.type.split(".").at(-2) ?? binding.artifact) } });
  }
  return [...routes, ...artifacts];
}

const BehaviorNode = memo(function BehaviorNode({ id, data, selected }: NodeProps<BehaviorFlowNode>) {
  const behavior = data.behavior;
  const title = graphNodeTitle(displayTitle(behavior?.title ?? "Unavailable step"), behavior?.execution_state, data.invalid);
  const updateNodeInternals = useUpdateNodeInternals();
  const handleSignature = JSON.stringify([
    behavior?.inputs.slice(0, 4).map((input) => input.name) ?? [],
    behavior?.outputs.slice(0, 4).map((output) => output.name) ?? [],
    data.routeIn, data.routeOut,
  ]);
  const measuredHandles = useRef({ id, signature: handleSignature });
  // React Flow measures new nodes. Only changed handles need an explicit refresh
  // when a same-size method replacement would not notify its ResizeObserver.
  useEffect(() => {
    if (measuredHandles.current.id === id && measuredHandles.current.signature === handleSignature) return;
    measuredHandles.current = { id, signature: handleSignature };
    updateNodeInternals(id);
  }, [id, handleSignature, updateNodeInternals]);
  return <article className={`flow-node tier-${behavior?.safety_tier ?? "safe"} ${selected ? "selected" : ""} ${data.invalid ? "invalid" : ""}`} aria-label={title.method ? title.fullTitle : undefined}>
    <Handle type="target" position={data.routeIn ?? Position.Left} id="route:in" className="route-handle route-in" style={data.routeIn === Position.Top ? { left: 20 } : undefined} title="Continue from another step" />
    {(behavior?.inputs ?? []).slice(0, 4).map((input, index, items) => <Handle key={input.name} type="target" position={Position.Top} id={`in:${input.name}`} className="typed-handle input-handle" style={{ left: `${((index + 1) / (items.length + 1)) * 100}%` }} title={`Requires ${inputTypeLabel(input.type)}: ${inputLabel(input.name)}`} />)}
    <header><span className="node-order">Step {data.ordinal}</span>{data.invalid || behavior?.execution_state !== "action" ? <span className={`node-kind ${data.invalid ? "attention" : ""}`}>{data.invalid ? "Needs attention" : behavior?.execution_state === "simulation" ? "Simulation" : "Research only"}</span> : title.method ? <span className="node-method" title={title.method}>{title.method}</span> : null}</header>
    <div className="node-title"><span className="node-icon"><FileText aria-hidden="true"/></span><strong title={title.fullTitle}>{title.title}</strong></div>
    {data.method ? <p className="node-context" title={`Run override: ${displayTitle(data.method)}`}>Run override: {displayTitle(data.method)}</p> : null}
    {!data.method && stepParameterSummary(data.step, behavior) ? <p className="node-context" title={stepParameterSummary(data.step, behavior)}>{stepParameterSummary(data.step, behavior)}</p> : null}
    <footer>{data.step.alternates.length ? <span><GitBranch/>{data.step.alternates.length} saved {data.step.alternates.length === 1 ? "alternative" : "alternatives"}</span> : <span>{behavior?.platforms.map(inputLabel).join(" · ")}</span>}</footer>
    {(behavior?.outputs ?? []).slice(0, 4).map((output, index, items) => <Handle key={output.name} type="source" position={Position.Bottom} id={`out:${output.name}`} className="typed-handle output-handle" style={{ left: `${((index + 1) / (items.length + 1)) * 100}%` }} title={`Produces ${inputTypeLabel(output.type)}: ${inputLabel(output.name)}`} />)}
    <div className="route-handles">{outcomes.map((outcome, index) => <Handle key={outcome} type="source" position={outcome === "success" ? data.routeOut ?? Position.Right : Position.Right} id={`route:${outcome}`} className={`route-handle route-${outcome}`} style={outcome === "success" && data.routeOut === Position.Bottom ? { left: 20 } : { top: `${20 + index * 20}%` }} title={branchLabels[outcome]} />)}</div>
  </article>;
});

const nodeTypes = { behavior: BehaviorNode };
const edgeTypes = { outcomeRoute: BuilderRouteEdge };
const minimumGraphZoom = 0.005;
const minimumReadableGraphZoom = 0.8;
const deleteKeys = ["Backspace", "Delete"];
const connectionLineStyle = { stroke: "#38a8ff", strokeWidth: 2 };
const proOptions = { hideAttribution: true };
const miniMapStyle = { width: 132, height: 80 };
const rightRouteGutter = 72;
const sameViewport = (left: GraphViewport, right: GraphViewport) => left.zoom === right.zoom && Math.abs(left.x - right.x) < 0.001 && Math.abs(left.y - right.y) < 0.001;

function visibleCanvasFrame(canvas: HTMLElement): GraphFrame {
  const frame = { x: 0, y: 0, width: canvas.clientWidth, height: canvas.clientHeight };
  const main = canvas.closest(".builder-focus") ? null : canvas.closest("main");
  const bounds = canvas.getBoundingClientRect(), scrollport = main?.getBoundingClientRect();
  if (!bounds.width || !bounds.height) return { ...frame, width: 0, height: 0 };
  const left = bounds.left + canvas.clientLeft, top = bounds.top + canvas.clientTop;
  const scrollLeft = (scrollport?.left ?? 0) + (main?.clientLeft ?? 0);
  const scrollTop = (scrollport?.top ?? 0) + (main?.clientTop ?? 0);
  const visibleLeft = Math.max(left, scrollLeft, 0);
  const visibleTop = Math.max(top, scrollTop, 0);
  const right = Math.min(left + frame.width, scrollLeft + (main?.clientWidth ?? window.innerWidth), window.innerWidth);
  const bottom = Math.min(top + frame.height, scrollTop + (main?.clientHeight ?? window.innerHeight), window.innerHeight);
  return { x: visibleLeft - left, y: visibleTop - top, width: Math.max(0, right - visibleLeft), height: Math.max(0, bottom - visibleTop) };
}

function revealCanvasToolbar(canvas: HTMLElement) {
  const main = canvas.closest(".builder-focus") ? null : canvas.closest("main");
  if (!main?.clientHeight) return;
  const toolbar = canvas.closest(".graph-panel")?.querySelector(".graph-topbar");
  const scrollport = main.getBoundingClientRect();
  const distance = toolbar ? toolbar.getBoundingClientRect().top - scrollport.top - main.clientTop - 8 : 0;
  if (distance > 0 && canvas.getBoundingClientRect().bottom > scrollport.top + main.clientTop + main.clientHeight) main.scrollTop += distance;
}

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

export function GraphWorkspace({ behaviors, actions, review }: { behaviors: Behavior[]; actions: ActionDefinition[]; review?: GraphEditorDraft }) {
  const queryClient = useQueryClient();
  const product = useProduct();
  const assistant = useAssistancePanel();
  const { scenario, setScenario, dirty } = review ?? product;
  const { markSaved, setRunConfig, runConfig: durableRunConfig } = product;
  const runConfig = review ? { ...product.runConfig, mode: "simulate" as const, actionImplementations: {} } : product.runConfig;
  // Naming and other metadata edits keep the graph's presentation inputs stable.
  // The complete scenario still updates immediately for history, saves, and review.
  const graph = useMemo(() => ({ steps: scenario.steps, edges: scenario.edges, start: scenario.start, layout: scenario.layout }), [scenario.steps, scenario.edges, scenario.start, scenario.layout]);
  const fallbackLayout = useMemo<NonNullable<Scenario["layout"]>>(() => graph.steps.some(step => !graph.layout?.[step.id]) ? initialGraphLayout(graph, true) : {}, [graph]);
  const behaviorMap = useMemo(() => new Map(behaviors.map((item) => [item.id, item])), [behaviors]);
  const actionMap = useMemo(() => new Map(actions.map((item) => [item.id, item])), [actions]);
  const [invalidNodes, setInvalidNodes] = useState<Set<string>>(new Set());
  const methodOverrides = review ? undefined : product.runConfig.actionImplementations;
  const makeNodes = useCallback((value: ScenarioGraph) => value.steps.map((step, index) => {
    const node = behaviorNode(step, behaviorMap.get(step.behavior_id), index, value, fallbackLayout, invalidNodes.has(step.id));
    return { ...node, data: { ...node.data, method: actionMap.get(methodOverrides?.[step.id] ?? "")?.title } };
  }), [actionMap, behaviorMap, fallbackLayout, invalidNodes, methodOverrides]);
  const [initialView] = useState(() => review ? defaultGraphView(scenario) : readWorkingGraphView(scenario));
  const edgeDefinitions = useMemo(() => flowEdges(graph, behaviorMap), [graph, behaviorMap]);
  const [nodes, setNodes] = useState<BehaviorFlowNode[]>(() => makeNodes(graph).map((node) => ({ ...node, selected: node.id === initialView.selected?.id })));
  const [edges, setEdges] = useState<FlowEdge[]>(() => edgeDefinitions);
  const [selectedId, setSelectedId] = useState(initialView.selected?.id ?? "");
  const editContext = useMemo(() => {
    if (!selectedId || !scenario.steps.some(step => step.id === selectedId)) return {};
    try { return { selection: { scenario: graphEditDocument(scenario), step_id: selectedId, dirty } }; }
    catch { return { unavailable: "Complete the current graph fields before requesting a step edit. Your manual draft remains editable." }; }
  }, [scenario, selectedId, dirty]);
  const editTitle = selectedId ? behaviorMap.get(scenario.steps.find(step => step.id === selectedId)?.behavior_id ?? "")?.title ?? selectedId : undefined;
  usePublishGraphAssistanceSelection(!review, editContext.selection, editTitle, editContext.unavailable);
  const [search, setSearch] = useState(""); const [platform, setPlatform] = useState("all"); const [tier, setTier] = useState("all");
  const [compatibility, setCompatibilityMessage] = useState<{ message: string; error: boolean }>();
  const setCompatibility = (message: string | undefined, error = false) => setCompatibilityMessage(message ? { message, error } : undefined);
  const [purposeOpen, setPurposeOpen] = useState(!scenario.purpose.trim());
  const [purposeMissing, setPurposeMissing] = useState(false);
  const purposeInput = useRef<HTMLTextAreaElement>(null);
  const [validationIssues, setValidationIssues] = useState<ScenarioDiagnostic[]>([]); const [validationState, setValidationState] = useState<"idle" | "valid" | "invalid">("idle");
  const [history, setHistory] = useState<Scenario[]>(() => [structuredClone(scenario)]); const [historyIndex, setHistoryIndex] = useState(0);
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
    setCompatibilityMessage(current => current?.error ? undefined : current);
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
  const [graphZoom, setGraphZoom] = useState(1);
  const [miniMapOpen, setMiniMapOpen] = useState(false);
  const summaryZoom = graphZoom < minimumReadableGraphZoom;
  const sections = useMemo(() => graphSections(visibleGraph.ordered, graph.edges, graph.start), [visibleGraph, graph.edges, graph.start]);
  // Route edits can renumber groups. Resolve the selected step's group before
  // hiding nodes; explicit group changes move the selection in showSection.
  const selectedSection = sections.findIndex(section => section.steps.some(step => step.id === selectedId));
  const sectionIndex = focusedSection !== null && selectedSection >= 0 ? selectedSection : Math.min(focusedSection ?? 0, sections.length - 1);
  const shownSteps = viewMode === "graph" && focusedSection !== null ? sections[sectionIndex]!.steps : visibleGraph.ordered;
  const shownIds = useMemo(() => new Set(shownSteps.map((step) => step.id)), [shownSteps]);
  const focusedGroup = viewMode === "graph" && focusedSection !== null && sections.length > 1;
  const focusedLayout = useMemo(() => focusedGroup ? focusedGraphLayout(graph, shownSteps.map(step => step.id)) : undefined, [focusedGroup, graph, shownSteps]);
  const projectedNodes = useMemo(() => nodes.map((node) => {
    const generated = fallbackLayout[node.id];
    const projected = focusedLayout?.[node.id];
    const usesFallback = generated && node.position.x === generated.x && node.position.y === generated.y;
    return { ...node, position: projected && usesFallback ? projected : node.position, hidden: !shownIds.has(node.id), selected: node.selected && shownIds.has(node.id) };
  }), [fallbackLayout, focusedLayout, nodes, shownIds]);
  const routeNodeData = useMemo(() => {
    // Selection changes node records, but only data or port changes invalidate cards.
    const cache = new WeakMap<BehaviorNodeData, BehaviorNodeData>();
    return (data: BehaviorNodeData, routeIn: Position, routeOut: Position) => {
      const previous = cache.get(data);
      if (previous?.routeIn === routeIn && previous.routeOut === routeOut) return previous;
      const next = { ...data, routeIn, routeOut };
      cache.set(data, next);
      return next;
    };
  }, []);
  const displayNodes = useMemo(() => projectedNodes.map(node => {
    const incoming = graph.edges.find(edge => edge.to_step === node.id && edge.outcome === "success");
    const outgoing = graph.edges.find(edge => edge.from_step === node.id && edge.outcome === "success");
    const before = projectedNodes.find(item => item.id === incoming?.from_step);
    const after = projectedNodes.find(item => item.id === outgoing?.to_step);
    const routeIn = before && Math.abs(before.position.x - node.position.x) < 1 && before.position.y < node.position.y ? Position.Top : Position.Left;
    const routeOut = after && Math.abs(after.position.x - node.position.x) < 1 && after.position.y > node.position.y ? Position.Bottom : Position.Right;
    return { ...node, data: routeNodeData(node.data, routeIn, routeOut) };
  }), [graph.edges, projectedNodes, routeNodeData]);
  // Selection updates React Flow's node records, but does not invalidate routes.
  const routeGeometry = useMemo(() => JSON.stringify(displayNodes.filter(node => !node.hidden).map(node => ({ id: node.id, ...node.position, width: node.measured?.width ?? GRAPH_NODE_WIDTH, height: node.measured?.height ?? GRAPH_NODE_HEIGHT }))), [displayNodes]);
  const geometryRevision = useRef(0);
  // Moving a card invalidates resize recovery without panning underneath a drag.
  useEffect(() => { geometryRevision.current += 1; }, [routeGeometry]);
  const routeObstacles = useMemo<RouteObstacle[]>(() => JSON.parse(routeGeometry) as RouteObstacle[], [routeGeometry]);
  const runBands = useMemo(() => {
    const ordinals = new Map(scenario.steps.map((step, index) => [step.id, index + 1]));
    return connectedRunBands(routeObstacles.map(card => ({ ...card, ordinal: ordinals.get(card.id) ?? 0 })), graph.edges, { padding: 22 });
  }, [graph.edges, routeObstacles, scenario.steps]);
  const routedData = useMemo(() => new Map(edgeDefinitions.map(edge => [edge.id, edge.data ? { ...edge.data, obstacles: routeObstacles } : undefined])), [edgeDefinitions, routeObstacles]);
  const edgeIsShown = useCallback((edge: FlowEdge) => shownIds.has(edge.source) && shownIds.has(edge.target) && (edge.data?.kind !== "artifact" || showInputs) && (edge.data?.kind !== "route" || edge.data.outcome === "success" || allBranches || expandedBranches.has(edge.source)), [allBranches, expandedBranches, showInputs, shownIds]);
  const selectedRouteId = edges.find((edge) => edge.selected && edge.data?.kind === "route" && edgeIsShown(edge))?.id;
  const displayEdges = useMemo(() => edges.map((edge) => ({ ...edge, data: routedData.get(edge.id) ?? edge.data, hidden: !edgeIsShown(edge), selected: edge.selected && edgeIsShown(edge), style: { ...edge.style, opacity: selectedRouteId && edge.id !== selectedRouteId ? .45 : 1 } })), [edgeIsShown, edges, selectedRouteId, routedData]);
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
  const groupBoundaries = useMemo(() => {
    if (focusedSection === null || sections.length <= 1) return undefined;
    const incoming = scenario.edges.filter(edge => !shownIds.has(edge.from_step) && shownIds.has(edge.to_step));
    const outgoing = scenario.edges.filter(edge => shownIds.has(edge.from_step) && !shownIds.has(edge.to_step));
    const stepsById = new Map(scenario.steps.map(step => [step.id, step]));
    const stepOrdinals = new Map(scenario.steps.map((step, index) => [step.id, index + 1]));
    const titleCounts = new Map<string, number>();
    for (const step of scenario.steps) {
      const title = displayTitle(behaviorMap.get(step.behavior_id)?.title ?? step.id);
      titleCounts.set(title, (titleCounts.get(title) ?? 0) + 1);
    }
    const stepTitle = (id: string) => {
      const title = displayTitle(behaviorMap.get(stepsById.get(id)?.behavior_id ?? "")?.title ?? id);
      return titleCounts.get(title)! > 1 ? `${title} · Step ${stepOrdinals.get(id)}` : title;
    };
    const format = (edges: ScenarioGraph["edges"], side: "from_step" | "to_step") => {
      const values = [...new Map(edges.map(edge => [`${edge.from_step}:${edge.outcome}:${edge.to_step}`, `${stepTitle(edge[side])} · ${branchLabels[edge.outcome]}`])).values()];
      return values.length > 2 ? [...values.slice(0, 2), `+${values.length - 2} more`] : values;
    };
    const incomingArtifacts = scenario.steps.flatMap(consumer => shownIds.has(consumer.id) ? Object.entries(consumer.inputs)
      .filter(([, binding]) => !shownIds.has(binding.from_step) && stepsById.has(binding.from_step))
      .map(([input, binding]) => ({ identity: JSON.stringify([binding.from_step, consumer.id, input, binding.artifact]), label: `${stepTitle(binding.from_step)} · ${binding.artifact} → ${stepTitle(consumer.id)} · ${inputLabel(input)}` })) : []);
    const outgoingArtifacts = scenario.steps.flatMap(consumer => !shownIds.has(consumer.id) ? Object.entries(consumer.inputs)
      .filter(([, binding]) => shownIds.has(binding.from_step))
      .map(([input, binding]) => ({ identity: JSON.stringify([binding.from_step, consumer.id, input, binding.artifact]), label: `${stepTitle(binding.from_step)} · ${binding.artifact} → ${stepTitle(consumer.id)} · ${inputLabel(input)}` })) : []);
    const uniqueBindings = (items: typeof incomingArtifacts) => [...new Map(items.map(item => [item.identity, item])).values()];
    const limited = (items: typeof incomingArtifacts) => items.length > 5 ? [...items.slice(0, 5), { identity: `overflow:${items.length}`, label: `+${items.length - 5} more` }] : items;
    const incomingBindings = uniqueBindings(incomingArtifacts);
    const outgoingBindings = uniqueBindings(outgoingArtifacts);
    return {
      incoming: format(incoming, "from_step"), outgoing: format(outgoing, "to_step"), first: sectionIndex === 0,
      incomingArtifacts: limited(incomingBindings), outgoingArtifacts: limited(outgoingBindings),
      artifactCount: incomingBindings.length + outgoingBindings.length,
    };
  }, [behaviorMap, focusedSection, scenario.edges, scenario.steps, sectionIndex, sections.length, shownIds]);
  useEffect(() => {
    const index = sections.findIndex(section => section.steps.some(step => step.id === selectedId));
    if (focusedSection !== null && sections.length > 1 && index >= 0) setFocusedSection(index);
  }, [focusedSection, sections, selectedId]);
  const graphCanvas = useRef<HTMLDivElement>(null);
  const orderedSteps = useRef<HTMLOListElement>(null);
  const [selectionToReveal, setSelectionToReveal] = useState("");
  const selectStep = useCallback((id: string) => { setSelectedId(id); setSelectionToReveal(id); setNodes((items) => items.map((node) => ({ ...node, selected: node.id === id }))); setEdges((items) => items.map((edge) => ({ ...edge, selected: false }))); setInspectorOpen(true); setPaletteOpen(false); }, []);
  const selectRoute = useCallback((id: string) => { setRoutesOpen(true); setSelectedId(""); setNodes((items) => items.map((node) => ({ ...node, selected: false }))); setEdges((items) => items.map((edge) => ({ ...edge, selected: edge.id === id }))); setInspectorOpen(false); setPaletteOpen(false); }, []);
  const onEdgeClick = useCallback((_: unknown, edge: FlowEdge) => { if (edge.data?.kind === "route") selectRoute(edge.id); }, [selectRoute]);
  const onNodeClick = useCallback((_: unknown, node: BehaviorFlowNode) => selectStep(node.id), [selectStep]);
  const revealSearchResult = useCallback((id: string) => {
    const index = scenario.steps.findIndex(step => step.id === id);
    if (index < 0) return;
    setAllBranches(true);
    if (viewMode === "graph") setFocusedSection(null);
    selectStep(id);
  }, [scenario.steps, selectStep, viewMode]);
  const onSelectionChange = useCallback(({ nodes: selection }: { nodes: BehaviorFlowNode[] }) => setSelectedId(selection.at(-1)?.id ?? ""), []);
  const operatorViewportRevision = useRef(0);
  const claimViewport = useCallback(() => { operatorViewportRevision.current += 1; }, []);
  const onMove = useCallback((event: unknown, viewport: { zoom: number }) => {
    // React Flow reports automatic viewport updates with a null event.
    if (event) claimViewport();
    setGraphZoom(Math.round(viewport.zoom * 100) / 100);
  }, [claimViewport]);
  const togglePalette = () => { setPaletteOpen((open) => !open); setInspectorOpen(false); };
  const toggleInspector = () => { setInspectorOpen((open) => !open); setPaletteOpen(false); };
  const inspectorToggleId = useId();
  const [paletteWidth, setPaletteWidth] = useState(290); const [inspectorWidth, setInspectorWidth] = useState(310);
  const clipboard = useRef<ScenarioStep | undefined>(undefined); const flow = useReactFlow<BehaviorFlowNode, FlowEdge>();
  const nodesInitialized = useNodesInitialized();
  const initialFrameDone = useRef(false);
  const framedFocusMode = useRef(focusMode);
  const framedViewMode = useRef(viewMode);
  const frameStep = useCallback((id: string, mode: "start" | "readable" | "reveal", duration = 0, preferred?: GraphViewport) => {
    const canvas = graphCanvas.current;
    const node = flow.getNode(id);
    if (!canvas || !node || node.hidden || !canvas.clientWidth || !canvas.clientHeight) return false;
    const hasRightRoutes = graph.edges.some(edge => edge.from_step === id && (edge.outcome === "success" ? node.data.routeOut !== Position.Bottom : allBranches || expandedBranches.has(id)));
    // Reserve label width in graph units so it stays clear at operator zoom.
    const bounds = { ...node.position, width: (node.measured?.width ?? GRAPH_NODE_WIDTH) + (hasRightRoutes ? rightRouteGutter : 0), height: node.measured?.height ?? GRAPH_NODE_HEIGHT };
    const frame = visibleCanvasFrame(canvas);
    if (!frame.width || !frame.height) return false;
    const current = flow.getViewport();
    const neighborIds = new Set(graph.edges.flatMap(edge => edge.from_step === id ? [edge.to_step] : edge.to_step === id ? [edge.from_step] : []));
    const neighbors = [...neighborIds].flatMap(neighborId => {
      const neighbor = flow.getNode(neighborId);
      return neighbor && !neighbor.hidden ? [{ ...neighbor.position, width: neighbor.measured?.width ?? GRAPH_NODE_WIDTH, height: neighbor.measured?.height ?? GRAPH_NODE_HEIGHT }] : [];
    });
    const context = mode === "readable" ? flow.getNodes().filter(item => !item.hidden && item.id !== id).map(item => {
      const routes = graph.edges.some(edge => edge.from_step === item.id && (edge.outcome === "success" ? item.data.routeOut !== Position.Bottom : allBranches || expandedBranches.has(item.id)));
      return { ...item.position, width: (item.measured?.width ?? GRAPH_NODE_WIDTH) + (routes ? rightRouteGutter : 0), height: item.measured?.height ?? GRAPH_NODE_HEIGHT };
    }) : [];
    const next = mode === "reveal" ? revealGraphContext(preferred ?? current, bounds, neighbors, frame)
      : mode === "readable" ? focusedGraphViewport(bounds, context, frame) : readableGraphViewport(bounds, frame, true);
    if (!sameViewport(next, current)) void flow.setViewport(next, { duration: window.matchMedia?.("(prefers-reduced-motion: reduce)")?.matches ? 0 : duration });
    return next;
  }, [allBranches, expandedBranches, flow, graph.edges]);
  const fitNodes = useCallback((ids: readonly string[], duration = 0, readable = false) => {
    const canvas = graphCanvas.current;
    if (!canvas || !canvas.clientWidth || !canvas.clientHeight) return false;
    const bounds = ids.flatMap(id => {
      const node = flow.getNode(id);
      if (!node || node.hidden) return [];
      const hasRightRoutes = graph.edges.some(edge => edge.from_step === id && (edge.outcome === "success" ? node.data.routeOut !== Position.Bottom : allBranches || expandedBranches.has(id)));
      return [{ ...node.position, width: (node.measured?.width ?? GRAPH_NODE_WIDTH) + (hasRightRoutes ? rightRouteGutter : 0), height: node.measured?.height ?? GRAPH_NODE_HEIGHT }];
    });
    const viewport = graphBoundsViewport(bounds, visibleCanvasFrame(canvas), 48, 1);
    if (!viewport) return false;
    if (readable && viewport.zoom < minimumReadableGraphZoom) {
      // A scheduled group change may still capture the previous selection.
      const anchor = ids.includes(selectedId) ? selectedId : ids.includes(scenario.start) ? scenario.start : ids[0];
      return anchor ? Boolean(frameStep(anchor, "start", duration)) : false;
    }
    void flow.setViewport(viewport, { duration: window.matchMedia?.("(prefers-reduced-motion: reduce)")?.matches ? 0 : duration });
    return true;
  }, [allBranches, expandedBranches, flow, frameStep, graph.edges, scenario.start, selectedId]);
  useEffect(() => {
    if (!selectionToReveal || selectionToReveal !== selectedId || !inspectorOpen || viewMode !== "steps") return;
    const row = [...(orderedSteps.current?.querySelectorAll<HTMLButtonElement>("button[data-step-id]") ?? [])]
      .find(button => button.dataset.stepId === selectionToReveal);
    if (!row) return;
    row.scrollIntoView({ block: "nearest", behavior: "instant" });
    setSelectionToReveal("");
  }, [inspectorOpen, selectedId, selectionToReveal, viewMode]);

  useEffect(() => {
    if (!selectionToReveal || selectionToReveal !== selectedId || !inspectorOpen || !nodesInitialized || viewMode !== "graph") return;
    const frame = requestAnimationFrame(() => {
      if (frameStep(selectionToReveal, flow.getZoom() < minimumReadableGraphZoom ? "readable" : "reveal")) setSelectionToReveal("");
    });
    return () => cancelAnimationFrame(frame);
  }, [flow, frameStep, inspectorOpen, nodesInitialized, selectedId, selectionToReveal, viewMode]);

  const routeDockWasOpen = useRef(routesOpen);
  const routeDockRevealPending = useRef(false);
  const routeDockOpeningRevision = useRef<number | null>(null);
  useEffect(() => {
    const opened = routesOpen && !routeDockWasOpen.current;
    routeDockWasOpen.current = routesOpen;
    if (!routesOpen) { routeDockRevealPending.current = false; routeDockOpeningRevision.current = null; return; }
    if (opened) {
      routeDockRevealPending.current = true;
      routeDockOpeningRevision.current = operatorViewportRevision.current;
    }
    if (!routeDockRevealPending.current || viewMode !== "graph" || !selectedId || !nodesInitialized) return;
    const canvas = graphCanvas.current;
    const node = flow.getNode(selectedId);
    if (!canvas || !node || node.hidden || !canvas.clientWidth || !canvas.clientHeight) return;
    const id = selectedId;
    const openingRevision = routeDockOpeningRevision.current;
    if (openingRevision === null) return;
    // Consume only this false-to-true opening after layout is valid. Later graph
    // refreshes cannot reclaim a viewport the operator has panned or dragged.
    const frame = requestAnimationFrame(() => {
      if (!routeDockRevealPending.current || !routesOpen) return;
      if (operatorViewportRevision.current !== openingRevision) {
        routeDockRevealPending.current = false;
        routeDockOpeningRevision.current = null;
        return;
      }
      const current = flow.getNode(id);
      if (!current || current.hidden || !canvas.clientWidth || !canvas.clientHeight) return;
      if (current.dragging) { routeDockRevealPending.current = false; routeDockOpeningRevision.current = null; return; }
      if (frameStep(id, "reveal")) { routeDockRevealPending.current = false; routeDockOpeningRevision.current = null; }
    });
    return () => cancelAnimationFrame(frame);
  }, [flow, frameStep, nodesInitialized, routesOpen, selectedId, viewMode]);

  const resizeOwnership = useRef<{
    scenarioId: string; selectedId: string; focusMode: boolean; operatorRevision: number; interrupted: boolean;
    recovery?: { original: GraphViewport; applied: GraphViewport; geometryRevision: number; originalScroll: { top: number; left: number }; mainHeight: number };
  } | undefined>(undefined);
  useEffect(() => {
    if (viewMode !== "graph") { framedViewMode.current = viewMode; resizeOwnership.current = undefined; return; }
    const canvas = graphCanvas.current;
    if (!canvas || !nodesInitialized) return;
    // Committing a card move refreshes graph callbacks and replaces this observer.
    // Keep the operator's ownership and any automatic recovery for the same selection.
    if (!resizeOwnership.current || resizeOwnership.current.scenarioId !== scenario.id || resizeOwnership.current.selectedId !== selectedId || resizeOwnership.current.focusMode !== focusMode) {
      resizeOwnership.current = { scenarioId: scenario.id, selectedId, focusMode, operatorRevision: operatorViewportRevision.current, interrupted: false };
    }
    const ownership = resizeOwnership.current;
    let navigationTransition = framedFocusMode.current !== focusMode || framedViewMode.current !== viewMode;
    framedFocusMode.current = focusMode;
    framedViewMode.current = viewMode;
    const main = focusMode ? null : canvas.closest("main");
    const scrollPosition = () => ({ top: main?.scrollTop ?? 0, left: main?.scrollLeft ?? 0 });
    const sameScroll = (left: ReturnType<typeof scrollPosition>, right: ReturnType<typeof scrollPosition>) => Math.abs(left.top - right.top) < 1 && Math.abs(left.left - right.left) < 1;
    let pending = 0;
    let previousCanvas = { width: canvas.clientWidth, height: canvas.clientHeight };
    let previousMainWidth = main?.clientWidth ?? 0;
    let previousMainHeight = main?.clientHeight ?? 0;
    let lastScroll = scrollPosition();
    const onScroll = () => {
      const current = scrollPosition();
      if (sameScroll(current, lastScroll)) return;
      lastScroll = current;
      ownership.recovery = undefined;
      ownership.interrupted = true;
    };
    const reveal = () => {
      cancelAnimationFrame(pending);
      pending = requestAnimationFrame(() => {
        const frame = visibleCanvasFrame(canvas);
        const mainHeight = main?.clientHeight ?? 0;
        const mainWidth = main?.clientWidth ?? 0;
        const canvasSize = { width: canvas.clientWidth, height: canvas.clientHeight };
        const revealFromNavigation = navigationTransition;
        navigationTransition = false;
        const needsInitialFrame = !initialFrameDone.current && nodes.length > 0;
        // Returning from Steps or changing focus mode replaces the observer
        // after layout has settled. Reveal that navigation once at current zoom.
        if (!needsInitialFrame && !revealFromNavigation && mainHeight === previousMainHeight && mainWidth === previousMainWidth && canvasSize.width === previousCanvas.width && canvasSize.height === previousCanvas.height) return;
        const mainHeightShrank = mainHeight < previousMainHeight;
        const mainHeightGrew = mainHeight > previousMainHeight;
        const mainWidthShrank = mainWidth < previousMainWidth;
        const mainWidthGrew = mainWidth > previousMainWidth;
        if (ownership.operatorRevision !== operatorViewportRevision.current) {
          ownership.operatorRevision = operatorViewportRevision.current;
          ownership.recovery = undefined;
          ownership.interrupted = true;
        }
        if (needsInitialFrame) {
          // Opening Build into an already stacked dock has no resize transition.
          // Establish usable graph space before accepting its first frame.
          if (frame.height < GRAPH_NODE_HEIGHT + 96) revealCanvasToolbar(canvas);
          lastScroll = scrollPosition();
          initialFrameDone.current = fitNodes(shownSteps.map(step => step.id), 0, true);
        } else if (initialFrameDone.current && selectedId) {
          const current = flow.getViewport();
          // A later operator pan, zoom, focus, or card move owns the view from then on.
          if (ownership.recovery && (!sameViewport(current, ownership.recovery.applied) || ownership.recovery.geometryRevision !== geometryRevision.current)) {
            ownership.recovery = undefined;
            ownership.interrupted = true;
          }
          // Classify the measured container sizes, not the visible intersection:
          // scrolling can move that intersection without contracting the canvas.
          const grew = mainHeightGrew || mainWidthGrew || canvasSize.width > previousCanvas.width || canvasSize.height > previousCanvas.height;
          const shrank = mainHeightShrank || mainWidthShrank || canvasSize.width < previousCanvas.width || canvasSize.height < previousCanvas.height;
          // A contraction wins when one axis shrinks while another grows. It can
          // clip selected context, so reveal at the current zoom even after an
          // operator action; pure growth still respects interrupted ownership.
          if (shrank) ownership.interrupted = false;
          if (flow.getNode(selectedId)?.dragging) {
            ownership.recovery = undefined;
            ownership.interrupted = true;
          } else if (!(grew && ownership.interrupted)) {
            const originalScroll = scrollPosition();
            if (main && mainHeight > 0 && (mainHeightShrank || revealFromNavigation)) {
              // A stacked dock can shrink main without resizing the canvas. Reveal
              // its toolbar once instead of leaving the graph below the title rows.
              revealCanvasToolbar(canvas);
              lastScroll = scrollPosition();
            } else if (main && mainHeightGrew && !shrank && ownership.recovery && mainHeight >= ownership.recovery.mainHeight) {
              main.scrollTop = ownership.recovery.originalScroll.top;
              main.scrollLeft = ownership.recovery.originalScroll.left;
              lastScroll = scrollPosition();
            }
            const next = frameStep(selectedId, "reveal", 0, grew && !shrank ? ownership.recovery?.original : undefined);
            if (next) {
              if (ownership.recovery) ownership.recovery.applied = next;
              else if (shrank && (!sameViewport(next, current) || !sameScroll(originalScroll, lastScroll))) {
                ownership.recovery = { original: current, applied: next, geometryRevision: geometryRevision.current, originalScroll, mainHeight: previousMainHeight };
              }
              if (ownership.recovery && sameViewport(next, ownership.recovery.original) && sameScroll(lastScroll, ownership.recovery.originalScroll)) ownership.recovery = undefined;
            }
          }
        }
        previousCanvas = canvasSize;
        previousMainWidth = mainWidth;
        previousMainHeight = mainHeight;
      });
    };
    // Shrinking a pane may temporarily hide context. Recover only that automatic
    // scroll/pan when space returns. Scrolling itself never triggers a reveal.
    // Every reveal retains the current zoom and uses the visible canvas origin.
    const observer = new ResizeObserver(reveal);
    observer.observe(canvas);
    if (main) { observer.observe(main); main.addEventListener("scroll", onScroll, { passive: true }); }
    reveal();
    return () => { observer.disconnect(); main?.removeEventListener("scroll", onScroll); cancelAnimationFrame(pending); };
  }, [fitNodes, flow, focusMode, frameStep, nodes.length, nodesInitialized, scenario.id, selectedId, shownSteps, viewMode]);

  const selectionForGraphRefresh = useRef(selectedId);
  // Graph edits can add and select a node together. Keep that committed selection
  // available to the refresh without rebuilding graph data for selection alone.
  useEffect(() => { selectionForGraphRefresh.current = selectedId; }, [selectedId]);
  useEffect(() => {
    const selected = selectionForGraphRefresh.current;
    setNodes((current) => {
      const previousNodes = new Map(current.map((node) => [node.id, node]));
      return makeNodes(graph).map((node) => {
        const previous = previousNodes.get(node.id);
        // Preserve measured dimensions and selection when refreshing graph data.
        return { ...node, measured: previous?.measured, selected: previous?.selected ?? node.id === selected };
      });
    });
    setEdges((current) => {
      const selectedEdges = new Set(current.filter((edge) => edge.selected).map((edge) => edge.id));
      return edgeDefinitions.map((edge) => ({ ...edge, selected: selectedEdges.has(edge.id) }));
    });
  }, [graph, edgeDefinitions, makeNodes]);
  const deletionScope = JSON.stringify([viewMode, allBranches, [...expandedBranches].sort(), focusedSection, showInputs, [...shownIds], selectedId, nodes.filter(node => node.selected && shownIds.has(node.id)).map(node => node.id).sort(), edges.filter(edge => edge.selected && edgeIsShown(edge)).map(edge => edge.id).sort()]);
  const deletion = useGraphDeletion<BehaviorFlowNode, FlowEdge>({ revision: scenario, scope: deletionScope, readOnly: Boolean(review?.readOnly), currentRevision: () => currentScenario.current, focusContainer: () => graphCanvas.current, removalCommitted: elements => {
    const remaining = Array.from(graphCanvas.current?.querySelectorAll<HTMLElement>(".react-flow__node, .react-flow__edge") ?? []);
    return elements.nodes.every(node => !remaining.some(element => element.classList.contains("react-flow__node") && element.dataset.id === node.id)) && elements.edges.every(edge => !remaining.some(element => element.classList.contains("react-flow__edge") && element.dataset.id === edge.id));
  }, focusFallback: elements => {
    const workspace = graphCanvas.current?.closest(".builder-page");
    if (viewMode === "steps") return workspace?.querySelector<HTMLElement>(".ordered-steps button[aria-pressed='true']") ?? workspace?.querySelector<HTMLElement>(".ordered-steps button, [aria-label='Show behavior palette'], [aria-label='Hide behavior palette']") ?? null;
    if (elements.nodes.length) return graphCanvas.current?.querySelector<HTMLElement>(".react-flow__node.selected, .graph-empty-overlay button") ?? graphCanvas.current;
    if (elements.edges.every(edge => edge.data?.kind === "route")) return workspace?.querySelector<HTMLElement>(".builder-routes button[data-route][aria-pressed='true']") ?? workspace?.querySelector<HTMLElement>(".builder-routes button[data-route]") ?? graphCanvas.current;
    return graphCanvas.current;
  } });
  const { isPending: deletionPending, allowsRemoval: deletionAllowsRemoval, consume: consumeDeletion, request: requestDeletion } = deletion;
  useEffect(() => {
    if (!focusMode) return;
    const exitFocus = (event: globalThis.KeyboardEvent) => { if (event.key === "Escape" && !commandPaletteOpen && !deletionPending()) setFocusMode(false); };
    window.addEventListener("keydown", exitFocus);
    return () => window.removeEventListener("keydown", exitFocus);
  }, [commandPaletteOpen, focusMode, deletionPending]);
  useEffect(() => {
    const openCommands = (event: globalThis.KeyboardEvent) => {
      if (!deletionPending() && (event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") { event.preventDefault(); setCommandPaletteOpen(true); }
    };
    window.addEventListener("keydown", openCommands);
    return () => window.removeEventListener("keydown", openCommands);
  }, [deletionPending]);
  const replaceScenario = useCallback((next: Scenario) => {
    locallyAppliedScenario.current = next;
    currentScenario.current = next;
    setScenario(next);
    setValidationState("idle"); setValidationIssues((current) => current.length ? [] : current); setInvalidNodes((current) => current.size ? new Set() : current);
  }, [setScenario]);
  const applyScenario = useCallback((next: Scenario, record = true) => {
    if (review?.readOnly || deletionPending()) return;
    replaceScenario(next);
    if (record) { setHistory((items) => [...items.slice(0, historyIndex + 1), structuredClone(next)]); setHistoryIndex((index) => index + 1); }
    else setHistory((items) => [...items.slice(0, historyIndex), structuredClone(next)]);
  }, [historyIndex, replaceScenario, review?.readOnly, deletionPending]);

  // A step ID edit keeps the step's identity, so the selection and the chosen run
  // method travel with it. Both would otherwise be lost per keystroke: the old ID
  // stops matching any step, and setScenario drops an override whose step ID has
  // vanished. Ordinary replacement with a different behavior still drops its
  // override, because only this identity-preserving path re-keys one.
  const renameStep = useCallback((previousId: string, nextId: string, next: Scenario) => {
    if (review?.readOnly || deletionPending()) return;
    // Overrides are only selectable outside a review, and the review-mode copy of
    // runConfig is rebuilt every render, so read the durable one.
    const override = review ? undefined : durableRunConfig.actionImplementations?.[previousId];
    applyScenario(next);
    if (override) {
      // setScenario prunes by step ID and a rename changes nothing else, so the
      // rest of the map is already correct after it runs. setRunConfig clears any
      // prepared approval, so the renamed step carries no stale authorization.
      const actionImplementations = { ...(durableRunConfig.actionImplementations ?? {}) };
      delete actionImplementations[previousId];
      actionImplementations[nextId] = override;
      setRunConfig({ ...durableRunConfig, actionImplementations });
    }
    // Re-key the existing node in the same update. Leaving it under the old ID lets
    // React Flow report an empty selection for one render, which unmounts the
    // inspector and drops focus mid-rename even though the selection is restored
    // immediately afterwards.
    selectionForGraphRefresh.current = nextId;
    setSelectedId(nextId);
    setNodes((items) => items.map((node) => (node.id === previousId ? { ...node, id: nextId, selected: true } : node)));
  }, [applyScenario, durableRunConfig, review, setNodes, setRunConfig, deletionPending]);

  const undo = useCallback(() => { if (review?.readOnly || deletionPending() || historyIndex <= 0) return; const index = historyIndex - 1; setHistoryIndex(index); replaceScenario(structuredClone(history[index]!)); }, [history, historyIndex, replaceScenario, review?.readOnly, deletionPending]);
  const redo = useCallback(() => { if (review?.readOnly || deletionPending() || historyIndex >= history.length - 1) return; const index = historyIndex + 1; setHistoryIndex(index); replaceScenario(structuredClone(history[index]!)); }, [history, historyIndex, replaceScenario, review?.readOnly, deletionPending]);

  const uniqueId = (title: string) => { const root = title.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "").replace(/^[^a-z]+/, "") || "step"; let id = root; let suffix = 2; while (scenario.steps.some((step) => step.id === id)) id = `${root}_${suffix++}`; return id; };
  const addBehavior = (behavior: Behavior, position?: { x: number; y: number }) => {
    if (review?.readOnly || deletionPending()) return;
    const id = uniqueId(behavior.title); const step: ScenarioStep = { id, behavior_id: behavior.id, parameters: Object.fromEntries(behavior.parameters.filter(shouldInitializeParameter).map((item) => [item.name, initialParameterValue(item)])), inputs: {}, alternates: [] };
    const previous = scenario.steps.at(-1); const next: Scenario = { ...scenario, start: scenario.steps.length ? scenario.start : id, steps: [...scenario.steps, step], edges: previous ? [...scenario.edges, { from_step: previous.id, outcome: "success", to_step: id }] : scenario.edges, layout: { ...scenario.layout, [id]: position ?? { x: 70 + (scenario.steps.length % 3) * 310, y: 70 + Math.floor(scenario.steps.length / 3) * 220 } } };
    applyScenario(next); setAllBranches(true); selectStep(id); setCompatibility(`${displayTitle(behavior.title)} added. Set its inputs and parameters in step details.`);
  };

  const updateStep = (stepId: string, update: (step: ScenarioStep) => ScenarioStep) => applyScenario({ ...scenario, steps: scenario.steps.map((step) => step.id === stepId ? update(structuredClone(step)) : step) });
  const useAlternative = (stepId: string, behaviorId: string) => {
    if (review?.readOnly || deletionPending()) return;
    try {
      applyScenario(selectScenarioAlternative(scenario, stepId, behaviorId, behaviorMap));
      setCompatibility(`${displayTitle(behaviorMap.get(behaviorId)!.title)} selected. Inputs, parameters, and connections are preserved. Validate and review the changed run before executing.`);
    } catch (error) { setCompatibility(error instanceof Error ? error.message : "This alternative is unavailable.", true); }
  };
  const onNodesChange = useCallback((changes: NodeChange<BehaviorFlowNode>[]) => {
    const allowed = changes.filter(change => change.type === "remove" ? deletionAllowsRemoval("nodes", change.id) : !(review?.readOnly || deletionPending()) || change.type === "select" || change.type === "dimensions");
    setNodes(items => applyNodeChanges(allowed, items));
  }, [review?.readOnly, deletionAllowsRemoval, deletionPending]);
  const onEdgesChange = useCallback((changes: EdgeChange<FlowEdge>[]) => {
    const allowed = changes.filter(change => change.type === "remove" ? deletionAllowsRemoval("edges", change.id) : !(review?.readOnly || deletionPending()) || change.type === "select");
    setEdges(items => applyEdgeChanges(allowed, items));
  }, [review?.readOnly, deletionAllowsRemoval, deletionPending]);
  const onNodeDragStop = (_: unknown, node: BehaviorFlowNode) => {
    claimViewport();
    applyScenario({ ...scenario, layout: { ...scenario.layout, [node.id]: { x: Math.round(node.position.x), y: Math.round(node.position.y) } } });
  };
  const onDelete = ({ nodes: deletedNodes, edges: deletedEdges }: { nodes: BehaviorFlowNode[]; edges: FlowEdge[] }) => {
    if (review?.readOnly || !consumeDeletion({ nodes: deletedNodes, edges: deletedEdges })) return;
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
    if (deletedNodeIds.includes(selectedId)) {
      const remaining = graphView(next, allBranches, expandedBranches).ordered;
      const remainingSections = graphSections(remaining, next.edges, next.start);
      const nextSection = Math.min(sectionIndex, remainingSections.length - 1);
      const candidates = viewMode === "graph" && focusedSection !== null ? remainingSections[nextSection]!.steps : remaining;
      const replacementId = candidates.find((step) => shownIds.has(step.id))?.id ?? candidates[0]?.id ?? "";
      // Select within the resulting visible section, falling back to the last
      // section only when this deletion removes the operator's current one.
      if (viewMode === "graph" && focusedSection !== null) setFocusedSection(nextSection);
      // Keep the canvas and inspector on the same remaining step. Otherwise the
      // graph refresh preserves its old unselected flag and clears the inspector.
      selectionForGraphRefresh.current = replacementId;
      setSelectedId(replacementId);
      setNodes((items) => items.map((node) => ({ ...node, selected: node.id === replacementId })));
    }
  };
  const confirmDelete = useCallback(async ({ nodes: requestedNodes, edges: requestedEdges }: { nodes: BehaviorFlowNode[]; edges: FlowEdge[] }) => {
    if (review?.readOnly) return false;
    const visibleNodes = requestedNodes.filter((node) => shownIds.has(node.id));
    const visibleEdges = requestedEdges.filter(edgeIsShown);
    if (!visibleNodes.length && !visibleEdges.length) return false;
    const elements = { nodes: visibleNodes, edges: visibleEdges };
    return requestDeletion(elements, graphDeletionSummary(scenario, behaviorMap, elements));
  }, [edgeIsShown, shownIds, review?.readOnly, requestDeletion, scenario, behaviorMap]);

  const onConnect = (connection: Connection) => {
    if (review?.readOnly || deletionPending()) return;
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
      if (!output || !input || output.type !== input.type || Boolean(output.multiple) !== Boolean(input.multiple)) { setCompatibility(`This step requires ${inputTypeLabel(input?.type ?? "compatible results")}${input?.multiple ? " (multiple values)" : ""}; the selected output provides ${inputTypeLabel(output?.type ?? "unknown results")}${output?.multiple ? " (multiple values)" : ""}. Choose a compatible output in step details.`, true); return; }
      if (!guaranteedInputSources(scenario, target.id).has(source.id)) { setCompatibility("Connect the producer before this step on every incoming path, then choose its output in step details.", true); return; }
      updateStep(target.id, (step) => ({ ...step, inputs: { ...step.inputs, [inputName]: { from_step: source.id, artifact: outputName } } })); setCompatibility(`Connected ${inputLabel(outputName)} to ${inputLabel(inputName)}.`);
    }
  };

  const copySelected = () => { const selected = scenario.steps.find((step) => step.id === selectedId && shownIds.has(step.id)); if (!selected || deletionPending()) return false; clipboard.current = structuredClone(selected); setCompatibility(`${graphStepName(scenario, behaviorMap, selected.id)} copied.`); return true; };
  const paste = () => { if (review?.readOnly || deletionPending() || !clipboard.current) return; const source = clipboard.current; const behavior = behaviorMap.get(source.behavior_id); if (!behavior) return; const id = uniqueId(`${source.id} copy`); const step = { ...structuredClone(source), id, inputs: {} }; const origin = scenario.layout?.[source.id] ?? { x: 60, y: 60 }; applyScenario({ ...scenario, steps: [...scenario.steps, step], layout: { ...scenario.layout, [id]: { x: origin.x + 36, y: origin.y + 36 } } }); setAllBranches(true); selectStep(id); };
  const duplicateSelected = () => { if (!review?.readOnly && copySelected()) window.setTimeout(paste, 0); };
  const keyboard = (event: ReactKeyboardEvent<HTMLDivElement>) => {
    const target = event.target as HTMLElement;
    if (event.defaultPrevented || commandPaletteOpen || deletionPending() || target.closest("[role='dialog'], input, select, textarea, [contenteditable]:not([contenteditable='false'])")) return;
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
    mutationFn: async (submitted: Scenario) => {
      const issues = adaptiveExecutionIssues(submitted, behaviorMap, actionMap);
      if (issues.length) return { valid: false, findings: issues.map(issue => ({ message: issue.message, stepId: issue.missingStep ? undefined : issue.stepId })) };
      const result = await api.validate(submitted);
      return { valid: result.valid, findings: result.valid ? [] : scenarioDiagnostics(result.issues, submitted, behaviorMap, id => graphStepName(submitted, behaviorMap, id)) };
    },
    onSuccess: (result, submitted) => {
      if (JSON.stringify(currentScenario.current) !== JSON.stringify(submitted)) return;
      setValidationIssues(result.findings); setValidationState(result.valid ? "valid" : "invalid");
      setInvalidNodes(new Set(result.findings.flatMap(issue => issue.stepId ? [issue.stepId] : [])));
    },
    onError: (error, submitted) => {
      if (JSON.stringify(currentScenario.current) !== JSON.stringify(submitted)) return;
      const { findings } = scenarioAuthoringFailure(error, submitted, behaviorMap, id => graphStepName(submitted, behaviorMap, id));
      setValidationIssues(findings); setValidationState("invalid");
      setInvalidNodes(new Set(findings.flatMap(issue => issue.stepId ? [issue.stepId] : [])));
    },
  });
  const saveMutation = useMutation({ mutationFn: (submitted: Scenario) => api.saveScenarioVersion(submitted), onSuccess: ({ scenario: saved }, submitted) => {
    const currentSaved = markSaved(submitted);
    setCompatibility(`Version ${saved.version} saved${currentSaved ? "." : "; newer changes remain unsaved."}`);
    void queryClient.invalidateQueries({ queryKey: ["scenarios"] });
    void queryClient.invalidateQueries({ queryKey: ["scenario-versions"] });
  }, onError: (error, submitted) => {
    if (JSON.stringify(currentScenario.current) !== JSON.stringify(submitted)) return;
    const { findings, rejected } = scenarioAuthoringFailure(error, submitted, behaviorMap, id => graphStepName(submitted, behaviorMap, id));
    setCompatibility(`Save refused: ${findings[0]!.message}`, true);
    if (rejected) { setValidationIssues(findings); setValidationState("invalid"); setInvalidNodes(new Set(findings.flatMap(issue => issue.stepId ? [issue.stepId] : []))); }
  } });
  const selected = scenario.steps.find((step) => step.id === selectedId && shownIds.has(step.id)); const selectedBehavior = behaviorMap.get(selected?.behavior_id ?? "");
  const filtered = behaviors.filter((behavior) => { const haystack = `${behavior.title} ${behavior.purpose} ${behavior.capabilities.join(" ")}`.toLowerCase(); return (!search || haystack.includes(search.toLowerCase())) && (platform === "all" || behavior.platforms.includes(platform)) && (tier === "all" || behavior.safety_tier === tier); });
  const platforms = [...new Set(behaviors.flatMap((item) => item.platforms))].sort();

  const drop = (event: DragEvent<HTMLDivElement>) => { event.preventDefault(); const id = event.dataTransfer.getData("application/x-bluefire-behavior"); const behavior = behaviorMap.get(id); if (!behavior) return; addBehavior(behavior, flow.screenToFlowPosition({ x: event.clientX, y: event.clientY })); };
  const fitGraph = () => { claimViewport(); fitNodes(shownSteps.map(step => step.id), 250); };
  const showSection = (value: string) => {
    const targetSection = value === "all" ? undefined : sections[Number(value)];
    setFocusedSection(value === "all" ? null : Number(value));
    const selectionIsVisible = targetSection?.steps.some(step => step.id === selectedId) ?? value === "all";
    const nextSelection = selectionIsVisible ? undefined : targetSection?.steps[0];
    if (nextSelection) {
      setSelectedId(nextSelection.id);
      setNodes((items) => items.map((node) => ({ ...node, selected: node.id === nextSelection.id })));
    }
    setInspectorOpen(false); setPaletteOpen(false);
    window.requestAnimationFrame(() => { fitNodes(targetSection?.steps.map(step => step.id) ?? visibleGraph.ordered.map(step => step.id), 180, true); });
  };
  const showAllBranches = () => {
    setAllBranches(true); setFocusedSection(null);
    window.requestAnimationFrame(() => { fitNodes(scenario.steps.map(step => step.id), 180, true); });
  };
  const fitSelection = () => { if (selectedId) { claimViewport(); frameStep(selectedId, "readable", 180); } };
  const autoLayoutLabel = focusedGroup ? "Arrange visible group" : "Auto-layout";
  const autoLayout = () => {
    if (review?.readOnly || !scenario.steps.length) return;
    if (focusedGroup) {
      const groupLayout = focusedGraphLayout(graph, shownSteps.map(step => step.id), true) ?? {};
      applyScenario({ ...scenario, layout: { ...scenario.layout, ...groupLayout } });
      setCompatibility("Visible group arranged by its connections. Use Undo to restore its positions.");
      window.setTimeout(() => { fitNodes(shownSteps.map(step => step.id), 180, true); }, 0);
    } else {
      applyScenario({ ...scenario, layout: initialGraphLayout(scenario) }); setCompatibility("Steps arranged by their connections. Use Undo to restore your positions.");
      window.setTimeout(() => { fitNodes(shownSteps.map(step => step.id), 180, true); }, 0);
    }
  };
  const runCommand = (action: () => void) => { setCommandPaletteOpen(false); action(); };

  const saveVersion = () => {
    if (!scenario.purpose.trim()) {
      setPurposeMissing(true); setPurposeOpen(true);
      setCompatibility("Describe the question this experiment will answer before saving.", true);
      window.requestAnimationFrame(() => purposeInput.current?.focus());
      return;
    }
    if (!scenario.steps.length) { setCompatibility("Add the first step before saving this experiment.", true); setPaletteOpen(true); return; }
    const retryIssues = adaptiveExecutionIssues(scenario, behaviorMap, actionMap);
    if (retryIssues.length) { setCompatibility(retryIssues[0]!.message, true); if (!retryIssues[0]!.missingStep) selectStep(retryIssues[0]!.stepId); return; }
    saveMutation.mutate(structuredClone(scenario));
  };

  const displayedValidation = validationState === "idle" && review?.validated ? "valid" : validationState;
  return <div className={`page builder-page workbench-builder ${focusMode ? "builder-focus" : ""} ${showInputs ? "show-inputs" : ""} ${summaryZoom ? "graph-summary-zoom" : ""}`} onPointerDownCapture={() => { viewInteracted.current = true; }} onClickCapture={() => { viewInteracted.current = true; }} onKeyDownCapture={(event) => { viewInteracted.current = true; keyboard(event); }}>
    <header className="page-header builder-header"><div className="builder-heading"><h1 aria-label={displayTitle(scenario.title)}><input className="builder-name-input" aria-label="Experiment name" disabled={review?.readOnly} value={scenario.title} onChange={(event) => applyScenario({ ...scenario, title: event.target.value }, false)} /></h1><p title={review?.description ?? scenario.purpose}>{review?.description ?? scenario.purpose}</p></div><div className="page-actions builder-actions"><Button variant="secondary" onClick={() => validateMutation.mutate(structuredClone(scenario))} disabled={validateMutation.isPending}><Check/>Validate</Button>{review ? review.controls : <><Button variant="secondary" onClick={saveVersion} disabled={saveMutation.isPending}>{saveMutation.isPending ? "Saving version" : "Save version"}</Button><Link className="button button-primary button-medium" to="/runs?prepare=1">Review run<ArrowRight/></Link></>}</div></header>
    {review?.details}
    <AdaptiveRepair scenario={scenario} behaviors={behaviorMap} actions={actionMap} overrides={runConfig.actionImplementations} onSelect={selectStep} onChange={applyScenario} readOnly={review?.readOnly} />
    <div className="experiment-summary"><div className="experiment-facts"><span><Network/>{scenario.steps.length} steps</span><span><GitBranch/>{scenario.edges.filter(edge => edge.outcome !== "success").length} conditional routes</span><Badge tone={review?.readOnly ? "neutral" : dirty ? "warning" : "neutral"} dot>{review?.statusLabel ?? (dirty ? "Unsaved changes" : "Working copy")}</Badge><Badge tone={displayedValidation === "valid" ? "success" : displayedValidation === "invalid" ? "danger" : "neutral"}>{displayedValidation === "valid" ? "Ready for review" : displayedValidation === "invalid" ? "Needs attention" : "Not validated"}</Badge></div><details className="purpose-editor" open={purposeOpen} onToggle={(event) => setPurposeOpen(event.currentTarget.open)}><summary>{scenario.purpose.trim() ? "Experiment purpose" : "Describe the experiment question"}</summary><Field label="Experiment question" hint="What do you want to learn or verify? Required before saving."><textarea aria-label="Experiment question" ref={purposeInput} rows={2} disabled={review?.readOnly} value={scenario.purpose} required aria-invalid={purposeMissing && !scenario.purpose.trim()} onChange={(event) => { setPurposeMissing(false); applyScenario({ ...scenario, purpose: event.target.value }, false); }} placeholder="Describe the behavior, observation or detection you want to test." /></Field></details>{!review ? <div className="builder-assistance-actions"><Button variant="ghost" size="small" onClick={() => assistant?.setOpen(true)} disabled={!assistant}>Plan with Assistant</Button><Link className="button button-ghost button-small" to="/scenarios">Browse examples</Link></div> : null}</div>
    {compatibility ? <div className={`compatibility-banner ${compatibility.error ? "error" : ""}`} role={compatibility.error ? "alert" : "status"}><GitBranch/>{compatibility.message}<button onClick={() => setCompatibility(undefined)} aria-label="Dismiss compatibility message">×</button></div> : null}
    <div className="graph-review-editor">
    <div className={`builder-layout ${paletteOpen ? "" : "palette-hidden"} ${inspectorOpen ? "" : "inspector-hidden"}`} style={{ "--palette-width": `${paletteWidth}px`, "--inspector-width": `${inspectorWidth}px` } as CSSProperties}>
      <Panel className="palette-panel" hidden={!paletteOpen}>{paletteOpen ? <><PanelHeader eyebrow="Available steps" title="Add a step" actions={<Badge>{filtered.length}</Badge>} /><div className="palette-filters"><label className="search-box"><Search/><input aria-label="Search palette" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Find a step" /></label><div><label><span className="sr-only">Platform filter</span><select aria-label="Platform filter" value={platform} onChange={(event) => setPlatform(event.target.value)}><option value="all">All platforms</option>{platforms.map((item) => <option key={item}>{item}</option>)}</select></label><label><span className="sr-only">Tier filter</span><select aria-label="Safety tier filter" value={tier} onChange={(event) => setTier(event.target.value)}><option value="all">All tiers</option><option value="safe">Safe</option><option value="controlled">Controlled</option><option value="restricted">Restricted</option></select></label></div></div><div className="palette-list">{filtered.map((behavior) => <button key={behavior.id} disabled={review?.readOnly} draggable={!review?.readOnly} onDragStart={(event) => { event.dataTransfer.setData("application/x-bluefire-behavior", behavior.id); event.dataTransfer.effectAllowed = "copy"; }} onClick={() => addBehavior(behavior)}><span className={`palette-icon tier-${behavior.safety_tier}`}><GitBranch/></span><span><strong>{displayTitle(behavior.title)}</strong><small>{behavior.purpose}</small><em>{behavior.platforms.slice(0, 3).join(" · ")}</em></span><Badge tone={behavior.execution_state === "action" ? "success" : behavior.execution_state === "simulation" ? "info" : "neutral"}>{behavior.execution_state === "action" ? "Action" : behavior.execution_state === "simulation" ? "Simulation" : "Research"}</Badge></button>)}</div><p className="panel-footnote"><Filter/> Choose a step to add it. Research entries describe techniques and cannot execute.</p></> : null}</Panel>
      <Panel className="graph-panel">
        <div className="graph-topbar">
          <div className="graph-view-actions" aria-label="Graph workspace controls">
            <IconButton label={paletteOpen ? "Hide behavior palette" : "Show behavior palette"} aria-pressed={paletteOpen} onClick={togglePalette}>{paletteOpen ? <PanelLeftClose/> : <PanelLeftOpen/>}</IconButton><IconButton label="Add step" aria-pressed={paletteOpen} onClick={togglePalette}><Plus/></IconButton><div className="view-toggle" aria-label="Experiment view"><button aria-pressed={viewMode === "graph"} onClick={() => setViewMode("graph")}><Network/>Canvas</button><button aria-pressed={viewMode === "steps"} onClick={() => setViewMode("steps")}><ListOrdered/>Steps</button></div>
            <div className="graph-history"><IconButton label="Undo" onClick={undo} disabled={review?.readOnly || historyIndex <= 0}><Undo2/></IconButton><IconButton label="Redo" onClick={redo} disabled={review?.readOnly || historyIndex >= history.length - 1}><Redo2/></IconButton></div>
            <Button className="graph-auto-layout" size="small" variant="ghost" aria-label={autoLayoutLabel} onClick={autoLayout} disabled={review?.readOnly || !nodes.length}><LayoutGrid/><span>{autoLayoutLabel}</span></Button>
            <Button className="graph-fit-view" size="small" variant="ghost" aria-label="Fit view" onClick={fitGraph} disabled={!nodes.length}><ScanSearch/><span>Fit view</span></Button>
            <BuilderStepSearch steps={scenario.steps} behaviors={behaviorMap} onSelect={revealSearchResult} />
            <output className="graph-scale" aria-label="Graph zoom">{Math.round(graphZoom * 100)}%</output>
            <div className="graph-utility-actions">
            {viewMode === "graph" ? <IconButton id={routesToggleId} label={routesOpen ? "Hide route list" : "Show route list"} aria-pressed={routesOpen} onClick={() => { setRoutesOpen(value => !value); if (!routesOpen) { setInspectorOpen(false); setPaletteOpen(false); } }}><GitBranch/></IconButton> : null}
            <IconButton id={inspectorToggleId} label={inspectorOpen ? "Hide node inspector" : "Show node inspector"} aria-pressed={inspectorOpen} onClick={toggleInspector}>{inspectorOpen ? <PanelRightClose/> : <PanelRightOpen/>}</IconButton>
            <IconButton label={focusMode ? "Exit graph focus mode" : "Enter graph focus mode"} aria-pressed={focusMode} onClick={() => setFocusMode((active) => !active)}>{focusMode ? <Minimize2/> : <Maximize2/>}</IconButton>
            <details className="graph-options"><summary aria-label="View options"><MoreHorizontal/><span className="sr-only">View options</span></summary><div>
            <div className="graph-compacted-tools"><Button size="small" variant="ghost" onClick={autoLayout} disabled={review?.readOnly || !nodes.length}><LayoutGrid/>{autoLayoutLabel}</Button><output aria-label="Graph zoom">Zoom {Math.round(graphZoom * 100)}%</output></div>
            <div className="graph-option-actions"><Button variant="ghost" size="small" onClick={fitSelection} disabled={!selected}><Maximize2/>Focus selected step</Button><Button variant="ghost" size="small" onClick={() => setCommandPaletteOpen(true)}><CommandIcon/>Commands</Button><Button size="small" variant="ghost" onClick={() => { const url = URL.createObjectURL(new Blob([JSON.stringify(scenario, null, 2)], { type: "application/json" })); const link = document.createElement("a"); link.href = url; link.download = `${scenario.id}.json`; link.click(); URL.revokeObjectURL(url); }}><Download/>Export</Button></div>
            <div className="graph-edit-actions" role="group" aria-label="Selection tools"><IconButton label="Copy selected node" onClick={copySelected} disabled={!selected}><Copy/></IconButton><IconButton label="Paste node" onClick={paste} disabled={review?.readOnly || !clipboard.current}><Clipboard/></IconButton><IconButton label="Duplicate selected node" onClick={duplicateSelected} disabled={review?.readOnly || !selected}><RotateCcw/></IconButton><IconButton label="Delete selected node" onClick={() => { if (selected) void flow.deleteElements({ nodes: [{ id: selected.id }] }); }} disabled={review?.readOnly || !selected}><Trash2/></IconButton></div>
            <label className="check-row"><input type="checkbox" checked={allBranches} onChange={(event) => setAllBranches(event.target.checked)}/>Show all branches and disconnected steps</label>
            <label className="check-row"><input type="checkbox" checked={showInputs} onChange={(event) => setShowInputs(event.target.checked)}/>Show input connections</label>
            {allBranches ? <Button variant="ghost" size="small" onClick={() => { setAllBranches(false); setFocusedSection(null); }}>Focus on success path</Button> : null}
            {viewMode === "graph" && sections.length > 1 ? <Field label="Focus a connected path" hint="Optional view grouping. Review run always includes the whole experiment."><select aria-label="Step group" value={focusedSection === null ? "all" : sectionIndex} onChange={event => showSection(event.target.value)}><option value="all">All steps</option>{sections.map((section, index) => <option key={index} value={index}>{section.title} · {section.steps.length} steps</option>)}</select></Field> : null}
            <label className="panel-width-control"><span>Palette width</span><input aria-label="Behavior palette width" type="range" min="220" max="420" step="10" value={paletteWidth} disabled={!paletteOpen} onChange={(event) => setPaletteWidth(Number(event.target.value))}/><output>{paletteWidth}px</output></label>
            <label className="panel-width-control"><span>Inspector width</span><input aria-label="Node inspector width" type="range" min="260" max="480" step="10" value={inspectorWidth} disabled={!inspectorOpen} onChange={(event) => setInspectorWidth(Number(event.target.value))}/><output>{inspectorWidth}px</output></label></div></details>
            </div>
            {focusMode ? <span className="focus-hint">Esc to exit</span> : null}
          </div>
        </div>
        {viewMode === "graph" && focusedGroup ? <nav className="graph-sections" aria-label="Focused connected path"><span>{sections[sectionIndex]!.title} · {shownIds.size} of {scenario.steps.length} steps</span><Button size="small" variant="ghost" onClick={() => showSection("all")}>Return to whole plan</Button>{groupBoundaries ? <details className="graph-group-connections"><summary>Group connections</summary><div><span className="graph-group-boundaries" aria-label="Conditional execution routes">{groupBoundaries.incoming.length ? `From: ${groupBoundaries.incoming.join(", ")}` : groupBoundaries.first ? "Entry group" : "No incoming route"}{groupBoundaries.outgoing.length ? ` · To: ${groupBoundaries.outgoing.join(", ")}` : ""}</span>{groupBoundaries.artifactCount ? <details className="graph-data-boundaries"><summary>Data dependencies ({groupBoundaries.artifactCount})</summary><div>{groupBoundaries.incomingArtifacts.length ? <section><strong>Inputs from other groups</strong><ul>{groupBoundaries.incomingArtifacts.map(item => <li key={`in-${item.identity}`}>{item.label}</li>)}</ul></section> : null}{groupBoundaries.outgoingArtifacts.length ? <section><strong>Outputs used by other groups</strong><ul>{groupBoundaries.outgoingArtifacts.map(item => <li key={`out-${item.identity}`}>{item.label}</li>)}</ul></section> : null}</div></details> : null}</div></details> : null}</nav> : null}
        {!allBranches || hiddenBranches || shownIds.size < scenario.steps.length ? <div className="graph-disclosure" role="status"><span>{shownIds.size} of {scenario.steps.length} steps shown · {hiddenBranches} routes hidden. Review run includes the whole experiment.</span><button onClick={showAllBranches}>Show all branches</button>{selected && scenario.edges.some((edge) => edge.from_step === selected.id && edge.outcome !== "success") && !allBranches ? <button onClick={() => setExpandedBranches((previous) => { const next = new Set(previous); if (next.has(selected.id)) next.delete(selected.id); else next.add(selected.id); return next; })}>{expandedBranches.has(selected.id) ? "Collapse selected branches" : "Expand selected branches"}</button> : null}</div> : null}
        {viewMode === "steps" ? <ol ref={orderedSteps} className="ordered-steps" aria-label="Experiment steps">{visibleGraph.ordered.map((step, index) => { const behavior = behaviorMap.get(step.behavior_id); return <li key={step.id}><button data-step-id={step.id} aria-pressed={selectedId === step.id} onClick={() => selectStep(step.id)}><span className="step-number">{index + 1}</span><span><strong>{displayTitle(behavior?.title ?? "Unavailable step")}</strong><small>{behavior?.purpose}</small><span className="step-routes">{scenario.edges.filter((edge) => edge.from_step === step.id).map((edge) => <em key={edge.outcome}>{branchLabels[edge.outcome]} → {behaviorMap.get(scenario.steps.find((item) => item.id === edge.to_step)?.behavior_id ?? "")?.title ? displayTitle(behaviorMap.get(scenario.steps.find((item) => item.id === edge.to_step)?.behavior_id ?? "")!.title) : edge.to_step}</em>)}</span></span><Badge>{behavior?.execution_state === "action" ? "Executable" : behavior?.execution_state === "simulation" ? "Simulated" : "Research"}</Badge></button></li>; })}</ol> : null}
        <div className={`graph-stage ${routesOpen ? "routes-open" : ""}`} hidden={viewMode !== "graph"}>
        <div ref={graphCanvas} className="graph-canvas" tabIndex={0} aria-label="Scenario graph canvas" onKeyDown={(event) => {
          if (event.key !== "Enter" && event.key !== " ") return;
          const id = event.target instanceof Element ? event.target.closest(".react-flow__edge")?.getAttribute("data-id") : null;
          if (id && visibleRoutes.some((edge) => edge.id === id)) { event.preventDefault(); selectRoute(id); }
        }} onPointerDown={(event) => { const target = event.target as HTMLElement; if (!target.closest("button, input, select, textarea")) event.currentTarget.focus(); }} onDragOver={(event) => { if (event.dataTransfer.types.includes("application/x-bluefire-behavior")) event.preventDefault(); }} onDrop={drop}>
        <ReactFlow<BehaviorFlowNode, FlowEdge> nodes={displayNodes} edges={displayEdges} nodesDraggable={!review?.readOnly && !deletion.summary} nodesConnectable={!review?.readOnly && !deletion.summary} nodeTypes={nodeTypes} edgeTypes={edgeTypes} onEdgeClick={onEdgeClick} onNodesChange={onNodesChange} onEdgesChange={onEdgesChange} onNodeClick={onNodeClick} onSelectionChange={onSelectionChange} onMove={onMove} onNodeDragStop={onNodeDragStop} onDelete={onDelete} onBeforeDelete={confirmDelete} onConnect={onConnect} minZoom={minimumGraphZoom} maxZoom={1.6} deleteKeyCode={review?.readOnly || deletion.summary ? null : deleteKeys} connectionLineStyle={connectionLineStyle} proOptions={proOptions}>
          {runBands.length ? <ViewportPortal><svg className="graph-run-bands" aria-hidden="true" width="1" height="1">{runBands.map(band => <g key={band.id} className={band.stepIds.includes(selectedId) ? "selected" : undefined}><rect x={band.x} y={band.y} width={band.width} height={band.height} rx="10"/><text x={band.x + 12} y={band.y + 15}>{band.label}</text></g>)}</svg></ViewportPortal> : null}
          <Background variant={BackgroundVariant.Dots} gap={20} size={1} color="rgba(117,198,255,.12)"/>{scenario.steps.length > 3 && miniMapOpen ? <MiniMap style={miniMapStyle} position="bottom-left" pannable zoomable nodeColor={(node) => node.selected ? "var(--blue)" : "var(--muted)"} bgColor="var(--ink-950)" maskColor="color-mix(in srgb, var(--ink-1000) 72%, transparent)"/> : null}<Controls position="bottom-right" showInteractive={false} onZoomIn={claimViewport} onZoomOut={claimViewport} onFitView={claimViewport}/>
        </ReactFlow>{!nodes.length ? <div className="graph-empty-overlay"><GitBranch/><strong>Add the first step</strong><span>Choose a method to begin designing this experiment.</span><Button variant="primary" disabled={review?.readOnly} onClick={() => { setPaletteOpen(true); setInspectorOpen(false); }}>Add first step</Button></div> : null}</div>
        {routesOpen ? <BuilderRoutes routes={visibleRoutes} total={scenario.edges.length} selected={selectedRoute} readOnly={Boolean(review?.readOnly)} select={selectRoute} inspect={(source) => { selectStep(source); setRoutesOpen(false); window.requestAnimationFrame(() => document.getElementById(inspectorToggleId)?.focus()); }} remove={(id) => { void flow.deleteElements({ edges: [{ id }] }); }} close={() => { setRoutesOpen(false); document.getElementById(routesToggleId)?.focus(); }} /> : null}
        </div>
        {viewMode === "graph" ? <footer className="graph-key"><div className="graph-legend" aria-label="Connection types"><span><i className="legend-success"/>Success</span><span><i className="legend-conditional"/>Conditional</span><span><i className="legend-data"/>Data</span></div>{scenario.steps.length > 3 ? <button type="button" className="graph-overview-toggle" aria-pressed={miniMapOpen} onClick={() => setMiniMapOpen(open => !open)}><LayoutGrid aria-hidden="true"/>{miniMapOpen ? "Hide overview" : "Overview map"}</button> : null}</footer> : null}
        {viewMode === "graph" ? <BuilderEvidenceTray key={scenario.id} step={selected} ordinal={selected ? scenario.steps.indexOf(selected) + 1 : undefined} behavior={selectedBehavior} /> : null}
        <GraphValidationFeedback state={displayedValidation} findings={validationIssues} stepCount={scenario.steps.length} routeCount={scenario.edges.length} readOnly={review?.readOnly} name={id => graphStepName(scenario, behaviorMap, id)} onSelect={id => { setAllBranches(true); setFocusedSection(null); selectStep(id); }} />
      </Panel>
      <Panel className="inspector-panel" hidden={!inspectorOpen}>{inspectorOpen ? <><header className="inspector-header"><span className="inspector-step-icon"><FileText/></span><div><h2>{displayTitle(selectedBehavior?.title ?? "Select a step")}</h2><p>{selected ? `Step ${scenario.steps.indexOf(selected) + 1} · ${selectedBehavior?.execution_state === "action" ? "Method" : selectedBehavior?.execution_state === "simulation" ? "Simulation" : "Research only"}` : "Method, evidence, and parameters"}</p></div><IconButton label="Close step details" onClick={() => { setInspectorOpen(false); document.getElementById(inspectorToggleId)?.focus(); }}><X/></IconButton></header>{selected && selectedBehavior ? <Inspector scenario={scenario} step={selected} behavior={selectedBehavior} behaviors={behaviorMap} actions={actionMap} readOnly={Boolean(review?.readOnly)} onAlternative={useAlternative} updateStep={updateStep} updateScenario={applyScenario} renameStep={renameStep} selectedAction={runConfig.actionImplementations?.[selected.id] ?? ""} allowRunOverride={!review} onAction={(actionId) => { const next = { ...(runConfig.actionImplementations ?? {}) }; if (actionId) next[selected.id] = actionId; else delete next[selected.id]; setRunConfig({ ...runConfig, actionImplementations: next }); }} /> : <EmptyState title="Select a step" description="Select a step on the canvas or in the list to choose its method, inputs, and branches." />}</> : null}</Panel>
    </div>
    </div>
    <GraphDeleteDialog summary={deletion.summary} confirm={deletion.confirm} cancel={deletion.cancel} restoreFocus={deletion.restoreFocus} />
    <Dialog.Root open={commandPaletteOpen} onOpenChange={setCommandPaletteOpen}>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay builder-command-overlay" />
        <Dialog.Content className="dialog-content builder-command-dialog" onEscapeKeyDown={(event) => event.stopPropagation()}>
          <div><Dialog.Title>Builder commands</Dialog.Title><Dialog.Description>Run an existing graph-editor action. Commands never authorize or start execution.</Dialog.Description></div>
          <Dialog.Close asChild><button className="dialog-close" aria-label="Close Builder commands"><X/></button></Dialog.Close>
          <div className="builder-command-list">
            <button onClick={() => runCommand(autoLayout)} disabled={review?.readOnly || !nodes.length}><LayoutGrid/><span><strong>{autoLayoutLabel}</strong><small>{focusedGroup ? "Arrange only the visible group by its connections." : "Arrange steps by their connections."}</small></span></button>
            <button onClick={() => runCommand(fitGraph)} disabled={!nodes.length}><ScanSearch/><span><strong>Fit view</strong><small>Show an overview of the visible path.</small></span></button>
            <button onClick={() => runCommand(fitSelection)} disabled={!selected}><ScanSearch/><span><strong>Focus selected step</strong><small>Frame the selected node at a readable scale.</small></span></button>
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

function Inspector({ scenario, step, behavior, behaviors, actions, readOnly, updateStep, updateScenario, renameStep, selectedAction, allowRunOverride, onAction, onAlternative }: { scenario: Scenario; step: ScenarioStep; behavior: Behavior; behaviors: Map<string, Behavior>; actions: Map<string, ActionDefinition>; readOnly: boolean; updateStep: (id: string, update: (step: ScenarioStep) => ScenarioStep) => void; updateScenario: (scenario: Scenario) => void; renameStep: (previousId: string, nextId: string, scenario: Scenario) => void; selectedAction: string; allowRunOverride: boolean; onAction: (id: string) => void; onAlternative: (stepId: string, behaviorId: string) => void }) {
  const [tab, setTab] = useState<"method" | "evidence" | "parameters">("method");
  const tabId = useId();
  const tabs = ["method", "evidence", "parameters"] as const;
  const behaviorTitle = displayTitle(behavior.title);
  const behaviorMethodTitle = inspectorMethodTitle(behavior, actions);
  const sources = guaranteedInputSources(scenario, step.id);
  const outputs = scenario.steps.flatMap((source) => (behaviors.get(source.behavior_id)?.outputs ?? []).map((output) => ({ source, output }))).filter((item) => sources.has(item.source.id));
  const changeId = (id: string) => { if (!/^[a-z][a-z0-9_]*$/.test(id) || scenario.steps.some((item) => item.id === id && item.id !== step.id)) return; renameStep(step.id, id, { ...scenario, ...(scenario.adaptive_execution ? { adaptive_execution: renameAdaptiveExecutionStep(scenario.adaptive_execution, step.id, id) } : {}), start: scenario.start === step.id ? id : scenario.start, steps: scenario.steps.map((item) => item.id === step.id ? { ...item, id } : { ...item, inputs: Object.fromEntries(Object.entries(item.inputs).map(([name, binding]) => [name, binding.from_step === step.id ? { ...binding, from_step: id } : binding])) }), edges: scenario.edges.map((edge) => ({ ...edge, from_step: edge.from_step === step.id ? id : edge.from_step, to_step: edge.to_step === step.id ? id : edge.to_step })), layout: Object.fromEntries(Object.entries(scenario.layout ?? {}).map(([key, value]) => [key === step.id ? id : key, value])) }); };
  return <div className="inspector-editor"><div className="inspector-tabs" role="tablist" aria-label="Selected step details">{tabs.map((item, index) => <button key={item} id={`${tabId}-${item}`} role="tab" type="button" aria-selected={tab === item} aria-controls={`${tabId}-${item}-panel`} tabIndex={tab === item ? 0 : -1} onClick={() => setTab(item)} onKeyDown={event => {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
    event.preventDefault();
    const next = event.key === "Home" ? 0 : event.key === "End" ? tabs.length - 1 : (index + (event.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length;
    setTab(tabs[next]!); event.currentTarget.parentElement?.querySelectorAll<HTMLButtonElement>("[role=tab]")[next]?.focus();
  }}>{sentence(item)}</button>)}</div><fieldset className="graph-review-editor inspector-fields" disabled={readOnly}><div className="inspector-body">
    <div role="tabpanel" id={`${tabId}-method-panel`} aria-labelledby={`${tabId}-method`} hidden={tab !== "method"}>
    <section><h3>Selected method</h3><article className="method-card current-method" aria-label={`Primary method: ${behaviorTitle}`}><div className="method-card-heading"><FileText/><strong title={behaviorTitle}>{behaviorMethodTitle}</strong><Badge tone="info">Primary</Badge></div><p>{behavior.purpose}</p><div className="chip-list"><Badge tone={behavior.safety_tier === "restricted" ? "danger" : behavior.safety_tier === "controlled" ? "warning" : "success"}>{sentence(behavior.safety_tier)}</Badge>{behavior.platforms.map(item => <Badge key={item}>{inputLabel(item)}</Badge>)}</div></article></section>
    {(behavior.compatible_behaviors?.length || step.alternates.length) ? <section><h3>Alternative methods</h3>{[...new Set([...(behavior.compatible_behaviors ?? []), ...step.alternates])].filter(id => id !== behavior.id).map(id => {
      const alternative = behaviors.get(id);
      const title = alternative?.title ? displayTitle(alternative.title) : id;
      const methodTitle = alternative ? inspectorMethodTitle(alternative, actions) : id;
      return <article className="method-card alternative-method" aria-label={`Alternative method: ${title}`} key={id}><strong aria-label={title} title={title}>{methodTitle}</strong><p>{alternative?.purpose ?? "This method is unavailable in the loaded catalog."}</p><div className="chip-list">{alternative?.platforms.map(item => <Badge key={item}>{inputLabel(item)}</Badge>)}</div><Button size="small" variant="primary" disabled={!alternative} onClick={() => onAlternative(step.id, id)} aria-label={`Use ${title} for this step`}>Use this method<ArrowRight/></Button><label className="check-row"><input type="checkbox" aria-label={title} checked={step.alternates.includes(id)} onChange={event => updateStep(step.id, next => ({ ...next, alternates: event.target.checked ? [...next.alternates, id] : next.alternates.filter(value => value !== id) }))}/><span>Keep as a saved alternative</span></label></article>;
    })}<p>Saved alternatives are available for reuse. Adaptive retry choices separately control changes during execution.</p></section> : null}
    <section><Field label="Run method override" hint={!allowRunOverride ? "Adopt this reviewed experiment before choosing a run override." : behavior.action_ids.length ? "Optional for this run, across Simulate and Execute. Reviewed for compatibility and approval before execution; not saved with the experiment." : "This step has no executable method. Choose a supported alternative to execute it."}><select aria-label="Run method override" value={selectedAction} onChange={event => onAction(event.target.value)} disabled={!allowRunOverride || !behavior.action_ids.length}><option value="">Recommended at run review</option>{behavior.action_ids.map(id => <option key={id} value={id}>{actions.get(id)?.title ? displayTitle(actions.get(id)!.title) : id}{actions.get(id)?.platforms.length ? ` · ${actions.get(id)!.platforms.join(" / ")}` : ""}</option>)}</select></Field></section>
    <AdaptiveMethodEditor key={`${step.id}:${JSON.stringify(scenario.adaptive_execution)}:${selectedAction}`} scenario={scenario} step={step} behaviors={behaviors} actions={actions} selectedAction={selectedAction} onChange={updateScenario} />
    </div>
    <div role="tabpanel" id={`${tabId}-evidence-panel`} aria-labelledby={`${tabId}-evidence`} hidden={tab !== "evidence"}>
      <section><h3>Expected evidence</h3><p>These are the method’s expected outputs and observations. Run results distinguish runner-reported evidence from independent observations.</p>{behavior.outputs.length ? <ul className="evidence-contracts">{behavior.outputs.map(output => <li key={output.name}><FileText/><span><strong>{inputLabel(output.name)}</strong><small>{inputTypeLabel(output.type)}{output.multiple ? " · Multiple items" : ""}</small></span></li>)}</ul> : <p>This method declares no output artifacts.</p>}</section>
      <section><h3>Expected observations</h3>{behavior.telemetry.length ? <div className="chip-list">{behavior.telemetry.map(item => <Badge key={item} tone="info">{item}</Badge>)}</div> : <p>No observation types are declared for this method.</p>}{behavior.detection_hints.length ? <ul>{behavior.detection_hints.map(hint => <li key={hint}>{hint}</li>)}</ul> : null}</section>
      {behavior.limitations.length ? <section><h3>Evidence limitations</h3><ul>{behavior.limitations.map(limitation => <li key={limitation}>{limitation}</li>)}</ul></section> : null}
      <Link className="button button-secondary button-small evidence-run-link" to="/runs">Open run results<ArrowRight/></Link>
    </div>
    <div role="tabpanel" id={`${tabId}-parameters-panel`} aria-labelledby={`${tabId}-parameters`} hidden={tab !== "parameters"}>
    <section><h3>Required input</h3>{behavior.inputs.length ? behavior.inputs.map((input) => {
      const options = outputs.filter(({ output }) => output.type === input.type && Boolean(output.multiple) === Boolean(input.multiple));
      const binding = step.inputs[input.name];
      const selectedValue = binding ? `${binding.from_step}:${binding.artifact}` : "";
      const invalidBinding = Boolean(binding && !options.some(({ source, output }) => source.id === binding.from_step && output.name === binding.artifact));
      const hint = invalidBinding ? "This connection is not guaranteed on every path or its output no longer matches. Reconnect it or choose a compatible earlier step." : options.length ? `${input.required ? "Required" : "Optional"}: ${inputTypeLabel(input.type)} from a step that runs on every incoming path.` : `Add or connect an earlier step that produces ${inputTypeLabel(input.type)} on every incoming path.`;
      return <Field key={input.name} label={inputLabel(input.name)} hint={hint}><select aria-label={inputLabel(input.name)} aria-invalid={invalidBinding} value={selectedValue} onChange={(event) => updateStep(step.id, (next) => { if (!event.target.value) { delete next.inputs[input.name]; return next; } const [from_step, artifact] = event.target.value.split(":", 2); return { ...next, inputs: { ...next.inputs, [input.name]: { from_step: from_step!, artifact: artifact! } } }; })}><option value="">{input.required ? "Choose compatible output" : "No input"}</option>{invalidBinding ? <option value={selectedValue} disabled>Current connection needs attention</option> : null}{options.map(({ source, output }) => <option key={`${source.id}:${output.name}`} value={`${source.id}:${output.name}`}>{behaviors.get(source.behavior_id)?.title ? displayTitle(behaviors.get(source.behavior_id)!.title) : source.id} · {inputLabel(output.name)}</option>)}</select></Field>;
    }) : <p>This step needs no input from another step.</p>}</section>
    <section><h3>Parameters</h3>{behavior.parameters.length ? behavior.parameters.map((spec) => <ParameterField key={spec.name} behaviorId={step.behavior_id} spec={spec} value={step.parameters[spec.name]} onChange={(value) => updateStep(step.id, (next) => ({ ...next, parameters: updateParameter(next.parameters, spec.name, value) }))} />) : <p>No configurable parameters.</p>}</section>
    </div>
    <details className="step-technical-details"><summary>Routes and step details</summary><p>The primary method is saved with this step. A run override applies only to the current run and is reviewed before execution.</p><section><h3>Next step</h3>{outcomes.map((outcome) => { const edge = scenario.edges.find((item) => item.from_step === step.id && item.outcome === outcome); return <Field key={outcome} label={branchLabels[outcome]}><select value={edge?.to_step ?? ""} onChange={(event) => updateScenario({ ...scenario, edges: [...scenario.edges.filter((item) => !(item.from_step === step.id && item.outcome === outcome)), ...(event.target.value ? [{ from_step: step.id, outcome, to_step: event.target.value }] : [])] })}><option value="">End path</option>{scenario.steps.filter((item) => item.id !== step.id).map((item) => <option key={item.id} value={item.id}>{behaviors.get(item.behavior_id)?.title ? displayTitle(behaviors.get(item.behavior_id)!.title) : item.id}</option>)}</select></Field>; })}</section><Field label="Step ID" hint="Changing this also updates connected steps."><input value={step.id} onChange={(event) => changeId(event.target.value)} pattern="[a-z][a-z0-9_]*" /></Field><p><code>{behavior.id}</code></p></details>
  </div></fieldset></div>;
}

function updateParameter(parameters: Record<string, unknown>, name: string, value: unknown) {
  const next = { ...parameters };
  if (value === undefined) delete next[name];
  else next[name] = value;
  return next;
}
